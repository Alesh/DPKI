import asyncio
import json
import os.path

import tend.abci.ext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tend import abci
from tend.abci.handlers import RequestQuery, ResponseQuery, ResultCode

from csp.provider import CSProvider
from dpki import database
from dpki.database.repository import AppState, CertEntity

from .checker import TxChecker
from .config import Config
from .keeper import TxKeeper
from .caserv import CAService
from .rpcli import Client
from ..utils import load_from_key_file


class Application(abci.ext.Application):
    """ ABCI Chain application
    """

    def __init__(self, home_path: str, logger=None):
        super().__init__(TxChecker(self), TxKeeper(self), logger)
        config = Config(os.path.join(home_path, 'config', 'config.toml'))
        self.csp = CSProvider()
        self.client = Client(config['rpc']['laddr'])
        self.database = database.engine_factory()

        ca_config = config['ca']
        ca_key = ca_config.get('ca_key_file')
        if ca_key is not None:
            ca_key = load_from_key_file(os.path.join(home_path, ca_key))
        self.ca = CAService(self, ca_key, ca_config, logger)

    async def get_initial_app_state(self):
        #
        self._ca = asyncio.create_task(self.ca.start())
        #
        async with self.database.begin() as ac:
            return await AppState.get_initial(ac)

    async def update_app_state(self, new_state: 'AppState'):
        await super().update_app_state(new_state)
        if new_state.block_height > 1:
            ca_subject = await self.ca.initialize()
            if ca_subject:
                self.logger.info(f"CA initialized on this node; subject: {ca_subject}")

    async def query(self, req: 'RequestQuery') -> 'ResponseQuery':
        path = req.path.lower()
        data = req.data
        if data:
            if data.startswith(b'0x'):
                data = bytes.fromhex(data[2:].decode('utf8'))
            else:
                data = data.decode('utf8')
        if path.startswith('ca/'):
            if path.endswith('/list'):
                result = list()
                async with self.database.begin() as ac:
                    ca_list = await CertEntity.list_by_role(ac, 'CA')
                    for ca in ca_list:
                        cert = x509.load_pem_x509_certificate(ca.pem_serialized.encode('utf8'), backend=default_backend())
                        path_length = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
                        result.append(dict(subject=ca.subject_name, path_length=path_length,
                                           issuer=cert.issuer.rfc4514_string()))
                    return ResponseQuery(code=ResultCode.OK, height=self.state.block_height,
                                         value=json.dumps(result, ensure_ascii=False).encode('utf8'))
            elif path.endswith('/get'):
                async with self.database.begin() as ac:
                    if isinstance(data, bytes):
                        pen_serialized = await CertEntity.get_by_address(ac, data)
                    else:
                        pen_serialized = await CertEntity.get_by_subject(ac, data)
                    if pen_serialized:
                        return ResponseQuery(code=ResultCode.OK, height=self.state.block_height,
                                             value=pen_serialized.encode('utf8'))
                    else:
                        data = req.data.decode('utf8')
                        return ResponseQuery(code=ResultCode.Error, log=f'Certificate not found for: {data}')
        return await super().query(req)
