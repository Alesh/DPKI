import json
import logging
from dataclasses import asdict
from typing import TYPE_CHECKING

import tend.abci.ext
from tend import abci
from tend.abci.handlers import ResultCode, ResponseDeliverTx

import csp.sha256
from dpki.database.repository import CertEntity, AppState
from dpki.x509cert.utils import deserialize_certificate_from_pem_x509
from .checker import CheckerMixin
from .caserv import Certificate, CertificateSigningRequest

if TYPE_CHECKING:
    from typing import Optional
    from sqlalchemy.ext.asyncio import AsyncConnection
    from . import Application

    AsyncConnection = Optional[AsyncConnection]


class TxKeeper(abci.ext.TxKeeper, CheckerMixin):
    """ TX keeper
    """
    app: 'Application'

    def __init__(self, app: 'Application'):
        self.ac = None  # type: 'AsyncConnection'
        super(TxKeeper, self).__init__(app)

    async def load_genesis(self, genesis_data: bytes):
        if self.ac is None:
            self.ac = self.app.database.connect()
            await self.ac.start()
        self.app.logger.info(f'Received genesis app state with size: {len(genesis_data)}')
        cert_entities = []
        data = json.loads(genesis_data)
        hasher = self.app.csp.get_hash(csp.sha256.HashOpts())
        for pem_serialized in data['certificates']:
            cert = deserialize_certificate_from_pem_x509(pem_serialized.encode('utf8'))
            cert_entities.append(self.app.ca.make_cert_entity(cert))
            hasher.write(pem_serialized.encode('utf8'))
        await CertEntity.insert(self.ac, cert_entities)
        return hasher.sum()

    async def begin_block(self, req):
        if self.ac is None:
            self.ac = self.app.database.connect()
            await self.ac.start()
        return await super().begin_block(req)

    async def deliver_tx(self, req):
        if self.app.logger.isEnabledFor(logging.DEBUG):
            self.app.logger.debug(f'deliver_tx: {asdict(req)}')
        if req.tx.startswith(b'TX\n'):
            code, payload = await self._check_tx(req.tx[3:])
            if code == ResultCode.OK:
                if isinstance(payload, Certificate):
                    await CertEntity.insert(self.ac, [self.app.ca.make_cert_entity(payload)])
                    return ResponseDeliverTx(code=code)
                else:
                    raise TypeError('Unexpected payload')
        return ResponseDeliverTx(code=ResultCode.Error, log='Incorrect TX')

    async def commit(self, req):
        resp = await super().commit(req)
        app_hash = resp.data
        block_height = self.block_height
        if block_height == self.app.state.block_height:
            await AppState.update(self.ac, app_hash, block_height)
        await self.ac.commit()
        await self.ac.close()
        self.ac = None
        return resp
