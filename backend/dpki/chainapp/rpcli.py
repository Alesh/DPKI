from typing import TYPE_CHECKING
import json
import httpx

from dpki.x509cert.utils import serialize_certificate_to_pem_x509, serialize_csr_to_pem_x509

if TYPE_CHECKING:
    from typing import Tuple, Union
    from tend.abci.handlers import ResultCode
    from cryptography.x509 import Certificate, CertificateSigningRequest

    CheckerResult = Tuple[ResultCode | int, Union[str, None]]


class Client:
    """ RPC client wrapper
    """

    def __init__(self, rpc_laddr: str):
        self.base_url = f'http://{rpc_laddr.split("//")[1]}'

    async def query(self, path, data=None):
        if data is not None:
            if isinstance(data, bytes):
                data = '0x' + data.hex().upper()
            data = f'"{data}"'
        else:
            data = ''
        r = httpx.post(f'{self.base_url}/abci_query', data=dict(path=f'"{path}"', data=data))
        if r.is_error:
            raise RuntimeError('Cannot send TX')
        result = json.loads(r.content)['result']['response']
        code = result['code']
        payload = (result.get('value') if code == 0 else result.get('log', None)) or None
        return code, payload

    async def send_scr_nx(self, csr: 'CertificateSigningRequest') -> 'CheckerResult':
        return await self._check_tx(b'NX\n' + serialize_csr_to_pem_x509(csr))

    async def send_cert_tx(self, cert: 'Certificate') -> 'CheckerResult':
        return await self._send_tx(b'TX\n' + serialize_certificate_to_pem_x509(cert))

    async def _check_tx(self, tx: bytes) -> 'CheckerResult':
        r = httpx.post(f'{self.base_url}/check_tx', data=dict(tx='0x' + tx.hex()))
        if r.is_error:
            raise RuntimeError('Cannot send TX')
        result = json.loads(r.content)['result']
        return result['code'], (result.get('log', None) or None)

    async def _send_tx(self, tx: bytes) -> 'CheckerResult':
        r = httpx.post(f'{self.base_url}/broadcast_tx_async', data=dict(tx='0x' + tx.hex()))
        if r.is_error:
            raise RuntimeError('Cannot send TX')
        result = json.loads(r.content)['result']
        return result['code'], (result.get('log', None) or None)
