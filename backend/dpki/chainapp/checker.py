from enum import IntEnum
from typing import TYPE_CHECKING

import tend.abci.ext
from cryptography.x509 import CertificateSigningRequest, Certificate
from tend import abci
from tend.abci.handlers import ResponseCheckTx


class ResultCode(IntEnum):
    """ ABCI result codes enum
    """
    OK = 0
    Error = 1
    Accepted = 100


if TYPE_CHECKING:
    from typing import Union, Tuple
    from . import Application

    CheckerResult = Tuple[ResultCode | int, Union[str, None, Certificate]]


class CheckerMixin:
    app: 'Application'

    async def _apply_nx(self, tx: bytes) -> 'CheckerResult':
        """ Applies mempool notification """
        if tx.startswith(b'-----BEGIN CERTIFICATE REQUEST-----'):
            result, payload = await self.app.ca.check_csr_and_try_apply(tx)
            return ResultCode.Accepted if result else ResultCode.Error, payload
        return ResultCode.Error, 'Unknown mempool notification'

    async def _check_tx(self, tx: bytes) -> 'CheckerResult':
        """ Checks transaction """
        if tx.startswith(b'-----BEGIN CERTIFICATE-----'):
            result, payload = await self.app.ca.check_certificate(tx)
            return ResultCode.OK if result else ResultCode.Error, payload
        return ResultCode.Error, 'Unknown transaction type'


class TxChecker(abci.ext.TxChecker, CheckerMixin):
    """ TX checker
    """
    app: 'Application'

    def __init__(self, app: 'Application'):
        super(TxChecker, self).__init__(app)

    async def check_tx(self, req):
        """ ABCI method that checks transaction """
        if req.tx.startswith(b'NX\n'):
            code, log = await self._apply_nx(req.tx[3:])
        elif req.tx.startswith(b'TX\n'):
            code, log = await self._check_tx(req.tx[3:])
        else:
            code, log = ResultCode.Error, 'Incorrect TX'
        if code == ResultCode.OK:
            return ResponseCheckTx(code=code)
        return ResponseCheckTx(code=code, log=log)
