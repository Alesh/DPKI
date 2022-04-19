import asyncio
from datetime import date, timedelta, timezone
from typing import TYPE_CHECKING, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate, CertificateSigningRequest

from csp.base import Key
from csp.provider import CSProvider
from dpki.database.repository import CertEntity
from dpki.utils import Service
from dpki.x509cert import apply_csr
from dpki.x509cert import template
from names import DistinguishedName, Hierarchy
from .. import x509cert

if TYPE_CHECKING:
    from logging import Logger
    from . import Application


class CAService(Service):
    """ Certificate authority service
    """

    def __init__(self, app: 'Application', key: Optional['Key'], config: dict, logger: 'Logger' = None, ):
        super().__init__(logger)
        self.app = app
        self.config = config
        self.__chain = []
        self.__key = key

    @property
    def cert(self) -> 'Optional[Certificate]':
        """ CA cert if present """
        return self.__chain[0] if self.__key else None

    @property
    def root(self) -> 'Certificate':
        """ CA root cert """
        return self.__chain[-1]

    async def initialize(self) -> str | None:
        """ Tries to initialize. """
        result = None
        async with self.app.database.begin() as ac:
            public_key = bytes(self.__key.public_key)
            pem_serialized = await CertEntity.get_by_public_key(ac, public_key)
            if pem_serialized:  # if CA cert present
                cert = x509.load_pem_x509_certificate(pem_serialized.encode('utf8'))
                result = cert.subject.rfc4514_string()
                self.__chain.append(cert)
                while cert.subject.public_bytes() != cert.issuer.public_bytes():  # load CA certificate chain
                    pem_serialized = await CertEntity.get_by_subject(ac, cert.issuer.rfc4514_string())
                    if pem_serialized:
                        cert = x509.load_pem_x509_certificate(pem_serialized.encode('utf8'))
                        self.__chain.append(cert)
            else:
                result = await CertEntity.list_by_role(ac, 'CA Root', 1)
                if result:
                    self.__chain.append(x509.load_pem_x509_certificate(result[0].pem_serialized.encode('utf8')))
                else:
                    raise RuntimeError('Not found active CA root cert')
        return result

    async def check_csr_and_try_apply(self, csr_pem: bytes) -> tuple[bool, str | None]:
        """ Checks certificate signing request, and try to start issuing process
        """
        csp = CSProvider()
        csr = x509.load_pem_x509_csr(csr_pem)
        if csr.is_signature_valid and x509cert.template.matches_to(csr):
            pub = csp.key_import(csr.public_key())
            async with self.app.database.begin() as ac:
                if pem_serialized := await CertEntity.get_by_subject(ac, csr.subject.rfc4514_string()):
                    found = x509.load_pem_x509_certificate(pem_serialized.encode('utf8'))
                    found_pub = csp.key_import(found.public_key())
                    if found_pub == pub:
                        return False, 'Certificate already exists'
                    else:
                        return False, 'Certificate for given subject already issued for an other public key'
            if self.cert: # tries to issue
                cert_dn = DistinguishedName(self.cert.subject.rfc4514_string())
                csr_dn = DistinguishedName(csr.subject.rfc4514_string())
                if str(csr_dn) in self.tasks:
                    return False, 'CSR already in issue process'
                distance = cert_dn.max_distance(csr_dn)
                if distance > 0:
                    self.create_task(self._issue_csr(csr, (distance - 1) * self.config['waiting_for_downstream']),
                                     cid=csr.subject.rfc4514_string())
            return True, None
        return False, 'Wrong CSR'

    async def check_certificate(self, cert_pem: bytes) -> tuple[bool, Union[str, 'Certificate']]:
        """ Checks certificate PEM from transaction
        """
        csp = CSProvider()
        cert = x509.load_pem_x509_certificate(cert_pem)
        pub = csp.key_import(cert.public_key())
        if x509cert.template.matches_to(cert):
            async with self.app.database.begin() as ac:
                if pem_serialized := await CertEntity.get_by_subject(ac, cert.subject.rfc4514_string()):
                    found = x509.load_pem_x509_certificate(pem_serialized.encode('utf8'))
                    found_pub = csp.key_import(found.public_key())
                    if found_pub == pub:
                        return False, 'Certificate already exists'
                    else:
                        return False, 'Certificate for given subject already issued for an other public key'
                if not await CertEntity.get_by_subject(ac, cert.issuer.rfc4514_string()):
                    return False, 'Certificate issuer not found'
            return True, cert
        return False, 'Wrong Certificate'

    def make_cert_entity(self, cert: 'Certificate') -> 'CertEntity':
        not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        pem_serialized = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf8')
        tmpl = template.matches_to(cert)
        if tmpl == template.CA:
            if cert.issuer.rfc4514_string() == cert.subject.rfc4514_string():
                role = 'Root CA'
            else:
                role = 'CA'
        elif tmpl:
            role = tmpl.__name__
        else:
            role = None
        subject = DistinguishedName(cert.subject.rfc4514_string())
        return CertEntity(sn=bytes.fromhex('{0:040X}'.format(cert.serial_number)),
                          subject_name=str(subject), role=role,
                          public_key=bytes(self.app.csp.key_import(cert.public_key())), pem_serialized=pem_serialized,
                          not_valid_before=not_valid_before, not_valid_after=not_valid_after)

    async def _issue_csr(self, csr: 'CertificateSigningRequest', pre_timeout: int):
        await asyncio.sleep(pre_timeout)
        tmpl = template.matches_to(csr)
        if tmpl == template.CA:
            valid_for = self.config['ca_valid_for']
        elif tmpl == template.Host:
            valid_for = self.config['host_valid_for']
        elif tmpl == template.User:
            valid_for = self.config['host_valid_for']
        else:
            raise RuntimeError('Unexpected template')
        not_valid_after = date.today() + timedelta(days=valid_for)
        cert = apply_csr(csr, (self.cert, self.__key), not_valid_after=not_valid_after)
        await self.app.client.send_cert_tx(cert)
