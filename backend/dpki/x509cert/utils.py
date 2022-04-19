from datetime import date, datetime, time
from typing import TYPE_CHECKING, Type

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from names import DistinguishedName
from dpki.x509cert.template import Template

if TYPE_CHECKING:
    from csp.base import Key
    from cryptography.x509 import CertificateSigningRequestBuilder, CertificateBuilder, \
        CertificateSigningRequest, Certificate

    SubjectName = str | 'DistinguishedName'
    CommonBuilder = CertificateSigningRequestBuilder | CertificateBuilder
    IssuerPair = tuple[Certificate | CertificateSigningRequest, Key]


def create_csr(subject_name: 'SubjectName', key: 'Key',
               template: Template | Type[Template], **kwargs) -> 'CertificateSigningRequest':
    """ Creates certificate signing request (CSR) """
    subject_name = DistinguishedName(subject_name) if isinstance(subject_name, str) else subject_name
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name.from_rfc4514_string(str(subject_name)))
    builder = template.apply(builder, subject_name, **kwargs)
    return builder.sign(private_key=key.raw, algorithm=None, backend=default_backend())


def apply_csr(csr: 'CertificateSigningRequest', issuer_pair: 'IssuerPair',
              not_valid_after: date | str, not_valid_before: date | str = None) -> 'Certificate':
    """ Create and sings certificate based on CSR """

    def normalize_if_str(value):
        return date.fromisoformat(value) if isinstance(value, str) else value

    issuer, key = issuer_pair
    not_valid_after = datetime.combine(normalize_if_str(not_valid_after), time(23, 59, 59))
    not_valid_before = datetime.combine(normalize_if_str(not_valid_before) or date.today(), time(0, 0, 0))
    builder = x509.CertificateBuilder(subject_name=csr.subject,
                                      extensions=list(csr.extensions),
                                      public_key=csr.public_key()) \
        .issuer_name(issuer.subject) \
        .not_valid_before(not_valid_before).not_valid_after(not_valid_after) \
        .serial_number(x509.random_serial_number())
    return builder.sign(private_key=key.raw, algorithm=None, backend=default_backend())


def deserialize_certificate_from_pem_x509(pem_serialized: bytes) -> 'Certificate':
    """ Deserializes PEM representation of x.509 certificate """
    return x509.load_pem_x509_certificate(pem_serialized, backend=default_backend())


def serialize_certificate_to_pem_x509(cert: 'Certificate') -> bytes:
    """ Serializes x.509 certificate to PEM representation  """
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def deserialize_csr_from_pem_x509(pem_serialized: bytes) -> 'CertificateSigningRequest':
    """ Deserializes PEM representation of x.509 certificate signing request """
    return x509.load_pem_x509_csr(pem_serialized, backend=default_backend())


def serialize_csr_to_pem_x509(csr: 'CertificateSigningRequest') -> bytes:
    """ Serializes x.509 certificate signing request to PEM representation  """
    return csr.public_bytes(encoding=serialization.Encoding.PEM)
