import pytest
from cryptography import x509

from csp import ed25519
from csp.provider import CSProvider

from dpki.x509cert import create_csr, apply_csr, template as t


@pytest.fixture
def ca_root_pair():
    csp = CSProvider()
    key = csp.key_gen(ed25519.KeyOpts())
    subject = "CN=Root Wonderland CA, C=WN"
    csr = create_csr(subject, key, template=t.CA, path_length=7)
    cert = apply_csr(csr, (csr, key), not_valid_after='2030-01-01')
    yield cert, key


@pytest.fixture
def ca_first_pair():
    csp = CSProvider()
    key = csp.key_gen(ed25519.KeyOpts())
    subject = "CN=First Wonderland CA, OU=Data center, C=WN, O=The Corporation"
    csr = create_csr(subject, key, template=t.CA, path_length=7)
    return csr, key


@pytest.fixture
def ca_cats_pair():
    csp = CSProvider()
    key = csp.key_gen(ed25519.KeyOpts())
    subject = "CN=CA controlled by Cheshire Cat, STREET=Cat's house, L=Cheshire, C=WN"
    csr = create_csr(subject, key, template=t.CA, path_length=5)
    return csr, key
