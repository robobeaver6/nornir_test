"""
Tests for CA functionality
"""
import pytest
# import cert_auth.cert_functions as cry
from cert_auth import cert_functions as cry
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from datetime import datetime


key_usage = {"IS_CA": x509.KeyUsage(digital_signature=False,
                                    content_commitment=False,
                                    key_encipherment=False,
                                    data_encipherment=False,
                                    key_agreement=False,
                                    key_cert_sign=True,
                                    crl_sign=True,
                                    encipher_only=False,
                                    decipher_only=False),
             "Key Establishment": x509.KeyUsage(digital_signature=False,
                                                content_commitment=False,
                                                key_encipherment=False,
                                                data_encipherment=False,
                                                key_agreement=True,
                                                key_cert_sign=False,
                                                crl_sign=False,
                                                encipher_only=False,
                                                decipher_only=False),
             "Signature": x509.KeyUsage(digital_signature=True,
                                        content_commitment=True,
                                        key_encipherment=False,
                                        data_encipherment=False,
                                        key_agreement=False,
                                        key_cert_sign=False,
                                        crl_sign=False,
                                        encipher_only=False,
                                        decipher_only=False)}


@pytest.fixture(scope='module')
def cert_parameters():
    cert_params = []
    for i in range(0, 5):
        cert_params.append({'country_name': 'GB',
                            'state_or_province': 'State',
                            'locality': 'Identity',
                            'organisation': 'Organisation',
                            'common_name': f'Common Name {i}',
                            'dns_list': [f'www.name{i}.com', f'www{i}.name.com'],
                            'ip_list': [f'192.168.1.{i}', f'10.1.1.{i}']}
                           )
    return cert_params


@pytest.fixture(scope='module')
def root_ca_key():
    key = cry.create_key(2048)
    return key


@pytest.fixture(scope='module')
def root_ca_csr(root_ca_key, cert_parameters):
    csr = cry.create_csr(key=root_ca_key, is_ca=True, **cert_parameters[0])
    return csr


@pytest.fixture(scope='module')
def root_ca_cert(root_ca_key, root_ca_csr, cert_parameters):
    cert = cry.create_cert(root_ca_key, csr=root_ca_csr,
                           **cert_parameters[0],
                           is_ca=True)
    return cert


@pytest.fixture(scope='module')
def ra_key():
    key = cry.create_key(2048)
    return key


@pytest.fixture(scope='module')
def ra_csr(ra_key, cert_parameters):
    csr = cry.create_csr(key=ra_key, is_ca=True, **cert_parameters[1])
    return csr


@pytest.fixture(scope='module')
def ra_cert(root_ca_key, root_ca_cert, ra_csr, cert_parameters):
    cert = cry.create_cert(ca_key=root_ca_key,
                           ca_cert=root_ca_cert,
                           csr=ra_csr,
                           **cert_parameters[1],
                           is_ca=True)
    return cert


@pytest.fixture(scope='module')
def user_key():
    key = cry.create_key(2048)
    return key


@pytest.fixture(scope='module')
def user_csr(user_key, cert_parameters):
    csr = cry.create_csr(key=user_key, is_ca=False, **cert_parameters[2])
    return csr


@pytest.fixture(scope='module')
def user_cert(ra_key, ra_cert, user_csr, cert_parameters):
    cert = cry.create_cert(ra_key, ra_cert, user_csr,
                           **cert_parameters[2],
                           is_ca=False)
    return cert


def test_create_key():
    key = cry.create_key(2048)
    assert isinstance(key, rsa.RSAPrivateKey)


def test_create_csr(root_ca_csr):
    assert isinstance(root_ca_csr, x509.CertificateSigningRequest)


def test_create_self_signed_cert_with_csr(cert_parameters):
    key = cry.create_key(2048)
    csr = cry.create_csr(key, **cert_parameters[0])
    cert = cry.create_cert(key, csr=csr)
    assert isinstance(cert, x509.Certificate)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_create_self_signed_cert_without_csr(cert_parameters):
    key = cry.create_key(2048)
    cert = cry.create_cert(key, **cert_parameters[0])
    assert isinstance(cert, x509.Certificate)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_create_self_signed_cert_no_parameters(cert_parameters):
    key = cry.create_key(2048)
    cert = cry.create_cert(key)
    assert isinstance(cert, x509.Certificate)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


class TestCreateRootCA:
    def test_create(self, root_ca_cert):
        assert isinstance(root_ca_cert, x509.Certificate)

    def test_subject_key_identifier(self, root_ca_key, root_ca_cert):
        # test SubjectKeyIdentifier
        assert root_ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value.digest == x509.SubjectKeyIdentifier.from_public_key(
            root_ca_key.public_key()).digest

    def test_key_usage(self, root_ca_cert):
        # Test Key Usage
        assert root_ca_cert.extensions.get_extension_for_class(x509.KeyUsage).critical is True
        assert key_usage["IS_CA"] == root_ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value

    def test_basic_constraints(self, root_ca_cert):
        # Test BasicConstraints
        assert root_ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
        assert root_ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).critical is True

    def test_no_authority_key_identifier(self, root_ca_cert):
        with pytest.raises(x509.extensions.ExtensionNotFound):
            assert root_ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier) is None


class TestCreateRA:
    def test_create_ra_csr(self, ra_csr):
        assert isinstance(ra_csr, x509.CertificateSigningRequest)

    def test_create_ra_cert(self, ra_cert):
        assert isinstance(ra_cert, x509.Certificate)

    def test_authority_key_identifier(self, root_ca_key, ra_cert):
        # test SubjectKeyIdentifier
        assert ra_cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value.key_identifier == x509.AuthorityKeyIdentifier.from_issuer_public_key(
            root_ca_key.public_key()).key_identifier

    def test_subject_key_identifier(self, ra_cert, ra_key):
        assert ra_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value.digest == x509.SubjectKeyIdentifier.from_public_key(
            ra_key.public_key()).digest

    def test_key_usage(self, ra_cert):
        # Test Key Usage
        assert ra_cert.extensions.get_extension_for_class(x509.KeyUsage).critical is True
        assert key_usage["IS_CA"] == ra_cert.extensions.get_extension_for_class(x509.KeyUsage).value

    def test_basic_constraints(self, ra_cert):
        # Test BasicConstraints
        assert ra_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
        assert ra_cert.extensions.get_extension_for_class(x509.BasicConstraints).critical is True


class TestCreateEndUserKeyEstablishmentCert:
    def test_create_user_csr(self, user_csr):
        assert isinstance(user_csr, x509.CertificateSigningRequest)

    def test_create_user_cert(self, user_cert):
        assert isinstance(user_cert, x509.Certificate)

    def test_authority_key_identifier(self, ra_key, user_cert):
        assert user_cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier).value.key_identifier == x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ra_key.public_key()).key_identifier

    def test_subject_key_identifier(self, user_cert, user_key):
        assert user_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value.digest == x509.SubjectKeyIdentifier.from_public_key(
            user_key.public_key()).digest

    def test_key_usage(self, user_cert):
        # Test Key Usage
        assert user_cert.extensions.get_extension_for_class(x509.KeyUsage).critical is True
        assert key_usage["Key Establishment"] == user_cert.extensions.get_extension_for_class(x509.KeyUsage).value

    def test_basic_constraints(self, user_cert):
        # Test BasicConstraints
        assert user_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
        assert user_cert.extensions.get_extension_for_class(x509.BasicConstraints).critical is True


def test_save_and_load_key(root_ca_key):
    passphrase = "Shit Passowrd"
    path = "tests/tmp/test_save_key.pem"
    cry.save_key(root_ca_key, path, passphrase)
    key2 = cry.load_key(path, passphrase)
    assert cry.get_key_bytes(root_ca_key) == cry.get_key_bytes(key2)


def test_save_and_load_csr(ra_csr):
    path = "tests/tmp/test_save_csr.pem"
    cry.save_csr(ra_csr, path)
    key2 = cry.load_csr(path)
    assert cry.get_csr_bytes(ra_csr) == cry.get_csr_bytes(key2)


def test_save_and_load_cert(root_ca_cert):
    # save cert for inspection with openssl
    path = "tests/tmp/test_save_ca_cert.pem"
    cry.save_cert(root_ca_cert, path)
    key2 = cry.load_cert(path)
    assert cry.get_cert_bytes(root_ca_cert) == cry.get_cert_bytes(key2)


def test_save_and_load_ra_cert(ra_cert):
    # save cert for inspection with openssl
    path = "tests/tmp/test_save_ra_cert.pem"
    cry.save_cert(ra_cert, path)
    key2 = cry.load_cert(path)
    assert cry.get_cert_bytes(ra_cert) == cry.get_cert_bytes(key2)


def test_save_and_load_user_cert(user_cert):
    # save cert for inspection with openssl
    path = "tests/tmp/test_save_user_cert.pem"
    cry.save_cert(user_cert, path)
    key2 = cry.load_cert(path)
    assert cry.get_cert_bytes(user_cert) == cry.get_cert_bytes(key2)


def test_get_cert_expiry(user_cert):
    assert isinstance(user_cert.not_valid_after, datetime)


def test_get_host_cert():
    assert isinstance(cry.get_host_cert('www.bbc.com', 443), x509.Certificate)


def test_cert_is_issued_by(user_cert, ra_cert):
    assert cry.cert_is_issued_by(user_cert, ra_cert) is True


def test_generate_host_key_pair(root_ca_key, root_ca_cert):
    hostname = 'test-hostname'
    host = cry.generate_host_keypair(hostname, root_ca_key, root_ca_cert)
    assert isinstance(host['key'], rsa.RSAPrivateKey)
    assert isinstance(host['cert'], x509.Certificate)
    assert host['cert'].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == hostname
