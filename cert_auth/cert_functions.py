from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import os
import ssl
import datetime
import ipaddress
from pprint import pprint


def get_key_bytes(key):
    return key.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption())


def get_cert_bytes(cert):
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def get_csr_bytes(csr):
    return csr.public_bytes(encoding=serialization.Encoding.PEM)


def save_key(key, path, passphrase):
    # Write our key to disk for safe keeping
    if isinstance(key, rsa.RSAPrivateKey):
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8')),
            ))


def load_key(path, passphrase):
    if os.path.isfile(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), passphrase.encode('utf-8'), default_backend())
        return key


def save_cert(cert, path):
    # Write our certificate out to disk.
    if isinstance(cert, x509.Certificate):
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path):
    if os.path.isfile(path):
        with open(path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert


def save_csr(csr, path):
    if isinstance(csr, x509.CertificateSigningRequest):
        with open(path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))


def load_csr(path):
    try:
        with open(path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())
        return csr
    except FileNotFoundError:
        print(f'CSR File {path} Not Found')
        exit(1)


def create_key(length=2048):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=length,
        backend=default_backend()
    )
    return key


def create_cert(ca_key,
                ca_cert=None,
                csr=None,
                lifetime=365,
                country_name=None,
                state_or_province=None,
                locality=None,
                organisation=None,
                common_name=None,
                dns_list=None,
                ip_list=None,
                is_ca=False):
    # generate Subject Alternate Name list
    san_list = []

    if isinstance(csr, x509.CertificateSigningRequest):
        san_list = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    else:
        if dns_list:
            for san in dns_list:
                san_list.append(x509.DNSName(san))
        if ip_list:
            for ip in ip_list:
                ipv4 = ipaddress.ip_address(ip)
                san_list.append(x509.IPAddress(ipv4))

    # generate SubjectName list
    sn_list = []
    if isinstance(csr, x509.CertificateSigningRequest):
        sn_list = csr.subject
    else:
        if country_name:
            sn_list.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_name))
        if state_or_province:
            sn_list.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province))
        if locality:
            sn_list.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organisation:
            sn_list.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation))
        if common_name:
            sn_list.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    # Key Usage
    if is_ca:
        key_usage = x509.KeyUsage(digital_signature=False,
                                  content_commitment=False,
                                  key_encipherment=False,
                                  data_encipherment=False,
                                  key_agreement=False,
                                  key_cert_sign=True,
                                  crl_sign=True,
                                  encipher_only=False,
                                  decipher_only=False)
    else:
        key_usage = x509.KeyUsage(digital_signature=False,
                                  content_commitment=False,
                                  key_encipherment=False,
                                  data_encipherment=False,
                                  key_agreement=True,
                                  key_cert_sign=False,
                                  crl_sign=False,
                                  encipher_only=False,
                                  decipher_only=False)

    if isinstance(ca_cert, x509.Certificate) and isinstance(csr, x509.CertificateSigningRequest):
        if ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            subject = x509.Name(csr.subject)
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.issuer
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=lifetime)
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False
            ).add_extension(
                key_usage,
                critical=True
            ).add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None),
                critical=True
            ).add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            ).sign(ca_key, hashes.SHA256(), default_backend())
            return cert
    elif ca_cert is None:
        # If CA Cert and CSR is not presented, then generate a Self Signed Cert
        subject = issuer = x509.Name(sn_list)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 years
            datetime.datetime.utcnow() + datetime.timedelta(days=lifetime)
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        ).add_extension(
            key_usage,
            critical=True
        ).add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True
        ).add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        ).sign(ca_key, hashes.SHA256(), default_backend())
        # Sign our certificate with our private key
        return cert
    else:
        raise ValueError("Something went wrong with the values passed")


def create_csr(key,
               country_name="GB",
               state_or_province=None,
               locality=None,
               organisation=None,
               common_name=None,
               dns_list=None,
               ip_list=None,
               is_ca=False):
    # generate Subject Alternate Name list
    san_list = []
    if dns_list:
        for san in dns_list:
            san_list.append(x509.DNSName(san))
    if ip_list:
        for ip in ip_list:
            ipv4 = ipaddress.ip_address(ip)
            san_list.append(x509.IPAddress(ipv4))

    sn_list = []
    if country_name:
        sn_list.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_name))
    if state_or_province:
        sn_list.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province))
    if locality:
        sn_list.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organisation:
        sn_list.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation))
    if common_name:
        sn_list.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(sn_list)
                                                               ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None), critical=True,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    return csr


def get_cert_expiry(cert):
    return cert.not_valid_after


def get_host_cert(hostname, port):
    try:
        cert_str = ssl.get_server_certificate((hostname, port))
        cert = x509.load_pem_x509_certificate(cert_str.encode('utf-8'), default_backend())
        assert isinstance(cert, x509.Certificate)
        return cert
    except ValueError as e:
        print(f"Cert Error: {e}")


def get_authority_key_identifier(cert: x509.Certificate) -> bytes:
    return cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier


def cert_is_issued_by(cert, ca_cert):
    try:
        # check Authority Key Identifier matches issuing certs Subject Key Identifier
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier == ca_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    except x509.extensions.ExtensionNotFound:
        return False


def generate_host_keypair(hostname, ca_key, ca_cert, domainname='testdomain.com'):
    host_ssl = dict()
    subject = dict()
    if len(ca_cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)) > 0:
        subject['country_name'] = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value
    if len(ca_cert.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)) > 0:
        subject['state_or_province'] = ca_cert.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[
            0].value
    if len(ca_cert.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)) > 0:
        subject['locality'] = ca_cert.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value
    if len(ca_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)) > 0:
        subject['organisation'] = ca_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
    subject['common_name'] = hostname
    if len(hostname.split('.')) > 1:
        subject['dns_list'] = [hostname]
    elif len(hostname.split('.')) == 1:
        subject['dns_list'] = [f'{hostname}.{domainname}']
    else:
        raise ValueError(f'Hostname: {hostname} possibly in incorrect format')

    host_ssl['key'] = create_key()
    csr = create_csr(host_ssl['key'], **subject, is_ca=False)
    host_ssl['cert'] = create_cert(ca_key=ca_key, ca_cert=ca_cert, csr=csr, is_ca=False)
    host_ssl['key_bytes'] = get_key_bytes(host_ssl['key'])
    host_ssl['cert_bytes'] = get_cert_bytes(host_ssl['cert'])
    return host_ssl


def main():
    ca_key = create_key(2048)
    ca_csr = create_csr(ca_key, common_name='ca.localdomain', is_ca=True)
    ca_cert = create_cert(ca_key, csr=ca_csr, is_ca=True)
    save_key(ca_key, './tests/tmp/ca_test_key.pem', 'wibble')
    save_cert(ca_cert, './tests/tmp/ca_test_cert.pem')

    ca_key = load_key('./tests/tmp/ca_test_key.pem', 'wibble')
    ca_cert = load_cert('./tests/tmp/ca_test_cert.pem')

    key = create_key()
    save_key(key, './tests/tmp/test_host1_key.pem', 'wibble')
    dns_list = ["host1.otherdomain", "www.otherdomain"]
    ip_list = ['192.168.1.100', "192.168.1.101"]
    csr = create_csr(key, common_name='host1.localdomain', dns_list=dns_list, ip_list=ip_list)
    cert = create_cert(ca_key, ca_cert, csr)
    save_cert(cert, './tests/tmp/host1_cert.pem')


if __name__ == '__main__':
    main()
