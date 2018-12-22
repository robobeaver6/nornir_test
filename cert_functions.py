from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import datetime
import ipaddress


def create_key(length=2048):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=length,
        backend=default_backend()
    )
    return key


def save_key(key, path, passphrase):
    # Write our key to disk for safe keeping
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8')),
        ))


def load_key(path, passphrase):
    if os.path.isfile(path):
        ca_key = crypto.load_key(CA_KEY_PATH, ca_passphrase)
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), passphrase.encode('utf-8'), default_backend())
    return key


def cry_create_self_signed_cert(key,
                                country_name="GB",
                                state_or_province=None,
                                locality=None,
                                organisation=None,
                                common_name=None,
                                dns_list=[],
                                ip_list=[]):
    # generate Subject Alternate Name list
    san_list = []
    for san in dns_list:
        san_list.append(x509.DNSName(san))
    for ip in ip_list:
        san_list.append(x509.IPAddress(ip))

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

    # subject and issuer are always the same.
    subject = issuer = x509.Name(sn_list)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
        # Sign our certificate with our private key
    ).sign(key, hashes.SHA256(), default_backend())
    return cert


def create_cert(csr,
                ca_key,
                ca_cert,
                lifetime=365,
                country_name="GB",
                state_or_province=None,
                locality=None,
                organisation=None,
                common_name=None,
                dns_list=[],
                ip_list=[]):
    # generate Subject Alternate Name list
    san_list = []
    for san in dns_list:
        san_list.append(x509.DNSName(san))
    for ip in ip_list:
        san_list.append(x509.IPAddress(ip))

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

    # subject and issuer are always the same.
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
        x509.SubjectAlternativeName(csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value),
        critical=False,
        # Sign our certificate with our private key
    ).sign(ca_key, hashes.SHA256(), default_backend())
    return cert


def save_cert(cert, path):
    # Write our certificate out to disk.
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path):
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert


def create_csr(key,
               country_name="GB",
               state_or_province=None,
               locality=None,
               organisation=None,
               common_name=None,
               dns_list=[],
               ip_list=[]):
    # generate Subject Alternate Name list
    san_list = []
    for san in dns_list:
        san_list.append(x509.DNSName(san))
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
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    return csr


def save_csr(csr, path):
    # Write our CSR out to disk.
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def main():
    # ca_key = cry_create_key(2048)
    # cry_save_key(ca_key, './certs/ca_key.pem', 'wibble')
    # ca_cert = cry_create_self_signed_cert(ca_key, common_name='ca.localdomain')
    # cry_save_cert(ca_cert, './certs/ca_cert.pem')

    ca_key = load_key('./certs/ca_key.pem', 'wibble')
    ca_cert = load_cert('./certs/ca_cert.pem')

    key = create_key()
    save_key(key, './certs/host3_key.pem', 'wibble')
    dns_list = ["host3.otherdomain", "www.otherdomain"]
    ip_list = ['192.168.1.100', "192.168.1.101"]
    csr = create_csr(key, common_name='host3.localdomain', dns_list=dns_list, ip_list=ip_list)
    # csr = cry_create_csr(key, common_name='host3.localdomain')
    cert = create_cert(csr, ca_key, ca_cert)
    save_cert(cert, './certs/host3_cert.pem')



if __name__ == '__main__':
    main()
