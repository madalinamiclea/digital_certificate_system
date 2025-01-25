from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
import os

# Directory to store certificates
CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

CRL_FILE = f"{CERTS_DIR}/crl.pem"

# Generate a self-signed root certificate
def generate_root_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RO"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bucharest"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyCA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MyRootCA")
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    # Save root key & certificate
    with open(f"{CERTS_DIR}/root_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"{CERTS_DIR}/root_cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Root certificate generated successfully.")

# Generate a new certificate signed by the root
def issue_certificate(common_name):
    with open(f"{CERTS_DIR}/root_key.pem", "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(f"{CERTS_DIR}/root_cert.pem", "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )
    with open(f"{CERTS_DIR}/{common_name}_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"{CERTS_DIR}/{common_name}_cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate issued for {common_name} with serial number {certificate.serial_number} and expiration {certificate.not_valid_after}.")

# Check if a certificate is expired and renew it
def renew_certificate(common_name):
    cert_path = f"{CERTS_DIR}/{common_name}_cert.pem"
    if not os.path.exists(cert_path):
        print(f"Certificate for {common_name} does not exist.")
        return
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    if cert.not_valid_after < datetime.utcnow():
        print(f"Certificate for {common_name} is expired. Renewing...")
        issue_certificate(common_name)
    else:
        print(f"Certificate for {common_name} is still valid until {cert.not_valid_after}.")

# Revoke a certificate
def revoke_certificate(serial_number):
    revoked_cert = x509.RevokedCertificateBuilder()
    revoked_cert = revoked_cert.serial_number(serial_number)
    revoked_cert = revoked_cert.revocation_date(datetime.utcnow())
    revoked_cert = revoked_cert.build()
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MyRootCA")
    ]))
    crl_builder = crl_builder.last_update(datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=30))
    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
    with open(f"{CERTS_DIR}/root_key.pem", "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)
    crl = crl_builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    with open(CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate with serial number {serial_number} revoked.")

if __name__ == "__main__":
    generate_root_certificate()
    issue_certificate("example.com")
    renew_certificate("example.com")
    revoke_certificate(123456789)  # Example serial number for revocation
