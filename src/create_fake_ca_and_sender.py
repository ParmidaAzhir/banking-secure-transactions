from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def save_private_key(path, key):
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

def save_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def build_name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Data Prevention"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

def main():
    now = datetime.now(timezone.utc)

    fake_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) 
    fake_ca_subject = build_name("Fake CA")

    fake_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(fake_ca_subject)
        .issuer_name(fake_ca_subject)
        .public_key(fake_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(fake_ca_key, hashes.SHA256())
    )

    fake_sender_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) 
    fake_sender_subject = build_name("Fake Sender")

    fake_sender_cert = (
        x509.CertificateBuilder()
        .subject_name(fake_sender_subject)
        .issuer_name(fake_ca_cert.subject)
        .public_key(fake_sender_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(fake_ca_key, hashes.SHA256())
    )

    save_private_key("keys/fake_ca_key.pem", fake_ca_key)
    save_cert("keys/fake_ca_cert.pem", fake_ca_cert)

    save_private_key("keys/fake_sender_key.pem", fake_sender_key)
    save_cert("keys/fake_sender_cert.pem", fake_sender_cert)

    print("Fake CA and fake sender files created successfully")

if __name__ == "__main__":
    main()