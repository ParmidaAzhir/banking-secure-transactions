from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def save_private_key(path, key):
    with open(path, "wb") as f:
        f.write( # Write private key bytes in pem format
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
    with open("keys/ca_key.pem", "rb") as f: 
        ca_key = serialization.load_pem_private_key(f.read(), password=None) #Load CA private key

    with open("keys/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read()) #Load CA certificate

    receiver_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) #generate rsa private key

    now = datetime.now(timezone.utc)
    receiver_subject = build_name("Receiver")

    receiver_cert = (
        x509.CertificateBuilder()
        .subject_name(receiver_subject) #owner = receiver
        .issuer_name(ca_cert.subject)
        .public_key(receiver_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256()) #sign eceiver cert with
    )

    save_private_key("keys/receiver_key.pem", receiver_key)
    save_cert("keys/receiver_cert.pem", receiver_cert)

    print("receiver_key.pem and receiver_cert.pem created successfully")

if __name__ == "__main__":
    main()
