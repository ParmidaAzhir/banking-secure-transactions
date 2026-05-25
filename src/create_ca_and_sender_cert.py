from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID #defines standard certificate identity fields
from cryptography.hazmat.primitives import hashes, serialization #save/load pem files
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
    # Create CA private key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create CA certificate
    ca_subject = build_name("Project CA")
    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder() 
        .subject_name(ca_subject) #owner = ca
        .issuer_name(ca_subject) #issuer (self)
        .public_key(ca_key.public_key()) #Adds CA public key.
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) #Marks this certificate as a CA certificate.
        .sign(ca_key, hashes.SHA256()) #Signs CA certificate using CA private key (self) and sha256
    )

   # Open the sender private key file and load the PEM private key.
    with open("keys/sender_key.pem", "rb") as f:
        sender_key = serialization.load_pem_private_key(f.read(), password=None)

    # Create sender certificate signed by CA
    sender_subject = build_name("Sender")
    sender_cert = (
        x509.CertificateBuilder()
        .subject_name(sender_subject)
        .issuer_name(ca_cert.subject)
        .public_key(sender_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) # not ca
        .sign(ca_key, hashes.SHA256()) #Signs the sender certificate using the CA private key and SHA256.
    )

    save_private_key("keys/ca_key.pem", ca_key) #save ca_key in keys/ca_key.pem
    save_cert("keys/ca_cert.pem", ca_cert)
    save_cert("keys/sender_cert.pem", sender_cert)

    print("ca_key.pem, ca_cert.pem, and sender_cert.pem created successfully")

if __name__ == "__main__":
    main()
