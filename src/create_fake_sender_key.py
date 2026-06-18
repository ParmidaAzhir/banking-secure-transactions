from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

fake_key = rsa.generate_private_key( 
    public_exponent=65537,
    key_size=2048
)

with open("keys/fake_sender_key.pem", "wb") as f:
    f.write(
        fake_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

print("fake_sender_key.pem created")