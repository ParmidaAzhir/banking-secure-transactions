from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

fake_key = rsa.generate_private_key( #Generate fake receiver RSA public/private key pair.
    public_exponent=65537,
    key_size=2048
)

with open("keys/fake_receiver_key.pem", "wb") as f:
    f.write(
        fake_key.private_bytes( #Convert fake receiver private key into PEM bytes.
            encoding=serialization.Encoding.PEM,## Save key in PEM format
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption() ## Save key without password encryption
        )
    )

print("fake_receiver_key.pem created")
