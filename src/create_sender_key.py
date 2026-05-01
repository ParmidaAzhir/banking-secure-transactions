from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# generate private key
private_key = rsa.generate_private_key(   #This line creates a new private key using the RSA algorithm.
    public_exponent=65537,
    key_size=2048
    #Key size defines the strength of the key. 2048 bits is a secure standard.
)

# save
with open("keys/sender_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

print("sender_key created")