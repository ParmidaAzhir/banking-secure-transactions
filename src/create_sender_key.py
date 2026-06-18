from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization

# generate rsa private key
private_key = rsa.generate_private_key(  
    public_exponent=65537, 
    key_size=2048
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