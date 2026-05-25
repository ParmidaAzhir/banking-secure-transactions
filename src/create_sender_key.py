from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization

# generate rsa private key
private_key = rsa.generate_private_key(  
    public_exponent=65537, #mathematical value required by the RSA algorithm
    key_size=2048
    #Key size defines the strength of the key. 2048 bits is a secure standard.
)

# save
with open("keys/sender_key.pem", "wb") as f: #Open sender_key.pem
    f.write( # Write the private key bytes into the PEM file.
        private_key.private_bytes( 
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL, #defines the private key format as Traditional OpenSSL
            encryption_algorithm=serialization.NoEncryption()
        )
    )

print("sender_key created")
