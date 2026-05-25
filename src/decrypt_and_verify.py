import json
import base64 # #convert bytes into text so they can be saved in JSON.
import argparse
import jwt #to decode and verify JWT tokens.
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM ## Create AES decryptor and decrypt the JWT token.


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8")) #Convert text to bytes.


def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def main(packet_path: str, receiver_key_path: str, sender_cert_path: str, ca_cert_path: str) -> int:
    with open(packet_path, "r", encoding="utf-8") as f:
        packet = json.load(f) 
# Convert packet values to bytes
    encrypted_key = b64d(packet["encrypted_key"]) #encrypted AES key
    nonce = b64d(packet["nonce"])
    ciphertext = b64d(packet["ciphertext"]) #encrypted JWT

    with open(receiver_key_path, "rb") as f:
        receiver_key = serialization.load_pem_private_key(f.read(), password=None)

    try:
        aes_key = receiver_key.decrypt( #Uses receiver private key to decrypt the encrypted AES key.
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        print("INVALID: wrong receiver private key, decryption failed")
        return 1

    aesgcm = AESGCM(aes_key)  #Create AES-GCM object (here decryptor) that performs AES encryption and decryption using the AES key..
    token = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8") #Decrypts ciphertext back into JWT token text.

    sender_cert = load_certificate(sender_cert_path)
    ca_cert = load_certificate(ca_cert_path)

    try:
        ca_public_key = ca_cert.public_key() 
        ca_public_key.verify(
            sender_cert.signature,
            sender_cert.tbs_certificate_bytes, #original signed certificate data
            padding.PKCS1v15(),
            sender_cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        print("INVALID: sender certificate is not trusted or was not signed by the trusted CA")
        return 1

    public_key = sender_cert.public_key()
    decoded = jwt.decode(token, public_key, algorithms=["RS256"]) #Verifies and decodes JWT using sender public key and RS256

    print("VALID PACKET")
    print("Decoded data:", decoded)
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Decrypt and verify packet.")
    p.add_argument("packet", help="Path to encrypted packet JSON")
    p.add_argument("receiver_key", help="Path to receiver private key")
    p.add_argument("sender_cert", help="Path to sender certificate")
    p.add_argument("ca_cert", help="Path to CA certificate")
    args = p.parse_args()

    raise SystemExit(main(args.packet, args.receiver_key, args.sender_cert, args.ca_cert))
