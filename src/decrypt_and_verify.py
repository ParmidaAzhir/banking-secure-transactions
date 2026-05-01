import json
import base64
import argparse
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))

def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def main(packet_path: str, receiver_key_path: str, sender_cert_path: str, ca_cert_path: str):
    with open(packet_path, "r", encoding="utf-8") as f:
        packet = json.load(f)

    encrypted_key = b64d(packet["encrypted_key"])
    nonce = b64d(packet["nonce"])
    ciphertext = b64d(packet["ciphertext"])

    # Load receiver private key
    with open(receiver_key_path, "rb") as f:
        receiver_key = serialization.load_pem_private_key(f.read(), password=None)

    # Decrypt AES key
    aes_key = receiver_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt JWT
    aesgcm = AESGCM(aes_key)
    token = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    # Load certificates
    sender_cert = load_certificate(sender_cert_path)
    ca_cert = load_certificate(ca_cert_path)

    # Verify sender cert with CA
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        sender_cert.signature,
        sender_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        sender_cert.signature_hash_algorithm,
    )

    # Verify JWT
    public_key = sender_cert.public_key()
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])

    print("VALID PACKET")
    print("Decoded data:", decoded)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Decrypt and verify packet.")
    p.add_argument("packet", help="Path to encrypted packet JSON")
    p.add_argument("receiver_key", help="Path to receiver private key")
    p.add_argument("sender_cert", help="Path to sender certificate")
    p.add_argument("ca_cert", help="Path to CA certificate")
    args = p.parse_args()

    main(args.packet, args.receiver_key, args.sender_cert, args.ca_cert)