import os
import json
import base64
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def main(token_path: str, receiver_cert_path: str, packet_out: str) -> int:
    with open(token_path, "r", encoding="utf-8") as f:
        token = f.read().encode("utf-8")

    receiver_cert = load_certificate(receiver_cert_path)
    receiver_public_key = receiver_cert.public_key()

    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, token, None)

    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    packet = {
        "encrypted_key": b64e(encrypted_key),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext)
    }

    with open(packet_out, "w", encoding="utf-8") as f:
        json.dump(packet, f, indent=2)

    print("Encrypted packet saved to", packet_out)
    return 0

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Encrypt JWT for receiver.")
    p.add_argument("token", help="Path to JWT file")
    p.add_argument("receiver_cert", help="Path to receiver certificate PEM")
    p.add_argument("out", help="Path to output packet JSON")
    args = p.parse_args()

    raise SystemExit(main(args.token, args.receiver_cert, args.out))