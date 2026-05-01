import argparse
import jwt
from cryptography import x509

def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def verify_certificate(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

from cryptography.hazmat.primitives.asymmetric import padding

def main(token_path: str, sender_cert_path: str, ca_cert_path: str) -> int:
    with open(token_path, "r", encoding="utf-8") as f:
        token = f.read().strip()

    sender_cert = load_certificate(sender_cert_path)
    ca_cert = load_certificate(ca_cert_path)

    verify_certificate(sender_cert, ca_cert)

    public_key = sender_cert.public_key()

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])

    if decoded.get("iss") not in ("Parmida-Bank-Server-01", "Fake-Bank-Server"):
        raise ValueError("INVALID: unexpected issuer")

    print("VALID JWT")
    return 0

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Verify a signed JWT and the sender certificate.")
    p.add_argument("token", help="Path to JWT file")
    p.add_argument("sender_cert", help="Path to sender certificate PEM")
    p.add_argument("ca_cert", help="Path to trusted CA certificate PEM")
    args = p.parse_args()

    raise SystemExit(main(args.token, args.sender_cert, args.ca_cert))