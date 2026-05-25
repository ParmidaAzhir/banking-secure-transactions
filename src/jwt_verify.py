import argparse
import jwt #to create, decode, and verify JWT tokens.
from jwt.exceptions import ExpiredSignatureError #introduce - so we can detect it
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_certificate(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature, #sender certificate signature
        cert.tbs_certificate_bytes, # Original signed certificate data.
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def main(token_path: str, sender_cert_path: str, ca_cert_path: str) -> int:
    with open(token_path, "r", encoding="utf-8") as f:
        token = f.read().strip() # Read JWT token text and remove extra spaces/newlines.

    sender_cert = load_certificate(sender_cert_path)
    ca_cert = load_certificate(ca_cert_path)

    try:
        verify_certificate(sender_cert, ca_cert) ## Verify sender certificate using trusted CA certificate.
    except InvalidSignature:
        print("INVALID: fake or untrusted certificate authority")
        return 1

    public_key = sender_cert.public_key() # uses sender certificate to Get sender public key 

    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"]) ## Decode and verify JWT using token, sender public key, and RS256.
    except ExpiredSignatureError:
        print("INVALID: JWT token has expired")
        return 1

    if decoded.get("iss") not in ("Parmida-Bank-Server-01", "Fake-Bank-Server"): ## If JWT issuer is not valid.
        print("INVALID: unexpected issuer")
        return 1

    print("VALID JWT")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Verify a signed JWT and the sender certificate.")
    p.add_argument("token", help="Path to JWT file")
    p.add_argument("sender_cert", help="Path to sender certificate PEM")
    p.add_argument("ca_cert", help="Path to trusted CA certificate PEM")
    args = p.parse_args()

    raise SystemExit(main(args.token, args.sender_cert, args.ca_cert))
