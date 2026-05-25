import json
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature #introduce - so we can detect it


def canonicalize_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_certificate(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_certificate(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes, # Original signed certificate data.
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def verify_signature(data: bytes, signature: bytes, cert):
    public_key = cert.public_key()
    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def main(data_path: str, sig_path: str, sender_cert_path: str, ca_cert_path: str) -> int:
    with open(data_path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    data = canonicalize_json(obj)

    with open(sig_path, "rb") as f:
        signature = f.read()
        # Read signature bytes from signature file.
     
    #Loads sender certificate.
    sender_cert = load_certificate(sender_cert_path)
    #Loads trusted CA certificate.
    ca_cert = load_certificate(ca_cert_path)

    try: #ca_public_key.verify(...)
        verify_certificate(sender_cert, ca_cert)
    except InvalidSignature:
        print("INVALID: sender certificate is not trusted or was not signed by the trusted CA")
        return 1

    try: #public_key.verify(...)
        verify_signature(data, signature, sender_cert)
    except InvalidSignature:
        print("INVALID: signature verification failed")
        return 1

    print("VALID")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify signed JSON data.")
    parser.add_argument("data", help="Path to JSON file")
    parser.add_argument("signature", help="Path to signature file")
    parser.add_argument("sender_cert", help="Path to sender certificate")
    parser.add_argument("ca_cert", help="Path to CA certificate")
    args = parser.parse_args()

    raise SystemExit(main(args.data, args.signature, args.sender_cert, args.ca_cert))
