import json
import argparse
from cryptography.hazmat.primitives import hashes, serialization 
from cryptography.hazmat.primitives.asymmetric import padding

def canonicalize_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8") 

def sign_data(data: bytes, private_key_path: str) -> bytes:
    with open(private_key_path, "rb") as f: 
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign( 
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def main(data_path: str, key_path: str, sig_out: str):
    with open(data_path, "r", encoding="utf-8") as f: 
        obj = json.load(f)

    data = canonicalize_json(obj)
    signature = sign_data(data, key_path)

    with open(sig_out, "wb") as f:
        f.write(signature) 

    print("Signature created and saved to", sig_out)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign JSON data.")
    parser.add_argument("data", help="Path to JSON file")
    parser.add_argument("key", help="Path to private key")
    parser.add_argument("output", help="Output signature file")
    args = parser.parse_args()

    main(args.data, args.key, args.output)