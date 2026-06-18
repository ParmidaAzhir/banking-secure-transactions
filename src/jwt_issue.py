import json
import time
import argparse
import jwt 
from cryptography.hazmat.primitives import serialization

def main(payload_path: str, sender_key_path: str, token_out: str, issuer: str = "Bank-Server-01", ttl_seconds: int = 300) -> int:
    with open(payload_path, "r", encoding="utf-8") as f:
        payload = json.load(f) 

    now = int(time.time())

    claims = { #Create JWT claims
        "iss": "Parmida-Bank-Server-01",
        "iat": now,
        "exp": now + ttl_seconds,
        "data": payload
    }

    with open(sender_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None) 

    token = jwt.encode(claims, private_key, algorithm="RS256") 

    with open(token_out, "w", encoding="utf-8") as f: 
        f.write(token)

    print("JWT created and saved to", token_out)
    return 0

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Issue a signed JWT containing the JSON payload.")
    p.add_argument("payload") 
    p.add_argument("key") 
    p.add_argument("out")
    p.add_argument("--iss", default="Parmida-Bank-Server-01")
    p.add_argument("--ttl", type=int, default=300)
    args = p.parse_args()

    raise SystemExit(main(args.payload, args.key, args.out, args.iss, args.ttl))