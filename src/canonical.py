import json 
import sys 
import argparse 
def canonicalize_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8") #Canonicalize (sort keys/remove spaces after , and :)  #Convert to bytes

def main(in_path: str, out_path: str | None = None) -> int:
    with open(in_path, "r", encoding="utf-8") as f:
        obj = json.load(f) 

    data = canonicalize_json(obj).decode("utf-8")

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(data)
    else: 
        sys.stdout.write(data) 

    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Canonicalize JSON.")
    parser.add_argument("input", help="Input JSON path") 
    parser.add_argument("-o", "--out", help="Output path", default=None)
    args = parser.parse_args()
    raise SystemExit(main(args.input, args.out)) 