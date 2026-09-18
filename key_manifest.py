#!/usr/bin/env python3
"""Write a public-only signing identity manifest (safe to track in Git)."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parent

def sha256(b: bytes)->str:return hashlib.sha256(b).hexdigest()

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,default=ROOT/"PUBLIC_KEY_MANIFEST.json")
    args=ap.parse_args()
    data={"schema":1,"certificates":[],"avb_public_keys":[]}
    for p in sorted(ROOT.rglob("*.x509.pem")):
        c=x509.load_pem_x509_certificate(p.read_bytes())
        pub=c.public_key()
        bits=getattr(pub,"key_size",None)
        data["certificates"].append({
            "path":str(p.relative_to(ROOT)),
            "certificate_sha256":sha256(c.public_bytes(serialization.Encoding.DER)),
            "public_key_bits":bits,
            "subject":c.subject.rfc4514_string(),
            "issuer":c.issuer.rfc4514_string(),
            "serial":hex(c.serial_number),
        })
    for p in sorted(ROOT.rglob("*.avbpubkey")):
        data["avb_public_keys"].append({
            "path":str(p.relative_to(ROOT)),
            "sha256":sha256(p.read_bytes()),
        })
    args.output.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("[ok] public manifest:",args.output)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
