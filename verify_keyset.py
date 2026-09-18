#!/usr/bin/env python3
"""Verify private/public key-pair consistency without printing private material."""
from __future__ import annotations
import hashlib, os, subprocess, sys, tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from signing_config import override_certificates

ROOT=Path(__file__).resolve().parent
TOP=ROOT.parents[2]
AVBTOOL=TOP/"external/avb/avbtool.py"

def cert_fp(path: Path) -> str:
    c=x509.load_pem_x509_certificate(path.read_bytes())
    return hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()

def pub_from_cert(path: Path) -> bytes:
    c=x509.load_pem_x509_certificate(path.read_bytes())
    return c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

def pub_from_pk8(path: Path) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    k=load_der_private_key(path.read_bytes(),password=None)
    return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

def main() -> int:
    failures=0; warnings=0; fps={}

    required = ["releasekey","platform","media","shared","networkstack"]
    required += override_certificates()
    for stem in required:
        base=ROOT/stem
        pk=Path(str(base)+".pk8"); crt=Path(str(base)+".x509.pem")
        if not pk.is_file() or not crt.is_file():
            print("[FAIL] required certificate pair missing:",base)
            failures+=1

    certs=sorted(ROOT.rglob("*.x509.pem"))
    for cert in certs:
        base=Path(str(cert)[:-len(".x509.pem")])
        pk=Path(str(base)+".pk8")
        if not pk.is_file():
            print("[FAIL] certificate without .pk8:",cert); failures+=1; continue
        try:
            if pub_from_cert(cert)!=pub_from_pk8(pk):
                print("[FAIL] public/private mismatch:",base); failures+=1; continue
            fp=cert_fp(cert); fps.setdefault(fp,[]).append(base)
            mode=pk.stat().st_mode & 0o777
            if mode & 0o077:
                print(f"[WARN] private key permissions {oct(mode)}: {pk}"); warnings+=1
            print("[OK]  pair:",base)
        except Exception as e:
            print("[FAIL] cannot validate",base,":",e); failures+=1

    for fp,items in fps.items():
        if len(items)>1:
            names=", ".join(str(x.relative_to(ROOT)) for x in items)
            print(f"[WARN] identical certificate identity used by multiple names: {names}")
            warnings+=1

    rel=ROOT/"releasekey.x509.pem"; test=ROOT/"testkey.x509.pem"
    if rel.is_file() and test.is_file() and cert_fp(rel)==cert_fp(test):
        print("[WARN] releasekey and testkey are the same identity. Preserve this only for existing release continuity; use independent keys for a fresh identity.")
        warnings+=1

    avb=ROOT/"avb.pem"; pub=ROOT/"avb.avbpubkey"
    if avb.is_file():
        if not AVBTOOL.is_file():
            print("[FAIL] avbtool missing:",AVBTOOL); failures+=1
        else:
            with tempfile.TemporaryDirectory() as td:
                tmp=Path(td)/"pub"
                p=subprocess.run([str(AVBTOOL),"extract_public_key","--key",str(avb),"--output",str(tmp)])
                if p.returncode or not tmp.is_file():
                    print("[FAIL] cannot derive AVB public key"); failures+=1
                elif not pub.is_file() or tmp.read_bytes()!=pub.read_bytes():
                    print("[FAIL] avb.avbpubkey does not match avb.pem"); failures+=1
                else:
                    print("[OK]  AVB private/public pair")

    payload=ROOT/"apex-payload"
    if payload.exists() and AVBTOOL.is_file():
        for pem in sorted(payload.glob("*.pem")):
            pub=pem.with_suffix(".avbpubkey")
            with tempfile.TemporaryDirectory() as td:
                tmp=Path(td)/"pub"
                p=subprocess.run([str(AVBTOOL),"extract_public_key","--key",str(pem),"--output",str(tmp)],
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if p.returncode or not pub.is_file() or tmp.read_bytes()!=pub.read_bytes():
                    print("[FAIL] APEX payload pair mismatch:",pem); failures+=1
                else:
                    print("[OK]  APEX payload pair:",pem.name)

    print(f"failures={failures} warnings={warnings}")
    return 1 if failures else 0

if __name__=="__main__":
    raise SystemExit(main())
