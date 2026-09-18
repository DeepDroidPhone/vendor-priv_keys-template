#!/usr/bin/env python3
"""Prepare target-specific mapped APK certs and APEX payload keys.

Default mode is read-only. --generate must be explicitly supplied to create
missing private material. Release signing never generates keys as a side effect.
"""
from __future__ import annotations
import argparse, os, re, subprocess, sys, zipfile
from pathlib import Path
from signing_config import (
    STANDARD_RELEASE_MAP, SPECIAL_KEYS, is_our_key, preserved,
    stable_name, strip_cert_suffix, parse_meta_rows,
)

SCRIPT_DIR = Path(__file__).resolve().parent
TOP = SCRIPT_DIR.parents[2]
MAKE_KEY = SCRIPT_DIR / "make_key.sh"
AVBTOOL = TOP / "external/avb/avbtool.py"

def die(msg: str) -> None:
    print("error: " + msg, file=sys.stderr)
    raise SystemExit(1)

def read_meta(tf: Path, name: str) -> str:
    with zipfile.ZipFile(tf) as zf:
        try:
            return zf.read(name).decode("utf-8", errors="replace")
        except KeyError:
            return ""

def pair_exists(base: Path) -> bool:
    return Path(str(base)+".pk8").is_file() and Path(str(base)+".x509.pem").is_file()

def repo_path(path: str) -> Path:
    p = Path(strip_cert_suffix(path))
    return p if p.is_absolute() else TOP / p

def standard_dest(src: str) -> Path | None:
    target = STANDARD_RELEASE_MAP.get(Path(src).name)
    if not target:
        return None
    d = SCRIPT_DIR / target
    return d if pair_exists(d) else None

def mapped_dest(src: str) -> Path:
    return SCRIPT_DIR / "mapped" / stable_name(src)

def payload_dest(src: str) -> Path:
    return SCRIPT_DIR / "apex-payload" / f"{stable_name(src)}.pem"

def detect_bits(path: str, default: int = 4096) -> int:
    p = Path(path)
    if not p.is_absolute():
        p = TOP / p
    if not p.is_file():
        return default
    try:
        s = subprocess.check_output(
            ["openssl", "pkey", "-in", str(p), "-text", "-noout"],
            stderr=subprocess.STDOUT, text=True,
        )
        m = re.search(r"(?:Private|Public)-Key:\s*\((\d+) bit", s)
        return int(m.group(1)) if m else default
    except Exception:
        return default

def generate_payload(dest: Path, bits: int) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(dest.parent, 0o700)
    if not dest.exists():
        subprocess.run(
            ["openssl", "genrsa", "-out", str(dest), str(bits)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.chmod(dest, 0o600)
    pub = dest.with_suffix(".avbpubkey")
    subprocess.run(
        [str(AVBTOOL), "extract_public_key", "--key", str(dest), "--output", str(pub)],
        check=True,
    )
    os.chmod(pub, 0o644)

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target_files", type=Path)
    ap.add_argument("--generate", action="store_true")
    args = ap.parse_args()
    tf = args.target_files.resolve()
    if not tf.is_file():
        die(f"target-files not found: {tf}")
    if args.generate and not AVBTOOL.is_file():
        die(f"avbtool not found: {AVBTOOL}")

    missing = []
    generated = 0
    preserved_count = 0

    cert_sources = set()
    for r in parse_meta_rows(read_meta(tf, "META/apkcerts.txt")):
        cert = strip_cert_suffix(r.get("certificate", ""))
        if cert and cert not in SPECIAL_KEYS:
            cert_sources.add(cert)
    for r in parse_meta_rows(read_meta(tf, "META/apexkeys.txt")):
        cert = strip_cert_suffix(r.get("container_private_key", ""))
        if cert and cert not in SPECIAL_KEYS:
            cert_sources.add(cert)

    for src in sorted(cert_sources):
        if preserved(src):
            preserved_count += 1
            continue
        if is_our_key(src):
            d = repo_path(src)
            if not pair_exists(d):
                missing.append(("private-cert", src, str(d)))
            continue
        d = standard_dest(src)
        if d:
            continue
        d = mapped_dest(src)
        if pair_exists(d):
            continue
        if args.generate:
            d.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(d.parent, 0o700)
            subprocess.run(
                [str(MAKE_KEY), str(d), os.environ.get("ANDROID_MAPPED_KEY_BITS", "2048"), Path(src).name],
                check=True,
            )
            generated += 1
        else:
            missing.append(("mapped-cert", src, str(d)))

    payload_sources = set()
    for r in parse_meta_rows(read_meta(tf, "META/apexkeys.txt")):
        src = r.get("private_key", "")
        if not src or src in SPECIAL_KEYS:
            continue
        if preserved(src):
            preserved_count += 1
            continue
        payload_sources.add(src)

    for src in sorted(payload_sources):
        if is_our_key(src):
            d = repo_path(src)
            if not d.is_file():
                missing.append(("private-payload", src, str(d)))
            pub = d.with_suffix(".avbpubkey")
            if d.is_file() and not pub.is_file():
                missing.append(("payload-public", src, str(pub)))
            continue
        d = payload_dest(src)
        pub = d.with_suffix(".avbpubkey")
        if d.is_file() and pub.is_file():
            continue
        if args.generate:
            generate_payload(d, detect_bits(src, 4096))
            generated += 1
        else:
            missing.append(("apex-payload", src, str(d)))

    if missing:
        for kind, src, dst in missing:
            print(f"[MISSING] {kind:16s} {src} -> {dst}")
        print(f"\nMissing objects: {len(missing)}")
        print("Review the mapping, then rerun with --generate only for the intended fresh target-files.")
        return 1

    print(f"All required target-specific keys are present. generated={generated} preserved={preserved_count}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
