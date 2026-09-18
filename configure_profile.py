#!/usr/bin/env python3
"""Import the exact certificate-override map from an existing keys.mk.

Run this against the CURRENT source-tree keys.mk before replacing vendor/priv/keys
when you want v6 to preserve the exact mapping set rather than using its audited
84-entry fallback profile.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAIR = re.compile(r'^\s*([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)\s*\\?\s*$')

def extract(path: Path) -> list[dict[str, str]]:
    rows = []
    seen = set()
    active = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s.startswith("PRODUCT_CERTIFICATE_OVERRIDES"):
            active = True
            continue
        if active:
            m = PAIR.match(raw)
            if m:
                item = (m.group(1), m.group(2))
                if item not in seen:
                    seen.add(item)
                    rows.append({"module": item[0], "certificate": item[1]})
                continue
            if s and not s.startswith("#") and not s.endswith("\\"):
                active = False
    # Fallback for unusual formatting.
    if not rows:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = PAIR.match(raw)
            if m:
                item = (m.group(1), m.group(2))
                if item not in seen:
                    seen.add(item)
                    rows.append({"module": item[0], "certificate": item[1]})
    return rows

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--import-keys-mk", type=Path, required=True)
    ap.add_argument("--name", default="imported-current-source")
    ap.add_argument("--write", action="store_true",
                    help="write signing_profile.json and regenerate keys.mk/Android.bp")
    args = ap.parse_args()
    src = args.import_keys_mk.resolve()
    if not src.is_file():
        print(f"error: not found: {src}", file=sys.stderr)
        return 2
    rows = extract(src)
    if not rows:
        print("error: no PRODUCT_CERTIFICATE_OVERRIDES mappings found", file=sys.stderr)
        return 1
    certs = sorted({r["certificate"] for r in rows})
    print(f"mappings={len(rows)} unique_certificate_modules={len(certs)}")
    for r in rows:
        print(f'{r["module"]}:{r["certificate"]}')
    if not args.write:
        return 0

    profile = {
        "schema": 1,
        "name": args.name,
        "description": f"Imported from {src}",
        "certificate_overrides": rows,
    }
    dst = ROOT / "signing_profile.json"
    dst.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT/"generate_config.py"), "--write"], check=True)
    print(f"[ok] wrote {dst}, keys.mk and Android.bp")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
