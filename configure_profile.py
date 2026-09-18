#!/usr/bin/env python3
"""Import the active certificate-override map from an existing keys.mk.

The DeepDroid v8 profile intentionally distinguishes:
- active PRODUCT_CERTIFICATE_OVERRIDES mappings; and
- extra certificate modules kept available without active mappings.

When --write is used, existing extra_certificate_modules are preserved by default.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROFILE = ROOT / "signing_profile.json"
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
    if not rows:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = PAIR.match(raw)
            if m:
                item = (m.group(1), m.group(2))
                if item not in seen:
                    seen.add(item)
                    rows.append({"module": item[0], "certificate": item[1]})
    return rows


def existing_extras() -> list[str]:
    if not PROFILE.is_file():
        return []
    try:
        data = json.loads(PROFILE.read_text(encoding="utf-8"))
        vals = data.get("extra_certificate_modules", [])
        return sorted({str(v).strip() for v in vals if str(v).strip()})
    except Exception:
        return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--import-keys-mk", type=Path, required=True)
    ap.add_argument("--name", default="deepdroid-imported-current-source")
    ap.add_argument("--write", action="store_true",
                    help="write signing_profile.json and regenerate keys.mk/Android.bp")
    ap.add_argument("--drop-extra-certificates", action="store_true",
                    help="drop intentionally available-but-unmapped certificate modules")
    args = ap.parse_args()

    src = args.import_keys_mk.resolve()
    if not src.is_file():
        print(f"error: not found: {src}", file=sys.stderr)
        return 2

    rows = extract(src)
    if not rows:
        print("error: no PRODUCT_CERTIFICATE_OVERRIDES mappings found", file=sys.stderr)
        return 1

    active_certs = sorted({r["certificate"] for r in rows})
    extras = [] if args.drop_extra_certificates else existing_extras()
    available = sorted(set(active_certs) | set(extras))

    print(
        f"mappings={len(rows)} "
        f"unique_certificate_modules={len(active_certs)} "
        f"available_certificate_modules={len(available)}"
    )
    for r in rows:
        print(f'{r["module"]}:{r["certificate"]}')
    if extras:
        print("\n# Available but not actively mapped:")
        for cert in extras:
            if cert not in active_certs:
                print(cert)

    if not args.write:
        return 0

    profile = {
        "schema": 1,
        "name": args.name,
        "description": (
            f"DeepDroid active mapping profile imported from {src}; "
            "extra certificate modules preserved separately."
        ),
        "certificate_overrides": rows,
        "extra_certificate_modules": extras,
    }
    PROFILE.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "generate_config.py"), "--write"], check=True)
    print(f"[ok] wrote {PROFILE}, keys.mk and Android.bp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
