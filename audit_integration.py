#!/usr/bin/env python3
"""Read-only integration audit for the DeepDroid signing tree."""
from __future__ import annotations
import re, shlex, subprocess, sys
from pathlib import Path

SCRIPT_DIR=Path(__file__).resolve().parent
TOP=SCRIPT_DIR.parents[2]

def parse_flags(text: str) -> list[str]:
    try: toks=shlex.split(text)
    except ValueError: toks=text.split()
    bad=[]; i=0
    while i<len(toks):
        t=toks[i]
        if t=="--set_hashtree_disabled_flag":
            bad.append(t)
        if t=="--flags" and i+1<len(toks):
            try:
                v=int(toks[i+1],0)
                if v&3: bad.append(f"--flags {toks[i+1]}")
            except ValueError: pass
            i+=1
        elif t.startswith("--flags="):
            try:
                v=int(t.split("=",1)[1],0)
                if v&3: bad.append(t)
            except ValueError: pass
        i+=1
    return bad

def avb_key_bits(p: Path) -> int|None:
    if not p.is_file(): return None
    try:
        s=subprocess.check_output(["openssl","pkey","-in",str(p),"-text","-noout"],
                                  stderr=subprocess.STDOUT,text=True)
        m=re.search(r"(?:Private|Public)-Key:\s*\((\d+) bit",s)
        return int(m.group(1)) if m else None
    except Exception: return None

def main() -> int:
    blockers=0; warnings=0
    print("Android root:",TOP)

    p=subprocess.run([sys.executable,str(SCRIPT_DIR/"generate_config.py"),"--check"])
    if p.returncode: blockers+=1

    common=TOP/"vendor/aosp/config/common.mk"
    if common.is_file() and "vendor/priv/keys/keys.mk" in common.read_text(errors="replace"):
        print("[OK] product signing include:",common)
    else:
        print("[BLOCKER] vendor/priv/keys/keys.mk is not inherited from vendor/aosp/config/common.mk")
        blockers+=1

    keys_mk=SCRIPT_DIR/"keys.mk"
    if keys_mk.is_file() and "-include vendor/priv/keys/BoardConfigPrivKeys.mk" in keys_mk.read_text(errors="replace"):
        print("[OK] single-entry private AVB fan-out: keys.mk -> BoardConfigPrivKeys.mk")
    else:
        print("[BLOCKER] keys.mk does not include vendor/priv/keys/BoardConfigPrivKeys.mk")
        blockers+=1

    danger=[]
    device_root=TOP/"device"
    if device_root.exists():
        for path in device_root.rglob("*.mk"):
            text=path.read_text(errors="replace")
            for ln,line in enumerate(text.splitlines(),1):
                if "BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS" in line:
                    for b in parse_flags(line):
                        danger.append((path,ln,b,line.strip()))
    for path,ln,b,line in danger:
        print(f"[BLOCKER] unsafe AVB config {path}:{ln}: {b} :: {line}")
        blockers+=1

    # Keyset state. Missing keys are a warning before generation, not a config blocker.
    core=("releasekey","platform","media","shared","networkstack")
    for stem in core:
        pk=SCRIPT_DIR/f"{stem}.pk8"; crt=SCRIPT_DIR/f"{stem}.x509.pem"
        if pk.exists()!=crt.exists():
            print("[BLOCKER] incomplete core pair:",stem); blockers+=1
        elif not pk.exists():
            print("[WARN] core pair not generated yet:",stem); warnings+=1

    bits=avb_key_bits(SCRIPT_DIR/"avb.pem")
    if bits:
        print(f"[OK] avb.pem RSA-{bits}")
        if bits not in (2048,3072,4096):
            print("[BLOCKER] unsupported AVB RSA size"); blockers+=1
    else:
        print("[WARN] avb.pem not generated yet"); warnings+=1

    # Report GMS packages that intentionally use platform cert instead of PRESIGNED.
    gms=TOP/"vendor/gms"
    platform_refs=0
    if gms.exists():
        for bp in gms.rglob("Android.bp"):
            try:text=bp.read_text(errors="replace")
            except OSError:continue
            if 'certificate: "platform"' in text:
                platform_refs += text.count('certificate: "platform"')
        if platform_refs:
            print(f"[INFO] vendor/gms contains {platform_refs} certificate:\"platform\" references; these will follow the ROM platform key by design. Audit package compatibility separately.")
        else:
            print("[OK] no platform-signed GMS references detected")

    print(f"blockers={blockers} warnings={warnings}")
    return 1 if blockers else 0

if __name__=="__main__":
    raise SystemExit(main())
