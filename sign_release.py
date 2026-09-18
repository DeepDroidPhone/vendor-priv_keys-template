#!/usr/bin/env python3
"""Release-sign PE13 target-files with pre-generated private keys.

The wrapper never creates private keys. PRESIGNED and external vendor/device
artifacts are preserved, while vendor/priv/keys/* is always this ROM's keyspace.
"""
from __future__ import annotations
import argparse, re, shlex, subprocess, sys, zipfile
from pathlib import Path
from signing_config import (
    STANDARD_RELEASE_MAP, SPECIAL_KEYS, is_our_key, preserved,
    stable_name, strip_cert_suffix, parse_meta_rows,
)

SCRIPT_DIR = Path(__file__).resolve().parent
TOP = SCRIPT_DIR.parents[2]
SIGN_TOOL = TOP / "build/make/tools/releasetools/sign_target_files_apks.py"

def die(msg: str) -> None:
    print("error: " + msg, file=sys.stderr)
    raise SystemExit(1)

def read_meta(tf: Path, name: str) -> str:
    with zipfile.ZipFile(tf) as zf:
        try:
            return zf.read(name).decode("utf-8", errors="replace")
        except KeyError:
            return ""

def misc(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def pair_exists(base: Path) -> bool:
    return Path(str(base)+".pk8").is_file() and Path(str(base)+".x509.pem").is_file()

def repo_path(path: str) -> Path:
    p = Path(strip_cert_suffix(path))
    return p if p.is_absolute() else TOP / p

def mapped_dest(src: str) -> Path:
    return SCRIPT_DIR / "mapped" / stable_name(src)

def payload_dest(src: str) -> Path:
    return SCRIPT_DIR / "apex-payload" / f"{stable_name(src)}.pem"

def standard_dest(src: str) -> Path | None:
    target = STANDARD_RELEASE_MAP.get(Path(src).name)
    if not target:
        return None
    d = SCRIPT_DIR / target
    return d if pair_exists(d) else None

def require_pair(base: Path, label: str) -> None:
    if not pair_exists(base):
        die(f"missing {label}: {base}.pk8/.x509.pem; run keys.sh/prepare_target_keys.py")

def cert_dest(src: str) -> Path:
    src = strip_cert_suffix(src)
    if is_our_key(src):
        d = repo_path(src)
        require_pair(d, "private certificate pair")
        return d
    d = standard_dest(src)
    if d:
        return d
    d = mapped_dest(src)
    require_pair(d, "mapped certificate pair")
    return d

def parse_disable_flags(argtext: str) -> list[str]:
    try:
        tokens = shlex.split(argtext)
    except ValueError:
        tokens = argtext.split()
    bad = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        low = t.lower()
        if t == "--set_hashtree_disabled_flag" or "verification_disabled" in low or "hashtree_disabled" in low:
            bad.append(t)
        if t == "--flags" and i + 1 < len(tokens):
            try:
                v = int(tokens[i+1], 0)
                if v & 0x3:
                    bad.append(f"--flags {tokens[i+1]}")
            except ValueError:
                pass
            i += 1
        elif t.startswith("--flags="):
            try:
                v = int(t.split("=", 1)[1], 0)
                if v & 0x3:
                    bad.append(t)
            except ValueError:
                pass
        i += 1
    return bad

def preflight(tf: Path) -> dict[str, str]:
    m = misc(read_meta(tf, "META/misc_info.txt"))
    if not m:
        die("META/misc_info.txt missing")
    bad = []
    for k, v in m.items():
        if k.startswith("avb_") and (k.endswith("_args") or k == "avb_vbmeta_args"):
            bad += [f"{k}: {x}" for x in parse_disable_flags(v)]
    if bad:
        die("unsafe AVB disable flags found: " + ", ".join(bad))
    return m

def add_apk_mappings(cmd: list[str], tf: Path) -> None:
    mappings = {}
    for r in parse_meta_rows(read_meta(tf, "META/apkcerts.txt")):
        cert = strip_cert_suffix(r.get("certificate", ""))
        if not cert or cert in SPECIAL_KEYS or preserved(cert) or is_our_key(cert):
            continue
        d = cert_dest(cert)
        if str(d) != cert:
            mappings[cert] = d
    for src, dst in sorted(mappings.items()):
        cmd += ["--key_mapping", f"{src}={dst}"]
    print("APK key mappings:", len(mappings))

def add_apex_mappings(cmd: list[str], tf: Path) -> None:
    signed = preserved_count = 0
    global_maps = {}
    for r in parse_meta_rows(read_meta(tf, "META/apexkeys.txt")):
        name = r.get("name", "")
        payload = r.get("private_key", "")
        container = strip_cert_suffix(r.get("container_private_key", ""))
        if not name:
            continue
        if payload in SPECIAL_KEYS or container in SPECIAL_KEYS or preserved(payload) or preserved(container):
            print("[preserve] APEX", name)
            preserved_count += 1
            continue

        cdest = cert_dest(container)
        if is_our_key(payload):
            pdest = repo_path(payload)
            if not pdest.is_file():
                die(f"missing private APEX payload key: {pdest}")
        else:
            pdest = payload_dest(payload)
            if not pdest.is_file():
                die(f"missing APEX payload key {pdest}; run prepare_target_keys.py TARGET_FILES.zip --generate")

        # Android 13's releasetool uses --extra_apks for APEX container keys and
        # --extra_apex_payload_key for payload AVB keys.
        cmd += ["--extra_apks", f"{name}={cdest}"]
        cmd += ["--extra_apex_payload_key", f"{name}={pdest}"]
        if container and not is_our_key(container) and str(cdest) != container:
            global_maps[container] = cdest
        signed += 1

    for src, dst in sorted(global_maps.items()):
        cmd += ["--key_mapping", f"{src}={dst}"]
    print(f"APEX mappings: {signed} private, {preserved_count} preserved")

def tool_supports(opt: str) -> bool:
    try:
        return opt in SIGN_TOOL.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

def avb_bits(key: Path) -> int:
    s = subprocess.check_output(
        ["openssl", "pkey", "-in", str(key), "-text", "-noout"],
        stderr=subprocess.STDOUT, text=True,
    )
    m = re.search(r"(?:Private|Public)-Key:\s*\((\d+) bit", s)
    if not m:
        die(f"cannot determine RSA size for {key}")
    return int(m.group(1))

def add_avb(cmd: list[str], m: dict[str, str]) -> None:
    key = SCRIPT_DIR / "avb.pem"
    if not key.is_file():
        die("missing avb.pem; run keys.sh")
    bits = avb_bits(key)
    alg = f"SHA256_RSA{bits}"
    parts = [
        "vbmeta", "vbmeta_system", "vbmeta_vendor", "boot", "dtbo", "recovery",
        "system", "system_other", "vendor", "product", "odm", "system_ext",
        "vendor_boot", "init_boot",
    ]
    done = []
    for part in parts:
        keymeta = f"avb_{part}_key_path"
        need = (part == "vbmeta" and m.get("avb_enable") == "true") or bool(m.get(keymeta))
        if not need:
            continue
        keyopt = f"--avb_{part}_key"
        algopt = f"--avb_{part}_algorithm"
        if tool_supports(keyopt) and tool_supports(algopt):
            cmd += [keyopt, str(key), algopt, alg]
            done.append(part)
            continue

        # If the releasetool cannot override a slot, only accept it when target
        # metadata already points at this private AVB key.
        current = m.get(keymeta, "")
        if current and strip_cert_suffix(current) == "vendor/priv/keys/avb":
            print(f"[keep] AVB slot {part} already points at private key")
            continue
        if part == "vbmeta" and m.get("avb_vbmeta_key_path") == "vendor/priv/keys/avb.pem":
            print("[keep] vbmeta already points at private key")
            continue
        die(f"releasetool cannot replace AVB slot {part}, and target-files is not already wired to vendor/priv/keys/avb.pem")

    print("AVB replacements:", ", ".join(done) if done else "none needed")

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not SIGN_TOOL.is_file():
        die(f"sign_target_files_apks.py not found: {SIGN_TOOL}")
    tf = args.input.resolve()
    output = args.output.resolve()
    if not tf.is_file():
        die(f"target-files not found: {tf}")
    if output.exists() and not args.dry_run:
        die(f"refusing to overwrite: {output}")

    for k in ("releasekey", "platform", "shared", "media", "networkstack"):
        require_pair(SCRIPT_DIR/k, k)

    m = preflight(tf)
    cmd = [
        sys.executable, str(SIGN_TOOL),
        "--default_key_mappings", str(SCRIPT_DIR),
        "--replace_ota_keys",
    ]
    add_apk_mappings(cmd, tf)
    add_apex_mappings(cmd, tf)
    add_avb(cmd, m)
    cmd += [str(tf), str(output)]

    print("\n" + shlex.join(cmd))
    if args.dry_run:
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(cmd, cwd=TOP, check=True)
    if not output.is_file():
        die("signer returned success but output is missing")
    print("[ok] signed target-files:", output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
