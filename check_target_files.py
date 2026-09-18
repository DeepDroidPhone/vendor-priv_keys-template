#!/usr/bin/env python3
"""Verify a signed DeepDroid target-files ZIP against the v7 private key policy.

Unlike v5, APK/APEX container verification checks the EXPECTED certificate for
that metadata key path, not merely "any certificate from vendor/priv/keys".
"""
from __future__ import annotations
import gzip, hashlib, io, re, shlex, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from signing_config import (
    STANDARD_RELEASE_MAP, SPECIAL_KEYS, is_our_key, preserved,
    stable_name, strip_cert_suffix, parse_meta_rows,
)

SCRIPT_DIR = Path(__file__).resolve().parent
TOP = SCRIPT_DIR.parents[2]
AVBTOOL = TOP / "external/avb/avbtool.py"

def read(zf: zipfile.ZipFile, name: str) -> str:
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

def cert_hash(data: bytes) -> str:
    c = x509.load_pem_x509_certificate(data)
    return hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()

def pair_exists(base: Path) -> bool:
    return Path(str(base)+".pk8").is_file() and Path(str(base)+".x509.pem").is_file()

def repo_path(path: str) -> Path:
    p = Path(strip_cert_suffix(path))
    return p if p.is_absolute() else TOP / p

def expected_cert_base(src: str) -> Path | None:
    src = strip_cert_suffix(src)
    if not src or src in SPECIAL_KEYS or preserved(src):
        return None
    if is_our_key(src):
        return repo_path(src)
    target = STANDARD_RELEASE_MAP.get(Path(src).name)
    if target and pair_exists(SCRIPT_DIR/target):
        return SCRIPT_DIR/target
    return SCRIPT_DIR/"mapped"/stable_name(src)

def expected_payload_pub(src: str) -> Path | None:
    if not src or src in SPECIAL_KEYS or preserved(src):
        return None
    if is_our_key(src):
        p = repo_path(src)
        return p.with_suffix(".avbpubkey")
    return SCRIPT_DIR/"apex-payload"/f"{stable_name(src)}.avbpubkey"

def find_apksigner() -> list[str]:
    host = TOP/"out/host/linux-x86/bin/apksigner"
    if host.is_file():
        return [str(host)]
    p = shutil.which("apksigner")
    if p:
        return [p]
    for jar in (
        TOP/"prebuilts/sdk/tools/linux/lib/apksigner.jar",
        TOP/"prebuilts/sdk/tools/lib/apksigner.jar",
    ):
        if jar.is_file():
            return ["java", "-jar", str(jar)]
    raise RuntimeError("apksigner not found")

def pem_certs(blob: bytes) -> list[bytes]:
    begin=b"-----BEGIN CERTIFICATE-----"; end=b"-----END CERTIFICATE-----"
    out=[]; pos=0
    while True:
        s=blob.find(begin,pos)
        if s<0: break
        e=blob.find(end,s)
        if e<0: break
        e += len(end)
        out.append(blob[s:e]+b"\n")
        pos=e
    return out

def signer_hashes(path: Path, cmd: list[str]) -> list[str]:
    p = subprocess.run(cmd+["verify","--print-certs-pem",str(path)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode:
        raise RuntimeError(p.stdout.decode(errors="replace"))
    certs = pem_certs(p.stdout)
    if not certs:
        raise RuntimeError("no certificate returned")
    return [cert_hash(c) for c in certs]

def expected_hash(base: Path) -> str:
    cert = Path(str(base)+".x509.pem")
    if not cert.is_file():
        raise FileNotFoundError(cert)
    return cert_hash(cert.read_bytes())

def known_private_cert_hashes() -> set[str]:
    out=set()
    for cert in SCRIPT_DIR.rglob("*.x509.pem"):
        try: out.add(cert_hash(cert.read_bytes()))
        except Exception: pass
    return out

def known_private_payloads() -> set[bytes]:
    out=set()
    d=SCRIPT_DIR/"apex-payload"
    if d.exists():
        for pub in d.glob("*.avbpubkey"):
            try: out.add(pub.read_bytes())
            except OSError: pass
    return out

def verify_outer(path: Path, source_key: str, cmd: list[str], private_hashes: set[str]) -> tuple[bool,str]:
    try:
        actual = signer_hashes(path, cmd)
    except Exception as e:
        return False, f"cannot verify: {e}"
    expected = expected_cert_base(source_key)
    if expected is None:
        if any(h in private_hashes for h in actual):
            return False, "preserved/external item was re-signed with a ROM private certificate"
        return True, "preserved/external signer"
    try:
        want = expected_hash(expected)
    except Exception as e:
        return False, f"expected certificate missing/bad: {e}"
    if want in actual:
        return True, f"expected signer: {expected}"
    return False, f"wrong signer; expected {expected}"

def verify_payload(path: Path, suffix: str, source_key: str, private_payloads: set[bytes]) -> tuple[bool,str]:
    expected = expected_payload_pub(source_key)
    try:
        if suffix == ".apex":
            with zipfile.ZipFile(path) as z:
                pub = z.read("apex_pubkey")
        else:
            with zipfile.ZipFile(path) as z:
                orig = z.read("original_apex")
            with zipfile.ZipFile(io.BytesIO(orig)) as z:
                pub = z.read("apex_pubkey")
    except Exception as e:
        return False, f"cannot inspect apex_pubkey: {e}"
    if expected is None:
        if pub in private_payloads:
            return False, "preserved/external APEX payload was replaced by a ROM private payload key"
        return True, "preserved/external payload"
    if not expected.is_file():
        return False, f"expected payload public key missing: {expected}"
    if pub == expected.read_bytes():
        return True, f"expected payload key: {expected}"
    return False, f"wrong payload key; expected {expected}"

def parse_disable_flags(argtext: str) -> list[str]:
    try:
        toks = shlex.split(argtext)
    except ValueError:
        toks = argtext.split()
    bad=[]; i=0
    while i<len(toks):
        t=toks[i]; low=t.lower()
        if t=="--set_hashtree_disabled_flag" or "verification_disabled" in low or "hashtree_disabled" in low:
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

def avb_info(path: Path):
    p=subprocess.run([str(AVBTOOL),"info_image","--image",str(path)],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode:
        return None
    alg=flags=None
    for line in p.stdout.splitlines():
        s=line.strip()
        if s.startswith("Algorithm:"):
            alg=s.split(":",1)[1].strip()
        elif s.startswith("Flags:"):
            try: flags=int(s.split(":",1)[1].strip(),0)
            except ValueError: pass
    return alg,flags,p.stdout

def verify_avb(zf: zipfile.ZipFile, tmp: Path, m: dict[str,str]) -> int:
    failures=0; inspected=0
    for k,v in m.items():
        if k.startswith("avb_") and (k.endswith("_args") or k=="avb_vbmeta_args"):
            bad=parse_disable_flags(v)
            if bad:
                failures += 1
                print(f"[FAIL] {k} unsafe flags: {', '.join(bad)}")
    avbkey=SCRIPT_DIR/"avb.pem"
    if not avbkey.is_file():
        print("[FAIL] avb.pem missing")
        return failures+1
    for name in sorted(n for n in zf.namelist() if n.startswith("IMAGES/") and n.endswith(".img")):
        p=tmp/Path(name).name
        p.write_bytes(zf.read(name))
        info=avb_info(p)
        if info is None:
            continue
        inspected+=1
        alg,flags,_=info
        if flags is not None and (flags&3):
            failures+=1
            print(f"[FAIL] {name} AVB flags={flags}")
        if Path(name).name.startswith("vbmeta"):
            q=subprocess.run([str(AVBTOOL),"verify_image","--image",str(p),"--key",str(avbkey)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if q.returncode:
                failures+=1
                print(f"[FAIL] {name} not verifiable by avb.pem")
            else:
                print(f"[OK]   {name} private AVB algorithm={alg} flags={flags}")
    if not inspected:
        print("[WARN] no AVB-bearing images detected")
    return failures

def verify_ota(zf: zipfile.ZipFile, release_hash: str) -> int:
    candidates=[n for n in zf.namelist()
                if n.endswith("/etc/security/otacerts.zip") or n.endswith("etc/security/otacerts.zip")]
    if not candidates:
        print("[WARN] OTA certificate bundle not present in target-files")
        return 0
    fail=0
    for n in candidates:
        try:
            with zipfile.ZipFile(io.BytesIO(zf.read(n))) as oz:
                hashes=[]
                for e in oz.namelist():
                    if e.endswith(".x509.pem"):
                        try: hashes.append(cert_hash(oz.read(e)))
                        except Exception: pass
            if release_hash in hashes:
                print("[OK]   OTA cert bundle contains releasekey:",n)
            else:
                fail+=1
                print("[FAIL] OTA cert bundle does not contain releasekey:",n)
        except Exception as e:
            fail+=1
            print(f"[FAIL] cannot inspect OTA cert bundle {n}: {e}")
    return fail

def main() -> int:
    if len(sys.argv)!=2:
        print(f"usage: {sys.argv[0]} SIGNED_TARGET_FILES.zip", file=sys.stderr)
        return 2
    tf=Path(sys.argv[1]).resolve()
    if not tf.is_file():
        print("error: target-files not found:",tf,file=sys.stderr); return 2
    if not AVBTOOL.is_file():
        print("error: avbtool missing:",AVBTOOL,file=sys.stderr); return 2
    try:
        apkcmd=find_apksigner()
    except Exception as e:
        print("error:",e,file=sys.stderr); return 2

    rel=SCRIPT_DIR/"releasekey.x509.pem"
    if not rel.is_file():
        print("error: releasekey.x509.pem missing",file=sys.stderr); return 2
    release_hash=cert_hash(rel.read_bytes())
    private_hashes=known_private_cert_hashes()
    private_payloads=known_private_payloads()

    failures=checked=0
    with zipfile.ZipFile(tf) as zf, tempfile.TemporaryDirectory(prefix="deepdroid-v7-check-") as td:
        tmp=Path(td)
        apk_meta={r.get("name",""): r for r in parse_meta_rows(read(zf,"META/apkcerts.txt"))}
        apex_meta={r.get("name",""): r for r in parse_meta_rows(read(zf,"META/apexkeys.txt"))}
        m=misc(read(zf,"META/misc_info.txt"))

        for idx,info in enumerate(zf.infolist()):
            if info.is_dir() or info.filename.startswith("META/"):
                continue
            base=Path(info.filename).name
            low=base.lower()
            if not (low.endswith(".apk") or low.endswith(".apk.gz") or low.endswith(".apex") or low.endswith(".capex")):
                continue
            p=tmp/(f"{idx:06d}-"+re.sub(r"[^A-Za-z0-9._-]","_",base))
            p.write_bytes(zf.read(info))
            logical=base
            if low.endswith(".apk.gz"):
                up=p.with_suffix("")
                with gzip.open(p,"rb") as s, open(up,"wb") as d:
                    shutil.copyfileobj(s,d)
                p=up; logical=base[:-3]

            if logical.endswith(".apk"):
                row=apk_meta.get(logical,{})
                source=row.get("certificate","PRESIGNED")
                ok,detail=verify_outer(p,source,apkcmd,private_hashes)
                checked+=1; failures+=int(not ok)
                print(f"[{'OK' if ok else 'FAIL'}] APK  {logical}: {detail}")
                continue

            suff=".capex" if logical.endswith(".capex") else ".apex"
            apex_name=logical[:-6]+".apex" if suff==".capex" else logical
            row=apex_meta.get(apex_name,{})
            container=row.get("container_private_key","PRESIGNED")
            payload=row.get("private_key","PRESIGNED")

            ok,detail=verify_outer(p,container,apkcmd,private_hashes)
            checked+=1; failures+=int(not ok)
            print(f"[{'OK' if ok else 'FAIL'}] APEX {logical} container: {detail}")

            ok,detail=verify_payload(p,suff,payload,private_payloads)
            checked+=1; failures+=int(not ok)
            print(f"[{'OK' if ok else 'FAIL'}] APEX {logical} payload:   {detail}")

        print("\n== AVB ==")
        failures += verify_avb(zf,tmp,m)
        print("\n== OTA ==")
        failures += verify_ota(zf,release_hash)

    print(f"\nchecked={checked} failures={failures}")
    return 1 if failures else 0

if __name__=="__main__":
    raise SystemExit(main())
