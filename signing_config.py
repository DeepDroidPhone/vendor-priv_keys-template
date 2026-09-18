#!/usr/bin/env python3
"""Shared policy/config helpers for the DeepDroid private-signing toolset."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROFILE_PATH = ROOT / "signing_profile.json"

STANDARD_RELEASE_MAP = {
    "devkey": "releasekey",
    "testkey": "releasekey",
    "releasekey": "releasekey",
    "platform": "platform",
    "shared": "shared",
    "media": "media",
    "networkstack": "networkstack",
    "bluetooth": "bluetooth",
    "sdk_sandbox": "sdk_sandbox",
}

OUR_KEY_PREFIX = "vendor/priv/keys/"
PRESERVE_PREFIXES = ("vendor/", "device/")
SPECIAL_KEYS = {"", "PRESIGNED", "EXTERNAL"}

PAIR_RE = re.compile(r'([A-Za-z0-9_]+)="([^"]*)"')


def load_profile(path: Path = PROFILE_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1:
        raise ValueError("unsupported signing_profile.json schema")
    ovs = data.get("certificate_overrides")
    if not isinstance(ovs, list) or not ovs:
        raise ValueError("certificate_overrides must be a non-empty list")
    extras = data.get("extra_certificate_modules", [])
    if not isinstance(extras, list):
        raise ValueError("extra_certificate_modules must be a list")
    return data


def certificate_overrides() -> list[tuple[str, str]]:
    """Return active PRODUCT_CERTIFICATE_OVERRIDES mappings only."""
    out: list[tuple[str, str]] = []
    seen = set()
    for row in load_profile()["certificate_overrides"]:
        module = str(row["module"]).strip()
        cert = str(row["certificate"]).strip()
        if not module or not cert:
            raise ValueError("empty module/certificate in signing profile")
        key = (module, cert)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def active_override_certificates() -> list[str]:
    """Certificates referenced by the active 80-map DeepDroid profile."""
    return sorted({cert for _, cert in certificate_overrides()})


def extra_certificate_modules() -> list[str]:
    """Available certificate modules intentionally kept even when not actively mapped."""
    out: list[str] = []
    seen = set()
    for raw in load_profile().get("extra_certificate_modules", []):
        cert = str(raw).strip()
        if not cert:
            raise ValueError("empty certificate in extra_certificate_modules")
        if cert not in seen:
            seen.add(cert)
            out.append(cert)
    return sorted(out)


def override_certificates() -> list[str]:
    """All certificate modules that Android.bp/keys.sh should provide.

    This is the union of certificates referenced by active mappings and optional
    compatibility modules kept available for other build variants/direct Soong refs.
    """
    return sorted(set(active_override_certificates()) | set(extra_certificate_modules()))


def strip_cert_suffix(path: str) -> str:
    for suffix in (".x509.pem", ".pk8"):
        if path.endswith(suffix):
            return path[:-len(suffix)]
    return path


def is_our_key(path: str) -> bool:
    return strip_cert_suffix(path).startswith(OUR_KEY_PREFIX)


def preserved(path: str) -> bool:
    p = strip_cert_suffix(path)
    return p in SPECIAL_KEYS or (not is_our_key(p) and p.startswith(PRESERVE_PREFIXES))


def stable_name(source: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(source).name) or "key"
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    return f"{base}-{digest}"


def parse_meta_rows(text: str) -> list[dict[str, str]]:
    rows = []
    for raw in text.splitlines():
        attrs = dict(PAIR_RE.findall(raw.strip()))
        if attrs:
            rows.append(attrs)
    return rows
