#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "usage: $0 <output-base> [rsa-bits] [certificate-CN]" >&2
    exit 2
fi

OUT="$1"
BITS="${2:-${ANDROID_KEY_BITS:-2048}}"
CN="${3:-$(basename "${OUT}")}"
DAYS="${ANDROID_KEY_DAYS:-10000}"

case "${BITS}" in
    2048|3072|4096) ;;
    *) echo "error: unsupported RSA size '${BITS}'" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "${OUT}")"

if [[ -e "${OUT}.pk8" || -e "${OUT}.x509.pem" ]]; then
    if [[ -f "${OUT}.pk8" && -f "${OUT}.x509.pem" ]]; then
        echo "[skip] ${OUT}: pair already exists"
        exit 0
    fi
    echo "error: incomplete/broken certificate pair for ${OUT}" >&2
    exit 1
fi

umask 077
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
RAW="${TMP}/key.pem"

SUBJECT="${ANDROID_KEY_SUBJECT:-/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=${CN}/emailAddress=android@android.com}"

openssl genrsa -out "${RAW}" "${BITS}" >/dev/null 2>&1
openssl req -new -x509 -sha256 -key "${RAW}" -out "${OUT}.x509.pem" \
    -days "${DAYS}" -subj "${SUBJECT}"
openssl pkcs8 -topk8 -inform PEM -outform DER -in "${RAW}" \
    -out "${OUT}.pk8" -nocrypt

chmod 600 "${OUT}.pk8"
chmod 644 "${OUT}.x509.pem"
echo "[ok] ${OUT} (RSA-${BITS})"
