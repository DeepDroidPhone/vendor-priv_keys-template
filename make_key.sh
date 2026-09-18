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

# X.509 commonName is limited to 64 characters by OpenSSL's ASN.1 string rules.
# Keep Android module/key filenames unchanged and shorten only the certificate CN.
make_x509_cn() {
    local original="$1"
    if (( ${#original} <= 64 )); then
        printf '%s' "${original}"
        return 0
    fi

    local digest prefix
    digest="$(printf '%s' "${original}" | sha256sum | awk '{print $1}' | cut -c1-12)"
    prefix="${original:0:51}"
    printf '%s-%s' "${prefix}" "${digest}"
}

CERT_CN="$(make_x509_cn "${CN}")"
if (( ${#CERT_CN} > 64 )); then
    echo "error: internal CN shortening failure for '${CN}'" >&2
    exit 1
fi

mkdir -p "$(dirname "${OUT}")"
PK8="${OUT}.pk8"
CERT="${OUT}.x509.pem"

# A complete existing pair is an existing signing identity: never regenerate it silently.
if [[ -e "${PK8}" || -e "${CERT}" ]]; then
    if [[ -f "${PK8}" && -s "${PK8}" && -f "${CERT}" && -s "${CERT}" ]]; then
        if openssl x509 -in "${CERT}" -noout >/dev/null 2>&1 \
                && openssl pkcs8 -inform DER -in "${PK8}" -nocrypt -out /dev/null >/dev/null 2>&1; then
            echo "[skip] ${OUT}: valid pair already exists"
            exit 0
        fi
        echo "error: existing complete pair is invalid/corrupt; refusing to regenerate identity: ${OUT}" >&2
        exit 1
    fi

    # Only a partial/zero-byte pair is safe to discard and recreate.
    echo "[warn] ${OUT}: incomplete pair found; removing only partial artifacts" >&2
    rm -f -- "${PK8}" "${CERT}"
fi

umask 077
OUT_DIR="$(dirname "${OUT}")"
TMP="$(mktemp -d "${OUT_DIR}/.deepdroid-keygen.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT
RAW="${TMP}/key.pem"
TMP_CERT="${TMP}/cert.x509.pem"
TMP_PK8="${TMP}/key.pk8"

SUBJECT="${ANDROID_KEY_SUBJECT:-/C=US/ST=California/L=Mountain View/O=Android/OU=Android/CN=${CERT_CN}/emailAddress=android@android.com}"

openssl genrsa -out "${RAW}" "${BITS}" >/dev/null 2>&1
openssl req -new -x509 -sha256 -key "${RAW}" -out "${TMP_CERT}" \
    -days "${DAYS}" -subj "${SUBJECT}"
openssl pkcs8 -topk8 -inform PEM -outform DER -in "${RAW}" \
    -out "${TMP_PK8}" -nocrypt

# Validate temporary outputs before publishing them under their final names.
openssl x509 -in "${TMP_CERT}" -noout >/dev/null 2>&1
openssl pkcs8 -inform DER -in "${TMP_PK8}" -nocrypt -out /dev/null >/dev/null 2>&1

chmod 600 "${TMP_PK8}"
chmod 644 "${TMP_CERT}"

# Publish only after the full pair has been created and validated.
mv -f -- "${TMP_PK8}" "${PK8}"
mv -f -- "${TMP_CERT}" "${CERT}"

echo "[ok] ${OUT} (RSA-${BITS}, CN=${CERT_CN})"
