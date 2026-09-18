#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SECURITY_DIR="${TOP}/build/make/target/product/security"
AVBTOOL="${TOP}/external/avb/avbtool.py"
cd "${SCRIPT_DIR}"

[[ -f "${TOP}/build/make/core/config.mk" ]] || { echo "error: not inside Android source tree" >&2; exit 1; }
[[ -d "${SECURITY_DIR}" ]] || { echo "error: missing ${SECURITY_DIR}" >&2; exit 1; }
[[ -f "${AVBTOOL}" ]] || { echo "error: missing ${AVBTOOL}" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required" >&2; exit 1; }

# Generate files that bind the generated keys into the Android build, like the
# older private-key templates. They are intentionally not shipped pre-generated.
echo "== Generate DeepDroid signing build files =="
python3 ./generate_config.py --write
chmod +x ./make_key.sh

PLATFORM_BITS="${ANDROID_PLATFORM_KEY_BITS:-2048}"
OVERRIDE_BITS="${ANDROID_OVERRIDE_KEY_BITS:-4096}"
AVB_BITS="${ANDROID_AVB_BITS:-4096}"

echo
echo "== Standard Android package keys =="
# Fresh keysets get an independent release identity.
./make_key.sh releasekey "${PLATFORM_BITS}" releasekey
for src in "${SECURITY_DIR}"/*.pk8; do
    [[ -e "${src}" ]] || continue
    name="$(basename "${src}" .pk8)"
    ./make_key.sh "${name}" "${PLATFORM_BITS}" "${name}"
done

echo
echo "== DeepDroid/Mainline certificate override keys =="
while IFS= read -r cert; do
    [[ -n "${cert}" ]] || continue
    ./make_key.sh "${cert}" "${OVERRIDE_BITS}" "${cert}"
done < <(python3 ./generate_config.py --print-certificates)

echo
echo "== Android Verified Boot key =="
if [[ ! -f avb.pem ]]; then
    umask 077
    TMP_AVB="$(mktemp .avb.pem.XXXXXX)"
    trap 'rm -f "${TMP_AVB:-}"' EXIT
    openssl genrsa -out "${TMP_AVB}" "${AVB_BITS}" >/dev/null 2>&1
    openssl pkey -in "${TMP_AVB}" -noout >/dev/null 2>&1
    chmod 600 "${TMP_AVB}"
    mv -f "${TMP_AVB}" avb.pem
    trap - EXIT
    echo "[ok] avb.pem (RSA-${AVB_BITS})"
else
    openssl pkey -in avb.pem -noout >/dev/null 2>&1 || {
        echo "error: existing avb.pem is invalid; refusing to regenerate signing identity" >&2
        exit 1
    }
    echo "[skip] avb.pem already exists"
fi
"${AVBTOOL}" extract_public_key --key avb.pem --output avb.avbpubkey
chmod 644 avb.avbpubkey

mkdir -p mapped apex-payload
chmod 700 mapped apex-payload

echo
echo "== Verify generated keyset =="
python3 ./verify_keyset.py

echo
echo "DeepDroid private keyset is ready."
echo "Generated build files: keys.mk, Android.bp, BUILD.bazel"
echo "Do not regenerate keys after a release if signing continuity matters."
