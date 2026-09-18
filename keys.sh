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

python3 ./generate_config.py --check
chmod +x ./make_key.sh

PLATFORM_BITS="${ANDROID_PLATFORM_KEY_BITS:-2048}"
OVERRIDE_BITS="${ANDROID_OVERRIDE_KEY_BITS:-4096}"
AVB_BITS="${ANDROID_AVB_BITS:-4096}"

echo "== Standard Android package keys =="
# Fresh v6 keysets get an independent release identity.
./make_key.sh releasekey "${PLATFORM_BITS}" releasekey
for src in "${SECURITY_DIR}"/*.pk8; do
    [[ -e "${src}" ]] || continue
    name="$(basename "${src}" .pk8)"
    ./make_key.sh "${name}" "${PLATFORM_BITS}" "${name}"
done

echo
echo "== PE13/Mainline certificate override keys =="
while IFS= read -r cert; do
    [[ -n "${cert}" ]] || continue
    ./make_key.sh "${cert}" "${OVERRIDE_BITS}" "${cert}"
done < <(python3 ./generate_config.py --print-certificates)

echo
echo "== Android Verified Boot key =="
if [[ ! -f avb.pem ]]; then
    umask 077
    openssl genrsa -out avb.pem "${AVB_BITS}" >/dev/null 2>&1
    chmod 600 avb.pem
    echo "[ok] avb.pem (RSA-${AVB_BITS})"
else
    echo "[skip] avb.pem already exists"
fi
"${AVBTOOL}" extract_public_key --key avb.pem --output avb.avbpubkey
chmod 644 avb.avbpubkey

mkdir -p mapped apex-payload
chmod 700 mapped apex-payload

echo
echo "Core keyset is ready."
echo "Do not regenerate any key after a release if signature/OTA/APEX/AVB continuity matters."
echo "Next: build fresh target-files, then run prepare_target_keys.py in read-only mode first."
