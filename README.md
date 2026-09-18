# PE13 / sargo private signing template v6

A source-aware private-signing template for the audited **PixelExperience/AOSP Android 13**
tree targeting **Google Pixel 3a (`sargo`)**.

This is for ROM release security:

- APK/system package certificates;
- APEX container certificates;
- APEX payload AVB keys;
- OTA verification identity;
- ROM/vbmeta AVB identity.

It is **not** a Google/OEM signing-key set, KeyMint/TEE attestation credential, or a
Play Integrity bypass.

## Why v6

The latest source audit found that private signing is not required by the custom DeepDroid
features, but it has a real security benefit for a long-lived ROM release. The old
`vendor/priv` implementation was partial. v6 keeps the useful private-signing concept and
removes the most important failure modes:

- exact current `PRODUCT_CERTIFICATE_OVERRIDES` can be imported before migration;
- `keys.mk` and `Android.bp` are generated from one JSON profile;
- `releasekey` is independent for a fresh keyset;
- v6 does not clear upstream recovery-key policy;
- APEX container and payload signing are handled as separate layers;
- private APEX payload keys are created only by an explicit preparation step;
- release signing never generates private material;
- `vendor/priv/keys/*` is the ROM's own keyspace, not blindly preserved as vendor content;
- PRESIGNED/vendor/device artifacts remain preserved;
- AVB disable flags are rejected;
- verification checks the **expected signer per metadata key path**, not merely “some private
  certificate from this directory”;
- public-key manifest and key-pair consistency tools are included.

## Recommended workflow

### 1. Stage v6 outside the old key directory

If `vendor/priv/keys` already exists, do not overwrite it yet.

Import the exact current mapping:

```bash
python3 /path/to/pe13-priv-keys-template-v6/configure_profile.py \
  --import-keys-mk <android-root>/vendor/priv/keys/keys.mk
```

Review the output. Then write the imported profile/config:

```bash
python3 /path/to/pe13-priv-keys-template-v6/configure_profile.py \
  --import-keys-mk <android-root>/vendor/priv/keys/keys.mk \
  --write
```

For a fresh tree without an existing private-signing config, the included audited baseline
profile can be used.

### 2. Install at `vendor/priv/keys`

Keep the existing single product include in `vendor/aosp/config/common.mk`.

Follow `INTEGRATION.md` for the AVB BoardConfig changes. In particular, remove `--flags 3`.

### 3. Generate/import keys

For a fresh identity:

```bash
vendor/priv/keys/keys.sh
```

Defaults:

- standard Android package keys: RSA-2048;
- override certificate keys: RSA-4096;
- ROM AVB key: RSA-4096.

To preserve an already-released identity, migrate the existing key files instead of running
fresh generation.

### 4. Verify keyset

```bash
python3 -m pip install -r vendor/priv/keys/requirements.txt
python3 vendor/priv/keys/verify_keyset.py
python3 vendor/priv/keys/key_manifest.py
```

`PUBLIC_KEY_MANIFEST.json` contains public fingerprints only and is safe to keep for release
audit/history.

### 5. Build fresh target-files

```bash
source build/envsetup.sh
lunch aosp_sargo-user
m target-files-package otatools
```

Do not reuse stale target-files from a different key generation.

### 6. Prepare target-specific APEX/mapped keys

Read-only first:

```bash
python3 vendor/priv/keys/prepare_target_keys.py TARGET_FILES.zip
```

After reviewing:

```bash
python3 vendor/priv/keys/prepare_target_keys.py TARGET_FILES.zip --generate
```

### 7. Release-sign

```bash
python3 vendor/priv/keys/sign_release.py --dry-run \
  TARGET_FILES.zip SIGNED_TARGET_FILES.zip

python3 vendor/priv/keys/sign_release.py \
  TARGET_FILES.zip SIGNED_TARGET_FILES.zip
```

### 8. Verify the signed artifact

```bash
python3 vendor/priv/keys/check_target_files.py SIGNED_TARGET_FILES.zip
```

The checker validates the expected APK/APEX container certificate, expected APEX payload
public key, AVB flags/vbmeta signature, and OTA certificate bundle.

### 9. Produce OTA/image

```bash
python3 build/make/tools/releasetools/ota_from_target_files.py \
  -k vendor/priv/keys/releasekey \
  SIGNED_TARGET_FILES.zip SIGNED_OTA.zip
```

Use the tree's `img_from_target_files` for an image package.

## Device profiles

All spoofed device profiles may share the same v6 platform certificate. The platform
certificate is a ROM signing-domain identity, not a unique hardware-device identity.

If a profile-specific PackageInfo/SigningInfo spoof is later used, keep it as a separate
userspace compatibility layer. Do not rotate the real private ROM keyset per profile.

## Boundaries

Keep these concepts separate:

```text
APK/platform certificate
APEX container certificate
APEX payload AVB key
OTA verification certificate
ROM/vbmeta AVB key
KeyMint/TEE hardware attestation
```

The first five are release-signing infrastructure. The last one is not provided by this
repository.
