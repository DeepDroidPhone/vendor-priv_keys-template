# PixelExperience 13 / sargo integration

## Before replacing the current vendor/priv tree

If the source already contains `vendor/priv/keys/keys.mk`, stage v6 somewhere else first and
import the exact current mapping set:

```bash
python3 /path/to/v6/configure_profile.py \
  --import-keys-mk /home/mat/ROM/deepdroid/vendor/priv/keys/keys.mk \
  --write
```

This avoids guessing whether the current source uses 80/73, 84/76, or another mapping set.

## Product signing

The audited source already includes:

```make
-include vendor/priv/keys/keys.mk
```

from `vendor/aosp/config/common.mk`. Keep one include only.

## AVB

Remove the current release-unsafe line from the bonito tree:

```make
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3
```

Then include, at the END of the final bonito/sargo BoardConfig chain:

```make
include vendor/priv/keys/BoardConfigPrivKeys.mk
```

Do not depend on the missing `external/avb-keys/avb.pem` path if v6 is the chosen AVB identity.

## Preflight

Before key generation/building:

```bash
python3 vendor/priv/keys/audit_integration.py
```

After keys are generated/imported:

```bash
python3 vendor/priv/keys/verify_keyset.py
python3 vendor/priv/keys/key_manifest.py
```

## Build/release flow

```text
fresh source build
  -> target-files
  -> prepare_target_keys.py (read-only)
  -> prepare_target_keys.py --generate
  -> sign_release.py --dry-run
  -> sign_release.py
  -> check_target_files.py
  -> ota_from_target_files / img_from_target_files
```

Use a clean flash when intentionally starting a new APK/APEX/OTA/AVB signing identity.
