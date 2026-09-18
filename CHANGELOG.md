# Changelog

## 6.0

- Re-audited the two supplied private-key repositories and PE13 templates v3/v4/v5.
- Kept the audited DeepDroid-style 84/76 mapping set only as a fallback baseline.
- Added `configure_profile.py` so the exact current source `keys.mk` can be imported before
  replacing the old `vendor/priv` tree.
- Removed v5's explicit empty `PRODUCT_EXTRA_RECOVERY_KEYS` assignment.
- Kept independent `releasekey` for fresh identities, but migration tooling no longer treats
  an already-shipped release/test alias as an automatic blocker.
- Improved release verification to require the expected certificate for each APK/APEX
  container key path instead of accepting any private certificate in the repository.
- Kept APEX payload replacement separate and explicit.
- Tightened AVB fallback behavior: unsupported releasetool AVB replacement is an error unless
  target-files already points to the private AVB key.
- Added `verify_keyset.py` for public/private-pair consistency.
- Added `key_manifest.py` for a public-only release identity manifest.
- Added migration/source-audit documentation based on the latest Codex report.
