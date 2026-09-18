# Source-analysis conclusions used for v6

The latest Codex audit concluded that the current `vendor/priv` implementation should not
be kept unchanged. The important findings used to design v6 are:

- private package signing has a real Android-security benefit over public AOSP test keys;
- no custom DeepDroid feature was demonstrated to require the exact current private
  platform-key fingerprint; those features require the Android `platform` signing role;
- one platform certificate across many spoofed device profiles is valid because it is a
  ROM/signing-domain identity, not a physical-device identity;
- the old tree custom-signed APEX containers but left APEX payload keys at source defaults;
- the old `vendor/priv/keys/avb.pem` existed but was not wired into the device BoardConfig;
- `BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3` must not be used for a release trust chain;
- GMS core/Play Store/GSF are mostly PRESIGNED and should remain so; packages intentionally
  declared `certificate: "platform"` will follow the ROM platform key;
- private package signing is not demonstrated to fix Play Integrity/NO_INTEGRITY.

v6 therefore implements private signing as a stable ROM release-security domain, not as a
device-profile identity and not as a KeyMint/TEE attestation replacement.
