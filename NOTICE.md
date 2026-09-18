# Notice / provenance

This template was rebuilt from analysis of:

- `android_vendor_lineage-priv_keys` supplied by the user (Giovanni Ricca / Apache-2.0 headers);
- `vendor-priv_keys-template` supplied by the user (LineageOS Project / Apache-2.0 headers);
- the previously generated PE13 private-key templates v3/v4/v5;
- the user's Codex audit of the current PixelExperience 13 / sargo source tree.

The certificate-override baseline in `signing_profile.json` is derived from the supplied
DeepDroid-style template because it was closest to the audited current source. For exact
source compatibility, import the current source's existing `keys.mk` with
`configure_profile.py` before replacing the old key repository.
