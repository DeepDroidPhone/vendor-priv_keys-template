# Migration policy

## If the current keyset has already shipped

Do **not** regenerate or rename keys merely to make the layout prettier. Signing continuity
is more important than naming.

1. Back up the complete existing `vendor/priv/keys` private material offline.
2. Import the existing `keys.mk` mappings into v6 with `configure_profile.py`.
3. Copy existing private/public key pairs into the v6 layout only when preserving the same
   signing identity is required.
4. Run `verify_keyset.py`.
5. Do not change APEX payload, OTA, or AVB keys in an incremental release without a
   supported rotation/migration plan.

The old `releasekey -> testkey` alias is suboptimal for a **new** keyset, but if a released
build already uses that identity, v6 reports it as a warning rather than silently rotating it.

## If this is a fresh signing identity

Use the generated v6 configuration, run `keys.sh` once, back up private material, and never
regenerate keys for later releases.

A fresh identity should use an independent `releasekey`.
