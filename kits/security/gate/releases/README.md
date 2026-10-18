# Upgrade fixture provenance

`1.0.1/` contains only the exact `cruxible-kit.json`, `artifacts/` and
`providers/` bytes from kits commit `11a3548` (the 1.0.1 rebuild on core
`ac1c33665`). Do not regenerate these bytes with a newer core: the gate must
start from the old Procedures, registrations and bundled builds on a live
instance before making its single 1.0.2 kit-add upgrade.
