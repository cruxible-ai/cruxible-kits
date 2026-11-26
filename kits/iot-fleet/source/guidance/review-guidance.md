# IoT fleet review guidance

Guides: `fleet.asset.condition`, `fleet.baseline.status`, `fleet.anomaly.disposition`, `fleet.firmware.status`.

## Mirror vs. fetch boundary

Keep raw high-frequency telemetry and time-series data in your historian or TSDB. Cruxible holds what the historian does not: approved operating bounds, reviewed asset conditions, firmware release trust, anomaly dispositions, and the evidence each decision rests on.

## Approving a baseline (`fleet.baseline.status`)

- Cite the commissioning report, vendor datasheet, or engineering sign-off (`FileEvidence`) that justifies `low` and `high` in the declared `unit`.
- Revise the `(asset, metric)` baseline in place when bounds change so every condition or dismissed anomaly pinned via `based_on` reopens automatically.

## Judging asset condition (`fleet.asset.condition`)

- Pin (`based_on`) the judgment to the asset's `operating_state` and the approved `fleet.baseline` bounds (`low` / `high`) used to decide it.
- Cite the inspection note or diagnostic report when moving an asset to `degraded` or `failed`.

## Disposing an anomaly (`fleet.anomaly.disposition`)

- When marking an anomaly `dismissed`, record a `fleet.anomaly.justification` (`sensor_drift`, `maintenance_window`, `transient_spike`, `baseline_outdated`) and pin (`based_on`) the baseline it was evaluated against so a baseline update reopens the dismissal.
- When marking an anomaly `resolved`, link the corrective `fleet.maintenance` record via `fleet.maintenance.resolves`.

## Firmware release status (`fleet.firmware.status`)

- Moving a firmware release to `deprecated` or `recalled` immediately flags every asset and sensor linked to it via `fleet.assets_on_recalled_firmware`.
