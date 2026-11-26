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

## Automated telemetry Lines and agent-edited providers

- The bundled `iot-telemetry-provider` (`telemetry.analyze`) runs an EWMA gain filter (`alpha`), flatline/heartbeat check, and approved-baseline comparator under a `scope: observations` Mandate. It settles `fleet.asset.operating_state`, `fleet.sensor.status`, and new `fleet.anomaly` observations only; it cannot modify approved baselines, `asset.condition`, `anomaly.disposition`, or `firmware.status`.
- Treat bundled and example providers as starting code for agents to customize, not a ceiling. When a fleet needs custom signal processing or hardware checks (such as OpenCV blur, occlusion, or frozen-frame detection on edge cameras, FFT bearing harmonics, or MQTT/OPC-UA adapters), adapt the starter provider (see `examples/camera-opencv/frame_health_provider.py`), publish and pin it via `cruxible provider publish`, and swap it into the Line through a governed proposal.
