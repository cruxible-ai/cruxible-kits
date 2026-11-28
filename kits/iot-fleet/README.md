# IoT fleet kit

## What it is

A governed vocabulary and deterministic telemetry automation kit for industrial
IoT and edge fleets: sites, equipment and edge assets (pumps, chillers, cameras,
edge hubs, motors, inverters), the sensors that watch them, firmware releases,
reviewed operating baselines, anomalies, and maintenance records. Raw
time-series stays in your historian or hub; Cruxible holds what the historian
does not: approved bounds, reviewed asset conditions, firmware trust, dismissed
false positives, and the evidence each judgment rests on.

It bundles a lightweight pure-Python telemetry provider
(`iot-telemetry-provider`, `telemetry.analyze`) with an EWMA gain filter,
flatline/heartbeat detector, and approved-baseline comparator, wired into
observations-only Lines and an observe-only attention Line. A reviewed baseline
is reused by every later check, a dismissed false positive stays dismissed until
its baseline changes, and a sensor's health goes stale 30 minutes after its last
heartbeat so a silent device never reads as healthy.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which assets need attention? | `fleet.assets_needing_attention` (`operating_state >= warning` or `condition >= degraded`) |
| What runs at one site? | `fleet.assets_by_site` (parameter `site`, such as `yard-north`) |
| Which anomalies are unreviewed? | `fleet.open_anomalies` (unset or `open`, severity `medium` or worse) |
| Which assets run deprecated or recalled firmware? | `fleet.assets_on_recalled_firmware` |
| Which judgments rest on a reading or baseline that moved? | `cruxible next` lists each as `claim_dependency_stale` alongside unjudged Line inbox items |

## Automation loop

| Component | Authority | What it does |
|---|---|---|
| `fleet.telemetry-ingest.<name>` | `settle` (`scope: observations`) | Reads approved `fleet.baseline` rows and one hub telemetry batch (`workspace.file`), runs `iot-telemetry-provider#telemetry.analyze` (EWMA gain filter + flatline check + bound comparator), lands `fleet.telemetry-analysis`, and settles `fleet.asset.operating_state`. |
| `fleet.sensor-health.<name>` | `settle` (`scope: observations`) | Runs automatically on `capture_landing` of `fleet.telemetry-analysis` (zero recompute) and settles `fleet.sensor.status` (`online`, `degraded`, `offline`). |
| `fleet.anomaly-ingest.<name>` | `settle` (`scope: observations`) | Runs automatically on `capture_landing` of `fleet.telemetry-analysis` (zero recompute) and creates/populates `fleet.anomaly` observations (`asset`, `metric`, `severity`). |
| `fleet.attention` | `observe` | Queries unjudged anomalies at or above `min_severity` (`fleet.anomalies_needing_triage`) and posts them to the Line inbox for `cruxible next`. |

No automated Line can touch normative judgments (`fleet.baseline.*`,
`fleet.asset.condition`, `fleet.anomaly.disposition`, `fleet.firmware.status`).

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `fleet.site` | its slug (`yard-north`) | `title`, `region` |
| `fleet.asset` | its asset tag (`cam-dock-02`, `line-2-pump-b`) | `site`, `asset_type`, `model`, `firmware`, `criticality`, `operating_state`, `condition`, `last_inspected` |
| `fleet.sensor` | its device id (`cam-dock-02-temp`) | `site`, `measures`, `mounted_on`, `firmware`, `status` (stale after 30 minutes) |
| `fleet.firmware` | its slug (`cam-os-2.4.1`) | `vendor`, `version`, `applies_to`, `status` (`testing` to `recalled`) |
| `fleet.baseline` | its asset and metric (`cam-dock-02--temperature`) | `low`, `high`, `unit`, `status` (`proposed`, `approved`, `retired`) |
| `fleet.anomaly` | its slug | `asset`, `metric`, `severity`, `disposition`, `justification` |
| `fleet.maintenance` | its slug | `asset`, `kind`, `status`, `performed_on`, `resolves` |

Ranked levels are ordered enums, lowest first, so queries compare them:
`criticality` (`low` to `critical`), `operating_state` (`normal` to `offline`),
`condition` (`healthy` to `failed`), `severity` (`info` to `critical`), and
`fleet.firmware.status` (`testing` to `recalled`). The kit also installs one
governed review guidance Document (`document:fleet.guidance.review-guidance`)
attached to `asset.condition`, `baseline.status`, `anomaly.disposition`, and
`firmware.status`.

## Install and adopt

```sh
cruxible kit add iot-fleet --commit
cruxible kit adopt iot-fleet --yes
cruxible kit adopt iot-fleet:telemetry --param name=hub --param relative_path=telemetry/hub.json --yes
cruxible line enable fleet.sensor-health.hub fleet.anomaly-ingest.hub --runbook fleet.check
cruxible runbook run fleet.check
```

See `examples/camera-hub/README.md` for a full 60-second walkthrough (1 central
hub, 3 cameras, a transient spike absorbed by the EWMA gain filter, and a
sustained thermal fault plus flatlined sensor that wake `cruxible next`).

## Extending providers with your agent

The bundled `iot-telemetry-provider` is pure Python stdlib so every fleet gets a
fast, cross-platform baseline with zero native wheel bloat. Providers are meant
to be edited or replaced by your agent as your fleet grows: see
`examples/camera-opencv/frame_health_provider.py` for an optional agent-editable
OpenCV starter (blur, lens occlusion, and frozen-frame checks) you can adapt and
pin with `cruxible provider publish`.

In the kits repository this release rebuilds from `kits/iot-fleet/source/` with
`python kits/iot-fleet/source/build_release.py SCRATCH`.
