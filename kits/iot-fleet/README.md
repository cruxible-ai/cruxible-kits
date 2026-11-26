# IoT fleet kit

## What it is

A starter vocabulary for industrial IoT and edge fleets: sites, equipment
assets (pumps, chillers, compressors, motors, gateways), the sensors that watch
them, firmware releases, reviewed operating baselines, anomalies, and
maintenance records. Raw time-series stays in your historian; Cruxible holds
what the historian does not: approved bounds, reviewed asset conditions,
firmware trust, dismissed false positives, and the evidence each judgment rests
on.

A reviewed baseline is reused by every later check, and a dismissed false
positive stays dismissed until the baseline it was judged against changes. A
sensor's health goes stale 30 minutes after its last heartbeat, so a silent
device reads as unknown, never as healthy.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which assets need attention? | `fleet.assets_needing_attention` (`operating_state >= warning` or `condition >= degraded`) |
| What runs at one site? | `fleet.assets_by_site` (parameter `site`, such as `plant-a`) |
| Which anomalies are unreviewed? | `fleet.open_anomalies` (`open`, severity `medium` or worse) |
| Which assets run deprecated or recalled firmware? | `fleet.assets_on_recalled_firmware` |
| Which judgments rest on a reading or baseline that moved? | `cruxible next` lists each as `claim_dependency_stale` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `fleet.site` | its slug (`plant-a`) | `title`, `region` |
| `fleet.asset` | its asset tag (`line-2-pump-b`) | `site`, `asset_type`, `model`, `firmware`, `criticality`, `operating_state`, `condition`, `last_inspected` |
| `fleet.sensor` | its device id (`coldroom-04-temp`) | `site`, `measures`, `mounted_on`, `firmware`, `status` (stale after 30 minutes) |
| `fleet.firmware` | its slug (`acme-ctrl-3.4.2`) | `vendor`, `version`, `applies_to`, `status` (`testing` to `recalled`) |
| `fleet.baseline` | its asset and metric (`line-2-pump-b--vibration`) | `low`, `high`, `unit`, `status` (`proposed`, `approved`, `retired`) |
| `fleet.anomaly` | its slug | `asset`, `metric`, `severity`, `disposition`, `justification` |
| `fleet.maintenance` | its slug | `asset`, `kind`, `status`, `performed_on`, `resolves` |

Ranked levels are ordered enums, lowest first, so queries compare them:
`criticality` (`low` to `critical`), `operating_state` (`normal` to `offline`),
`condition` (`healthy` to `failed`), `severity` (`info` to `critical`), and
`fleet.firmware.status` (`testing` to `recalled`). The kit also installs one
governed review guidance Document (`document:fleet.guidance.review-guidance`)
attached to `asset.condition`, `baseline.status`, `anomaly.disposition`, and
`firmware.status`.

## Recording a judgment

A reviewed condition pinned to the observed state and approved baseline it was
judged from. When either changes, `cruxible next` flags the condition for a
re-check:

```python
from cruxible_client import Cruxible, FileEvidence

with Cruxible.connect() as cx:
    w = cx.world()  # closed types from .cruxible/world.pyi
    w.fleet.asset["line-2-pump-b"].set(
        condition="degraded",
        because="Vibration past the approved 4500 um/s bound; bearing swap planned.",
        evidence=FileEvidence(file="inspections/line-2-pump-b.md#Outer race spalling"),
        based_on=[
            "fleet.asset/line-2-pump-b#operating_state",
            "fleet.baseline/line-2-pump-b--vibration#high",
        ],
    )
```

## Install

```sh
cruxible kit add iot-fleet
```

The kit carries definitions and review guidance only: no values, Providers,
Procedures, or Lines. Telemetry sync and model runs are yours to automate. In
the kits repository the release rebuilds from
`kits/iot-fleet/source/definitions.py` with
`python scripts/build_kit.py kits/iot-fleet SCRATCH`.
