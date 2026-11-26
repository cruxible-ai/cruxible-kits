# IoT fleet kit

## What it is

A starter vocabulary for IoT and edge fleets: sites, pumps, the sensors that
watch them, reviewed operating baselines and the anomalies flagged against
them. Telemetry and model output are recorded as observations; approved
baselines, pump condition and anomaly dispositions are governed decisions an
agent pins to the readings it judged from.

A reviewed baseline is reused by every later check, and a dismissed false
positive stays dismissed until the baseline it was judged against changes. A
sensor's health goes stale 30 minutes after its last heartbeat, so a silent
device reads as unknown, never as healthy.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which pumps need attention? | `fleet.pumps_needing_attention` (bearing wear `high` or worse, or condition `degraded` or worse) |
| What runs at one site? | `fleet.pumps_by_site` (parameter `site`, such as `plant-a`) |
| Which anomalies are unreviewed? | `fleet.open_anomalies` (`open`, severity `medium` or worse) |
| Which judgments rest on a reading that moved? | `cruxible next` lists each as `claim_dependency_stale` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `fleet.site` | its slug (`plant-a`) | `title`, `region` |
| `fleet.pump` | its asset tag (`line-2-pump-b`) | `site`, `model`, `firmware`, `criticality`, `bearing_wear`, `condition`, `last_inspected` |
| `fleet.sensor` | its device id (`coldroom-04-temp`) | `site`, `measures`, `mounted_on` (a pump), `firmware`, `status` (stale after 30 minutes) |
| `fleet.baseline` | its pump and metric (`line-2-pump-b--vibration`) | `low`, `high`, `unit`, `status` (`proposed`, `approved`, `retired`) |
| `fleet.anomaly` | its slug | `asset` (a pump or sensor), `metric`, `severity`, `disposition` (`open`, `confirmed`, `dismissed`, `resolved`) |

Ranked levels are ordered enums, lowest first, so queries compare them:
`criticality` (`low` to `critical`), `bearing_wear` (`none` to `severe`),
`condition` (`healthy`, `watch`, `degraded`, `failed`) and `severity` (`info`
to `critical`). Baseline bounds are whole numbers in the baseline's own unit
(`4500` with unit `um/s`). Every field admits your own words or a passage of a
catalogued workspace file; an approved baseline should cite its commissioning
report or vendor manual.

## Recording a judgment

A reviewed condition pinned to the reading and baseline it was judged from.
When either changes, `cruxible next` flags the condition for a re-check:

```python
from cruxible_client import Cruxible, FileEvidence

with Cruxible.connect() as cx:
    w = cx.world()  # closed types from .cruxible/world.pyi
    w.fleet.pump["line-2-pump-b"].set(
        condition="degraded",
        because="Vibration past the approved 4500 um/s bound; bearing swap planned.",
        evidence=FileEvidence(file="inspections/line-2-pump-b.md#Outer race spalling"),
        based_on=[
            "fleet.pump/line-2-pump-b#bearing_wear",
            "fleet.baseline/line-2-pump-b--vibration#high",
        ],
    )
```

## Install

```sh
cruxible kit add /path/to/cruxible-kits/kits/iot-fleet                  # preview; prints the coordinate
cruxible kit add /path/to/cruxible-kits/kits/iot-fleet --commit --at OID
```

`cruxible kit add iot-fleet:1.0.0` installs the same release from the registry
once it is published. The kit carries definitions only: no values, Providers,
Procedures or Lines. Telemetry sync and model runs are yours to automate. In
the kits repository the release rebuilds from
`kits/iot-fleet/source/definitions.py` with
`python scripts/build_kit.py kits/iot-fleet SCRATCH`.
