# Camera hub walkthrough (iot-fleet 2.1.0)

This 60-second walkthrough runs the `iot-fleet` telemetry Line (`fleet.telemetry-ingest`,
`fleet.sensor-health`, `fleet.anomaly-ingest`, and `fleet.attention`) on a small edge camera
fleet: one central hub (`hub-north-01`) and three cameras (`cam-gate-01`, `cam-dock-02`,
`cam-lot-03`).

## What it demonstrates

1. **Batch 1 (transient spike absorbed):** `cam-gate-01-temp` reports a single-sample `74.0 C`
   spike (`7400` centi-degC) inside a normal `42 C` window. The EWMA gain filter (`alpha=0.3`)
   and sustained-breach window (`min_breach_samples=3`) absorb it cleanly: zero anomalies,
   `operating_state` stays `normal`, and `cruxible next` stays quiet.
2. **Batch 2 (sustained thermal climb + flatlined sensor):**
   - `cam-dock-02-temp` climbs past its approved `55.0 C` (`5500`) baseline for 3 consecutive
     filtered samples -> `fleet.telemetry-ingest.hub` settles `operating_state=fault`,
     `fleet.anomaly-ingest.hub` opens `cam-dock-02--temperature--bound-breach` (`high`), and
     the prior pinned `condition=healthy` judgment wakes up in `cruxible next`.
   - `cam-lot-03-temp` flatlines at `4100` for 6 consecutive samples -> `fleet.sensor-health.hub`
     settles `status=degraded`, `fleet.anomaly-ingest.hub` opens
     `cam-lot-03-temp--temperature--sensor-flatline` (`medium`), and `fleet.attention` posts
     both unjudged anomalies to the Line inbox.
3. **Mandate boundary:** every automated Line holds a `scope: observations` Mandate. None of
   them can touch approved baselines, `asset.condition`, `anomaly.disposition`, or firmware
   trust status.

## Run it

```bash
mkdir camera-hub-demo && cd camera-hub-demo
git init -q -b main
cruxible init
cruxible kit add iot-fleet

# Copy the bundled example files into your workspace
cruxible kit docs iot-fleet --out .cruxible-docs

# 1. Seed the site, hub, 3 cameras, approved baselines, and 1 pinned sign-off
cruxible python .cruxible-docs/iot-fleet/examples/camera-hub/seed_fleet.py

# 2. Adopt the telemetry Line and attention backbone
mkdir -p telemetry
cp .cruxible-docs/iot-fleet/examples/camera-hub/hub-batch-01.json telemetry/hub.json
cruxible kit adopt iot-fleet
cruxible kit adopt iot-fleet:telemetry --param name=hub --param relative_path=telemetry/hub.json
cruxible line enable fleet.sensor-health.hub fleet.anomaly-ingest.hub --runbook fleet.check

# 3. Run Batch 1: single-sample spike on cam-gate-01 is filtered out, then pin a reviewed sign-off
cruxible runbook run fleet.check
cruxible python .cruxible-docs/iot-fleet/examples/camera-hub/seed_fleet.py --sign-off
cruxible next

# 4. Drop Batch 2 and run again: sustained thermal fault + flatlined sensor wake cruxible next
cp .cruxible-docs/iot-fleet/examples/camera-hub/hub-batch-02.json telemetry/hub.json
cruxible runbook run fleet.check
# Landing Triggers settle fleet.sensor.status and fleet.anomaly observations in the background;
# run fleet.attention once they land to post the new unjudged anomalies to the Line inbox:
sleep 2 && cruxible line run fleet.attention
cruxible next
```
