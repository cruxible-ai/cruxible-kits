"""Seed the camera-hub example fleet into the current workspace's Cruxible instance.

Run after `cruxible init` and `cruxible kit add iot-fleet`:

    cruxible python examples/camera-hub/seed_fleet.py

After running Batch 1 telemetry, pin the reviewed condition sign-off on cam-dock-02:

    cruxible python examples/camera-hub/seed_fleet.py --sign-off
"""

from __future__ import annotations

import sys

from cruxible_client import Cruxible


def seed() -> None:
    with Cruxible.connect() as cx:
        w = cx.world()

        site = w.fleet.site.define(
            "yard-north",
            title="North Yard",
            region="us-east",
        )
        fw_cam = w.fleet.firmware.define(
            "cam-os-2.4.1",
            vendor="Acme Vision",
            version="2.4.1",
            applies_to="CamPro-4K",
            status="approved",
        )
        fw_hub = w.fleet.firmware.define(
            "hub-os-1.9.0",
            vendor="Acme Vision",
            version="1.9.0",
            applies_to="EdgeHub-X2",
            status="approved",
        )

        hub = w.fleet.asset.define(
            "hub-north-01",
            site=site,
            asset_type="edge_hub",
            model="Acme EdgeHub-X2",
            firmware=fw_hub,
            criticality="critical",
        )
        cam_gate = w.fleet.asset.define(
            "cam-gate-01",
            site=site,
            asset_type="camera",
            model="Acme CamPro-4K",
            firmware=fw_cam,
            criticality="high",
        )
        cam_dock = w.fleet.asset.define(
            "cam-dock-02",
            site=site,
            asset_type="camera",
            model="Acme CamPro-4K",
            firmware=fw_cam,
            criticality="high",
        )
        cam_lot = w.fleet.asset.define(
            "cam-lot-03",
            site=site,
            asset_type="camera",
            model="Acme CamPro-4K",
            firmware=fw_cam,
            criticality="medium",
        )

        sensors = [
            w.fleet.sensor.define(
                "hub-north-01-temp", site=site, measures="temperature", mounted_on=hub, firmware=fw_hub
            ),
            w.fleet.sensor.define(
                "cam-gate-01-temp", site=site, measures="temperature", mounted_on=cam_gate, firmware=fw_cam
            ),
            w.fleet.sensor.define(
                "cam-dock-02-temp", site=site, measures="temperature", mounted_on=cam_dock, firmware=fw_cam
            ),
            w.fleet.sensor.define(
                "cam-lot-03-temp", site=site, measures="temperature", mounted_on=cam_lot, firmware=fw_cam
            ),
        ]

        # Approved operating baselines in centi-degC (500 = 5.0 C, 5500 = 55.0 C).
        # cam-gate-01 sits in direct sun and carries a higher approved ceiling (60.0 C).
        baselines = [
            w.fleet.baseline.define(
                asset=hub, metric="temperature", low=500, high=6500, unit="centi-degC", status="approved"
            ),
            w.fleet.baseline.define(
                asset=cam_gate, metric="temperature", low=500, high=6000, unit="centi-degC", status="approved"
            ),
            w.fleet.baseline.define(
                asset=cam_dock, metric="temperature", low=500, high=5500, unit="centi-degC", status="approved"
            ),
            w.fleet.baseline.define(
                asset=cam_lot, metric="temperature", low=500, high=5500, unit="centi-degC", status="approved"
            ),
        ]

        w.write(
            site,
            fw_cam,
            fw_hub,
            hub,
            cam_gate,
            cam_dock,
            cam_lot,
            *sensors,
            *baselines,
            because="Commissioned North Yard camera hub and three cameras with approved thermal baselines.",
        )
        print("Seeded yard-north (1 hub, 3 cameras, 4 sensors, 4 approved baselines).")


def sign_off() -> None:
    """Pin cam-dock-02's reviewed condition to its live telemetry operating_state and baseline."""

    with Cruxible.connect() as cx:
        w = cx.world()
        dock_asset = w.fleet.asset["cam-dock-02"]
        dock_bound = next(
            b
            for b in w.fleet.baseline
            if b.metric and b.metric[0].value == "temperature"
            and any("cam-dock-02" in str(c.value) for c in b.asset)
        )
        dock_asset.set(
            condition="healthy",
            based_on=[*dock_asset.operating_state, *dock_bound.high],
            because="Commissioning check passed; operating state normal within 55.0 C ceiling.",
        )
        print("Signed off cam-dock-02 condition=healthy pinned to operating_state and baseline.")


def main() -> None:
    if "--sign-off" in sys.argv[1:]:
        sign_off()
    else:
        seed()


if __name__ == "__main__":
    main()
