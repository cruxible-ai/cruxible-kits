"""Unit tests for iot_telemetry_provider.telemetry."""

from __future__ import annotations

import json
import pytest

from iot_telemetry_provider.telemetry import TelemetryRefused, analyze_batch

BASELINES = [
    {"asset": "cam-gate-01", "metric": "temperature", "low": 500, "high": 5500, "unit": "centi-degC"},
    {"asset": "cam-dock-02", "metric": "temperature", "low": 500, "high": 5500, "unit": "centi-degC"},
    {"asset": "cam-lot-03", "metric": "temperature", "low": 500, "high": 5500, "unit": "centi-degC"},
]


def _encode(payload: dict) -> bytes:
    return json.dumps(payload).encode()


def test_single_sample_spike_absorbed_by_ewma_gain_filter() -> None:
    batch = {
        "hub": "hub-north-01",
        "captured_at": "2026-11-26T15:00:00Z",
        "sensors": [
            {
                "sensor": "cam-gate-01-temp",
                "asset": "cam-gate-01",
                "metric": "temperature",
                "unit": "centi-degC",
                "last_seen_age_s": 30,
                "samples": [4100, 4120, 4110, 6800, 4130, 4125],
            }
        ],
    }
    doc = analyze_batch(_encode(batch), BASELINES, alpha="0.3", min_breach_samples=3)
    assert doc["spikes_filtered"] == 1
    assert doc["anomalies_count"] == 0
    assert doc["sensors"][0]["status"] == "online"
    assert doc["assets"][0] == {
        "asset": "cam-gate-01",
        "operating_state": "normal",
        "reason": doc["assets"][0]["reason"],
    }
    assert "absorbed by EWMA" in doc["assets"][0]["reason"]


def test_sustained_thermal_climb_triggers_fault_and_anomaly() -> None:
    batch = {
        "hub": "hub-north-01",
        "captured_at": "2026-11-26T15:15:00Z",
        "sensors": [
            {
                "sensor": "cam-dock-02-temp",
                "asset": "cam-dock-02",
                "metric": "temperature",
                "unit": "centi-degC",
                "last_seen_age_s": 20,
                "samples": [5200, 5450, 5780, 6100, 6350, 6500],
            }
        ],
    }
    doc = analyze_batch(_encode(batch), BASELINES, alpha="0.3", min_breach_samples=3)
    assert doc["assets"][0]["operating_state"] == "fault"
    assert doc["anomalies_count"] == 1
    anomaly = doc["anomalies"][0]
    assert anomaly["name"] == "cam-dock-02--temperature--bound-breach"
    assert anomaly["asset"] == "cam-dock-02"
    assert anomaly["metric"] == "temperature"
    assert anomaly["severity"] == "high"


def test_flatlined_sensor_marks_degraded_and_opens_anomaly() -> None:
    batch = {
        "hub": "hub-north-01",
        "captured_at": "2026-11-26T15:15:00Z",
        "sensors": [
            {
                "sensor": "cam-lot-03-temp",
                "asset": "cam-lot-03",
                "metric": "temperature",
                "unit": "centi-degC",
                "last_seen_age_s": 15,
                "samples": [4100, 4100, 4100, 4100, 4100, 4100],
            }
        ],
    }
    doc = analyze_batch(_encode(batch), BASELINES, flatline_samples=5)
    assert doc["sensors"][0]["status"] == "degraded"
    assert doc["assets"][0]["operating_state"] == "warning"
    assert doc["anomalies_count"] == 1
    assert doc["anomalies"][0]["name"] == "cam-lot-03-temp--temperature--sensor-flatline"
    assert doc["anomalies"][0]["severity"] == "medium"


def test_stale_heartbeat_marks_sensor_and_asset_offline() -> None:
    batch = {
        "hub": "hub-north-01",
        "captured_at": "2026-11-26T15:15:00Z",
        "sensors": [
            {
                "sensor": "cam-lot-03-temp",
                "asset": "cam-lot-03",
                "metric": "temperature",
                "unit": "centi-degC",
                "last_seen_age_s": 2400,
                "samples": [4100, 4120],
            }
        ],
    }
    doc = analyze_batch(_encode(batch), BASELINES, max_heartbeat_age_s=1800)
    assert doc["sensors"][0]["status"] == "offline"
    assert doc["assets"][0]["operating_state"] == "offline"
    assert doc["anomalies"][0]["name"] == "cam-lot-03-temp--temperature--sensor-offline"


def test_invalid_inputs_refused() -> None:
    with pytest.raises(TelemetryRefused):
        analyze_batch(b"not-json", BASELINES)
    with pytest.raises(TelemetryRefused):
        analyze_batch(_encode({"hub": "h", "captured_at": "t", "sensors": []}), BASELINES, alpha="0")
    with pytest.raises(TelemetryRefused):
        analyze_batch(
            _encode(
                {
                    "hub": "h",
                    "captured_at": "t",
                    "sensors": [
                        {"sensor": "s1", "asset": "a1", "metric": "bogus", "samples": [1, 2]}
                    ],
                }
            ),
            BASELINES,
        )
