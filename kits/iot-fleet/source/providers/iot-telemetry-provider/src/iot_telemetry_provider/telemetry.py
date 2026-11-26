"""``telemetry.analyze``: hub telemetry batch + approved baselines -> one derived JSON document.

Pure ``@derive`` function (cruxible-provider-runtime 0.6): no network, no clock,
identical output bytes for identical inputs.

Each sensor entry in a hub batch carries raw integer samples (in the baseline's unit,
such as centi-degC or mW) and ``last_seen_age_s``. The derive runs three deterministic
checks:

1. **Heartbeat & flatline sensor health.** A sensor whose ``last_seen_age_s`` exceeds
   ``max_heartbeat_age_s`` (or has no samples) is ``offline``. A sensor with at least
   ``flatline_samples`` samples whose trailing ``flatline_samples`` readings are identical
   (zero variance) is ``degraded`` and emits a ``flatline`` anomaly against its asset.
2. **EWMA gain filter.** For each live sensor with an approved ``fleet.baseline``
   ``(low, high)``, samples pass through ``y[i] = alpha * x[i] + (1 - alpha) * y[i-1]``
   (with ``y[0] = x[0]``). Single-sample environmental spikes that fail to push the
   filtered series outside bounds for ``min_breach_samples`` consecutive points are
   absorbed and counted in ``spikes_filtered`` without opening an anomaly.
3. **Approved-baseline classification.** A sustained filtered breach (at least
   ``min_breach_samples`` consecutive filtered readings outside ``[low, high]``) sets the
   asset's ``operating_state`` to ``fault`` and emits a ``bound-breach`` anomaly
   (``critical`` when the filtered excursion exceeds 20% of the baseline span, else
   ``high``). A brief filtered excursion (1 to ``min_breach_samples - 1``) or a reading
   within 10% of the bound margin sets ``warning``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any

from cruxible_provider_runtime import CaptureView, decline, derive
from cruxible_provider_runtime.provider_api import ProviderResult

OPERATION = "telemetry.analyze"
PROVIDER_DECLINED = "provider_declined"
COORDINATE_TYPE = "http-response-v1"
SELECTOR_TYPE = "whole-response-v1"
MAX_SENSORS = 10_000
MAX_SAMPLES = 10_000

VALID_METRICS = frozenset(
    {"vibration", "temperature", "pressure", "flow", "humidity", "current", "voltage", "power"}
)
_STATE_RANK = {"normal": 0, "warning": 1, "fault": 2, "offline": 3}


class TelemetryRefused(ValueError):
    """The hub telemetry batch or parameters are malformed."""


def _parse_alpha(raw: str) -> float:
    try:
        dec = Decimal(raw)
    except (InvalidOperation, TypeError) as exc:
        raise TelemetryRefused(f"alpha must be a decimal in (0, 1], got {raw!r}") from exc
    if dec <= 0 or dec > 1:
        raise TelemetryRefused(f"alpha must be in (0, 1], got {raw!r}")
    return float(dec)


def _ewma(samples: Sequence[int], alpha: float) -> list[float]:
    filtered: list[float] = []
    acc = float(samples[0])
    for sample in samples:
        acc = alpha * float(sample) + (1.0 - alpha) * acc
        filtered.append(acc)
    return filtered


def _max_consecutive_breach(values: Sequence[float], low: int, high: int) -> int:
    best = 0
    run = 0
    for val in values:
        if val < low or val > high:
            run += 1
            if run > best:
                best = run
        else:
            run = 0
    return best


def _index_baselines(baselines: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in baselines:
        asset = row.get("asset")
        metric = row.get("metric")
        low = row.get("low")
        high = row.get("high")
        if (
            isinstance(asset, str)
            and isinstance(metric, str)
            and isinstance(low, int)
            and not isinstance(low, bool)
            and isinstance(high, int)
            and not isinstance(high, bool)
        ):
            index[(asset, metric)] = {
                "low": low,
                "high": high,
                "unit": str(row.get("unit") or ""),
            }
    return index


def analyze_batch(
    content: bytes,
    baselines: Sequence[Mapping[str, Any]],
    *,
    alpha: str = "0.3",
    min_breach_samples: int = 3,
    flatline_samples: int = 5,
    max_heartbeat_age_s: int = 1800,
) -> dict[str, Any]:
    """Run EWMA gain filtering, flatline checks, and baseline classification on one batch."""

    gain = _parse_alpha(alpha)
    if min_breach_samples < 1:
        raise TelemetryRefused("min_breach_samples must be at least 1")
    if flatline_samples < 2:
        raise TelemetryRefused("flatline_samples must be at least 2")
    if max_heartbeat_age_s < 60:
        raise TelemetryRefused("max_heartbeat_age_s must be at least 60")

    try:
        payload = json.loads(content)
    except ValueError as exc:
        raise TelemetryRefused(f"telemetry batch is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise TelemetryRefused("telemetry batch must be a JSON object")

    hub = payload.get("hub")
    if not isinstance(hub, str) or not hub.strip():
        raise TelemetryRefused("telemetry batch needs a non-empty string 'hub'")
    captured_at = payload.get("captured_at")
    if not isinstance(captured_at, str) or not captured_at.strip():
        raise TelemetryRefused("telemetry batch needs a non-empty string 'captured_at'")

    raw_sensors = payload.get("sensors")
    if not isinstance(raw_sensors, list):
        raise TelemetryRefused("telemetry batch 'sensors' must be a list")
    if len(raw_sensors) > MAX_SENSORS:
        raise TelemetryRefused(f"telemetry batch lists more than {MAX_SENSORS} sensors")

    baseline_index = _index_baselines(baselines)

    sensors_out: list[dict[str, Any]] = []
    anomalies_out: list[dict[str, Any]] = []
    asset_states: dict[str, list[tuple[str, str]]] = {}
    asset_all_offline: dict[str, bool] = {}
    seen_sensors: set[str] = set()
    total_spikes_filtered = 0

    for entry in raw_sensors:
        if not isinstance(entry, Mapping):
            raise TelemetryRefused("each item in 'sensors' must be a JSON object")
        sensor_name = entry.get("sensor")
        asset_name = entry.get("asset")
        metric = entry.get("metric")
        if not isinstance(sensor_name, str) or not sensor_name.strip():
            raise TelemetryRefused("sensor entry missing string 'sensor'")
        if not isinstance(asset_name, str) or not asset_name.strip():
            raise TelemetryRefused(f"sensor {sensor_name!r} missing string 'asset'")
        if metric not in VALID_METRICS:
            raise TelemetryRefused(f"sensor {sensor_name!r} has unknown metric {metric!r}")
        if sensor_name in seen_sensors:
            raise TelemetryRefused(f"duplicate sensor {sensor_name!r} in telemetry batch")
        seen_sensors.add(sensor_name)

        age = entry.get("last_seen_age_s", 0)
        if not isinstance(age, int) or isinstance(age, bool) or age < 0:
            raise TelemetryRefused(f"sensor {sensor_name!r} has invalid 'last_seen_age_s'")
        dropped = entry.get("dropped_samples", 0)
        if not isinstance(dropped, int) or isinstance(dropped, bool) or dropped < 0:
            raise TelemetryRefused(f"sensor {sensor_name!r} has invalid 'dropped_samples'")

        raw_samples = entry.get("samples", [])
        if not isinstance(raw_samples, list) or len(raw_samples) > MAX_SAMPLES:
            raise TelemetryRefused(f"sensor {sensor_name!r} has invalid 'samples'")
        samples: list[int] = []
        for s in raw_samples:
            if not isinstance(s, int) or isinstance(s, bool):
                raise TelemetryRefused(f"sensor {sensor_name!r} samples must be integers")
            samples.append(s)

        unit = str(entry.get("unit") or "")
        asset_states.setdefault(asset_name, [])
        asset_all_offline.setdefault(asset_name, True)

        # 1. Heartbeat freshness check.
        if age > max_heartbeat_age_s or not samples:
            reason = (
                f"last heartbeat {age}s ago exceeds {max_heartbeat_age_s}s limit"
                if age > max_heartbeat_age_s
                else "no telemetry samples reported"
            )
            sensors_out.append(
                {
                    "sensor": sensor_name,
                    "asset": asset_name,
                    "metric": metric,
                    "status": "offline",
                    "reason": reason,
                }
            )
            asset_states[asset_name].append(("offline", f"{sensor_name} offline ({reason})"))
            anomalies_out.append(
                {
                    "name": f"{sensor_name}--{metric}--sensor-offline",
                    "asset": asset_name,
                    "metric": metric,
                    "severity": "medium",
                    "reason": f"Sensor {sensor_name} is offline: {reason}.",
                }
            )
            continue

        asset_all_offline[asset_name] = False

        # 2. Flatline / stuck-sensor check.
        is_flatlined = (
            len(samples) >= flatline_samples
            and len(set(samples[-flatline_samples:])) == 1
        )
        if is_flatlined:
            stuck_val = samples[-1]
            suffix = f" {unit}" if unit else ""
            reason = (
                f"flatlined at {stuck_val}{suffix} for the last {flatline_samples} samples"
            )
            sensors_out.append(
                {
                    "sensor": sensor_name,
                    "asset": asset_name,
                    "metric": metric,
                    "status": "degraded",
                    "reason": reason,
                }
            )
            asset_states[asset_name].append(("warning", f"{sensor_name} {reason}"))
            anomalies_out.append(
                {
                    "name": f"{sensor_name}--{metric}--sensor-flatline",
                    "asset": asset_name,
                    "metric": metric,
                    "severity": "medium",
                    "reason": f"Sensor {sensor_name} {reason}; check wiring or stuck ADC.",
                }
            )
            continue

        # 3. EWMA gain filter + approved baseline comparison.
        filtered = _ewma(samples, gain)
        last_filtered = filtered[-1]
        baseline = baseline_index.get((asset_name, metric))
        sensor_status = "degraded" if dropped > 0 else "online"

        if baseline is None:
            sensor_reason = (
                f"reporting with {dropped} dropped samples; no approved baseline for {metric}"
                if dropped > 0
                else f"reporting normally (EWMA={round(last_filtered)}); no approved baseline"
            )
            sensors_out.append(
                {
                    "sensor": sensor_name,
                    "asset": asset_name,
                    "metric": metric,
                    "status": sensor_status,
                    "reason": sensor_reason,
                }
            )
            asset_states[asset_name].append(("normal", sensor_reason))
            continue

        low = baseline["low"]
        high = baseline["high"]
        b_unit = baseline["unit"] or unit
        unit_str = f" {b_unit}" if b_unit else ""

        raw_breaches = sum(1 for x in samples if x < low or x > high)
        breach_run = _max_consecutive_breach(filtered, low, high)
        span = max(high - low, 1)

        if breach_run >= min_breach_samples:
            excursion = max(last_filtered - high, low - last_filtered, 0.0)
            severity = "critical" if excursion >= 0.20 * span else "high"
            direction = "above high" if last_filtered > high else "below low"
            bound_val = high if last_filtered > high else low
            reason = (
                f"EWMA filtered {metric} {round(last_filtered)}{unit_str} stayed {direction} "
                f"{bound_val}{unit_str} for {breach_run} consecutive samples (alpha={alpha})"
            )
            sensors_out.append(
                {
                    "sensor": sensor_name,
                    "asset": asset_name,
                    "metric": metric,
                    "status": sensor_status,
                    "reason": f"reporting; {reason}",
                }
            )
            asset_states[asset_name].append(("fault", reason))
            anomalies_out.append(
                {
                    "name": f"{asset_name}--{metric}--bound-breach",
                    "asset": asset_name,
                    "metric": metric,
                    "severity": severity,
                    "reason": f"{reason}.",
                }
            )
        elif breach_run > 0:
            reason = (
                f"EWMA filtered {metric} {round(last_filtered)}{unit_str} crossed bound for "
                f"{breach_run} sample(s) (below sustained threshold {min_breach_samples})"
            )
            sensors_out.append(
                {
                    "sensor": sensor_name,
                    "asset": asset_name,
                    "metric": metric,
                    "status": sensor_status,
                    "reason": reason,
                }
            )
            asset_states[asset_name].append(("warning", reason))
        else:
            margin = 0.10 * span
            near_high = last_filtered >= high - margin and last_filtered > filtered[0]
            near_low = last_filtered <= low + margin and last_filtered < filtered[0]
            if raw_breaches > 0:
                total_spikes_filtered += raw_breaches
            if near_high or near_low:
                reason = (
                    f"EWMA filtered {metric} {round(last_filtered)}{unit_str} trending within "
                    f"10% of approved bound [{low}, {high}]{unit_str}"
                )
                sensors_out.append(
                    {
                        "sensor": sensor_name,
                        "asset": asset_name,
                        "metric": metric,
                        "status": sensor_status,
                        "reason": reason,
                    }
                )
                asset_states[asset_name].append(("warning", reason))
            else:
                spike_note = (
                    f" ({raw_breaches} transient spike(s) absorbed by EWMA alpha={alpha})"
                    if raw_breaches > 0
                    else ""
                )
                reason = (
                    f"EWMA filtered {metric} {round(last_filtered)}{unit_str} within "
                    f"[{low}, {high}]{unit_str}{spike_note}"
                )
                sensors_out.append(
                    {
                        "sensor": sensor_name,
                        "asset": asset_name,
                        "metric": metric,
                        "status": sensor_status,
                        "reason": reason,
                    }
                )
                asset_states[asset_name].append(("normal", reason))

    assets_out: list[dict[str, Any]] = []
    for asset_name in sorted(asset_states):
        entries = asset_states[asset_name]
        if asset_all_offline[asset_name]:
            state = "offline"
            reason = "; ".join(r for _, r in entries)
        else:
            # Among non-offline sensors, highest severity (fault > warning > normal) wins.
            live_entries = [(s, r) for s, r in entries if s != "offline"]
            has_offline_sensor = len(live_entries) < len(entries)
            worst_state, worst_reason = max(live_entries, key=lambda item: _STATE_RANK[item[0]])
            if has_offline_sensor and worst_state == "normal":
                state = "warning"
                offline_reasons = [r for s, r in entries if s == "offline"]
                reason = "; ".join(offline_reasons)
            else:
                state = worst_state
                reason = worst_reason
        assets_out.append(
            {
                "asset": asset_name,
                "operating_state": state,
                "reason": reason,
            }
        )

    sensors_out.sort(key=lambda item: item["sensor"])
    anomalies_out.sort(key=lambda item: item["name"])

    return {
        "hub": hub,
        "captured_at": captured_at,
        "alpha": alpha,
        "min_breach_samples": min_breach_samples,
        "flatline_samples": flatline_samples,
        "sensors_count": len(sensors_out),
        "assets_count": len(assets_out),
        "anomalies_count": len(anomalies_out),
        "spikes_filtered": total_spikes_filtered,
        "sensors": sensors_out,
        "assets": assets_out,
        "anomalies": anomalies_out,
    }


@derive(
    OPERATION,
    serves="fleet.telemetry.analyze",
    input_contract="fleet.telemetry.analyze.request@1",
    output_contract="fleet.telemetry.analyze.result@1",
    refusals={
        PROVIDER_DECLINED: {
            "contract": f"{OPERATION}.refusal.{PROVIDER_DECLINED}@1",
            "absorbable": False,
        }
    },
)
def telemetry_analyze(
    batches: list[CaptureView],
    baselines: list[dict[str, Any]],
    logical_source: str,
    alpha: str = "0.3",
    min_breach_samples: int = 3,
    flatline_samples: int = 5,
    max_heartbeat_age_s: int = 1800,
) -> ProviderResult:
    """Applies an EWMA gain filter, flatline check, and approved-baseline classifier to one hub
    telemetry batch Capture and returns one derived analysis document."""

    if not isinstance(logical_source, str) or not logical_source:
        raise decline(PROVIDER_DECLINED, "telemetry.analyze needs logical_source")
    if len(batches) != 1:
        raise decline(PROVIDER_DECLINED, f"telemetry.analyze expects 1 batch Capture, got {len(batches)}")
    batch = batches[0]
    try:
        document = analyze_batch(
            batch.raw_bytes,
            baselines,
            alpha=alpha,
            min_breach_samples=min_breach_samples,
            flatline_samples=flatline_samples,
            max_heartbeat_age_s=max_heartbeat_age_s,
        )
    except TelemetryRefused as error:
        raise decline(PROVIDER_DECLINED, str(error)) from None
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return ProviderResult.ok(
        {
            "document": batch.derive(
                content,
                source_identity=logical_source,
                coordinate_type=COORDINATE_TYPE,
                coordinate={
                    "hub": document["hub"],
                    "captured_at": document["captured_at"],
                    "sensors": document["sensors_count"],
                },
                selector_type=SELECTOR_TYPE,
            )
        },
        metrics={
            "sensors": float(document["sensors_count"]),
            "assets": float(document["assets_count"]),
            "anomalies": float(document["anomalies_count"]),
            "spikes_filtered": float(document["spikes_filtered"]),
        },
    )
