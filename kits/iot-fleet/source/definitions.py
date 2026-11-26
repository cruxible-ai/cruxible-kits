"""The iot-fleet kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/iot-fleet SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default.

The vocabulary keeps what telemetry and models report (``observation``) apart from
what a person or reviewing agent decides about it (``normative``). Raw time-series
stays in your historian; Cruxible holds sites, industrial or edge assets, sensors,
firmware releases, approved operating baselines, anomalies, and maintenance records.
Ranked levels (criticality, operating_state, condition, severity, firmware status)
are ordered enums so queries can compare rank directly.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "iot-fleet"
VERSION = "2.0.0"
OWNS = ("fleet.",)

SITE = "fleet.site"
ASSET = "fleet.asset"
SENSOR = "fleet.sensor"
FIRMWARE = "fleet.firmware"
BASELINE = "fleet.baseline"
ANOMALY = "fleet.anomaly"
MAINTENANCE = "fleet.maintenance"
SELF = "playbill.coordinator-self-source-v1"

OBSERVED = "observation"
DECIDED = "normative"

SOURCE_DIR = Path(__file__).resolve().parent


def _rule(role: str) -> dict[str, Any]:
    """Own words, or a passage of any catalogued workspace file."""

    return {
        "rule_id": "own-words-or-file",
        "claim_roles": [role],
        "capture_contracts": [SELF],
        "capture_contract_families": ["workspace_file"],
        "admission": "direct",
        "attestation_requirement": "none",
        "subject_binding": "exact_claim_subject",
    }


def _key(predicate: str, value: dict[str, Any], description: str) -> dict[str, Any]:
    """A key part: the slug, value or Subject that names the Subject."""

    return {
        "predicate": predicate,
        "cardinality": "one",
        "value": value,
        "default_role": DECIDED,
        "permitted_roles": [DECIDED],
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": []},
        "description": description,
    }


def _field(
    predicate: str,
    value: dict[str, Any],
    description: str,
    *,
    role: str = OBSERVED,
    cardinality: str = "one",
    **more: Any,
) -> dict[str, Any]:
    return {
        "predicate": predicate,
        "cardinality": cardinality,
        "value": value,
        "default_role": role,
        "permitted_roles": [role],
        "evidence_requirement": "self",
        "evidence_admission_policy": {"rules": [_rule(role)]},
        "description": description,
        **more,
    }


def _text(maximum: int = 256) -> dict[str, Any]:
    return {"kind": "string", "min_len": 1, "max_len": maximum}


def _enum(*members: str) -> dict[str, Any]:
    return {"kind": "enum", "members": list(members)}


def _ranked(*members: str) -> dict[str, Any]:
    """An ordered enum: members lowest first, so queries can compare rank."""

    return {"kind": "enum", "members": list(members), "ordered": True}


def _subjects(*kinds: str) -> dict[str, Any]:
    return {"kind": "subject", "subject_kinds": list(kinds)}


def _meanings(**members: str) -> list[dict[str, str]]:
    return [{"member": member, "description": text} for member, text in members.items()]


CRITICALITY = _ranked("low", "medium", "high", "critical")
METRICS = _enum(
    "vibration", "temperature", "pressure", "flow", "humidity", "current", "voltage", "power"
)


def claim_type_records() -> list[dict[str, Any]]:
    return [
        # Sites.
        _key(f"{SITE}.name", _text(), "The site's slug (plant-a, coldroom-north); its key."),
        _field(f"{SITE}.title", _text(120), "The site's display name.", role=DECIDED),
        _field(
            f"{SITE}.region", _text(120), "The region or campus the site belongs to.", role=DECIDED
        ),
        # Firmware releases.
        _key(
            f"{FIRMWARE}.name",
            _text(),
            "The firmware release's slug (acme-ctrl-3.4.2); its key.",
        ),
        _field(f"{FIRMWARE}.vendor", _text(120), "The vendor or team that built the release."),
        _field(f"{FIRMWARE}.version", _text(64), "The semantic or build version string."),
        _field(
            f"{FIRMWARE}.applies_to",
            _text(120),
            "The hardware family or model this firmware targets.",
        ),
        _field(
            f"{FIRMWARE}.status",
            _ranked("testing", "approved", "deprecated", "recalled"),
            "Trust status of the firmware release, ordered from pre-release to recalled.",
            role=DECIDED,
            member_descriptions=_meanings(
                testing="Under qualification; not cleared for production assets.",
                approved="Cleared for fleet deployment.",
                deprecated="Superseded; schedule upgrade.",
                recalled="Known safety, reliability, or security defect; replace promptly.",
            ),
        ),
        # Industrial or edge assets (pumps, chillers, motors, gateways, inverters, ...).
        _key(f"{ASSET}.name", _text(), "The asset's tag or slug (line-2-pump-b); its key."),
        _field(f"{ASSET}.site", _subjects(SITE), "The site the asset runs at.", role=DECIDED),
        _field(
            f"{ASSET}.asset_type",
            _text(64),
            "The kind of equipment (pump, chiller, compressor, gateway, motor, inverter).",
            role=DECIDED,
        ),
        _field(f"{ASSET}.model", _text(120), "The manufacturer and model, as on the nameplate."),
        _field(
            f"{ASSET}.firmware",
            _subjects(FIRMWARE),
            "The firmware release currently reported on the asset's controller.",
        ),
        _field(
            f"{ASSET}.criticality",
            CRITICALITY,
            "How much an outage of this asset costs the operation, lowest first.",
            role=DECIDED,
            member_descriptions=_meanings(
                low="Redundant or idle; an outage is a nuisance.",
                medium="An outage slows one line or zone.",
                high="An outage stops one line or zone.",
                critical="An outage stops the site or risks safety.",
            ),
        ),
        _field(
            f"{ASSET}.operating_state",
            _ranked("normal", "warning", "fault", "offline"),
            "Latest observed operating state from telemetry, PLC status, or a diagnostic model, "
            "lowest first; cite the telemetry export or model run.",
            member_descriptions=_meanings(
                normal="All watched metrics within normal range.",
                warning="One or more metrics trending toward or past a warning bound.",
                fault="Active fault or alarm reported by the controller or model.",
                offline="Asset powered down or unreachable.",
            ),
        ),
        _field(
            f"{ASSET}.condition",
            _ranked("healthy", "watch", "degraded", "failed"),
            "The reviewed condition of the asset, lowest first: a judgment pinned (based_on) "
            "to the operating_state and approved baselines it was judged from.",
            role=DECIDED,
            member_descriptions=_meanings(
                healthy="Operating within its approved baselines.",
                watch="Drifting; keep on the attention list.",
                degraded="Running outside an approved bound; maintenance planned.",
                failed="Out of service.",
            ),
        ),
        _field(f"{ASSET}.last_inspected", {"kind": "date"}, "Date of the last physical inspection."),
        # Sensors.
        _key(f"{SENSOR}.name", _text(), "The sensor's device id (coldroom-04-temp); its key."),
        _field(f"{SENSOR}.site", _subjects(SITE), "The site the sensor reports from.", role=DECIDED),
        _field(f"{SENSOR}.measures", METRICS, "What the sensor measures.", role=DECIDED),
        _field(
            f"{SENSOR}.mounted_on",
            _subjects(ASSET),
            "The asset the sensor is mounted on, when it watches one.",
            role=DECIDED,
        ),
        _field(
            f"{SENSOR}.firmware",
            _subjects(FIRMWARE),
            "The firmware release currently reported by the sensor.",
        ),
        _field(
            f"{SENSOR}.status",
            _enum("online", "degraded", "offline"),
            "The device's last reported health. Its evidence goes stale 30 minutes after "
            "the last heartbeat, so a silent sensor reads as unknown, never as healthy.",
            evidence_freshness={"stale_after": "PT30M"},
            member_descriptions=_meanings(
                online="Reporting on schedule.",
                degraded="Reporting, with dropped or out-of-range samples.",
                offline="Reported itself offline.",
            ),
        ),
        # Reviewed operating baselines: one per (asset, metric).
        _key(f"{BASELINE}.asset", _subjects(ASSET), "The asset the baseline bounds; a key part."),
        _key(f"{BASELINE}.metric", METRICS, "The metric the baseline bounds; a key part."),
        _field(
            f"{BASELINE}.low",
            {"kind": "int"},
            "The lowest reading still in bounds, as a whole number in the baseline's unit.",
            role=DECIDED,
        ),
        _field(
            f"{BASELINE}.high",
            {"kind": "int"},
            "The highest reading still in bounds, as a whole number in the baseline's unit.",
            role=DECIDED,
        ),
        _field(
            f"{BASELINE}.unit",
            _text(32),
            "The unit low and high count in, small enough to keep them whole (um/s, "
            "centi-degC, mbar, mA).",
            role=DECIDED,
        ),
        _field(
            f"{BASELINE}.status",
            _enum("proposed", "approved", "retired"),
            "Where the baseline stands. An approved baseline cites its source "
            "(commissioning report, vendor manual) and is reused by every later check.",
            role=DECIDED,
        ),
        # Anomalies flagged on an asset or sensor, and what was decided about them.
        _key(f"{ANOMALY}.name", _text(), "The anomaly's slug; its key."),
        _field(
            f"{ANOMALY}.asset",
            _subjects(ASSET, SENSOR),
            "The asset or sensor the anomaly was flagged on.",
        ),
        _field(f"{ANOMALY}.metric", METRICS, "The metric that broke its bound."),
        _field(
            f"{ANOMALY}.severity",
            _ranked("info", "low", "medium", "high", "critical"),
            "How serious the anomaly is, lowest first.",
        ),
        _field(
            f"{ANOMALY}.disposition",
            _enum("open", "confirmed", "dismissed", "resolved"),
            "What was decided. A dismissal is a reviewed false positive: pin it (based_on) "
            "to the baseline it was judged against, so a changed baseline reopens it.",
            role=DECIDED,
            member_descriptions=_meanings(
                open="Not yet reviewed.",
                confirmed="A real fault; maintenance follows.",
                dismissed="A reviewed false positive; state the justification.",
                resolved="Fixed and verified.",
            ),
        ),
        _field(
            f"{ANOMALY}.justification",
            _enum(
                "sensor_drift",
                "maintenance_window",
                "transient_spike",
                "baseline_outdated",
                "confirmed_fault",
            ),
            "Structured reason backing the anomaly's disposition.",
            role=DECIDED,
            member_descriptions=_meanings(
                sensor_drift="Alert caused by an uncalibrated or drifting sensor.",
                maintenance_window="Expected reading during scheduled work.",
                transient_spike="Brief spike that cleared without sustained fault.",
                baseline_outdated="Equipment operating profile changed; baseline update needed.",
                confirmed_fault="Verified physical or firmware fault requiring maintenance.",
            ),
        ),
        # Maintenance actions linked to assets and resolved anomalies.
        _key(f"{MAINTENANCE}.name", _text(), "The maintenance work order slug; its key."),
        _field(
            f"{MAINTENANCE}.asset",
            _subjects(ASSET, SENSOR),
            "The asset or sensor the work is performed on.",
            role=DECIDED,
        ),
        _field(
            f"{MAINTENANCE}.kind",
            _enum("inspection", "calibration", "repair", "replacement", "firmware_update"),
            "What kind of maintenance action it is.",
            role=DECIDED,
        ),
        _field(
            f"{MAINTENANCE}.status",
            _enum("planned", "in_progress", "completed", "cancelled"),
            "Where the maintenance action stands.",
            role=DECIDED,
        ),
        _field(
            f"{MAINTENANCE}.performed_on",
            {"kind": "date"},
            "Date the maintenance was performed or completed.",
        ),
        _field(
            f"{MAINTENANCE}.resolves",
            _subjects(ANOMALY),
            "An anomaly resolved by this maintenance action.",
            role=DECIDED,
            cardinality="many",
        ),
    ]


SUBJECT_KINDS = (
    (SITE, "A site or facility the fleet runs at, named by its slug.", [f"{SITE}.name"]),
    (
        FIRMWARE,
        "A firmware release tracked across assets and sensors, named by its slug.",
        [f"{FIRMWARE}.name"],
    ),
    (
        ASSET,
        "An industrial or edge asset (pump, chiller, motor, gateway), named by its asset tag.",
        [f"{ASSET}.name"],
    ),
    (SENSOR, "A telemetry sensor or edge device, named by its device id.", [f"{SENSOR}.name"]),
    (
        BASELINE,
        "A reviewed operating bound for one metric of one asset, keyed by the asset and metric.",
        [f"{BASELINE}.asset", f"{BASELINE}.metric"],
    ),
    (ANOMALY, "An anomaly flagged on an asset or sensor, named by its slug.", [f"{ANOMALY}.name"]),
    (
        MAINTENANCE,
        "A planned or completed maintenance intervention on an asset or sensor, named by its slug.",
        [f"{MAINTENANCE}.name"],
    ),
)

ASSETS_NEEDING_ATTENTION = {
    "query": "fleet.assets_needing_attention",
    "description": "Assets whose operating_state is warning or worse, or whose reviewed condition "
    "is degraded or worse.",
    "from": {"asset": ASSET},
    "where": 'asset.operating_state >= "warning" or asset.condition >= "degraded"',
    "fields": [
        "asset.site",
        "asset.asset_type",
        "asset.operating_state",
        "asset.condition",
        "asset.criticality",
    ],
    "limit": 200,
    "max": {"results": 2000},
}

ASSETS_BY_SITE = {
    "query": "fleet.assets_by_site",
    "description": "The assets at one site, with their type, condition, criticality and firmware.",
    "params": {"site": "string"},
    "from": {"asset": ASSET},
    "hops": [{"site": f"asset.{ASSET}.site!: {SITE}"}],
    "where": "site.name == $site",
    "fields": [
        "asset.asset_type",
        "asset.model",
        "asset.condition",
        "asset.criticality",
        "asset.firmware",
    ],
    "limit": 200,
    "max": {"results": 2000},
}

OPEN_ANOMALIES = {
    "query": "fleet.open_anomalies",
    "description": "Anomalies not yet reviewed, medium severity or worse.",
    "from": {"anomaly": ANOMALY},
    "where": 'anomaly.disposition == "open" and anomaly.severity >= "medium"',
    "fields": ["anomaly.asset", "anomaly.metric", "anomaly.severity"],
    "limit": 200,
    "max": {"results": 2000},
}

ASSETS_ON_RECALLED_FIRMWARE = {
    "query": "fleet.assets_on_recalled_firmware",
    "description": "Assets running deprecated or recalled firmware.",
    "from": {"asset": ASSET},
    "hops": [{"fw": f'asset.{ASSET}.firmware!: {FIRMWARE} where fw.status >= "deprecated"'}],
    "fields": [
        "asset.site",
        "asset.asset_type",
        "asset.criticality",
        "fw",
        {"firmware_status": "fw.status"},
    ],
    "limit": 200,
    "max": {"results": 2000},
}

QUERIES = (
    ASSETS_NEEDING_ATTENTION,
    ASSETS_BY_SITE,
    OPEN_ANOMALIES,
    ASSETS_ON_RECALLED_FIRMWARE,
)


def guidance_documents(store_body: Callable[[Path], str]) -> list[dict[str, Any]]:
    path = SOURCE_DIR / "guidance" / "review-guidance.md"
    title = path.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
    guided = (
        f"ClaimType:{ASSET}.condition",
        f"ClaimType:{BASELINE}.status",
        f"ClaimType:{ANOMALY}.disposition",
        f"ClaimType:{FIRMWARE}.status",
    )
    return [
        {
            "kind": "document",
            "identity": "document:fleet.guidance.review-guidance",
            "document_kind": "fleet.guidance",
            "title": title,
            "media_type": "text/markdown",
            "body_digest": store_body(path),
            "links": [
                {"relation": "guides", "target_identity": target}
                for target in sorted(guided, key=lambda item: item.encode("utf-8"))
            ],
            "governance_scope": ["fleet"],
            "lifecycle": {"revision": 1},
        }
    ]


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"iot-fleet {VERSION}: sites, assets, sensors, firmware, baselines, "
        "anomalies and maintenance.",
        "members": [
            *(
                {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
                for t in claim_types
            ),
            *(
                {"kind": "subject_kind", "name": name, "description": description, "keys": keys}
                for name, description, keys in SUBJECT_KINDS
            ),
            *({"kind": "query_definition", "query_definition": q} for q in QUERIES),
        ],
    }
