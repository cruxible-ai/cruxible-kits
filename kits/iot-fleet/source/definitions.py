"""The iot-fleet kit's definitions, as authored inputs.

Rebuild the kit from here with ``python scripts/build_kit.py kits/iot-fleet SCRATCH``
(see that script). Each ClaimType is a ``ClaimTypeInputRecord`` lowered with the
client's ``lower_claim_type_input``; what a record leaves out takes the current
default.

The vocabulary keeps what telemetry and models report (``observation``) apart from
what a person or reviewing agent decides about it (``normative``). An observation
admits own words or a passage of any catalogued workspace file (a telemetry export,
a model report). A decision, such as an approved operating baseline or a dismissed
anomaly, is meant to cite its source (a commissioning report, a vendor manual, an
inspection note); the rules admit a workspace file passage on every decision so a
reviewer can ask for one. Ranked levels (wear, condition, criticality, severity) are
ordered enums, so a query can ask for ``>= high``.
"""

from __future__ import annotations

from typing import Any

from cruxible_client.contracts.claim_type_inputs import (
    ClaimTypeInputRecord,
    lower_claim_type_input,
)

KIT_ID = "iot-fleet"
VERSION = "1.0.0"
OWNS = ("fleet.",)

SITE = "fleet.site"
PUMP = "fleet.pump"
SENSOR = "fleet.sensor"
BASELINE = "fleet.baseline"
ANOMALY = "fleet.anomaly"
SELF = "playbill.coordinator-self-source-v1"

OBSERVED = "observation"
DECIDED = "normative"


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
METRICS = _enum("vibration", "temperature", "pressure", "flow", "humidity", "current")


def claim_type_records() -> list[dict[str, Any]]:
    return [
        # Sites.
        _key(f"{SITE}.name", _text(), "The site's slug (plant-a, coldroom-north); its key."),
        _field(f"{SITE}.title", _text(120), "The site's display name.", role=DECIDED),
        _field(f"{SITE}.region", _text(120), "The region or campus the site belongs to.", role=DECIDED),
        # Pumps.
        _key(f"{PUMP}.name", _text(), "The pump's asset tag (line-2-pump-b); its key."),
        _field(f"{PUMP}.site", _subjects(SITE), "The site the pump runs at.", role=DECIDED),
        _field(f"{PUMP}.model", _text(120), "The manufacturer and model, as on the nameplate."),
        _field(f"{PUMP}.firmware", _text(64), "The controller firmware version it reports."),
        _field(
            f"{PUMP}.criticality",
            CRITICALITY,
            "How much an outage of this pump costs the operation, lowest first.",
            role=DECIDED,
            member_descriptions=_meanings(
                low="Redundant or idle; an outage is a nuisance.",
                medium="An outage slows one line.",
                high="An outage stops one line.",
                critical="An outage stops the site or risks safety.",
            ),
        ),
        _field(
            f"{PUMP}.bearing_wear",
            _ranked("none", "low", "moderate", "high", "severe"),
            "Bearing wear as a vibration model or inspection reports it, lowest first; "
            "cite the model run or inspection report.",
            member_descriptions=_meanings(
                none="No measurable wear.",
                low="Within the reviewed baseline.",
                moderate="Trending toward the reviewed bound.",
                high="Past the reviewed bound; plan maintenance.",
                severe="Imminent failure; stop and inspect.",
            ),
        ),
        _field(
            f"{PUMP}.condition",
            _ranked("healthy", "watch", "degraded", "failed"),
            "The reviewed condition of the pump, lowest first: a judgment, usually pinned "
            "(based_on) to the bearing_wear and baseline it was judged from.",
            role=DECIDED,
            member_descriptions=_meanings(
                healthy="Operating within its approved baselines.",
                watch="Drifting; keep it on the attention list.",
                degraded="Running outside an approved bound; maintenance planned.",
                failed="Out of service.",
            ),
        ),
        _field(f"{PUMP}.last_inspected", {"kind": "date"}, "The date of the last physical inspection."),
        # Sensors.
        _key(f"{SENSOR}.name", _text(), "The sensor's device id (coldroom-04-temp); its key."),
        _field(f"{SENSOR}.site", _subjects(SITE), "The site the sensor reports from.", role=DECIDED),
        _field(f"{SENSOR}.measures", METRICS, "What the sensor measures.", role=DECIDED),
        _field(
            f"{SENSOR}.mounted_on",
            _subjects(PUMP),
            "The pump the sensor is mounted on, when it watches one.",
            role=DECIDED,
        ),
        _field(f"{SENSOR}.firmware", _text(64), "The firmware version the device reports."),
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
        # Reviewed operating baselines: one per (pump, metric).
        _key(f"{BASELINE}.pump", _subjects(PUMP), "The pump the baseline bounds; a key part."),
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
            "centi-degC, mbar).",
            role=DECIDED,
        ),
        _field(
            f"{BASELINE}.status",
            _enum("proposed", "approved", "retired"),
            "Where the baseline stands. An approved baseline should cite its source "
            "(commissioning report, vendor manual) and is reused by every later check.",
            role=DECIDED,
        ),
        # Anomalies flagged on an asset, and what was decided about them.
        _key(f"{ANOMALY}.name", _text(), "The anomaly's slug; its key."),
        _field(
            f"{ANOMALY}.asset",
            _subjects(PUMP, SENSOR),
            "The pump or sensor the anomaly was flagged on.",
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
                dismissed="A reviewed false positive.",
                resolved="Fixed and verified.",
            ),
        ),
    ]


SUBJECT_KINDS = (
    (SITE, "A site or facility the fleet runs at, named by its slug.", [f"{SITE}.name"]),
    (PUMP, "A pump in the fleet, named by its asset tag.", [f"{PUMP}.name"]),
    (SENSOR, "A telemetry sensor or edge device, named by its device id.", [f"{SENSOR}.name"]),
    (
        BASELINE,
        "A reviewed operating bound for one metric of one pump, keyed by the pump and "
        "metric.",
        [f"{BASELINE}.pump", f"{BASELINE}.metric"],
    ),
    (ANOMALY, "An anomaly flagged on a pump or sensor, named by its slug.", [f"{ANOMALY}.name"]),
)

PUMPS_NEEDING_ATTENTION = {
    "query": "fleet.pumps_needing_attention",
    "description": "Pumps whose bearing wear is high or worse, or whose reviewed condition "
    "is degraded or worse.",
    "from": {"pump": PUMP},
    "where": 'pump.bearing_wear >= "high" or pump.condition >= "degraded"',
    "fields": ["pump.site", "pump.bearing_wear", "pump.condition", "pump.criticality"],
    "limit": 200,
    "max": {"results": 2000},
}

PUMPS_BY_SITE = {
    "query": "fleet.pumps_by_site",
    "description": "The pumps at one site, with their condition and criticality.",
    "params": {"site": "string"},
    "from": {"pump": PUMP},
    "hops": [{"site": f"pump.{PUMP}.site!: {SITE}"}],
    "where": "site.name == $site",
    "fields": ["pump.model", "pump.condition", "pump.criticality", "pump.firmware"],
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

QUERIES = (PUMPS_NEEDING_ATTENTION, PUMPS_BY_SITE, OPEN_ANOMALIES)


def change_set() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    return {
        "kind": "change_set",
        "rationale": f"iot-fleet {VERSION}: sites, pumps, sensors, baselines and anomalies.",
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
