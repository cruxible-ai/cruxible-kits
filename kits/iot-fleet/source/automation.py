"""Capabilities, CaptureKinds, Procedures, provider registration, and adoption recipes
for iot-fleet 2.1.0.

Architecture:
1. ``fleet.telemetry-ingest``: reads approved ``fleet.baseline`` rows -> reads one hub
   telemetry JSON batch via ``cruxible-builtin#workspace.file`` -> runs pure ``@derive``
   ``iot-telemetry-provider#telemetry.analyze`` (EWMA gain filter + flatline check +
   approved-baseline classifier) -> emits one derived ``fleet.telemetry-analysis`` Capture ->
   settles ``fleet.asset.operating_state``.
2. ``fleet.sensor-health`` (triggered on ``capture_landing`` of ``fleet.telemetry-analysis``,
   substituting the Capture without re-running the derive): settles ``fleet.sensor.status``.
3. ``fleet.anomaly-ingest`` (triggered on ``capture_landing`` of ``fleet.telemetry-analysis``,
   substituting the Capture without re-running the derive): creates each flagged
   ``fleet.anomaly`` and settles ``asset``, ``metric``, and ``severity``.
4. ``fleet.attention`` (observe-only): queries unjudged anomalies at or above
   ``min_severity`` and posts them to the Line inbox for ``cruxible next``.
"""

from __future__ import annotations

import functools
import json
import shutil
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from cruxible_client.contracts.authoring.inputs import (
    CapabilityInput,
    ContractInput,
    ProcedureInput,
    lower_authoring_input,
)
from cruxible_client.contracts.refs import ref_from_graph_text

import definitions as defs

SOURCE = Path(__file__).resolve().parent
KIT = SOURCE.parent
PROVIDER_PACKAGE = "iot-telemetry-provider"
PROVIDER_ROOT = SOURCE / "providers" / PROVIDER_PACKAGE / "src" / "iot_telemetry_provider"
REPOSITORY = "https://github.com/cruxible-ai/cruxible-kits"

TELEMETRY_BATCH_KIND = "fleet.telemetry-batch"
TELEMETRY_ANALYSIS_KIND = defs.TELEMETRY_ANALYSIS_KIND

ANALYZE_CAPABILITY = "fleet.telemetry.analyze"
WORKSPACE_FILE_CAPABILITY = "workspace.file"

ASSET_ROW = "fleet.telemetry-asset-row"
SENSOR_ROW = "fleet.telemetry-sensor-row"
ANOMALY_ROW = "fleet.telemetry-anomaly-row"
ATTENTION_ITEM = "fleet.anomaly-attention"

INGEST_PROCEDURE = "fleet.telemetry-ingest"
SENSOR_PROCEDURE = "fleet.sensor-health"
ANOMALY_PROCEDURE = "fleet.anomaly-ingest"
ATTENTION_PROCEDURE = "fleet.attention"

WORKSPACE_FILE_BINDING = "cruxible-builtin#workspace.file"
ANALYZE_BINDING = f"{PROVIDER_PACKAGE}#telemetry.analyze"

_PATH = 'string{min_len: 1, max_len: 256, pattern: "^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}$"}'
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_ALPHA = 'string{pattern: "^(0\\\\.[0-9]{1,6}|1(\\\\.0{1,6})?)$"}'
_METRICS = (
    'enum["vibration", "temperature", "pressure", "flow", "humidity", "current", "voltage", "power"]'
)
_OPERATING_STATES = 'enum["normal", "warning", "fault", "offline"]'
_SENSOR_STATUSES = 'enum["online", "degraded", "offline"]'
_SEVERITIES = 'enum["info", "low", "medium", "high", "critical"]'


def refs(value: Any) -> Any:
    """Every ``$steps``/``$item``/``$params`` string as the typed reference it names."""

    if isinstance(value, str):
        found = ref_from_graph_text(value)
        return value if found is None else found.model_dump(mode="json", by_alias=True)
    if isinstance(value, Mapping):
        return {key: refs(member) for key, member in value.items()}
    if isinstance(value, list | tuple):
        return [refs(member) for member in value]
    return value


def _json_decoding(max_bytes: int, records: int, depth: int) -> dict[str, Any]:
    return {
        "format": "json",
        "encoding": "identity",
        "limits": {"decoded_bytes": max_bytes, "depth": depth, "records": records},
    }


#: Row Contracts authored alongside the vocabulary (queries and derived layouts name them).
ROW_CONTRACTS: tuple[dict[str, Any], ...] = (
    {
        "kind": "contract",
        "name": defs.APPROVED_BASELINE_ROW,
        "version": 1,
        "description": "One approved operating baseline row passed to telemetry.analyze.",
        "fields": {
            "asset": "string{min_len: 1, max_len: 256}",
            "metric": _METRICS,
            "low": "int",
            "high": "int",
            "unit": "string{min_len: 1, max_len: 32}?",
        },
    },
    {
        "kind": "contract",
        "name": defs.ANOMALY_TRIAGE_ROW,
        "version": 1,
        "description": "One unjudged anomaly row returned by fleet.anomalies_needing_triage.",
        "fields": {
            "anomaly": "string{min_len: 1, max_len: 256}",
            "asset": "string{min_len: 1, max_len: 256}",
            "metric": _METRICS,
            "severity": _SEVERITIES,
        },
    },
    {
        "kind": "contract",
        "name": ASSET_ROW,
        "version": 1,
        "description": "Derived operating state for one fleet.asset from a telemetry batch.",
        "fields": {
            "operating_state": _OPERATING_STATES,
            "reason": "string{min_len: 1, max_len: 512}",
        },
    },
    {
        "kind": "contract",
        "name": SENSOR_ROW,
        "version": 1,
        "description": "Derived health status for one fleet.sensor from a telemetry batch.",
        "fields": {
            "status": _SENSOR_STATUSES,
            "reason": "string{min_len: 1, max_len: 512}",
        },
    },
    {
        "kind": "contract",
        "name": ANOMALY_ROW,
        "version": 1,
        "description": "Derived anomaly flagged by telemetry.analyze (sustained bound breach, "
        "flatlined sensor, or missed heartbeat).",
        "fields": {
            "asset": "string{min_len: 1, max_len: 256}",
            "metric": _METRICS,
            "severity": _SEVERITIES,
            "reason": "string{min_len: 1, max_len: 512}",
        },
    },
    {
        "kind": "contract",
        "name": ATTENTION_ITEM,
        "version": 1,
        "description": "An unjudged fleet anomaly posted to the Line inbox for review.",
        "fields": {
            "anomaly": "string{min_len: 1, max_len: 256}",
            "asset": "string{min_len: 1, max_len: 256}",
            "metric": _METRICS,
            "severity": _SEVERITIES,
        },
    },
)

#: Capability request/result Contracts and Procedure parameter Contracts.
CAPABILITY_CONTRACTS: tuple[dict[str, Any], ...] = (
    {
        "kind": "contract",
        "name": ANALYZE_CAPABILITY + ".request",
        "version": 1,
        "description": "One hub telemetry JSON batch Capture, approved fleet.baseline rows, and "
        "EWMA gain filter / flatline parameters.",
        "fields": {
            "batches": f"list<capture<{TELEMETRY_BATCH_KIND}>>{{max_items: 16}}",
            "baselines": f"list<{defs.APPROVED_BASELINE_ROW}@1>{{max_items: 20000}}",
            "logical_source": _SOURCE,
            "alpha": _ALPHA,
            "min_breach_samples": "int{min: 1, max: 1000}",
            "flatline_samples": "int{min: 2, max: 1000}",
            "max_heartbeat_age_s": "int{min: 60, max: 86400}",
        },
    },
    {
        "kind": "contract",
        "name": ANALYZE_CAPABILITY + ".result",
        "version": 1,
        "description": "One derived JSON analysis document in the layout of CaptureKind "
        f"{TELEMETRY_ANALYSIS_KIND}.",
        "fields": {"document": f"capture<{TELEMETRY_ANALYSIS_KIND}>"},
    },
    {
        "kind": "contract",
        "name": INGEST_PROCEDURE + ".params",
        "version": 1,
        "description": "Parameters for one hub's fleet.telemetry-ingest Line.",
        "fields": {
            "relative_path": _PATH,
            "logical_source": _SOURCE,
            "alpha": _ALPHA,
            "min_breach_samples": "int{min: 1, max: 1000}",
            "flatline_samples": "int{min: 2, max: 1000}",
            "max_heartbeat_age_s": "int{min: 60, max: 86400}",
        },
    },
    {
        "kind": "contract",
        "name": SENSOR_PROCEDURE + ".params",
        "version": 1,
        "description": "Parameters for one hub's fleet.sensor-health landing Line.",
        "fields": {"logical_source": _SOURCE},
    },
    {
        "kind": "contract",
        "name": ANOMALY_PROCEDURE + ".params",
        "version": 1,
        "description": "Parameters for one hub's fleet.anomaly-ingest landing Line.",
        "fields": {"logical_source": _SOURCE},
    },
    {
        "kind": "contract",
        "name": ATTENTION_PROCEDURE + ".params",
        "version": 1,
        "description": "Parameters for the observe-only fleet.attention Line.",
        "fields": {"min_severity": _SEVERITIES},
    },
)

CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "kind": "capability",
        "name": ANALYZE_CAPABILITY,
        "version": 1,
        "description": "Applies an EWMA gain filter, flatline/heartbeat check, and approved "
        "baseline comparison to one hub telemetry batch Capture and returns one derived "
        "analysis document with per-sensor health, per-asset operating state, and anomalies.",
        "effect": "pure",
        "in": ANALYZE_CAPABILITY + ".request@1",
        "out": ANALYZE_CAPABILITY + ".result@1",
    },
)


@functools.cache
def contract_tree() -> Mapping[str, bytes]:
    from cruxible_core.authoring.capability_lowering import render_capability_member
    from cruxible_core.authoring.contract_lowering import render_contract_member

    tree: dict[str, bytes] = {}
    for member in (*ROW_CONTRACTS, *CAPABILITY_CONTRACTS):
        payload: Any = lower_authoring_input(ContractInput.model_validate(member))
        path, content, _digest = render_contract_member(payload, tree=tree)
        tree[path] = content
    for member in CAPABILITIES:
        payload = lower_authoring_input(CapabilityInput.model_validate(member))
        path, content, _digest = render_capability_member(payload, tree=tree)
        tree[path] = content
    return tree


def contract_pin(spelling: str) -> dict[str, Any]:
    from cruxible_client.contracts.shapes import contract_digest, contract_path, parse_contract

    name, _, version = spelling.partition("@")
    path = contract_path(name, int(version))
    contract = parse_contract(contract_tree()[path], path=path)
    return {"name": name, "version": int(version), "digest": contract_digest(contract).tagged}


def pinned_layout(layout: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **layout,
        "records": {
            name: {**item, "row": contract_pin(item["row"])}
            for name, item in layout["records"].items()
        },
    }


ANALYSIS_LAYOUT: dict[str, Any] = {
    "header": {},
    "records": {
        "assets": {
            "at": "/assets/*",
            "key": {"name": {"at": "asset", "type": f"key_part<{defs.ASSET}:name>"}},
            "row": f"{ASSET_ROW}@1",
            "fields": {
                "operating_state": {"at": "operating_state"},
                "reason": {"at": "reason"},
            },
            "count_at": "/assets_count",
        },
        "sensors": {
            "at": "/sensors/*",
            "key": {"name": {"at": "sensor", "type": f"key_part<{defs.SENSOR}:name>"}},
            "row": f"{SENSOR_ROW}@1",
            "fields": {
                "status": {"at": "status"},
                "reason": {"at": "reason"},
            },
            "count_at": "/sensors_count",
        },
        "anomalies": {
            "at": "/anomalies/*",
            "key": {"name": {"at": "name", "type": f"key_part<{defs.ANOMALY}:name>"}},
            "row": f"{ANOMALY_ROW}@1",
            "fields": {
                "asset": {"at": "asset"},
                "metric": {"at": "metric"},
                "severity": {"at": "severity"},
                "reason": {"at": "reason"},
            },
            "count_at": "/anomalies_count",
        },
    },
}


def capture_kinds() -> dict[str, dict[str, Any]]:
    return {
        TELEMETRY_BATCH_KIND: {
            "name": TELEMETRY_BATCH_KIND,
            "shape": "http_response",
            "grade": "observed",
            "retention": "P90D",
            "erasable": False,
            "max_bytes": 8 * 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": _json_decoding(8 * 1024 * 1024, 50_000, 16),
        },
        TELEMETRY_ANALYSIS_KIND: {
            "name": TELEMETRY_ANALYSIS_KIND,
            "shape": "http_response",
            "grade": "derived",
            "replay": "attested",
            "retention": "P180D",
            "erasable": False,
            "max_bytes": 8 * 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": _json_decoding(8 * 1024 * 1024, 50_000, 16),
            "layout": pinned_layout(ANALYSIS_LAYOUT),
        },
    }


def staged_capture_kinds() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """First stage omits layouts (which pin row Contracts); second stage adds layouts."""

    full = capture_kinds()
    base = {
        name: {k: v for k, v in record.items() if k != "layout"} for name, record in full.items()
    }
    layouts = {name: record for name, record in full.items() if "layout" in record}
    return base, layouts


def capabilities_change_set() -> dict[str, Any]:
    return {
        "kind": "change_set",
        "rationale": "iot-fleet 2.1.0 telemetry capability, request/result Contracts, and "
        "Procedure parameter Contracts.",
        "members": [*CAPABILITY_CONTRACTS, *CAPABILITIES],
    }


_CAPS = {
    "wall_clock": "PT2M",
    "provider_calls": 2,
    "capture_bytes": 16 * 1024 * 1024,
    "items": 50_000,
    "read_rows": 20_000,
    "repeat_attempts": 1,
}


def procedures_change_set() -> dict[str, Any]:
    ingest = refs(
        {
            "procedure": INGEST_PROCEDURE,
            "description": "Read one hub telemetry batch from the workspace, filter and classify "
            "each sensor against approved fleet.baseline bounds via EWMA gain filtering, emit "
            "one derived fleet.telemetry-analysis Capture, and settle fleet.asset.operating_state.",
            "input": {},
            "output": {},
            "parameter_contract": f"{INGEST_PROCEDURE}.params@1",
            "slots": {
                "read": {"capability": f"{WORKSPACE_FILE_CAPABILITY}@1"},
                "derive": {"capability": f"{ANALYZE_CAPABILITY}@1"},
            },
            "hard_caps": _CAPS,
            "steps": [
                {"read": "baselines", "query": defs.APPROVED_BASELINES_QUERY},
                {
                    "call": "batch",
                    "slot": "read",
                    "captures": {"capture": TELEMETRY_BATCH_KIND},
                    "input": {
                        "logical_source": "$params.logical_source",
                        "relative_path": "$params.relative_path",
                    },
                },
                {
                    "call": "analysis",
                    "slot": "derive",
                    "captures": {"document": TELEMETRY_ANALYSIS_KIND},
                    "input": {
                        "batches": ["$steps.batch.capture"],
                        "baselines": "$steps.baselines.rows",
                        "logical_source": "$params.logical_source",
                        "alpha": "$params.alpha",
                        "min_breach_samples": "$params.min_breach_samples",
                        "flatline_samples": "$params.flatline_samples",
                        "max_heartbeat_age_s": "$params.max_heartbeat_age_s",
                    },
                },
                {
                    "extract": "assets",
                    "capture": "$steps.analysis.document",
                    "records": "assets",
                },
                {
                    "id": "write",
                    "for_each": "$steps.assets.records",
                    "subject": {
                        "kind": defs.ASSET,
                        "key": {"name": "$item.key.name"},
                    },
                    "claims": [
                        {
                            "type": f"{defs.ASSET}.operating_state",
                            "value": "$item.fields.operating_state",
                            "rationale": "{$item.fields.reason}",
                        }
                    ],
                },
            ],
        }
    )

    sensor_health = refs(
        {
            "procedure": SENSOR_PROCEDURE,
            "description": "Settle fleet.sensor.status from one landed fleet.telemetry-analysis "
            "Capture (substituted by its landing Trigger without re-running the derive).",
            "input": {},
            "output": {},
            "parameter_contract": f"{SENSOR_PROCEDURE}.params@1",
            "slots": {"derive": {"capability": f"{ANALYZE_CAPABILITY}@1"}},
            "hard_caps": {**_CAPS, "provider_calls": 1},
            "steps": [
                {
                    "call": "analysis",
                    "slot": "derive",
                    "captures": {"document": TELEMETRY_ANALYSIS_KIND},
                    "input": {
                        "batches": [],
                        "baselines": [],
                        "logical_source": "$params.logical_source",
                        "alpha": "0.3",
                        "min_breach_samples": 3,
                        "flatline_samples": 5,
                        "max_heartbeat_age_s": 1800,
                    },
                },
                {
                    "extract": "sensors",
                    "capture": "$steps.analysis.document",
                    "records": "sensors",
                },
                {
                    "id": "write",
                    "for_each": "$steps.sensors.records",
                    "subject": {
                        "kind": defs.SENSOR,
                        "key": {"name": "$item.key.name"},
                    },
                    "claims": [
                        {
                            "type": f"{defs.SENSOR}.status",
                            "value": "$item.fields.status",
                            "rationale": "{$item.fields.reason}",
                        }
                    ],
                },
            ],
        }
    )

    anomaly_ingest = refs(
        {
            "procedure": ANOMALY_PROCEDURE,
            "description": "Create and populate flagged fleet.anomaly observations (asset, metric, "
            "severity) from one landed fleet.telemetry-analysis Capture without touching normative "
            "dispositions.",
            "input": {},
            "output": {},
            "parameter_contract": f"{ANOMALY_PROCEDURE}.params@1",
            "slots": {"derive": {"capability": f"{ANALYZE_CAPABILITY}@1"}},
            "hard_caps": {**_CAPS, "provider_calls": 1},
            "steps": [
                {
                    "call": "analysis",
                    "slot": "derive",
                    "captures": {"document": TELEMETRY_ANALYSIS_KIND},
                    "input": {
                        "batches": [],
                        "baselines": [],
                        "logical_source": "$params.logical_source",
                        "alpha": "0.3",
                        "min_breach_samples": 3,
                        "flatline_samples": 5,
                        "max_heartbeat_age_s": 1800,
                    },
                },
                {
                    "extract": "anomalies",
                    "capture": "$steps.analysis.document",
                    "records": "anomalies",
                },
                {
                    "id": "write",
                    "for_each": "$steps.anomalies.records",
                    "subject": {
                        "kind": defs.ANOMALY,
                        "key": {"name": "$item.key.name"},
                        "create": "if_absent",
                    },
                    "claims": [
                        {
                            "type": f"{defs.ANOMALY}.asset",
                            "value": {
                                "kind": defs.ASSET,
                                "key": {"name": "$item.fields.asset"},
                            },
                            "rationale": "{$item.fields.reason}",
                        },
                        {
                            "type": f"{defs.ANOMALY}.metric",
                            "value": "$item.fields.metric",
                            "rationale": "{$item.fields.reason}",
                        },
                        {
                            "type": f"{defs.ANOMALY}.severity",
                            "value": "$item.fields.severity",
                            "rationale": "{$item.fields.reason}",
                        },
                    ],
                },
            ],
        }
    )

    attention = refs(
        {
            "procedure": ATTENTION_PROCEDURE,
            "description": "Post one Line inbox item per unjudged fleet.anomaly at or above "
            "min_severity for review in cruxible next.",
            "input": {},
            "output": {},
            "parameter_contract": f"{ATTENTION_PROCEDURE}.params@1",
            "returns": {"fields": {}},
            "hard_caps": {**_CAPS, "provider_calls": 0, "capture_bytes": 0},
            "steps": [
                {
                    "read": "open_items",
                    "query": defs.ANOMALIES_NEEDING_TRIAGE_QUERY,
                    "params": {"min_severity": "$params.min_severity"},
                },
                {
                    "id": "post",
                    "inbox": f"{ATTENTION_ITEM}@1",
                    "for_each": "$steps.open_items.rows",
                    "fields": {
                        "anomaly": "$item.anomaly",
                        "asset": "$item.asset",
                        "metric": "$item.metric",
                        "severity": "$item.severity",
                    },
                    "dedupe_key": ["anomaly"],
                },
            ],
        }
    )

    members = [
        {"kind": "procedure", "spec": spec}
        for spec in (ingest, sensor_health, anomaly_ingest, attention)
    ]
    for member in members:
        ProcedureInput.model_validate(member)
    return {
        "kind": "change_set",
        "rationale": "iot-fleet 2.1.0 telemetry ingest, sensor health, anomaly ingest, and "
        "observe-only attention Procedures.",
        "members": members,
    }


def provider_shapes() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    from cruxible_client.contracts.capabilities import capability_digest, parse_capability
    from cruxible_client.contracts.capture_layouts import (
        DeclaredCaptureKind,
        declared_capture_kind_digest,
    )

    tree = contract_tree()
    contracts = [
        json.loads(content) for path, content in tree.items() if path.startswith("contracts/")
    ]
    kinds: list[dict[str, Any]] = []
    built_against: list[dict[str, Any]] = []
    for name, record in sorted(capture_kinds().items()):
        declared = DeclaredCaptureKind.model_validate(
            {
                "name": name,
                "decoding": record.get("decoding"),
                "layout": record.get("layout"),
            }
        )
        kinds.append(declared.model_dump(mode="json"))
        if declared.layout is not None:
            built_against.append(
                {
                    "kind": "CaptureKind",
                    "name": name,
                    "digest": declared_capture_kind_digest(declared).tagged,
                }
            )
    for path, content in tree.items():
        if path.startswith("capabilities/"):
            item = parse_capability(content, path=path)
            built_against.append(
                {
                    "kind": "Capability",
                    "name": item.name,
                    "version": item.version,
                    "digest": capability_digest(item).tagged,
                }
            )
    return contracts, kinds, built_against


def write_registration(*, check: bool = False) -> bool:
    from cruxible_provider_runtime.registration import write_registration as _write

    refusal_contract = {
        "artifact_format": "cruxible-contract-v1",
        "description": "Detail of a provider_declined refusal (malformed telemetry batch or "
        "invalid filter parameters).",
        "fields": {},
        "name": "telemetry.analyze.refusal.provider_declined",
        "version": 1,
    }
    operation = {
        "name": "telemetry.analyze",
        "description": "Applies an EWMA gain filter, flatline check, and approved-baseline "
        "classifier to one hub telemetry batch Capture and returns one derived analysis document.",
        "source": {
            "path": "kits/iot-fleet/source/providers/iot-telemetry-provider/src/"
            "iot_telemetry_provider/telemetry.py",
            "repository": REPOSITORY,
        },
        "serves": [ANALYZE_CAPABILITY],
        "in": ANALYZE_CAPABILITY + ".request@1",
        "out": ANALYZE_CAPABILITY + ".result@1",
        "effect": "pure",
        "refusals": {
            "provider_declined": {
                "contract": "telemetry.analyze.refusal.provider_declined@1",
                "absorbable": False,
            }
        },
        "entrypoint": "iot_telemetry_provider.telemetry:telemetry_analyze",
    }
    contracts, kinds, built_against = provider_shapes()
    with tempfile.TemporaryDirectory(prefix="iot-registration-") as scratch:
        copy = Path(scratch) / "iot_telemetry_provider"
        copy.mkdir()
        shutil.copyfile(PROVIDER_ROOT / "manifest.yaml", copy / "manifest.yaml")
        (copy / "registration.json").write_text(
            json.dumps(
                {
                    "schema_version": 3,
                    "manifest": {"path": "manifest.yaml", "digest": "sha256:" + "0" * 64},
                    "operations": [operation],
                    "declares": {"contracts": [refusal_contract]},
                    "runtime_requirements": [],
                }
            )
        )
        pool = [*contracts, refusal_contract]
        _write(copy, contracts=pool, capture_kinds=kinds)
        carried = {
            item["name"]
            for item in json.loads((copy / "registration.json").read_bytes())["declares"].get(
                "capture_kinds", ()
            )
        }
        _write(
            copy,
            contracts=pool,
            capture_kinds=kinds,
            built_against=[
                item
                for item in built_against
                if (item["kind"] == "Capability" and item["name"] == ANALYZE_CAPABILITY)
                or (item["kind"] == "CaptureKind" and item["name"] in carried)
            ],
        )
        rendered = (copy / "registration.json").read_bytes()
    target = PROVIDER_ROOT / "registration.json"
    current = target.is_file() and target.read_bytes() == rendered
    if not current and not check:
        target.write_bytes(rendered)
    return current


_FINDINGS_INBOX = [
    "extract_refused",
    "duplicate_key",
    "incomplete_source",
    "held_disagrees",
    "slot_contested",
]


def _telemetry_members(
    *,
    name: str,
    relative_path: str,
    alpha: str,
    min_breach_samples: Any,
    flatline_samples: Any,
    max_heartbeat_age_s: Any,
    expires: str,
) -> list[dict[str, Any]]:
    ingest_line = f"fleet.telemetry-ingest.{name}"
    sensor_line = f"fleet.sensor-health.{name}"
    anomaly_line = f"fleet.anomaly-ingest.{name}"
    source_label = f"fleet.telemetry.{name}"
    return [
        {
            "kind": "line",
            "name": ingest_line,
            "procedure_name": INGEST_PROCEDURE,
            "bindings": {
                "read": WORKSPACE_FILE_BINDING,
                "derive": ANALYZE_BINDING,
            },
            "parameters": {
                "relative_path": relative_path,
                "logical_source": source_label,
                "alpha": alpha,
                "min_breach_samples": min_breach_samples,
                "flatline_samples": flatline_samples,
                "max_heartbeat_age_s": max_heartbeat_age_s,
            },
            "acquisition": {},
            "findings": {"inbox": _FINDINGS_INBOX},
            "max_authority": "settle",
        },
        {
            "kind": "procedure_mandate",
            "name": f"{ingest_line}-propose",
            "line_name": ingest_line,
            "grants": "propose",
            "namespace": ["claims"],
            "expires": expires,
        },
        {
            "kind": "procedure_mandate",
            "name": f"{ingest_line}-settle",
            "line_name": ingest_line,
            "grants": "settle",
            "scope": "observations",
            "expires": expires,
        },
        {
            "kind": "line",
            "name": sensor_line,
            "procedure_name": SENSOR_PROCEDURE,
            "bindings": {"derive": ANALYZE_BINDING},
            "parameters": {"logical_source": source_label},
            "trigger_input": "analysis.document",
            "acquisition": {"analysis.document": {}},
            "findings": {"inbox": _FINDINGS_INBOX},
            "max_authority": "settle",
        },
        {
            "kind": "procedure_mandate",
            "name": f"{sensor_line}-propose",
            "line_name": sensor_line,
            "grants": "propose",
            "namespace": ["claims"],
            "expires": expires,
        },
        {
            "kind": "procedure_mandate",
            "name": f"{sensor_line}-settle",
            "line_name": sensor_line,
            "grants": "settle",
            "scope": "observations",
            "expires": expires,
        },
        {
            "kind": "trigger",
            "name": f"fleet.sensor-health-on-analysis.{name}",
            "line_name": sensor_line,
            "schedule": {
                "kind": "capture_landing",
                "capture_contract": TELEMETRY_ANALYSIS_KIND,
                "logical_sources": [source_label],
            },
        },
        {
            "kind": "line",
            "name": anomaly_line,
            "procedure_name": ANOMALY_PROCEDURE,
            "bindings": {"derive": ANALYZE_BINDING},
            "parameters": {"logical_source": source_label},
            "trigger_input": "analysis.document",
            "acquisition": {"analysis.document": {}},
            "findings": {"inbox": _FINDINGS_INBOX},
            "max_authority": "settle",
        },
        {
            "kind": "procedure_mandate",
            "name": f"{anomaly_line}-propose",
            "line_name": anomaly_line,
            "grants": "propose",
            "namespace": ["claims", "subjects"],
            "expires": expires,
        },
        {
            "kind": "procedure_mandate",
            "name": f"{anomaly_line}-settle",
            "line_name": anomaly_line,
            "grants": "settle",
            "scope": "observations",
            "expires": expires,
            "subject_creation": [defs.ANOMALY],
        },
        {
            "kind": "trigger",
            "name": f"fleet.anomaly-ingest-on-analysis.{name}",
            "line_name": anomaly_line,
            "schedule": {
                "kind": "capture_landing",
                "capture_contract": TELEMETRY_ANALYSIS_KIND,
                "logical_sources": [source_label],
            },
        },
    ]


def _default_members(*, min_severity: str) -> list[dict[str, Any]]:
    return [
        {
            "kind": "line",
            "name": "fleet.attention",
            "procedure_name": ATTENTION_PROCEDURE,
            "bindings": {},
            "parameters": {"min_severity": min_severity},
            "acquisition": {},
            "max_authority": "observe",
        },
        {
            "kind": "runbook",
            "name": "fleet.check",
            "description": "Run every adopted hub telemetry ingest Line (EWMA gain filter and "
            "approved-baseline classifier), then post unjudged anomalies to the Line inbox. "
            "Landing Triggers automatically settle fleet.sensor.status and fleet.anomaly "
            "observations from the derived analysis Capture.",
            "steps": [
                {"procedure": INGEST_PROCEDURE},
                {"line": "fleet.attention"},
            ],
        },
    ]


def render_automation() -> str:
    payload = {
        "kind": "change_set",
        "rationale": "Adopt the iot-fleet telemetry loop for one hub (telemetry/hub.json): "
        "EWMA gain filter and approved-baseline classifier settling observation claims only "
        "(fleet.asset.operating_state, fleet.sensor.status, fleet.anomaly observations), plus "
        "the observe-only fleet.attention Line and fleet.check Runbook. Normative judgments "
        "(baselines, asset condition, anomaly disposition, firmware status) stay outside every "
        "Mandate.",
        "members": [
            *_default_members(min_severity="medium"),
            *_telemetry_members(
                name="hub",
                relative_path="telemetry/hub.json",
                alpha="0.3",
                min_breach_samples=3,
                flatline_samples=5,
                max_heartbeat_age_s=1800,
                expires="90d",
            ),
        ],
    }
    return json.dumps(payload, indent=1) + "\n"


def render_recipes() -> dict[Path, str]:
    default_recipe = {
        "kind": "change_set",
        "rationale": "kit adopt iot-fleet: observe-only fleet.attention Line (min_severity "
        "{{min_severity}}) and fleet.check Runbook fanning out over every adopted hub telemetry "
        "Line. Adopt iot-fleet:telemetry once per hub telemetry export.",
        "members": _default_members(min_severity="{{min_severity}}"),
    }
    telemetry_recipe = {
        "kind": "change_set",
        "rationale": "kit adopt iot-fleet:telemetry: hub telemetry ingest Line "
        "fleet.telemetry-ingest.{{name}} reading {{relative_path}} with EWMA gain {{alpha}}, "
        "its capture-landing sensor-health and anomaly-ingest Lines, and scope: observations "
        "Mandates valid for {{expires}}.",
        "members": _telemetry_members(
            name="{{name}}",
            relative_path="{{relative_path}}",
            alpha="{{alpha}}",
            min_breach_samples="{{min_breach_samples}}",
            flatline_samples="{{flatline_samples}}",
            max_heartbeat_age_s="{{max_heartbeat_age_s}}",
            expires="{{expires}}",
        ),
    }
    return {
        KIT / "recipes" / "default.json": json.dumps(default_recipe, indent=1) + "\n",
        KIT / "recipes" / "telemetry.json": json.dumps(telemetry_recipe, indent=1) + "\n",
    }


def render_recipe_specs() -> str:
    specs = [
        {
            "name": "default",
            "path": "recipes/default.json",
            "description": "Shared fleet automation backbone: the observe-only fleet.attention "
            "Line (posts unjudged anomalies to cruxible next) and the fleet.check Runbook.",
            "params": {
                "min_severity": {
                    "type": "enum",
                    "default": "medium",
                    "values": ["info", "low", "medium", "high", "critical"],
                    "description": "Minimum anomaly severity posted to the Line inbox.",
                }
            },
        },
        {
            "name": "telemetry",
            "path": "recipes/telemetry.json",
            "description": "One hub's telemetry ingest Line (EWMA gain filter + approved-baseline "
            "classifier), its capture-landing sensor-health and anomaly-ingest Lines, and their "
            "observations-only Mandates. Adopt once per hub export.",
            "params": {
                "name": {
                    "type": "string",
                    "default": "hub",
                    "pattern": "^[a-z][a-z0-9_-]{0,48}$",
                    "description": "Short identifier for this hub export (Line suffix and logical "
                    "source suffix).",
                },
                "relative_path": {
                    "type": "string",
                    "required": True,
                    "example": "telemetry/hub.json",
                    "pattern": "^(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\\.[A-Za-z0-9_-][A-Za-z0-9._-]*)"
                    "(?:/(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\\.[A-Za-z0-9_-][A-Za-z0-9._-]*))*$",
                    "description": "Workspace-relative path of the hub telemetry JSON batch.",
                },
                "alpha": {
                    "type": "string",
                    "default": "0.3",
                    "pattern": "^(0\\.[0-9]{1,6}|1(\\.0{1,6})?)$",
                    "description": "EWMA smoothing gain in (0, 1]. Lower values absorb sharper "
                    "transient spikes.",
                },
                "min_breach_samples": {
                    "type": "integer",
                    "default": 3,
                    "description": "Consecutive filtered samples outside approved bounds required "
                    "to classify a fault.",
                },
                "flatline_samples": {
                    "type": "integer",
                    "default": 5,
                    "description": "Consecutive identical samples required to mark a sensor "
                    "degraded (flatlined).",
                },
                "max_heartbeat_age_s": {
                    "type": "integer",
                    "default": 1800,
                    "description": "Maximum heartbeat age in seconds before marking a sensor "
                    "offline (default 1800 = 30 min).",
                },
                "expires": {
                    "type": "string",
                    "default": "90d",
                    "pattern": "^[1-9][0-9]{0,4}[hdwy]$",
                    "description": "How long each observations-only Mandate stays valid (36h, "
                    "90d, 12w, 1y).",
                },
            },
        },
    ]
    return json.dumps(specs, indent=1) + "\n"


def write_templates() -> None:
    (KIT / "automation.json").write_text(render_automation())
    for path, content in render_recipes().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (SOURCE / "recipes.json").write_text(render_recipe_specs())
