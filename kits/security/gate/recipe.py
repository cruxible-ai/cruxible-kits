"""The README consumer recipe as payloads, for the release gate and the self-dogfood run.

Every function returns the exact authoring JSON the README shows; nothing here
talks to a daemon. ``automation`` needs the four CaptureContract digests its
capture-landing Triggers pin (``cruxible get CaptureContract:NAME --detail
proof``'s ``artifact_digest``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

POLICY = "security.acquisition"
LANDING_CONTRACTS = (
    "security.kev-http-v1",
    "security.epss-daily-v1",
    "security.cyclonedx-sbom-v1",
    "security.cve-record-http-v1",
)
#: Line -> (Procedure, max_authority, trigger_input)
LINES: dict[str, tuple[str, str, str | None]] = {
    "security.kev-daily": ("security.kev-acquire", "observe", None),
    "security.kev-triage": ("security.kev-triage", "propose", "catalog"),
    "security.kev-attention": ("security.kev-attention", "observe", "catalog"),
    "security.epss-daily": ("security.epss-acquire", "observe", None),
    "security.epss-triage": ("security.epss-triage", "propose", "epss"),
    "security.sbom-import": ("security.sbom-import", "propose", "sbom"),
    "security.osv-applicability": ("security.osv-applicability", "propose", None),
    "security.cve-applicability": ("security.cve-applicability", "propose", "record"),
}
APPLICABILITY_NAMESPACE = [
    "claims", "subjects/security.assessment", "subjects/security.vulnerability"]
#: Procedure -> (namespace, wall clock s, provider calls, capture bytes, items)
MANDATES: dict[str, tuple[list[str], int, int, int, int]] = {
    "security.kev-triage": (["claims"], 300, 2, 16_777_216, 5000),
    "security.epss-triage": (["claims"], 300, 2, 33_554_432, 5000),
    "security.sbom-import": (
        ["claims", "subjects/security.product", "subjects/security.release",
         "subjects/security.supplier"], 300, 2, 16_777_216, 5000),
    "security.osv-applicability": (APPLICABILITY_NAMESPACE, 600, 2, 67_108_864, 5000),
    "security.cve-applicability": (APPLICABILITY_NAMESPACE, 300, 2, 16_777_216, 5000),
}
KEV_FIELDS = ("kev_date_added", "kev_due_date", "kev_listed", "kev_ransomware_use")
EPSS_FIELDS = ("epss_percentile", "epss_score")


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def instantiate(fetch: str, sources: str) -> dict[str, Any]:
    """Step 1: the four acquisition Blueprints, bound to installed Providers."""

    members = [
        {"kind": "blueprint_instance", "name": name, "blueprint": name,
         "bindings": {slot: provider}, "acquisition_policy": POLICY}
        for name, slot, provider in (
            ("security.kev-acquire", "catalog", fetch),
            ("security.cve-record-acquire", "record", fetch),
            ("security.epss-acquire", "epss", sources),
            ("security.osv-applicability", "osv", sources),
        )
    ]
    return {"kind": "change_set", "rationale": "Instantiate the security Blueprints.",
            "members": members}


def mandate(procedure: str, grants: str, *, name: str | None = None,
            days: int = 90, **extra: Any) -> dict[str, Any]:
    namespace, seconds, calls, capture_bytes, items = MANDATES[procedure]
    now = _now()
    return {
        "kind": "procedure_mandate",
        "name": name or f"{procedure}-{grants}",
        "procedure_name": procedure,
        "grants": grants,
        "namespace": namespace if grants == "propose" else ["claims"],
        "valid_from": _stamp(now),
        "expires_at": _stamp(now + timedelta(days=days)),
        "resource_ceiling": {
            "max_wall_clock": {"microseconds": seconds * 1_000_000},
            "max_provider_calls": calls,
            "max_capture_bytes": capture_bytes,
            "max_items": items,
            "max_repeat_attempts": 1,
        },
        **extra,
    }


def line(name: str, *, authority: str | None = None) -> dict[str, Any]:
    procedure, cap, trigger_input = LINES[name]
    payload: dict[str, Any] = {
        "kind": "line", "name": name, "procedure_name": procedure,
        "acquisition_policy_name": POLICY, "max_authority": authority or cap,
    }
    if trigger_input is not None:
        payload["trigger_input"] = trigger_input
    return payload


def landing(name: str, line_name: str, contract: str, digest: str) -> dict[str, Any]:
    return {"kind": "trigger", "name": name, "line_name": line_name,
            "schedule": {"kind": "capture_landing", "event": {
                "capture_contract_identity": {"kind": "CaptureContract", "name": contract},
                "capture_contract_digest": digest}}}


def cron(name: str, line_name: str, expression: str) -> dict[str, Any]:
    return {"kind": "trigger", "name": name, "line_name": line_name,
            "schedule": {"kind": "cron", "expression": expression}}


def automation(digests: dict[str, str]) -> dict[str, Any]:
    """Step 2: every Line, its Triggers, and the propose mandates, in one change set."""

    members: list[dict[str, Any]] = [line(name) for name in LINES]
    members += [
        cron("security.kev-daily", "security.kev-daily", "17 14 * * *"),
        cron("security.epss-daily", "security.epss-daily", "45 13 * * *"),
        cron("security.osv-daily", "security.osv-applicability", "30 15 * * *"),
        landing("security.kev-landed", "security.kev-triage", "security.kev-http-v1",
                digests["security.kev-http-v1"]),
        landing("security.kev-landed-attention", "security.kev-attention",
                "security.kev-http-v1", digests["security.kev-http-v1"]),
        landing("security.epss-landed", "security.epss-triage", "security.epss-daily-v1",
                digests["security.epss-daily-v1"]),
        landing("security.sbom-landed", "security.sbom-import", "security.cyclonedx-sbom-v1",
                digests["security.cyclonedx-sbom-v1"]),
        landing("security.cve-landed", "security.cve-applicability",
                "security.cve-record-http-v1", digests["security.cve-record-http-v1"]),
    ]
    members += [mandate(procedure, "propose") for procedure in MANDATES]
    return {"kind": "change_set",
            "rationale": "Automate KEV, EPSS, SBOM import and applicability (propose-only).",
            "members": members}


def graduate() -> dict[str, Any]:
    """Step 8: settle the verbatim KEV and EPSS fields under settle mandates."""

    def scope(fields: tuple[str, ...]) -> list[dict[str, Any]]:
        return [{"claim_type": f"security.vulnerability.{field}",
                 "change_kinds": ["create", "revise"]} for field in fields]

    condition = {"query_name": "security.settle_condition",
                 "binding_parameter": "vulnerability_id", "required_fields": ["cve_id"],
                 "fallback": "propose"}
    return {"kind": "change_set",
            "rationale": "Graduate KEV and EPSS triage to settle under mandates.",
            "members": [
                mandate("security.kev-triage", "settle", scope=scope(KEV_FIELDS),
                        condition=condition),
                mandate("security.epss-triage", "settle", scope=scope(EPSS_FIELDS),
                        condition=condition),
                line("security.kev-triage", authority="settle"),
                line("security.epss-triage", authority="settle"),
            ]}


def subject(kind: str, key: Any, rationale: str) -> dict[str, Any]:
    return {"kind": "subject", "subject_kind": kind, "key": key, "rationale": rationale}


def claim(subject_ref: str, predicate: str, value: Any, rationale: str, *,
          subject_valued: bool = False) -> dict[str, Any]:
    obj: dict[str, Any] = (
        {"kind": "subject", "subject": subject_ref_of(value)} if subject_valued
        else {"kind": "literal", "value": value}
    )
    return {"kind": "claim", "subject": subject_ref, "predicate": predicate, "object": obj,
            "role": "normative", "rationale": rationale,
            "source": {"kind": "self_source", "body": rationale + "\n"}}


def subject_ref_of(value: str) -> str:
    return value


def watch(*cves: str, reason: str = "Tracked by the security team.") -> dict[str, Any]:
    """Watch CVEs: create each vulnerability by key (a held key creates nothing) and state
    the decision to track it (``watch_reason``). Existence alone watches nothing."""

    members: list[dict[str, Any]] = []
    for cve in cves:
        canonical = cve.strip().upper()
        members.append(subject("security.vulnerability", cve, f"Track {canonical}."))
        members.append({
            "kind": "claim",
            # A claim member names the Subject its sibling creates by the id core renders.
            "subject": f"security.vulnerability/{canonical.lower()}",
            "predicate": "security.vulnerability.watch_reason",
            "object": {"kind": "literal", "value": reason},
            "role": "normative",
            "rationale": f"Track {canonical}: {reason}",
            "source": {"kind": "self_source", "body": f"track {canonical}: {reason}\n"},
        })
    return {"kind": "change_set", "rationale": "Watch vulnerabilities.", "members": members}
