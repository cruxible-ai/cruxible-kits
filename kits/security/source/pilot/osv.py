"""The OSV link of the chain, in the template form (D-R37, K-B1-3/4/6).

    read (inventoried components) -> fetch osv.query (OSV's responses, a list of
    Captures) -> derive osv.match (one derived JSON document) -> extract ->
    claims (component.affected_by)

One Procedure and one Line. ``affected_by`` creates each vulnerability OSV
names by value (``create: if_absent``, V1); ``expect`` is the derived
document's ``queried`` header (V4), so a component OSV did not answer in full
(a distro package, K-B1-6, or a failed request) is never retired. The Line
settles ``affected_by`` on the extracted record and retires it on a complete
read's absence (K-B1-4, K-B2-G4). A component is asked about while some
inventory holds it: an occurrence of it with a live ``scope``.

An advisory with no CVE alias keys no vulnerability, so it writes no Claim: the
derived document lists it under ``unkeyed``. A second Procedure and Line,
``security.osv-unkeyed``, runs on that document's landing (a
``capture_landing`` Trigger; the match call is substituted, never re-run, as
``security.sarif-attention`` does) and posts one inbox item per (advisory,
component). A Procedure has one terminal, so the claims and this inbox egress
are two Procedures composed through the derived Capture. When OSV later lists a
CVE alias, the next run writes the ordinary ``affected_by`` finding and the
advisory leaves ``unkeyed``, so the item is no longer posted (it stays in the
inbox as it was; core does not withdraw inbox items).

An agent's package-level not_affected judgment is "affected_by none of V",
normative, on V's own unit (K-B2-J1): OSV's next observation of V cannot
override it and is reported as ``held_disagrees``, which this Line routes to
its inbox.

OSV writes no pair Subjects (D-R43). The versions OSV lists as fixed are no
Claim: they stay in the derived ``osv.match`` document every ``affected_by``
cites (each record's ``fixed``; see ``security_osv_provider.osv``), where an
agent reads them (D-R44: nothing reacts to their change).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from capabilities import OSV_MATCH, OSV_QUERY, capability
from definitions import VULN, params_contract, params_contract_members, refs
from inventory import COMPONENT, DEPENDENCY_PROVIDER, OCCURRENCE, OSV_MATCH_KIND, OSV_SOURCE

OSV_PROCEDURE = "security.osv-query"
OSV_LINE = "security.osv-query"
OSV_COMPONENTS = "security.osv_components"
OSV_COMPONENT_ROW = "security.osv-component"
OSV_ROW = "security.osv-affected"
#: Each OSV response (one querybatch POST or one vulns GET), verbatim.
OSV_RESPONSE_KIND = "security.osv-response"
OSV_ORIGIN = "https://api.osv.dev"
AFFECTED_BY = COMPONENT + ".affected_by"
#: The advisories with no CVE alias, to the Line inbox (one Procedure, Line and
#: inbox item Contract of this name), on the derived match document's landing.
UNKEYED = "security.osv-unkeyed"
UNKEYED_PROCEDURE = UNKEYED
UNKEYED_LINE = UNKEYED
UNKEYED_ITEM = UNKEYED
UNKEYED_ROW = "security.osv-unkeyed-record"
UNKEYED_TRIGGER = "security.osv-matches-landed"
#: The most items one unkeyed run posts (core's ceiling for a declared max_items).
UNKEYED_MAX_ITEMS = 1000
#: Where a reader looks an advisory up by its id.
OSV_ADVISORY_PAGE = "https://osv.dev/vulnerability/"


# -- CaptureKinds -----------------------------------------------------------------------


def capture_kinds() -> dict[str, dict[str, Any]]:
    """One OSV response's kind: the body verbatim, decoded as JSON when read."""

    return {
        OSV_RESPONSE_KIND: {
            "name": OSV_RESPONSE_KIND,
            "shape": "http_response",
            "grade": "observed",
            "replay": "attested",
            "retention": "P400D",
            "erasable": False,
            "max_bytes": 4 * 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": {
                "format": "json",
                "encoding": "identity",
                "limits": {"decoded_bytes": 4 * 1024 * 1024, "depth": 32, "records": 100_000},
            },
        }
    }


# -- Vocabulary -------------------------------------------------------------------------


#: Every inventoried component, one row each: what the OSV Line asks about. A
#: component is inventoried while an occurrence of it holds a visible scope (R3).
COMPONENTS_SPEC: dict[str, Any] = {
    "query": OSV_COMPONENTS,
    "description": "Every component some inventory holds (an occurrence with a scope), once "
    "each: the components OSV is asked about.",
    "from": {"c": COMPONENT},
    "hops": [{"o": f"{OCCURRENCE}{{component: c}}! with scope"}],
    "row": f"{OSV_COMPONENT_ROW}@1",
    "fields": ["c.purl"],
}


def vocabulary_members(claim_types: Sequence[Any]) -> list[dict[str, Any]]:
    from definitions import subject_shaped

    return [
        {
            "kind": "contract",
            "name": OSV_COMPONENT_ROW,
            "version": 1,
            "description": "One inventoried component's purl: what OSV is asked about.",
            "fields": {"purl": "string{max_len: 256}"},
        },
        {
            "kind": "contract",
            "name": OSV_ROW,
            "version": 1,
            "description": "One (component, CVE) pair the OSV match found, with its OSV "
            "advisory id; the versions OSV lists as fixed stay in the cited document.",
            "fields": {"osv_id": "string{max_len: 128}"},
        },
        {
            "kind": "contract",
            "name": UNKEYED_ROW,
            "version": 1,
            "description": "One OSV advisory with no CVE alias that lists a component: the "
            "component's purl and the advisory id.",
            "fields": {"purl": "string{max_len: 256}", "osv_id": "string{max_len: 128}"},
        },
        {
            "kind": "contract",
            "name": UNKEYED_ITEM,
            "version": 1,
            "description": "An OSV advisory that lists a component but names no CVE yet, so it "
            "is no vulnerability Subject and no finding: read it and decide. When OSV lists a "
            "CVE for it, the next OSV run records the ordinary affected_by finding and this "
            "item is no longer posted.",
            "fields": {
                "osv_id": {
                    "type": "string{max_len: 128}",
                    "description": "The OSV advisory id (GHSA-..., PYSEC-..., ...): read it at "
                    f"{OSV_ADVISORY_PAGE}<osv_id>.",
                },
                "purl": {
                    "type": f"key<{COMPONENT}>",
                    "description": "The component's key: its purl@version.",
                },
            },
        },
        {
            "kind": "query_definition",
            "query_definition": subject_shaped(COMPONENTS_SPEC, claim_types),
        },
        *params_contract_members(OSV_PROCEDURE, *OSV_PARAMS),
    ]


# -- Procedure --------------------------------------------------------------------------

#: What the Line on security.osv-query supplies, as its params Contract says it.
OSV_PARAMS = (
    "What the Line on security.osv-query needs: only the source label. It asks "
    "api.osv.dev about every component an inventory holds; when the Line lists "
    "acquisition origins, https://api.osv.dev must be one.",
    {
        "logical_source": (
            'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}',
            "Source label OSV's responses and the derived match document are recorded "
            "under, lowercase (the template uses osv.dev.query). Evidence requirements and "
            "landing Triggers can name it.",
        ),
    },
)


def osv_spec() -> dict[str, Any]:
    return refs(
        {
            "procedure": OSV_PROCEDURE,
            "description": "Ask OSV about every inventoried component and write the "
            "vulnerabilities OSV lists for its exact purl@version; for a component OSV answered "
            "in full, a vulnerability it no longer lists is retired.",
            "input": {},
            "output": {},
            "parameter_contract": params_contract(OSV_PROCEDURE),
            "slots": {
                "query": {"capability": capability(OSV_QUERY)},
                "match": {"capability": capability(OSV_MATCH)},
            },
            "hard_caps": {
                "wall_clock": "PT5M",
                "provider_calls": 2,
                "capture_bytes": 64 * 1024 * 1024,
                "items": 50_000,
                "read_rows": 20_000,
                "repeat_attempts": 1,
            },
            "steps": [
                {"read": "components", "query": OSV_COMPONENTS},
                {
                    "call": "osv",
                    "slot": "query",
                    "captures": {"responses": OSV_RESPONSE_KIND},
                    "input": {
                        "components": "$steps.components.rows.[*].purl",
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "call": "matched",
                    "slot": "match",
                    "captures": {"document": OSV_MATCH_KIND},
                    "input": {
                        "responses": "$steps.osv.responses",
                        "components": "$steps.components.rows.[*].purl",
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "extract": "affected",
                    "capture": "$steps.matched.document",
                    "records": "affected",
                    "header": ["queried"],
                },
                {
                    "id": "write",
                    "for_each": "$steps.affected.records",
                    "subject": {
                        "kind": COMPONENT,
                        "key": {"purl": "$item.key.purl"},
                        "create": "never",
                    },
                    # K-B1-6: only the components OSV answered in full are judged.
                    "expect": "$steps.affected.header.queried",
                    "claims": [
                        {
                            "type": AFFECTED_BY,
                            "value": {
                                "kind": VULN,
                                "key": {"cve_id": "$item.key.cve_id"},
                                "create": "if_absent",
                            },
                            "when_absent": "mirror",
                            "rationale": "OSV {$item.fields.osv_id} lists {$item.key.cve_id} "
                            "for {$item.key.purl}.",
                        },
                    ],
                },
            ],
        }
    )


def unkeyed_spec() -> dict[str, Any]:
    """``security.osv-unkeyed``: each advisory with no CVE alias to the Line inbox.

    It runs on the landing of the OSV Line's derived match document: the Trigger
    substitutes that Capture for the match call, so nothing is fetched or
    re-derived (the call's input is never evaluated; it is typed against the
    capability's request only). One item per (advisory, component): seen again
    while OSV still lists the advisory with no CVE, no longer posted once it
    names one.
    """

    return refs(
        {
            "procedure": UNKEYED_PROCEDURE,
            "description": "Post each OSV advisory with no CVE alias in one derived OSV match "
            "document to the Line's inbox, one item per advisory and component: no Claim "
            "records it until OSV lists a CVE for it.",
            "input": {},
            "output": {},
            # Inbox egress is the terminal; the run's own value is empty.
            "returns": {"fields": {}},
            "slots": {"match": {"capability": capability(OSV_MATCH)}},
            "hard_caps": {
                "wall_clock": "PT5M",
                "provider_calls": 1,
                "capture_bytes": 4 * 1024 * 1024,
                "items": 20_000,
                "read_rows": 1,
                "repeat_attempts": 1,
            },
            "steps": [
                {
                    "call": "matched",
                    "slot": "match",
                    "captures": {"document": OSV_MATCH_KIND},
                    "input": {"responses": [], "components": [], "logical_source": OSV_SOURCE},
                },
                {
                    "extract": "unkeyed",
                    "capture": "$steps.matched.document",
                    "records": "unkeyed",
                },
                {
                    "id": "post",
                    "inbox": f"{UNKEYED_ITEM}@1",
                    "for_each": "$steps.unkeyed.records",
                    "fields": {
                        "osv_id": "$item.fields.osv_id",
                        "purl": "$item.fields.purl",
                    },
                    "dedupe_key": ["osv_id", "purl"],
                    "max_items": UNKEYED_MAX_ITEMS,
                },
            ],
        }
    )


def procedure_members() -> list[dict[str, Any]]:
    from cruxible_client.contracts.authoring.inputs import ProcedureInput

    members = [
        {"kind": "procedure", "spec": osv_spec()},
        {"kind": "procedure", "spec": unkeyed_spec()},
    ]
    for member in members:
        ProcedureInput.model_validate(member)
    return members


# -- Automation -------------------------------------------------------------------------

#: K-B1-4 / K-B2-G4: the osv Line settles affected_by create/revise on the
#: extracted record and retire on a complete read's absence, and may create
#: security.vulnerability Subjects. Judgments (the none, the justifications) are
#: never in it.
OSV_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    AFFECTED_BY: {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    }
}


def automation(
    *, now: datetime, findings: Sequence[str], settle: bool = True
) -> list[dict[str, Any]]:
    """The OSV Line (the consumer's) and its Mandates; the template's maintenance
    Runbook runs it daily. Then the unkeyed Line and its Trigger: it runs on each
    landing of the OSV Line's derived match document, so it is no Runbook step (a
    Line that binds its triggering Capture runs only on an event)."""

    valid_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    members: list[dict[str, Any]] = [
        {
            "kind": "line",
            "name": OSV_LINE,
            "procedure_name": OSV_PROCEDURE,
            "bindings": {
                "query": f"{DEPENDENCY_PROVIDER}#osv.query",
                "match": f"{DEPENDENCY_PROVIDER}#osv.match",
            },
            "parameters": {"logical_source": OSV_SOURCE},
            "acquisition": {"osv.responses": {"origins": [OSV_ORIGIN]}},
            "findings": {"inbox": list(findings)},
            "max_authority": "settle" if settle else "propose",
        },
        {
            "kind": "procedure_mandate",
            "name": OSV_LINE + "-propose",
            "line_name": OSV_LINE,
            "grants": "propose",
            "namespace": ["claims", "subjects"],
            "valid_from": valid_from,
            "expires_at": expires_at,
        },
    ]
    if settle:
        members.append(
            {
                "kind": "procedure_mandate",
                "name": OSV_LINE + "-settle",
                "line_name": OSV_LINE,
                "grants": "settle",
                "namespace": ["claims"],
                "valid_from": valid_from,
                "expires_at": expires_at,
                "subject_creation": [VULN],
                "scope": [
                    {"claim_type": claim_type, "changes": changes}
                    for claim_type, changes in OSV_SETTLE_SCOPE.items()
                ],
            }
        )
    members += unkeyed_automation()
    return members


def unkeyed_automation() -> list[dict[str, Any]]:
    """The unkeyed Line (inbox egress only: ``observe``, no Mandate) and the Trigger
    that runs it on each landing of the derived match document under the OSV
    Line's logical source."""

    return [
        {
            "kind": "line",
            "name": UNKEYED_LINE,
            "procedure_name": UNKEYED_PROCEDURE,
            "bindings": {"match": f"{DEPENDENCY_PROVIDER}#osv.match"},
            "parameters": {},
            "trigger_input": "matched.document",
            "acquisition": {"matched.document": {}},
            "max_authority": "observe",
        },
        {
            "kind": "trigger",
            "name": UNKEYED_TRIGGER,
            "line_name": UNKEYED_LINE,
            "schedule": {
                "kind": "capture_landing",
                "capture_contract": OSV_MATCH_KIND,
                "logical_sources": [OSV_SOURCE],
            },
        },
    ]

