"""PREPARED, NOT WIRED: the OSV link of the chain (K2/K5/K6), in the template form.

    read (inventoried components) -> fetch osv.query (OSV's responses, one
    Capture each) -> derive osv.match (one derived JSON document) -> extract
    -> claims (component.affected_by, settled per K-B1-4)

Nothing here is installed: ``definitions.procedures()`` does not include it.
It needs core lanes A (list Captures, template-slice-decisions a1-a8) and B
(derive inputs and derived Captures, b1-b8, c1-c6), and the provider package
``source/providers/security-osv-provider`` (wheel + lock, installed like
cruxible-provider-web). Each TODO(core lane ...) marks what changes then.

Open points for the wiring slice (recorded in the round-2 report):

- Creating ``security.vulnerability`` Subjects (K-B1-4) needs its own claims
  node; a Procedure has one terminal per path, so it is a second Procedure
  (``security.osv-vulnerabilities``) on the same fetch + derive, run first, or a
  core change that lets a claims node create the value's Subject.
- ``expect`` must be the components OSV answered in full (the derived
  document's ``queried``), not every inventoried component, so a "not checked"
  component (K-B1-6) never retires. Today ``expect`` names a read's rows.
"""

from __future__ import annotations

from typing import Any

from definitions import VULN, refs
from inventory import COMPONENT, OSV_MATCH_KIND, OSV_SOURCE

OSV_PROCEDURE = "security.osv-query"
OSV_LINE = "security.osv-query"
OSV_COMPONENTS = "security.osv_components"
OSV_ROW = "security.osv-affected"
#: TODO(core lane A): the fetched list's member kind (one OSV response each).
OSV_RESPONSE_KIND = "security.osv-response"


def osv_spec() -> dict[str, Any]:
    """DRAFT spec. Do not author until core lanes A + B land."""

    return refs(
        {
            "procedure": OSV_PROCEDURE,
            "description": "Ask OSV about every inventoried component and write which "
            "vulnerabilities OSV lists for its exact purl@version.",
            "input": {},
            "output": {},
            "params": {"logical_source": 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'},
            "slots": {
                "query": {
                    "in": "osv.query.request@1",
                    "out": "osv.query.result@1",
                    "effect": "external_read",
                },
                "match": {
                    "in": "osv.match.request@1",
                    "out": "osv.match.result@1",
                    "effect": "pure",
                },
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
                    # TODO(core lane A, a1): binds the list<capture<*>> field.
                    "captures": {"responses": OSV_RESPONSE_KIND},
                    "input": {
                        "components": "$steps.components.rows[*].purl",
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "call": "matched",
                    "slot": "match",
                    # TODO(core lane B, c5): the derived kind the kit declares.
                    "captures": {"document": OSV_MATCH_KIND},
                    "input": {
                        "responses": "$steps.osv.responses",
                        "components": "$steps.components.rows[*].purl",
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "extract": "affected",
                    "capture": "$steps.matched.document",
                    "records": "/affected/*",
                    "row": f"{OSV_ROW}@1",
                    "key": {
                        "purl": {"at": "purl", "type": f"key_part<{COMPONENT}:purl>"},
                        "cve_id": {"at": "cve_id", "type": f"key_part<{VULN}:cve_id>"},
                    },
                    "fields": {"osv_id": {"at": "osv_id"}},
                },
                {
                    "id": "write",
                    "for_each": "$steps.affected.records",
                    "subject": {
                        "kind": COMPONENT,
                        "key": {"purl": "$item.key.purl"},
                        "create": "never",
                    },
                    # TODO(core): expect = the document's `queried` components only (K-B1-6).
                    "expect": "$steps.components.rows",
                    "claims": [
                        {
                            "type": COMPONENT + ".affected_by",
                            "value": {"kind": VULN, "key": {"cve_id": "$item.key.cve_id"}},
                            "when_absent": "mirror",
                            "rationale": "OSV {$item.fields.osv_id} lists {$item.key.cve_id} "
                            "for {$item.key.purl}.",
                        }
                    ],
                },
            ],
        }
    )


#: K-B1-4: the osv Line settles affected_by create/revise/retire on extracted and
#: absence bases, and may create security.vulnerability Subjects.
OSV_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    COMPONENT + ".affected_by": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    },
}
OSV_LINE_DRAFT: dict[str, Any] = {
    "kind": "line",
    "name": OSV_LINE,
    "procedure_name": OSV_PROCEDURE,
    "bindings": {
        "query": "security-osv-provider#osv.query",
        "match": "security-osv-provider#osv.match",
    },
    "parameters": {"logical_source": OSV_SOURCE},
    "acquisition": {"osv.responses": {"origins": ["https://api.osv.dev"]}},
    "max_authority": "settle",
}
