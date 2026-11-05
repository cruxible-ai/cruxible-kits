"""The security kit's inventory slice (batch 1): SBOM import and the OSV link.

Everything is in the Procedure template form (D-R37): read -> fetch ->
derive* -> extract -> claims, with filter/dedupe narrowing and inbox egress.

- ``security.sbom-import`` reads a CycloneDX JSON SBOM through core's builtin
  ``workspace.file`` (one Capture per file), extracts its components and writes
  each component's ``in_inventory`` membership. The inventory is named by the
  SBOM's own ``metadata.component`` purl (K-B1-5), read when the Line is
  authored (:func:`lint_sbom`); an SBOM without one falls back to its file
  path with a lint warning. A component the next import of the same file no
  longer lists retires (``when_absent: mirror``) with the complete read as its
  witness. Two Lines per SBOM: ``security.sbom-inventory.<name>`` creates the
  inventory, then ``security.sbom-import.<name>`` writes its components.
- ``security.component.affected_by`` is OSV's word (K-B1-3): the vulnerabilities
  OSV lists for the exact purl@version. Until the OSV Line is wired (core lanes
  A + B, see ``osv.py``), it is seeded by agents' own-word proposals.
- Applicability is the watch-list Query join (K-B1-2): ``definitions.py``'s
  ``security.watched_vulnerabilities`` walks vulnerability <- component.affected_by
  <- component.in_inventory -> inventory.

Distro coverage (K-B1-6): OSV's distro ecosystems (Debian, Ubuntu, Alpine, the
RPM distributions) are keyed by SOURCE package name, while an SBOM lists
binary packages (libc6, libssl3). The OSV query leaves any distro component it
cannot match by source-package name out of its ``queried`` list: such a
component reads "not checked" (no affected_by, never clean), and absence never
retires its Claims. Post-v1: map binary to source packages (syft sourceName,
or a distro name table).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any, NamedTuple

from cruxible_client.contracts.authoring.inputs import ProcedureInput
from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input

from definitions import VULN, refs

INVENTORY = "security.inventory"
COMPONENT = "security.component"
SBOM_KIND = "security.cyclonedx-sbom"
#: The derived Capture osv.match emits (D-R37 derive; c5: the kit declares it).
OSV_MATCH_KIND = "security.osv-matches"
SBOM_SOURCE = "cyclonedx.sbom"
OSV_SOURCE = "osv.dev.query"
SBOM_DOC_ROW = "security.sbom-document"
SBOM_ROW = "security.sbom-component"
HELD_ROW = "security.inventoried-component"
INVENTORY_COMPONENTS = "security.inventory_components"
SBOM_PROCEDURE = "security.sbom-import"
INVENTORY_PROCEDURE = "security.sbom-inventory"
INVENTORY_LINE = "security.sbom-inventory"
SBOM_LINE = "security.sbom-import"
WORKSPACE_FILE = "cruxible-builtin#workspace.file"

_PATH = 'string{max_len: 256, pattern: "^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}$"}'
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_INVENTORY_ID = "string{min_len: 1, max_len: 256}"


# -- 1. CaptureKinds ------------------------------------------------------------------


def capture_kinds() -> dict[str, dict[str, Any]]:
    """The SBOM file's kind (the file's bytes verbatim, decoded as JSON), and the
    derived kind osv.match will emit (declared now so affected_by can name it)."""

    return {
        OSV_MATCH_KIND: {
            "name": OSV_MATCH_KIND,
            "shape": "procedure_output",
            "grade": "derived",
            "retention": "P400D",
            "erasable": False,
            "max_bytes": 4 * 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": {
                "format": "json",
                "encoding": "identity",
                "limits": {"decoded_bytes": 4 * 1024 * 1024, "depth": 16, "records": 100_000},
            },
        },
        SBOM_KIND: {
            "name": SBOM_KIND,
            "shape": "http_response",
            "grade": "observed",
            "retention": "P400D",
            "erasable": False,
            "max_bytes": 1024 * 1024,
            "selector_privacy": "direct_allowed",
            "decoding": {
                "format": "json",
                "encoding": "identity",
                "limits": {"decoded_bytes": 1024 * 1024, "depth": 32, "records": 10_000},
            },
        },
    }


# -- 2. Vocabulary ----------------------------------------------------------------------


def _rule(rule_id: str, roles: Sequence[str], kind: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "claim_roles": list(roles),
        "capture_contracts": [kind],
        "admission": "direct",
        "subject_binding": "exact_claim_subject",
    }


SELF_SOURCE = "cruxible.coordinator-self-source-v1"


def claim_type_records() -> list[dict[str, Any]]:
    return [
        {
            "predicate": INVENTORY + ".inventory_id",
            "allowed_subject_kinds": [INVENTORY],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256},
            "description": "What one SBOM describes, named by its metadata.component purl "
            "(or, without one, by the SBOM's workspace path); the inventory's key.",
        },
        {
            "predicate": INVENTORY + ".sbom_path",
            "allowed_subject_kinds": [INVENTORY],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256},
            "description": "The workspace path of the SBOM file the inventory was imported from.",
            "permitted_roles": ["observation"],
            "default_role": "observation",
            "evidence_requirement": "captured",
            "revision_evidence": "replace",
            "evidence_admission_policy": {"rules": [_rule("sbom", ["observation"], SBOM_KIND)]},
        },
        {
            "predicate": COMPONENT + ".purl",
            "allowed_subject_kinds": [COMPONENT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256},
            "description": "The component's package URL with its version (qualifiers dropped); "
            "the component's key.",
        },
        {
            "predicate": COMPONENT + ".in_inventory",
            "allowed_subject_kinds": [COMPONENT],
            "cardinality": "many",
            "value": {"kind": "subject", "subject_kinds": [INVENTORY]},
            "description": "An inventory whose SBOM lists the component, from the SBOM file "
            "as retained.",
            "permitted_roles": ["observation"],
            "default_role": "observation",
            "evidence_requirement": "captured",
            "revision_evidence": "replace",
            "evidence_admission_policy": {"rules": [_rule("sbom", ["observation"], SBOM_KIND)]},
            "resolution_policy": {
                "cardinality": "many",
                "eligible_verdicts": ["supported"],
                "selector": "all",
            },
        },
        {
            "predicate": COMPONENT + ".affected_by",
            "allowed_subject_kinds": [COMPONENT],
            "cardinality": "many",
            "value": {"kind": "subject", "subject_kinds": [VULN]},
            "description": "A vulnerability OSV lists for the component's exact purl@version "
            "(OSV's own version matching); normative when an agent states it.",
            "permitted_roles": ["normative", "observation"],
            "default_role": "observation",
            "evidence_requirement": "self",
            "revision_evidence": "replace",
            "evidence_admission_policy": {
                "rules": [
                    _rule("osv", ["observation"], OSV_MATCH_KIND),
                    _rule("self", ["normative"], SELF_SOURCE),
                ]
            },
            "resolution_policy": {
                "cardinality": "many",
                "eligible_verdicts": ["supported"],
                "selector": "all",
            },
        },
    ]


def claim_types() -> list[Any]:
    return [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]


def vocabulary_members() -> list[dict[str, Any]]:
    """Row Contracts, ClaimTypes, the two SubjectKinds and the inventory Query."""

    return [
        {
            "kind": "contract",
            "name": SBOM_DOC_ROW,
            "version": 1,
            "description": "The SBOM's metadata: what the SBOM describes.",
            "fields": {
                "component_purl": "string{max_len: 256}?",
                "component_name": "string{max_len: 256}?",
            },
        },
        {
            "kind": "contract",
            "name": SBOM_ROW,
            "version": 1,
            "description": "One CycloneDX component the import reads.",
            "fields": {"name": "string{max_len: 256}?"},
        },
        {
            "kind": "contract",
            "name": HELD_ROW,
            "version": 1,
            "description": "One component an earlier import of this SBOM path inventoried.",
            "fields": {"subject_kind": "string", "subject_id": "string", "purl": "string"},
        },
        *(
            {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
            for t in claim_types()
        ),
        {
            "kind": "subject_kind",
            "name": INVENTORY,
            "description": "What one SBOM describes (an application, an image, an environment).",
            "keys": [INVENTORY + ".inventory_id"],
        },
        {
            "kind": "subject_kind",
            "name": COMPONENT,
            "description": "One package release, named by its purl@version (R1, R12).",
            "keys": [COMPONENT + ".purl"],
            "normalizers": {
                COMPONENT + ".purl": {
                    "normalizer": "purl-type",
                    "version": 1,
                    "identity": "package",
                }
            },
        },
        {
            "kind": "query_definition",
            "query_definition": {
                "query": INVENTORY_COMPONENTS,
                "description": "Every component an inventory imported from one SBOM path holds.",
                "params": {"path": "string"},
                "from": {"c": COMPONENT},
                "hops": [
                    {"i": f"c.{COMPONENT}.in_inventory!: {INVENTORY} where i.sbom_path == $path"}
                ],
                "row": f"{HELD_ROW}@1",
                "fields": ["c.subject_kind", "c.subject_id", "c.purl"],
            },
        },
    ]


# -- 3. Procedure ----------------------------------------------------------------------


_SLOTS = {
    "read": {
        "in": "workspace.file.request@1",
        "out": "workspace.file.result@1",
        "effect": "pure",
    }
}
_CAPS = {
    "wall_clock": "PT2M",
    "provider_calls": 1,
    "capture_bytes": 1024 * 1024,
    "items": 20_000,
    "read_rows": 20_000,
    "repeat_attempts": 1,
}
_PARAMS = {"relative_path": _PATH, "logical_source": _SOURCE, "inventory_id": _INVENTORY_ID}
_PATH_REF = "$params.relative_path"
_INVENTORY_REF = "$params.inventory_id"


def _read_sbom() -> dict[str, Any]:
    return {
        "call": "sbom",
        "slot": "read",
        "captures": {"capture": SBOM_KIND},
        "input": {"logical_source": "$params.logical_source", "relative_path": _PATH_REF},
    }


def inventory_spec() -> dict[str, Any]:
    """``security.sbom-inventory``: name the inventory one SBOM describes.

    fetch (workspace.file) -> extract ``/metadata`` -> claims: the inventory
    Subject (keyed ``$params.inventory_id``, which :func:`lint_sbom` reads from
    the SBOM's metadata.component purl) and its ``sbom_path``. It runs before
    the component import, which names this inventory (composition through
    state: a Subject-valued Claim names a live Subject).
    """

    return refs(
        {
            "procedure": INVENTORY_PROCEDURE,
            "description": "Read one CycloneDX JSON SBOM from the workspace and name the "
            "inventory it describes.",
            "input": {},
            "output": {},
            "params": _PARAMS,
            "slots": _SLOTS,
            "hard_caps": _CAPS,
            "steps": [
                _read_sbom(),
                {
                    "extract": "document",
                    "capture": "$steps.sbom.capture",
                    "records": "/metadata",
                    "row": f"{SBOM_DOC_ROW}@1",
                    "fields": {
                        "component_purl": {"at": "/component/purl", "presence": "optional"},
                        "component_name": {"at": "/component/name", "presence": "optional"},
                    },
                },
                {
                    "id": "inventory",
                    "for_each": "$steps.document.records",
                    "subject": {
                        "kind": INVENTORY,
                        "key": {"inventory_id": _INVENTORY_REF},
                        "create": "if_absent",
                    },
                    "claims": [
                        {
                            "type": INVENTORY + ".sbom_path",
                            "value": _PATH_REF,
                            "rationale": "Imported from the SBOM at {$params.relative_path}.",
                        }
                    ],
                },
            ],
        }
    )


def sbom_spec() -> dict[str, Any]:
    """``security.sbom-import``: each component's membership in the SBOM's inventory.

    read (the components this path's inventory held) -> fetch (workspace.file)
    -> extract ``/components/*`` -> claims: the component Subject, created by
    its purl, and ``in_inventory`` with ``when_absent: mirror`` over the held
    set, so a component the SBOM no longer lists retires with the complete read
    as witness.
    """

    return refs(
        {
            "procedure": SBOM_PROCEDURE,
            "description": "Read one CycloneDX JSON SBOM from the workspace and write each "
            "component's membership in its inventory; a component the SBOM no longer lists "
            "retires.",
            "input": {},
            "output": {},
            "params": _PARAMS,
            "slots": _SLOTS,
            "hard_caps": _CAPS,
            "steps": [
                {"read": "held", "query": INVENTORY_COMPONENTS, "params": {"path": _PATH_REF}},
                _read_sbom(),
                {
                    "extract": "components",
                    "capture": "$steps.sbom.capture",
                    "records": "/components/*",
                    "row": f"{SBOM_ROW}@1",
                    "key": {"purl": {"at": "purl", "type": f"key_part<{COMPONENT}:purl>"}},
                    "duplicates": "first",
                    "fields": {"name": {"at": "name", "presence": "optional"}},
                },
                {
                    "id": "write",
                    "for_each": "$steps.components.records",
                    "subject": {
                        "kind": COMPONENT,
                        "key": {"purl": "$item.key.purl"},
                        "create": "if_absent",
                    },
                    "expect": "$steps.held.rows",
                    "claims": [
                        {
                            "type": COMPONENT + ".in_inventory",
                            "value": {"kind": INVENTORY, "key": {"inventory_id": _INVENTORY_REF}},
                            "when_absent": "mirror",
                            "rationale": "The SBOM at {$params.relative_path} lists "
                            "{$item.key.purl}.",
                        }
                    ],
                },
            ],
        }
    )


def procedure_members() -> list[dict[str, Any]]:
    members = [{"kind": "procedure", "spec": spec} for spec in (inventory_spec(), sbom_spec())]
    for member in members:
        ProcedureInput.model_validate(member)
    return members


class SbomLint(NamedTuple):
    """What the authoring lint found in one SBOM file (K-B1-5): the inventory id
    its Lines name, and any warning."""

    inventory_id: str
    warnings: tuple[str, ...]


def lint_sbom(content: bytes, relative_path: str) -> SbomLint:
    """The inventory one SBOM names: its ``metadata.component`` purl, else its path.

    The fallback raises a lint warning: an SBOM without metadata.component is
    named by where it sits, so moving the file starts a new inventory.
    """

    document = json.loads(content)
    component = (document.get("metadata") or {}).get("component") or {}
    purl = component.get("purl")
    if isinstance(purl, str) and purl.strip():
        return SbomLint(purl.strip(), ())
    return SbomLint(
        relative_path,
        (
            f"cruxible.kit.security.sbom_unnamed: {relative_path} has no "
            "metadata.component purl; its inventory is named by its path, and moving "
            "the file starts a new inventory",
        ),
    )


# -- 4. Automation ----------------------------------------------------------------------

#: The import settles component memberships on the extracted record and retires
#: them on absence; the inventory Line settles the inventory's SBOM path.
SBOM_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    COMPONENT + ".in_inventory": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    },
}
INVENTORY_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    INVENTORY + ".sbom_path": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
    },
}


def sbom_line_name(suffix: str) -> str:
    return f"{SBOM_LINE}.{suffix}"


def inventory_line_name(suffix: str) -> str:
    return f"{INVENTORY_LINE}.{suffix}"


def sbom_automation(
    sboms: Sequence[tuple[str, str, str]], *, now: datetime, findings: Sequence[str]
) -> list[dict[str, Any]]:
    """Two Lines per SBOM, (line suffix, workspace path, inventory id) each: the inventory
    Line names the inventory, then the import Line writes its components. A
    capture_landing Trigger chains them (the inventory Line's Capture lands, the
    import runs); Lines are enabled by the consumer.

    Each SBOM's Lines read under their own logical source
    (``cyclonedx.sbom.<suffix>``): absence retires only Claims from the same
    logical source (D-R18), so dropping a component from one SBOM never retires
    its membership in another inventory. The inventory id comes from
    :func:`lint_sbom`.
    """

    valid_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    members: list[dict[str, Any]] = []
    for suffix, path, inventory_id in sboms:
        source = f"{SBOM_SOURCE}.{suffix}"
        for line, procedure, scope, created in (
            (
                inventory_line_name(suffix),
                INVENTORY_PROCEDURE,
                INVENTORY_SETTLE_SCOPE,
                [INVENTORY],
            ),
            (
                sbom_line_name(suffix),
                SBOM_PROCEDURE,
                SBOM_SETTLE_SCOPE,
                [COMPONENT],
            ),
        ):
            members += [
                {
                    "kind": "line",
                    "name": line,
                    "procedure_name": procedure,
                    "bindings": {"read": WORKSPACE_FILE},
                    "parameters": {
                        "relative_path": path,
                        "logical_source": source,
                        "inventory_id": inventory_id,
                    },
                    "acquisition": {},
                    "findings": {"inbox": list(findings)},
                    "max_authority": "settle",
                },
                {
                    "kind": "procedure_mandate",
                    "name": line + "-propose",
                    "line_name": line,
                    "grants": "propose",
                    "namespace": ["claims", "subjects"],
                    "valid_from": valid_from,
                    "expires_at": expires_at,
                },
                {
                    "kind": "procedure_mandate",
                    "name": line + "-settle",
                    "line_name": line,
                    "grants": "settle",
                    "namespace": ["claims"],
                    "valid_from": valid_from,
                    "expires_at": expires_at,
                    "subject_creation": created,
                    "scope": [
                        {"claim_type": claim_type, "changes": changes}
                        for claim_type, changes in scope.items()
                    ],
                },
            ]
        members.append(
            {
                "kind": "trigger",
                "name": f"security.sbom-landed.{suffix}",
                "line_name": sbom_line_name(suffix),
                "schedule": {
                    "kind": "capture_landing",
                    "capture_contract": SBOM_KIND,
                    "logical_sources": [source],
                },
            }
        )
    return members
