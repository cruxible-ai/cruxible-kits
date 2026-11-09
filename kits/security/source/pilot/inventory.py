"""The security kit's inventory: SBOM import, the occurrence pair and the judgment pairs (D-R37).

Everything is in the Procedure template form (D-R37): read -> fetch ->
derive* -> extract -> claims, with filter/dedupe narrowing and inbox egress.

The model (D-R43, D-R46): a plain relationship is a link; a relationship with
facts of its own is a pair Subject keyed by its ends.

- ``security.component`` is a global package release, keyed by its purl.
- ``security.occurrence`` (inventory, component) is the component's place in
  one inventory. Its ``scope`` (CycloneDX's scope, default ``required``) is
  the membership fact (R3): live while the inventory's SBOM lists the
  component, retired when it no longer does. The occurrence itself stays as
  history, and a relisted component lands on it again.
- ``security.exposure`` (component, vulnerability) holds a package-level VEX
  justification (``vulnerable_code_not_present``), stated beside the global
  "affected_by none of V"; ``security.app_exposure`` (occurrence,
  vulnerability) holds the four app-level ones, for one inventory only (R4).
  Both are created only by an agent's judgment write (``triage.py``).

- ``security.sbom-import`` reads a CycloneDX JSON SBOM through core's builtin
  ``workspace.file`` (one Capture per file); the pure derive ``sbom.components``
  (security-osv-provider) emits the inventory as a header (the SBOM's own
  ``metadata.component`` purl, K-B1-5, K-B1-G1, or, without one, the file path
  plus ``warning: sbom_unnamed``) and one record per component with its scope.
  The claims step's row is the occurrence: both ends are nested templates
  created if absent, so one run creates the inventory, its components and
  their occurrences, ends first, and writes each occurrence's ``scope``.
  ``expect: {by: inventory, ends: [header]}`` judges absence by the inventory
  alone: core finds the inventory's current occurrences from its pair index,
  and a component the complete SBOM no longer lists has its scope retired
  (``when_absent: mirror``) with the complete read as its witness. One
  Procedure; one Line per SBOM file, naming nothing about the SBOM but its path.
- ``security.component.affected_by`` is OSV's word (K-B1-3): the vulnerabilities
  OSV lists for the exact purl@version (``osv.py``). An agent's package-level
  not_affected judgment is the declared inverse on its unit, "none of V"
  (K-B2-J1), with its typed VEX reason on the exposure pair.
- Applicability is a Query join (K-B1-2): vulnerability <- component.affected_by
  <- an occurrence holding a scope -> inventory.

Distro coverage (K-B1-6): OSV's distro ecosystems (Debian, Ubuntu, Alpine, the
RPM distributions) are keyed by SOURCE package name, while an SBOM lists
binary packages (libc6, libssl3). The OSV query leaves any distro component it
cannot match by source-package name out of its ``queried`` list: such a
component reads "not checked" (no affected_by, never clean), and absence never
retires its Claims. Post-v1: map binary to source packages (syft sourceName,
or a distro name table).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from cruxible_client.contracts.authoring.inputs import ProcedureInput
from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input
from definitions import VULN, refs

INVENTORY = "security.inventory"
COMPONENT = "security.component"
#: The pair (inventory, component): a component's place in one inventory (R3).
OCCURRENCE = "security.occurrence"
#: The pair (component, vulnerability): a package-level judgment (R4).
EXPOSURE = "security.exposure"
#: The pair (occurrence, vulnerability): an app-level judgment, one inventory (R4).
APP_EXPOSURE = "security.app_exposure"
SBOM_KIND = "security.cyclonedx-sbom"
#: The derived Capture sbom.components emits (D-R37 derive; c5: the kit declares it).
SBOM_COMPONENTS_KIND = "security.sbom-components"
#: The derived Capture osv.match emits.
OSV_MATCH_KIND = "security.osv-matches"
SBOM_SOURCE = "cyclonedx.sbom"
OSV_SOURCE = "osv.dev.query"
SBOM_ROW = "security.sbom-component"
#: One inventory's current components (its occurrences holding a scope).
INVENTORY_COMPONENTS = "security.inventory_components"
INVENTORY_COMPONENT_ROW = "security.inventory-component"
SBOM_PROCEDURE = "security.sbom-import"
SBOM_LINE = "security.sbom-import"
WORKSPACE_FILE = "cruxible-builtin#workspace.file"
#: The kit's dependency-plane provider (sbom.components, osv.query, osv.match).
DEPENDENCY_PROVIDER = "security-osv-provider"
SBOM_COMPONENTS = f"{DEPENDENCY_PROVIDER}#sbom.components"
SCOPE = OCCURRENCE + ".scope"
#: CycloneDX's component scopes; ``required`` is the specification's default.
SCOPES = ("required", "optional", "excluded")
#: The VEX justification a package-level judgment states (R4): the vulnerable
#: code is not in the package at all, so it holds for every inventory.
PACKAGE_JUSTIFICATIONS = ("vulnerable_code_not_present",)
#: The VEX justifications an app-level judgment states (R4): they depend on how
#: one inventory uses the component.
APP_JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
#: Each pair kind's parts, in key order: (part, end kind).
PAIR_PARTS: dict[str, tuple[tuple[str, str], ...]] = {
    OCCURRENCE: (("inventory", INVENTORY), ("component", COMPONENT)),
    EXPOSURE: (("component", COMPONENT), ("vulnerability", VULN)),
    APP_EXPOSURE: (("occurrence", OCCURRENCE), ("vulnerability", VULN)),
}

_PATH = 'string{max_len: 256, pattern: "^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,255}$"}'
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_INVENTORY_ID = "string{min_len: 1, max_len: 256}"


# -- 1. CaptureKinds ------------------------------------------------------------------


def _json_kind(
    name: str, *, shape: str, grade: str, max_bytes: int, depth: int, records: int
) -> dict[str, Any]:
    return {
        "name": name,
        "shape": shape,
        "grade": grade,
        "retention": "P400D",
        "erasable": False,
        "max_bytes": max_bytes,
        "selector_privacy": "direct_allowed",
        "decoding": {
            "format": "json",
            "encoding": "identity",
            "limits": {"decoded_bytes": max_bytes, "depth": depth, "records": records},
        },
    }


def capture_kinds() -> dict[str, dict[str, Any]]:
    """The SBOM file's kind (the file's bytes verbatim, decoded as JSON) and the two
    derived kinds the dependency plane emits (sbom.components, osv.match).

    A derived kind takes the ``http_response`` shape: a provider derive returns
    its document as external Capture wire, which ``procedure_output`` does not
    admit (e2).
    """

    return {
        SBOM_KIND: _json_kind(
            SBOM_KIND,
            shape="http_response",
            grade="observed",
            max_bytes=1024 * 1024,
            depth=32,
            records=20_000,
        ),
        SBOM_COMPONENTS_KIND: _json_kind(
            SBOM_COMPONENTS_KIND,
            shape="http_response",
            grade="derived",
            max_bytes=4 * 1024 * 1024,
            depth=8,
            records=20_000,
        ),
        OSV_MATCH_KIND: _json_kind(
            OSV_MATCH_KIND,
            shape="http_response",
            grade="derived",
            max_bytes=4 * 1024 * 1024,
            depth=16,
            records=100_000,
        ),
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
_MANY = {"cardinality": "many", "eligible_verdicts": ["supported"], "selector": "all"}

_PART_DESCRIPTIONS = {
    (OCCURRENCE, "inventory"): "The inventory this occurrence is in; a key part.",
    (OCCURRENCE, "component"): "The component this occurrence places in its inventory; a key part.",
    (EXPOSURE, "component"): "The component (package release) judged; a key part.",
    (EXPOSURE, "vulnerability"): "The vulnerability judged; a key part.",
    (APP_EXPOSURE, "occurrence"): "The occurrence (one inventory's component) judged; a key part.",
    (APP_EXPOSURE, "vulnerability"): "The vulnerability judged; a key part.",
}


def _key_part(pair: str, part: str, end: str) -> dict[str, Any]:
    """A Subject-valued key part: one end of a pair, frozen for the pair's life."""

    return {
        "predicate": f"{pair}.{part}",
        "allowed_subject_kinds": [pair],
        "cardinality": "one",
        "value": {"kind": "subject", "subject_kinds": [end]},
        "description": _PART_DESCRIPTIONS[(pair, part)],
    }


def _file_rule(roles: Sequence[str]) -> dict[str, Any]:
    """A workspace-file/section receipt rule (``file``): any catalogued workspace file.

    The family selector (D1) admits a Capture under any accepted foreign-source
    contract of a catalogued file, so a judgment citing the code it read drifts
    when that code changes.
    """

    return {
        "rule_id": "file",
        "claim_roles": list(roles),
        "capture_contract_families": ["workspace_file"],
        "admission": "direct",
        "subject_binding": "exact_claim_subject",
    }


def _justification(pair: str, members: Sequence[str], description: str) -> dict[str, Any]:
    """An agent's VEX justification on a judgment pair: normative, never a Mandate's
    (no Line writes it). It cites the code read (a catalogued workspace file or a
    section of one) or the agent's own words."""

    return {
        "predicate": f"{pair}.justification",
        "allowed_subject_kinds": [pair],
        "cardinality": "one",
        "value": {"kind": "enum", "members": list(members)},
        "description": description,
        "permitted_roles": ["normative"],
        "default_role": "normative",
        "evidence_requirement": "self",
        "revision_evidence": "replace",
        # Rules sorted by rule_id: the cited code (file), or own words (self).
        "evidence_admission_policy": {
            "rules": [_file_rule(["normative"]), _rule("self", ["normative"], SELF_SOURCE)]
        },
    }


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
            "predicate": COMPONENT + ".purl",
            "allowed_subject_kinds": [COMPONENT],
            "cardinality": "one",
            "value": {"kind": "string", "max_len": 256},
            "description": "The component's package URL with its version (qualifiers dropped); "
            "the component's key.",
        },
        {
            "predicate": COMPONENT + ".affected_by",
            "allowed_subject_kinds": [COMPONENT],
            "cardinality": "many",
            "value": {"kind": "subject", "subject_kinds": [VULN]},
            "description": "A vulnerability OSV lists for the component's exact purl@version "
            "(OSV's own version matching). None of V is an agent's package-level not_affected "
            "judgment (normative, own words), which OSV cannot override.",
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
            "resolution_policy": _MANY,
            # K-B2-J1: "affected_by none of V" is the judgment, on V's own unit.
            "inverse": {"key": {"kind": "object"}, "evidence_rules": ["self"]},
        },
        *(_key_part(pair, part, end) for pair, parts in PAIR_PARTS.items() for part, end in parts),
        {
            "predicate": SCOPE,
            "allowed_subject_kinds": [OCCURRENCE],
            "cardinality": "one",
            "value": {"kind": "enum", "members": list(SCOPES)},
            "description": "The component's CycloneDX scope in this inventory's SBOM (required "
            "when the SBOM states none). The membership fact: live while the SBOM lists the "
            "component, retired when it no longer does.",
            "permitted_roles": ["observation"],
            "default_role": "observation",
            "evidence_requirement": "captured",
            "revision_evidence": "replace",
            "evidence_admission_policy": {
                "rules": [_rule("sbom", ["observation"], SBOM_COMPONENTS_KIND)]
            },
        },
        _justification(
            EXPOSURE,
            PACKAGE_JUSTIFICATIONS,
            "The VEX justification of an agent's package-level not_affected judgment, stated "
            "with affected_by none of the vulnerability on the component: the vulnerable code "
            "is not in this package release, for every inventory.",
        ),
        _justification(
            APP_EXPOSURE,
            APP_JUSTIFICATIONS,
            "The VEX justification of an agent's app-level not_affected judgment: why this "
            "inventory's use of the component is not affected. It silences this occurrence "
            "only and never states the global none.",
        ),
    ]


def claim_types() -> list[Any]:
    return [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]


_KIND_DESCRIPTIONS = {
    OCCURRENCE: "A component's place in one inventory, keyed by (inventory, component); its "
    "scope is the membership fact.",
    EXPOSURE: "A (component, vulnerability) pair an agent judged at package level, keyed by "
    "its ends.",
    APP_EXPOSURE: "An (occurrence, vulnerability) pair an agent judged for one inventory, "
    "keyed by its ends.",
}


def subject_kind_members() -> list[dict[str, Any]]:
    """The inventory, the component and the three pair kinds (each ``unique``, R6)."""

    return [
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
        *(
            {
                "kind": "subject_kind",
                "name": pair,
                "description": _KIND_DESCRIPTIONS[pair],
                "keys": [f"{pair}.{part}" for part, _end in parts],
                "uniqueness": "unique",
            }
            for pair, parts in PAIR_PARTS.items()
        ),
    ]


#: An inventory's current components: its occurrences holding a visible scope,
#: found from the pair index by that one end (S4), so the read costs this
#: inventory's current occurrences, never another inventory's or history.
INVENTORY_COMPONENTS_SPEC: dict[str, Any] = {
    "query": INVENTORY_COMPONENTS,
    "description": "One inventory's current components: each occurrence holding a scope, "
    "with the component's purl and its scope.",
    "params": {"inventory": "subject"},
    "from": {"i": f"{INVENTORY} = $inventory"},
    "hops": [
        {"o": f"{OCCURRENCE}{{inventory: i}}! with scope"},
        {"c": f"o.{OCCURRENCE}.component!: {COMPONENT}"},
    ],
    "row": f"{INVENTORY_COMPONENT_ROW}@1",
    "fields": [{"occurrence": "o.subject_id"}, "c.purl", "o.scope"],
    "order": ["c.purl"],
}


def vocabulary_members() -> list[dict[str, Any]]:
    """The row Contracts, the ClaimTypes, the SubjectKinds and the inventory Query."""

    return [
        {
            "kind": "contract",
            "name": SBOM_ROW,
            "version": 1,
            "description": "One component sbom.components read from an SBOM, with its scope.",
            "fields": {
                "name": "string{max_len: 256}?",
                "scope": f"enum_of {SCOPE}",
                "named_by": "enum[metadata_component, file_path]",
                "warning": "enum[sbom_unnamed]?",
            },
        },
        *(
            {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
            for t in claim_types()
        ),
        *subject_kind_members(),
        {
            "kind": "contract",
            "name": INVENTORY_COMPONENT_ROW,
            "version": 1,
            "description": "One current component of an inventory: its occurrence, purl and scope.",
            "fields": {
                "occurrence": "string",
                "purl": "string{max_len: 256}",
                "scope": f"enum_of {SCOPE}",
            },
        },
        {"kind": "query_definition", "query_definition": INVENTORY_COMPONENTS_SPEC},
    ]


# -- 3. Procedure ----------------------------------------------------------------------


_SLOTS = {
    "read": {
        "in": "workspace.file.request@1",
        "out": "workspace.file.result@1",
        "effect": "pure",
    },
    "derive": {
        "in": "sbom.components.request@1",
        "out": "sbom.components.result@1",
        "effect": "pure",
    },
}
_CAPS = {
    "wall_clock": "PT2M",
    "provider_calls": 2,
    "capture_bytes": 8 * 1024 * 1024,
    "items": 40_000,
    "read_rows": 20_000,
    "repeat_attempts": 1,
}
_PARAMS = {"relative_path": _PATH, "logical_source": _SOURCE}
_PATH_REF = "$params.relative_path"
_INVENTORY_REF = "$steps.listed.header.inventory"


def sbom_spec() -> dict[str, Any]:
    """``security.sbom-import``: each listed component's occurrence in the SBOM's inventory.

    fetch (workspace.file) -> derive (sbom.components: the inventory as a
    header, one record per component with its scope) -> extract
    ``/components/*`` -> claims: the occurrence (inventory, component), both
    ends created by key if absent, and its ``scope``. Absence is judged by the
    inventory (``expect: {by: inventory}``): a component the complete SBOM no
    longer lists has its occurrence's scope retired (``when_absent: mirror``).
    """

    return refs(
        {
            "procedure": SBOM_PROCEDURE,
            "description": "Read one CycloneDX JSON SBOM from the workspace and write each "
            "component's occurrence in the inventory it describes, with its scope; a "
            "component the SBOM no longer lists has its scope retired.",
            "input": {},
            "output": {},
            "params": _PARAMS,
            "slots": _SLOTS,
            "hard_caps": _CAPS,
            "steps": [
                {
                    "call": "sbom",
                    "slot": "read",
                    "captures": {"capture": SBOM_KIND},
                    "input": {
                        "logical_source": "$params.logical_source",
                        "relative_path": _PATH_REF,
                    },
                },
                {
                    "call": "derived",
                    "slot": "derive",
                    "captures": {"document": SBOM_COMPONENTS_KIND},
                    "input": {
                        "sbom": "$steps.sbom.capture",
                        "relative_path": _PATH_REF,
                        "logical_source": "$params.logical_source",
                    },
                },
                {
                    "extract": "listed",
                    "capture": "$steps.derived.document",
                    "records": "/components/*",
                    "row": f"{SBOM_ROW}@1",
                    "key": {"purl": {"at": "purl", "type": f"key_part<{COMPONENT}:purl>"}},
                    "duplicates": "refuse_key",
                    "complete_when": {"count_at": "/count"},
                    "fields": {
                        "name": {"at": "name", "presence": "optional"},
                        "scope": {"at": "scope", "canonicalize": "claim_type"},
                        "named_by": {"at": "named_by"},
                        "warning": {"at": "warning", "presence": "optional"},
                    },
                    "header": {
                        "inventory": {"at": "/inventory", "type": _INVENTORY_ID},
                    },
                },
                {
                    "id": "write",
                    "for_each": "$steps.listed.records",
                    "subject": {
                        "kind": OCCURRENCE,
                        "key": {
                            "inventory": {
                                "kind": INVENTORY,
                                "key": {"inventory_id": _INVENTORY_REF},
                                "create": "if_absent",
                            },
                            "component": {
                                "kind": COMPONENT,
                                "key": {"purl": "$item.key.purl"},
                                "create": "if_absent",
                            },
                        },
                        "create": "if_absent",
                    },
                    # Absence by one end: this inventory's current occurrences.
                    "expect": {"by": "inventory", "ends": [_INVENTORY_REF]},
                    "claims": [
                        {
                            "type": SCOPE,
                            "value": "$item.fields.scope",
                            "when_absent": "mirror",
                            "rationale": "The SBOM at {$params.relative_path} lists "
                            "{$item.key.purl} with scope {$item.fields.scope} (inventory "
                            "{$steps.listed.header.inventory}, named by "
                            "{$item.fields.named_by}).",
                        }
                    ],
                },
            ],
        }
    )


def procedure_members() -> list[dict[str, Any]]:
    members = [{"kind": "procedure", "spec": sbom_spec()}]
    for member in members:
        ProcedureInput.model_validate(member)
    return members


# -- 4. Automation ----------------------------------------------------------------------

#: The import settles each occurrence's scope on the extracted record and retires
#: it on absence, creating components, inventories and occurrences (G4).
SBOM_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    SCOPE: {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    },
}


#: The findings an SBOM import Line routes to its inbox (D-R10). Not
#: ``claim_not_in_source``: a finding of the run report only (another logical
#: source's scope on a candidate occurrence, D-R18).
SBOM_FINDINGS = ("extract_refused", "duplicate_key", "incomplete_source", "slot_contested")


def sbom_line_name(suffix: str) -> str:
    return f"{SBOM_LINE}.{suffix}"


def sbom_automation(
    sboms: Sequence[tuple[str, str]], *, now: datetime, findings: Sequence[str] = SBOM_FINDINGS
) -> list[dict[str, Any]]:
    """One Line per SBOM file, (line suffix, workspace path) each. The Line names
    only the file: the inventory comes from the SBOM itself (K-B1-G1).

    Each SBOM's Line reads under its own logical source (``cyclonedx.sbom.<suffix>``)
    and judges absence by its own inventory only, so dropping a component from
    one SBOM never touches its occurrence in another inventory. (``workspace.file``
    reads one path, and a Line run takes no per-run input before R-ON5, so one
    Line per file is the v1 form; D-R41 globs are optional.)
    """

    valid_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    members: list[dict[str, Any]] = []
    for suffix, path in sboms:
        line = sbom_line_name(suffix)
        members += [
            {
                "kind": "line",
                "name": line,
                "procedure_name": SBOM_PROCEDURE,
                "bindings": {"read": WORKSPACE_FILE, "derive": SBOM_COMPONENTS},
                "parameters": {"relative_path": path, "logical_source": f"{SBOM_SOURCE}.{suffix}"},
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
                "subject_creation": [COMPONENT, INVENTORY, OCCURRENCE],
                "scope": [
                    {"claim_type": claim_type, "changes": changes}
                    for claim_type, changes in SBOM_SETTLE_SCOPE.items()
                ],
            },
        ]
    return members
