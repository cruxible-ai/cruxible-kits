"""The kit's four capabilities, their Contracts, and the offline rendering providers copy.

A Procedure slot names a capability (``{capability: security.osv.match@1}``), never
a Contract pair. The kit owns four, under its own prefix; the file read
(``workspace.file@1``) and the web fetches (``web.fetch@1``, ``web.fetch.pages@1``)
are the base kit's, which the kit requires and never carries:

| Capability | Effect | Request -> result |
|---|---|---|
| ``security.osv.query@2`` | external_read | components (+ distro packages by OSV source package) -> OSV's responses, ``list<capture<security.osv-response>>`` (``@1``, without distro packages, stays as its predecessor) |
| ``security.osv.match@1`` | pure | responses + components -> ``capture<security.osv-matches>`` |
| ``security.sbom.components@1`` | pure | ``capture<security.cyclonedx-sbom>`` -> ``capture<security.sbom-components>`` |
| ``security.sarif.findings@1`` | pure | ``list<capture<security.sarif-log>>`` + held findings -> ``capture<security.sarif-findings>`` |

A derived result names its kind, whose layout (``definitions.capture_kinds``) is
the document's declared shape; an operation that serves the capability must
carry a copy of that layout covering the instance's. ``provider_shapes`` renders
exactly what the kit authors (the Contracts with their nested pins, the kinds
with their row pins), so the kit's provider packages carry byte-for-byte copies
(``../providers/build_registrations.py``).

Also here: two Contracts a capability or a layout names that no Procedure step
types, ``security.osv-not-checked`` (the OSV match document's ``not_checked``
records) and ``security.sarif-held-finding`` (one held finding, the SARIF
derive's input and the held-findings Query's row).
"""

from __future__ import annotations

import functools
from collections.abc import Iterable, Mapping
from typing import Any

_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'
_REPO = 'string{pattern: "^[a-z0-9.-]+/[^/\\\\s]+/[^/\\\\s]+$", max_len: 256}'
_PURLS = "list<string{max_len: 256}>{max_items: 20000}"

OSV_QUERY = "security.osv.query"
OSV_MATCH = "security.osv.match"
SBOM_COMPONENTS = "security.sbom.components"
SARIF_FINDINGS = "security.sarif.findings"
OSV_NOT_CHECKED_ROW = "security.osv-not-checked"
HELD_ROW = "security.sarif-held-finding"
#: The base kit's capabilities the kit's slots name (required, never carried).
WORKSPACE_FILE = "workspace.file"
WEB_FETCH = "web.fetch"
WEB_FETCH_PAGES = "web.fetch.pages"


def capability(name: str, version: int = 1) -> str:
    """A slot's capability pin as authored: ``name@N``."""

    return f"{name}@{version}"


#: In dependency order: a Contract names only Contracts above it (or accepted earlier).
CONTRACTS: tuple[dict[str, Any], ...] = (
    {
        "kind": "contract",
        "name": OSV_NOT_CHECKED_ROW,
        "version": 1,
        "description": "One component the OSV match left unchecked, and why: a distro package "
        "whose source name OSV cannot be asked by, a component with no version, a batch that "
        "failed or was truncated, an advisory that could not be read, or a component never "
        "asked.",
        "fields": {
            "reason": 'enum["advisory_unreadable", "batch_failed", "distro_source_name_unknown", '
            '"no_version", "not_asked", "truncated"]'
        },
    },
    {
        "kind": "contract",
        "name": HELD_ROW,
        "version": 1,
        "description": "One finding the instance holds for the repository: its Subject, its key "
        "parts, its verification and the rules that reported it (tool:ruleId).",
        "fields": {
            "locus": "string{max_len: 256}",
            "rules": "list<string{max_len: 256}>{max_items: 64}?",
            "subject_id": "string{max_len: 256}",
            "subject_kind": "string{max_len: 64}",
            "verification": "string{max_len: 16}?",
            "weakness": "string{max_len: 256}",
        },
    },
    {
        "kind": "contract",
        "name": OSV_QUERY + ".request",
        "version": 1,
        "description": "The components to ask OSV about, as purl@version, and the logical "
        "source the responses are stated under. Distro packages (purl types deb, rpm, apk) are "
        "never asked and never in queried: OSV keys distro ecosystems by source package name, "
        "which an SBOM's binary packages do not give; they read not checked.",
        "fields": {"components": _PURLS, "logical_source": _SOURCE},
    },
    # Version 2 adds the distro packages the SBOM import resolved to OSV source packages
    # (security.osv_distro_packages); version 1 stays as its predecessor.
    {
        "kind": "contract",
        "name": OSV_QUERY + ".request",
        "version": 2,
        "description": "The components to ask OSV about, as purl@version, the logical source "
        "the responses are stated under, and the distro packages (purl types deb, rpm, apk) "
        "the SBOM import resolved to an OSV source package. A distro component is asked by "
        "that package (ecosystem, source name, version); one without it is never asked, never "
        "in queried, and reads not checked.",
        "fields": {
            "components": _PURLS,
            "logical_source": _SOURCE,
            "distro_purls": {
                "type": f"{_PURLS}?",
                "description": "The distro components that have an OSV package, one per "
                "distro_packages entry, in the same order.",
            },
            "distro_packages": {
                "type": "list<string{max_len: 256}>{max_items: 20000}?",
                "description": "ECOSYSTEM|NAME|VERSION for each distro_purls entry "
                "(security.occurrence.osv_package). A purl given two different packages is "
                "never asked.",
            },
        },
    },
    {
        "kind": "contract",
        "name": OSV_QUERY + ".result",
        "version": 1,
        "description": "OSV's responses as canonical JSON (sorted keys, no spaces; a body that is not JSON "
        "stays verbatim), one Capture each: every POST /v1/querybatch "
        "(at most 1000 components) and every GET /v1/vulns/{id} a batch names. A request that "
        "got no response at all is left out and the call is marked incomplete; a response with "
        "an error status is still a member.",
        "fields": {"responses": "list<capture<security.osv-response>>{max_items: 1020}"},
    },
    {
        "kind": "contract",
        "name": OSV_MATCH + ".request",
        "version": 1,
        "description": "This run's OSV responses (their Capture bytes, passed by core), the "
        "components the run asked about, and the logical source the derived document is "
        "stated under.",
        "fields": {
            "components": _PURLS,
            "logical_source": _SOURCE,
            "responses": "list<capture<security.osv-response>>{max_items: 1020}",
        },
    },
    {
        "kind": "contract",
        "name": OSV_MATCH + ".result",
        "version": 1,
        "description": "One derived JSON document of (component, CVE) matches, in the layout of "
        "CaptureKind security.osv-matches: queried (the components OSV answered in full), "
        "not_checked (each with why), affected (purl, cve_id, osv_id, and the versions OSV "
        "lists as fixed), count, and unkeyed (advisories with no CVE alias).",
        "fields": {"document": "capture<security.osv-matches>"},
    },
    {
        "kind": "contract",
        "name": SBOM_COMPONENTS + ".request",
        "version": 1,
        "description": "One CycloneDX JSON SBOM this run read (its Capture bytes, passed by "
        "core), its workspace path (the inventory's name when the SBOM has no "
        "metadata.component purl) and the logical source the derived document is stated "
        "under.",
        "fields": {
            "logical_source": _SOURCE,
            "relative_path": "string{max_len: 256}",
            "sbom": "capture<security.cyclonedx-sbom>",
        },
    },
    {
        "kind": "contract",
        "name": SBOM_COMPONENTS + ".result",
        "version": 1,
        "description": "One derived JSON document in the layout of CaptureKind "
        "security.sbom-components: the inventory the SBOM describes, how it was named, and one "
        "record per distinct purl with its scope; count is every component the SBOM lists, "
        "unidentified ones included.",
        "fields": {"document": "capture<security.sbom-components>"},
    },
    {
        "kind": "contract",
        "name": SARIF_FINDINGS + ".request",
        "version": 1,
        "description": "This run's SARIF logs (their Capture bytes, passed by core), the "
        "findings the instance holds for the repository, the repository (host/owner/repo) and "
        "the logical source the derived document is stated under.",
        "fields": {
            "held": f"list<{HELD_ROW}@1>{{max_items: 20000}}",
            "logical_source": _SOURCE,
            "logs": "list<capture<security.sarif-log>>{max_items: 16}",
            "repo": _REPO,
        },
    },
    {
        "kind": "contract",
        "name": SARIF_FINDINGS + ".result",
        "version": 1,
        "description": "One derived JSON document in the layout of CaptureKind "
        "security.sarif-findings: covered (the held findings a full run's rules cover: the "
        "Claims' expect), findings by repository, weakness and locus with their verification, "
        "count, and attention records (regressions and location gaps). It also states the "
        "rules that ran, whether every run was full, the tainted rules and tools, and the "
        "dependency advisories routed to the SBOM loop.",
        "fields": {"document": "capture<security.sarif-findings>"},
    },
)

CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "kind": "capability",
        "name": OSV_QUERY,
        "version": 1,
        "description": "Asks OSV.dev which advisories affect each component (purl@version) and "
        "returns every response as canonical JSON, one Capture each. OSV does the version "
        "matching; "
        "distro packages are never asked.",
        "effect": "external_read",
        "in": OSV_QUERY + ".request@1",
        "out": OSV_QUERY + ".result@1",
    },
    {
        "kind": "capability",
        "name": OSV_QUERY,
        "version": 2,
        "description": "Asks OSV.dev which advisories affect each component (purl@version), "
        "and each distro package (deb, rpm, apk) by the OSV source package its SBOM states "
        "(Debian:12 glibc, Alpine:v3.19 openssl, ...), and returns every response as canonical "
        "JSON, one Capture each. OSV does the version matching; a distro package with no "
        "source package is never asked.",
        "effect": "external_read",
        "in": OSV_QUERY + ".request@2",
        "out": OSV_QUERY + ".result@1",
    },
    {
        "kind": "capability",
        "name": OSV_MATCH,
        "version": 1,
        "description": "Matches this run's OSV responses to the components asked about and "
        "returns one document of (component, CVE) pairs, each with its advisory and the "
        "versions OSV lists as fixed. A component OSV did not answer in full is not in "
        "queried, is listed in not_checked with why, and is never clean.",
        "effect": "pure",
        "in": OSV_MATCH + ".request@1",
        "out": OSV_MATCH + ".result@1",
    },
    {
        "kind": "capability",
        "name": SBOM_COMPONENTS,
        "version": 1,
        "description": "Reads one CycloneDX JSON SBOM and returns one document naming the "
        "inventory it describes and each distinct component by purl, with its scope. A "
        "component with no purl is counted but never listed, so the count marks the listing "
        "incomplete and absence retires nothing.",
        "effect": "pure",
        "in": SBOM_COMPONENTS + ".request@1",
        "out": SBOM_COMPONENTS + ".result@1",
    },
    {
        "kind": "capability",
        "name": SARIF_FINDINGS,
        "version": 1,
        "description": "Reads this run's SARIF 2.1.0 logs for one repository, with the findings "
        "the instance holds for it, and returns one document of findings keyed by repository, "
        "weakness and locus, each present or fixed, plus attention records for regressions and "
        "results it could not place. Only a full run (every invocation succeeded and the run "
        "declares cruxible.coverage full) covers a held finding, and only a covered finding "
        "the logs no longer report is fixed: a partial scan marks nothing fixed. A result it "
        "cannot key is a location gap and taints its rule, which then covers nothing in this "
        "scan. A CVE or GHSA result in a manifest or lockfile is left to the SBOM loop, never "
        "a finding.",
        "effect": "pure",
        "in": SARIF_FINDINGS + ".request@1",
        "out": SARIF_FINDINGS + ".result@1",
    },
)


def change_set() -> dict[str, Any]:
    """The capabilities and the Contracts they and the kit's layouts name, as one change set.

    Submitted after the kit's CaptureKinds (each request and result names a kind)
    and before the audit vocabulary (the held-findings Query's row is here).
    """

    return {
        "kind": "change_set",
        "rationale": "Security kit capabilities: OSV query and match, SBOM components, SARIF "
        "findings, with their request and result Contracts.",
        "members": [*CONTRACTS, *CAPABILITIES],
    }


# -- the rendering providers copy ------------------------------------------------------------


def _contract_members() -> Iterable[Mapping[str, Any]]:
    """Every Contract member the kit authors, in an order each names only earlier ones."""

    import definitions
    import findings

    yield from (m for m in definitions.vocabulary()["members"] if m["kind"] == "contract")
    yield from CONTRACTS
    yield from (m for m in findings.vocabulary()["members"] if m["kind"] == "contract")


@functools.cache
def contract_tree() -> Mapping[str, bytes]:
    """Every kit Contract and capability, rendered as an accepted tree holds them.

    The same lowering ``authoring submit`` runs (nested ``name@N`` pinned to the
    digest of the version rendered before it), with no instance: the kit's own
    definitions are the whole closure.
    """

    from cruxible_client.contracts.authoring.inputs import (
        CapabilityInput,
        ContractInput,
        lower_authoring_input,
    )
    from cruxible_core.authoring.capability_lowering import render_capability_member
    from cruxible_core.authoring.contract_lowering import render_contract_member

    tree: dict[str, bytes] = {}
    for member in _contract_members():
        payload: Any = lower_authoring_input(ContractInput.model_validate(member))
        path, content, _digest = render_contract_member(payload, tree=tree)
        tree[path] = content
    for member in CAPABILITIES:
        payload = lower_authoring_input(CapabilityInput.model_validate(member))
        path, content, _digest = render_capability_member(payload, tree=tree)
        tree[path] = content
    return tree


def contract_pin(spelling: str) -> dict[str, Any]:
    """``name@N`` as the pin ``{name, version, digest}`` of the kit's rendered version."""

    from cruxible_client.contracts.shapes import contract_digest, contract_path, parse_contract

    name, _, version = spelling.partition("@")
    path = contract_path(name, int(version))
    contract = parse_contract(contract_tree()[path], path=path)
    return {"name": name, "version": int(version), "digest": contract_digest(contract).tagged}


def pinned_layout(layout: Mapping[str, Any]) -> dict[str, Any]:
    """A layout with every record set's row ``name@N`` pinned to the kit's rendered digest."""

    return {
        **layout,
        "records": {
            name: {**item, "row": contract_pin(item["row"])}
            for name, item in layout["records"].items()
        },
    }


def provider_shapes() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """``(contracts, capture_kinds, built_against)`` a kit provider package carries.

    ``contracts``: every rendered kit Contract (the registration writer keeps
    only what the operations reach). ``capture_kinds``: every kit kind as its
    declared copy (name, decoding, pinned layout). ``built_against``: each kit
    capability by digest, and each kind with a layout by its declared copy's
    digest, the record of what the copies were made from.
    """

    import json

    import definitions
    import findings
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
    for name, record in sorted({**definitions.capture_kinds(), **findings.capture_kinds()}.items()):
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
