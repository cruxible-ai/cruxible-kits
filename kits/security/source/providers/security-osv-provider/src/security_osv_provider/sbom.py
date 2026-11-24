"""``sbom.components``: one CycloneDX or SPDX JSON SBOM -> one derived JSON document (pure).

**Formats.** CycloneDX JSON (``bomFormat: CycloneDX``) as before, byte for byte;
and SPDX 2.2 / 2.3 JSON (``spdxVersion`` ``SPDX-2.*`` with a ``packages`` list),
as GitHub's dependency graph export and Syft or Trivy write it. An SPDX package
is a component when it has a ``purl`` external reference (``versionInfo`` is
appended when the purl names no version); the package the document describes
(``documentDescribes`` or ``SPDXRef-DOCUMENT DESCRIBES``) names the inventory by
its purl, as ``metadata.component`` does, and is no component. Its relationships
give the scope: ``DEPENDS_ON`` / ``DEPENDENCY_OF`` (and ``RUNTIME_`` /
``PROVIDED_DEPENDENCY_OF``, ``CONTAINS``) ``required``, ``OPTIONAL_DEPENDENCY_OF``
``optional``, ``DEV_`` / ``TEST_`` / ``BUILD_DEPENDENCY_OF`` ``excluded`` (not in
the shipped runtime), the most included winning, ``required`` when none says. An
SPDX record also carries its ``supplier``. Anything else is refused.

**Distro packages** (purl types ``deb``, ``rpm``, ``apk``) carry the OSV package
they are asked as, ``osv_package`` (``ECOSYSTEM|NAME|VERSION``: the release from
the purl's ``distro`` qualifier, the source package from its ``upstream``
qualifier, Syft or Trivy properties or SPDX ``sourceInfo``; ``distro.py``), or
``osv_unmapped`` with the reason none is known; the header's ``distro`` counts
both. A document listing no distro package has no such field, so its bytes are
unchanged.

The CycloneDX form, in detail:

The SBOM import Procedure reads the SBOM file through core's builtin
``workspace.file`` (one Capture, the file's bytes verbatim). This derive reads
those bytes (passed by core) and emits ONE derived JSON document::

    {"inventory":    "<metadata.component purl, or the file path>",
     "named_by":     "metadata_component" | "file_path",
     "warning":      "sbom_unnamed"                  # only when named by path
     "components":   [{"purl", "name"?, "inventory", "named_by", "scope", "warning"?}, ...],
     "count":        len(components) + unidentified,  # what the SBOM lists
     "unidentified": N}                              # components with no purl

The inventory key is the SBOM's own ``metadata.component`` purl (K-B1-5,
K-B1-G1): one import Procedure serves every SBOM, and a new product needs only
its SBOM. An SBOM without one is named by its workspace path, and every record
carries ``warning: sbom_unnamed``: moving the file starts a new inventory.

The import's row is the occurrence (inventory, component) (D-R46 R3): the
header's ``inventory`` names one end, each record's purl the other, and the
record's ``scope`` is the occurrence's membership fact. ``scope`` is the
component's CycloneDX scope as the SBOM states it, or ``required`` (the
specification's default) when the SBOM states none. A value that is not one
of CycloneDX's three is passed through as stated, so the import's typed
extract refuses that field: the component is still listed, its occurrence keeps
the scope it held, and its siblings write.

Nested components (``components[*].components``) are flattened, depth first.
Two entries with the same purl text and scope are one record (the same
identifier listed twice); with different scopes they stay two records, so
core's ``duplicates: refuse_key`` writes nothing for that key (fail closed).
Two spellings that core's purl normalizer folds to one key also stay two
records. A component with no purl cannot be keyed: it is counted in
``unidentified`` and is never a record, but it is still in ``count`` (every
component the SBOM lists). The import declares ``complete_when: {count_at:
/count}``, so an SBOM with any unidentified component is an incomplete read:
its keyed components still write, and absence retires nothing. A held
component whose purl went missing therefore never reads as removed.

Absence is judged by the inventory (``expect: {by: inventory}``): core finds
that inventory's current occurrences itself, so the derive reads no state.

Pure: the output is a function of the SBOM bytes and the path; the result's
observation time is the SBOM Capture's own, never the clock. The operation is a
``@derive`` function (cruxible-provider-runtime 0.6): it declares ``effect: pure``
with no endpoint, receives the SBOM as a digest-checked ``CaptureView`` and writes
the document's wire with ``CaptureView.derive``, so a rebuilt build is a pure,
non-widening move (``provider install --move``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any

from cruxible_provider_runtime import CaptureView, decline, derive
from cruxible_provider_runtime.provider_api import ProviderResult

from . import distro

COMPONENTS = "sbom.components"
PROVIDER_DECLINED = "provider_declined"
#: Core's HTTP coordinate schema: a derived kind takes the http_response shape,
#: which admits only it (the coordinate names no URL: nothing was fetched).
COORDINATE_TYPE = "http-response-v1"
SELECTOR_TYPE = "whole-response-v1"
#: The most components one SBOM document may list (the Contract's bound too).
MAX_COMPONENTS = 20_000
#: The deepest component nesting the derive walks.
MAX_DEPTH = 16
UNNAMED = "sbom_unnamed"
#: CycloneDX's default scope, when a component states none.
DEFAULT_SCOPE = "required"


class SbomRefused(ValueError):
    """The bytes are not a CycloneDX JSON SBOM this derive reads."""


def _walk(components: object, depth: int = 0) -> Iterator[Mapping[str, Any]]:
    if depth > MAX_DEPTH:
        raise SbomRefused(f"components nest deeper than {MAX_DEPTH} levels")
    if components is None:
        return
    if not isinstance(components, list):
        raise SbomRefused("components is not a list")
    for component in components:
        if not isinstance(component, Mapping):
            raise SbomRefused("a component is not an object")
        yield component
        yield from _walk(component.get("components"), depth + 1)


#: The SPDX relationship types that place a package in a scope, by the package that is
#: the relationship's element (``A <TYPE> B``: A is B's dependency of that kind).
_SPDX_SCOPES: dict[str, str] = {
    "DEPENDENCY_OF": "required",
    "RUNTIME_DEPENDENCY_OF": "required",
    "PROVIDED_DEPENDENCY_OF": "required",
    "OPTIONAL_DEPENDENCY_OF": "optional",
    "DEV_DEPENDENCY_OF": "excluded",
    "TEST_DEPENDENCY_OF": "excluded",
    "BUILD_DEPENDENCY_OF": "excluded",
}
#: The relationships that place their RELATED element (``A DEPENDS_ON B``: B is required).
_SPDX_REQUIRED_TARGETS = frozenset({"DEPENDS_ON", "CONTAINS"})
#: When several relationships place one package, the most included scope wins.
_SCOPE_RANK = {"required": 0, "optional": 1, "excluded": 2}
_NOASSERTION = frozenset({"NOASSERTION", "NONE", ""})


def _properties(component: Mapping[str, Any]) -> dict[str, str]:
    """A CycloneDX component's ``properties`` as name -> value (first of each name)."""

    found: dict[str, str] = {}
    for item in component.get("properties") or ():
        if isinstance(item, Mapping):
            name, value = item.get("name"), item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                found.setdefault(name, value)
    return found


def _distro_fields(
    text: str,
    *,
    properties: Mapping[str, str],
    source_info: str | None = None,
    syft: bool = False,
) -> dict[str, str]:
    """``osv_package`` (or ``osv_unmapped`` and why) for a distro purl; nothing otherwise."""

    parsed = distro.parse(text)
    if parsed is None or parsed.type not in distro.DISTRO_TYPES:
        return {}
    package, reason = distro.osv_package(
        text, properties=properties, source_info=source_info, binary_is_source=syft
    )
    return {"osv_package": package} if package else {"osv_unmapped": str(reason)}


def _assemble(
    entries: Iterator[tuple[str, Any, Any, dict[str, str]]],
    *,
    inventory: str,
    named_by: str,
    warning: str | None,
    unidentified: int,
) -> dict[str, Any]:
    """The derived document from ``(purl text, scope, name, extra fields)`` entries."""

    # One record per (purl text, scope): a purl listed twice with one scope is
    # one record; with two scopes it is two, a duplicate key core refuses.
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for text, scope, name, extra in entries:
        marker = (text, json.dumps(scope, sort_keys=True))
        if marker in records:
            continue
        record: dict[str, Any] = {
            "purl": text,
            "inventory": inventory,
            "named_by": named_by,
            "scope": scope,
        }
        if isinstance(name, str) and name:
            record["name"] = name[:256]
        if warning is not None:
            record["warning"] = warning
        record.update(extra)
        records[marker] = record
        if len(records) > MAX_COMPONENTS:
            raise SbomRefused(f"the SBOM lists more than {MAX_COMPONENTS} components")
    out: dict[str, Any] = {
        "inventory": inventory,
        "named_by": named_by,
        "components": [records[key] for key in sorted(records)],
        # Every component the SBOM lists, keyed or not: core's complete_when
        # count check makes a read with an unidentified component incomplete.
        "count": len(records) + unidentified,
        "unidentified": unidentified,
    }
    if warning is not None:
        out["warning"] = warning
    # Distro packages: how many OSV can be asked about by source package, and why the
    # rest cannot (only present when the SBOM lists any, so other documents keep
    # their exact bytes).
    distro_records = [r for r in records.values() if "osv_package" in r or "osv_unmapped" in r]
    if distro_records:
        unmapped: dict[str, int] = {}
        for record in distro_records:
            if "osv_unmapped" in record:
                unmapped[record["osv_unmapped"]] = unmapped.get(record["osv_unmapped"], 0) + 1
        out["distro"] = {
            "mapped": sum(1 for r in distro_records if "osv_package" in r),
            "unmapped": dict(sorted(unmapped.items())),
        }
    return out


def _written_by_syft(names: Iterator[object]) -> bool:
    return any(isinstance(name, str) and "syft" in name.lower() for name in names)


def _cyclonedx_tools(metadata: Mapping[str, Any]) -> Iterator[object]:
    """The tool names in CycloneDX metadata: 1.4's list, or 1.5's ``{components: [...]}``."""

    tools = metadata.get("tools")
    items = tools.get("components") if isinstance(tools, Mapping) else tools
    for item in items or ():
        if isinstance(item, Mapping):
            yield item.get("name")


def _cyclonedx(document: Mapping[str, Any], relative_path: str) -> dict[str, Any]:
    metadata = document.get("metadata") or {}
    root = metadata.get("component") if isinstance(metadata, Mapping) else None
    purl = root.get("purl") if isinstance(root, Mapping) else None
    if isinstance(purl, str) and purl.strip():
        inventory, named_by, warning = purl.strip(), "metadata_component", None
    else:
        inventory, named_by, warning = relative_path, "file_path", UNNAMED
    syft = isinstance(metadata, Mapping) and _written_by_syft(_cyclonedx_tools(metadata))
    unidentified = 0
    entries: list[tuple[str, Any, Any, dict[str, str]]] = []
    for component in _walk(document.get("components")):
        text = component.get("purl")
        if not isinstance(text, str) or not text.strip():
            unidentified += 1
            continue
        text = text.strip()
        stated = component.get("scope")
        scope = DEFAULT_SCOPE if stated is None else stated
        extra = _distro_fields(text, properties=_properties(component), syft=syft)
        entries.append((text, scope, component.get("name"), extra))
    return _assemble(
        iter(entries),
        inventory=inventory,
        named_by=named_by,
        warning=warning,
        unidentified=unidentified,
    )


def _spdx_purl(package: Mapping[str, Any]) -> str | None:
    """The first ``purl`` external reference of an SPDX package, with ``versionInfo``
    appended when the purl names no version."""

    for ref in package.get("externalRefs") or ():
        if not isinstance(ref, Mapping) or ref.get("referenceType") != "purl":
            continue
        locator = ref.get("referenceLocator")
        if not isinstance(locator, str) or not locator.strip().startswith("pkg:"):
            continue
        text = locator.strip()
        version = package.get("versionInfo")
        tail = text.split("?", 1)[0].split("#", 1)[0].rsplit("/", 1)[-1]
        if "@" not in tail and isinstance(version, str) and version not in _NOASSERTION:
            head, sep, rest = text.partition("?")
            text = f"{head}@{version}" + (sep + rest if sep else "")
        return text
    return None


def _spdx(document: Mapping[str, Any], relative_path: str) -> dict[str, Any]:
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise SbomRefused("the SPDX document lists no packages")
    by_id: dict[str, Mapping[str, Any]] = {}
    for package in packages:
        if not isinstance(package, Mapping):
            raise SbomRefused("an SPDX package is not an object")
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id:
            raise SbomRefused("an SPDX package has no SPDXID")
        by_id[spdx_id] = package
    relationships = document.get("relationships", [])
    if not isinstance(relationships, list):
        raise SbomRefused("the SPDX relationships are not a list")
    described = {str(i) for i in document.get("documentDescribes") or () if isinstance(i, str)}
    scopes: dict[str, str] = {}

    def place(spdx_id: object, scope: str) -> None:
        if isinstance(spdx_id, str):
            held = scopes.get(spdx_id)
            if held is None or _SCOPE_RANK[scope] < _SCOPE_RANK[held]:
                scopes[spdx_id] = scope

    for item in relationships:
        if not isinstance(item, Mapping):
            raise SbomRefused("an SPDX relationship is not an object")
        kind = item.get("relationshipType")
        element, related = item.get("spdxElementId"), item.get("relatedSpdxElement")
        if kind == "DESCRIBES" and element == "SPDXRef-DOCUMENT" and isinstance(related, str):
            described.add(related)
        elif kind == "DESCRIBED_BY" and related == "SPDXRef-DOCUMENT" and isinstance(element, str):
            described.add(element)
        elif kind in _SPDX_SCOPES:
            place(element, _SPDX_SCOPES[str(kind)])
        elif kind in _SPDX_REQUIRED_TARGETS:
            place(related, "required")
    roots = [by_id[i] for i in sorted(described) if i in by_id]
    root_purls = sorted({p for p in (_spdx_purl(r) for r in roots) if p})
    if len(root_purls) == 1:
        inventory, named_by, warning = root_purls[0], "metadata_component", None
    else:
        inventory, named_by, warning = relative_path, "file_path", UNNAMED
    creation = document.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, Mapping) else None
    syft = _written_by_syft(iter(creators if isinstance(creators, list) else ()))
    unidentified = 0
    entries: list[tuple[str, Any, Any, dict[str, str]]] = []
    for spdx_id, package in by_id.items():
        if spdx_id in described:
            continue
        text = _spdx_purl(package)
        if text is None:
            unidentified += 1
            continue
        source_info = package.get("sourceInfo")
        extra = _distro_fields(
            text,
            properties={},
            source_info=source_info if isinstance(source_info, str) else None,
            syft=syft,
        )
        supplier = package.get("supplier")
        if isinstance(supplier, str) and supplier not in _NOASSERTION:
            extra["supplier"] = supplier[:256]
        entries.append((text, scopes.get(spdx_id, DEFAULT_SCOPE), package.get("name"), extra))
    return _assemble(
        iter(entries),
        inventory=inventory,
        named_by=named_by,
        warning=warning,
        unidentified=unidentified,
    )


def components_document(content: bytes, relative_path: str) -> dict[str, Any]:
    """The derived document for one SBOM's bytes (pure: same input, same output).

    CycloneDX JSON (``bomFormat: CycloneDX``) or SPDX 2.x JSON (``spdxVersion``
    ``SPDX-2.*`` with a ``packages`` list); anything else is refused.
    """

    try:
        document = json.loads(content)
    except ValueError as exc:
        raise SbomRefused(f"the SBOM is not JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise SbomRefused("the SBOM is not a JSON object")
    if document.get("bomFormat") == "CycloneDX":
        return _cyclonedx(document, relative_path)
    version = document.get("spdxVersion")
    if isinstance(version, str) and version.startswith("SPDX-2.") and "packages" in document:
        return _spdx(document, relative_path)
    raise SbomRefused(
        "the document is neither a CycloneDX JSON SBOM (bomFormat) nor an SPDX 2.x JSON "
        "document (spdxVersion, packages)"
    )


@derive(
    COMPONENTS,
    serves="security.sbom.components",
    input_contract="security.sbom.components.request@1",
    output_contract="security.sbom.components.result@1",
    refusals={
        PROVIDER_DECLINED: {
            "contract": f"{COMPONENTS}.refusal.{PROVIDER_DECLINED}@1",
            "absorbable": False,
        }
    },
)
def sbom_components(
    sbom: CaptureView, relative_path: str, logical_source: str | None = None
) -> ProviderResult:
    """Reads one CycloneDX or SPDX 2.x JSON SBOM: one document naming its inventory and each
    distinct component by purl with its scope, nested components flattened, unidentified ones
    counted, distro packages with the OSV source package they are asked as."""

    if not isinstance(relative_path, str) or not relative_path:
        raise decline(PROVIDER_DECLINED, "sbom.components needs the SBOM path")
    try:
        document = components_document(sbom.raw_bytes, relative_path)
    except SbomRefused as error:
        raise decline(PROVIDER_DECLINED, str(error)) from None
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return ProviderResult.ok(
        {
            # Observed when the SBOM was, never the clock: a rerun is byte-identical.
            "document": sbom.derive(
                content,
                source_identity=str(logical_source or "cyclonedx.sbom"),
                coordinate_type=COORDINATE_TYPE,
                coordinate={"relative_path": relative_path, "components": document["count"]},
                selector_type=SELECTOR_TYPE,
            )
        },
        metrics={"components": float(len(document["components"]))},
    )
