"""``sbom.components``: one CycloneDX JSON SBOM -> one derived JSON document (pure, D-R37).

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
observation time is the SBOM Capture's own, never the clock.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any

from cruxible_provider_runtime.acquisition import (
    CaptureInputError,
    capture_input,
    capture_observed_at,
    external_capture_result,
)
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

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


def components_document(content: bytes, relative_path: str) -> dict[str, Any]:
    """The derived document for one SBOM's bytes (pure: same input, same output)."""

    try:
        document = json.loads(content)
    except ValueError as exc:
        raise SbomRefused(f"the SBOM is not JSON: {exc}") from exc
    if not isinstance(document, Mapping) or document.get("bomFormat") != "CycloneDX":
        raise SbomRefused("the document is not a CycloneDX SBOM (bomFormat)")
    metadata = document.get("metadata") or {}
    root = metadata.get("component") if isinstance(metadata, Mapping) else None
    purl = root.get("purl") if isinstance(root, Mapping) else None
    if isinstance(purl, str) and purl.strip():
        inventory, named_by, warning = purl.strip(), "metadata_component", None
    else:
        inventory, named_by, warning = relative_path, "file_path", UNNAMED
    # One record per (purl text, scope): a purl listed twice with one scope is
    # one record; with two scopes it is two, a duplicate key core refuses.
    records: dict[tuple[str, str], dict[str, Any]] = {}
    unidentified = 0
    for component in _walk(document.get("components")):
        text = component.get("purl")
        if not isinstance(text, str) or not text.strip():
            unidentified += 1
            continue
        text = text.strip()
        stated = component.get("scope")
        scope = DEFAULT_SCOPE if stated is None else stated
        marker = (text, json.dumps(scope, sort_keys=True))
        if marker in records:
            continue
        record: dict[str, Any] = {
            "purl": text,
            "inventory": inventory,
            "named_by": named_by,
            "scope": scope,
        }
        name = component.get("name")
        if isinstance(name, str) and name:
            record["name"] = name[:256]
        if warning is not None:
            record["warning"] = warning
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
    return out


class SbomComponents:
    """``sbom.components``: an SBOM Capture -> one derived JSON document (pure)."""

    operations = (COMPONENTS,)

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        view = context.input.get("sbom")
        path = context.input.get("relative_path")
        source = str(context.input.get("logical_source") or "cyclonedx.sbom")
        if not isinstance(path, str) or not path:
            return ProviderResult.refused(PROVIDER_DECLINED, "sbom.components needs the SBOM path")
        try:
            sbom = capture_input(view)
            observed_at = capture_observed_at(view)
            document = components_document(sbom.content, path)
        except (CaptureInputError, SbomRefused) as error:
            return ProviderResult.refused(PROVIDER_DECLINED, str(error))
        content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return ProviderResult.ok(
            {
                "document": external_capture_result(
                    content,
                    source_identity=source,
                    coordinate_type=COORDINATE_TYPE,
                    coordinate={"relative_path": path, "components": document["count"]},
                    observed_at=observed_at,
                    selector_type=SELECTOR_TYPE,
                )
            },
            metrics={"components": float(len(document["components"]))},
        )
