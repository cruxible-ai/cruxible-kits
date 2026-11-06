"""``sbom.components``: one CycloneDX JSON SBOM -> one derived JSON document (pure, D-R37).

The SBOM import Procedure reads the SBOM file through core's builtin
``workspace.file`` (one Capture, the file's bytes verbatim). This derive reads
those bytes (passed by core) and the instance's held memberships (a state read,
``held``: purl and inventory id per membership), and emits ONE derived JSON
document::

    {"inventory":    "<metadata.component purl, or the file path>",
     "named_by":     "metadata_component" | "file_path",
     "warning":      "sbom_unnamed"                  # only when named by path
     "components":   [{"purl", "name", "inventory", "named_by", "warning"?}, ...],
     "count":        len(components),
     "held":         [purl, ...],    # what this inventory held before: the expect list
     "unidentified": N}                              # components with no purl

The inventory key is the SBOM's own ``metadata.component`` purl (K-B1-5,
K-B1-G1): one import Procedure serves every SBOM, and a new product needs only
its SBOM. An SBOM without one is named by its workspace path, and every record
carries ``warning: sbom_unnamed``: moving the file starts a new inventory.

Nested components (``components[*].components``) are flattened, depth first.
Two entries with the same purl text are one record (the same identifier
listed twice). Two spellings that core's purl normalizer folds to one key stay
two records, so core's ``duplicates: refuse_key`` writes nothing for that key
(fail closed). A component with no purl cannot be keyed: it is counted in
``unidentified`` and is never a record.

``held`` is the import's absence scope: the components the inventory this SBOM
names held before the run. Core cannot parameterize a read by a value only the
derive knows (a read's parameters may not depend on runtime output), so the
import reads every membership and this derive selects the inventory's own.

Pure: the output is a function of the SBOM bytes, the path and the held rows;
the result's observation time is the SBOM Capture's own, never the clock.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
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


def components_document(
    content: bytes, relative_path: str, held: Iterable[Mapping[str, Any]] = ()
) -> dict[str, Any]:
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
    records: dict[str, dict[str, Any]] = {}
    unidentified = 0
    for component in _walk(document.get("components")):
        text = component.get("purl")
        if not isinstance(text, str) or not text.strip():
            unidentified += 1
            continue
        text = text.strip()
        if text in records:
            continue
        record: dict[str, Any] = {"purl": text, "inventory": inventory, "named_by": named_by}
        name = component.get("name")
        if isinstance(name, str) and name:
            record["name"] = name[:256]
        if warning is not None:
            record["warning"] = warning
        records[text] = record
        if len(records) > MAX_COMPONENTS:
            raise SbomRefused(f"the SBOM lists more than {MAX_COMPONENTS} components")
    out: dict[str, Any] = {
        "inventory": inventory,
        "named_by": named_by,
        "components": [records[key] for key in sorted(records)],
        "count": len(records),
        "held": sorted(
            {
                str(row.get("purl"))
                for row in held
                if isinstance(row, Mapping)
                and row.get("inventory_id") == inventory
                and isinstance(row.get("purl"), str)
            }
        ),
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
        held = context.input.get("held") or []
        source = str(context.input.get("logical_source") or "cyclonedx.sbom")
        if not isinstance(path, str) or not path or not isinstance(held, list):
            return ProviderResult.refused(
                PROVIDER_DECLINED, "sbom.components needs the SBOM path and the held memberships"
            )
        try:
            sbom = capture_input(view)
            observed_at = capture_observed_at(view)
            document = components_document(sbom.content, path, held)
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
            metrics={"components": float(document["count"])},
        )
