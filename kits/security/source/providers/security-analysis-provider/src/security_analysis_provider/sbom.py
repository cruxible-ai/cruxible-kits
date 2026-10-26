"""CycloneDX JSON SBOM: the release it describes and that release's components.

The input is the retained SBOM text (the ``security.file-v1`` Capture's
``content.text``) and the releases already in inventory (rows of
``security.release_inventory``). The SBOM's ``metadata.component`` names the
product and version; its ``components`` with a package URL are the release's
components.

The output ``items``: a Subject item for the product (key: name) and one for the
release (key: product name + version) when inventory does not hold them yet, the
release's ``product`` (when the release does not have one), one
``security.release.component`` observation per component purl the release does
not hold yet, and the supplier with ``product.supplied_by`` when the SBOM names
a supplier the product does not have (revising the held one when it differs), and
``security.release.unidentified_components`` (how many components it lists without a
purl with a version, an operating-system component included) when that is not zero or
differs from the held count: OSV is never asked about those, so the release's OSV
coverage stays partial and no negative rests on it.
A re-import of the same SBOM proposes nothing; a new version of the product is a
new release beside the held ones, which stay (they may still be deployed).
Removing components, retiring releases, licences and the dependency graph are
out of scope.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    InputError,
    claim_item,
    key_ref,
    name_form,
    parse_rows,
    purl_version,
    sorted_items,
    unindexed_counts,
    subject_item,
)

PRODUCT = "security.product"
RELEASE = "security.release"
SUPPLIER = "security.supplier"
COMPONENT = "security.release.component"
UNIDENTIFIED = "security.release.unidentified_components"
MAX_COMPONENTS = 5000


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    sbom = payload.get("sbom_text")
    if (
        not isinstance(sbom, str)
        or not sbom.strip()
        or not isinstance(payload.get("releases"), list)
    ):
        return None
    return {"sbom": "present", "size": "small" if len(sbom) <= 4_194_304 else "large"}


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


#: How deep a release SBOM's nested components are read: deeper is refused, never cut.
MAX_DEPTH = 32


def _every_component(items: object, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    """Every component of the hierarchy, nested ``components`` included (R2-005): a
    child the reader skipped would be neither a component nor unidentified, so a negative
    could rest on a set that leaves it out. A listed entry that is not an object counts
    as unidentified (an empty mapping)."""

    if depth > MAX_DEPTH:
        raise InputError(f"the SBOM nests components deeper than {MAX_DEPTH}")
    for item in items if isinstance(items, list) else ():
        if not isinstance(item, Mapping):
            yield {}
            continue
        yield item
        yield from _every_component(item.get("components"), depth + 1)


def read_sbom(text: str) -> tuple[str, str, str, list[str], int]:
    """(product name, version, supplier name, sorted component purls, skipped count)."""

    try:
        document = json.loads(text)
    except ValueError as error:
        raise InputError("the SBOM is not JSON") from error
    if not isinstance(document, Mapping) or document.get("bomFormat") != "CycloneDX":
        raise InputError("the SBOM is not a CycloneDX JSON document")
    metadata = document.get("metadata") if isinstance(document.get("metadata"), Mapping) else {}
    component = metadata.get("component") if isinstance(metadata.get("component"), Mapping) else {}
    name, version = _text(component.get("name")), _text(component.get("version"))
    if not name or not version:
        raise InputError("metadata.component must name the product and its version")
    supplier = ""
    for holder in (
        component.get("supplier"),
        metadata.get("supplier"),
        metadata.get("manufacturer"),
    ):
        if isinstance(holder, Mapping) and _text(holder.get("name")):
            supplier = _text(holder.get("name"))
            break
    purls: set[str] = set()
    skipped = 0
    for item in _every_component(document.get("components")):
        purl = _text(item.get("purl"))
        if purl_version(purl) is not None:
            purls.add(purl)
        else:
            # Listed, but not identifiable as a package at a version (an operating system
            # without a purl included): never asked of OSV, so the release's coverage can't
            # be complete (security.release.unidentified_components).
            skipped += 1
    if len(purls) + skipped > MAX_COMPONENTS:
        raise InputError(f"the SBOM lists more than {MAX_COMPONENTS} components")
    return name, version, supplier, sorted(purls), skipped


class CycloneDxComponents:
    """The ``security.cyclonedx-components`` implementation."""

    interface_id = "security.cyclonedx-components"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            name, version, supplier, purls, skipped = read_sbom(str(context.input.get("sbom_text")))
            rows = parse_rows(context.input.get("releases"))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        unindexed = unindexed_counts(purls, context.input.get("osv_ecosystems") or {})
        product = key_ref(PRODUCT, name=name)
        release = key_ref(RELEASE, product_name=name, version=version)
        # What inventory already holds, matched by key values: the release (its
        # components, its product link) and the product (any of its releases' rows
        # carries its supplier). Only what is new or changed is proposed: core does
        # not see a statement as restated when its Subject is named through a Subject
        # item of the same terminal (the item's creation address, not the live path),
        # so restating a one-valued relationship would demand a disposition.
        held_components: set[str] = set()
        held_unidentified: tuple[Any, str | None] = (None, None)  # (count, Claim id)
        held_release: Any = None
        release_held = has_product = False
        product_held = False
        held_supplier: tuple[str, str | None] | None = None  # (name, Claim id)
        for row in rows:
            if row.value("product_name") != name_form(name):
                continue
            product_bound = row.subject("product")
            product_held = product_held or product_bound is not None
            if product_bound is not None and row.subject("supplier") is not None:
                held_supplier = (
                    str(row.value("supplier_name") or ""),
                    row.claim_id(product_bound, "security.product.supplied_by"),
                )
            if row.value("version") == version:
                release_held = True
                held_components.update(row.value("components") or ())
                has_product = product_bound is not None
                release_bound = row.subject("release")
                held_release = release_bound or held_release
                if release_bound is not None and row.value("unidentified") is not None:
                    held_unidentified = (row.value("unidentified"),
                                         row.claim_id(release_bound, UNIDENTIFIED))
        source = f"CycloneDX SBOM for {name} {version}"
        items = []
        if not product_held:
            items.append(
                subject_item(PRODUCT, {"name": name}, f"{source} names the product {name}.")
            )
        if not release_held:
            items.append(
                subject_item(
                    RELEASE,
                    {"product_name": name, "version": version},
                    f"{source} describes release {version} of {name}.",
                )
            )
        if not has_product:
            items.append(
                claim_item(
                    release,
                    "security.release.product",
                    product,
                    f"{source}: the release is a version of {name}.",
                    role="normative",
                )
            )
        if supplier and (held_supplier is None or held_supplier[0] != name_form(supplier)):
            items.append(
                subject_item(
                    SUPPLIER, {"name": supplier}, f"{source} names the supplier {supplier}."
                )
            )
            items.append(
                claim_item(
                    product,
                    "security.product.supplied_by",
                    key_ref(SUPPLIER, name=supplier),
                    f"{source} names {supplier} as the supplier.",
                    role="normative",
                    revises=held_supplier[1] if held_supplier is not None else None,
                )
            )
        if (skipped or held_unidentified[0] is not None) and held_unidentified[0] != skipped:
            items.append(claim_item(
                held_release or release, UNIDENTIFIED, skipped,
                f"{source} lists {skipped} component(s) without a package URL and version: "
                "OSV can't be asked about them, so its coverage of the release stays partial.",
                revises=held_unidentified[1] if held_unidentified[0] is not None else None))
        added = [purl for purl in purls if purl not in held_components]
        for purl in added:
            items.append(
                claim_item(release, COMPONENT, purl, f"{source} lists the component {purl}.")
            )
        claims = [
            item for item in items if item["tag"] != "playbill-procedure-subject-proposal-item-v1"
        ]
        subjects = [item for item in items if item not in claims]
        if unindexed:
            note = "; OSV will not answer " + ", ".join(f"{kind} {count}" for kind, count in unindexed.items())
            for item in claims:
                item["rationale"] += note
        changed = len(claims)
        return ProviderResult.ok(
            {
                "items": subjects + sorted_items(claims) if changed else [],
                "changed": changed,
                "product": name,
                "version": version,
                "components": len(purls),
                "added": len(added),
                "skipped": skipped,
                "osv_not_indexed": unindexed, "osv_unindexed": sum(unindexed.values()),
            },
            metrics={"components": float(len(purls)), "added": float(len(added))},
        )
