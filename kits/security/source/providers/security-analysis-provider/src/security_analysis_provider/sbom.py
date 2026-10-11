"""CycloneDX JSON SBOM: the release it describes and that release's components.

The input is the retained SBOM text (the ``security.cyclonedx-sbom-v1`` Capture's
``content.text``) and the releases already in inventory (rows of
``security.release_inventory``). The SBOM's ``metadata.component`` names the
product and version; its ``components`` with a package URL are the release's
components.

The output ``items``: a Subject item for the product (key: name) and one for the
release (key: product name + version) -- each names the live holder when there
is one, and creates nothing then -- the release's ``product`` (when the release
does not have one yet), one ``security.release.component`` observation per
component purl the release does not hold yet, and the supplier with
``product.supplied_by`` when the SBOM names a supplier and the product has none.
A re-import of the same SBOM proposes nothing. Removing components, licences and
the dependency graph are out of scope.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    InputError,
    claim_item,
    key_ref,
    name_form,
    parse_rows,
    sorted_items,
    subject_item,
)

PRODUCT = "security.product"
RELEASE = "security.release"
SUPPLIER = "security.supplier"
COMPONENT = "security.release.component"
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
    for item in document.get("components") or ():
        purl = _text(item.get("purl")) if isinstance(item, Mapping) else ""
        if purl.startswith("pkg:") and "@" in purl.split("/", 1)[-1]:
            purls.add(purl)
        else:
            skipped += 1
    if len(purls) > MAX_COMPONENTS:
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
        product = key_ref(PRODUCT, name=name)
        release = key_ref(RELEASE, product_name=name, version=version)
        # The release's held facts, when inventory already has it (matched by its key values).
        held_components: set[str] = set()
        has_product = has_supplier = False
        for row in rows:
            if (row.value("product_name"), row.value("version")) == (name_form(name), version):
                held_components.update(row.value("components") or ())
                has_product = row.subject("product") is not None
                has_supplier = row.subject("supplier") is not None
        source = f"CycloneDX SBOM for {name} {version}"
        items = [
            subject_item(PRODUCT, {"name": name}, f"{source} names the product {name}."),
            subject_item(
                RELEASE,
                {"product_name": name, "version": version},
                f"{source} describes release {version} of {name}.",
            ),
        ]
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
        if supplier and not has_supplier:
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
                )
            )
        added = [purl for purl in purls if purl not in held_components]
        for purl in added:
            items.append(
                claim_item(release, COMPONENT, purl, f"{source} lists the component {purl}.")
            )
        claims = [
            item for item in items if item["tag"] != "playbill-procedure-subject-proposal-item-v1"
        ]
        subjects = [item for item in items if item not in claims]
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
            },
            metrics={"components": float(len(purls)), "added": float(len(added))},
        )
