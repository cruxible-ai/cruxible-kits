"""CISA KEV catalog: attention for inventory nobody tracks.

KEV triage (membership, dates, ransomware use of watched vulnerabilities) is no
longer provider code: the ``security.kev-triage`` Procedure extracts the catalog
Capture and writes its Claims through a declared claims template (kit pilot).

``KevAttention`` (``security.kev-attention``) finds catalog entries added in the
last ``NEW_WINDOW_DAYS`` days (counted back from the catalog's own
``dateReleased``) whose vendor/product matches a release in inventory that has
no watched vulnerability for the CVE (no watch_reason, no affected or
inconclusive assessment), or no assessment of that release for it.
Each such (CVE, release) pair is one inbox payload: the automation cannot state
a belief about exposure, so it asks. The payload holds only facts that stay the
same while the situation does, so core's inbox dedupe counts a repeat sighting
instead of posting a new item.

Evidence is not named here: the daemon attaches the catalog Capture the run consumed.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, timedelta
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    InputError,
    cve_token,
    decode_base64,
    decode_json,
    match_token,
    parse_rows,
    sorted_items,
)

WATCH_LIMIT = 1000
NEW_WINDOW_DAYS = 7

def classify_attention(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    catalog = payload.get("catalog_base64")
    releases = payload.get("releases")
    if not isinstance(catalog, str) or not catalog or not isinstance(releases, list):
        return None
    return {"catalog": "present", "inventory": "small" if len(releases) <= WATCH_LIMIT else "large"}


def _catalog(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str, Mapping[str, Any]]:
    catalog = decode_json(decode_base64(payload.get("catalog_base64"), "catalog_base64"), "catalog")
    if not isinstance(catalog, Mapping) or not isinstance(catalog.get("vulnerabilities"), list):
        raise InputError("the Capture body is not a KEV catalog")
    count = catalog.get("count")
    if isinstance(count, int) and count != len(catalog["vulnerabilities"]):
        # A cut-off catalog would read every missing entry as unlisted: refuse it whole.
        raise InputError(f"the KEV catalog states {count} entries but holds "
                         f"{len(catalog['vulnerabilities'])}: incomplete, not an answer")
    index: dict[str, Any] = {}
    for entry in catalog["vulnerabilities"]:
        if isinstance(entry, Mapping):
            cve = cve_token(entry.get("cveID"))
            if cve is not None:
                index[cve] = entry
    return index, str(catalog.get("catalogVersion") or ""), catalog


def _declined(error: InputError) -> ProviderResult:
    return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))


def _matches(release: Mapping[str, str], entry: Mapping[str, Any]) -> str | None:
    """Why a KEV entry's vendor/product names this release's product, or None.

    Product text equal to the release's product name (or to vendor + product),
    or the vendor equal to the release's supplier with one product name
    containing the other. Comparison only (``match_token``); a false match costs
    one inbox item, a missed one a silent exposure, so this leans to matching.
    """

    product = match_token(release.get("product_name"))
    supplier = match_token(release.get("supplier_name"))
    kev_product = match_token(entry.get("product"))
    kev_vendor = match_token(entry.get("vendorProject"))
    if not product or not kev_product:
        return None
    if product in {kev_product, kev_vendor + kev_product}:
        return "product name"
    if (
        supplier
        and supplier == kev_vendor
        and len(product) >= 3
        and (product in kev_product or kev_product in product)
    ):
        return "supplier and product name"
    return None


class KevAttention:
    """The ``security.kev-attention`` implementation: inbox payloads, never Claims."""

    interface_id = "security.kev-attention"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            index, version, catalog = _catalog(context.input)
            releases = parse_rows(context.input.get("releases"))
            watched_rows = parse_rows(context.input.get("watched"))
            assessed_rows = parse_rows(context.input.get("assessments"))
        except InputError as error:
            return _declined(error)
        released = str(catalog.get("dateReleased") or "")[:10]
        try:
            newest = date.fromisoformat(released)
        except ValueError:
            return _declined(InputError("the catalog carries no dateReleased date"))
        since = newest - timedelta(days=NEW_WINDOW_DAYS)
        watched = {cve for row in watched_rows if (cve := cve_token(row.value("cve_id")))}
        assessed = {
            (cve, release_id)
            for row in assessed_rows
            if (cve := cve_token(row.value("cve_id")))
            and isinstance(release_id := row.value("release_id"), str)
            and row.value("status") is not None
        }
        inventory = []
        for row in releases:
            bound = row.subject("release")
            if bound is None:
                continue
            inventory.append(
                (
                    bound,
                    {
                        "product_name": row.value("product_name") or "",
                        "supplier_name": row.value("supplier_name") or "",
                        "version": row.value("version") or "",
                    },
                )
            )
        posts: list[dict[str, Any]] = []
        new = 0
        for cve in sorted(index):
            entry = index[cve]
            try:
                added = date.fromisoformat(str(entry.get("dateAdded") or "")[:10])
            except ValueError:
                continue
            if added < since:
                continue
            new += 1
            for bound, release in inventory:
                reason = _matches(release, entry)
                if reason is None:
                    continue
                if cve not in watched:
                    gap = "not_watched"
                elif (cve, bound.subject_id) not in assessed:
                    gap = "no_assessment"
                else:
                    continue
                posts.append(
                    {
                        "attention": "possibly_exposed",
                        "cve_id": cve,
                        "gap": gap,
                        "kev": {
                            "date_added": str(entry.get("dateAdded") or ""),
                            "due_date": str(entry.get("dueDate") or ""),
                            "product": str(entry.get("product") or ""),
                            "vendor_project": str(entry.get("vendorProject") or ""),
                            "vulnerability_name": str(entry.get("vulnerabilityName") or ""),
                        },
                        "matched_by": reason,
                        "release": bound.path,
                        "product_name": release["product_name"],
                        "version": release["version"],
                        "summary": (
                            f"KEV newly lists {cve} ({entry.get('vendorProject')} "
                            f"{entry.get('product')}); inventory has {release['product_name']} "
                            f"{release['version']}"
                            + (
                                " and nobody watches the CVE."
                                if gap == "not_watched"
                                else " and nobody has assessed this release for it."
                            )
                        ),
                    }
                )
        posts = sorted_items(posts)
        return ProviderResult.ok(
            {
                "items": posts,
                "posted": len(posts),
                "newly_listed": new,
                "catalog_version": version,
            },
            metrics={"items": float(len(posts))},
        )
