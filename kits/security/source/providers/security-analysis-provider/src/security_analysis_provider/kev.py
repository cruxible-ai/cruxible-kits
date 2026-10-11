"""CISA KEV catalog: triage of watched vulnerabilities, and attention for inventory nobody tracks.

``KevTriage`` (``security.kev-catalog``) compares the retained catalog with the
watched vulnerabilities (rows of ``security.watched_vulnerabilities``) and
returns one observation Claim item per KEV field whose catalog value differs
from the held Claim, revising it when one is held. An identical catalog yields
no items. A watched vulnerability the catalog does not list gets
``kev_listed = false`` once; its other KEV fields are left alone. A field whose
held Claims conflict is skipped and reported, never overwritten.

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
    claim_item,
    cve_token,
    decode_base64,
    decode_json,
    match_token,
    once_per,
    parse_rows,
    sorted_items,
)

WATCH_LIMIT = 1000
NEW_WINDOW_DAYS = 7
VULNERABILITY = "security.vulnerability"

# Projected field -> (ClaimType predicate, KEV catalog key).
FIELDS: dict[str, tuple[str, str]] = {
    "kev_listed": ("security.vulnerability.kev_listed", ""),
    "kev_date_added": ("security.vulnerability.kev_date_added", "dateAdded"),
    "kev_due_date": ("security.vulnerability.kev_due_date", "dueDate"),
    "kev_ransomware_use": (
        "security.vulnerability.kev_ransomware_use",
        "knownRansomwareCampaignUse",
    ),
}


def classify_triage(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    """Bucket a triage request: a catalog is present, and the watch list is small or large."""

    catalog = payload.get("catalog_base64")
    watched = payload.get("watched")
    if not isinstance(catalog, str) or not catalog or not isinstance(watched, list):
        return None
    return {"catalog": "present", "watchlist": "small" if len(watched) <= WATCH_LIMIT else "large"}


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
    index: dict[str, Any] = {}
    for entry in catalog["vulnerabilities"]:
        if isinstance(entry, Mapping):
            cve = cve_token(entry.get("cveID"))
            if cve is not None:
                index[cve] = entry
    return index, str(catalog.get("catalogVersion") or ""), catalog


def _catalog_value(field: str, entry: Mapping[str, Any] | None) -> Any:
    if field == "kev_listed":
        return entry is not None
    if entry is None:
        return None
    raw = entry.get(FIELDS[field][1])
    if not isinstance(raw, str) or not raw.strip():
        return None
    if field == "kev_ransomware_use":
        lowered = raw.strip().lower()
        return lowered if lowered in {"known", "unknown"} else None
    return raw.strip()


def _declined(error: InputError) -> ProviderResult:
    return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))


class KevTriage:
    """The ``security.kev-catalog`` implementation."""

    interface_id = "security.kev-catalog"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            index, version, _ = _catalog(context.input)
            rows = once_per(parse_rows(context.input.get("watched")), "vulnerability")
        except InputError as error:
            return _declined(error)
        items: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        listed = watched = 0
        for row in rows:
            vulnerability = row.subject("vulnerability")
            cve = cve_token(row.value("cve_id"))
            if vulnerability is None or cve is None:
                continue
            watched += 1
            entry = index.get(cve)
            listed += entry is not None
            for name in sorted(FIELDS):
                predicate, key = FIELDS[name]
                value = _catalog_value(name, entry)
                if value is None:
                    continue
                state = row.state(name)
                if state == "conflict":
                    skipped.append({"cve_id": cve, "field": name, "reason": "conflict"})
                    continue
                if state == "present" and row.value(name) == value:
                    continue
                rationale = (
                    f"CISA KEV catalog {version} ({len(index)} entries) does not list {cve}."
                    if entry is None
                    else f"CISA KEV catalog {version} lists {cve} with "
                    f"{key or 'an entry'} = {value!r}."
                )
                items.append(
                    claim_item(
                        vulnerability,
                        predicate,
                        value,
                        rationale,
                        revises=row.claim_id(vulnerability, predicate)
                        if state == "present"
                        else None,
                    )
                )
        return ProviderResult.ok(
            {
                "items": sorted_items(items),
                "changed": len(items),
                "watched": watched,
                "listed": listed,
                "catalog_version": version,
                "catalog_count": len(index),
            },
            metrics={"items": float(len(items)), "watched": float(watched)},
            events=[{"skipped": skipped}] if skipped else [],
        )


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
