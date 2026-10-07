"""KEV catalog Capture plus watched vulnerabilities -> one proposal item per changed field.

The input is the retained KEV catalog body (base64, exactly the bytes the
Capture holds) and the rows of the ``security.watched_vulnerabilities`` query
(each watched vulnerability with its current supported KEV Claims). The output
``items`` are ``propose_change_set`` items: one observation Claim per KEV field
whose catalog value differs from the current Claim, revising that Claim when one
exists. Nothing is proposed for a field that already holds the catalog's value,
so an identical catalog yields no items.

A watched vulnerability absent from the catalog gets ``kev_listed = false``
(once: an existing false Claim is left alone). Its other KEV fields are left as
they are.

Evidence is not named here: the daemon attaches the Capture the run consumed.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

INTERFACE_ID = "security.kev-catalog"
SUBJECT_KIND = "security.vulnerability"
WATCH_LIMIT = 1000

# Query projection field -> (ClaimType predicate, KEV catalog key, value mapper).
FIELDS: dict[str, tuple[str, str]] = {
    "kev_listed": ("security.vulnerability.kev_listed", ""),
    "kev_date_added": ("security.vulnerability.kev_date_added", "dateAdded"),
    "kev_due_date": ("security.vulnerability.kev_due_date", "dueDate"),
    "kev_ransomware_use": (
        "security.vulnerability.kev_ransomware_use",
        "knownRansomwareCampaignUse",
    ),
}


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    """Bucket the request: a catalog is present, and the watch list is small or large."""

    catalog = payload.get("catalog_base64")
    watched = payload.get("watched")
    if not isinstance(catalog, str) or not catalog or not isinstance(watched, list):
        return None
    return {
        "catalog": "present",
        "watchlist": "small" if len(watched) <= WATCH_LIMIT else "large",
    }


def _subject_address(subject_id: str) -> dict[str, Any]:
    return {
        "tag": "playbill-semantic-address-v1",
        "artifact_path": f"subjects/{SUBJECT_KIND}/{subject_id}.json",
        "selector": {"scheme": "artifact-v1", "value": ""},
    }


def _claim_id(claim_path: str) -> str:
    return claim_path.rsplit("/", 1)[-1].removesuffix(".json")


def _catalog_value(field: str, entry: Mapping[str, Any] | None) -> Any:
    if field == "kev_listed":
        return entry is not None
    if entry is None:
        return None
    raw = entry.get(FIELDS[field][1])
    if not isinstance(raw, str) or not raw:
        return None
    if field == "kev_ransomware_use":
        lowered = raw.strip().lower()
        return lowered if lowered in {"known", "unknown"} else None
    return raw.strip()


def _row(row: Mapping[str, Any]) -> tuple[str, dict[str, tuple[str, Any]], dict[str, str]]:
    """(subject_id, {field: (state, value)}, {predicate: current claim id})."""

    subject_id = next(
        binding["subject_id"]
        for binding in row["bindings"]
        if binding.get("subject_kind") == SUBJECT_KIND and binding.get("subject_id")
    )
    fields = {item["name"]: (item["state"], item.get("value")) for item in row.get("fields", ())}
    claims: dict[str, str] = {}
    for claim in row.get("read_claims", ()):
        address = claim.get("subject_identity", "")
        if address.endswith(f"{SUBJECT_KIND}/{subject_id}"):
            claims.setdefault(claim["predicate"], _claim_id(claim["claim_path"]))
    return subject_id, fields, claims


class KevCatalog:
    """The ``security.kev-catalog`` implementation."""

    interface_id = INTERFACE_ID

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            body = base64.b64decode(context.input["catalog_base64"], validate=True)
            catalog = json.loads(body)
            entries = catalog["vulnerabilities"]
        except (KeyError, TypeError, ValueError, binascii.Error) as error:
            return ProviderResult.refused(
                RefusalCode.PROVIDER_DECLINED,
                "the Capture body is not a KEV catalog",
                reason=type(error).__name__,
            )
        index = {
            str(entry["cveID"]).strip().lower(): entry
            for entry in entries
            if isinstance(entry, Mapping) and entry.get("cveID")
        }
        version = str(catalog.get("catalogVersion") or "")
        rows = sorted(
            (_row(row) for row in context.input["watched"]), key=lambda item: item[0]
        )
        items: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        listed = 0
        for subject_id, current, claims in rows:
            entry = index.get(subject_id.lower())
            listed += entry is not None
            for field in sorted(FIELDS):
                predicate = FIELDS[field][0]
                value = _catalog_value(field, entry)
                if value is None:
                    continue
                state, held = current.get(field, ("absent", None))
                if state == "conflict":
                    skipped.append({"subject": subject_id, "field": field, "reason": "conflict"})
                    continue
                if state == "present" and held == value:
                    continue
                if entry is None:
                    rationale = (
                        f"CISA KEV catalog {version} ({len(index)} entries) does not list "
                        f"{subject_id.upper()}."
                    )
                else:
                    rationale = (
                        f"CISA KEV catalog {version} lists {subject_id.upper()} with "
                        f"{FIELDS[field][1] or 'an entry'} = {value!r}."
                    )
                items.append(
                    {
                        "tag": "playbill-procedure-claim-proposal-item-v1",
                        "statement": {
                            "tag": "playbill-authoring-claim-statement-v1",
                            "subject": _subject_address(subject_id),
                            "predicate": predicate,
                            "qualifier": None,
                            "object": {"kind": "literal", "value": value},
                            "role": "observation",
                            "effective_from": None,
                            "effective_until": None,
                        },
                        "rationale": rationale,
                        "revises": claims.get(predicate) if state == "present" else None,
                    }
                )
        return ProviderResult.ok(
            {
                "items": items,
                "changed": len(items),
                "watched": len(rows),
                "listed": listed,
                "catalog_version": version,
                "catalog_count": len(index),
            },
            metrics={"items": float(len(items)), "watched": float(len(rows))},
            events=[{"skipped": skipped}] if skipped else [],
        )
