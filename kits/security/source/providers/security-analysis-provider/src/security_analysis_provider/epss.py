"""FIRST EPSS daily scores: triage of watched vulnerabilities.

The input is the retained daily file (the ``security.epss-daily`` Capture's
gzip body, base64) and the watched vulnerabilities (rows of
``security.watched_vulnerabilities``). The output ``items`` are one observation
Claim item per watched CVE whose ``epss_score`` or ``epss_percentile`` differs
from the held Claim, with the value exactly as the file states it. A CVE the
file does not score is left alone. An identical file yields no items.
"""

from __future__ import annotations

import csv
import gzip
import re
from collections.abc import Mapping
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    InputError,
    claim_item,
    cve_token,
    decode_base64,
    once_per,
    parse_rows,
    sorted_items,
)

WATCH_LIMIT = 1000
FIELDS = {
    "epss_score": ("security.vulnerability.epss_score", "epss"),
    "epss_percentile": ("security.vulnerability.epss_percentile", "percentile"),
}
_PROBABILITY = re.compile(r"^(0(\.[0-9]+)?|1(\.0+)?)$")
_HEADER = re.compile(r"model_version:([^,]+),score_date:(\S+)")


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    daily = payload.get("daily_base64")
    watched = payload.get("watched")
    if not isinstance(daily, str) or not daily or not isinstance(watched, list):
        return None
    return {"daily": "present", "watchlist": "small" if len(watched) <= WATCH_LIMIT else "large"}


def read_daily(body: bytes) -> tuple[dict[str, tuple[str, str]], str, str]:
    """(CVE -> (score, percentile), model_version, score_date) from the gzip CSV."""

    try:
        text = gzip.decompress(body).decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError) as error:
        raise InputError("the EPSS body is not a gzip UTF-8 file") from error
    lines = text.splitlines()
    model = score_date = ""
    if lines and lines[0].startswith("#"):
        header = _HEADER.search(lines[0])
        if header:
            model, score_date = header.group(1), header.group(2)
        lines = lines[1:]
    scores: dict[str, tuple[str, str]] = {}
    reader = csv.DictReader(lines)
    if reader.fieldnames is None or not {"cve", "epss", "percentile"} <= set(reader.fieldnames):
        raise InputError("the EPSS file has no cve,epss,percentile header")
    for record in reader:
        cve = cve_token(record.get("cve"))
        score = (record.get("epss") or "").strip()
        percentile = (record.get("percentile") or "").strip()
        if cve and _PROBABILITY.match(score) and _PROBABILITY.match(percentile):
            scores[cve] = (score, percentile)
    return scores, model, score_date


class EpssTriage:
    """The ``security.epss-scores`` implementation."""

    interface_id = "security.epss-scores"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            scores, model, score_date = read_daily(
                decode_base64(context.input.get("daily_base64"), "daily_base64")
            )
            rows = once_per(parse_rows(context.input.get("watched")), "vulnerability")
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        items: list[dict[str, Any]] = []
        scored = watched = 0
        for row in rows:
            vulnerability = row.subject("vulnerability")
            cve = cve_token(row.value("cve_id"))
            if vulnerability is None or cve is None:
                continue
            watched += 1
            found = scores.get(cve)
            if found is None:
                continue
            scored += 1
            for name in sorted(FIELDS):
                predicate, column = FIELDS[name]
                value = found[0] if column == "epss" else found[1]
                state = row.state(name)
                if state == "conflict" or (state == "present" and row.value(name) == value):
                    continue
                items.append(
                    claim_item(
                        vulnerability,
                        predicate,
                        value,
                        f"FIRST EPSS {model} scored {cve} on {score_date}: {column} = {value}.",
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
                "scored": scored,
                "model_version": model,
                "score_date": score_date,
            },
            metrics={"items": float(len(items)), "watched": float(watched)},
        )
