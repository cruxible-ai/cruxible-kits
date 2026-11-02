"""The security kit's KEV + EPSS slice in the Claim-authority form (kit pilot).

Every definition the slice installs, as the authoring payloads a fresh instance
accepts, in order:

1. ``capture-kinds/*.json``: the two CaptureKinds (``capture-contract propose``)
   whose bytes are the origin's JSON body, verbatim (D-R25), decoded as JSON;
2. ``vocabulary.json``: row Contracts, the ClaimTypes, the two SubjectKinds and
   the watched-vulnerabilities Query, as one change set;
3. ``procedures.json``: ``security.kev-triage`` and ``security.epss-triage``;
4. ``automation.json``: the consumer's Lines, Mandates and Triggers (a kit
   carries no authority; the instance that adopts it authors these);
5. ``watch.json``: the ``security.catalog/cisa-kev`` Subject and the watched
   vulnerability Subjects (state, not kit).

No provider computes a Claim. ``web.fetch`` (cruxible-provider-web, bound by
the Line) returns the catalog bytes; core extracts typed records under the
CaptureKind's decoding and the claims template writes them. Membership is
``listed_in = security.catalog/cisa-kev`` (D-R4), whose absence over a complete
catalog read is the declared inverse (D-R11, D-R24); the KEV dates mirror; the
ransomware field surfaces. EPSS decimals are typed in the extract (D-R23).

    python definitions.py OUT_DIR [--watch CVE ...] [--now ISO8601]
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cruxible_client.contracts.authoring.inputs import ChangeSetInput, ProcedureInput
from cruxible_client.contracts.refs import ref_from_graph_text
from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input

VULN = "security.vulnerability"
CATALOG = "security.catalog"
KEV_KIND = "security.kev-catalog"
EPSS_KIND = "security.epss-scores"
KEV_SOURCE = "cisa.kev.catalog"
EPSS_SOURCE = "first.epss.api"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
#: The KEV record row. (``security.kev-entry@1``, the first pilot shape, had no
#: ``listed_from``; an accepted Contract version never changes, so the reshaped
#: row is a new name rather than an edit.)
KEV_ROW = "security.kev-record"
EPSS_ROW = "security.epss-row"
WATCH_ROW = "security.watched-vulnerability"
WATCHED_QUERY = "security.watched_vulnerabilities"
KEV_PROCEDURE = "security.kev-triage"
EPSS_PROCEDURE = "security.epss-triage"
KEV_LINE = "security.kev-triage"
EPSS_LINE = "security.epss-triage"
WEB_FETCH = "cruxible-provider-web#web.fetch"

#: The pilot's default watch list: listed in KEV (all but the last two), and
#: two CVEs the catalog does not list, whose absence the complete read proves.
DEFAULT_WATCH = (
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-4863",  # libwebp
    "CVE-2014-0160",  # Heartbleed
    "CVE-2017-0144",  # EternalBlue
    "CVE-2019-0708",  # BlueKeep
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2021-26855",  # ProxyLogon
    "CVE-2024-3094",  # xz backdoor: not in KEV
    "CVE-2023-38545",  # curl SOCKS5: not in KEV
)

_CVE_PATTERN = "^CVE-[0-9]{4}-[0-9]{4,}$"
_URL = 'string{pattern: "^[Hh][Tt][Tt][Pp][Ss]?://\\\\S+$"}'
_SOURCE = 'string{pattern: "^[a-z][a-z0-9_.-]{0,255}$"}'


def refs(value: Any) -> Any:
    """Every ``$steps``/``$item``/``$params`` string as the typed reference it names."""

    if isinstance(value, str):
        found = ref_from_graph_text(value)
        return value if found is None else found.model_dump(mode="json", by_alias=True)
    if isinstance(value, Mapping):
        return {key: refs(member) for key, member in value.items()}
    if isinstance(value, list | tuple):
        return [refs(member) for member in value]
    return value


# -- 1. CaptureKinds ------------------------------------------------------------------


def capture_kinds() -> dict[str, dict[str, Any]]:
    """One CaptureKind per origin document; the bytes are the body, decoded as JSON."""

    def kind(name: str, *, max_bytes: int, records: int) -> dict[str, Any]:
        return {
            "name": name,
            "shape": "http_response",
            "grade": "observed",
            "replay": "attested",
            "retention": "P400D",
            "erasable": False,
            "max_bytes": max_bytes,
            "selector_privacy": "direct_allowed",
            "decoding": {
                "format": "json",
                "encoding": "identity",
                "limits": {"decoded_bytes": max_bytes, "depth": 16, "records": records},
            },
        }

    return {
        KEV_KIND: kind(KEV_KIND, max_bytes=16 * 1024 * 1024, records=100_000),
        EPSS_KIND: kind(EPSS_KIND, max_bytes=1024 * 1024, records=1_000),
    }


# -- 2. Vocabulary ----------------------------------------------------------------------


def _captured(rule: str, kind: str) -> dict[str, Any]:
    return {
        "rules": [
            {
                "rule_id": rule,
                "claim_roles": ["observation"],
                "capture_contracts": [kind],
                "admission": "direct",
                "subject_binding": "exact_claim_subject",
            }
        ]
    }


def _observation(
    predicate: str,
    value: Mapping[str, Any],
    description: str,
    *,
    rule: str,
    kind: str,
    **changes: Any,
) -> dict[str, Any]:
    return {
        "predicate": predicate,
        "allowed_subject_kinds": [VULN],
        "cardinality": "one",
        "value": dict(value),
        "description": description,
        "permitted_roles": ["observation"],
        "default_role": "observation",
        "evidence_requirement": "captured",
        "revision_evidence": "replace",
        "evidence_admission_policy": _captured(rule, kind),
        **changes,
    }


def claim_type_records() -> list[dict[str, Any]]:
    date = {"kind": "date"}
    unit = {"kind": "decimal", "min": "0", "max": "1"}
    return [
        {
            "predicate": VULN + ".cve_id",
            "allowed_subject_kinds": [VULN],
            "cardinality": "one",
            "value": {"kind": "string", "pattern": _CVE_PATTERN, "max_len": 32},
            "description": "The CVE identifier; the vulnerability's key.",
        },
        {
            "predicate": CATALOG + ".catalog_id",
            "allowed_subject_kinds": [CATALOG],
            "cardinality": "one",
            "value": {"kind": "string", "pattern": "^[a-z][a-z0-9-]{0,63}$", "max_len": 64},
            "description": "The catalog's short id, e.g. cisa-kev; the catalog's key.",
        },
        _observation(
            VULN + ".listed_in",
            {"kind": "subject", "subject_kinds": [CATALOG]},
            "A catalog that lists the vulnerability, from the catalog's own retained "
            "document; none of a catalog means a complete read of it did not list it.",
            rule="kev-catalog",
            kind=KEV_KIND,
            cardinality="many",
            resolution_policy={
                "cardinality": "many",
                "eligible_verdicts": ["supported"],
                "selector": "all",
            },
            inverse={"key": {"kind": "object"}, "evidence_rules": ["kev-catalog"]},
        ),
        _observation(
            VULN + ".kev_date_added",
            date,
            "The date CISA added the vulnerability to the KEV catalog (dateAdded).",
            rule="kev-catalog",
            kind=KEV_KIND,
        ),
        _observation(
            VULN + ".kev_due_date",
            date,
            "The KEV remediation due date for federal agencies (dueDate).",
            rule="kev-catalog",
            kind=KEV_KIND,
        ),
        _observation(
            VULN + ".kev_ransomware_use",
            {"kind": "enum", "members": ["Known", "Unknown"]},
            "Whether KEV reports known ransomware campaign use (knownRansomwareCampaignUse).",
            rule="kev-catalog",
            kind=KEV_KIND,
        ),
        _observation(
            VULN + ".epss_score",
            unit,
            "FIRST's EPSS probability of exploitation in the next 30 days (epss).",
            rule="epss-api",
            kind=EPSS_KIND,
        ),
        _observation(
            VULN + ".epss_percentile",
            unit,
            "The EPSS score's percentile among all scored CVEs (percentile).",
            rule="epss-api",
            kind=EPSS_KIND,
        ),
        _observation(
            VULN + ".epss_score_date",
            date,
            "The date FIRST computed the EPSS score and percentile (date).",
            rule="epss-api",
            kind=EPSS_KIND,
        ),
    ]


def vocabulary() -> dict[str, Any]:
    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    members: list[dict[str, Any]] = [
        {
            "kind": "contract",
            "name": KEV_ROW,
            "version": 1,
            "description": "One KEV catalog record's fields the slice writes.",
            "fields": {
                "date_added": "date",
                "listed_from": "datetime",
                "due_date": "date?",
                "ransomware_use": f"enum_of {VULN}.kev_ransomware_use?",
            },
        },
        {
            "kind": "contract",
            "name": EPSS_ROW,
            "version": 1,
            "description": "One EPSS API record, typed in the extract (D-R23).",
            "fields": {"score": "decimal{0..1}", "percentile": "decimal{0..1}", "date": "date"},
        },
        {
            "kind": "contract",
            "name": WATCH_ROW,
            "version": 1,
            "description": "One watched vulnerability: its Subject and CVE id.",
            "fields": {"subject_kind": "string", "subject_id": "string", "cve_id": "string"},
        },
        *(
            {"kind": "claim_type", "claim_type": t.model_dump(mode="json", by_alias=True)}
            for t in claim_types
        ),
        {
            "kind": "subject_kind",
            "name": VULN,
            "description": "A CVE, named by its id.",
            "keys": [VULN + ".cve_id"],
        },
        {
            "kind": "subject_kind",
            "name": CATALOG,
            "description": "A published vulnerability catalog (e.g. cisa-kev), named by its id.",
            "keys": [CATALOG + ".catalog_id"],
        },
        {
            "kind": "query_definition",
            "query_definition": {
                "query": WATCHED_QUERY,
                "description": "Every vulnerability this instance tracks, with its CVE id.",
                "from": {"v": VULN},
                "row": f"{WATCH_ROW}@1",
                "fields": ["v.subject_kind", "v.subject_id", "v.cve_id"],
            },
        },
    ]
    return {
        "kind": "change_set",
        "rationale": "Security kit pilot vocabulary: KEV and EPSS facts about watched CVEs.",
        "members": members,
    }


# -- 3. Procedures ----------------------------------------------------------------------


def _fetch(alias: str, kind: str) -> dict[str, Any]:
    return {
        "call": alias,
        "slot": "fetch",
        "captures": {"capture": kind},
        "input": {
            "url": "$params.url",
            "logical_source": "$params.logical_source",
            "expected_format": "json",
            "max_bytes": "$params.max_bytes",
        },
    }


def _spec(name: str, description: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
    return refs(
        {
            "procedure": name,
            "description": description,
            "input": {},
            "output": {},
            "params": {
                "url": _URL,
                "logical_source": _SOURCE,
                "max_bytes": "int{1..33554432}",
            },
            "slots": {
                "fetch": {
                    "in": "web.fetch.request@1",
                    "out": "web.fetch.result@1",
                    "effect": "external_read",
                }
            },
            "hard_caps": {
                "wall_clock": "PT5M",
                "provider_calls": 1,
                "capture_bytes": 16 * 1024 * 1024,
                "items": 20_000,
                "read_rows": 50_000,
                "repeat_attempts": 1,
            },
            "steps": steps,
        }
    )


def kev_spec() -> dict[str, Any]:
    within = "$steps.watched.rows"
    version = "{$steps.entries.header.catalog_version}"
    return _spec(
        KEV_PROCEDURE,
        "Read the CISA KEV catalog and write each watched CVE's catalog membership, "
        "dates and ransomware use; a complete read records the unlisted ones.",
        [
            _fetch("catalog", KEV_KIND),
            {"read": "watched", "query": WATCHED_QUERY},
            {
                "extract": "entries",
                "capture": "$steps.catalog.capture",
                "records": "/vulnerabilities/*",
                "row": f"{KEV_ROW}@1",
                "key": {"cve_id": {"at": "cveID", "type": f"key_part<{VULN}:cve_id>"}},
                "complete_when": {"count_at": "/count"},
                "duplicates": "refuse_key",
                "fields": {
                    "date_added": {"at": "dateAdded", "parse": "date"},
                    # The same dateAdded, as the moment the listing takes effect:
                    # 00:00 UTC that day (D-R29), for listed_in's effective_from.
                    "listed_from": {
                        "at": "dateAdded",
                        "parse": "date",
                        "project": "utc_start_of_day",
                    },
                    "due_date": {"at": "dueDate", "parse": "date", "presence": "optional"},
                    "ransomware_use": {
                        "at": "knownRansomwareCampaignUse",
                        "canonicalize": "claim_type",
                        "presence": "optional",
                    },
                },
                "header": {
                    "catalog_version": {"at": "/catalogVersion", "presence": "required"},
                },
            },
            {
                "id": "write",
                "for_each": "$steps.entries.records",
                "subject": {
                    "kind": VULN,
                    "key": {"cve_id": "$item.key.cve_id"},
                    "create": "never",
                    "within": within,
                },
                "expect": within,
                "claims": [
                    {
                        "type": VULN + ".listed_in",
                        "value": {"kind": CATALOG, "key": {"catalog_id": "cisa-kev"}},
                        "effective_from": "$item.fields.listed_from",
                        "when_absent": "inverse",
                        "rationale": f"CISA KEV catalog {version} lists {{$item.key.cve_id}}.",
                    },
                    {
                        "type": VULN + ".kev_date_added",
                        "value": "$item.fields.date_added",
                        "when_absent": "mirror",
                        "rationale": f"CISA KEV catalog {version}: dateAdded "
                        "{$item.fields.date_added}.",
                    },
                    {
                        "type": VULN + ".kev_due_date",
                        "value": "$item.fields.due_date",
                        "when_absent": "mirror",
                        "rationale": f"CISA KEV catalog {version}: dueDate {{$item.fields.due_date}}.",
                    },
                    {
                        "type": VULN + ".kev_ransomware_use",
                        "value": "$item.fields.ransomware_use",
                        "when_absent": "surface",
                        "rationale": f"CISA KEV catalog {version}: knownRansomwareCampaignUse "
                        "{$item.fields.ransomware_use}.",
                    },
                ],
            },
        ],
    )


def epss_spec() -> dict[str, Any]:
    within = "$steps.watched.rows"
    return _spec(
        EPSS_PROCEDURE,
        "Read FIRST's EPSS API answer for the watched CVEs and write each one's score, "
        "percentile and score date.",
        [
            _fetch("scores_api", EPSS_KIND),
            {"read": "watched", "query": WATCHED_QUERY},
            {
                "transform": "watch_keys",
                "kind": "shape",
                "spec": {
                    "input": within,
                    "fields": {"cve_id": {"from": "$item.fields.cve_id"}},
                },
            },
            {
                "extract": "scores",
                "capture": "$steps.scores_api.capture",
                "records": "/data/*",
                "row": f"{EPSS_ROW}@1",
                "key": {"cve_id": {"at": "cve", "type": f"key_part<{VULN}:cve_id>"}},
                "complete_when": {"count_at": "/total"},
                "only_keys": "$steps.watch_keys.rows",
                "fields": {
                    "score": {"at": "epss", "parse": "decimal"},
                    "percentile": {"at": "percentile", "parse": "decimal"},
                    "date": {"at": "date", "parse": "date"},
                },
            },
            {
                "id": "write",
                "for_each": "$steps.scores.records",
                "subject": {
                    "kind": VULN,
                    "key": {"cve_id": "$item.key.cve_id"},
                    "create": "never",
                    "within": within,
                },
                "claims": [
                    {
                        "type": VULN + ".epss_score",
                        "value": "$item.fields.score",
                        "rationale": "FIRST EPSS on {$item.fields.date}: epss "
                        "{$item.fields.score}.",
                    },
                    {
                        "type": VULN + ".epss_percentile",
                        "value": "$item.fields.percentile",
                        "rationale": "FIRST EPSS on {$item.fields.date}: percentile "
                        "{$item.fields.percentile}.",
                    },
                    {
                        "type": VULN + ".epss_score_date",
                        "value": "$item.fields.date",
                        "rationale": "FIRST EPSS scored this CVE on {$item.fields.date}.",
                    },
                ],
            },
        ],
    )


def procedures() -> dict[str, Any]:
    members = [{"kind": "procedure", "spec": spec} for spec in (kev_spec(), epss_spec())]
    for member in members:
        ProcedureInput.model_validate(member)
    return {
        "kind": "change_set",
        "rationale": "Security kit pilot: KEV and EPSS triage as declared extract + claims.",
        "members": members,
    }


# -- 4. Automation (the consumer's Lines, Mandates, Triggers) ----------------------------

#: Findings each Line routes to its inbox (D-R10); everything else stays in the run report.
FINDINGS = [
    "extract_refused",
    "duplicate_key",
    "incomplete_source",
    "held_disagrees",
    "slot_contested",
    "claim_not_in_source",
]

#: KEV settles by basis (B4c): records create and revise on the extracted record;
#: the complete read's absence writes and revises the inverse and retires the dates.
KEV_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    VULN + ".listed_in": {
        "create": {"basis": ["extracted", "absence"]},
        "revise": {"basis": ["extracted", "absence"]},
    },
    VULN + ".kev_date_added": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    },
    VULN + ".kev_due_date": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
        "retire": {"basis": ["absence"]},
    },
    VULN + ".kev_ransomware_use": {
        "create": {"basis": ["extracted"]},
        "revise": {"basis": ["extracted"]},
    },
}
#: EPSS is clean: records create and revise on the extracted record, nothing else.
EPSS_SETTLE_SCOPE: dict[str, dict[str, Any]] = {
    VULN + predicate: {"create": {"basis": ["extracted"]}, "revise": {"basis": ["extracted"]}}
    for predicate in (".epss_score", ".epss_percentile", ".epss_score_date")
}


def epss_url(watch: Sequence[str]) -> str:
    return f"{EPSS_API}?cve={','.join(watch)}"


def automation(watch: Sequence[str], *, now: datetime, settle: bool = True) -> dict[str, Any]:
    valid_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    lines = (
        (KEV_LINE, KEV_PROCEDURE, KEV_URL, KEV_SOURCE, "https://www.cisa.gov", KEV_SETTLE_SCOPE),
        (
            EPSS_LINE,
            EPSS_PROCEDURE,
            epss_url(watch),
            EPSS_SOURCE,
            "https://api.first.org",
            EPSS_SETTLE_SCOPE,
        ),
    )
    alias = {KEV_LINE: "catalog", EPSS_LINE: "scores_api"}
    members: list[dict[str, Any]] = []
    for line, procedure, url, source, origin, scope in lines:
        members.append(
            {
                "kind": "line",
                "name": line,
                "procedure_name": procedure,
                "bindings": {"fetch": WEB_FETCH},
                "parameters": {"url": url, "logical_source": source, "max_bytes": 4 * 1024 * 1024},
                "acquisition": {f"{alias[line]}.capture": {"origins": [origin]}},
                "findings": {"inbox": FINDINGS},
                "max_authority": "settle" if settle else "propose",
            }
        )
        members.append(
            {
                "kind": "procedure_mandate",
                "name": line + "-propose",
                "line_name": line,
                "grants": "propose",
                "namespace": ["claims"],
                "valid_from": valid_from,
                "expires_at": expires_at,
            }
        )
        if settle:
            members.append(
                {
                    "kind": "procedure_mandate",
                    "name": line + "-settle",
                    "line_name": line,
                    "grants": "settle",
                    "namespace": ["claims"],
                    "valid_from": valid_from,
                    "expires_at": expires_at,
                    "subjects": "expected",
                    "scope": [
                        {"claim_type": claim_type, "changes": changes}
                        for claim_type, changes in scope.items()
                    ],
                }
            )
    members += [
        {
            "kind": "trigger",
            "name": "security.kev-daily",
            "line_name": KEV_LINE,
            "schedule": {"kind": "cron", "expression": "15 18 * * *"},
        },
        {
            "kind": "trigger",
            "name": "security.epss-daily",
            "line_name": EPSS_LINE,
            "schedule": {"kind": "cron", "expression": "30 14 * * *"},
        },
    ]
    return {
        "kind": "change_set",
        "rationale": "Adopt the KEV and EPSS Lines: web.fetch from cisa.gov and api.first.org.",
        "members": members,
    }


# -- 5. Watched Subjects (state) ----------------------------------------------------------


def watch_subjects(watch: Sequence[str]) -> dict[str, Any]:
    members: list[dict[str, Any]] = [
        {
            "kind": "subject",
            "subject_kind": CATALOG,
            "key": {CATALOG + ".catalog_id": "cisa-kev"},
            "rationale": "The CISA Known Exploited Vulnerabilities catalog.",
        }
    ]
    members += [
        {
            "kind": "subject",
            "subject_kind": VULN,
            "key": {VULN + ".cve_id": cve},
            "rationale": "Watched by the security kit pilot.",
        }
        for cve in watch
    ]
    return {"kind": "change_set", "rationale": "Watch the pilot's CVEs.", "members": members}


def write_all(out: Path, *, watch: Sequence[str], now: datetime) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, record in capture_kinds().items():
        path = out / f"capture-kind.{name}.json"
        path.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
        written.append(path)
    for name, payload in (
        ("vocabulary", vocabulary()),
        ("procedures", procedures()),
        ("automation", automation(watch, now=now)),
        ("watch", watch_subjects(watch)),
    ):
        ChangeSetInput.model_validate(payload)
        path = out / f"{name}.json"
        path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--watch", nargs="*", default=list(DEFAULT_WATCH))
    parser.add_argument("--now", default=None, help="ISO-8601 instant Mandates start from")
    args = parser.parse_args()
    now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    for path in write_all(args.out, watch=args.watch, now=now.replace(microsecond=0)):
        print(path)


if __name__ == "__main__":
    main()
