"""The security kit's KEV + EPSS slice in the Claim-authority form (kit pilot).

Every definition the slice installs, as the authoring payloads a fresh instance
accepts, in order:

1. ``capture-kind.*.json``: the CaptureKinds (``capture-contract propose``),
   KEV's and EPSS's bytes the origin's JSON body, verbatim (D-R25), decoded as
   JSON; their layouts wait (``capture-layout.*.json``, step 3);
2. ``vocabulary.json``: row Contracts, the ClaimTypes, the two SubjectKinds and
   the watched-vulnerabilities Query, as one change set; ``capabilities.json``:
   the kit's capabilities (``capabilities.py``);
3. ``capture-layout.*.json``: each read kind's layout, a successor that only
   adds it (a layout pins row Contracts the vocabulary holds);
4. ``procedures.json``: ``security.kev-triage`` and ``security.epss-triage``,
   their ``fetch`` slot naming the base kit's ``web.fetch@1`` /
   ``web.fetch.pages@1``, each EXTRACT a thin node over its kind's layout;
5. ``automation.json``: the consumer's Lines and Mandates (a kit carries no
   authority; the instance that adopts it authors these; the kit's automation
   template adds the Runbooks and their one daily Trigger, ``template.py``);
6. ``watch.json``: the vulnerability Subjects (state, not kit); the KEV Line
   creates the ``security.catalog/cisa-kev`` Subject on its first run.

Batch 1 (``inventory.py``) adds the SBOM import and redefines the watch list:
``security.watched_vulnerabilities`` is the applicability join (K-B1-2),
vulnerability <- component.affected_by <- an occurrence of the component holding
a scope (the pair hop, S4), one row per vulnerability with the same row
Contract, so kev-triage reads it unchanged. Every Procedure is in the template
form (D-R37): epss-triage reads its key list from ``security.watched_cve_keys``
and asks FIRST for exactly those CVEs (``web.fetch.pages``, D-R34), so a CVE
OSV adds is scored on EPSS's next run with no Line change.

Batch 2, the dependency loop (``inventory.py``, ``osv.py``, ``triage.py``): one
SBOM import Procedure writing occurrences (inventory, component) and their
scope, the OSV Line (``affected_by``), package-level and app-level not_affected
judgments on the exposure pairs, and the triage and track-record Queries.

No provider computes a Claim. ``web.fetch`` and ``web.fetch.pages``
(cruxible-provider-web, bound by the Lines) return the origins' bytes; core
extracts typed records under the CaptureKind's decoding and the claims template
writes them. Membership is
``listed_in = security.catalog/cisa-kev`` (D-R4), whose absence over a complete
catalog read is the declared inverse (D-R11, D-R24); the KEV dates mirror; the
ransomware field surfaces. EPSS decimals are typed in the extract (D-R23).

    python definitions.py OUT_DIR [--watch CVE ...] [--now ISO8601]
        [--sbom NAME=RELATIVE_PATH ...] [--seed PURL=CVE ...]
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

from capabilities import WEB_FETCH as WEB_FETCH_CAPABILITY
from capabilities import WEB_FETCH_PAGES as WEB_FETCH_PAGES_CAPABILITY
from capabilities import capability, pinned_layout

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
WATCH_KEYS_QUERY = "security.watched_cve_keys"
WATCH_KEY_ROW = "security.watched-cve-key"
KEV_PROCEDURE = "security.kev-triage"
EPSS_PROCEDURE = "security.epss-triage"
KEV_LINE = "security.kev-triage"
EPSS_LINE = "security.epss-triage"
WEB_FETCH = "cruxible-provider-web#web.fetch"
WEB_FETCH_PAGES = "cruxible-provider-web#web.fetch.pages"

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


#: The described version of each params Contract a Procedure names. Version 1 is
#: the shape core co-proposed from the Procedure's inline params (no
#: descriptions); a Contract version never changes, so the descriptions are
#: version 2, and version 1 stays in the release as its predecessor. An instance
#: that installed version 1 then takes version 2 by kit add.
PARAMS_VERSION = 2


def params_contract(procedure: str) -> str:
    """The params Contract ``procedure`` names: ``<procedure>.params@2``."""

    return f"{procedure}.params@{PARAMS_VERSION}"


def params_contract_members(
    procedure: str, description: str, fields: Mapping[str, tuple[str, str]]
) -> list[dict[str, Any]]:
    """``<procedure>.params`` version 1 (types only) and version 2 (with descriptions).

    ``fields`` maps each parameter to its type spelling and what a Line author
    must supply for it. Version 1 renders the bytes core co-proposed from the
    inline params, so an instance holding it sees it unchanged.
    """

    name = f"{procedure}.params"
    return [
        {
            "kind": "contract",
            "name": name,
            "version": 1,
            "fields": {field: spelling for field, (spelling, _text) in fields.items()},
        },
        {
            "kind": "contract",
            "name": name,
            "version": PARAMS_VERSION,
            "description": description,
            "fields": {
                field: {"type": spelling, "description": text}
                for field, (spelling, text) in fields.items()
            },
        },
    ]


# -- 1. CaptureKinds ------------------------------------------------------------------


def capture_kinds() -> dict[str, dict[str, Any]]:
    """One CaptureKind per origin document; the bytes are the body, decoded as JSON.

    A kind an EXTRACT reads declares its layout: the header fields and record
    sets of the document, which the Procedure's thin EXTRACT node names
    (``layout`` here, rows pinned by ``capabilities.pinned_layout``). KEV's and
    EPSS's layouts state the origin's format as the kit reads it.
    """

    def kind(
        name: str, *, max_bytes: int, records: int, layout: dict[str, Any]
    ) -> dict[str, Any]:
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
            "layout": pinned_layout(layout),
        }

    from inventory import capture_kinds as inventory_kinds
    from osv import capture_kinds as osv_kinds

    return {
        KEV_KIND: kind(
            KEV_KIND, max_bytes=16 * 1024 * 1024, records=100_000, layout=KEV_LAYOUT
        ),
        EPSS_KIND: kind(EPSS_KIND, max_bytes=1024 * 1024, records=1_000, layout=EPSS_LAYOUT),
        **inventory_kinds(),
        **osv_kinds(),
    }


#: The CISA KEV catalog: its version, and one record per listed CVE, counted by
#: ``/count``. ``listed_from`` reads the same ``dateAdded`` as the moment the
#: listing takes effect: 00:00 UTC that day (D-R29), for listed_in's effective_from.
KEV_LAYOUT: dict[str, Any] = {
    "header": {"catalog_version": {"at": "/catalogVersion", "presence": "required"}},
    "records": {
        "vulnerabilities": {
            "at": "/vulnerabilities/*",
            "key": {"cve_id": {"at": "cveID", "type": f"key_part<{VULN}:cve_id>"}},
            "row": f"{KEV_ROW}@1",
            "fields": {
                "date_added": {"at": "dateAdded", "parse": "date"},
                "listed_from": {"at": "dateAdded", "parse": "date", "project": "utc_start_of_day"},
                "due_date": {"at": "dueDate", "parse": "date", "presence": "optional"},
                "ransomware_use": {
                    "at": "knownRansomwareCampaignUse",
                    "canonicalize": "claim_type",
                    "presence": "optional",
                },
            },
            "count_at": "/count",
        }
    },
}
#: One FIRST EPSS API answer: one record per scored CVE. No count: a page's own
#: ``/total`` cannot speak for the merged pages a list extract reads.
EPSS_LAYOUT: dict[str, Any] = {
    "records": {
        "scores": {
            "at": "/data/*",
            "key": {"cve_id": {"at": "cve", "type": f"key_part<{VULN}:cve_id>"}},
            "row": f"{EPSS_ROW}@1",
            "fields": {
                "score": {"at": "epss", "parse": "decimal"},
                "percentile": {"at": "percentile", "parse": "decimal"},
                "date": {"at": "date", "parse": "date"},
            },
        }
    }
}


def staged_capture_kinds(
    kinds: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """``(kinds without their layouts, each layout as a successor patch)``.

    A layout pins its row Contracts, and a row may name a ClaimType that names
    the kind in its evidence rules, so an instance accepts the kinds first, the
    vocabulary next, and the layouts last (each a successor that only adds the
    layout).
    """

    first = {
        name: {key: value for key, value in record.items() if key != "layout"}
        for name, record in kinds.items()
    }
    layouts = {
        name: {"name": name, "layout": record["layout"]}
        for name, record in kinds.items()
        if record.get("layout") is not None
    }
    return first, layouts


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
    from inventory import vocabulary_members as inventory_vocabulary

    claim_types = [
        lower_claim_type_input(ClaimTypeInputRecord.model_validate(record), tree={})
        for record in claim_type_records()
    ]
    members: list[dict[str, Any]] = [
        {
            "kind": "contract",
            "name": KEV_ROW,
            "version": 1,
            "description": "One KEV catalog record: when the CVE was added, the moment it counts "
            "as listed from, its due date and its known ransomware use.",
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
            "description": "One EPSS record: a CVE's score, percentile and score date.",
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
        *subject_kind_members()[:2],
        {
            "kind": "contract",
            "name": WATCH_KEY_ROW,
            "version": 1,
            "description": "One watched vulnerability's CVE id: the EPSS extract keeps only "
            "records with these ids.",
            "fields": {"cve_id": "string"},
        },
        *inventory_vocabulary(),
        *fetch_params_members(),
    ]
    from inventory import claim_types as inventory_claim_types

    members += [
        {"kind": "query_definition", "query_definition": query}
        for query in watch_queries([*claim_types, *inventory_claim_types()])
    ]
    # -- Batch 2, dependency loop: OSV vocabulary, triage and track-record Queries.
    import osv
    import triage

    members += osv.vocabulary_members([*claim_types, *inventory_claim_types()])
    members += triage.vocabulary_members()
    # Codebase facts: the fact kind, app_exposure.rests_on and their Queries.
    import facts

    members += facts.dependency_members()
    return {
        "kind": "change_set",
        "rationale": "Security kit vocabulary: SBOM inventory (occurrences), KEV and EPSS "
        "facts, the judgment pairs, and the watch list and worklists that join them.",
        "members": members,
    }


#: The watch list (K-B1-2): a vulnerability is watched when OSV (or, until the OSV
#: Line is wired, an agent's seed) says it affects a component an imported SBOM
#: lists: an occurrence of it holding a visible scope. One row per vulnerability
#: (Subject dedupe), the same row Contract the KEV and EPSS Procedures already
#: read. A package-level judgment removes the link, so it drops V here too; an
#: app-level one does not (a Subject-shaped query takes no optional hop), so the
#: watch list may keep V for an occurrence only an app judgment silenced: KEV and
#: EPSS then keep its facts current, which is harmless.
WATCHED_SPEC: dict[str, Any] = {
    "query": WATCHED_QUERY,
    "description": "Every vulnerability that affects a component of an imported inventory.",
    "from": {"v": VULN},
    "hops": [
        {"c": "<v.security.component.affected_by!"},
        {"o": "security.occurrence{component: c}! with scope"},
    ],
    "row": f"{WATCH_ROW}@1",
    "fields": ["v.subject_kind", "v.subject_id", "v.cve_id"],
}
WATCH_KEYS_SPEC: dict[str, Any] = {
    **WATCHED_SPEC,
    "query": WATCH_KEYS_QUERY,
    "description": "The CVE id of every watched vulnerability: the ids the EPSS Procedure "
    "asks about.",
    "row": f"{WATCH_KEY_ROW}@1",
    "fields": ["v.cve_id"],
}


def subject_shaped(
    spec: Mapping[str, Any],
    claim_types: Sequence[Any],
    *,
    result_binding: str | None = None,
    subject_kinds: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """One Query, lowered against this vocabulary and made Subject-shaped.

    The authored form (``QuerySpecInput``) lowers a query with hops to one row per
    path; a list such as the watch list is one row per entry Subject, so the
    lowered definition is stated with ``result_shape: subject`` and Subject
    dedupe (every hop is required, as a Subject-shaped query needs).
    ``result_binding`` dedupes by a hop's Subject instead of the entry's (one row
    per Subject the walk reaches); ``subject_kinds`` are the SubjectKind members
    the spec names (default: the dependency loop's).
    """

    from cruxible_client.contracts.claim_types import claim_type_path, render_claim_type
    from cruxible_client.contracts.query.authored import QuerySpecInput, lower_query_spec
    from cruxible_core.service.discovery.authored_query import (
        AuthoredQueryResolver,
        candidate_query_vocabulary,
    )

    tree = {claim_type_path(t.predicate): render_claim_type(t) for t in claim_types}
    tree.update(subject_kind_tree(subject_kinds))
    resolver = AuthoredQueryResolver(candidate_query_vocabulary(tree))
    lowered = lower_query_spec(QuerySpecInput.model_validate(spec), resolver)
    wire = lowered.model_dump(mode="json", by_alias=True)
    for budget in ("default_budgets", "maximum_budgets"):
        wire[budget] = {**wire[budget], "max_paths": None, "max_paths_per_result": None}
    wire.update(result_shape="subject", dedupe="subject")
    if result_binding is not None:
        wire["result_binding"] = result_binding
    shaped = lowered.model_validate(wire)
    return shaped.model_dump(mode="json", by_alias=True)


def subject_kind_members() -> list[dict[str, Any]]:
    """Every SubjectKind the kit declares, as authoring members."""

    from inventory import subject_kind_members as inventory_kinds

    return [
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
        *inventory_kinds(),
    ]


def subject_kind_tree(members: Sequence[Mapping[str, Any]] | None = None) -> dict[str, bytes]:
    """The SubjectKinds as a candidate tree holds them: a pair hop resolves its parts
    against its kind's key. ``members`` default to the kit's dependency kinds."""

    from cruxible_client.contracts.artifacts import ArtifactIdentity
    from cruxible_client.contracts.authoring.models import SubjectKindAuthoringPayload
    from cruxible_client.contracts.subject_kinds import (
        SubjectKind,
        SubjectKindKeys,
        render_subject_kind,
        subject_kind_path,
    )

    tree: dict[str, bytes] = {}
    for member in subject_kind_members() if members is None else members:
        payload = SubjectKindAuthoringPayload.model_validate(
            {key: value for key, value in member.items() if key != "kind"}
        )
        declared = SubjectKind(
            identity=ArtifactIdentity(kind="SubjectKind", name=payload.name),
            description=payload.description,
            identity_rule=SubjectKindKeys(
                parts=payload.key_rules(), uniqueness=payload.uniqueness or "unique"
            ),
        )
        tree[subject_kind_path(payload.name)] = render_subject_kind(declared)
    return tree


def watch_queries(claim_types: Sequence[Any]) -> list[dict[str, Any]]:
    """The two watch Queries, Subject-shaped (one row per vulnerability)."""

    return [subject_shaped(spec, claim_types) for spec in (WATCHED_SPEC, WATCH_KEYS_SPEC)]


# -- 3. Procedures ----------------------------------------------------------------------

_MAX_BYTES = "int{1..33554432}"

#: What a Line on each fetching Procedure supplies, as its params Contract says it.
KEV_PARAMS = (
    "What the Line on security.kev-triage fetches: the CISA KEV catalog's URL, the most "
    "bytes to accept and the source label. It writes KEV fields only for vulnerabilities "
    "already watched (the ones OSV found affecting an inventoried component).",
    {
        "url": (
            _URL,
            "HTTP(S) URL of the CISA KEV catalog JSON (the template uses CISA's feed). When "
            "the Line lists acquisition origins, its origin must be one. The body must hold "
            "catalogVersion, count and vulnerabilities[], each with cveID and dateAdded "
            "(dueDate and knownRansomwareCampaignUse optional). The read is complete only "
            "when the records match count, and only a complete read records a watched CVE "
            "as not listed.",
        ),
        "logical_source": (
            _SOURCE,
            "Source label the catalog Capture is recorded under, lowercase (the template "
            "uses cisa.kev.catalog). Evidence requirements and landing Triggers can name it.",
        ),
        "max_bytes": (
            _MAX_BYTES,
            "The most bytes the fetch accepts from the origin, 1 to 33554432 (the template "
            "uses 4194304, 4 MiB). A larger response is refused and the run writes nothing. "
            "The catalog's CaptureKind holds at most 16 MiB, so a larger value gains "
            "nothing.",
        ),
    },
)
EPSS_PARAMS = (
    "What the Line on security.epss-triage fetches: FIRST's EPSS API URL, the most bytes "
    "per response and the source label. The Procedure sends the watched CVE ids as the "
    "cve parameter, at most 100 per request.",
    {
        "url": (
            _URL,
            "HTTP(S) URL of FIRST's EPSS API endpoint (the template uses "
            "https://api.first.org/data/v1/epss); the Procedure adds the cve parameter. When "
            "the Line lists acquisition origins, its origin must be one. Each response must "
            "be JSON with data[] rows of cve, epss, percentile and date. A failed request "
            "leaves the run incomplete; a CVE FIRST has not scored gets no score.",
        ),
        "logical_source": (
            _SOURCE,
            "Source label each response's Capture is recorded under, lowercase (the template "
            "uses first.epss.api). Evidence requirements and landing Triggers can name it.",
        ),
        "max_bytes": (
            _MAX_BYTES,
            "The most bytes accepted for each response, 1 to 33554432 (the template uses "
            "4194304, 4 MiB). A larger response is refused and left out, so the run is "
            "incomplete. Each response's CaptureKind holds at most 1 MiB.",
        ),
    },
)


def fetch_params_members() -> list[dict[str, Any]]:
    """The KEV and EPSS params Contracts, versions 1 and 2 (``params_contract_members``)."""

    return [
        *params_contract_members(KEV_PROCEDURE, *KEV_PARAMS),
        *params_contract_members(EPSS_PROCEDURE, *EPSS_PARAMS),
    ]


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


def _spec(
    name: str,
    description: str,
    steps: list[dict[str, Any]],
    *,
    fetch: str = WEB_FETCH_CAPABILITY,
) -> dict[str, Any]:
    return refs(
        {
            "procedure": name,
            "description": description,
            "input": {},
            "output": {},
            "parameter_contract": params_contract(name),
            "slots": {"fetch": {"capability": capability(fetch)}},
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
        "Read the CISA KEV catalog and write, for each watched CVE, whether it is listed, its "
        "dates and its ransomware use; only a complete read records a CVE as not listed.",
        [
            _fetch("catalog", KEV_KIND),
            {"read": "watched", "query": WATCHED_QUERY},
            {
                "extract": "entries",
                "capture": "$steps.catalog.capture",
                "records": "vulnerabilities",
                "header": ["catalog_version"],
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
                        # The catalog Subject is created on the first run that
                        # names it, so a fresh instance needs no seed.
                        "value": {
                            "kind": CATALOG,
                            "key": {"catalog_id": "cisa-kev"},
                            "create": "if_absent",
                        },
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


#: The EPSS query parameter the watched CVE ids go in, comma-joined (``cve=A,B``).
EPSS_PARAM = "cve"
#: FIRST answers at most 100 rows per request (its default ``limit``). A list
#: extract declares no ``complete_when`` (one page's ``/total`` cannot speak for
#: the merged pages), so no page asks for more than 100 CVEs: 100 of the shortest
#: CVE ids (13 characters, plus a comma between) fill exactly this many
#: characters of ``EPSS_API?cve=...``; a 101st needs 14 more. A longer base URL,
#: or longer ids, only fit fewer.
EPSS_MAX_URL_CHARS = len(EPSS_API) + len("?cve=") + 13 + 99 * 14


def epss_spec() -> dict[str, Any]:
    """Ask FIRST's EPSS API for exactly the watched CVEs, in as few pages as fit.

    ``web.fetch.pages`` sends the watched CVE ids read from state as the ``cve``
    parameter, comma-joined, split across pages of at most 100 ids; each page's
    body is its own Capture. The extract reads every page's records; a page that
    failed is left out and the call is incomplete, which the run reports.
    """

    within = "$steps.watched.rows"
    return _spec(
        EPSS_PROCEDURE,
        "Ask FIRST's EPSS API for the watched CVEs and write each one's score, "
        "percentile and score date.",
        [
            {"read": "watched", "query": WATCHED_QUERY},
            {"read": "watch_keys", "query": WATCH_KEYS_QUERY},
            {
                "call": "scores_api",
                "slot": "fetch",
                "captures": {"captures": EPSS_KIND},
                "input": {
                    "url": "$params.url",
                    "page_param": EPSS_PARAM,
                    "query": [
                        {
                            "name": EPSS_PARAM,
                            "values": "$steps.watch_keys.rows.[*].cve_id",
                            "join": "comma",
                        }
                    ],
                    "max_url_chars": EPSS_MAX_URL_CHARS,
                    "logical_source": "$params.logical_source",
                    "expected_format": "json",
                    "max_bytes": "$params.max_bytes",
                },
            },
            {
                "extract": "scores",
                "capture": "$steps.scores_api.captures",
                "records": "scores",
                "only_keys": "$steps.watch_keys.rows",
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
        fetch=WEB_FETCH_PAGES_CAPABILITY,
    )


def procedures() -> dict[str, Any]:
    import osv
    import triage
    from inventory import procedure_members

    members = [
        *procedure_members(),
        *({"kind": "procedure", "spec": spec} for spec in (kev_spec(), epss_spec())),
        # -- Batch 2, dependency loop: the OSV Procedure.
        *osv.procedure_members(),
        # The worklist's urgent pairs to the Line inbox: one Procedure per state, and
        # the unjudged one again for a single inventory.
        *({"kind": "procedure", "spec": spec} for spec in triage.attention_procedures()),
    ]
    for member in members:
        ProcedureInput.model_validate(member)
    return {
        "kind": "change_set",
        "rationale": "Security kit: SBOM import, KEV and EPSS triage as declared extract + claims.",
        "members": members,
    }


# -- 4. Automation (the consumer's Lines and Mandates) -----------------------------------

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


def automation(
    watch: Sequence[str],
    *,
    now: datetime,
    settle: bool = True,
    sboms: Sequence[tuple[str, str]] = (),
    osv_line: bool = True,
) -> dict[str, Any]:
    """The consumer's Lines and their Mandates: KEV and EPSS (EPSS asks for the CVEs
    the watch list holds at run time), one SBOM import Line per (name, workspace
    path) in ``sboms``, and the OSV Line. ``watch`` is unused: no Line names a CVE.

    No Line has a Trigger of its own: the automation template (``template.py``)
    runs OSV, KEV and EPSS on one daily Trigger aimed at its maintenance Runbook."""
    valid_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    del watch
    lines = (
        (KEV_LINE, KEV_PROCEDURE, KEV_URL, KEV_SOURCE, "https://www.cisa.gov", KEV_SETTLE_SCOPE),
        (
            EPSS_LINE,
            EPSS_PROCEDURE,
            EPSS_API,
            EPSS_SOURCE,
            "https://api.first.org",
            EPSS_SETTLE_SCOPE,
        ),
    )
    fetch = {
        KEV_LINE: ("catalog.capture", WEB_FETCH),
        EPSS_LINE: ("scores_api.captures", WEB_FETCH_PAGES),
    }
    members: list[dict[str, Any]] = []
    for line, procedure, url, source, origin, scope in lines:
        output, binding = fetch[line]
        members.append(
            {
                "kind": "line",
                "name": line,
                "procedure_name": procedure,
                "bindings": {"fetch": binding},
                "parameters": {"url": url, "logical_source": source, "max_bytes": 4 * 1024 * 1024},
                "acquisition": {output: {"origins": [origin]}},
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
                # KEV creates the catalog Subject its listed_in names.
                "namespace": ["claims", "subjects"] if line == KEV_LINE else ["claims"],
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
                    **({"subject_creation": [CATALOG]} if line == KEV_LINE else {}),
                    "scope": [
                        {"claim_type": claim_type, "changes": changes}
                        for claim_type, changes in scope.items()
                    ],
                }
            )
    from inventory import sbom_automation

    members += sbom_automation(sboms, now=now)
    # -- Batch 2, dependency loop: the OSV Line.
    if osv_line:
        import osv

        members += osv.automation(now=now, findings=FINDINGS, settle=settle)
    import triage

    members += triage.attention_automation()
    return {
        "kind": "change_set",
        "rationale": "Adopt the SBOM import, OSV, KEV and EPSS Lines.",
        "members": members,
    }


# -- 5. Watched Subjects (state) ----------------------------------------------------------


def watch_subjects(watch: Sequence[str]) -> dict[str, Any]:
    # No catalog Subject: the KEV Line creates security.catalog/cisa-kev itself.
    members: list[dict[str, Any]] = [
        {
            "kind": "subject",
            "subject_kind": VULN,
            "key": {VULN + ".cve_id": cve},
            "rationale": "Watched by the security kit pilot.",
        }
        for cve in watch
    ]
    return {"kind": "change_set", "rationale": "Watch the pilot's CVEs.", "members": members}


def seed_affected_by(pairs: Sequence[tuple[str, str]], *, reason: str) -> dict[str, Any]:
    """A SEED: agents' own-word affected_by Claims (component purl, CVE id).

    The pilot gate's stand-in components are not real packages, so OSV says
    nothing about them; this states ``security.component.affected_by`` in the
    agent's own words (normative, self-source), labelled as a seed. A real
    instance has the OSV Line instead.
    """

    from inventory import COMPONENT

    members: list[dict[str, Any]] = []
    for purl, cve in pairs:
        said = f"seed: {purl} is affected by {cve} ({reason})"
        members.append(
            {
                "kind": "claim",
                "subject": {"subject_kind": COMPONENT, "key": {COMPONENT + ".purl": purl}},
                "predicate": COMPONENT + ".affected_by",
                "object": {
                    "kind": "subject",
                    "subject": {"subject_kind": VULN, "key": {VULN + ".cve_id": cve}},
                },
                "role": "normative",
                "rationale": f"Seed, not OSV: {cve} affects {purl} ({reason}).",
                "source": {"kind": "self_source", "body": said + "\n"},
            }
        )
    return {
        "kind": "change_set",
        "rationale": "Seed affected_by until the OSV Line is wired (labelled seed).",
        "members": members,
    }


def write_all(
    out: Path,
    *,
    watch: Sequence[str],
    now: datetime,
    sboms: Sequence[tuple[str, str]] = (),
    seeds: Sequence[tuple[str, str]] = (),
) -> list[Path]:
    import capabilities
    import findings

    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    # Every kit kind (the capabilities name the SARIF kinds too); the SARIF layouts
    # wait for the findings vocabulary (findings.write_all).
    kinds, _ = staged_capture_kinds({**capture_kinds(), **findings.capture_kinds()})
    _, layouts = staged_capture_kinds(capture_kinds())
    for prefix, records in (("capture-kind", kinds), ("capture-layout", layouts)):
        for name, record in records.items():
            path = out / f"{prefix}.{name}.json"
            path.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
            written.append(path)
    vulnerabilities = list(dict.fromkeys([*watch, *(cve for _purl, cve in seeds)]))
    payloads = [
        ("vocabulary", vocabulary()),
        ("capabilities", capabilities.change_set()),
        ("procedures", procedures()),
        ("automation", automation(vulnerabilities, now=now, sboms=sboms)),
        ("watch", watch_subjects(vulnerabilities)),
    ]
    if seeds:
        payloads.append(("seed", seed_affected_by(seeds, reason="recorded OSV answer")))
    for name, payload in payloads:
        ChangeSetInput.model_validate(payload)
        path = out / f"{name}.json"
        path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--watch", nargs="*", default=[], help="CVE ids to create as Subjects")
    parser.add_argument("--now", default=None, help="ISO-8601 instant Mandates start from")
    parser.add_argument(
        "--sbom", nargs="*", default=[], help="NAME=RELATIVE_PATH: one import Line per SBOM"
    )
    parser.add_argument(
        "--seed", nargs="*", default=[], help="PURL=CVE: an own-word affected_by seed"
    )
    args = parser.parse_args()
    now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    sboms = [tuple(item.split("=", 1)) for item in args.sbom]
    seeds = [tuple(item.split("=", 1)) for item in args.seed]
    for path in write_all(
        args.out,
        watch=args.watch,
        now=now.replace(microsecond=0),
        sboms=sboms,  # type: ignore[arg-type]
        seeds=seeds,  # type: ignore[arg-type]
    ):
        print(path)


if __name__ == "__main__":
    main()
