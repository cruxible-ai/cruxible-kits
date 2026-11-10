"""Triage worklists and the judgment track record, as Queries (K-B2-1, K-B2-TR).

No Procedure writes any of this: an agent reads the worklists, judges, and its
judgment is ordinary state. Every worklist row is one occurrence (an
inventory's component) a vulnerability affects, reached through the pair hops
(S4): vulnerability <- ``affected_by`` <- component -> its occurrences holding a
visible ``scope`` -> inventory.

- ``security.urgent_exposures``: every (inventory, component, vulnerability)
  exposure nobody has judged, KEV-listed first (``kev_date_added`` present),
  then by EPSS score.
- ``security.kev_triage_backlog``: the KEV-listed exposures nobody has judged.
- ``security.confirmed_exposures``: the exposures an agent judged ``affected``
  whose occurrence is still present (its SBOM still lists the component): the
  confirmed, fix-pending work, with the same KEV and EPSS facts.
- ``security.covered_app_exposures`` / ``security.covered_package_exposures`` /
  ``security.came_back_exposures``: the exposure counts with the two above
  (:func:`exposure_counts`): covered, new, confirmed and came back.
- ``security.not_affected_judgments`` / ``security.app_not_affected_judgments``:
  the track record: every package-level and app-level judgment with its VEX
  justification. ``get <claim> --detail history`` on its Claims gives who
  stated it and when; a source that later disagrees surfaces as a
  ``held_disagrees`` finding in the OSV Line's inbox.

An exposure is affected unless a judgment holds (D-R46 R4), and it stays in
the worklists until an agent judges it:

- a **package-level** judgment (:func:`judgment`, one write): OSV's
  observation of V on the component retires, "affected_by none of V" is
  stated (normative, own words, K-B2-J1), and the pair ``security.exposure``
  (component, V) gets ``justification = vulnerable_code_not_present``. The
  none removes the link, so V leaves every inventory's worklists for that
  component (it is the same package release everywhere);
- an **app-level** judgment (:func:`app_judgment`, one write): the pair
  ``security.app_exposure`` (occurrence, V) gets one of the four app-level
  justifications. It silences that occurrence only and never states the
  global none;
- an **affected** verdict (:func:`affected_judgment`, one write): the pair
  ``security.app_exposure`` (occurrence, V) gets ``verdict = affected``,
  citing the reachability evidence (the code that reaches the vulnerable
  function), and NO justification. The pair moves from the worklists to
  ``security.confirmed_exposures``. Confirmed-affected is always app-level:
  the package-level pair holds only ``vulnerable_code_not_present``.

Each judgment is one write: it lands or refuses as a whole.

The rule that reads the judgment pairs is one place (``_PACKAGE_NOT_AFFECTED``,
``_APP_NOT_AFFECTED``, ``_APP_AFFECTED``), and a judgment counts only when its
value is RESOLVED (one uncontested, supported value): a resolved justification
is not_affected when the pair holds no verdict or a resolved ``not_affected``
verdict (optional; it is how a reversal revises an affected verdict in place),
and a resolved ``verdict = affected`` with no justification is affected.
Anything else on the pair -- a contested verdict or justification, affected
beside a justification, or not_affected with none -- is no judgment, so the
pair stays in the worklists and in neither track record: a contradictory or
contested write can never silence a row.

**Under investigation** (K-CF1) is no judgment: the agent attests ``unsure``
on OSV's ``affected_by`` Claim (:func:`investigation`), with its reason
(``--because`` or a cited section) and a ``valid_until`` at most 14 days ahead,
or the end of the KEV due date if that is sooner and still in the future
(:func:`hold_until`). The pair stays in the worklists and the KEV backlog;
reading that one Claim's evidence (:func:`under_investigation`) marks the row.

Judgments are agents' alone: no Mandate settles a justification, a verdict or the none,
and review is on the honor system (K-CF2a): the author writes with
``accept: never`` and a different agent approves after reading the dependency
guidance (``../guidance/dependency.md``).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Literal

from definitions import VULN
from inventory import (
    APP_EXPOSURE,
    APP_JUSTIFICATIONS,
    APP_VERDICTS,
    COMPONENT,
    EXPOSURE,
    INVENTORY,
    OCCURRENCE,
    PACKAGE_JUSTIFICATIONS,
    SCOPE,
)

URGENT = "security.urgent_exposures"
BACKLOG = "security.kev_triage_backlog"
JUDGMENTS = "security.not_affected_judgments"
APP_JUDGMENTS = "security.app_not_affected_judgments"
CONFIRMED = "security.confirmed_exposures"
COVERED_APP = "security.covered_app_exposures"
COVERED_PACKAGE = "security.covered_package_exposures"
CAME_BACK = "security.came_back_exposures"
UNJUDGED = "security.unjudged_exposures"
CONTESTED = "security.contested_exposures"
#: The inbox item Contract the attention Lines post.
ATTENTION_ITEM = "security.exposure-attention"
ATTENTION_STATES = ("unjudged", "contested")
#: One Procedure and Line per state, each reading its own worklist split: a
#: Procedure has one terminal (a second is unreachable without a guard, and guards
#: are closed in authoring), so one run cannot post two states.
ATTENTION = {state: f"{ATTENTION_ITEM}.{state}" for state in ATTENTION_STATES}
#: The most items one attention run posts (core: a declared max_items, at most
#: 1000; 100 when undeclared). Past it the run reports inbox_truncation and posts
#: the first rows in worklist order: KEV-listed first, then by EPSS score.
ATTENTION_MAX_ITEMS = 100
CONFIRMED_ROW = "security.confirmed-exposure"
EXPOSURE_ROW = "security.exposure-row"
JUDGMENT_ROW = "security.judgment"
APP_JUDGMENT_ROW = "security.app-judgment"
AFFECTED_BY = COMPONENT + ".affected_by"

#: The worklist walk: the link, the occurrences holding a scope, their
#: inventory, and the two judgment pairs (optional: absent means not judged).
_HOPS = (
    {"c": f"<v.{AFFECTED_BY}!"},
    {"o": f"{OCCURRENCE}{{component: c}}! with scope"},
    {"i": f"o.{OCCURRENCE}.inventory!: {INVENTORY}"},
    {"e": f"{EXPOSURE}{{component: c, vulnerability: v}}"},
    {"ae": f"{APP_EXPOSURE}{{occurrence: o, vulnerability: v}}"},
)


def _one_of(field: str, members: Sequence[str]) -> str:
    """``field`` holds ONE resolved value among ``members``.

    A comparison or membership test reads the field's resolved value: an absent
    field, or a contested one (competing Claims), has none and fails. ``exists``
    only tests that some visible Claim is there, contested or not, so it is used
    here only to require that NO Claim is there.
    """

    return f"{field} in ({', '.join(json.dumps(m) for m in members)})"


#: The judgment pairs, read the same way by every Query. A judgment counts only
#: when its value is resolved (one uncontested, supported value):
#:
#: - package level: a resolved justification;
#: - app level, not_affected: a resolved justification, and either no visible
#:   verdict at all or a resolved verdict of not_affected;
#: - app level, affected: a resolved verdict of affected, and no visible
#:   justification at all.
#:
#: Every other combination -- a contested verdict or justification, affected
#: beside a justification, a bare not_affected verdict -- is no judgment: the
#: pair stays in the worklists and in neither track record.
_PACKAGE_NOT_AFFECTED = _one_of("e.justification", PACKAGE_JUSTIFICATIONS)
_APP_NOT_AFFECTED = (
    f"{_one_of('ae.justification', APP_JUSTIFICATIONS)} and "
    f'(not exists ae.verdict or ae.verdict == "{APP_VERDICTS[1]}")'
)
_APP_AFFECTED = f'ae.verdict == "{APP_VERDICTS[0]}" and not exists ae.justification'
#: Not judged: no package-level judgment and no app-level judgment.
_NOT_JUDGED = (
    f"not ({_PACKAGE_NOT_AFFECTED}) and not ({_APP_NOT_AFFECTED}) and not ({_APP_AFFECTED})"
)
#: Some judgment Claim is on the pair, resolved or not (``exists`` is presence).
_ANY_JUDGMENT = "exists e.justification or exists ae.justification or exists ae.verdict"
#: A judgment pair exists: its key-part Claims stay when its judgment is withdrawn.
_PAIR_EXISTS = "exists e.component or exists ae.occurrence"
_FIELDS = (
    {"inventory": "i.inventory_id"},
    {"component": "c.purl"},
    {"occurrence": "o.subject_id"},
    "o.scope",
    "v.cve_id",
    "v.kev_date_added",
    "v.kev_due_date",
    "v.kev_ransomware_use",
    "v.epss_score",
    "v.epss_percentile",
)

URGENT_SPEC: dict[str, Any] = {
    "query": URGENT,
    "description": "Every occurrence (an inventory's component) a vulnerability affects "
    "that nobody has judged, KEV-listed first, then by EPSS score; a package-level or "
    "app-level not_affected judgment or an affected verdict removes it.",
    "from": {"v": VULN},
    "hops": list(_HOPS),
    "where": _NOT_JUDGED,
    "row": f"{EXPOSURE_ROW}@1",
    "fields": list(_FIELDS),
    "order": ["-v.kev_date_added", "-v.epss_score"],
}
BACKLOG_SPEC: dict[str, Any] = {
    **URGENT_SPEC,
    "query": BACKLOG,
    "description": "The KEV-listed exposures nobody has judged yet, by EPSS score (pairs "
    "under investigation stay).",
    "where": f"exists v.kev_date_added and {_NOT_JUDGED}",
    "order": ["-v.epss_score"],
}
JUDGMENTS_SPEC: dict[str, Any] = {
    "query": JUDGMENTS,
    "description": "Every package-level not_affected judgment: the component, the "
    "vulnerability and the VEX justification.",
    "from": {"e": EXPOSURE},
    "where": _PACKAGE_NOT_AFFECTED,
    "hops": [
        {"c": f"e.{EXPOSURE}.component!: {COMPONENT}"},
        {"v": f"e.{EXPOSURE}.vulnerability!: {VULN}"},
    ],
    "row": f"{JUDGMENT_ROW}@1",
    "fields": [
        {"exposure": "e.subject_id"},
        {"component": "c.purl"},
        "v.cve_id",
        "e.justification",
    ],
}
APP_JUDGMENTS_SPEC: dict[str, Any] = {
    "query": APP_JUDGMENTS,
    "description": "Every app-level not_affected judgment: the inventory, the component, "
    "the vulnerability and the VEX justification.",
    "from": {"ae": APP_EXPOSURE},
    "where": _APP_NOT_AFFECTED,
    "hops": [
        {"o": f"ae.{APP_EXPOSURE}.occurrence!: {OCCURRENCE}"},
        {"v": f"ae.{APP_EXPOSURE}.vulnerability!: {VULN}"},
        {"i": f"o.{OCCURRENCE}.inventory!: {INVENTORY}"},
        {"c": f"o.{OCCURRENCE}.component!: {COMPONENT}"},
    ],
    "row": f"{APP_JUDGMENT_ROW}@1",
    "fields": [
        {"app_exposure": "ae.subject_id"},
        {"inventory": "i.inventory_id"},
        {"component": "c.purl"},
        "v.cve_id",
        "ae.justification",
    ],
}
#: Confirmed, fix pending: from the judgment pairs (one per judged occurrence), so
#: OSV later dropping its listing never hides a confirmed exposure; the
#: occurrence must still hold a scope (its SBOM still lists the component).
CONFIRMED_SPEC: dict[str, Any] = {
    "query": CONFIRMED,
    "description": "Every occurrence an agent judged affected whose SBOM still lists the "
    "component: the confirmed exposures to remediate or escalate, KEV-listed first, then by "
    "EPSS score. The fixed versions are in the osv.match document the component's "
    "affected_by Claim cites.",
    "from": {"ae": APP_EXPOSURE},
    "hops": [
        {"o": f"ae.{APP_EXPOSURE}.occurrence!: {OCCURRENCE}"},
        {"v": f"ae.{APP_EXPOSURE}.vulnerability!: {VULN}"},
        {"i": f"o.{OCCURRENCE}.inventory!: {INVENTORY}"},
        {"c": f"o.{OCCURRENCE}.component!: {COMPONENT}"},
    ],
    "where": f"{_APP_AFFECTED} and exists o.scope",
    "row": f"{CONFIRMED_ROW}@1",
    "fields": [{"app_exposure": "ae.subject_id"}, *_FIELDS],
    "order": ["-v.kev_date_added", "-v.epss_score"],
}

#: The exposure counts (K-B2-TR): covered, new, confirmed and came back, each the
#: row count of its Queries (the Query engine has no count or union form).
#:
#: - covered: occurrences with a resolved not_affected judgment, at app level (the
#:   worklist walk: OSV still lists V) or at package level (every occurrence
#:   holding a scope of the judged component). The two never share a row;
#: - new: ``security.urgent_exposures`` (no judgment counts: unjudged, contested
#:   or withdrawn);
#: - confirmed: ``security.confirmed_exposures``;
#: - came back: the part of new whose judgment pair exists but holds no judgment
#:   Claim, i.e. a judgment was withdrawn (the pair stays as history). A judgment
#:   whose cited code changed still stands; ``next`` lists it, not this.
COVERED_APP_SPEC: dict[str, Any] = {
    **URGENT_SPEC,
    "query": COVERED_APP,
    "description": "Every occurrence a vulnerability affects that an agent judged "
    "not_affected for its inventory (a resolved app-level judgment), KEV-listed first, then "
    "by EPSS score.",
    "where": f"({_APP_NOT_AFFECTED}) and not ({_PACKAGE_NOT_AFFECTED})",
}
COVERED_PACKAGE_SPEC: dict[str, Any] = {
    "query": COVERED_PACKAGE,
    "description": "Every occurrence holding a scope of a component an agent judged "
    "not_affected at package level (a resolved justification): one row per inventory "
    "holding it, KEV-listed first, then by EPSS score.",
    "from": {"e": EXPOSURE},
    "where": _PACKAGE_NOT_AFFECTED,
    "hops": [
        {"c": f"e.{EXPOSURE}.component!: {COMPONENT}"},
        {"v": f"e.{EXPOSURE}.vulnerability!: {VULN}"},
        {"o": f"{OCCURRENCE}{{component: c}}! with scope"},
        {"i": f"o.{OCCURRENCE}.inventory!: {INVENTORY}"},
    ],
    "row": f"{EXPOSURE_ROW}@1",
    "fields": list(_FIELDS),
    "order": ["-v.kev_date_added", "-v.epss_score"],
}
CAME_BACK_SPEC: dict[str, Any] = {
    **URGENT_SPEC,
    "query": CAME_BACK,
    "description": "The exposures nobody has judged whose judgment pair exists but holds no "
    "judgment: a judgment was withdrawn and the occurrence is back in the worklists. A "
    "judgment whose cited code changed still stands: next lists it.",
    "where": f"not ({_ANY_JUDGMENT}) and ({_PAIR_EXISTS})",
}
#: The worklist split by why a pair is there, for the attention Line (one inbox
#: item per pair and state): no judgment Claim at all, or a judgment Claim that
#: does not count (contested, affected beside a justification, a bare not_affected).
UNJUDGED_SPEC: dict[str, Any] = {
    **URGENT_SPEC,
    "query": UNJUDGED,
    "description": "The exposures nobody has judged that hold no judgment Claim at all, "
    "KEV-listed first, then by EPSS score.",
    "where": f"not ({_ANY_JUDGMENT})",
}
CONTESTED_SPEC: dict[str, Any] = {
    **URGENT_SPEC,
    "query": CONTESTED,
    "description": "The exposures holding a judgment Claim that does not count (a contested "
    "verdict or justification, or an affected verdict beside a justification), KEV-listed "
    "first, then by EPSS score.",
    "where": f"{_NOT_JUDGED} and ({_ANY_JUDGMENT})",
}
#: Each count and the Queries whose rows it is (``came_back`` is part of ``new``).
COUNT_QUERIES: dict[str, tuple[str, ...]] = {
    "covered": (COVERED_APP, COVERED_PACKAGE),
    "new": (URGENT,),
    "confirmed": (CONFIRMED,),
    "came_back": (CAME_BACK,),
}


#: The exposure row's fields (the worklists and the confirmed list alike).
_EXPOSURE_FIELDS: dict[str, str] = {
    "inventory": "string",
    "component": "string",
    "occurrence": "string",
    "scope": f"enum_of {SCOPE}",
    "cve_id": "string",
    "kev_date_added": "date?",
    "kev_due_date": "date?",
    "kev_ransomware_use": f"enum_of {VULN}.kev_ransomware_use?",
    "epss_score": "decimal{0..1}?",
    "epss_percentile": "decimal{0..1}?",
}


def vocabulary_members() -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = [
        {
            "kind": "contract",
            "name": EXPOSURE_ROW,
            "version": 1,
            "description": "One exposure: an occurrence (an inventory's component) a "
            "vulnerability affects, with its scope and the vulnerability's KEV and EPSS facts.",
            "fields": dict(_EXPOSURE_FIELDS),
        },
        {
            "kind": "contract",
            "name": CONFIRMED_ROW,
            "version": 1,
            "description": "One confirmed exposure: the judgment pair, the occurrence (an "
            "inventory's component) judged affected, its scope and the vulnerability's KEV and "
            "EPSS facts.",
            "fields": {
                "app_exposure": "string",
                **_EXPOSURE_FIELDS,
            },
        },
        {
            "kind": "contract",
            "name": JUDGMENT_ROW,
            "version": 1,
            "description": "One package-level judgment: its exposure pair, component, CVE "
            "and VEX justification.",
            "fields": {
                "exposure": "string",
                "component": "string",
                "cve_id": "string",
                "justification": f"enum_of {EXPOSURE}.justification",
            },
        },
        {
            "kind": "contract",
            "name": APP_JUDGMENT_ROW,
            "version": 1,
            "description": "One app-level judgment: its pair, inventory, component, CVE and "
            "VEX justification.",
            "fields": {
                "app_exposure": "string",
                "inventory": "string",
                "component": "string",
                "cve_id": "string",
                "justification": f"enum_of {APP_EXPOSURE}.justification",
            },
        },
    ]
    for spec in (
        URGENT_SPEC,
        BACKLOG_SPEC,
        CONFIRMED_SPEC,
        JUDGMENTS_SPEC,
        APP_JUDGMENTS_SPEC,
        COVERED_APP_SPEC,
        COVERED_PACKAGE_SPEC,
        CAME_BACK_SPEC,
        UNJUDGED_SPEC,
        CONTESTED_SPEC,
    ):
        members.append({"kind": "query_definition", "query_definition": spec})
    members.append(
        {
            "kind": "contract",
            "name": ATTENTION_ITEM,
            "version": 1,
            "description": "One urgent exposure for an agent to judge: the inventory, the "
            "component, the vulnerability, the occurrence's Subject id (get "
            "security.occurrence/<occurrence>) and why it is here: unjudged, or contested (a "
            "judgment is on the pair but none counts). Stable identity only, so the same pair "
            "in the same state is the same item.",
            "fields": {
                "inventory": "string",
                "component": "string",
                "cve_id": "string",
                "occurrence": "string",
                "state": "enum[" + ", ".join(f'"{s}"' for s in ATTENTION_STATES) + "]",
            },
        }
    )
    return members


# -- The attention Line: urgent unjudged exposures reach the Line inbox ------------------


def attention_spec(state: str) -> dict[str, Any]:
    """``security.exposure-attention.<state>``: read one worklist split, post one item
    per pair.

    No provider slot: one state read (``security.unjudged_exposures`` or
    ``security.contested_exposures``) and one ``post_inbox`` terminal, with the
    state as a literal field. An item is only the pair's stable identity and its
    state, so a pair seen daily in the same state is one item re-sighted, never a
    new one; a contested judgment is a new item. The worklist order (KEV-listed
    first, then EPSS) is the posting order, so a capped run posts the most urgent.
    """

    from definitions import refs

    query = {"unjudged": UNJUDGED, "contested": CONTESTED}[state]
    return refs(
        {
            "procedure": ATTENTION[state],
            "description": f"Post one Line inbox item per {state} urgent exposure ({query}), "
            "KEV-listed first, then by EPSS score.",
            "input": {},
            "output": {},
            # Inbox egress is the terminal; the run's own value is empty.
            "returns": {"fields": {}},
            "hard_caps": {
                "wall_clock": "PT5M",
                "provider_calls": 0,
                "capture_bytes": 0,
                "items": 20_000,
                "read_rows": 50_000,
                "repeat_attempts": 1,
            },
            "steps": [
                {"read": "pairs", "query": query},
                {
                    "id": "post",
                    "inbox": f"{ATTENTION_ITEM}@1",
                    "for_each": "$steps.pairs.rows",
                    "fields": {
                        "inventory": "$item.inventory",
                        "component": "$item.component",
                        "cve_id": "$item.cve_id",
                        "occurrence": "$item.occurrence",
                        "state": state,
                    },
                    "dedupe_key": ["occurrence", "cve_id", "state"],
                    "max_items": ATTENTION_MAX_ITEMS,
                },
            ],
        }
    )


def attention_automation() -> list[dict[str, Any]]:
    """The two attention Lines: inbox egress only, so ``observe`` and no Mandate
    (posting feeds agents, it changes no accepted state)."""

    return [
        {
            "kind": "line",
            "name": ATTENTION[state],
            "procedure_name": ATTENTION[state],
            "bindings": {},
            "parameters": {},
            "acquisition": {},
            "max_authority": "observe",
        }
        for state in ATTENTION_STATES
    ]


def exposure_counts(answer: Callable[[str], Any]) -> dict[str, int]:
    """How many exposures are covered, new, confirmed and came back.

    ``answer(name)`` is one named Query's answer, a ``cruxible query --name NAME
    --json`` page (or the SDK's): each count is the rows of its Queries
    (``COUNT_QUERIES``), a page's ``rows`` plus its ``remaining``. A ``capped``
    answer (its budget clipped the rows) is refused rather than under-counted:
    ask again with a larger budget.
    """

    def count(name: str) -> int:
        page = answer(name)

        def field(key: str, default: Any) -> Any:
            if isinstance(page, Mapping):
                return page.get(key, default)
            return getattr(page, key, default)

        capped = field("capped", ())
        if capped:
            raise ValueError(
                f"{name} is capped ({', '.join(capped)}): its rows are not all counted"
            )
        return len(field("rows", ())) + int(field("remaining", 0) or 0)

    return {label: sum(count(name) for name in names) for label, names in COUNT_QUERIES.items()}


# -- Judgments: one write each ------------------------------------------------------------

Accept = Literal["if_allowed", "never"]


def _vulnerability(cve_id: str) -> str:
    return f"{VULN}/{cve_id.lower()}"


def _key(kind: str, **parts: Any) -> list[dict[str, Any]]:
    return [{"predicate": f"{kind}.{name}", "value": value} for name, value in parts.items()]


def judgment(
    purl: str,
    cve_id: str,
    *,
    reason: str,
    because: str,
    retire: Sequence[str] = (),
    accept: Accept = "never",
) -> dict[str, Any]:
    """A package-level not_affected judgment: ONE ``write`` request.

    It retires OSV's observation of V on the component (``retire``: the
    ``affected_by`` Claims of this unit; a none beside a live value of its unit
    is refused), states "affected_by none of V" (normative, own words), creates
    the pair ``security.exposure`` (component, V) -- or lands on it when it
    exists -- and sets its ``justification``. It lands or refuses whole.

    ``purl`` is the component's key (its purl@version). ``accept`` defaults to
    ``never`` (K-CF2a): a different agent approves it.
    """

    if reason not in PACKAGE_JUSTIFICATIONS:
        raise ValueError(
            f"a package-level justification is one of {PACKAGE_JUSTIFICATIONS}; "
            f"{reason!r} is app-level: use app_judgment"
        )
    vulnerability = _vulnerability(cve_id)
    component = f"{COMPONENT}/{purl}"
    return {
        "because": because,
        "accept": accept,
        "changes": [
            *({"op": "retire", "target": claim, "reason": "superseded"} for claim in retire),
            {
                "op": "add",
                "subject": component,
                "field": "affected_by",
                "value": {"none": vulnerability},
                "role": "normative",
            },
            {
                "op": "create",
                "label": "exposure",
                "subject_kind": EXPOSURE,
                "key": _key(EXPOSURE, component=component, vulnerability=vulnerability),
            },
            {
                "op": "set",
                "subject": {"created": "exposure"},
                "field": "justification",
                "value": reason,
                "role": "normative",
            },
        ],
    }


def _app_pair(occurrence: str, cve_id: str) -> dict[str, Any]:
    ref = occurrence if occurrence.startswith(OCCURRENCE + "/") else f"{OCCURRENCE}/{occurrence}"
    return {
        "op": "create",
        "label": "app_exposure",
        "subject_kind": APP_EXPOSURE,
        "key": _key(APP_EXPOSURE, occurrence=ref, vulnerability=_vulnerability(cve_id)),
    }


def _app_set(field: str, value: str) -> dict[str, Any]:
    return {
        "op": "set",
        "subject": {"created": "app_exposure"},
        "field": field,
        "value": value,
        "role": "normative",
    }


def app_judgment(
    occurrence: str,
    cve_id: str,
    *,
    reason: str,
    because: str,
    verdict: bool = False,
    accept: Accept = "never",
) -> dict[str, Any]:
    """An app-level not_affected judgment for one inventory: ONE ``write`` request.

    ``occurrence`` is the occurrence's id (a worklist row's ``occurrence``) or
    its ``security.occurrence/<id>`` reference. It creates the pair
    ``security.app_exposure`` (occurrence, V) -- or lands on it -- and sets its
    ``justification``. It never states the global none, so OSV's observation
    and every other inventory's exposure stay.

    The justification alone is the not_affected judgment. ``verdict`` also sets
    ``verdict = not_affected``: required when it reverses an affected verdict
    (the set revises that Claim in the same write), optional otherwise.
    """

    if reason not in APP_JUSTIFICATIONS:
        raise ValueError(
            f"an app-level justification is one of {APP_JUSTIFICATIONS}; "
            f"{reason!r} is package-level: use judgment"
        )
    return {
        "because": because,
        "accept": accept,
        "changes": [
            _app_pair(occurrence, cve_id),
            *([_app_set("verdict", APP_VERDICTS[1])] if verdict else []),
            _app_set("justification", reason),
        ],
    }


def affected_judgment(
    occurrence: str,
    cve_id: str,
    *,
    because: str,
    evidence: Mapping[str, Any] | None = None,
    accept: Accept = "never",
) -> dict[str, Any]:
    """An app-level affected verdict for one inventory: ONE ``write`` request.

    It creates the pair ``security.app_exposure`` (occurrence, V) -- or lands on
    it -- and sets ``verdict = affected`` with no justification. ``evidence`` is
    the verdict's reachability evidence: cite the code that reaches the
    vulnerable function (``{"kind": "file", "file": "PATH#ANCHOR"}``), so the
    verdict drifts when that code changes; without it the write's ``because``
    is its own-words evidence. The pair leaves the worklists for
    ``security.confirmed_exposures``; every other inventory's exposure stays.
    """

    change = _app_set("verdict", APP_VERDICTS[0])
    if evidence is not None:
        change["evidence"] = dict(evidence)
    return {
        "because": because,
        "accept": accept,
        "changes": [_app_pair(occurrence, cve_id), change],
    }


def reverse_judgment(
    justification: str,
    *,
    none: str | None = None,
    because: str,
    reason: Literal["was-wrong", "was-rescinded"] = "was-wrong",
    accept: Accept = "never",
) -> dict[str, Any]:
    """Withdraw a judgment: ONE ``write`` retiring its justification Claim (or an
    affected verdict's Claim) and, for a package-level judgment, its none Claim
    (``none``) together.

    The pair Subject stays as history. OSV's next run re-observes V on the
    component; an app-level reversal brings that one occurrence back to the
    worklists. To turn an affected verdict into not_affected instead, write
    :func:`app_judgment` with ``verdict=True``.
    """

    targets = [justification, *(() if none is None else (none,))]
    return {
        "because": because,
        "accept": accept,
        "changes": [{"op": "retire", "target": claim, "reason": reason} for claim in targets],
    }


# -- Under investigation (K-CF1) ----------------------------------------------------------


def _end_of_day(value: date) -> datetime:
    return datetime.combine(value + timedelta(days=1), time(0), tzinfo=UTC)


#: The longest an investigation holds a pair (K-CF1).
HOLD_DAYS = 14


def _utc(value: datetime) -> datetime:
    """An instant in UTC (a naive one is read as UTC).

    Adding a timedelta to an aware datetime in a zone with daylight saving adds
    wall-clock time, so 14 days across a clock change would be 337 or 335 hours.
    """

    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def hold_until(*, now: datetime, kev_due_date: date | None = None) -> datetime:
    """When the longest hold allowed ``now`` ends, in UTC: 14 days (336 hours) from
    ``now``, or the end of the KEV due date if that is sooner and still ahead.

    A KEV due date already past neither shortens nor cancels the hold (most KEV
    entries are past due), so it is held for 14 days like a pair with no KEV entry.
    """

    now = _utc(now)
    cap = now + timedelta(days=HOLD_DAYS)
    if kev_due_date is not None:
        due = _end_of_day(kev_due_date)
        if now < due < cap:
            cap = due
    return cap


def investigation(
    claim: str,
    *,
    because: str,
    until: datetime | None = None,
    kev_due_date: date | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The ``claim attest --unsure`` of a pair under investigation.

    ``claim`` is OSV's ``affected_by`` Claim of the pair. The hold lasts until
    :func:`hold_until` (at most 14 days, or the end of a KEV due date still
    ahead, whichever is sooner), or until ``until`` when that is sooner. The
    reason is ``because`` (or cite a section instead). The pair stays in the
    worklists and the KEV backlog.

    Returns the attestation's arguments: ``claim``, ``stance``, ``because`` and
    ``valid_until`` (``cruxible claim attest CLAIM --unsure --because ...
    --valid-until ...``; :func:`investigation_argv`). An ``until`` already past
    is refused (ValueError).
    """

    now = _utc(now or datetime.now(UTC))
    valid_until = hold_until(now=now, kev_due_date=kev_due_date)
    if until is not None:
        valid_until = min(valid_until, _utc(until))
    if valid_until <= now:
        raise ValueError(f"the hold would end at {valid_until.isoformat()}, already past")
    return {
        "claim": claim,
        "stance": "unsure",
        "because": because,
        "valid_until": valid_until,
    }


def investigation_argv(request: Mapping[str, Any]) -> list[str]:
    """:func:`investigation`'s request as ``cruxible`` CLI arguments."""

    until = request["valid_until"].astimezone(UTC).isoformat().replace("+00:00", "Z")
    return [
        "claim",
        "attest",
        str(request["claim"]),
        "--unsure",
        "--because",
        str(request["because"]),
        "--valid-until",
        until,
    ]


def under_investigation(attestations: Iterable[Any]) -> bool:
    """Whether one Claim is under investigation: a current ``unsure`` attestation.

    ``attestations`` is ``get <claim> --detail evidence``'s ``attestations``
    (one Claim read per pair). An attestation past its ``valid_until``, or one
    its principal has since superseded with support or contradict, is not
    current.
    """

    def field(item: Any, name: str) -> Any:
        return item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)

    return any(
        field(item, "stance") == "unsure" and bool(field(item, "current")) for item in attestations
    )
