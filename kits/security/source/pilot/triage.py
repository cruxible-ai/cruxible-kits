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

The rule that reads the app-level pair is one place (``_APP_NOT_AFFECTED``,
``_APP_AFFECTED``): a justification is not_affected (a ``verdict`` of
``not_affected`` beside it is optional; it is how a reversal revises an
affected verdict in place), and ``verdict = affected`` with no justification
is affected. Anything else on the pair -- affected beside a justification, or
not_affected with none -- is no judgment, so the pair stays in the worklists
and in neither track record: a contradictory write can never silence a row.

**Under investigation** (K-CF1) is no judgment: the agent attests ``unsure``
on OSV's ``affected_by`` Claim (:func:`investigation`), with its reason
(``--because`` or a cited section) and a ``valid_until`` capped at the KEV due
date. The pair stays in the worklists and the KEV backlog; reading that one
Claim's evidence (:func:`under_investigation`) marks the row.

Judgments are agents' alone: no Mandate settles a justification, a verdict or the none,
and review is on the honor system (K-CF2a): the author writes with
``accept: never`` and a different agent approves after reading the dependency
guidance (``../guidance/dependency.md``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
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
#: The app-level pair's two judgments, read the same way by every Query: a
#: justification is not_affected unless the verdict says affected; the verdict
#: affected counts only with no justification beside it. Both at once (or a bare
#: not_affected verdict) is no judgment.
_APP_NOT_AFFECTED = 'exists ae.justification and not ae.verdict == "affected"'
_APP_AFFECTED = 'ae.verdict == "affected" and not exists ae.justification'
#: Not judged: no package-level justification and no app-level judgment.
_NOT_JUDGED = f"not exists e.justification and not ({_APP_NOT_AFFECTED}) and not ({_APP_AFFECTED})"
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
    "where": "exists e.justification",
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
    for spec in (URGENT_SPEC, BACKLOG_SPEC, CONFIRMED_SPEC, JUDGMENTS_SPEC, APP_JUDGMENTS_SPEC):
        members.append({"kind": "query_definition", "query_definition": spec})
    return members


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


def investigation(
    claim: str,
    *,
    because: str,
    until: datetime,
    kev_due_date: date | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The ``claim attest --unsure`` of a pair under investigation.

    ``claim`` is OSV's ``affected_by`` Claim of the pair. The hold lasts until
    ``until``, capped at the end of the KEV due date when the vulnerability has
    one (K-CF1): an investigation never outlives the remediation deadline. The
    reason is ``because`` (or cite a section instead). The pair stays in the
    worklists and the KEV backlog.

    Returns the attestation's arguments: ``claim``, ``stance``, ``because`` and
    ``valid_until`` (``cruxible claim attest CLAIM --unsure --because ...
    --valid-until ...``; :func:`investigation_argv`). A pair whose KEV due date
    has passed cannot be held: judge it instead (ValueError).
    """

    valid_until = until if until.tzinfo else until.replace(tzinfo=UTC)
    if kev_due_date is not None:
        valid_until = min(valid_until, _end_of_day(kev_due_date))
    if valid_until <= (now or datetime.now(UTC)):
        raise ValueError(
            f"the hold would end at {valid_until.isoformat()}, already past: the KEV due "
            "date has passed, so judge the pair instead of holding it"
        )
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
