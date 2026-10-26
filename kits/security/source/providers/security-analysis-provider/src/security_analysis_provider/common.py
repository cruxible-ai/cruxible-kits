"""Shared reading of state-tap rows and the proposal items every analysis returns.

A state-tap row is the wire form of one QueryDefinition result row: its
``bindings`` (each bound Subject's kind, id and path, exactly as core resolved
them), its projected ``fields`` (``present`` with a value, ``absent`` or
``conflict``), the ``read_claims`` it was read through and its ``includes``
(each Claim of a predicate one hop out, with its object and Claim path: how a
many-valued fact's values are told apart when one of them goes). Nothing here derives
or normalizes a Subject id: an existing Subject is named by the path core
returned, a new one by its kind and key (core assigns the id).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

CLAIM_ITEM = "playbill-procedure-claim-proposal-item-v1"
KEYED_CLAIM_ITEM = "playbill-procedure-claim-proposal-item-v3"
SUBJECT_ITEM = "playbill-procedure-subject-proposal-item-v1"
RETIREMENT_ITEM = "playbill-procedure-claim-retirement-item-v1"
STATEMENT = "playbill-authoring-claim-statement-v1"
KEYED_STATEMENT = "playbill-procedure-claim-statement-v1"
ADDRESS = "playbill-semantic-address-v1"


class InputError(ValueError):
    """The request does not have the shape the interface promises."""


@dataclass(frozen=True)
class Bound:
    kind: str
    subject_id: str
    path: str
    identity: str


@dataclass(frozen=True)
class Included:
    """One Claim an include read: its literal value or object Subject path, and its ID.

    A none (an inverse Claim, ClaimType v9) has neither: ``none_of`` is the unit it says
    holds nothing (the key value of an ``object_key`` inverse), and ``is_none`` is true.
    """

    value: Any
    object_path: str | None
    claim_id: str
    none_of: Any = None
    is_none: bool = False


@dataclass(frozen=True)
class Row:
    """One state-tap row: bound Subjects, projected fields, the Claims behind them."""

    bindings: dict[str, Bound]
    fields: dict[str, tuple[str, Any]]
    claims: dict[tuple[str, str], str] = field(default_factory=dict)
    includes: dict[str, tuple[Included, ...]] = field(default_factory=dict)

    def included(self, name: str) -> tuple[Included, ...]:
        return self.includes.get(name, ())

    def subject(self, binding: str) -> Bound | None:
        return self.bindings.get(binding)

    def value(self, name: str) -> Any:
        """The projected value, or None when absent or conflicted."""

        state, value = self.fields.get(name, ("absent", None))
        return value if state == "present" else None

    def state(self, name: str) -> str:
        return self.fields.get(name, ("absent", None))[0]

    def claim_id(self, bound: Bound, predicate: str) -> str | None:
        """The ID of the live Claim of ``predicate`` about ``bound`` this row read."""

        found = self.claims.get((bound.identity, predicate))
        if found is not None:
            return found
        suffix = f"{bound.kind}/{bound.subject_id}"
        for (identity, held), claim in self.claims.items():
            if held == predicate and identity.endswith(suffix):
                return claim
        return None


def unindexed_counts(purls: Iterable[str], ecosystems: Mapping[str, Any]) -> dict[str, int]:
    """Count what the kit's OSV map cannot name; this is no assertion of coverage."""
    counts: dict[str, int] = {}
    for purl in purls:
        package = purl.removeprefix("pkg:").split("@", 1)[0]
        parts = package.split("/")
        kind = parts[0]
        key = "/".join(parts[:2]) if kind in {"apk", "deb", "rpm"} else kind
        if key not in ecosystems:
            counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def parse_rows(rows: object) -> list[Row]:
    if not isinstance(rows, list):
        raise InputError("state-tap rows must be a list")
    parsed: list[Row] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise InputError("a state-tap row must be an object")
        bindings: dict[str, Bound] = {}
        for item in raw.get("bindings") or ():
            if item.get("subject_id") and item.get("subject_path"):
                bindings[str(item["binding"])] = Bound(
                    kind=str(item["subject_kind"]),
                    subject_id=str(item["subject_id"]),
                    path=str(item["subject_path"]),
                    identity=str(item.get("subject_identity") or ""),
                )
        fields = {
            str(item["name"]): (str(item.get("state", "absent")), item.get("value"))
            for item in raw.get("fields") or ()
        }
        claims: dict[tuple[str, str], str] = {}
        for claim in raw.get("read_claims") or ():
            path = str(claim.get("claim_path", ""))
            key = (str(claim.get("subject_identity", "")), str(claim.get("predicate", "")))
            claims.setdefault(key, path.rsplit("/", 1)[-1].removesuffix(".json"))
        includes: dict[str, tuple[Included, ...]] = {}
        for include in raw.get("includes") or ():
            if not isinstance(include, Mapping):
                continue
            items = []
            for item in include.get("items") or ():
                obj = item.get("claim_object") or {}
                path = str((item.get("visibility") or {}).get("claim_path", ""))
                claim = path.rsplit("/", 1)[-1].removesuffix(".json")
                if obj.get("kind") == "subject":
                    target = str((obj.get("address") or {}).get("artifact_path") or "")
                    items.append(Included(value=None, object_path=target, claim_id=claim))
                elif obj.get("kind") == "none":
                    unit = obj.get("of") if isinstance(obj.get("of"), Mapping) else {}
                    items.append(Included(value=None, object_path=None, claim_id=claim,
                                          none_of=unit.get("value"), is_none=True))
                else:
                    items.append(Included(value=obj.get("value"), object_path=None,
                                          claim_id=claim))
            includes[str(include.get("name"))] = tuple(items)
        parsed.append(Row(bindings=bindings, fields=fields, claims=claims, includes=includes))
    return parsed


def once_per(rows: list[Row], binding: str) -> list[Row]:
    """The first row per Subject bound at ``binding``.

    ``security.watched_vulnerabilities`` is path-shaped (one row per qualifying
    assessment path); a vulnerability is read once.
    """

    seen: set[str] = set()
    unique: list[Row] = []
    for row in rows:
        bound = row.subject(binding)
        if bound is None or bound.path in seen:
            continue
        seen.add(bound.path)
        unique.append(row)
    return unique


def decode_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise InputError(f"{label} must be a nonempty base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InputError(f"{label} is not base64") from error


def decode_json(value: bytes, label: str) -> Any:
    try:
        return json.loads(value)
    except (UnicodeDecodeError, ValueError) as error:
        raise InputError(f"{label} is not JSON") from error


# --- identity -----------------------------------------------------------------


def address(path: str) -> dict[str, Any]:
    """The semantic address of a Subject core named at ``path``."""

    return {
        "tag": ADDRESS,
        "artifact_path": path,
        "selector": {"scheme": "artifact-v1", "value": ""},
    }


def key_ref(kind: str, **key: str) -> dict[str, Any]:
    """A Subject named by its kind's key: the holder, or the one this terminal creates."""

    return {"subject_kind": kind, "key": dict(key)}


def subject_item(kind: str, key: Mapping[str, str], rationale: str) -> dict[str, Any]:
    """Create the Subject of ``kind`` by ``key``, or name the live holder (creates nothing).

    Its key Claims are covered by the creation itself (Claim law v2 revision 9); like
    every other item, it cites the Capture the run read.
    """

    return {
        "tag": SUBJECT_ITEM,
        "subject_kind": kind,
        "key": dict(key),
        "rationale": rationale,
        "create_new": False,
        "source": None,
    }


class NoneOf(dict):  # type: ignore[type-arg]
    """A none's object for ``claim_item``: the key value an ``object_key`` inverse names
    (``NoneOf("php")``: the subject holds no value whose key is php)."""

    def __init__(self, key: str) -> None:
        super().__init__(of=key)


def claim_item(
    subject: Bound | dict[str, Any],
    predicate: str,
    value: Any,
    rationale: str,
    *,
    role: str = "observation",
    revises: str | None = None,
) -> dict[str, Any]:
    """One Claim item about an existing Subject (``Bound``) or a keyed one (``key_ref``).

    ``value`` is a literal, a ``Bound`` (a Subject-valued object core already
    named), a ``key_ref`` (a Subject-valued object named by key) or a ``NoneOf`` (a
    none: an inverse Claim of a ClaimType v9 keyed ``object_key``). Every item
    cites the Capture the run read (core attaches it): an observation as the
    source's verdict, a normative relationship as the source that states it.
    """

    keyed = isinstance(subject, dict) or (isinstance(value, dict) and not isinstance(
        value, NoneOf))
    if isinstance(value, NoneOf):
        obj: dict[str, Any] = {"kind": "none", "of": {"kind": "literal",
                                                      "value": value["of"]}}
    elif isinstance(value, Bound):
        obj = {"kind": "subject", "address": address(value.path)}
    elif isinstance(value, dict):
        obj = {"kind": "subject_key", "subject": value}
    else:
        obj = {"kind": "literal", "value": value}
    statement = {
        "tag": KEYED_STATEMENT if keyed else STATEMENT,
        "subject": subject if isinstance(subject, dict) else address(subject.path),
        "predicate": predicate,
        "qualifier": None,
        "object": obj,
        "role": role,
        "effective_from": None,
        "effective_until": None,
    }
    item: dict[str, Any] = {
        "tag": KEYED_CLAIM_ITEM if keyed else CLAIM_ITEM,
        "statement": statement,
        "rationale": rationale,
        "revises": revises,
    }
    if keyed:
        item["source"] = None
    return item


def replacing(held: Mapping[Any, str], wanted: Iterable[Any],
              same: Any = None, *, together: bool = False
              ) -> tuple[list[tuple[Any, str]], list[Any], list[Any]]:
    """How a many-valued slot moves from ``held`` (value -> Claim ID) to ``wanted``.

    A replaced value revises the Claim it replaces (``same(value)`` pairs them, e.g. by
    product name; else in order) and the rest adds. What is gone retires in the same
    terminal when ``together`` (core dispositions a retiring sibling ``not_tested``, as the
    write verbs do: a run's flip to none needs it); otherwise only in a terminal that
    stages nothing else in the slot, the retirements waiting for the next read.

    Returns (``(new value, revised Claim)`` pairs, values to add, held values to retire).
    """

    wanted_set = set(wanted)
    gone = sorted(set(held) - wanted_set, key=str)
    pairs: list[tuple[Any, str]] = []
    adds: list[Any] = []
    for value in sorted(wanted_set - set(held), key=str):
        if same is not None:
            match = next((g for g in gone if same(g) == same(value)), None)
        else:
            match = gone[0] if gone else None
        if match is None:
            adds.append(value)
            continue
        gone.remove(match)
        pairs.append((value, held[match]))
    return pairs, adds, ([] if (adds or pairs) and not together else gone)


def retirement_item(claim_id: str, rationale: str, reason: str = "superseded") -> dict[str, Any]:
    """Retire one live Claim by ID: the source no longer states it."""

    return {"tag": RETIREMENT_ITEM, "retires": claim_id, "reason": reason, "rationale": rationale}


# --- matching -----------------------------------------------------------------

_NON_ALNUM = re.compile(r"[^0-9a-z]+")


def match_token(value: object) -> str:
    """A name reduced for comparison only: NFKC, casefolded, letters and digits.

    Used to compare an inventory name with a source's vendor or product text.
    It never names anything: Subjects are addressed by core's ids and keys.
    """

    if not isinstance(value, str):
        return ""
    return _NON_ALNUM.sub("", unicodedata.normalize("NFKC", value).casefold())


def name_form(value: object) -> str:
    """A name in the canonical form of the kit's name keys (``security.product.name``,
    ``security.release.product_name``): NFKC, trimmed, whitespace collapsed, casefolded.

    Used to find the inventory row a source's name already names; core applies
    the same form when it stores the key.
    """

    if not isinstance(value, str):
        return ""
    text = value
    for _ in range(8):
        settled = " ".join(unicodedata.normalize("NFKC", text).split()).casefold()
        if settled == text:
            break
        text = settled
    return text


def purl_version(purl: object) -> str | None:
    """The version of a ``pkg:type/[namespace/]name@version`` purl (qualifiers and
    subpath dropped), or None: the version separator is an ``@`` in the last segment
    only, so a scoped npm name (``pkg:npm/@angular/core``) has none."""

    if not isinstance(purl, str) or not purl.strip().startswith("pkg:"):
        return None
    body = purl.strip()[4:].split("#", 1)[0].split("?", 1)[0]
    _, _, rest = body.partition("/")
    last = rest.rstrip("/").rsplit("/", 1)[-1]
    if "@" not in last:
        return None
    name, _, version = last.partition("@")
    return version if name and version.strip() else None


def cve_token(value: object) -> str | None:
    """A CVE identifier in the key's canonical form (trimmed, uppercase), else None."""

    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    return text if re.fullmatch(r"CVE-\d{4}-\d{4,}", text) else None


def sorted_items(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Items in a stable order, so the same inputs produce the same proposal bytes."""

    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))


# --- OSV coverage ---------------------------------------------------------------

_COVERAGE = re.compile(r"^(complete|partial): (\d+) of (\d+) components answered"
                       r"(?:; not indexed: ([^;]+))?(?:; unanswered (\d+))?"
                       r"(?:; unidentified (\d+))?(?:; set ([0-9a-f]{16}))?$")


@dataclass(frozen=True)
class OsvCoverage:
    """A release's ``security.release.osv_coverage``: did OSV answer every component?"""

    complete: bool
    answered: int
    total: int
    #: purl type -> components of it OSV does not index (never asked)
    not_indexed: dict[str, int] = field(default_factory=dict)
    #: components asked whose answer is missing, truncated or names an advisory whose
    #: record could not be read
    unanswered: int = 0
    #: components the release's SBOM lists without a usable purl@version: never asked
    unidentified: int = 0
    #: the digest of the component set OSV answered for (``component_set``); a coverage
    #: is about that exact set, never about whatever the release holds later
    digest: str | None = None


def component_set(purls: Iterable[str]) -> str:
    """The digest a coverage is bound to: 16 hex of the sha256 of the sorted, distinct
    component purls. One component replaced by another (the same count) is another set."""

    body = json.dumps(sorted({str(purl) for purl in purls}), separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def coverage_text(total: int, answered: int, not_indexed: Mapping[str, int],
                  unanswered: int, unidentified: int = 0, digest: str | None = None) -> str:
    """The release's OSV coverage, one value: ``complete: N of N components answered; set
    D``, or ``partial: A of N components answered; not indexed: brew 1, generic 2;
    unanswered K; unidentified U; set D``. Complete only when OSV answered every component
    and the SBOM identified every one (no component without a purl)."""

    state = "complete" if answered == total and total and not unidentified else "partial"
    text = f"{state}: {answered} of {total} components answered"
    if not_indexed:
        text += "; not indexed: " + ", ".join(f"{t} {n}" for t, n in sorted(not_indexed.items()))
    if unanswered:
        text += f"; unanswered {unanswered}"
    if unidentified:
        text += f"; unidentified {unidentified}"
    if digest:
        text += f"; set {digest}"
    return text


def parse_coverage(text: object) -> OsvCoverage | None:
    """The coverage a ``coverage_text`` value states, or None (no coverage, or not one)."""

    match = _COVERAGE.match(text.strip()) if isinstance(text, str) else None
    if match is None:
        return None
    skipped: dict[str, int] = {}
    for item in (match.group(4) or "").split(","):
        purl_type, _, count = item.strip().partition(" ")
        if purl_type and count.isdigit():
            skipped[purl_type] = int(count)
    unidentified = int(match.group(6) or 0)
    return OsvCoverage(complete=match.group(1) == "complete" and not unidentified,
                       answered=int(match.group(2)), total=int(match.group(3)),
                       not_indexed=skipped, unanswered=int(match.group(5) or 0),
                       unidentified=unidentified, digest=match.group(7))


# --- untrusted text --------------------------------------------------------------

#: Prefixes of secrets, never of identifiers.
SECRET_PREFIXES = ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_", "ghp_", "gho_",
                   "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-",
                   "npm_", "pypi-", "aiza", "-----begin")


def entropy(text: str) -> float:
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def secret_in_text(value: object, *, max_length: int = 200, name: bool = False) -> bool:
    """Whether an identifier the kit would copy into Claims, inbox items or a run's output
    (a credential's issuer or name, a principal, a log source, a service) holds something
    secret-shaped: a private key marker, a secret's prefix on any token, or a long
    high-entropy token. Such a value is never echoed: the body is refused with a fixed
    message. ``name`` (a hostname, a purl, a scope): the entropy test reads each label
    between ``/ . - _ + ~`` on its own, so a generated workload name
    (``storefront-7d9f8b6c5d-x2k4p``) is a name, while a secret's prefix still refuses."""

    if not isinstance(value, str):
        return False
    if "%" in value and unquote(value) != value and secret_in_text(
            unquote(value), max_length=max_length, name=name):
        return True  # percent-encoded: what it decodes to is what gets copied (R2-004)
    lowered = value.casefold()
    if len(value) > max_length or "-----begin" in lowered or "private key" in lowered:
        return True
    # A secret's prefix at any boundary that is not a letter or digit (punctuation,
    # parentheses, quotes, dots, slashes, a hyphen or an underscore before it), whatever
    # the entropy, on a token long enough to be one (a name like aizawa is not).
    for start in range(len(lowered)):
        if start and lowered[start - 1].isalnum():
            continue
        for prefix in SECRET_PREFIXES:
            if lowered.startswith(prefix, start):
                token = re.match(r"[0-9a-z_-]*", lowered[start + len(prefix):])
                if token is not None and len(token.group()) >= 12:
                    return True
    breaks = r"[\s:@=,;\"'<>()\[\]{}/.+~_-]+" if name else r"[\s:@=,;\"'<>()\[\]{}]+"
    for token in re.split(breaks, value):
        folded = token.casefold()
        if not folded:
            continue
        if len(token) >= 24 and not re.fullmatch(r"[0-9a-f/-]+", folded) and entropy(
                token) >= 4.3:
            return True
    return False
