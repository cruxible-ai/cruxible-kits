"""Shared reading of state-tap rows and the proposal items every analysis returns.

A state-tap row is the wire form of one QueryDefinition result row: its
``bindings`` (each bound Subject's kind, id and path, exactly as core resolved
them), its projected ``fields`` (``present`` with a value, ``absent`` or
``conflict``) and the ``read_claims`` it was read through. Nothing here derives
or normalizes a Subject id: an existing Subject is named by the path core
returned, a new one by its kind and key (core assigns the id).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

CLAIM_ITEM = "playbill-procedure-claim-proposal-item-v1"
KEYED_CLAIM_ITEM = "playbill-procedure-claim-proposal-item-v3"
SUBJECT_ITEM = "playbill-procedure-subject-proposal-item-v1"
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
class Row:
    """One state-tap row: bound Subjects, projected fields, the Claims behind them."""

    bindings: dict[str, Bound]
    fields: dict[str, tuple[str, Any]]
    claims: dict[tuple[str, str], str] = field(default_factory=dict)

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
        parsed.append(Row(bindings=bindings, fields=fields, claims=claims))
    return parsed


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


def own_words(text: str) -> dict[str, str]:
    """A self-source citing the item's own words.

    Identity and relationship Claims are normative: they are supported by their
    own origin, and no kit ClaimType admits a source Capture as their evidence.
    The observation Claims of the same run cite the Capture the run read.
    """

    return {
        "tag": "playbill-self-source-body-v1",
        "content_base64": base64.b64encode((text + "\n").encode("utf-8")).decode("ascii"),
    }


def subject_item(kind: str, key: Mapping[str, str], rationale: str) -> dict[str, Any]:
    """Create the Subject of ``kind`` by ``key``, or name the live holder (creates nothing).

    Its key Claims cite the item's own words (``own_words``).
    """

    return {
        "tag": SUBJECT_ITEM,
        "subject_kind": kind,
        "key": dict(key),
        "rationale": rationale,
        "create_new": False,
        "source": own_words(rationale),
    }


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
    named) or a ``key_ref`` (a Subject-valued object named by key). An
    observation cites the Capture the run read (core attaches it); a normative
    Claim cites its own words.
    """

    keyed = isinstance(subject, dict) or isinstance(value, dict) or role == "normative"
    if isinstance(value, Bound):
        obj: dict[str, Any] = {"kind": "subject", "address": address(value.path)}
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
        item["source"] = own_words(rationale) if role == "normative" else None
    return item


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


def cve_token(value: object) -> str | None:
    """A CVE identifier in the key's canonical form (trimmed, uppercase), else None."""

    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    return text if re.fullmatch(r"CVE-\d{4}-\d{4,}", text) else None


def sorted_items(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Items in a stable order, so the same inputs produce the same proposal bytes."""

    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
