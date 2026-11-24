"""Export the security kit's exposure judgments as CycloneDX 1.5 VEX or OpenVEX v0.2.0.

    cruxible python export_vex.py --format openvex   > vex.openvex.json
    cruxible python export_vex.py --format cyclonedx > vex.cdx.json
    cruxible python export_vex.py --format openvex --inventory pkg:maven/com.example/app@1.0.0

``cruxible python`` runs it with the CLI's own interpreter and instance settings;
plain ``python export_vex.py`` works wherever ``cruxible_client`` is importable.
It needs nothing beyond the standard library and ``cruxible_client``.

**One coordinate.** Every read is pinned to the accepted head as the export
starts (its ``instance_id``, ``generation``, ``git_oid`` and ``state_digest``, the
semantic root), so the document is one consistent state. The timestamp is that
generation's own (``proposed_at``) unless ``--timestamp`` names one, and the
serial number / document id derive from the coordinate unless ``--serial`` /
``--id`` name one, so two exports at the same coordinate are byte-identical.

**What each exposure says** (one statement per current occurrence a
vulnerability affects: an inventory's component its SBOM still lists):

| Cruxible state | CycloneDX ``analysis.state`` | OpenVEX ``status`` |
|---|---|---|
| ``security.confirmed_exposures`` (a resolved ``verdict = affected``) | ``exploitable``, ``response: update`` and the fixed versions OSV lists | ``affected``, ``action_statement`` with the fixed versions |
| ``security.covered_app_exposures`` (a resolved app-level justification) | ``not_affected`` and the mapped justification | ``not_affected``, ``justification``, ``impact_statement`` |
| ``security.covered_package_exposures`` (a resolved package-level justification) | ``not_affected`` (``code_not_present``) | ``not_affected`` (``vulnerable_code_not_present``) |
| anything else in ``security.urgent_exposures``: unjudged, contested, or a withdrawn judgment | ``in_triage`` | ``under_investigation`` |

A contested judgment never counts (the kit's Queries require a resolved
value), and the export checks it again: a pair ``security.contested_exposures``
lists that any covered or confirmed list also holds refuses the export rather
than state ``not_affected``. A release the inventory's SBOM no longer lists is
not exported (every Query here requires the occurrence's scope).

**Provenance.** The document names the coordinate; each statement names the
Claims it rests on (the judgment's justification or verdict, OSV's
``affected_by``, the occurrence's ``scope``) and the Captures that back them
(``CAP-...`` with contract and source), so an auditor can ``cruxible get`` each.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote, unquote

TOOL = "cruxible-security-kit-vex"
KIT_VERSION = "1.4.0"
FORMATS = ("cyclonedx", "openvex")

CONFIRMED = "security.confirmed_exposures"
COVERED_APP = "security.covered_app_exposures"
COVERED_PACKAGE = "security.covered_package_exposures"
URGENT = "security.urgent_exposures"
CONTESTED = "security.contested_exposures"
APP_JUDGMENTS = "security.app_not_affected_judgments"
JUDGMENTS = "security.not_affected_judgments"

#: The kit's VEX justifications are OpenVEX's own names; CycloneDX names them so.
CYCLONEDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}
CYCLONEDX_STATE = {
    "affected": "exploitable",
    "not_affected": "not_affected",
    "under_investigation": "in_triage",
}
_FIXED = re.compile(r"\(fixed in: (?P<versions>.*)\)\.\s*$")


class ExportRefused(RuntimeError):
    """The state cannot be exported faithfully (a contested pair in a covered list, a
    pair in two lists, a capped Query)."""


class Reader(Protocol):
    """Reads pinned to one accepted coordinate."""

    def head(self) -> dict[str, Any]:
        """``instance_id``, ``generation``, ``git_oid``, ``state_digest``, ``proposed_at``."""
        ...

    def rows(self, name: str, params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
        """Every row of a named Query (all pages); refuses a capped answer."""
        ...

    def card(self, ref: str) -> dict[str, Any] | None:
        """A Subject's card (``claims``: predicate, claim, value), or None if absent."""
        ...

    def evidence(self, claim: str) -> dict[str, Any]:
        """A Claim's evidence: ``rationale`` and ``captures`` (capture, contract, source)."""
        ...


@dataclass
class Statement:
    cve: str
    inventory: str
    component: str
    status: str  # affected | not_affected | under_investigation
    basis: str  # confirmed | app_judgment | package_judgment | contested | unjudged
    justification: str | None = None
    detail: str | None = None
    fixed_versions: tuple[str, ...] = ()
    claims: list[dict[str, str]] = field(default_factory=list)
    evidence: list[dict[str, str]] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.cve, self.inventory, self.component)


@dataclass
class Snapshot:
    coordinate: dict[str, Any]
    statements: list[Statement]


# -- reading state ------------------------------------------------------------------------


def _claim_ids(card: Mapping[str, Any] | None, predicate: str) -> list[tuple[str, Any]]:
    """(claim id, value) of each live Claim of ``predicate`` on a card (several when
    many-valued or contested)."""

    out: list[tuple[str, Any]] = []
    for row in (card or {}).get("claims") or ():
        if row.get("predicate") != predicate:
            continue
        claims, values = row.get("claim"), row.get("value")
        if isinstance(claims, list):
            values = values if isinstance(values, list) and len(values) == len(claims) else [values] * len(claims)
            out += list(zip(claims, values, strict=True))
        elif isinstance(claims, str):
            out.append((claims, values))
    return out


def fixed_from(rationale: str | None) -> tuple[str, ...]:
    """The fixed versions OSV listed, from an ``affected_by`` reason ``(fixed in: ...)``."""

    match = _FIXED.search(rationale or "")
    if not match or match["versions"] in ("none listed", ""):
        return ()
    return tuple(v.strip() for v in match["versions"].split(",") if v.strip() and v.strip() != "...")


def _key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (str(row["cve_id"]), str(row["inventory"]), str(row["component"]))


def collect(reader: Reader, *, inventory: str | None = None) -> Snapshot:
    """Every current exposure as one statement, with its Claims and evidence."""

    def rows(name: str) -> list[dict[str, Any]]:
        found = reader.rows(name)
        return [r for r in found if inventory is None or r.get("inventory") == inventory]

    confirmed = {_key(r): r for r in rows(CONFIRMED)}
    covered_app = {_key(r): r for r in rows(COVERED_APP)}
    covered_package = {_key(r): r for r in rows(COVERED_PACKAGE)}
    urgent = {_key(r): r for r in rows(URGENT)}
    contested = {_key(r) for r in rows(CONTESTED)}
    app_judgments = {_key(r): r for r in rows(APP_JUDGMENTS)}
    package_judgments = {
        (str(r["cve_id"]), str(r["component"])): r for r in reader.rows(JUDGMENTS)
    }

    # INVARIANT: a contested pair is never stated not_affected (or affected).
    leaked = sorted(contested & (set(confirmed) | set(covered_app) | set(covered_package)))
    if leaked:
        raise ExportRefused(f"contested pairs in a covered or confirmed list: {leaked}")
    lists = [set(confirmed), set(covered_app), set(covered_package), set(urgent)]
    seen: set[tuple[str, str, str]] = set()
    for members in lists:
        twice = seen & members
        if twice:
            raise ExportRefused(f"pairs in two judgment states: {sorted(twice)}")
        seen |= members

    cards: dict[str, dict[str, Any] | None] = {}
    evidence: dict[str, dict[str, Any]] = {}

    def card(ref: str) -> dict[str, Any] | None:
        if ref not in cards:
            cards[ref] = reader.card(ref)
        return cards[ref]

    def cite(statement: Statement, ref: str, predicate: str, claim: str) -> dict[str, Any]:
        statement.claims.append({"claim": claim, "field": predicate, "subject": ref})
        if claim not in evidence:
            evidence[claim] = reader.evidence(claim)
        for capture in evidence[claim].get("captures") or ():
            statement.evidence.append(
                {
                    "claim": claim,
                    "capture": str(capture.get("capture")),
                    "contract": str(capture.get("contract") or ""),
                    "source": str(capture.get("source") or ""),
                }
            )
        return evidence[claim]

    def osv_claim(statement: Statement) -> None:
        ref = f"security.component/{statement.component}"
        for claim, value in _claim_ids(card(ref), "affected_by"):
            if str(value).lower().endswith("/" + statement.cve.lower()):
                found = cite(statement, ref, "security.component.affected_by", claim)
                statement.fixed_versions = fixed_from(found.get("rationale"))

    def scope_claim(statement: Statement, occurrence: str | None) -> None:
        if not occurrence:
            return
        ref = f"security.occurrence/{occurrence}"
        for claim, _value in _claim_ids(card(ref), "scope"):
            cite(statement, ref, "security.occurrence.scope", claim)

    def pair_claims(statement: Statement, ref: str, fields: Sequence[str]) -> list[str]:
        """Cite the pair's judgment Claims; the reasons the write stated."""

        reasons: list[str] = []
        for name in fields:
            for claim, _value in _claim_ids(card(ref), name):
                found = cite(statement, ref, f"{ref.split('/', 1)[0]}.{name}", claim)
                if found.get("rationale"):
                    reasons.append(str(found["rationale"]))
        return reasons

    statements: list[Statement] = []
    for key, row in confirmed.items():
        s = Statement(*key, status="affected", basis="confirmed")
        ref = f"security.app_exposure/{row['app_exposure']}"
        reasons = pair_claims(s, ref, ("verdict",))
        osv_claim(s)
        scope_claim(s, row.get("occurrence"))
        s.detail = reasons[0] if reasons else None
        statements.append(s)
    for key, row in covered_app.items():
        judgment = app_judgments.get(key)
        if judgment is None:
            raise ExportRefused(f"{key} is covered at app level but lists no current judgment")
        s = Statement(
            *key,
            status="not_affected",
            basis="app_judgment",
            justification=str(judgment["justification"]),
        )
        reasons = pair_claims(
            s, f"security.app_exposure/{judgment['app_exposure']}", ("justification", "verdict")
        )
        osv_claim(s)
        scope_claim(s, row.get("occurrence"))
        s.detail = reasons[0] if reasons else None
        statements.append(s)
    for key, row in covered_package.items():
        judgment = package_judgments.get((key[0], key[2]))
        if judgment is None:
            raise ExportRefused(f"{key} is covered at package level but lists no judgment")
        s = Statement(
            *key,
            status="not_affected",
            basis="package_judgment",
            justification=str(judgment["justification"]),
        )
        reasons = pair_claims(s, f"security.exposure/{judgment['exposure']}", ("justification",))
        scope_claim(s, row.get("occurrence"))
        s.detail = reasons[0] if reasons else None
        statements.append(s)
    for key, row in urgent.items():
        s = Statement(
            *key,
            status="under_investigation",
            basis="contested" if key in contested else "unjudged",
        )
        if key in contested:
            # Cite the competing Claims, so a reader sees why it is not settled.
            occurrence = str(row.get("occurrence") or "")
            pair_claims(s, f"security.app_exposure/{occurrence}--{key[0].lower()}",
                        ("justification", "verdict"))
            component = card(f"security.component/{key[2]}")
            if component and component.get("subject"):
                package = str(component["subject"]).split("/", 1)[-1]
                pair_claims(s, f"security.exposure/{package}--{key[0].lower()}", ("justification",))
            s.detail = "Contested in Cruxible: competing judgment Claims, so no judgment counts."
        else:
            s.detail = "Not yet judged in Cruxible."
        osv_claim(s)
        scope_claim(s, row.get("occurrence"))
        statements.append(s)

    for s in statements:
        s.claims = sorted({json.dumps(c, sort_keys=True): c for c in s.claims}.values(),
                          key=lambda c: (c["field"], c["claim"]))
        s.evidence = sorted({json.dumps(e, sort_keys=True): e for e in s.evidence}.values(),
                            key=lambda e: (e["claim"], e["capture"]))
    statements.sort(key=lambda s: s.key)
    return Snapshot(coordinate=dict(reader.head()), statements=statements)


# -- rendering ------------------------------------------------------------------------------


def _purl_parts(purl: str) -> tuple[str, str | None]:
    """(name, version) of a purl, percent-decoded; the text itself for anything else."""

    if not purl.startswith("pkg:"):
        return purl, None
    body = purl.split("?", 1)[0].split("#", 1)[0]
    tail = body.rsplit("/", 1)[-1]
    name, _, version = tail.partition("@")
    return unquote(name), (unquote(version) or None)


def _product_id(inventory: str) -> str:
    return inventory if inventory.startswith("pkg:") else f"urn:cruxible:inventory:{quote(inventory, safe='')}"


def _timestamp(snapshot: Snapshot, override: str | None) -> str:
    value = override or str(snapshot.coordinate.get("proposed_at") or "")
    if not value:
        raise ExportRefused("no timestamp: the coordinate names none, pass --timestamp")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.utcoffset() is None:
        raise ExportRefused(f"the timestamp {value!r} names no offset")
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _digest(snapshot: Snapshot, fmt: str, scope: str | None) -> str:
    c = snapshot.coordinate
    text = "|".join(
        str(part) for part in (TOOL, fmt, c.get("instance_id"), c.get("git_oid"), c.get("state_digest"), scope or "")
    )
    return hashlib.sha256(text.encode()).hexdigest()


def _provenance_text(snapshot: Snapshot, s: Statement) -> str:
    c = snapshot.coordinate
    claims = "; ".join(f"{x['claim']} ({x['field']})" for x in s.claims) or "none"
    captures = "; ".join(
        f"{e['capture']} ({e['contract']}, {e['source']})" for e in s.evidence
    ) or "none"
    return (
        f"Cruxible {c.get('instance_id')} generation {c.get('generation')} "
        f"(git {c.get('git_oid')}, state {c.get('state_digest')}): {s.basis}. "
        f"Claims: {claims}. Evidence: {captures}."
    )


def _fix_text(s: Statement) -> str:
    if s.fixed_versions:
        return (
            f"Upgrade {s.component} to a release OSV lists as fixed: "
            f"{', '.join(s.fixed_versions)}."
        )
    return f"OSV lists no fixed version for {s.component}: remediate or escalate."


def cyclonedx(snapshot: Snapshot, *, timestamp: str | None = None, serial: str | None = None,
              inventory: str | None = None) -> bytes:
    """A CycloneDX 1.5 VEX document (canonical JSON, one trailing newline)."""

    c = snapshot.coordinate
    digest = _digest(snapshot, "cyclonedx", inventory)
    serial = serial or f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'cruxible:vex:' + digest)}"
    inventories: dict[str, set[str]] = {}
    for s in snapshot.statements:
        inventories.setdefault(s.inventory, set()).add(s.component)
    components = []
    for inv in sorted(inventories):
        name, version = _purl_parts(inv)
        app: dict[str, Any] = {"type": "application", "bom-ref": f"inventory:{inv}", "name": name}
        if version:
            app["version"] = version
        if inv.startswith("pkg:"):
            app["purl"] = inv
        nested = []
        for purl in sorted(inventories[inv]):
            pname, pversion = _purl_parts(purl)
            item: dict[str, Any] = {"type": "library", "bom-ref": f"{inv}|{purl}", "name": pname, "purl": purl}
            if pversion:
                item["version"] = pversion
            nested.append(item)
        app["components"] = nested
        components.append(app)
    vulnerabilities = []
    for s in snapshot.statements:
        analysis: dict[str, Any] = {"state": CYCLONEDX_STATE[s.status]}
        if s.status == "not_affected" and s.justification:
            analysis["justification"] = CYCLONEDX_JUSTIFICATION[s.justification]
        if s.status == "affected" and s.fixed_versions:
            analysis["response"] = ["update"]
        analysis["detail"] = " ".join(
            part for part in (
                s.detail or "",
                f"Justification: {s.justification}." if s.justification else "",
                _provenance_text(snapshot, s),
            ) if part
        )
        entry: dict[str, Any] = {
            "bom-ref": f"vex:{s.cve}:{s.inventory}|{s.component}",
            "id": s.cve,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{s.cve}"},
            "analysis": analysis,
            "affects": [{"ref": f"{s.inventory}|{s.component}"}],
            "properties": [
                {"name": "cruxible:basis", "value": s.basis},
                *({"name": "cruxible:claim", "value": f"{x['claim']} {x['field']}"} for x in s.claims),
                *(
                    {"name": "cruxible:evidence", "value": f"{e['claim']} {e['capture']} {e['contract']} {e['source']}"}
                    for e in s.evidence
                ),
            ],
        }
        if s.status == "affected":
            entry["recommendation"] = _fix_text(s)
        vulnerabilities.append(entry)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(snapshot, timestamp),
            "tools": {"components": [{"type": "application", "name": TOOL, "version": KIT_VERSION}]},
            "properties": [
                {"name": f"cruxible:{name}", "value": str(c.get(name))}
                for name in ("instance_id", "generation", "git_oid", "state_digest")
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def openvex(snapshot: Snapshot, *, timestamp: str | None = None, document_id: str | None = None,
            author: str | None = None, inventory: str | None = None) -> bytes:
    """An OpenVEX v0.2.0 document (canonical JSON, one trailing newline)."""

    c = snapshot.coordinate
    stamp = _timestamp(snapshot, timestamp)
    digest = _digest(snapshot, "openvex", inventory)
    statements = []
    for s in snapshot.statements:
        statement: dict[str, Any] = {
            "vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{s.cve}", "name": s.cve},
            "products": [{"@id": _product_id(s.inventory), "subcomponents": [{"@id": s.component}]}],
            "status": s.status,
            "status_notes": " ".join(part for part in (s.detail or "", _provenance_text(snapshot, s)) if part),
        }
        if s.status == "not_affected":
            statement["justification"] = s.justification
            statement["impact_statement"] = s.detail or f"Judged {s.justification} in Cruxible."
        if s.status == "affected":
            statement["action_statement"] = _fix_text(s)
        statements.append(statement)
    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": document_id or f"urn:cruxible:vex:{digest}",
        "author": author or f"Cruxible security kit ({c.get('instance_id')})",
        "timestamp": stamp,
        "version": 1,
        "tooling": f"{TOOL}/{KIT_VERSION}",
        "statements": statements,
    }
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def export(reader: Reader, fmt: str, *, inventory: str | None = None, timestamp: str | None = None,
           serial: str | None = None, author: str | None = None) -> bytes:
    snapshot = collect(reader, inventory=inventory)
    if fmt == "cyclonedx":
        return cyclonedx(snapshot, timestamp=timestamp, serial=serial, inventory=inventory)
    if fmt == "openvex":
        return openvex(snapshot, timestamp=timestamp, document_id=serial, author=author, inventory=inventory)
    raise ValueError(f"format is one of {FORMATS}")


# -- the cruxible_client reader -------------------------------------------------------------


class SdkReader:
    """Reads through ``cruxible_client``, every one pinned to the head read once at start."""

    def __init__(self, cx: Any) -> None:
        head = cx.refresh()
        self._cx = cx.at(head.coordinate)
        generations = self._cx.orient(section="generations", limit=1).generations or ()
        newest = generations[0] if generations else None
        coordinate = head.coordinate.model_dump(mode="json")
        self._head = {
            "instance_id": head.instance,
            "generation": head.generation,
            "git_oid": coordinate["git_oid"],
            "state_digest": coordinate["semantic_root"],
            "proposed_at": newest.proposed_at.isoformat() if newest is not None else None,
        }

    def head(self) -> dict[str, Any]:
        return dict(self._head)

    def rows(self, name: str, params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
        page = self._cx.query(name=name, params=dict(params or {}), limit=500, at=self._head["git_oid"])
        out: list[dict[str, Any]] = []
        while True:
            data = page.model_dump(mode="json")
            if data.get("capped"):
                raise ExportRefused(f"{name} is capped ({data['capped']}): not every row is read")
            out += [dict(row) for row in data.get("rows") or ()]
            if not data.get("truncated"):
                return out
            page = page.next_page()

    def card(self, ref: str) -> dict[str, Any] | None:
        try:
            data = self._cx.get(ref).model_dump(mode="json")
        except Exception as error:  # an absent Subject refuses with the nearest names
            if "not_found" in str(error) or "unknown" in str(error).lower():
                return None
            raise
        return data.get("card", data)

    def evidence(self, claim: str) -> dict[str, Any]:
        data = self._cx.get(claim, detail="evidence").model_dump(mode="json")
        return data.get("evidence", data)


def main(argv: Sequence[str] | None = None, *, connect: Callable[[], Any] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--format", choices=FORMATS, required=True)
    parser.add_argument("--inventory", help="export one inventory (its inventory_id)")
    parser.add_argument("--timestamp", help="ISO 8601 instant (default: the generation's own)")
    parser.add_argument("--serial", help="CycloneDX serialNumber / OpenVEX @id (default: from the coordinate)")
    parser.add_argument("--author", help="OpenVEX author (default: the instance)")
    parser.add_argument("--out", help="write here instead of standard output")
    args = parser.parse_args(argv)
    if connect is None:
        from cruxible_client import Cruxible

        connect = Cruxible.connect
    cx = connect()
    try:
        content = export(
            SdkReader(cx),
            args.format,
            inventory=args.inventory,
            timestamp=args.timestamp,
            serial=args.serial,
            author=args.author,
        )
    except ExportRefused as error:
        print(f"export refused: {error}", file=sys.stderr)
        return 2
    finally:
        close = getattr(cx, "close", None)
        if callable(close):
            close()
    if args.out:
        with open(args.out, "wb") as handle:
            handle.write(content)
    else:
        sys.stdout.buffer.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
