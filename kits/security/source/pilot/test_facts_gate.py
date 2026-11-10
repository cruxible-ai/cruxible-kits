"""Codebase facts gate: ``security.code_fact``, ``rests_on`` and their Queries.

The whole kit (dependency loop and audit extension) in one in-process instance:
the demo SBOM imported and OSV answered from recordings (so an app exposure can
be judged), and the gate app's code and a facts notes file catalogued. Every
write goes through the production write path (``cruxible write``: the client
observes the cited files and sections, applies the notes edits after admission).

    PYTHONPATH=$CORE/src:$CORE/packages/cruxible-client/src:$RUNTIME/src:$CORE \\
    CRUXIBLE_PROVIDERS_CHECKOUT=$PROVIDERS python -m pytest test_facts_gate.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import facts
import findings
import inventory
import pytest
import triage
from test_audit_gate import (
    DB,
    DB_CODE,
    NOTES,
    TRACE,
    _cited_sources,
    _guides,
    agent_finding,
    changed_claims,
    code,
    created,
    install_guidance,
    production_write,
    unit_changes,
)
from test_dependency_gate import (
    CORE,
    DEMO_APP,
    DEMO_PATH,
    DEMO_SBOM,
    LOG4SHELL,
    _next_rows,
    install_dependency_guidance,
    occurrence_of,
    run_osv,
)
from test_findings_gate import REPO, findings_world, query_rows
from test_pilot_gate import NOW, import_sbom, submit, write_file

FACT = facts.CODE_FACT
FACTS_NOTES = "security/facts/gate-app.md"
FACTS_TITLE = "Codebase facts: gate-app"
TOPIC = "sql-parameterisation"
#: The passage that decides the fact: the one query that binds its value.
PARAMETERISED = 'conn.execute("SELECT * FROM users WHERE id = ?"'
CATALOG = f"""\
tag: playbill-source-catalog-v1
catalog_kind: portable
entries:
  - name: gate-app.db
    locator: {DB}
  - name: gate-app.notes
    locator: {NOTES}
  - name: gate-app.facts
    locator: {FACTS_NOTES}
"""
STATEMENT = (
    f"## {TOPIC}\n\nEvery query in app/db.py binds its values as parameters, except "
    "find_by_name, which formats name into the SQL text. Holds for app/db.py only.\n"
)


def facts_world(tmp_path: Path) -> Any:
    """The kit with both vocabularies, the demo app imported and OSV answered, and the
    gate app's code, trace notes and facts notes catalogued (never cited yet)."""

    instance = findings_world(tmp_path)
    submit(
        instance,
        {
            "kind": "change_set",
            "members": inventory.sbom_automation((("demo", DEMO_PATH),), now=NOW),
        },
        name="demo-sbom-line",
    )
    write_file(tmp_path, DEMO_PATH, DEMO_SBOM.read_bytes())
    import_sbom(instance, "demo", minute=-10)
    run_osv(instance)
    write_file(tmp_path, ".cruxible/files.yaml", CATALOG.encode())
    write_file(tmp_path, DB, DB_CODE)
    write_file(tmp_path, NOTES, TRACE)
    write_file(tmp_path, FACTS_NOTES, f"# {FACTS_TITLE}\n".encode())
    return instance


def _key(**parts: str) -> list[dict[str, str]]:
    return [{"predicate": f"{FACT}.{name}", "value": value} for name, value in parts.items()]


def record_fact(instance: Any, tmp_path: Path, *, holds: str = "partly") -> Any:
    """One write: the notes section stating the fact (appended), the fact keyed by
    repo and topic, its category citing that section, and holds citing the code."""

    outcome = production_write(
        instance,
        tmp_path,
        because="app/db.py's queries bind their values, except find_by_name",
        docs=[
            {
                "op": "append",
                "id": "fact",
                "file": FACTS_NOTES,
                "under": [FACTS_TITLE],
                "text": STATEMENT,
            }
        ],
        changes=[
            {
                "op": "create",
                "label": "fact",
                "subject_kind": FACT,
                "key": _key(repo=REPO, topic=TOPIC),
            },
            {
                "op": "set",
                "subject": {"created": "fact"},
                "field": "category",
                "value": "invariant",
                "evidence": {"kind": "section", "ref": "fact"},
            },
            {
                "op": "set",
                "subject": {"created": "fact"},
                "field": "holds",
                "value": holds,
                "evidence": code(PARAMETERISED),
            },
        ],
    )
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    return outcome


def set_holds(instance: Any, tmp_path: Path, fact: str, value: str, *, contend: bool = False):
    outcome = production_write(
        instance,
        tmp_path,
        because=f"re-read app/db.py: {value}",
        changes=[
            {
                "op": "set",
                "subject": fact,
                "field": "holds",
                "value": value,
                "evidence": code(PARAMETERISED),
                **({"contend": True} if contend else {}),
            }
        ],
    )
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    return outcome


def located_sources(instance: Any, claim: Any) -> set[str]:
    """The catalog names of the workspace files a Claim's independent citations read
    (an own-words citation's body is the write's own, with no file)."""

    from cruxible_client.contracts.captures import parse_capture_envelope
    from cruxible_client.contracts.cas_contracts import BodyAccessContext

    access = BodyAccessContext(principal_id="kit-facts-gate", can_read_body=True)
    return {
        parse_capture_envelope(
            instance.body_store().read(citation.capture_digest, access=access)
        ).source.source_identity
        for citation in claim.backing.citations
        if citation.origin == "independent"
    }


def holds_claim(outcome: Any) -> str:
    (change,) = [c for c in outcome.changes if c.field == "holds"]
    return str(change.claim).removeprefix("Claim:")


def test_one_write_records_a_fact_its_notes_and_the_code_it_rests_on(tmp_path: Path) -> None:
    """Gate 1. One write lands the notes section, the fact, category (citing the
    section) and holds (citing the code passage). One write change carries one
    evidence, so holds cannot cite the code and the notes at once: the notes back
    category."""

    from cruxible_client.contracts.write import WriteRequest

    instance = facts_world(tmp_path)
    outcome = record_fact(instance, tmp_path)
    assert {c.field: c.verdict for c in outcome.changes if c.field} == {
        "category": "supported",
        "holds": "supported",
    }
    assert [d.written for d in outcome.docs] == [True]
    claims = {c.statement.predicate: c for c in changed_claims(instance, outcome)}
    # holds cites the code passage alone; category cites the notes section, as own words
    # with a located copy of the section it wrote.
    assert _cited_sources(instance, claims[FACT + ".holds"]) == {"gate-app.db"}
    assert {c.origin for c in claims[FACT + ".holds"].backing.citations} == {"independent"}
    category = claims[FACT + ".category"]
    assert {c.origin for c in category.backing.citations} == {"self_source", "independent"}
    assert located_sources(instance, category) == {"gate-app.facts"}
    (fact,) = created(outcome, FACT)
    (row,) = query_rows(instance, facts.FACTS_QUERY, repo=REPO)
    assert (f"{FACT}/{row['fact']}", row["topic"], row["category"], row["holds"]) == (
        fact,
        TOPIC,
        "invariant",
        "partly",
    )
    # A change has one evidence field: two citations on one change do not parse.
    with pytest.raises(ValueError):
        WriteRequest.model_validate(
            {
                "because": "x",
                "changes": [
                    {
                        "op": "set",
                        "subject": fact,
                        "field": "holds",
                        "value": "yes",
                        "evidence": [code(PARAMETERISED), {"kind": "section", "ref": "fact"}],
                    }
                ],
            }
        )
    # Evidence is required: holds in own words alone is refused.
    refused = production_write(
        instance,
        tmp_path,
        because="I am sure it holds",
        changes=[{"op": "set", "subject": fact, "field": "holds", "value": "yes"}],
    )
    assert refused.status == "refused", refused.model_dump(mode="json")


def test_editing_the_cited_passage_brings_the_fact_back_and_elsewhere_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate 2. next lists the fact's holds as citation_drifted once its cited code
    passage changes; an edit elsewhere in the same file does not."""

    monkeypatch.setenv("CRUXIBLE_STATE_ROOT", str(tmp_path / "server-state"))
    instance = facts_world(tmp_path)
    claim = holds_claim(record_fact(instance, tmp_path))

    def drifted() -> bool:
        rows = _next_rows(instance, tmp_path, "citation_drifted")
        return any(claim in json.dumps(row.model_dump(mode="json")) for row in rows)

    assert not drifted()
    write_file(tmp_path, DB, DB_CODE.replace(b"Look a user up by name.", b"Find users by name."))
    assert not drifted(), "an edit outside the cited passage must not reopen the fact"
    write_file(tmp_path, DB, DB_CODE.replace(b"WHERE id = ?", b"WHERE id = '%s'"))
    assert drifted(), "editing the cited passage must surface the fact as citation_drifted"


def resting_judgments(instance: Any, tmp_path: Path, fact: str) -> dict[str, str]:
    """A finding, a coverage unit and an app exposure, each resting on ``fact``;
    their Subjects by kind."""

    rests = {"op": "add", "field": "rests_on", "value": fact}
    outcome = production_write(
        instance,
        tmp_path,
        because="find_by_name formats name into the SQL text",
        changes=[
            *agent_finding("f", unit=None)[:-1],
            {**rests, "subject": {"created": "f"}},
            *unit_changes("u", "app/db.py#find_by_name", "injection", "checked", evidence=code()),
            {**rests, "subject": {"created": "u"}},
        ],
    )
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    judgment = triage.app_judgment(
        occurrence_of(instance, DEMO_APP, CORE),
        LOG4SHELL,
        reason="vulnerable_code_not_in_execute_path",
        because="The app logs no attacker input; all logging goes through the fact's helper.",
        accept="if_allowed",
    )
    judgment["changes"].append({**rests, "subject": {"created": "app_exposure"}})
    app = production_write(
        instance, tmp_path, because=judgment["because"], changes=judgment["changes"]
    )
    assert app.status == "accepted", app.model_dump(mode="json")
    supported = [c.verdict for c in (*outcome.changes, *app.changes) if c.field == "rests_on"]
    assert supported == ["supported"] * 3, supported
    return {
        findings.FINDING: created(outcome, findings.FINDING)[0],
        findings.UNIT: created(outcome, findings.UNIT)[0],
        inventory.APP_EXPOSURE: created(app, inventory.APP_EXPOSURE)[0],
    }


def resting(instance: Any, fact: str) -> dict[str, list[str]]:
    return {
        kind: [
            f"{r['judgment_kind']}/{r['judgment']}"
            for r in query_rows(instance, facts.RESTING_ON[kind], fact=fact)
        ]
        for kind in facts.JUDGING_KINDS
    }


def weakened(instance: Any) -> dict[str, list[str]]:
    return {
        kind: [
            f"{r['judgment_kind']}/{r['judgment']}"
            for r in query_rows(instance, facts.ON_WEAKENED[kind], repo=REPO)
        ]
        for kind in facts.JUDGING_KINDS
    }


def causes(instance: Any) -> dict[str, list[tuple[str, str]]]:
    return {
        kind: [
            (f"{r['judgment_kind']}/{r['judgment']}", f"{FACT}/{r['fact']}")
            for r in query_rows(instance, facts.WEAKENED_CAUSES[kind], repo=REPO)
        ]
        for kind in facts.JUDGING_KINDS
    }


def test_rests_on_from_each_judging_kind_resolves_and_lists_on_the_fact(tmp_path: Path) -> None:
    """Gate 3. A finding, a coverage unit and an app exposure each rest on the fact;
    each kind's resting_on Query lists exactly its own judgment."""

    instance = facts_world(tmp_path)
    (fact,) = created(record_fact(instance, tmp_path, holds="yes"), FACT)
    judged = resting_judgments(instance, tmp_path, fact)
    assert resting(instance, fact) == {kind: [ref] for kind, ref in judged.items()}


def test_judgments_on_weakened_facts_need_a_resolved_no_or_partly(tmp_path: Path) -> None:
    """Gate 4. holds = yes lists nothing; a resolved no lists every dependent; a
    contested holds (a real contend write) is no resolved value and lists nothing."""

    instance = facts_world(tmp_path)
    (fact,) = created(record_fact(instance, tmp_path, holds="yes"), FACT)
    judged = resting_judgments(instance, tmp_path, fact)
    nothing = {kind: [] for kind in facts.JUDGING_KINDS}
    assert weakened(instance) == nothing
    set_holds(instance, tmp_path, fact, "no")
    assert weakened(instance) == {kind: [ref] for kind, ref in judged.items()}
    assert causes(instance) == {kind: [(ref, fact)] for kind, ref in judged.items()}
    set_holds(instance, tmp_path, fact, "yes", contend=True)
    (row,) = query_rows(instance, facts.FACTS_QUERY, repo=REPO)
    assert row["holds"] is None, row  # contested: no single value
    assert weakened(instance) == nothing
    assert causes(instance) == nothing


def test_a_judgment_on_two_weakened_facts_is_listed_once_with_both_causes(
    tmp_path: Path,
) -> None:
    """A finding resting on two facts that hold no is one row of
    findings_on_weakened_facts, and two rows (one per fact) of its causes Query."""

    instance = facts_world(tmp_path)
    (first,) = created(record_fact(instance, tmp_path, holds="no"), FACT)
    judged = resting_judgments(instance, tmp_path, first)
    second = production_write(
        instance,
        tmp_path,
        because="find_by_id is the only query that binds",
        changes=[
            {
                "op": "create",
                "label": "f2",
                "subject_kind": FACT,
                "key": _key(repo=REPO, topic="query-binding"),
            },
            {"op": "set", "subject": {"created": "f2"}, "field": "category", "value": "control"},
            {
                "op": "set",
                "subject": {"created": "f2"},
                "field": "holds",
                "value": "no",
                "evidence": code(PARAMETERISED),
            },
        ],
    )
    assert second.status == "accepted", second.model_dump(mode="json")
    (other,) = created(second, FACT)
    finding = judged[findings.FINDING]
    linked = production_write(
        instance,
        tmp_path,
        because="also rests on the binding fact",
        changes=[{"op": "add", "subject": finding, "field": "rests_on", "value": other}],
    )
    assert linked.status == "accepted", linked.model_dump(mode="json")
    assert weakened(instance) == {kind: [ref] for kind, ref in judged.items()}
    found = causes(instance)
    assert sorted(found[findings.FINDING]) == sorted([(finding, first), (finding, other)])
    for kind in (findings.UNIT, inventory.APP_EXPOSURE):
        assert found[kind] == [(judged[kind], first)]


def test_two_claims_citing_one_passage_each_come_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate 5 (fact-finding). The fact's holds and a coverage unit's status cite the
    same code passage; when it changes, next names each Claim."""

    monkeypatch.setenv("CRUXIBLE_STATE_ROOT", str(tmp_path / "server-state"))
    instance = facts_world(tmp_path)
    fact_claim = holds_claim(record_fact(instance, tmp_path))
    outcome = production_write(
        instance,
        tmp_path,
        because="find_by_id binds user_id",
        changes=unit_changes(
            "u", "app/db.py#find_by_id", "injection", "checked", evidence=code(PARAMETERISED)
        ),
    )
    assert outcome.status == "accepted", outcome.model_dump(mode="json")
    (status,) = [c for c in outcome.changes if c.field == "status"]
    unit_claim = str(status.claim).removeprefix("Claim:")
    write_file(tmp_path, DB, DB_CODE.replace(b"WHERE id = ?", b"WHERE id = '%s'"))
    rows = [
        json.dumps(row.model_dump(mode="json"))
        for row in _next_rows(instance, tmp_path, "citation_drifted")
    ]
    named = {claim for claim in (fact_claim, unit_claim) if any(claim in r for r in rows)}
    assert named == {fact_claim, unit_claim}, rows
    assert sum(fact_claim in r for r in rows) == 1 and sum(unit_claim in r for r in rows) == 1


def test_the_guidance_guides_the_fact_and_rests_on_claim_types(tmp_path: Path) -> None:
    """The installed guidance Documents link the new ClaimTypes their readers write."""

    instance = facts_world(tmp_path)
    install_dependency_guidance(instance)
    install_guidance(instance)

    def guides(predicate: str) -> list[str]:
        return sorted(source for source, _title in _guides(instance, f"ClaimType:{predicate}"))

    doc = "document:security.guidance."
    for predicate in (FACT + ".category", FACT + ".holds", findings.FINDING + ".rests_on"):
        assert guides(predicate) == [doc + "hunter", doc + "verifier"], predicate
    assert guides(findings.UNIT + ".rests_on") == [doc + "coverage", doc + "hunter"]
    assert guides(inventory.APP_EXPOSURE + ".rests_on") == [doc + "dependency"]


# -- read cost ----------------------------------------------------------------------------

_FLAT = ("sql_statements", "sql_vm_steps", "projection_binds", "claim_parses")
OTHER_REPO = "github.com/acme/other-app"


def _synthetic_sbom(size: int) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"name": "other", "purl": "pkg:generic/other@1"}},
            "components": [
                {"type": "library", "name": f"u{i}", "purl": f"pkg:pypi/u{i}@1.0"}
                for i in range(size)
            ],
        }
    ).encode()


def counted_fact_reads(tmp_path: Path, unrelated: int) -> dict[str, dict[str, float]]:
    """The fact reads of the gate app beside an unrelated inventory of ``unrelated``
    components and ``unrelated`` facts of another repository."""

    from tests.test_scale._counters import counting, trace_sqlite

    out: dict[str, dict[str, float]] = {}
    with trace_sqlite(tmp_path):
        instance = facts_world(tmp_path)
        (fact,) = created(record_fact(instance, tmp_path, holds="no"), FACT)
        resting_judgments(instance, tmp_path, fact)
        submit(
            instance,
            {
                "kind": "change_set",
                "members": inventory.sbom_automation((("other", "sboms/other.cdx.json"),), now=NOW),
            },
            name="other-sbom-line",
        )
        write_file(tmp_path, "sboms/other.cdx.json", _synthetic_sbom(unrelated))
        import_sbom(instance, "other", minute=2)
        others = production_write(
            instance,
            tmp_path,
            because="another repository's facts",
            changes=[
                change
                for index in range(unrelated)
                for change in (
                    {
                        "op": "create",
                        "label": f"o{index}",
                        "subject_kind": FACT,
                        "key": _key(repo=OTHER_REPO, topic=f"topic-{index}"),
                    },
                    {
                        "op": "set",
                        "subject": {"created": f"o{index}"},
                        "field": "category",
                        "value": "control",
                    },
                )
            ],
        )
        assert others.status == "accepted", others.model_dump(mode="json")
        reads = {
            "facts": lambda: query_rows(instance, facts.FACTS_QUERY, repo=REPO),
            **{
                f"resting:{kind}": (
                    lambda k=kind: query_rows(instance, facts.RESTING_ON[k], fact=fact)
                )
                for kind in facts.JUDGING_KINDS
            },
            **{
                f"weakened:{kind}": (
                    lambda k=kind: query_rows(instance, facts.ON_WEAKENED[k], repo=REPO)
                )
                for kind in facts.JUDGING_KINDS
            },
            **{
                f"causes:{kind}": (
                    lambda k=kind: query_rows(instance, facts.WEAKENED_CAUSES[k], repo=REPO)
                )
                for kind in facts.JUDGING_KINDS
            },
        }
        for read in reads.values():
            read()  # warm: the first read after a write folds that write's projections
        for name, read in reads.items():
            with counting(tmp_path) as window:
                rows = read()
            assert not window.unexplained, window.unexplained
            assert len(rows) == 1, (name, rows)
            out[name] = {counter: window.counts[counter] for counter in _FLAT}
    return out


def test_fact_reads_are_flat_in_unrelated_inventories_and_repositories(tmp_path: Path) -> None:
    """code_facts, resting_on and on_weakened_facts cost the same beside 10 or 40
    unrelated components and 10 or 40 facts of another repository."""

    (tmp_path / "warm").mkdir()
    counted_fact_reads(tmp_path / "warm", 10)
    measured = {}
    for unrelated in (10, 40):
        root = tmp_path / f"u{unrelated}"
        root.mkdir()
        measured[unrelated] = counted_fact_reads(root, unrelated)
    for read in measured[10]:
        small, large = measured[10][read], measured[40][read]
        for counter in ("sql_statements", "projection_binds", "claim_parses"):
            assert large[counter] == small[counter], (read, counter, measured)
        assert large["sql_vm_steps"] <= small["sql_vm_steps"] * 1.05, (read, measured)
