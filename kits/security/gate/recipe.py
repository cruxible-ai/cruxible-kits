"""The kit docs' consumer recipe as payloads, for the release gate and the self-dogfood run.

Every function returns authoring JSON for a change the kit's pages make: ``automation()``
loads ``examples/automation.json``; ``repositories()``, ``pypi_projects()`` and
``scanned_repositories()`` are the JSON forms of intake.md's per-source SDK snippets (Add a
repository, Add a PyPI project), and ``graduate()`` and ``watch()`` those of README.md (Measure
and graduate) and in-depth.md (watching). ``own_sources()`` applies the per-source recipe to
this repository's own sources: the gate's recorded fixture repository, which the self-dogfood
reads live.
``test_doc_snippets.py`` runs the pages' Python snippets against a gate world and checks
that they write what these payloads describe. Nothing here talks to a daemon.
Capture-landing Triggers resolve CaptureContracts by name at prepare time.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import UTC, datetime, timedelta
from typing import Any

POLICY = "default"
#: Line -> (Procedure, max_authority, trigger_input)
LINES: dict[str, tuple[str, str, str | None]] = {
    "security.kev-daily": ("security.fetch-observed", "observe", None),
    "security.kev-triage": ("security.kev-triage", "propose", "catalog"),
    "security.kev-attention": ("security.kev-attention", "observe", "catalog"),
    "security.epss-daily": ("security.epss-acquire", "observe", None),
    "security.epss-triage": ("security.epss-triage", "propose", "epss"),
    "security.sbom-import": ("security.sbom-import", "propose", "sbom"),
    "security.osv-applicability": ("security.osv-applicability", "propose", None),
    "security.cve-applicability": ("security.cve-applicability", "propose", "record"),
    "security.harden": ("security.harden", "observe", None),
    "security.inventory-import.prod": ("security.inventory-import", "propose", "inventory"),
    "security.credential-import": ("security.credential-import", "propose", "credential"),
}

#: This repository's own sources, by Line suffix, through intake.md's per-source recipe:
#: the gate's recorded fixture repository (and the self-dogfood's live one).
OWN_REPOSITORIES = {"cruxible-ci": ("cruxible-ai/cruxible", "main")}
OWN_PYPI_PROJECTS = ("cruxible", "cruxible-client")
OWN_SCANNED_REPOSITORIES = {"cruxible": "github.com/cruxible-ai/cruxible"}
WORKFLOWS_SCOPE, WORKFLOWS_PATH = "ci.workflows", ".github/workflows/"
#: Versions each PyPI read takes (the newest N).
PYPI_VERSIONS = 3


def _landing(contract: str, logical_source: str) -> dict[str, Any]:
    return {"kind": "capture_landing", "capture_contract": contract,
            "logical_sources": [logical_source]}


def _cron(expression: str) -> dict[str, Any]:
    return {"kind": "cron", "expression": expression}


def _line(name: str, procedure: str, authority: str, *, trigger_input: str | None = None,
          parameters: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"kind": "line", "name": name, "procedure_name": procedure,
                               "max_authority": authority}
    if trigger_input is not None:
        payload["trigger_input"] = trigger_input
    payload["parameters"] = parameters
    return payload


def _trigger(name: str, line_name: str, schedule: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "trigger", "name": name, "line_name": line_name, "schedule": schedule}


def repositories(repos: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    """intake.md, Add a repository: per repository (Line suffix -> (``owner/repo`` on
    github.com, the branch)), a pull Line every 6 hours (minutes staggered by 5) and a parse
    Line its snapshot's landing starts. The example's propose Mandate covers every parse."""

    members: list[dict[str, Any]] = []
    for index, (slug, (full_name, ref)) in enumerate(repos.items()):
        read = {"forge_host": "github.com", "full_name": full_name, "ref": ref,
                "scope": WORKFLOWS_SCOPE, "path": WORKFLOWS_PATH}
        repo_source = f"github.com/{full_name}@{ref}"
        pull, parse = f"security.repo-pull.{slug}", f"security.repo-parse.{slug}"
        members += [
            _line(pull, "security.repo-acquire", "observe", parameters=read),
            _line(parse, "security.repo-parse", "propose", trigger_input="snapshot",
                  parameters={"source": f"{repo_source}:{WORKFLOWS_PATH}",
                              "repo_source": repo_source, **read}),
            _trigger(pull, pull, _cron(f"{(5 + 5 * index) % 60} */6 * * *")),
            _trigger(f"security.repo-landed.{slug}", parse,
                     _landing("security.fetched-v1", "github.repo.snapshot")),
        ]
    return members


def pypi_projects(projects: tuple[str, ...]) -> list[dict[str, Any]]:
    """intake.md, Add a PyPI project: per project, a daily pull Line (06:20 UTC, minutes
    staggered by 5) and a parse Line its release read's landing starts."""

    members: list[dict[str, Any]] = []
    for index, project in enumerate(projects):
        pull, parse = f"security.registry-pull.{project}", f"security.registry-parse.{project}"
        members += [
            _line(pull, "security.registry-acquire", "observe",
                  parameters={"project": project, "versions": PYPI_VERSIONS}),
            _line(parse, "security.registry-parse", "propose", trigger_input="registry",
                  parameters={"source": f"pypi/{project}", "project": project,
                              "versions": PYPI_VERSIONS}),
            _trigger(pull, pull, _cron(f"{(20 + 5 * index) % 60} 6 * * *")),
            _trigger(f"security.registry-landed.{project}", parse,
                     _landing("security.fetched-v1", "pypi.release")),
        ]
    return members


def scanned_repositories(scanned: dict[str, str]) -> list[dict[str, Any]]:
    """intake.md, Add a repository (its scans): per repository (Line suffix -> ``repo_ref``),
    the SARIF import and attention Lines, each started by a SARIF log's landing."""

    members: list[dict[str, Any]] = []
    for slug, repo_ref in scanned.items():
        imports, attention = f"security.sarif-import.{slug}", f"security.sarif-attention.{slug}"
        members += [
            _line(imports, "security.sarif-import", "propose", trigger_input="sarif",
                  parameters={"repo_ref": repo_ref}),
            _line(attention, "security.sarif-attention", "observe", trigger_input="sarif",
                  parameters={"repo_ref": repo_ref}),
            _trigger(f"security.sarif-landed.{slug}", imports,
                     _landing("security.file-v1", "sarif.log")),
            _trigger(f"security.sarif-landed-attention.{slug}", attention,
                     _landing("security.file-v1", "sarif.log")),
        ]
    return members


#: intake.md's placeholders: what its snippets author, as ``test_doc_snippets.py`` checks.
EXAMPLE_REPOSITORIES = {"example-app": ("example-org/example-app", "main")}
EXAMPLE_PYPI_PROJECTS = ("example-app",)
EXAMPLE_SCANNED_REPOSITORIES = {"example-app": "github.com/example-org/example-app"}


def example_sources() -> list[dict[str, Any]]:
    """The Lines and Triggers intake.md's per-source snippets author for its placeholders."""

    return (repositories(EXAMPLE_REPOSITORIES) + pypi_projects(EXAMPLE_PYPI_PROJECTS)
            + scanned_repositories(EXAMPLE_SCANNED_REPOSITORIES))


def own_sources() -> list[dict[str, Any]]:
    """The per-source Lines and Triggers for this repository's own sources."""

    return (repositories(OWN_REPOSITORIES) + pypi_projects(OWN_PYPI_PROJECTS)
            + scanned_repositories(OWN_SCANNED_REPOSITORIES))


#: Every Line ``automation(sources=True)`` authors: the example's and the own sources'.
LINES.update({member["name"]: (member["procedure_name"], member["max_authority"],
                               member.get("trigger_input"))
              for member in own_sources() if member["kind"] == "line"})

#: Lines the gate drives by hand (`line run`) instead of their clock: its runs must
#: not race a tick.
HELD_LINES = {"security.kev-daily", "security.repo-pull.cruxible-ci",
              "security.registry-pull.cruxible", "security.registry-pull.cruxible-client"}
#: Network slots are bound to recorded fixture Sources only in the release gate.
FIXTURE_INTERFACES = {"web.fetch", "security.epss-daily", "security.osv-query",
                      "security.osv-ecosystems", "security.repo-snapshot",
                      "security.pypi-release", "security.release-asset"}


def fixture_bindings(procedure: str) -> dict[str, str]:
    path = Path(__file__).parents[1] / "source/authoring/data/procedures.json"
    spec = next(s for s in json.loads(path.read_text()) if s["procedure"] == procedure)
    return {slot: "security-gate-sources" for slot, interface in spec["slots"].items()
            if interface.partition("@")[0] in FIXTURE_INTERFACES}


APPLICABILITY_NAMESPACE = [
    "claims", "subjects/security.assessment", "subjects/security.vulnerability"]
#: Procedure -> (namespace, wall clock s, provider calls, capture bytes, items)
MANDATES: dict[str, tuple[list[str], int, int, int, int]] = {
    "security.kev-triage": (["claims"], 300, 2, 16_777_216, 5000),
    "security.epss-triage": (["claims"], 300, 2, 33_554_432, 5000),
    "security.sbom-import": (
        ["claims", "subjects/security.product", "subjects/security.release",
         "subjects/security.supplier"], 300, 2, 16_777_216, 5000),
    "security.osv-applicability": (APPLICABILITY_NAMESPACE, 600, 3, 67_108_864, 5000),
    "security.cve-applicability": (APPLICABILITY_NAMESPACE, 300, 2, 16_777_216, 5000),
    "security.repo-parse": (
        ["claims", "subjects/security.artifact", "subjects/security.coverage",
         "subjects/security.job", "subjects/security.repo", "subjects/security.target",
         "subjects/security.workflow"], 300, 2, 16_777_216, 5000),
    "security.registry-parse": (
        ["claims", "subjects/security.artifact", "subjects/security.change",
         "subjects/security.coverage", "subjects/security.release", "subjects/security.repo",
         "subjects/security.target", "subjects/security.workflow"], 300, 2, 16_777_216, 5000),
    "security.sarif-import": (
        ["claims", "subjects/security.finding", "subjects/security.repo"], 300, 2, 16_777_216,
        5000),
    "security.inventory-import": (
        ["claims", "subjects/security.asset", "subjects/security.coverage",
         "subjects/security.release"], 300, 2, 1_048_576, 5000),
    "security.log-import": (["claims"], 120, 2, 1_048_576, 100),
    "security.credential-import": (
        ["claims", "subjects/security.credential"], 120, 2, 1_048_576, 500),
}
KEV_FIELDS = ("kev_date_added", "kev_due_date", "kev_listed", "kev_ransomware_use")
EPSS_FIELDS = ("epss_percentile", "epss_score")


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def example() -> dict[str, Any]:
    """Load the inert documented ChangeSet; fill only the two validity timestamps."""
    path = Path(__file__).resolve().parents[1] / "examples" / "automation.json"
    value = json.loads(path.read_text())
    now = _now()
    for member in value["members"]:
        if member["kind"] == "procedure_mandate":
            member.update(valid_from=_stamp(now), expires_at=_stamp(now + timedelta(days=90)))
    return value


def mandate(procedure: str, grants: str, *, name: str | None = None,
            days: int = 90, **extra: Any) -> dict[str, Any]:
    namespace, seconds, calls, capture_bytes, items = MANDATES[procedure]
    now = _now()
    return {
        "kind": "procedure_mandate",
        "name": name or f"{procedure}-{grants}",
        "procedure_name": procedure,
        "grants": grants,
        "namespace": namespace if grants == "propose" else ["claims"],
        "valid_from": _stamp(now),
        "expires_at": _stamp(now + timedelta(days=days)),
        "resource_ceiling": {
            "max_wall_clock": {"microseconds": seconds * 1_000_000},
            "max_provider_calls": calls,
            "max_capture_bytes": capture_bytes,
            "max_items": items,
            "max_repeat_attempts": 1,
        },
        **extra,
    }


def line(name: str, *, authority: str | None = None) -> dict[str, Any]:
    procedure, cap, trigger_input = LINES[name]
    payload: dict[str, Any] = {
        "kind": "line", "name": name, "procedure_name": procedure,
        "max_authority": authority or cap,
    }
    documented = next((m for m in example()["members"] + own_sources()
                       if m.get("kind") == "line" and m.get("name") == name), {})
    if "parameters" in documented:
        payload["parameters"] = documented["parameters"]
    if trigger_input is not None:
        payload["trigger_input"] = trigger_input
    return payload


def automation(*, fixtures: bool = False, sources: bool = False) -> dict[str, Any]:
    """Step 2: every Line, its Triggers, and the propose mandates, in one change set: the
    example as a consumer submits it, plus (``sources``) the own sources' Lines and Triggers,
    as intake.md's recipe authors them."""

    value = example()
    if sources:
        value["members"] += own_sources()
    if fixtures:
        for member in value["members"]:
            if member["kind"] == "line":
                bindings = fixture_bindings(member["procedure_name"])
                if bindings:
                    member["bindings"] = bindings
    return value


def graduate() -> dict[str, Any]:
    """Step 8: settle the verbatim KEV and EPSS fields under settle mandates."""

    def scope(fields: tuple[str, ...]) -> list[dict[str, Any]]:
        return [{"claim_type": f"security.vulnerability.{field}",
                 "change_kinds": ["create", "revise"]} for field in fields]

    condition = {"query_name": "security.settle_condition",
                 "binding_parameter": "vulnerability_id", "required_fields": ["cve_id"],
                 "fallback": "propose"}
    return {"kind": "change_set",
            "rationale": "Graduate KEV and EPSS triage to settle.",
            "members": [
                mandate("security.kev-triage", "settle", scope=scope(KEV_FIELDS),
                        condition=condition),
                mandate("security.epss-triage", "settle", scope=scope(EPSS_FIELDS),
                        condition=condition),
                line("security.kev-triage", authority="settle"),
                line("security.epss-triage", authority="settle"),
            ]}


def subject(kind: str, key: Any, rationale: str) -> dict[str, Any]:
    return {"kind": "subject", "subject_kind": kind, "key": key, "rationale": rationale}


def claim(subject_ref: str, predicate: str, value: Any, rationale: str, *,
          subject_valued: bool = False) -> dict[str, Any]:
    obj: dict[str, Any] = (
        {"kind": "subject", "subject": subject_ref_of(value)} if subject_valued
        else {"kind": "literal", "value": value}
    )
    return {"kind": "claim", "subject": subject_ref, "predicate": predicate, "object": obj,
            "role": "normative", "rationale": rationale,
            "source": {"kind": "self_source", "body": rationale + "\n"}}


def subject_ref_of(value: str) -> str:
    return value


def watch(*cves: str, reason: str = "Tracked by the security team.") -> dict[str, Any]:
    """Watch CVEs: create each vulnerability by key (a held key creates nothing) and state
    the decision to track it (``watch_reason``). Existence alone watches nothing."""

    members: list[dict[str, Any]] = []
    for cve in cves:
        canonical = cve.strip().upper()
        members.append(subject("security.vulnerability", cve, f"Track {canonical}."))
        members.append({
            "kind": "claim",
            # A claim member names the Subject its sibling creates by its kind and key.
            "subject": {"subject_kind": "security.vulnerability", "key": {"cve_id": canonical}},
            "predicate": "security.vulnerability.watch_reason",
            "object": {"kind": "literal", "value": reason},
            "role": "normative",
            "rationale": f"Track {canonical}: {reason}",
            "source": {"kind": "self_source", "body": f"track {canonical}: {reason}\n"},
        })
    return {"kind": "change_set", "rationale": "Watch vulnerabilities.", "members": members}
