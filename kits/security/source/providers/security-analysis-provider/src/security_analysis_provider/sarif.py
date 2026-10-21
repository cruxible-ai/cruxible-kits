"""SARIF 2.1.0 scan results: first-party code findings, keyed so every finder meets.

``SarifFindings`` (``security.sarif-findings``) reads a retained SARIF log (the
``security.sarif-v1`` Capture's text) beside the findings held for one
repository (rows of ``security.finding_index``) and returns what changed, as
proposal ``items`` (the import Line proposes them) and ``inbox`` items (the
attention Line posts them). No network, no clock: the output is a function of
the input.

**The key.** A finding is one weakness of one kind at one place in one
repository's code: ``repo_ref`` (host/owner/repo), ``weakness`` and ``locus``.

- ``repo_ref``: the run's ``versionControlProvenance[0].repositoryUri``,
  reduced to ``host/owner/repo`` and casefolded. A run that names another
  repository (or none) is not this Line's: the run is skipped, and a log
  with no run of the Line's repository halts ``wrong_repo``.
- ``weakness``: the smallest CWE number the rule or result names
  (``CWE-89`` from a Semgrep tag ``CWE-89: ...`` or a CodeQL tag
  ``external/cwe/cwe-089``); with none, ``RULE:<tool>/<ruleId>``.
- ``locus``: ``<repo-relative POSIX path>#<locator>``, the first tier that
  applies: the **symbol** (``logicalLocations[0].fullyQualifiedName``, else the
  run's ``logicalLocations[index]``, else ``properties["cruxible.symbol"]``),
  the **snippet** (``snippet:`` + 12 hex of sha256 of the whitespace-collapsed
  ``region.snippet.text``), the tool's **line hash** (``line-hash:`` +
  ``partialFingerprints.primaryLocationLineHash``). Line numbers are never in
  the key. A result with no path or no tier is a location gap (one inbox item
  per tool, rule and path), never a finding.

The tool is the first word of ``tool.driver.name``, casefolded (``Semgrep OSS``
is ``semgrep``, ``CodeQL`` is ``codeql``, an agent's SARIF names its
principal). Its rules are ``<tool>:<ruleId>``. Severity: ``security-severity``
(result, then rule) at least 9 / 7 / 4 / above 0 is critical / high / medium /
low; else the level (result, then the rule's default) error / warning / note is
high / medium / low.

**What is proposed.** A new key: the finding (created by key), its repository
(``finding.repo``, the repository created by key or the held one named), every
rule and tool that reported it, its severity. A held key: only the rules and
tools it does not hold yet, and a severity when it has none (a held one is
never revised: an analyst may have judged it). A dependency CVE (a rule id
that is a CVE or GHSA id, located in a manifest or lockfile) is not a finding:
it is counted ``routed_to_assessment`` (the SBOM and OSV path owns it).

**Verification.** A run *covers* a held finding when it declares
``properties["cruxible.coverage"] = "full"``, every invocation succeeded, its
tool reported the finding, and its rules include one of the finding's rules for
that tool. A covering run without the key proposes ``verification = fixed``
(unless it is already fixed or its verdict is ``false_positive``); a covering
run with the key, on a fixed finding, proposes ``present`` (a regression, also
posted). A run that does not cover a finding says nothing about it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    Bound,
    InputError,
    Row,
    claim_item,
    key_ref,
    parse_rows,
    sorted_items,
    subject_item,
)

FINDING = "security.finding"
REPO = "security.repo"
MAX_RESULTS = 20_000
SEVERITIES = ("low", "medium", "high", "critical")
LEVELS = {"error": "high", "warning": "medium", "note": "low"}
_CWE = re.compile(r"\bcwe[-_/: ]?0*(\d{1,6})\b", re.IGNORECASE)
_DEPENDENCY_RULE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$",
                              re.IGNORECASE)
#: Manifest and lockfile names: a dependency advisory located in one is the SBOM path's.
MANIFESTS = frozenset({
    "build.gradle", "build.gradle.kts", "cargo.lock", "cargo.toml", "composer.json",
    "composer.lock", "gemfile", "gemfile.lock", "go.mod", "go.sum", "package-lock.json",
    "package.json", "pipfile", "pipfile.lock", "pnpm-lock.yaml", "poetry.lock", "pom.xml",
    "pyproject.toml", "requirements.txt", "uv.lock", "yarn.lock",
})


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    text = payload.get("sarif_text")
    if not isinstance(text, str) or not text.strip() or not isinstance(payload.get("held"),
                                                                      list):
        return None
    return {"sarif": "present", "size": "small" if len(text) <= 16_777_216 else "large"}


# --- reading a SARIF log ----------------------------------------------------------


def repo_ref(uri: object) -> str | None:
    """``host/owner/repo`` (casefolded) of a repository URI, or None."""

    if not isinstance(uri, str) or not uri.strip():
        return None
    text = uri.strip()
    scp = re.fullmatch(r"[\w.-]+@([\w.-]+):(.+)", text)  # git@github.com:owner/repo.git
    if scp:
        host, path = scp.group(1), scp.group(2)
    else:
        parts = urlsplit(text if "://" in text else f"https://{text}")
        host, path = parts.hostname or "", parts.path
    segments = [s for s in path.strip("/").removesuffix(".git").split("/") if s]
    if not host or len(segments) < 2:
        return None
    return f"{host}/{segments[0]}/{segments[1]}".casefold()


def tool_name(driver: Mapping[str, Any]) -> str:
    words = str(driver.get("name") or "").split()
    return re.sub(r"[^0-9a-z._-]+", "-", words[0].casefold()).strip("-") if words else ""


def repo_path(location: Mapping[str, Any]) -> str | None:
    """The result's repository-relative POSIX path, or None (absolute, escaping, absent)."""

    artifact = location.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, Mapping) else None
    if not isinstance(uri, str) or not uri.strip():
        return None
    text = unquote(uri.strip())
    if "://" in text or text.startswith("/"):
        return None
    parts = [p for p in PurePosixPath(text).parts if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _texts(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _texts(item)


def weakness(tool: str, rule_id: str, *sources: Mapping[str, Any]) -> str:
    """``CWE-<n>`` for the smallest CWE the rule or result names, else ``RULE:tool/id``."""

    found: set[int] = set()
    for source in sources:
        properties = source.get("properties")
        if isinstance(properties, Mapping):
            for name in ("tags", "cwe", "cwes"):
                for text in _texts(properties.get(name)):
                    found.update(int(m) for m in _CWE.findall(text))
        # A taxonomy reference: relationships[].target {id: "89", toolComponent: {name: CWE}}.
        for relationship in source.get("relationships") or ():
            target = relationship.get("target") if isinstance(relationship, Mapping) else None
            component = target.get("toolComponent") if isinstance(target, Mapping) else None
            if (isinstance(component, Mapping)
                    and str(component.get("name", "")).casefold() == "cwe"):
                found.update(int(m) for m in _CWE.findall(f"CWE-{target.get('id')}"))
    found.update(int(m) for m in _CWE.findall(rule_id))
    found.discard(0)
    return f"CWE-{min(found)}" if found else f"RULE:{tool}/{rule_id}"


def snippet_locator(text: object) -> str | None:
    if not isinstance(text, str) or not text.strip():
        return None
    collapsed = " ".join(text.split())
    return "snippet:" + hashlib.sha256(collapsed.encode()).hexdigest()[:12]


def locator(result: Mapping[str, Any], run: Mapping[str, Any]) -> tuple[str, str] | None:
    """(tier, locator) of the first tier that applies, or None."""

    location = (result.get("locations") or [{}])[0]
    location = location if isinstance(location, Mapping) else {}
    logical = location.get("logicalLocations") or []
    first = logical[0] if logical and isinstance(logical[0], Mapping) else {}
    symbol = first.get("fullyQualifiedName")
    if not symbol and isinstance(first.get("index"), int):
        table = run.get("logicalLocations") or []
        if 0 <= first["index"] < len(table) and isinstance(table[first["index"]], Mapping):
            symbol = table[first["index"]].get("fullyQualifiedName")
    if not symbol:
        properties = result.get("properties")
        symbol = properties.get("cruxible.symbol") if isinstance(properties, Mapping) else None
    if isinstance(symbol, str) and symbol.strip():
        return "symbol", symbol.strip()
    physical = location.get("physicalLocation")
    region = physical.get("region") if isinstance(physical, Mapping) else None
    snippet = (region.get("snippet") or {}).get("text") if isinstance(region, Mapping) else None
    found = snippet_locator(snippet)
    if found:
        return "snippet", found
    fingerprints = result.get("partialFingerprints")
    line_hash = (fingerprints.get("primaryLocationLineHash")
                 if isinstance(fingerprints, Mapping) else None)
    if isinstance(line_hash, str) and line_hash.strip():
        return "line_hash", "line-hash:" + line_hash.strip()
    return None


def _score(value: object) -> float | None:
    try:
        return float(str(value))
    except ValueError:
        return None


def severity(result: Mapping[str, Any], rule: Mapping[str, Any]) -> str | None:
    for holder in (result, rule):
        properties = holder.get("properties")
        if isinstance(properties, Mapping):
            score = _score(properties.get("security-severity"))
            if score is not None and score > 0:
                return ("critical" if score >= 9 else "high" if score >= 7
                        else "medium" if score >= 4 else "low")
    level = result.get("level")
    if not isinstance(level, str):
        configuration = rule.get("defaultConfiguration")
        level = configuration.get("level") if isinstance(configuration, Mapping) else None
    return LEVELS.get(level) if isinstance(level, str) else None


@dataclass
class Reported:
    """One finding as one scan reports it (results with the same key merge)."""

    weakness: str
    locus: str
    tier: str
    rules: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)
    severity: str | None = None
    lines: set[str] = field(default_factory=set)

    def rank(self, value: str | None) -> None:
        if value and (self.severity is None
                      or SEVERITIES.index(value) > SEVERITIES.index(self.severity)):
            self.severity = value


@dataclass
class Run:
    tool: str
    revision: str
    full: bool
    rules: set[str]
    keys: set[tuple[str, str]] = field(default_factory=set)


@dataclass
class Scan:
    repo_ref: str | None
    runs: list[Run] = field(default_factory=list)
    reported: dict[tuple[str, str], Reported] = field(default_factory=dict)
    gaps: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    results: int = 0
    routed: int = 0
    other_repo_runs: int = 0


def _document(text: str) -> Mapping[str, Any]:
    try:
        document = json.loads(text)
    except ValueError as error:
        raise InputError("the SARIF log is not JSON") from error
    if not isinstance(document, Mapping) or not str(document.get("version", "")).startswith(
            "2.1"):
        raise InputError("the SARIF log is not SARIF 2.1.0")
    if not isinstance(document.get("runs"), list):
        raise InputError("the SARIF log has no runs")
    return document


def read_scan(text: str, line_repo: str) -> Scan:
    """Every run of ``line_repo`` in the log: its findings by key, gaps and coverage."""

    document = _document(text)
    scan = Scan(repo_ref=None)
    for run in document["runs"]:
        if not isinstance(run, Mapping):
            raise InputError("a SARIF run must be an object")
        provenance = (run.get("versionControlProvenance") or [{}])[0]
        provenance = provenance if isinstance(provenance, Mapping) else {}
        ref = repo_ref(provenance.get("repositoryUri"))
        if ref != line_repo:
            scan.other_repo_runs += 1
            continue
        scan.repo_ref = ref
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = tool_name(driver)
        if not tool:
            raise InputError("a SARIF run names no tool.driver.name")
        rules = [r for r in driver.get("rules") or () if isinstance(r, Mapping)]
        by_id = {str(r.get("id")): r for r in rules if r.get("id")}
        invocations = [i for i in run.get("invocations") or () if isinstance(i, Mapping)]
        properties = run.get("properties") if isinstance(run.get("properties"), Mapping) else {}
        current = Run(
            tool=tool, revision=str(provenance.get("revisionId") or ""),
            full=properties.get("cruxible.coverage") == "full" and bool(invocations)
            and all(i.get("executionSuccessful") is True for i in invocations),
            rules={f"{tool}:{rule_id}" for rule_id in by_id})
        scan.runs.append(current)
        for result in run.get("results") or ():
            if not isinstance(result, Mapping) or result.get("kind") in ("pass",
                                                                         "notApplicable"):
                continue
            scan.results += 1
            if scan.results > MAX_RESULTS:
                raise InputError(f"the SARIF log has more than {MAX_RESULTS} results")
            _read_result(scan, current, run, result, rules, by_id)
    return scan


def _read_result(scan: Scan, run: Run, raw_run: Mapping[str, Any], result: Mapping[str, Any],
                 rules: list[Mapping[str, Any]], by_id: Mapping[str, Mapping[str, Any]]) -> None:
    rule_id = result.get("ruleId")
    index = result.get("ruleIndex")
    if not isinstance(rule_id, str) and isinstance(index, int) and 0 <= index < len(rules):
        rule_id = rules[index].get("id")
    rule_id = str(rule_id or "")
    rule = by_id.get(rule_id, {})
    run.rules.add(f"{run.tool}:{rule_id}")
    location = (result.get("locations") or [{}])[0]
    physical = location.get("physicalLocation") if isinstance(location, Mapping) else None
    path = repo_path(physical) if isinstance(physical, Mapping) else None
    if _DEPENDENCY_RULE.fullmatch(rule_id) and path and (
            PurePosixPath(path).name.casefold() in MANIFESTS
            or PurePosixPath(path).name.casefold().startswith("requirements")):
        scan.routed += 1
        return
    tier = locator(result, raw_run)
    if path is None or tier is None:
        gap_path = path or "(none)"
        scan.gaps.setdefault((run.tool, rule_id, gap_path), {
            "kind": "location_gap", "repo_ref": scan.repo_ref, "tool": run.tool,
            "rule": f"{run.tool}:{rule_id}", "path": gap_path,
            "reason": "result lacks a repository-relative path" if path is None
            else "result lacks a stable location (no symbol, snippet or line hash)",
            "revision": run.revision})
        return
    key = (weakness(run.tool, rule_id, rule, result), f"{path}#{tier[1]}")
    found = scan.reported.setdefault(key, Reported(weakness=key[0], locus=key[1],
                                                   tier=tier[0]))
    found.rules.add(f"{run.tool}:{rule_id}")
    found.tools.add(run.tool)
    found.rank(severity(result, rule))
    region = physical.get("region") if isinstance(physical, Mapping) else None
    if isinstance(region, Mapping) and isinstance(region.get("startLine"), int):
        found.lines.add(f"{path}:{region['startLine']}")
    run.keys.add(key)


# --- what is held -------------------------------------------------------------


@dataclass
class Held:
    bound: Bound
    weakness: str
    locus: str
    rules: set[str]
    tools: set[str]
    severity: str | None
    verification: str | None
    verification_claim: str | None
    verdict: str | None


def held_findings(rows: list[Row]) -> dict[tuple[str, str], Held]:
    held: dict[tuple[str, str], Held] = {}
    for row in rows:
        bound = row.subject("finding")
        weakness_, locus = row.value("weakness"), row.value("locus")
        if bound is None or not isinstance(weakness_, str) or not isinstance(locus, str):
            continue
        held.setdefault((weakness_, locus), Held(
            bound=bound, weakness=weakness_, locus=locus,
            rules={str(v) for v in row.value("rules") or ()},
            tools={str(v) for v in row.value("reported_by") or ()},
            severity=row.value("severity"),
            verification=row.value("verification"),
            verification_claim=row.claim_id(bound, "security.finding.verification"),
            verdict=row.value("verdict") if row.state("verdict") == "present" else None))
    return held


# --- the analysis ---------------------------------------------------------------


def _covers(run: Run, finding: Held) -> bool:
    return (run.full and run.tool in finding.tools
            and any(rule.startswith(f"{run.tool}:") and rule in run.rules
                    for rule in finding.rules))


def findings(text: str, held_rows: list[Row], line_repo: str) -> dict[str, Any]:
    line_repo = repo_ref(line_repo) or ""
    if not line_repo:
        raise InputError("repo_ref must name host/owner/repo")
    scan = read_scan(text, line_repo)
    counts = {"new": 0, "added": 0, "fixed": 0, "regressed": 0}
    summary: dict[str, Any] = {
        "repo_ref": line_repo, "mine": 1 if scan.runs else 0, "results": scan.results,
        "findings": len(scan.reported), "gaps": len(scan.gaps),
        "routed_to_assessment": scan.routed, "tools": sorted({r.tool for r in scan.runs}),
        "revisions": sorted({r.revision for r in scan.runs if r.revision}),
        "full": sorted({r.tool for r in scan.runs if r.full}),
    }
    if not scan.runs:
        return {**summary, **counts, "items": [], "inbox": [], "changed": 0, "posted": 0}
    held = held_findings(held_rows)
    host, _, full_name = line_repo.partition("/")
    repo = key_ref(REPO, forge_host=host, full_name=full_name)
    subjects: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    inbox: list[dict[str, Any]] = list(scan.gaps.values())
    for key in sorted(scan.reported):
        found = scan.reported[key]
        at = ", ".join(sorted(f"{r.tool}@{r.revision[:12] or 'unknown'}" for r in scan.runs
                              if key in r.keys))
        said = f"SARIF ({at}) reports {found.weakness} at {found.locus}"
        have = held.get(key)
        subject: Any = have.bound if have else key_ref(
            FINDING, repo_ref=line_repo, weakness=found.weakness, locus=found.locus)
        if have is None:
            counts["new"] += 1
            if not subjects:  # the repository: created by key, or the held one named
                subjects.append(subject_item(REPO, {"forge_host": host, "full_name": full_name},
                                             f"SARIF scans of {line_repo}."))
            subjects.append(subject_item(FINDING, {"repo_ref": line_repo,
                                                   "weakness": found.weakness,
                                                   "locus": found.locus},
                                         f"{said} ({found.tier} tier; lines "
                                         f"{', '.join(sorted(found.lines)) or 'unknown'})."))
            claims.append(claim_item(subject, "security.finding.repo", repo,
                                     f"{said}: in {line_repo}.", role="normative"))
        for predicate, values, held_values in (
                ("security.finding.rule", found.rules, have.rules if have else set()),
                ("security.finding.reported_by", found.tools, have.tools if have else set())):
            for value in sorted(values - held_values):
                claims.append(claim_item(subject, predicate, value, f"{said}: {value}."))
                counts["added"] += 1 if have else 0
        if found.severity and (have is None or have.severity is None):
            claims.append(claim_item(subject, "security.finding.severity", found.severity,
                                     f"{said}: severity {found.severity}."))
    for key, finding in sorted(held.items()):
        covering = [run for run in scan.runs if _covers(run, finding)]
        if not covering:
            continue
        present = [run for run in covering if key in run.keys]
        at = ", ".join(sorted(f"{r.tool}@{r.revision[:12] or 'unknown'} (full)"
                              for r in (present or covering)))
        if not present and finding.verification != "fixed" and finding.verdict != (
                "false_positive"):
            claims.append(claim_item(
                finding.bound, "security.finding.verification", "fixed",
                f"A full scan ({at}) of rules that reported {finding.weakness} at "
                f"{finding.locus} no longer reports it.",
                revises=finding.verification_claim if finding.verification else None))
            counts["fixed"] += 1
        elif present and finding.verification == "fixed":
            claims.append(claim_item(
                finding.bound, "security.finding.verification", "present",
                f"A full scan ({at}) reports {finding.weakness} at {finding.locus} again "
                "after it was verified fixed: a regression.",
                revises=finding.verification_claim))
            counts["regressed"] += 1
            inbox.append({"kind": "regression", "repo_ref": line_repo,
                          "finding": f"{finding.bound.kind}/{finding.bound.subject_id}",
                          "weakness": finding.weakness, "locus": finding.locus,
                          "tools": sorted(r.tool for r in present),
                          "revisions": sorted({r.revision for r in present if r.revision})})
    items = subjects + sorted_items(claims) if claims else []
    return {**summary, **counts, "items": items, "changed": len(claims),
            "inbox": sorted_items(inbox), "posted": len(inbox)}


class SarifFindings:
    """The ``security.sarif-findings`` implementation."""

    interface_id = "security.sarif-findings"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            if context.input.get("truncated"):
                raise InputError("the held findings tap was truncated: a missing row would "
                                 "read as a new finding")
            result = findings(str(context.input.get("sarif_text") or ""),
                              parse_rows(context.input.get("held")),
                              str(context.input.get("repo_ref") or ""))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        return ProviderResult.ok(result, metrics={"items": float(len(result["items"])),
                                                  "posted": float(result["posted"])})
