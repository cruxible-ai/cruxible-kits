"""``sarif.findings``: SARIF 2.1.0 scan results -> one derived JSON document (pure).

The security kit's code-findings derive in the Procedure template (D-R37):
``read held findings -> fetch the SARIF file (workspace.file) -> derive
sarif.findings -> extract -> claims``. Core passes this run's SARIF Capture(s)
(their bytes, b1) and the findings the instance holds for the Line's repository
(typed rows of ``sarif.held-finding@1``); the operation returns ONE JSON
document, the same bytes for the same inputs. No network, no clock.

**The key.** A finding is one weakness of one kind at one place in one
repository's code: ``repo``, ``weakness`` and ``locus``. Line numbers are never
in the key, so a finding that moved lines keeps its key and re-locates (its
``reported_at`` changes) instead of duplicating.

- ``repo``: a run's ``versionControlProvenance[0].repositoryUri`` reduced to
  ``host/owner/repo`` and casefolded. Only runs of the Line's repository are
  read; a log with none of them gives no records (the wrong repository writes
  nothing).
- ``weakness``: the smallest CWE the rule or result names (a Semgrep tag
  ``CWE-89: ...``, a CodeQL tag ``external/cwe/cwe-089``, a CWE taxonomy
  relationship), else ``RULE:<tool>/<ruleId>``.
- ``locus``: ``<repo-relative POSIX path>#<locator>``, the first tier that
  applies: the **symbol** (``logicalLocations[0].fullyQualifiedName``, the
  run's ``logicalLocations[index]``, or ``properties["cruxible.symbol"]``), the
  **snippet** (``snippet:`` + 12 hex of sha256 of the whitespace-collapsed
  ``region.snippet.text``), the tool's **line hash** (``line-hash:`` +
  ``partialFingerprints.primaryLocationLineHash``). A result with no
  repository-relative path or no tier is a **location gap** (an attention
  record), never a finding.

The tool is the first word of ``tool.driver.name``, casefolded (``Semgrep OSS``
is ``semgrep``); its rules are ``<tool>:<ruleId>``. **Severity:** a
``security-severity`` (result, then rule) of at least 9 / 7 / 4 / above 0 is
critical / high / medium / low; else the level (result, then the rule's
default) error / warning / note is high / medium / low.

**Dependency advisories are routed out.** A result whose rule id is a CVE or
GHSA id, located in a manifest or lockfile, belongs to the SBOM -> OSV loop: it
is counted in ``routed``, never a finding.

**Coverage, ``fixed`` and regressions.** A run is *full* when it declares
``properties["cruxible.coverage"] = "full"`` and every invocation succeeded.
The header's ``queried`` is the rule set that ran (``tool:ruleId``, from the
driver's rules and the results), ``full`` says whether every run of the
repository was full, and ``covered`` names the held findings a full run's rule
set covers (one of the finding's rules ran in a full run): the Claims'
``expect``. A covered finding the log does not report is a ``fixed`` record; a
reported finding is ``present``. A partial scan covers nothing, so it never
marks anything fixed. A held ``fixed`` finding reported again is also a
``regressed`` attention record.

**Taint.** A result the derive cannot interpret or key (no repository path, no
stable locator, an unkeyable locus, malformed locations) may be a held
finding, so its rule is *tainted*: the rule covers nothing in this scan, its
held findings stay out of ``covered`` and get no ``fixed`` record, and the
result is a location gap in ``attention``. A result that is no record at all,
or names no rule, taints its whole tool for the scan (a run's rule catalog may
be empty or omit that rule, so no rule list bounds it): no held finding that
tool reported is covered, whatever another run of the tool says. Nothing is skipped silently.
The header lists the tainted rules. Coverage is one index of qualified rules
(covered = run by a full run, minus tainted), built once; each held finding is
checked against it in O(its rules).

Output::

    {"repo", "full", "queried": [rule], "covered": [subject_id],
     "tainted": [rule], "tainted_tools": [tool], "count",
     "findings":  [{repo, weakness, locus, verification, rule?, tool?,
                    severity?, reported_at?, tier?}],
     "attention": [{kind: regression | location_gap, ref, repo, rule, path,
                    weakness?, locus?, finding?, reason?}],
     "routed":    [{rule, path}],
     "other_repo_runs", "results"}

``sarif.findings`` is a ``@derive`` function (cruxible-provider-runtime 0.6):
pure, no endpoint, its logs read as digest-checked ``CaptureView``s and its
document's wire written by ``derived_capture``, observed at the latest log's time
(never the clock), so a rebuilt build is a pure, non-widening move.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from cruxible_provider_runtime import CaptureView, decline, derive, derived_capture
from cruxible_provider_runtime.acquisition import CaptureInputError
from cruxible_provider_runtime.provider_api import ProviderResult

OPERATION = "sarif.findings"
PROVIDER_DECLINED = "provider_declined"
MAX_RESULTS = 20_000
MAX_LOGS = 16
SEVERITIES = ("low", "medium", "high", "critical")
LEVELS = {"error": "high", "warning": "medium", "note": "low"}
COORDINATE_TYPE = "http-response-v1"
SELECTOR_TYPE = "whole-response-v1"
_CWE = re.compile(r"\bcwe[-_/: ]?0*(\d{1,6})\b", re.IGNORECASE)
_DEPENDENCY_RULE = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$", re.IGNORECASE
)
#: Manifest and lockfile names: a dependency advisory located in one is the SBOM loop's.
MANIFESTS = frozenset(
    {
        "build.gradle",
        "build.gradle.kts",
        "cargo.lock",
        "cargo.toml",
        "composer.json",
        "composer.lock",
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pipfile",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)


#: The finding key's bound: each key part is at most this many code points, one line.
KEY_MAX = 256
_WEAKNESS = re.compile(r"^(CWE-[0-9]{1,6}|RULE:\S{1,240})$")


def keyable(weakness_: str, locus: str) -> bool:
    """Whether (weakness, locus) can be a finding's key: bounded, one line, printable.

    A result whose locus cannot be a key (an over-long symbol, a path or
    symbol with control characters) is a location gap, never a record core
    would refuse: an agent locates it.
    """

    return (
        bool(_WEAKNESS.fullmatch(weakness_)) and 0 < len(locus) <= KEY_MAX and locus.isprintable()
    )


def _bounded(text: str, limit: int = KEY_MAX) -> str:
    """A gap's text, one printable line within ``limit`` (a gap is attention, not a key)."""

    clean = "".join(c if c.isprintable() else "?" for c in text)
    return (
        clean
        if len(clean) <= limit
        else clean[: limit - 13] + "#" + hashlib.sha256(text.encode()).hexdigest()[:12]
    )


class InputError(ValueError):
    """An input this operation declines to read (answered ``provider_declined``)."""


# -- reading a SARIF log ---------------------------------------------------------------


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


def repo_path(physical: Mapping[str, Any]) -> str | None:
    """The result's repository-relative POSIX path, or None (absolute, escaping, absent)."""

    artifact = physical.get("artifactLocation")
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
    elif isinstance(value, list | tuple):
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
            if (
                isinstance(target, Mapping)
                and isinstance(component, Mapping)
                and str(component.get("name", "")).casefold() == "cwe"
            ):
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
    line_hash = (
        fingerprints.get("primaryLocationLineHash") if isinstance(fingerprints, Mapping) else None
    )
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
                return (
                    "critical"
                    if score >= 9
                    else "high"
                    if score >= 7
                    else "medium"
                    if score >= 4
                    else "low"
                )
    level = result.get("level")
    if not isinstance(level, str):
        configuration = rule.get("defaultConfiguration")
        level = configuration.get("level") if isinstance(configuration, Mapping) else None
    return LEVELS.get(level) if isinstance(level, str) else None


@dataclass
class Reported:
    """One finding as one log reports it (results with the same key merge)."""

    weakness: str
    locus: str
    tier: str
    rules: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)
    severity: str | None = None
    lines: set[tuple[str, int]] = field(default_factory=set)
    revision: str = ""

    def rank(self, value: str | None) -> None:
        if value and (
            self.severity is None or SEVERITIES.index(value) > SEVERITIES.index(self.severity)
        ):
            self.severity = value


@dataclass
class Run:
    tool: str
    revision: str
    full: bool
    rules: set[str]
    keys: set[tuple[str, str]] = field(default_factory=set)
    #: Rules with a result this run could not interpret or key: their absence
    #: says nothing, so no finding of theirs is covered by this scan.
    tainted: set[str] = field(default_factory=set)
    #: A result whose rule cannot be determined taints the run's whole tool for
    #: the scan (see :func:`coverage_index`).
    tainted_whole: bool = False


@dataclass
class Scan:
    runs: list[Run] = field(default_factory=list)
    reported: dict[tuple[str, str], Reported] = field(default_factory=dict)
    gaps: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    routed: set[tuple[str, str]] = field(default_factory=set)
    results: int = 0
    other_repo_runs: int = 0


def _document(content: bytes) -> Mapping[str, Any]:
    try:
        document = json.loads(content)
    except ValueError as error:
        raise InputError("the SARIF log is not JSON") from error
    if not isinstance(document, Mapping) or not str(document.get("version", "")).startswith("2.1"):
        raise InputError("the SARIF log is not SARIF 2.1.0")
    if not isinstance(document.get("runs"), list):
        raise InputError("the SARIF log has no runs")
    return document


def read_scan(logs: Sequence[bytes], repo: str) -> Scan:
    """Every run of ``repo`` in the logs: its findings by key, gaps, routed advisories."""

    scan = Scan()
    for content in logs:
        for run in _document(content)["runs"]:
            if not isinstance(run, Mapping):
                raise InputError("a SARIF run must be an object")
            provenance = (run.get("versionControlProvenance") or [{}])[0]
            provenance = provenance if isinstance(provenance, Mapping) else {}
            if repo_ref(provenance.get("repositoryUri")) != repo:
                scan.other_repo_runs += 1
                continue
            driver = (run.get("tool") or {}).get("driver") or {}
            tool = tool_name(driver)
            if not tool:
                raise InputError("a SARIF run names no tool.driver.name")
            rules = [r for r in driver.get("rules") or () if isinstance(r, Mapping)]
            by_id = {str(r.get("id")): r for r in rules if r.get("id")}
            invocations = [i for i in run.get("invocations") or () if isinstance(i, Mapping)]
            declared = run.get("properties")
            properties: Mapping[str, Any] = declared if isinstance(declared, Mapping) else {}
            current = Run(
                tool=tool,
                revision=str(provenance.get("revisionId") or "")[:64],
                full=properties.get("cruxible.coverage") == "full"
                and bool(invocations)
                and all(i.get("executionSuccessful") is True for i in invocations),
                rules={f"{tool}:{rule_id}" for rule_id in by_id},
            )
            scan.runs.append(current)
            results = run.get("results")
            if results is not None and not isinstance(results, list):
                _malformed(scan, current, repo, "results_not_a_list")
                continue
            for result in results or ():
                scan.results += 1
                if scan.results > MAX_RESULTS:
                    raise InputError(f"the SARIF logs have more than {MAX_RESULTS} results")
                if not isinstance(result, Mapping):
                    # Never skipped silently: its rule is unknown, so the run
                    # judges no absence at all.
                    _malformed(scan, current, repo, "malformed_result")
                    continue
                if result.get("kind") in ("pass", "notApplicable"):
                    continue
                _read_result(scan, current, run, result, rules, by_id, repo)
    return scan


def _gap(scan: Scan, repo: str, qualified: str, path: str | None, reason: str) -> None:
    gap_path = _bounded(path or "(none)")
    scan.gaps.setdefault(
        (qualified, gap_path),
        {
            "kind": "location_gap",
            "ref": _bounded(f"location_gap:{qualified}:{gap_path}", KEY_MAX * 2),
            "repo": repo,
            "rule": _bounded(qualified),
            "path": gap_path,
            "reason": reason,
        },
    )


def _malformed(scan: Scan, run: Run, repo: str, reason: str) -> None:
    """A result whose rule cannot be established: its tool is tainted for the scan."""

    run.tainted_whole = True
    _gap(scan, repo, f"{run.tool}:(unknown)", None, reason)


def _read_result(
    scan: Scan,
    run: Run,
    raw_run: Mapping[str, Any],
    result: Mapping[str, Any],
    rules: list[Mapping[str, Any]],
    by_id: Mapping[str, Mapping[str, Any]],
    repo: str,
) -> None:
    rule_id = result.get("ruleId")
    index = result.get("ruleIndex")
    if not isinstance(rule_id, str) and isinstance(index, int) and 0 <= index < len(rules):
        rule_id = rules[index].get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        _malformed(scan, run, repo, "no_rule")
        return
    rule = by_id.get(rule_id, {})
    qualified = f"{run.tool}:{rule_id}"
    run.rules.add(qualified)
    locations = result.get("locations")
    if locations is not None and not isinstance(locations, list):
        run.tainted.add(qualified)
        _gap(scan, repo, qualified, None, "malformed_location")
        return
    location = (locations or [{}])[0]
    physical = location.get("physicalLocation") if isinstance(location, Mapping) else None
    path = repo_path(physical) if isinstance(physical, Mapping) else None
    if (
        _DEPENDENCY_RULE.fullmatch(rule_id)
        and path
        and (
            PurePosixPath(path).name.casefold() in MANIFESTS
            or PurePosixPath(path).name.casefold().startswith("requirements")
        )
    ):
        scan.routed.add((qualified, path))
        return
    tier = locator(result, raw_run)
    key = (
        None
        if path is None or tier is None
        else (weakness(run.tool, rule_id, rule, result), f"{path}#{tier[1]}")
    )
    reason = (
        "no_repository_path"
        if path is None
        else "no_stable_location"
        if tier is None
        else None
        if key is not None and keyable(*key)
        else "unkeyable_location"
    )
    if path is None or tier is None or key is None or reason is not None:
        # The rule reported something this scan cannot place: it may be a held
        # finding, so the rule's absence proves nothing in this scan.
        run.tainted.add(qualified)
        _gap(scan, repo, qualified, path, reason or "unkeyable_location")
        return
    found = scan.reported.setdefault(key, Reported(weakness=key[0], locus=key[1], tier=tier[0]))
    found.rules.add(qualified)
    found.tools.add(run.tool)
    found.rank(severity(result, rule))
    found.revision = found.revision or run.revision
    region = physical.get("region") if isinstance(physical, Mapping) else None
    if isinstance(region, Mapping) and isinstance(region.get("startLine"), int):
        found.lines.add((path, int(region["startLine"])))
    run.keys.add(key)


# -- held findings ---------------------------------------------------------------------


@dataclass(frozen=True)
class Held:
    subject_id: str
    weakness: str
    locus: str
    rules: frozenset[str]
    verification: str | None


def held_findings(rows: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str], Held]:
    """The held findings by key. A row without its key parts is unreadable input."""

    held: dict[tuple[str, str], Held] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise InputError("a held finding row must be a record")
        subject_id, weakness_, locus = row.get("subject_id"), row.get("weakness"), row.get("locus")
        if not all(isinstance(v, str) and v for v in (subject_id, weakness_, locus)):
            raise InputError("a held finding row names no subject, weakness or locus")
        rules = row.get("rules")
        verification = row.get("verification")
        held.setdefault(
            (str(weakness_), str(locus)),
            Held(
                subject_id=str(subject_id),
                weakness=str(weakness_),
                locus=str(locus),
                rules=frozenset(str(r) for r in rules or () if isinstance(r, str)),
                verification=verification if isinstance(verification, str) else None,
            ),
        )
    return held


# -- the derive --------------------------------------------------------------------------


@dataclass(frozen=True)
class Coverage:
    """Which qualified rules this scan covers: built once, O(rules of all runs)."""

    covered: frozenset[str]
    tainted: frozenset[str]
    #: Tools with a result whose rule could not be established: every rule of
    #: the tool is suspect in this scan, listed in a catalog or not.
    tainted_tools: frozenset[str] = frozenset()


def _tool_of(rule: str) -> str:
    return rule.split(":", 1)[0]


def coverage_index(scan: Scan) -> Coverage:
    """A rule is covered when a full run ran it and no run of the scan tainted it.

    A rule a run could not interpret a result of is tainted everywhere in the
    scan. A result whose rule is unknown taints its whole TOOL for the scan: a
    run's rule catalog may be empty or omit that rule, so no list of rules can
    bound the doubt, and no other run of the tool re-authorizes a negative.
    """

    tainted: set[str] = set()
    tools: set[str] = set()
    for run in scan.runs:
        tainted |= run.tainted
        if run.tainted_whole:
            tools.add(run.tool)
    tainted |= {rule for run in scan.runs if run.tool in tools for rule in run.rules}
    covered = {
        rule
        for run in scan.runs
        if run.full and run.tool not in tools
        for rule in run.rules
        if rule not in tainted
    }
    return Coverage(
        covered=frozenset(covered), tainted=frozenset(tainted), tainted_tools=frozenset(tools)
    )


def is_covered(finding: Held, index: Coverage) -> bool:
    """One of the finding's rules is covered and none is tainted, nor its tool.

    O(its rules).
    """

    if finding.rules & index.tainted:
        return False
    if index.tainted_tools and any(_tool_of(r) in index.tainted_tools for r in finding.rules):
        return False
    return bool(finding.rules & index.covered)


def findings(
    logs: Sequence[bytes], held_rows: Sequence[Mapping[str, Any]], repo: str
) -> dict[str, Any]:
    """The derived document (pure: same inputs, same document)."""

    line_repo = repo_ref(repo) or ""
    if not line_repo or line_repo != repo:
        raise InputError("repo must be host/owner/repo, lowercase")
    scan = read_scan(logs, line_repo)
    held = held_findings(held_rows)
    records: list[dict[str, Any]] = []
    attention: list[dict[str, Any]] = list(scan.gaps.values())
    for key in sorted(scan.reported):
        found = scan.reported[key]
        path, line = min(found.lines) if found.lines else (key[1].split("#", 1)[0], 0)
        record: dict[str, Any] = {
            "repo": line_repo,
            "weakness": found.weakness,
            "locus": found.locus,
            "verification": "present",
            # One record per finding: a key several rules of one log report
            # records the lowest rule (later logs add the others they report).
            "rule": min(found.rules),
            "tool": min(found.tools),
            "tier": found.tier,
        }
        if found.severity:
            record["severity"] = found.severity
        if line:
            record["reported_at"] = f"{path}:{line}"
        records.append(record)
        have = held.get(key)
        if have is not None and have.verification == "fixed":
            attention.append(
                {
                    "kind": "regression",
                    "ref": f"regression:{have.subject_id}:{found.revision or 'unknown'}",
                    "repo": line_repo,
                    "rule": record["rule"],
                    "path": path,
                    "weakness": found.weakness,
                    "locus": found.locus,
                    "finding": have.subject_id,
                }
            )
    index = coverage_index(scan)
    covered: list[str] = []
    for key, finding in sorted(held.items()):
        if not is_covered(finding, index):
            continue
        covered.append(finding.subject_id)
        if key not in scan.reported:
            records.append(
                {
                    "repo": line_repo,
                    "weakness": finding.weakness,
                    "locus": finding.locus,
                    "verification": "fixed",
                }
            )
    records.sort(key=lambda r: (r["weakness"], r["locus"]))
    attention.sort(key=lambda r: (r["kind"], r["rule"], r["path"], r.get("locus", "")))
    queried = sorted(set().union(*(run.rules for run in scan.runs))) if scan.runs else []
    return {
        "repo": line_repo,
        "full": bool(scan.runs) and all(run.full for run in scan.runs),
        "queried": queried,
        "covered": sorted(covered),
        "tainted": sorted(index.tainted),
        "tainted_tools": sorted(index.tainted_tools),
        "count": len(records),
        "findings": records,
        "attention": attention,
        "routed": [{"rule": r, "path": p} for r, p in sorted(scan.routed)],
        "other_repo_runs": scan.other_repo_runs,
        "results": scan.results,
    }


def document_bytes(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@derive(
    OPERATION,
    serves="security.sarif.findings",
    input_contract="security.sarif.findings.request@1",
    output_contract="security.sarif.findings.result@1",
    refusals={
        PROVIDER_DECLINED: {
            "contract": f"{OPERATION}.refusal.{PROVIDER_DECLINED}@1",
            "absorbable": False,
        }
    },
)
def sarif_findings(
    logs: list[CaptureView],
    held: list[Any],
    repo: str | None = None,
    logical_source: str | None = None,
) -> ProviderResult:
    """Reads this run's SARIF 2.1.0 logs for one repository with the findings it holds:
    one document of findings by repository, weakness and locus, present or fixed, the held
    findings a full run covers, and attention records for regressions and location gaps."""

    if not isinstance(logs, list) or not logs or not isinstance(held, list):
        raise decline(
            PROVIDER_DECLINED, "sarif.findings needs this run's SARIF logs and held findings"
        )
    if len(logs) > MAX_LOGS:
        raise decline(PROVIDER_DECLINED, f"sarif.findings reads at most {MAX_LOGS} logs a run")
    try:
        document = findings([log.raw_bytes for log in logs], held, str(repo or ""))
    except (CaptureInputError, InputError) as error:
        raise decline(PROVIDER_DECLINED, str(error)) from None
    content = document_bytes(document)
    return ProviderResult.ok(
        {
            "document": derived_capture(
                content,
                # Pure: observed at the latest log's time, never the clock.
                derived_from=logs,
                source_identity=str(logical_source or "sarif.findings"),
                coordinate_type=COORDINATE_TYPE,
                coordinate={"operation": OPERATION, "logs": [log.bytes_digest for log in logs]},
                selector_type=SELECTOR_TYPE,
            )
        },
        metrics={
            "findings": float(len(document["findings"])),
            "attention": float(len(document["attention"])),
        },
    )
