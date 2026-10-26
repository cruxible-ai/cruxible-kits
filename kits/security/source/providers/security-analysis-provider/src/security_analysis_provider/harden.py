"""The hardening classifier: the six questions about every gated target, in three states.

``Harden`` (``security.harden``) reads the rows of the six hardening queries
(``security.publish_paths``, ``security.credentialed_jobs``,
``security.mutable_actions``, ``security.shared_dependencies``,
``security.served_vs_declared``, ``security.published_findings``), each scoped to
the targets with a ``security.target.publish_gate`` (stating a gate is what asks the questions), and
answers each question per target and per covered source:

- **found**: the facts answer it, and the answer is a problem (posted as a finding);
- **none**: a current ``security.coverage`` of the source answers it and nothing
  matches ("looked and found nothing"); it names the coverage (source, revision)
  and goes in the run summary only, never in the inbox and never as a Claim;
- **unknown**: no current coverage answers it (nobody pulled the source, or the
  pull went stale); it names the source and the pull that would answer it.

Absence is an answer only inside current coverage: a stale coverage reads as
absent (the queries see supported, current Claims only), so every answer resting
on it turns unknown. Each unknown source is one gap item ``{kind, source, pull,
input}`` however many questions or facts wait on it; the inbox dedupes repeats.

HQ1 every path that can publish to T, and does any bypass T's gate: a job with
``publishes_to`` T whose workflow has a trigger the gate does not list. A job's
publish edges are derived when its source is parsed, against the targets known
then; a target stated later would have none until the next pull. So a publishing
job is also any job of a covered source holding T's registry credential, read
from its held permissions and actions (``can_publish``), and the answer never
waits on the parse order. HQ2 jobs
holding a write credential (a ``:write`` permission, ``*:write``, the
repository-default token, or a secret besides ``GITHUB_TOKEN``) that
``pull_request_target``, ``workflow_run`` or ``issue_comment`` can trigger, or
``workflow_dispatch`` without an environment. HQ3 a third-party action not
pinned to a 40-hex commit inside such a credentialed job. HQ4 a mutable action
or a secret every publishing job of T shares. HQ5 what T serves against the path
that declares it: an artifact whose ``published_by`` workflow, at the commit it
was built from, has no job publishing T (or none in its ``publish_environment``),
or whose served ``sha256`` differs from its ``declared_sha256`` (posted with both
Claims, the declared and the running). HQ6 an open confirmed code finding in what T
serves: a ``security.finding`` whose verdict is ``confirmed`` (an undisputed verdict;
a contended one reads ``conflict`` and is not confirmed) and whose verification is not
``fixed``, that ``affects`` a release an artifact of T is a file of. HQ6 has two
states, found or "no confirmed finding recorded": with no scan coverage belief, it
never answers none.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import Bound, InputError, Row, parse_rows, sorted_items

QUERIES = ("hq1", "hq2", "hq3", "hq4", "hq5", "hq6")
WORKFLOWS_PATH = ".github/workflows/"
RISKY_EVENTS = ("pull_request_target", "workflow_run", "issue_comment")
_PINNED = re.compile(r"@[0-9a-f]{40}$")
MAX_POSTS = 200


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not all(isinstance(payload.get(name), list) for name in QUERIES):
        return None
    rows = sum(len(payload[name]) for name in QUERIES)
    return {"rows": "small" if rows <= 5000 else "large"}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _subject(ref: str) -> str:
    """``kind/id`` of a Subject reference: a qualified identity, a path or ``kind/id``."""

    text = ref.removeprefix("subjects/").removesuffix(".json")
    return text.rsplit(":", 1)[-1] if ":" in text.split("/", 1)[0] else text


def _refs(value: Any) -> set[str]:
    """The Subjects a projected Subject-valued field names, as ``kind/id``."""

    found: set[str] = set()
    for item in _list(value):
        if isinstance(item, str):
            found.add(_subject(item))
        elif isinstance(item, Mapping):
            for key in ("subject_path", "path", "artifact_path", "identity"):
                if isinstance(item.get(key), str):
                    found.add(_subject(str(item[key])))
            address = item.get("address")
            if isinstance(address, Mapping) and isinstance(address.get("artifact_path"), str):
                found.add(_subject(str(address["artifact_path"])))
    return found


def _names(bound: Bound) -> set[str]:
    return {f"{bound.kind}/{bound.subject_id}", _subject(bound.path)}


def _event(trigger: str) -> str:
    return trigger.split(":", 1)[0]


@dataclass
class Coverage:
    bound: Bound
    source: str
    revision: str

    def cites(self) -> dict[str, str]:
        return {"source": self.source, "revision": self.revision}


@dataclass
class Target:
    bound: Bound
    registry: str
    name: str
    gate: set[str] = field(default_factory=set)
    repo: tuple[str, str] | None = None
    coverages: dict[str, Coverage] = field(default_factory=dict)

    @property
    def locator(self) -> str:
        return f"{self.registry}/{self.name}"


@dataclass
class Params:
    default_ref: str = "main"
    repo_pull: str = "security.repo-acquire"
    registry_pull: str = "security.registry-acquire"
    release_pull: str = "security.fetch"
    versions: int = 3


class _Answers:
    def __init__(self, params: Params) -> None:
        self.params = params
        self.answers: list[dict[str, Any]] = []
        self.gaps: dict[str, dict[str, Any]] = {}
        self.findings: list[dict[str, Any]] = []

    def gap(self, source: str, pull: str, payload: dict[str, Any]) -> str:
        self.gaps.setdefault(source, {"kind": "gap", "source": source, "pull": pull,
                                      "input": payload})
        return source

    def repo_gap(self, host: str, name: str, ref: str) -> str:
        source = f"{host}/{name}@{ref}:{WORKFLOWS_PATH}"
        return self.gap(source, self.params.repo_pull, {
            "forge_host": host, "full_name": name, "ref": ref, "scope": "ci.workflows",
            "path": WORKFLOWS_PATH})

    def unknown(self, question: str, subject: str, source: str) -> None:
        gap = self.gaps[source]
        self.answers.append({"question": question, "subject": subject, "state": "unknown",
                             "source": source, "pull": gap["pull"]})

    def none(self, question: str, subject: str, coverage: Coverage) -> None:
        self.answers.append({"question": question, "subject": subject, "state": "none",
                             **coverage.cites()})

    def found(self, question: str, subject: str, coverage: Coverage | None,
              detail: dict[str, Any]) -> None:
        cites = coverage.cites() if coverage else {}
        self.answers.append({"question": question, "subject": subject, "state": "found",
                             **cites})
        self.findings.append({"kind": "finding", "question": question, "subject": subject,
                              **cites, **detail})


def _coverage(row: Row, binding: str, source: str, revision: str) -> Coverage | None:
    bound = row.subject(binding)
    src, rev = row.value(source), row.value(revision)
    if bound is None or not isinstance(src, str) or not isinstance(rev, str):
        return None
    return Coverage(bound=bound, source=src, revision=rev)


def _targets(rows: list[Row]) -> dict[str, Target]:
    """Every gated target the rows name, with its repository and current coverages."""

    targets: dict[str, Target] = {}
    for row in rows:
        bound = row.subject("target")
        registry, name = row.value("target_registry"), row.value("target_name")
        if bound is None or not isinstance(registry, str) or not isinstance(name, str):
            continue
        target = targets.setdefault(bound.path, Target(bound=bound, registry=registry,
                                                       name=name))
        target.gate.update(str(v) for v in _list(row.value("gate")))
        host, full = row.value("repo_host"), row.value("repo_name")
        if isinstance(host, str) and isinstance(full, str) and row.subject("repo"):
            target.repo = (host, full)
        coverage = _coverage(row, "coverage", "coverage_source", "coverage_revision")
        if coverage is not None:
            target.coverages.setdefault(coverage.bound.path, coverage)
    return targets


def _unanswerable(answers: _Answers, target: Target) -> str | None:
    """The gap source when nothing about T's repository is known, else None."""

    if target.repo is not None:
        return None
    if target.registry == "pypi":
        return answers.gap(target.locator, answers.params.registry_pull,
                           {"project": target.name, "versions": answers.params.versions})
    return answers.gap(target.locator, "statement",
                       {"state": "security.target.source_repo", "target": target.locator})


def _repo_answers(
    answers: _Answers, question: str, target: Target, subject: str | None = None
) -> list[Coverage]:
    """The current coverages of T's repository; records the unknowns it cannot answer."""

    subject = subject or target.locator
    source = _unanswerable(answers, target)
    if source is not None:
        answers.unknown(question, subject, source)
        return []
    host, name = target.repo  # type: ignore[misc]
    default = f"{host}/{name}@{answers.params.default_ref}:{WORKFLOWS_PATH}"
    if not any(c.source == default for c in target.coverages.values()):
        answers.unknown(question, subject, answers.repo_gap(host, name,
                                                            answers.params.default_ref))
    return sorted(target.coverages.values(), key=lambda c: c.source)


@dataclass
class JobRow:
    bound: Bound
    key: str
    workflow_path: str
    triggers: set[str]
    permissions: set[str]
    secrets: set[str]
    environment: str
    uses: set[str]
    coverage: str | None


def _jobs(rows: Iterable[Row], coverage_binding: str) -> dict[str, JobRow]:
    jobs: dict[str, JobRow] = {}
    for row in rows:
        bound = row.subject("job")
        key = row.value("job_key")
        if bound is None or not isinstance(key, str) or bound.path in jobs:
            continue
        cover = row.subject(coverage_binding)
        jobs[bound.path] = JobRow(
            bound=bound, key=key, workflow_path=str(row.value("workflow_path") or ""),
            triggers={str(v) for v in _list(row.value("triggers"))},
            permissions={str(v) for v in _list(row.value("permissions"))},
            secrets={str(v) for v in _list(row.value("secrets"))},
            environment=str(row.value("environment") or "none"),
            uses={str(v) for v in _list(row.value("uses"))},
            coverage=cover.path if cover else None,
        )
    return jobs


def can_publish(job: JobRow, registry: str) -> bool:
    """Whether the job holds the credential ``registry`` accepts (the parse's rule table,
    on held facts: a PyPI publish step is read from the actions the job uses)."""

    held = job.permissions
    write_all = "*:write" in held
    if registry == "pypi":
        return (write_all or "id-token:write" in held) and any(
            use.split("@", 1)[0] == "pkg:githubactions/pypa/gh-action-pypi-publish"
            for use in job.uses)
    scope = {"ghcr": "packages", "github_release": "contents", "github_pages": "pages"}.get(
        registry)
    return scope is not None and (write_all or f"{scope}:write" in held)


def _publishing(target: Target, coverage: Coverage, edges: dict[str, JobRow],
                credentialed: dict[str, dict[str, JobRow]]) -> list[JobRow]:
    """T's publishing jobs at one coverage: its publish edges, and every job there that
    holds T's registry credential."""

    found = {path: job for path, job in edges.items() if job.coverage == coverage.bound.path}
    for path, job in credentialed.get(coverage.bound.path, {}).items():
        if can_publish(job, target.registry):
            found.setdefault(path, job)
    return sorted(found.values(), key=lambda j: (j.workflow_path, j.key))


def _jobs_by_coverage(rows: list[Row]) -> dict[str, dict[str, JobRow]]:
    jobs: dict[str, dict[str, JobRow]] = {}
    for job_rows in _by_target(rows).values():
        for path, job in _jobs(job_rows, "coverage").items():
            if job.coverage is not None:
                jobs.setdefault(job.coverage, {})[path] = job
    return jobs


def _credentials(job: JobRow) -> list[str]:
    held = sorted(p for p in job.permissions
                  if p.endswith(":write") or p == "token:repository-default")
    return held + sorted(f"secret:{s}" for s in job.secrets if s != "GITHUB_TOKEN")


def _mutable(job: JobRow) -> list[str]:
    return sorted(u for u in job.uses if not _PINNED.search(u))


def _by_target(rows: list[Row]) -> dict[str, list[Row]]:
    grouped: dict[str, list[Row]] = {}
    for row in rows:
        target = row.subject("target")
        if target is not None:
            grouped.setdefault(target.path, []).append(row)
    return grouped


def hq1(answers: _Answers, targets: dict[str, Target], rows: list[Row],
        credentialed: dict[str, dict[str, JobRow]]) -> None:
    grouped = _by_target(rows)
    for path, target in sorted(targets.items()):
        jobs = _jobs(grouped.get(path, ()), "job_coverage")
        for coverage in _repo_answers(answers, "HQ1", target):
            publishing = _publishing(target, coverage, jobs, credentialed)
            subject = f"{target.locator} @ {coverage.source}"
            bypasses = []
            for job in publishing:
                outside = sorted(job.triggers - target.gate)
                if outside:
                    bypasses.append({"job": f"{job.workflow_path}#{job.key}",
                                     "triggers": outside})
            if bypasses:
                answers.found("HQ1", subject, coverage, {
                    "target": target.locator, "gate": sorted(target.gate),
                    "paths": len(publishing), "bypass": bypasses})
            else:
                answers.none("HQ1", subject, coverage)


def _per_source(
    answers: _Answers, question: str, targets: dict[str, Target], rows: list[Row],
    judge: Any,
) -> None:
    """HQ2 and HQ3: per covered source of every gated target's repository."""

    jobs_by_coverage = _jobs_by_coverage(rows)
    seen: set[str] = set()
    for _path, target in sorted(targets.items()):
        for coverage in _repo_answers(answers, question, target,
                                      subject=f"repository of {target.locator}"):
            if coverage.bound.path in seen:
                continue
            seen.add(coverage.bound.path)
            jobs = sorted(jobs_by_coverage.get(coverage.bound.path, {}).values(),
                          key=lambda j: (j.workflow_path, j.key))
            hits = [hit for job in jobs if (hit := judge(job))]
            if hits:
                answers.found(question, coverage.source, coverage, {"jobs": hits})
            else:
                answers.none(question, coverage.source, coverage)


def _hq2_judge(job: JobRow) -> dict[str, Any] | None:
    credentials = _credentials(job)
    risky = sorted(t for t in job.triggers if _event(t) in RISKY_EVENTS)
    if job.environment == "none":
        risky += sorted(t for t in job.triggers if _event(t) == "workflow_dispatch")
    if credentials and risky:
        return {"job": f"{job.workflow_path}#{job.key}", "credentials": credentials,
                "triggers": risky, "environment": job.environment}
    return None


def _hq3_judge(job: JobRow) -> dict[str, Any] | None:
    credentials = _credentials(job)
    mutable = _mutable(job)
    if credentials and mutable:
        return {"job": f"{job.workflow_path}#{job.key}", "credentials": credentials,
                "mutable": mutable}
    return None


def hq4(answers: _Answers, targets: dict[str, Target], rows: list[Row],
        credentialed: dict[str, dict[str, JobRow]]) -> None:
    grouped = _by_target(rows)
    for path, target in sorted(targets.items()):
        jobs = _jobs(grouped.get(path, ()), "job_coverage")
        for coverage in _repo_answers(answers, "HQ4", target):
            publishing = _publishing(target, coverage, jobs, credentialed)
            subject = f"{target.locator} @ {coverage.source}"
            if not publishing:
                answers.none("HQ4", subject, coverage)
                continue
            shared_uses = set.intersection(*(set(_mutable(j)) for j in publishing))
            shared_secrets = set.intersection(*({s for s in j.secrets if s != "GITHUB_TOKEN"}
                                                for j in publishing))
            if shared_uses or shared_secrets:
                answers.found("HQ4", subject, coverage, {
                    "target": target.locator, "paths": len(publishing),
                    "shared": sorted(shared_uses) + sorted(f"secret:{s}"
                                                           for s in shared_secrets)})
            else:
                answers.none("HQ4", subject, coverage)


def _split_source(source: str) -> tuple[str, str, str] | None:
    """(forge_host, full_name, ref) of ``host/owner/repo@ref``."""

    repo, _, ref = source.partition("@")
    host, _, name = repo.partition("/")
    return (host, name, ref) if host and name and ref else None


def hq5(answers: _Answers, targets: dict[str, Target], rows: list[Row]) -> None:
    grouped = _by_target(rows)
    for path, target in sorted(targets.items()):
        artifacts: dict[str, list[Row]] = {}
        registry_coverage: Coverage | None = None
        for row in grouped.get(path, ()):
            registry_coverage = registry_coverage or _coverage(
                row, "registry_coverage", "registry_coverage_source",
                "registry_coverage_revision")
            artifact = row.subject("artifact")
            if artifact is not None:
                artifacts.setdefault(artifact.path, []).append(row)
        if target.registry == "pypi" and registry_coverage is None:
            source = answers.gap(target.locator, answers.params.registry_pull,
                                 {"project": target.name, "versions": answers.params.versions})
            answers.unknown("HQ5", target.locator, source)
            continue
        if not artifacts:
            if registry_coverage is not None:
                answers.none("HQ5", target.locator, registry_coverage)
            continue
        for artifact_path in sorted(artifacts):
            _hq5_artifact(answers, target, registry_coverage, artifacts[artifact_path])


def _hq5_artifact(answers: _Answers, target: Target, registry_coverage: Coverage | None,
                  rows: list[Row]) -> None:
    first = rows[0]
    artifact = first.subject("artifact")
    assert artifact is not None
    name = str(first.value("artifact_name") or artifact.subject_id)
    subject = f"{target.locator}:{name}"
    declared, served = first.value("declared_sha256"), first.value("sha256")
    if isinstance(declared, str) and isinstance(served, str) and declared != served:
        answers.found("HQ5", subject, registry_coverage, {
            "target": target.locator, "artifact": name, "disagreement": "digest",
            "declared": {"value": declared,
                         "claim": first.claim_id(artifact, "security.artifact.declared_sha256")},
            "served": {"value": served,
                       "claim": first.claim_id(artifact, "security.artifact.sha256")}})
        return
    if isinstance(declared, str) and served is None:
        tag = name.split("/", 1)[0]
        source = answers.gap(f"{target.locator}@{tag}", answers.params.release_pull, {
            "logical_source": "github.release", "max_bytes": 4194304,
            "url": f"https://api.github.com/repos/{target.name}/releases/tags/{tag}"})
        answers.unknown("HQ5", subject, source)
        return
    workflow_source, workflow_path = first.value("workflow_source"), first.value("workflow_path")
    if not isinstance(workflow_source, str) or not isinstance(workflow_path, str):
        if target.registry == "pypi":
            answers.found("HQ5", subject, registry_coverage, {
                "target": target.locator, "artifact": name, "disagreement": "no_provenance"})
        elif registry_coverage is not None or declared is not None:
            answers.answers.append({"question": "HQ5", "subject": subject, "state": "none",
                                    "source": target.locator, "revision": str(declared)})
        return
    wcoverage = _coverage(first, "workflow_coverage", "workflow_coverage_source",
                          "workflow_coverage_revision")
    if wcoverage is None:
        split = _split_source(workflow_source)
        if split is None:
            return
        answers.unknown("HQ5", subject, answers.repo_gap(*split))
        return
    environment = str(first.value("publish_environment") or "none")
    publishing = []
    for row in rows:
        job = row.subject("job")
        if job is None or not (_refs(row.value("job_publishes")) & _names(target.bound)):
            continue
        publishing.append((str(row.value("job_key")), str(row.value("job_environment")
                                                            or "none")))
    matching = [key for key, env in publishing if env == environment]
    cites = registry_coverage or wcoverage
    if not publishing:
        answers.found("HQ5", subject, cites, {
            "target": target.locator, "artifact": name, "disagreement": "no_declared_path",
            "published_by": f"{workflow_source}:{workflow_path}",
            "declared_at": wcoverage.cites()})
    elif not matching:
        answers.found("HQ5", subject, cites, {
            "target": target.locator, "artifact": name, "disagreement": "environment",
            "published_by": f"{workflow_source}:{workflow_path}",
            "publish_environment": environment,
            "declared_environments": sorted({env for _k, env in publishing}),
            "declared_at": wcoverage.cites()})
    else:
        answers.answers.append({"question": "HQ5", "subject": subject, "state": "none",
                                **wcoverage.cites(), "jobs": sorted(matching)})


def hq6(answers: _Answers, rows: list[Row]) -> None:
    """One finding per (gated target, open confirmed finding), naming every release and
    artifact of T it affects. Nothing is answered for a target without one."""

    found: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        target, finding = row.subject("target"), row.subject("finding")
        if target is None or finding is None:
            continue
        if row.value("verdict") != "confirmed" or row.value("verification") == "fixed":
            continue
        locator = f"{row.value('target_registry')}/{row.value('target_name')}"
        subject = f"{locator}: {finding.kind}/{finding.subject_id}"
        item = found.setdefault((target.path, finding.path), {
            "subject": subject, "target": locator,
            "finding": f"{finding.kind}/{finding.subject_id}",
            "weakness": row.value("weakness"), "locus": row.value("locus"),
            "severity": row.value("severity"), "releases": set(), "artifacts": set()})
        release, artifact = row.subject("release"), row.subject("artifact")
        if release is not None:
            item["releases"].add(f"{release.kind}/{release.subject_id}")
        if artifact is not None:
            item["artifacts"].add(str(row.value("artifact_name") or artifact.subject_id))
    for _key, item in sorted(found.items()):
        subject = item.pop("subject")
        answers.found("HQ6", subject, None, {
            **item, "releases": sorted(item["releases"]),
            "artifacts": sorted(item["artifacts"])})


def _params(value: object) -> Params:
    if not isinstance(value, Mapping):
        return Params()
    defaults = Params()
    return Params(
        default_ref=str(value.get("default_ref") or defaults.default_ref),
        repo_pull=str(value.get("repo_pull") or defaults.repo_pull),
        registry_pull=str(value.get("registry_pull") or defaults.registry_pull),
        release_pull=str(value.get("release_pull") or defaults.release_pull),
        versions=int(value.get("versions") or defaults.versions),
    )


def harden(payload: Mapping[str, Any]) -> dict[str, Any]:
    truncated = payload.get("truncated")
    if isinstance(truncated, Mapping) and any(truncated.get(name) for name in QUERIES):
        # A cut-off row set would turn a missing row into a "none": refuse instead.
        raise InputError(f"truncated hardening queries: "
                         f"{sorted(name for name in QUERIES if truncated.get(name))}")
    rows = {name: parse_rows(payload.get(name)) for name in QUERIES}
    answers = _Answers(_params(payload.get("params")))
    targets = _targets([*rows["hq1"], *rows["hq2"], *rows["hq4"], *rows["hq5"]])
    # HQ3's rows hold every covered job's permissions and actions: the credential view.
    credentialed = _jobs_by_coverage(rows["hq3"])
    hq1(answers, targets, rows["hq1"], credentialed)
    _per_source(answers, "HQ2", targets, rows["hq2"], _hq2_judge)
    _per_source(answers, "HQ3", targets, rows["hq3"], _hq3_judge)
    hq4(answers, targets, rows["hq4"], credentialed)
    hq5(answers, targets, rows["hq5"])
    hq6(answers, rows["hq6"])
    items = sorted_items(answers.findings) + sorted_items(answers.gaps.values())
    counts = {state: sum(1 for a in answers.answers if a["state"] == state)
              for state in ("found", "none", "unknown")}
    return {
        "items": items[:MAX_POSTS],
        "posted": min(len(items), MAX_POSTS),
        "answers": sorted(answers.answers, key=lambda a: (a["question"], a["subject"],
                                                          a["state"])),
        "targets": len(targets),
        "gaps": len(answers.gaps),
        **counts,
    }


class Harden:
    """The ``security.harden`` implementation: findings and gaps, never Claims."""

    interface_id = "security.harden"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            result = harden(context.input)
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        return ProviderResult.ok(result, metrics={"posted": float(result["posted"])})
