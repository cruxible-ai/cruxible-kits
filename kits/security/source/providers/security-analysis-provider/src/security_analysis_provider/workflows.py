"""What one repository snapshot declares: workflows, jobs, and a release manifest's digests.

``WorkflowFacts`` (``security.workflow-facts``) reads a ``security.fetched-v1``
Capture body (canonical JSON of the source locator, the revision R and every file
read at R) beside what is held for that source: its coverage (rows of
``security.coverage_index``), its workflow and job facts (``security.source_facts``),
the repository and the targets that name it as their source
(``security.repo_targets``) and, for a manifest, the declared release artifacts
(``security.release_artifacts``). It returns proposal items for exactly what
changed, plus the coverage restated every time.

Coverage is the fully-read-source belief: ``security.coverage.of`` (the
repository, stated once) and ``security.coverage.revision`` (R), restated on
every snapshot. Restating it on an unchanged snapshot is a recorded
re-observation, so its freshness moves without a revision; a new R revises the
one revision Claim. Every other fact is stated once and changed only when the
snapshot changes it: a value the snapshot no longer has is retired
(``superseded``), a new one added.

``ci.workflows`` facts, per workflow file (YAML 1.1: an unquoted ``on`` key reads
as ``True``; both spellings are read):

- ``security.workflow.trigger``: ``event``, or ``event:filter:pattern`` for each
  branch or tag pattern (``push:tags:v*``), ``schedule:cron:EXPR`` per schedule;
- per job: ``security.job.permission`` (the effective ``scope:level`` set: the
  job's own block, else the workflow's, else ``token:repository-default`` when
  neither declares one; ``read-all``/``write-all`` read as ``*:read``/``*:write``;
  an empty block is ``*:none``), ``security.job.secret`` (each ``secrets.NAME``
  the job references, ``GITHUB_TOKEN`` for ``github.token``, ``*inherit`` for
  ``secrets: inherit``), ``security.job.environment`` (its name, or ``none``),
  ``security.job.uses`` (``pkg:githubactions/owner/repo[/path]@ref`` per action
  or reusable workflow), ``security.job.needs`` and ``security.job.publishes_to``.

``publishes_to`` follows the credential a registry accepts (``PUBLISH_RULES``): a
job publishes to every target of that registry whose ``source_repo`` is this
repository when it holds the credential: PyPI needs ``id-token: write`` and a
publish step (``pypa/gh-action-pypi-publish``, ``twine upload``, ``uv publish``),
GHCR ``packages: write``, a GitHub release ``contents: write``, GitHub Pages
``pages: write``. What a job *can* publish is the question, so the rule leans to
over-approximating.

``release.manifest`` facts: each ``(asset, sha256)`` the manifest declares, as
``security.artifact.declared_sha256`` of the artifact ``<ref>/<asset>`` of the
repository's ``github_release`` target. A JSON manifest is read wherever an
object pairs an asset name (``asset``, ``name``, ``filename``) with a digest
(``sha256``, ``tarball_sha256``, ``digest``); a text manifest as
``SHA256SUMS`` lines.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml
from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    Bound,
    InputError,
    Row,
    claim_item,
    key_ref,
    parse_rows,
    retirement_item,
    sorted_items,
    subject_item,
)

REPO = "security.repo"
WORKFLOW = "security.workflow"
JOB = "security.job"
COVERAGE = "security.coverage"
TARGET = "security.target"
ARTIFACT = "security.artifact"
SCOPES = ("ci.workflows", "release.manifest")
MAX_JOBS = 500
_SECRET = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
_GITHUB_TOKEN = re.compile(r"github\.token\b")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HEX = re.compile(r"^(sha256:)?([0-9a-fA-F]{64})$")
_EVENT_FILTERS = ("branches", "branches-ignore", "tags", "tags-ignore")
_PYPI_PUBLISH = ("pypa/gh-action-pypi-publish",)
_PYPI_COMMANDS = ("twine upload", "uv publish", "poetry publish", "flit publish")


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    snapshot = payload.get("snapshot")
    if not isinstance(snapshot, Mapping) or snapshot.get("scope") not in SCOPES:
        return None
    return {"scope": str(snapshot["scope"])}


# --- reading a workflow ---------------------------------------------------------


@dataclass
class Job:
    key: str
    permissions: set[str] = field(default_factory=set)
    secrets: set[str] = field(default_factory=set)
    environment: str = "none"
    uses: set[str] = field(default_factory=set)
    needs: set[str] = field(default_factory=set)
    registries: set[str] = field(default_factory=set)


@dataclass
class Workflow:
    path: str
    triggers: set[str] = field(default_factory=set)
    jobs: dict[str, Job] = field(default_factory=dict)
    error: str | None = None


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    return []


def triggers(on: object) -> set[str]:
    """The workflow's trigger literals, from its ``on`` value in any of its three forms."""

    found: set[str] = set()
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(event) for event in on if isinstance(event, str)}
    if not isinstance(on, Mapping):
        return found
    for event, config in on.items():
        event = str(event)
        if event == "schedule":
            crons = [str(item.get("cron")) for item in config or ()
                     if isinstance(item, Mapping) and item.get("cron")]
            found.update(f"schedule:cron:{cron}" for cron in crons)
            if not crons:
                found.add(event)
            continue
        filtered = False
        if isinstance(config, Mapping):
            for name in _EVENT_FILTERS:
                for pattern in _strings(config.get(name)):
                    found.add(f"{event}:{name}:{pattern}")
                    filtered = True
        if not filtered:
            found.add(event)
    return found


def permissions(value: object) -> set[str] | None:
    """A permissions block as ``scope:level`` literals; None when the block is absent."""

    if value is None:
        return None
    if isinstance(value, str):
        level = {"read-all": "read", "write-all": "write"}.get(value.strip())
        return {f"*:{level}"} if level else {f"*:{value.strip()}"}
    if isinstance(value, Mapping):
        held = {f"{scope}:{level}" for scope, level in value.items()
                if isinstance(level, str) and level != "none"}
        return held or {"*:none"}
    return {"*:unreadable"}


def _uses_purl(value: str) -> str | None:
    text = value.strip()
    if text.startswith(("./", "docker://")) or "@" not in text:
        return None
    name, _, ref = text.rpartition("@")
    parts = name.split("/")
    if len(parts) < 2 or not ref:
        return None
    owner, repo, *rest = parts
    return "pkg:githubactions/" + "/".join([owner.lower(), repo.lower(), *rest]) + "@" + ref


def _environment(value: object) -> str:
    if isinstance(value, Mapping):
        value = value.get("name")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "none"


def _registries(job: Job, steps: list[Mapping[str, Any]], body: str) -> set[str]:
    """The registries whose publish credential this job holds (``PUBLISH_RULES``)."""

    held = job.permissions
    write_all = "*:write" in held
    found: set[str] = set()
    publish_step = any(
        str(step.get("uses", "")).split("@", 1)[0].lower() in _PYPI_PUBLISH
        and "test.pypi.org" not in json.dumps(step.get("with") or {})
        for step in steps
    ) or any(command in body for command in _PYPI_COMMANDS)
    if (write_all or "id-token:write" in held) and publish_step:
        found.add("pypi")
    if write_all or "packages:write" in held:
        found.add("ghcr")
    if write_all or "contents:write" in held:
        found.add("github_release")
    if write_all or "pages:write" in held:
        found.add("github_pages")
    return found


#: registry -> the credential a job must hold to publish there (see module docstring).
PUBLISH_RULES = {
    "pypi": "id-token: write and a PyPI publish step",
    "ghcr": "packages: write",
    "github_release": "contents: write",
    "github_pages": "pages: write",
}


def parse_workflow(path: str, text: str) -> Workflow:
    workflow = Workflow(path=path)
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        workflow.error = f"not YAML: {str(error).splitlines()[0]}"
        return workflow
    if not isinstance(document, Mapping):
        workflow.error = "not a workflow mapping"
        return workflow
    # YAML 1.1 reads an unquoted `on:` key as the boolean True.
    workflow.triggers = triggers(document.get("on", document.get(True)))
    default = permissions(document.get("permissions"))
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping):
        return workflow
    if len(jobs) > MAX_JOBS:
        workflow.error = f"more than {MAX_JOBS} jobs"
        return workflow
    for key, spec in jobs.items():
        if not isinstance(spec, Mapping):
            continue
        job = Job(key=str(key))
        own = permissions(spec.get("permissions"))
        job.permissions = own if own is not None else default or {"token:repository-default"}
        body = json.dumps(spec, default=str, sort_keys=True)
        job.secrets = set(_SECRET.findall(body))
        if _GITHUB_TOKEN.search(body):
            job.secrets.add("GITHUB_TOKEN")
        if spec.get("secrets") == "inherit":
            job.secrets.add("*inherit")
        job.environment = _environment(spec.get("environment"))
        steps = [step for step in spec.get("steps") or () if isinstance(step, Mapping)]
        for value in [spec.get("uses"), *(step.get("uses") for step in steps)]:
            if isinstance(value, str) and (purl := _uses_purl(value)):
                job.uses.add(purl)
        job.needs = set(_strings(spec.get("needs")))
        job.registries = _registries(job, steps, body)
        workflow.jobs[job.key] = job
    return workflow


# --- reading a manifest ---------------------------------------------------------


def _digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = _HEX.fullmatch(value.strip())
    return "sha256:" + match.group(2).lower() if match else None


def manifest_digests(text: str) -> dict[str, str]:
    """``asset -> sha256:hex`` from a JSON manifest or ``SHA256SUMS`` text."""

    found: dict[str, str] = {}
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    if document is None:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and (digest := _digest(parts[0])):
                found[parts[1].lstrip("*")] = digest
        return found

    def walk(value: object) -> None:
        if isinstance(value, Mapping):
            name = next((value[k] for k in ("asset", "name", "filename")
                         if isinstance(value.get(k), str)), None)
            digest = next((d for k in ("sha256", "tarball_sha256", "digest")
                           if (d := _digest(value.get(k)))), None)
            if name and digest:
                found[str(name)] = digest
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    return found


# --- what is held ---------------------------------------------------------------


@dataclass
class HeldJob:
    bound: Bound
    key: str
    one: dict[str, tuple[Any, str | None]] = field(default_factory=dict)
    many: dict[str, dict[Any, str]] = field(default_factory=dict)


@dataclass
class HeldWorkflow:
    bound: Bound
    path: str
    one: dict[str, str | None] = field(default_factory=dict)
    triggers: dict[str, str] = field(default_factory=dict)
    jobs: dict[str, HeldJob] = field(default_factory=dict)


#: include name -> (predicate, Subject-valued)
JOB_MANY = {
    "permission": ("security.job.permission", False),
    "secret": ("security.job.secret", False),
    "uses": ("security.job.uses", False),
    "needs": ("security.job.needs", True),
    "publishes_to": ("security.job.publishes_to", True),
}


def held_workflows(rows: list[Row]) -> dict[str, HeldWorkflow]:
    held: dict[str, HeldWorkflow] = {}
    for row in rows:
        bound = row.subject("workflow")
        path = row.value("path")
        if bound is None or not isinstance(path, str):
            continue
        workflow = held.setdefault(path, HeldWorkflow(bound=bound, path=path))
        for name in ("repo", "coverage"):
            workflow.one.setdefault(name, row.claim_id(bound, f"security.workflow.{name}"))
        for item in row.included("trigger"):
            workflow.triggers[str(item.value)] = item.claim_id
        job_bound = row.subject("job")
        job_key = row.value("job_key")
        if job_bound is None or not isinstance(job_key, str) or job_key in workflow.jobs:
            continue
        job = HeldJob(bound=job_bound, key=job_key)
        job.one["workflow"] = (None, row.claim_id(job_bound, "security.job.workflow"))
        job.one["environment"] = (
            row.value("environment"), row.claim_id(job_bound, "security.job.environment"))
        for name, (_predicate, subject_valued) in JOB_MANY.items():
            job.many[name] = {
                (item.object_path if subject_valued else item.value): item.claim_id
                for item in row.included(name)
            }
        workflow.jobs[job_key] = job
    return held


# --- the provider ---------------------------------------------------------------


def _snapshot(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InputError("snapshot must be the repo-snapshot Capture body")
    for name in ("forge_host", "full_name", "ref", "scope", "path", "locator", "revision"):
        if not isinstance(value.get(name), str) or not value.get(name):
            raise InputError(f"the snapshot has no {name}")
    if value["scope"] not in SCOPES:
        raise InputError("the snapshot names an unknown scope")
    if not _SHA.fullmatch(str(value["revision"])):
        raise InputError("the snapshot revision is not a commit SHA")
    if not isinstance(value.get("files"), list):
        raise InputError("the snapshot has no files list")
    return dict(value)


def _text(item: Mapping[str, Any]) -> str:
    try:
        return base64.b64decode(str(item.get("content_base64") or ""), validate=True).decode()
    except (ValueError, UnicodeDecodeError) as error:
        raise InputError(f"{item.get('path')} is not UTF-8 text") from error


class _Items:
    """Collects items and counts: subjects first, then Claims in a stable order."""

    def __init__(self) -> None:
        self.subjects: list[dict[str, Any]] = []
        self.claims: list[dict[str, Any]] = []
        self.counts = {"added": 0, "revised": 0, "retired": 0, "restated": 0}
        self._keys: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

    def subject(self, kind: str, key: Mapping[str, str], why: str) -> None:
        """Create a Subject by key, once per terminal however many facts name it."""

        if (kind, tuple(sorted(key.items()))) not in self._keys:
            self._keys.add((kind, tuple(sorted(key.items()))))
            self.subjects.append(subject_item(kind, key, why))

    def add(self, subject: Any, predicate: str, value: Any, why: str,
            revises: str | None = None, *, role: str = "observation") -> None:
        """A relationship the source states (``sourced`` ClaimTypes) is ``normative``."""

        self.claims.append(claim_item(subject, predicate, value, why, revises=revises,
                                      role=role))
        self.counts["revised" if revises else "added"] += 1

    def restate(self, subject: Any, predicate: str, value: Any, why: str) -> None:
        self.claims.append(claim_item(subject, predicate, value, why))
        self.counts["restated"] += 1

    def retire(self, claim_id: str | None, why: str) -> None:
        if claim_id:
            self.claims.append(retirement_item(claim_id, why))
            self.counts["retired"] += 1

    def sync_many(self, subject: Any, predicate: str, want: Iterable[Any],
                  held: Mapping[Any, str], why: str, *, value_of: Any = None) -> None:
        """Add each wanted value not held; retire each held value not wanted.

        ``want`` holds comparison keys; ``value_of`` maps a key to the item's object
        (a Subject reference) when they differ.
        """

        wanted = set(want)
        for key in sorted(wanted - set(held), key=str):
            self.add(subject, predicate, value_of(key) if value_of else key, why)
        for key in sorted(set(held) - wanted, key=str):
            self.retire(held[key], f"{why} No longer stated: {key}.")

    def output(self) -> list[dict[str, Any]]:
        return self.subjects + sorted_items(self.claims)


class WorkflowFacts:
    """The ``security.workflow-facts`` implementation."""

    interface_id = "security.workflow-facts"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            snapshot = _snapshot(context.input.get("snapshot"))
            coverage = parse_rows(context.input.get("coverage"))
            held = parse_rows(context.input.get("held"))
            targets = parse_rows(context.input.get("targets"))
            releases = parse_rows(context.input.get("releases") or [])
            output, metrics = _facts(snapshot, coverage, held, targets, releases)
            return ProviderResult.ok(output, metrics=metrics)
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))


def _facts(
    snapshot: dict[str, Any], coverage: list[Row], held: list[Row], targets: list[Row],
    releases: list[Row],
) -> tuple[dict[str, Any], dict[str, float]]:
    host, name = snapshot["forge_host"], snapshot["full_name"]
    scope, locator, revision = snapshot["scope"], snapshot["locator"], snapshot["revision"]
    repo_locator = f"{host}/{name}"
    at = f"{locator} at {revision[:12]}"
    items = _Items()
    repo_bound = next((b for row in targets if (b := row.subject("repo"))), None)
    repo: Any = repo_bound or key_ref(REPO, forge_host=host, full_name=name)
    if repo_bound is None:
        items.subject(REPO, {"forge_host": host, "full_name": name},
                      f"{at}: the snapshot reads the repository {repo_locator}.")
    held_coverage = next((row for row in coverage if row.subject("coverage")), None)
    coverage_bound = held_coverage.subject("coverage") if held_coverage else None
    cover: Any = coverage_bound or key_ref(COVERAGE, source=locator, scope=scope)
    if coverage_bound is None:
        items.subject(COVERAGE, {"source": locator, "scope": scope},
                      f"{at}: every file of {scope} at the source was read.")
    # The revision is restated on every snapshot: an unchanged one re-observes it.
    held_revision = held_coverage.value("revision") if held_coverage else None
    revision_id = (held_coverage.claim_id(coverage_bound, "security.coverage.revision")
                   if held_coverage and coverage_bound else None)
    why = f"{at}: read every file of {scope} ({len(snapshot['files'])} files)."
    if held_revision is not None and held_revision != revision and revision_id:
        items.add(cover, "security.coverage.revision", revision, why, revises=revision_id)
    else:
        items.restate(cover, "security.coverage.revision", revision, why)
    if held_coverage is None or held_coverage.value("of") is None:
        items.add(cover, "security.coverage.of", repo, why)
    summary: dict[str, Any] = {"locator": locator, "revision": revision, "scope": scope,
                               "workflows": 0, "jobs": 0, "unparsed": []}
    if scope == "ci.workflows":
        _workflow_facts(items, snapshot, repo, cover, held, targets, summary, at)
    else:
        _manifest_facts(items, snapshot, repo, targets, releases, summary, at)
    out = items.output()
    changed = items.counts["added"] + items.counts["revised"] + items.counts["retired"]
    return ({"items": out, "changed": changed, **items.counts, **summary},
            {"items": float(len(out)), "changed": float(changed)})


def _workflow_facts(
    items: _Items, snapshot: dict[str, Any], repo: Any, cover: Any, held_rows: list[Row],
    target_rows: list[Row], summary: dict[str, Any], at: str,
) -> None:
    source = f"{snapshot['forge_host']}/{snapshot['full_name']}@{snapshot['ref']}"
    held = held_workflows(held_rows)
    #: registry -> {target path}
    targets: dict[str, set[str]] = {}
    for row in target_rows:
        target = row.subject("target")
        registry = row.value("registry")
        if target is not None and isinstance(registry, str):
            targets.setdefault(registry, set()).add(target.path)
    seen: set[str] = set()
    for file in sorted(snapshot["files"], key=lambda f: str(f.get("path"))):
        path = str(file.get("path"))
        seen.add(path)
        workflow = parse_workflow(path, _text(file))
        if workflow.error:
            summary["unparsed"].append({"path": path, "error": workflow.error})
        summary["workflows"] += 1
        summary["jobs"] += len(workflow.jobs)
        mine = held.get(path)
        ref: Any = mine.bound if mine else key_ref(WORKFLOW, source=source, path=path)
        said = f"{at}: {path}"
        if mine is None:
            items.subject(WORKFLOW, {"source": source, "path": path}, f"{said} is a workflow.")
        for one, value in (("repo", repo), ("coverage", cover)):
            if mine is None or not mine.one.get(one):
                items.add(ref, f"security.workflow.{one}", value, f"{said} is read from it.")
        items.sync_many(ref, "security.workflow.trigger", workflow.triggers,
                        mine.triggers if mine else {}, f"{said} declares this trigger.")
        held_jobs = mine.jobs if mine else {}
        job_paths = {key: job.bound.path for key, job in held_jobs.items()}
        workflow_ref = f"{source}:{path}"

        def job_ref(key: str, *, _held: dict[str, HeldJob] = held_jobs,
                    _workflow: str = workflow_ref) -> Any:
            if key in _held:
                return _held[key].bound
            return key_ref(JOB, workflow_ref=_workflow, job_key=key)

        for key in sorted(workflow.jobs):
            job = workflow.jobs[key]
            have = held_jobs.get(key)
            subject = job_ref(key)
            said_job = f"{at}: {path} job {key}"
            if have is None:
                items.subject(JOB, {"workflow_ref": workflow_ref, "job_key": key},
                              f"{said_job} is declared.")
            if have is None or not have.one["workflow"][1]:
                items.add(subject, "security.job.workflow", ref, f"{said_job} is in {path}.")
            env_value, env_id = have.one["environment"] if have else (None, None)
            if env_value != job.environment:
                items.add(subject, "security.job.environment", job.environment,
                          f"{said_job} runs in environment {job.environment}.",
                          revises=env_id if env_value is not None else None)
            many = have.many if have else {}
            for name, values in (("permission", job.permissions), ("secret", job.secrets),
                                 ("uses", job.uses)):
                items.sync_many(subject, JOB_MANY[name][0], values, many.get(name, {}),
                                f"{said_job} holds {name} values as declared.")
            # needs: compared by the needed job's path when held, else by its key.
            needed = {job_paths.get(need, need): need for need in job.needs}
            items.sync_many(subject, "security.job.needs", needed, many.get("needs", {}),
                            f"{said_job} needs these jobs.",
                            value_of=lambda k, n=needed: job_ref(n[k]))
            wanted_targets = {path for registry in job.registries
                              for path in targets.get(registry, ())}
            items.sync_many(subject, "security.job.publishes_to", wanted_targets,
                            many.get("publishes_to", {}),
                            f"{said_job} holds the publish credential of this target "
                            f"({', '.join(sorted(job.registries)) or 'none'}).",
                            value_of=lambda p: _address_ref(p))
        for key in sorted(set(held_jobs) - set(workflow.jobs)):
            _retire_job(items, held_jobs[key], f"{at}: {path} no longer declares job {key}.")
    for path in sorted(set(held) - seen):
        gone = held[path]
        why = f"{at}: {path} is no longer in the source."
        for claim in (gone.one.get("repo"), gone.one.get("coverage"), *gone.triggers.values()):
            items.retire(claim, why)
        for job in gone.jobs.values():
            _retire_job(items, job, why)


def _address_ref(path: str) -> Bound:
    kind, _, rest = path.removeprefix("subjects/").partition("/")
    return Bound(kind=kind, subject_id=rest.removesuffix(".json"), path=path, identity="")


def _retire_job(items: _Items, job: HeldJob, why: str) -> None:
    for _value, claim in job.one.values():
        items.retire(claim, why)
    for values in job.many.values():
        for claim in values.values():
            items.retire(claim, why)


def _manifest_facts(
    items: _Items, snapshot: dict[str, Any], repo: Any, target_rows: list[Row],
    release_rows: list[Row], summary: dict[str, Any], at: str,
) -> None:
    files = snapshot["files"]
    if len(files) != 1:
        summary["unparsed"].append({"path": snapshot["path"], "error": "no manifest file"})
        return
    digests = manifest_digests(_text(files[0]))
    name, ref = snapshot["full_name"], snapshot["ref"]
    target_bound = next((row.subject("target") for row in target_rows
                         if row.value("registry") == "github_release"
                         and row.value("name") == name and row.subject("target")), None)
    target: Any = target_bound or key_ref(TARGET, registry="github_release", name=name)
    if target_bound is None:
        items.subject(TARGET, {"registry": "github_release", "name": name},
                      f"{at}: the manifest declares assets of this repository's releases.")
        items.add(target, "security.target.source_repo", repo,
                  f"{at}: a GitHub release target belongs to its repository.", role="normative")
    target_ref = f"github_release/{name}"
    held: dict[str, tuple[Bound, Any, str | None, bool]] = {}
    for row in release_rows:
        artifact = row.subject("artifact")
        artifact_name = row.value("artifact_name")
        if artifact is None or not isinstance(artifact_name, str):
            continue
        held[artifact_name] = (
            artifact, row.value("declared_sha256"),
            row.claim_id(artifact, "security.artifact.declared_sha256"),
            row.claim_id(artifact, "security.artifact.target") is not None)
    wanted = {f"{ref}/{asset}": digest for asset, digest in digests.items()}
    summary["workflows"] = len(wanted)
    for artifact_name in sorted(wanted):
        digest = wanted[artifact_name]
        said = f"{at}: the manifest declares {artifact_name.split('/', 1)[1]} as {digest}."
        have = held.get(artifact_name)
        subject: Any = have[0] if have else key_ref(
            ARTIFACT, target_ref=target_ref, name=artifact_name)
        if have is None:
            items.subject(ARTIFACT, {"target_ref": target_ref, "name": artifact_name}, said)
        if have is None or not have[3]:
            items.add(subject, "security.artifact.target", target, said)
        if have is None or have[1] != digest:
            items.add(subject, "security.artifact.declared_sha256", digest, said,
                      revises=have[2] if have and have[1] is not None else None)
    for artifact_name, have in sorted(held.items()):
        if artifact_name.startswith(f"{ref}/") and artifact_name not in wanted:
            items.retire(have[2], f"{at}: the manifest no longer declares {artifact_name}.")
