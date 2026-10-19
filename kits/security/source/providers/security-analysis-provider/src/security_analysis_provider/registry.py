"""What PyPI serves for one project: artifacts, digests, and who published them from where.

``RegistryFacts`` (``security.registry-facts``) reads a ``security.pypi-release-v1``
Capture body (the newest versions' files, each with its digest and PyPI
provenance) beside what is held for the project's target (rows of
``security.coverage_index`` and ``security.registry_facts``), and returns proposal
items for what changed:

- the target ``pypi/<project>`` and its coverage (``registry.files``):
  ``security.coverage.of`` the target, and ``security.coverage.revision``, the
  digest of the served file set, restated every time (an unchanged set
  re-observes it);
- ``security.target.source_repo``: the repository every provenance names, when they
  name one;
- per served file: the artifact ``pypi/<project>`` + file name, its
  ``security.artifact.target``, ``security.artifact.sha256`` (what PyPI serves),
  ``security.artifact.release`` (the ``security.release`` of that version, which
  joins the SBOM, OSV and KEV path) and, from its provenance, the workflow that
  published it (``security.artifact.published_by``: the workflow file at the commit
  it ran from, ``github.com/<repo>@<sha>``), the environment it ran in
  (``security.artifact.publish_environment``, ``none`` when it named none) and the
  commit (``security.artifact.built_from``).

The commit is read from the attestation's signing certificate: the Fulcio
extension ``1.3.6.1.4.1.57264.1.3`` (GitHub workflow SHA, raw bytes) or
``1.3.6.1.4.1.57264.1.13`` (source repository digest, a DER UTF8String). The
certificate's signature is not verified here: PyPI verified the attestation
when it accepted it; this reads what PyPI serves. A file without provenance gets
no publisher facts: nothing states one. A file that leaves the newest versions
keeps its facts (PyPI still serves it).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import Bound, InputError, Row, key_ref, parse_rows
from .workflows import ARTIFACT, COVERAGE, REPO, TARGET, WORKFLOW, _Items

CHANGE = "security.change"
RELEASE = "security.release"
SCOPE = "registry.files"
#: DER encodings of the Fulcio GitHub commit OIDs.
_OID_WORKFLOW_SHA = bytes.fromhex("060a2b0601040183bf300103")
_OID_SOURCE_DIGEST = bytes.fromhex("060a2b0601040183bf30010d")


def classify(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    release = payload.get("release")
    if not isinstance(release, Mapping) or not isinstance(release.get("versions"), list):
        return None
    return {"release": "present"}


def _tlv(data: bytes, at: int) -> tuple[int, int, int]:
    """(tag, value start, value end) of the DER element at ``at``."""

    tag = data[at]
    length = data[at + 1]
    start = at + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    return tag, start, start + length


def certificate_commit(certificate_b64: object) -> str | None:
    """The commit SHA a Fulcio signing certificate names, or None."""

    if not isinstance(certificate_b64, str):
        return None
    try:
        der = base64.b64decode(certificate_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    for oid, wrapped in ((_OID_SOURCE_DIGEST, True), (_OID_WORKFLOW_SHA, False)):
        at = der.find(oid)
        if at < 0:
            continue
        try:
            cursor = at + len(oid)
            tag, start, end = _tlv(der, cursor)
            if tag == 0x01:  # an explicit critical flag
                tag, start, end = _tlv(der, end)
            if tag != 0x04:
                continue
            value = der[start:end]
            if wrapped:
                inner, inner_start, inner_end = _tlv(value, 0)
                value = value[inner_start:inner_end] if inner == 0x0C else b""
            text = value.decode("ascii").strip().lower()
        except (IndexError, UnicodeDecodeError):
            continue
        if len(text) == 40 and all(c in "0123456789abcdef" for c in text):
            return text
    return None


def publisher(provenance: object) -> dict[str, Any] | None:
    """(repository, workflow, environment, commit) of a GitHub-published file, or None."""

    if not isinstance(provenance, Mapping):
        return None
    for bundle in provenance.get("attestation_bundles") or ():
        who = bundle.get("publisher") if isinstance(bundle, Mapping) else None
        if not isinstance(who, Mapping) or who.get("kind") != "GitHub":
            continue
        repository = str(who.get("repository") or "").strip().lower()
        workflow = str(who.get("workflow") or "").strip()
        if not repository or not workflow:
            continue
        commit = None
        for attestation in bundle.get("attestations") or ():
            material = (attestation or {}).get("verification_material") or {}
            commit = certificate_commit(material.get("certificate"))
            if commit:
                break
        environment = who.get("environment")
        return {
            "repository": repository,
            "workflow": workflow,
            "environment": environment.strip() if isinstance(environment, str)
            and environment.strip() else "none",
            "commit": commit,
        }
    return None


def _release(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not isinstance(value.get("versions"), list):
        raise InputError("release must be the pypi-release Capture body")
    if not isinstance(value.get("project"), str) or not value["project"]:
        raise InputError("the release names no project")
    return dict(value)


def served_revision(release: Mapping[str, Any]) -> str:
    """The digest of the served file set: what changes when PyPI serves anything else."""

    files = sorted(
        (str(version.get("version")), str(item.get("filename")), str(item.get("sha256")),
         int(item.get("provenance_status") or 0), bool(item.get("yanked")))
        for version in release["versions"] for item in version.get("files") or ()
    )
    return "sha256:" + hashlib.sha256(json.dumps(files).encode()).hexdigest()


class RegistryFacts:
    """The ``security.registry-facts`` implementation."""

    interface_id = "security.registry-facts"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            release = _release(context.input.get("release"))
            coverage = parse_rows(context.input.get("coverage"))
            held = parse_rows(context.input.get("held"))
            output, metrics = _facts(release, coverage, held)
            return ProviderResult.ok(output, metrics=metrics)
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))


def _facts(
    release: dict[str, Any], coverage: list[Row], held: list[Row]
) -> tuple[dict[str, Any], dict[str, float]]:
    project = release["project"]
    locator = f"pypi/{project}"
    revision = served_revision(release)
    at = f"PyPI {project}"
    items = _Items()
    target_bound = next((b for row in held if (b := row.subject("target"))), None)
    target: Any = target_bound or key_ref(TARGET, registry="pypi", name=project)
    if target_bound is None:
        items.subject(TARGET, {"registry": "pypi", "name": project},
                      f"{at}: PyPI serves the project {project}.")
    held_coverage = next((row for row in coverage if row.subject("coverage")), None)
    coverage_bound = held_coverage.subject("coverage") if held_coverage else None
    cover: Any = coverage_bound or key_ref(COVERAGE, source=locator, scope=SCOPE)
    if coverage_bound is None:
        items.subject(COVERAGE, {"source": locator, "scope": SCOPE},
                      f"{at}: every file of the newest versions was read.")
    files = [(str(v.get("version")), f) for v in release["versions"] for f in v.get("files") or ()]
    why = (f"{at}: read every file of the newest {len(release['versions'])} versions "
           f"({len(files)} files).")
    held_revision = held_coverage.value("revision") if held_coverage else None
    revision_id = (held_coverage.claim_id(coverage_bound, "security.coverage.revision")
                   if held_coverage and coverage_bound else None)
    if held_revision is not None and held_revision != revision and revision_id:
        items.add(cover, "security.coverage.revision", revision, why, revises=revision_id)
    else:
        items.restate(cover, "security.coverage.revision", revision, why)
    if held_coverage is None or held_coverage.value("of") is None:
        items.add(cover, "security.coverage.of", target, why)
    publishers = {name: publisher(f.get("provenance")) for _v, f in files
                  if (name := str(f.get("filename")))}
    repositories = {p["repository"] for p in publishers.values() if p}
    held_repo = next((row for row in held if row.value("repo_full_name")), None)
    if len(repositories) == 1:
        (repository,) = repositories
        if held_repo is None or held_repo.value("repo_full_name") != repository:
            repo = key_ref(REPO, forge_host="github.com", full_name=repository)
            items.subject(REPO, {"forge_host": "github.com", "full_name": repository},
                          f"{at}: its provenance names the repository {repository}.")
            items.add(target, "security.target.source_repo", repo,
                      f"{at}: every file's provenance names github.com/{repository}.",
                      revises=held_repo.claim_id(target_bound, "security.target.source_repo")
                      if held_repo is not None and target_bound is not None else None,
                      role="normative")
    by_name: dict[str, Row] = {}
    for row in held:
        name = row.value("artifact_name")
        if isinstance(name, str) and row.subject("artifact") is not None:
            by_name.setdefault(name, row)
    for version, item in sorted(files, key=lambda pair: str(pair[1].get("filename"))):
        _artifact(items, project, target, version, item, publishers.get(
            str(item.get("filename"))), by_name.get(str(item.get("filename"))))
    out = items.output()
    changed = items.counts["added"] + items.counts["revised"] + items.counts["retired"]
    return ({"items": out, "changed": changed, **items.counts, "locator": locator,
             "revision": revision, "files": len(files)},
            {"items": float(len(out)), "changed": float(changed)})


def _artifact(items: _Items, project: str, target: Any, version: str,
              item: Mapping[str, Any], who: dict[str, Any] | None, row: Row | None) -> None:
    name = str(item.get("filename"))
    bound: Bound | None = row.subject("artifact") if row else None
    artifact: Any = bound or key_ref(ARTIFACT, target_ref=f"pypi/{project}", name=name)
    said = f"PyPI {project} {version} serves {name}"
    if bound is None:
        items.subject(ARTIFACT, {"target_ref": f"pypi/{project}", "name": name}, f"{said}.")

    def held(field: str) -> Any:
        return row.value(field) if row else None

    def claim(predicate: str) -> str | None:
        return row.claim_id(bound, predicate) if row and bound else None

    if bound is None or not claim("security.artifact.target"):
        items.add(artifact, "security.artifact.target", target, f"{said}.")
    digest = "sha256:" + str(item.get("sha256") or "").lower()
    if held("sha256") != digest:
        items.add(artifact, "security.artifact.sha256", digest, f"{said} with {digest}.",
                  revises=claim("security.artifact.sha256") if held("sha256") else None)
    if held("release_version") != version:
        items.subject(RELEASE, {"product_name": project, "version": version},
                      f"{said}: release {version} of {project}.")
        items.add(artifact, "security.artifact.release",
                  key_ref(RELEASE, product_name=project, version=version),
                  f"{said} as part of release {version}.",
                  revises=claim("security.artifact.release") if held("release_version") else None,
                  role="normative")
    if who is None:
        return
    environment = who["environment"]
    if held("publish_environment") != environment:
        items.add(artifact, "security.artifact.publish_environment", environment,
                  f"{said}, published from environment {environment} (provenance).",
                  revises=claim("security.artifact.publish_environment")
                  if held("publish_environment") else None)
    commit = who["commit"]
    if commit is None:
        return
    source = f"github.com/{who['repository']}@{commit}"
    path = f".github/workflows/{who['workflow']}"
    if (held("workflow_source"), held("workflow_path")) != (source, path):
        items.subject(WORKFLOW, {"source": source, "path": path},
                      f"{said}: published by {path} at {commit[:12]} (provenance).")
        items.add(artifact, "security.artifact.published_by",
                  key_ref(WORKFLOW, source=source, path=path),
                  f"{said}, published by {who['repository']} {path} at {commit} (provenance).",
                  revises=claim("security.artifact.published_by")
                  if held("workflow_source") else None)
    if held("built_from_sha") != commit:
        items.subject(CHANGE, {"repo_ref": f"github.com/{who['repository']}",
                               "commit_sha": commit},
                      f"{said}: built from {commit} (provenance).")
        items.add(artifact, "security.artifact.built_from",
                  key_ref(CHANGE, repo_ref=f"github.com/{who['repository']}", commit_sha=commit),
                  f"{said}, built from commit {commit} (provenance).",
                  revises=claim("security.artifact.built_from") if held("built_from_sha") else None)
