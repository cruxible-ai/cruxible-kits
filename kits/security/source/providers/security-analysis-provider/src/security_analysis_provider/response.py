"""Incident response: runtime inventory, log reads, credential state, and the five questions.

Cruxible holds what needs doing and why, who approved it and the evidence that it
is done; the user's agent performs every action with its own tools. Nothing here
closes anything on a self-report: a patch is verified by a full inventory scan, a
rotation by a separate state read, an audit's ``none`` by complete reads.

``RuntimeInventory`` (``security.runtime-inventory``) reads one retained inventory
scan beside what one scope's coverage holds (rows of ``security.inventory_index``
and ``security.inventory_patches``):

- the kit body ``{scope, looked_for, coverage: full|partial, assets: [{hostname,
  runs: [purl@version]}]}``, tool-neutral and without timestamps, so an unchanged
  fleet is the same bytes and a re-scan re-observes the coverage revision (the
  digest of the scan's looked_for and (asset, runs) set). A **full** scan states the
  coverage (revision, looked_for), retires the runs it no longer sees of the
  products it looked for (``*``: every product), retires an asset it no longer
  lists from the scope, and may verify a patch. A **partial** scan only adds.
- a CycloneDX JSON SBOM of **one asset** (Syft, Trivy), annotated with the
  metadata properties ``cruxible.scope`` and ``cruxible.asset``: every component
  with a purl and a version is a run of that asset, and the SBOM is the asset's
  complete run set (it retires runs it no longer lists and may verify a patch on
  that asset). A raw SBOM carries its own timestamp, so each scan is new content:
  it never restates the scope's coverage revision, and proposes only when the
  asset's run set changed.

A release is named by key: ``product_name`` the purl's name, ``version`` its
version; ``release.component`` is the purl (qualifiers dropped), so OSV decides a
distro build. A patch (a remediation with ``work.asset`` and ``work.assessment``)
of a scanned asset is ``verified`` when a full read shows the asset no longer
runs the assessment's release (for a product the scan looked for), ``failed``
when it is claimed ``completed`` and a scan still shows it. A verified patch
whose release runs again is a regression: reported in the summary, never revised
(the respond Line posts it).

``LogReads`` (``security.log-reads``) reads one log read
``{audit: {incident, service}, source, query, from, to, complete,
records_scanned, matches: [{at, summary}]}`` for the Line's incident beside the
incident's audits (rows of ``security.audit_status``). A complete read of a
stated audit is one ``security.audit.read`` (``SOURCE FROM/TO``); an incomplete
read, or a read for an audit nobody stated, is posted, never recorded. Never a
result: that is the auditor's judgment.

``CredentialState`` (``security.credential-state``) reads one credential's key
state ``{issuer, name, read: receipt|state_read, keys: [{key_id, state,
created_at, revoked_at, last_used_at, created_by}]}`` and nothing else, beside
every credential's held state (rows of ``security.rotation_work``). An unknown
field anywhere, or a key id shaped like a secret, refuses the whole body: nothing
is proposed and one ``secret_shape`` item is posted that echoes no value (the
bytes are retained already: the contract authorizes ``cruxible capture erase``). From either read: the current
key's ``key_id``, ``issued_at`` and ``issued_by``. Only from a ``state_read`` (a
separate listing): ``revoked_key``, and a rotation's ``verification`` --
``verified`` when its ``revokes_key`` is revoked, deleted or no longer listed and
an active key other than it was issued after the incident's window_start,
``failed`` when it is claimed ``completed`` while ``revokes_key`` is still listed
active or inactive.

``Respond`` (``security.respond``) answers one incident's five questions in three
states, from the rows of ``security.incident_exposure``,
``security.incident_patches``, ``security.overdue_patches``,
``security.incident_exceptions``, ``security.audit_status`` and
``security.incident_credentials``:

- RQ1 which deployments run an affected release: ``exposed`` (found); an asset
  that only declares installing it, or a patched one, under no current coverage
  is unknown (a gap naming the inventory pull); a current full coverage that looked
  for the product and shows no affected run is none. An inconclusive assessment is
  unknown (an analyst's judgment answers it).
- RQ2 is each exposure patched: ``patch_missing``, ``patch_overdue``,
  ``patch_disputed`` (a scan read it after the claim and still shows the release:
  verification failed), ``patch_regressed`` (verified, then seen running again)
  are found; ``verified`` with no affected run is none; a claimed patch no scan has
  read since is unknown (the gap names the inventory pull); an approved one on
  schedule is pending (summary only). An exposure with no patch, or an overdue one,
  is ``excepted`` (summary only) while an approved risk exception of the asset holds
  for each of the release's incident CVEs (rows of ``security.incident_exceptions``,
  which drop an exception at its ``expires_at`` by the query's evaluation time);
  then it is ``patch_missing`` or ``patch_overdue`` again.
- RQ3 were we exploited in the window, per service: ``exploited`` is found;
  ``not_exploited`` is none only with ``window_end`` stated and, for every stated
  log source, complete reads whose union covers [window_start, window_end];
  anything else (no audit, no log source, window open, no result, inconclusive, a
  contended result, an uncovered interval, named per source) is unknown. An audit
  starts from the service's standing list (``service.log_source``): the gap that
  asks for a missing audit names it (``sources``), and a source the service lists
  that its audit does not state is unknown until the audit states it.
- RQ4 which credentials warrant rotation: under ``on_found_or_unknown`` the
  credentials of a service whose RQ3 is found or unknown, under ``all_exposed``
  every credential an exposed service uses. ``rotate`` is posted with the
  service's audit and patch state: rotating after a verified patch is the
  recommended order, never a gate (the agent decides; a key known leaked is
  rotated at once). A rotation is none once a state read verified it;
  ``rotation_disputed`` when it failed; unknown when claimed and no state read
  followed (a gap naming the credential pull).
- RQ5 can the incident close: ``ready_to_close`` once nothing is found, unknown
  or pending except audits that stay unknown, listed as accepted residue with
  their rotations.

A closed incident posts nothing. Every posted payload holds only what stays the
same while the situation does, so the inbox dedupes a repeat sighting. No
network, no clock: the overdue rows come from the query's evaluation time.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from cruxible_provider_runtime.errors import RefusalCode
from cruxible_provider_runtime.provider_api import ProviderResult, ProviderRunContext

from .common import (
    Bound,
    InputError,
    Row,
    claim_item,
    key_ref,
    name_form,
    parse_rows,
    replacing,
    retirement_item,
    sorted_items,
    subject_item,
)

ASSET = "security.asset"
RELEASE = "security.release"
COVERAGE = "security.coverage"
AUDIT = "security.audit"
CREDENTIAL = "security.credential"
INVENTORY_SCOPE = "inventory.runtime"
INVENTORY_CONTRACT = "security.runtime-inventory-v1"
MAX_ASSETS = 2000
MAX_RUNS = 20_000
MAX_POSTS = 200
_DATETIME = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:"
                       r"[0-5]\dZ$")


def _kind_id(path: str | None) -> str:
    """``kind/id`` of a Subject path (``subjects/kind/id.json``) or reference."""

    text = str(path or "").removeprefix("subjects/").removesuffix(".json")
    return text.rsplit(":", 1)[-1] if ":" in text.split("/", 1)[0] else text


def _ref(bound: Bound) -> str:
    return f"{bound.kind}/{bound.subject_id}"


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _when(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DATETIME.fullmatch(value):
        raise InputError(f"{label} must be an ISO 8601 UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    return value


def _refuse_truncated(truncated: object, names: Iterable[str]) -> None:
    cut = [name for name in names
           if (truncated.get(name) if isinstance(truncated, Mapping) else bool(truncated))]
    if cut:
        raise InputError(f"truncated taps {sorted(cut)}: a missing row would read as absent")


class _Items:
    """Subjects first (once per key), then Claims in a stable order, with counts."""

    def __init__(self) -> None:
        self.subjects: list[dict[str, Any]] = []
        self.claims: list[dict[str, Any]] = []
        self.counts = {"added": 0, "revised": 0, "retired": 0, "restated": 0}
        self._keys: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

    def subject(self, kind: str, key: Mapping[str, str], why: str) -> None:
        marker = (kind, tuple(sorted(key.items())))
        if marker not in self._keys:
            self._keys.add(marker)
            self.subjects.append(subject_item(kind, key, why))

    def add(self, subject: Any, predicate: str, value: Any, why: str,
            revises: str | None = None, *, role: str = "observation") -> None:
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

    def output(self) -> list[dict[str, Any]]:
        return self.subjects + sorted_items(self.claims) if self.claims else []


# --- runtime inventory ------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    """One running release: the purl (qualifiers dropped) and its release key."""

    purl: str
    name: str
    version: str

    @property
    def key(self) -> tuple[str, str]:
        return name_form(self.name), self.version.strip()

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}"


def parse_purl(text: object) -> Run | None:
    """A ``pkg:type/[namespace/]name@version`` purl as a run, or None."""

    if not isinstance(text, str) or not text.strip().startswith("pkg:"):
        return None
    body = text.strip().split("#", 1)[0].split("?", 1)[0]
    if "@" not in body:
        return None
    path, _, version = body.rpartition("@")
    version = unquote(version).strip()
    purl_type, _, rest = path[4:].partition("/")
    segments = [s for s in rest.split("/") if s]
    if not purl_type or not segments or not version:
        return None
    name = unquote(segments[-1]).strip()
    if not name:
        return None
    return Run(purl=f"pkg:{purl_type.lower()}/{'/'.join(segments)}@{version}", name=name,
               version=version)


@dataclass
class Scan:
    format: str
    scope: str
    looked_for: set[str]
    #: kit full scan: states the scope's coverage, retires across the scope
    full_scope: bool
    #: hostname (canonical) -> (hostname as written, runs, complete for this asset)
    assets: dict[str, tuple[str, dict[tuple[str, str], Run], bool]] = field(
        default_factory=dict)

    def covers(self, product: str) -> bool:
        return "*" in self.looked_for or name_form(product) in self.looked_for


_KIT_KEYS = {"scope", "looked_for", "coverage", "assets"}


def _kit_scan(document: Mapping[str, Any]) -> Scan:
    unknown = sorted(set(document) - _KIT_KEYS)
    if unknown or not _KIT_KEYS <= set(document):
        raise InputError(f"an inventory body is exactly {sorted(_KIT_KEYS)} "
                         f"(unknown {unknown}, missing {sorted(_KIT_KEYS - set(document))})")
    scope, looked_for, coverage = (document["scope"], document["looked_for"],
                                   document["coverage"])
    if not isinstance(scope, str) or not scope.strip():
        raise InputError("scope must be a nonempty string")
    if (not isinstance(looked_for, list) or not looked_for
            or not all(isinstance(item, str) and item.strip() for item in looked_for)):
        raise InputError("looked_for must list the products the scan looked for (or *)")
    if coverage not in ("full", "partial"):
        raise InputError("coverage must be full or partial")
    if not isinstance(document["assets"], list) or len(document["assets"]) > MAX_ASSETS:
        raise InputError(f"assets must be a list of at most {MAX_ASSETS}")
    scan = Scan(format="kit", scope=scope.strip(),
                looked_for={name_form(item) for item in looked_for},
                full_scope=coverage == "full")
    runs = 0
    for asset in document["assets"]:
        if not isinstance(asset, Mapping) or set(asset) - {"hostname", "runs"}:
            raise InputError("an asset is exactly {hostname, runs}")
        hostname, listed = asset.get("hostname"), asset.get("runs")
        if not isinstance(hostname, str) or not hostname.strip() or not isinstance(listed,
                                                                                   list):
            raise InputError("an asset needs a hostname and a runs list")
        _, held_runs, _ = scan.assets.setdefault(hostname.strip().casefold(),
                                                 (hostname.strip(), {}, scan.full_scope))
        for text in listed:
            run = parse_purl(text)
            if run is None:
                raise InputError(f"a run must be a purl with a version: {str(text)[:120]!r}")
            held_runs[run.key] = run
            runs += 1
    if runs > MAX_RUNS:
        raise InputError(f"the scan lists more than {MAX_RUNS} runs")
    return scan


def _properties(*holders: object) -> dict[str, str]:
    found: dict[str, str] = {}
    for holder in holders:
        if not isinstance(holder, Mapping):
            continue
        for item in holder.get("properties") or ():
            if isinstance(item, Mapping) and isinstance(item.get("name"), str):
                found.setdefault(str(item["name"]), str(item.get("value") or "").strip())
    return found


def _components(items: object) -> Iterable[Mapping[str, Any]]:
    for item in items if isinstance(items, list) else ():
        if isinstance(item, Mapping):
            yield item
            yield from _components(item.get("components"))


def _cyclonedx_scan(document: Mapping[str, Any]) -> Scan:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), Mapping) else {}
    properties = _properties(metadata, metadata.get("component"))
    scope, asset = properties.get("cruxible.scope"), properties.get("cruxible.asset")
    if not scope or not asset:
        raise InputError("a CycloneDX inventory names its asset and scope in metadata "
                         "properties cruxible.asset and cruxible.scope")
    runs: dict[tuple[str, str], Run] = {}
    for component in _components(document.get("components")):
        run = parse_purl(component.get("purl"))
        if run is not None:
            runs[run.key] = run
    if len(runs) > MAX_RUNS:
        raise InputError(f"the SBOM lists more than {MAX_RUNS} components with purls")
    scan = Scan(format="cyclonedx", scope=scope, looked_for={"*"}, full_scope=False)
    scan.assets[asset.casefold()] = (asset, runs, True)
    return scan


def read_inventory(text: str) -> Scan:
    try:
        document = json.loads(text)
    except ValueError as error:
        raise InputError("the inventory is not JSON") from error
    if not isinstance(document, Mapping):
        raise InputError("the inventory is not a JSON object")
    if document.get("bomFormat") == "CycloneDX":
        return _cyclonedx_scan(document)
    return _kit_scan(document)


def revision(scan: Scan) -> str:
    """The digest of a scan's looked_for and (asset, runs) set: the same fleet, the same
    revision, whatever order the tool wrote it in."""

    body = {"looked_for": sorted(scan.looked_for),
            "assets": sorted([host, sorted(run.purl for run in runs.values())]
                             for host, (_, runs, _) in scan.assets.items())}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class HeldAsset:
    bound: Bound
    scanned_in: str | None = None
    #: release key -> runs Claim ID
    runs: dict[tuple[str, str], str] = field(default_factory=dict)


@dataclass
class HeldScope:
    coverage: Bound | None = None
    revision: str | None = None
    revision_claim: str | None = None
    looked_for: dict[str, str] = field(default_factory=dict)
    assets: dict[str, HeldAsset] = field(default_factory=dict)


def held_scope(rows: list[Row]) -> HeldScope:
    held = HeldScope()
    keys: dict[str, tuple[str, str]] = {}  # release kind/id -> its key
    for row in rows:
        run = row.subject("run")
        product, version = row.value("run_product"), row.value("run_version")
        if run is not None and isinstance(product, str) and isinstance(version, str):
            keys[_ref(run)] = (name_form(product), version.strip())
    for row in rows:
        coverage = row.subject("coverage")
        if coverage is None:
            continue
        if held.coverage is None:
            held.coverage = coverage
            held.revision = row.value("revision")
            held.revision_claim = row.claim_id(coverage, "security.coverage.revision")
        for item in row.included("looked_for"):
            if isinstance(item.value, str):
                held.looked_for.setdefault(name_form(item.value), item.claim_id)
        asset, hostname = row.subject("asset"), row.value("hostname")
        if asset is None or not isinstance(hostname, str):
            continue
        entry = held.assets.setdefault(hostname.strip().casefold(), HeldAsset(bound=asset))
        for item in row.included("scanned_in"):
            if _kind_id(item.object_path) == _ref(coverage):
                entry.scanned_in = item.claim_id
        for item in row.included("runs"):
            key = keys.get(_kind_id(item.object_path))
            if key is not None:
                entry.runs.setdefault(key, item.claim_id)
    return held


@dataclass
class HeldPatch:
    bound: Bound
    hostname: str
    progress: str | None
    verification: str | None
    verification_claim: str | None
    affected: tuple[str, str]
    label: str


def held_patches(rows: list[Row]) -> dict[str, HeldPatch]:
    patches: dict[str, HeldPatch] = {}
    for row in rows:
        patch, hostname = row.subject("patch"), row.value("hostname")
        product, version = row.value("affected_product"), row.value("affected_version")
        if (patch is None or not isinstance(hostname, str) or not isinstance(product, str)
                or not isinstance(version, str) or patch.path in patches):
            continue
        patches[patch.path] = HeldPatch(
            bound=patch, hostname=hostname.strip().casefold(), progress=row.value("progress"),
            verification=row.value("verification"),
            verification_claim=row.claim_id(patch, "security.work.verification"),
            affected=(name_form(product), version.strip()), label=f"{product} {version}")
    return patches


def inventory(text: str, held_rows: list[Row], patch_rows: list[Row],
              line_scope: str) -> dict[str, Any]:
    scan = read_inventory(text)
    summary: dict[str, Any] = {
        "scope": line_scope, "format": scan.format,
        "coverage": "full" if scan.full_scope else (
            "asset" if scan.format == "cyclonedx" else "partial"),
        "revision": revision(scan) if scan.full_scope else "", "regressions": [],
        "assets": len(scan.assets),
        "runs": sum(len(runs) for _, runs, _ in scan.assets.values()),
        "verified": 0, "failed": 0}
    zero = {"added": 0, "revised": 0, "retired": 0, "restated": 0, "changed": 0,
            "proposes": 0}
    if name_form(scan.scope) != name_form(line_scope):
        return {**summary, **zero, "items": [], "mine": 0}
    held = held_scope(held_rows)
    items = _Items()
    said = (f"Runtime inventory of {line_scope} ({scan.format}, {summary['coverage']}, "
            f"looked for {', '.join(sorted(scan.looked_for))})")
    cover: Any = held.coverage or key_ref(COVERAGE, source=line_scope, scope=INVENTORY_SCOPE)
    if held.coverage is None:
        items.subject(COVERAGE, {"source": line_scope, "scope": INVENTORY_SCOPE},
                      f"{said}: the scope's assets and what they run.")
    if scan.full_scope:
        digest = summary["revision"]
        why = f"{said}: read every asset of the scope ({len(scan.assets)} assets)."
        if held.revision is not None and held.revision != digest and held.revision_claim:
            items.add(cover, "security.coverage.revision", digest, why,
                      revises=held.revision_claim)
        else:
            items.restate(cover, "security.coverage.revision", digest, why)
        pairs, adds, dropped = replacing(held.looked_for, scan.looked_for)
        for product, claim in pairs:
            items.add(cover, "security.coverage.looked_for", product, f"{said}.", revises=claim)
        for product in adds:
            items.add(cover, "security.coverage.looked_for", product, f"{said}.")
        for product in dropped:
            items.retire(held.looked_for[product], f"{said}: no longer looks for {product}.")
    components: set[tuple[tuple[str, str], str]] = set()
    for host in sorted(scan.assets):
        written, runs, complete = scan.assets[host]
        have = held.assets.get(host)
        asset: Any = have.bound if have else key_ref(ASSET, hostname=written)
        if have is None:
            items.subject(ASSET, {"hostname": written}, f"{said}: {written} is in the scope.")
        if have is None or have.scanned_in is None:
            items.add(asset, "security.asset.scanned_in", cover, f"{said}: {written} was read.")
        held_runs = have.runs if have else {}
        # What a complete read no longer sees goes (of the products it looked for); a new
        # version of a product revises the run it replaces (see common.replacing).
        retirable = {key: claim for key, claim in held_runs.items()
                     if key in runs or (complete and scan.covers(key[0]))}
        pairs, adds, gone = replacing(retirable, set(runs),
                                      same=lambda key: key[0])
        for key, revises in [*pairs, *((key, None) for key in adds)]:
            run = runs[key]
            release = key_ref(RELEASE, product_name=run.name, version=run.version)
            items.subject(RELEASE, {"product_name": run.name, "version": run.version},
                          f"{said}: {written} runs {run.purl}.")
            if (run.key, run.purl) not in components:  # one statement per terminal
                components.add((run.key, run.purl))
                items.add(release, "security.release.component", run.purl,
                          f"{said}: {run.purl} is the runtime's own package.")
            items.add(asset, "security.asset.runs", release, f"{said}: {written} runs "
                      f"{run.purl}.", revises=revises)
        for key in gone:
            items.retire(held_runs[key], f"{said}: {written} no longer runs {key[0]} {key[1]}.")
    if scan.full_scope:
        for host in sorted(set(held.assets) - set(scan.assets)):
            gone = held.assets[host]
            items.retire(gone.scanned_in, f"{said}: {host} is no longer in the scope.")
            for key in sorted(gone.runs):
                if scan.covers(key[0]):
                    items.retire(gone.runs[key], f"{said}: {host} is no longer in the scope.")
    for _path, patch in sorted(held_patches(patch_rows).items()):
        if patch.hostname not in scan.assets:
            continue
        written, runs, complete = scan.assets[patch.hostname]
        running = patch.affected in runs
        patch_ref = _ref(patch.bound)
        if not running and complete and scan.covers(patch.affected[0]):
            if patch.verification != "verified":
                items.add(patch.bound, "security.work.verification", "verified",
                          f"{said}: {written} no longer runs {patch.label} (patch {patch_ref}).",
                          revises=patch.verification_claim if patch.verification else None)
                summary["verified"] += 1
        elif running and patch.verification == "verified":
            summary["regressions"].append({"patch": patch_ref, "asset": written,
                                           "release": patch.label})
        elif running and patch.progress == "completed" and patch.verification != "failed":
            items.add(patch.bound, "security.work.verification", "failed",
                      f"{said}: patch {patch_ref} is claimed completed, but {written} still "
                      f"runs {patch.label}.",
                      revises=patch.verification_claim if patch.verification else None)
            summary["failed"] += 1
    output = items.output()
    changed = len(items.claims) - items.counts["restated"]
    return {**summary, **items.counts, "items": output, "mine": 1, "changed": changed,
            "proposes": len(items.claims)}


def classify_inventory(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    text = payload.get("inventory_text")
    if not isinstance(text, str) or not isinstance(payload.get("held"), list):
        return None
    return {"inventory": "present", "size": "small" if len(text) <= 1_048_576 else "large"}


class RuntimeInventory:
    """The ``security.runtime-inventory`` implementation."""

    interface_id = "security.runtime-inventory"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            _refuse_truncated(context.input.get("truncated"), ("held", "patches"))
            result = inventory(str(context.input.get("inventory_text") or ""),
                               parse_rows(context.input.get("held")),
                               parse_rows(context.input.get("patches")),
                               str(context.input.get("scope") or ""))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        return ProviderResult.ok(result, metrics={"items": float(len(result["items"]))})


# --- log reads ----------------------------------------------------------------------

_LOG_KEYS = {"audit", "source", "query", "from", "to", "complete", "records_scanned", "matches",
             "incomplete_reason"}


@dataclass
class HeldAudit:
    bound: Bound
    reads: set[str]


def read_log(text: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except ValueError as error:
        raise InputError("the log read is not JSON") from error
    if not isinstance(document, Mapping):
        raise InputError("the log read is not a JSON object")
    unknown = sorted(set(document) - _LOG_KEYS)
    if unknown:
        raise InputError(f"a log read has no fields {unknown}")
    audit = document.get("audit")
    if (not isinstance(audit, Mapping) or set(audit) != {"incident", "service"}
            or not all(isinstance(audit[k], str) and audit[k].strip() for k in audit)):
        raise InputError("audit must be exactly {incident, service}")
    source = document.get("source")
    if not isinstance(source, str) or not source.strip() or " " in source.strip():
        raise InputError("source must name one log source (no spaces)")
    start, end = _when(document.get("from"), "from"), _when(document.get("to"), "to")
    if start > end:
        raise InputError("from must not be after to")
    if not isinstance(document.get("complete"), bool):
        raise InputError("complete must be true or false")
    matches = document.get("matches") or []
    if not isinstance(matches, list):
        raise InputError("matches must be a list")
    return {"incident": audit["incident"].strip(), "service": audit["service"].strip(),
            "source": source.strip(), "from": start, "to": end,
            "complete": document["complete"], "matches": len(matches),
            "why": str(document.get("incomplete_reason") or
                       "the tool did not search every record in [from, to]")}


def log_reads(text: str, held_rows: list[Row], line_incident: str) -> dict[str, Any]:
    read = read_log(text)
    label = f"{read['source']} {read['from']}/{read['to']}"
    summary: dict[str, Any] = {"incident": read["incident"], "service": read["service"],
                               "source": read["source"], "read": label,
                               "matches": read["matches"], "added": 0, "changed": 0}
    if name_form(read["incident"]) != name_form(line_incident):
        return {**summary, "items": [], "inbox": [], "mine": 0, "recordable": 0, "posted": 0}
    audits: dict[str, HeldAudit] = {}
    for row in held_rows:
        audit, service = row.subject("audit"), row.value("service_ref")
        if audit is None or not isinstance(service, str):
            continue
        entry = audits.setdefault(name_form(service), HeldAudit(bound=audit, reads=set()))
        entry.reads.update(str(value).strip() for value in _list(row.value("read")))
    held = audits.get(name_form(read["service"]))
    posting = {"incident": read["incident"], "service": read["service"],
               "source": read["source"], "from": read["from"], "to": read["to"]}
    if not read["complete"]:
        item = {"kind": "read_incomplete", **posting, "why": read["why"]}
        return {**summary, "items": [], "inbox": [item], "mine": 1, "recordable": 0,
                "posted": 1}
    if held is None:
        item = {"kind": "audit_not_stated", **posting,
                "why": "no audit of this service is stated for the incident: state it with "
                       "its log sources (security.audit.log_source, from the service's "
                       "service.log_source), then acquire the read again"}
        return {**summary, "items": [], "inbox": [item], "mine": 1, "recordable": 0,
                "posted": 1}
    if label in held.reads:
        return {**summary, "items": [], "inbox": [], "mine": 1, "recordable": 1, "posted": 0}
    item = claim_item(held.bound, "security.audit.read", label,
                      f"A complete read of {read['source']} from {read['from']} to "
                      f"{read['to']} ({read['matches']} matches) for {read['service']}'s audit "
                      f"of {read['incident']}.")
    return {**summary, "items": [item], "inbox": [], "mine": 1, "recordable": 1, "posted": 0,
            "added": 1, "changed": 1}


def classify_log(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not isinstance(payload.get("read_text"), str) or not isinstance(payload.get("held"),
                                                                       list):
        return None
    return {"read": "present"}


class LogReads:
    """The ``security.log-reads`` implementation."""

    interface_id = "security.log-reads"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            _refuse_truncated(context.input.get("truncated"), ("held",))
            result = log_reads(str(context.input.get("read_text") or ""),
                               parse_rows(context.input.get("held")),
                               str(context.input.get("incident") or ""))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        return ProviderResult.ok(result, metrics={"items": float(len(result["items"]))})


# --- credential state -----------------------------------------------------------------

_CREDENTIAL_KEYS = {"issuer", "name", "read", "keys"}
_KEY_KEYS = {"key_id", "state", "created_at", "revoked_at", "last_used_at", "created_by"}
_KEY_STATES = ("active", "inactive", "revoked", "deleted")
#: Prefixes of secrets, never of identifiers.
_SECRET_PREFIXES = ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_", "ghp_", "gho_",
                    "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-",
                    "npm_", "pypi-", "aiza", "-----begin")


class SecretShape(ValueError):
    """The body is outside the allow-list, or a value looks like a secret."""


def _entropy(text: str) -> float:
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def secret_shaped(value: str) -> bool:
    """Whether a key id looks like a secret: too long, a secret's prefix, or a long
    high-entropy string. ``fp:`` + hex fingerprints and hex or UUID ids pass."""

    text = value.strip()
    lowered = text.casefold()
    if lowered.startswith("fp:"):
        return not re.fullmatch(r"fp:[0-9a-f]{16}", lowered)
    if len(text) > 40 or "private key" in lowered:
        return True
    if lowered.startswith(_SECRET_PREFIXES):
        return True
    if re.fullmatch(r"[0-9a-f-]+", lowered):
        return False
    return len(text) >= 24 and _entropy(text) >= 4.3


def read_credential(text: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except ValueError as error:
        raise SecretShape("the body is not JSON") from error
    if not isinstance(document, Mapping):
        raise SecretShape("the body is not a JSON object")
    unknown = sorted(set(document) - _CREDENTIAL_KEYS)
    if unknown or not _CREDENTIAL_KEYS <= set(document):
        raise SecretShape(f"the body is not exactly {sorted(_CREDENTIAL_KEYS)}; unknown fields: "
                          f"{unknown}")
    issuer, name, kind, keys = (document["issuer"], document["name"], document["read"],
                                document["keys"])
    if not isinstance(issuer, str) or not issuer.strip() or not isinstance(name, str) or (
            not name.strip()):
        raise SecretShape("issuer and name must be nonempty strings")
    if kind not in ("receipt", "state_read"):
        raise SecretShape("read must be receipt or state_read")
    if not isinstance(keys, list) or not keys or len(keys) > 100:
        raise SecretShape("keys must list 1-100 keys")
    parsed = []
    for key in keys:
        if not isinstance(key, Mapping):
            raise SecretShape("a key must be an object")
        extra = sorted(set(key) - _KEY_KEYS)
        if extra:
            raise SecretShape(f"a key has fields outside the allow-list: {extra}")
        key_id, state = key.get("key_id"), key.get("state")
        if not isinstance(key_id, str) or not key_id.strip():
            raise SecretShape("every key needs a key_id")
        if secret_shaped(key_id):
            raise SecretShape("a key_id looks like a secret (too long, a secret's prefix, or "
                              "high entropy): record the issuer's key id or fp: + 16 hex")
        if state not in _KEY_STATES:
            raise SecretShape(f"a key's state must be one of {list(_KEY_STATES)}")
        times = {}
        for stamp in ("created_at", "revoked_at", "last_used_at"):
            if key.get(stamp) is not None:
                try:
                    times[stamp] = _when(key[stamp], stamp)
                except InputError as error:
                    raise SecretShape(str(error)) from error
        created_by = key.get("created_by")
        if created_by is not None and (
                not isinstance(created_by, str) or len(created_by) > 200
                or created_by.strip().casefold().startswith(_SECRET_PREFIXES)
                or "-----begin" in created_by.casefold()):
            raise SecretShape("created_by must be a short principal name")
        parsed.append({"key_id": key_id.strip(), "state": state, **times,
                       "created_by": created_by.strip() if isinstance(created_by, str) else None})
    for value in (issuer, name):
        if "-----BEGIN" in value or len(value) > 200:
            raise SecretShape("issuer and name must be short identifiers")
    return {"issuer": issuer.strip(), "name": name.strip(), "read": kind, "keys": parsed}


@dataclass
class HeldRotation:
    bound: Bound
    progress: str | None
    verification: str | None
    verification_claim: str | None
    revokes_key: str | None
    window_start: str | None


@dataclass
class HeldCredential:
    bound: Bound
    fields: dict[str, tuple[Any, str | None]] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    rotations: dict[str, HeldRotation] = field(default_factory=dict)


def held_credentials(rows: list[Row]) -> dict[tuple[str, str], HeldCredential]:
    held: dict[tuple[str, str], HeldCredential] = {}
    for row in rows:
        bound, issuer, name = row.subject("credential"), row.value("issuer"), row.value("name")
        if bound is None or not isinstance(issuer, str) or not isinstance(name, str):
            continue
        entry = held.setdefault((issuer.strip().casefold(), name.strip()),
                                HeldCredential(bound=bound))
        for column in ("key_id", "issued_at", "issued_by"):
            entry.fields.setdefault(column, (row.value(column), row.claim_id(
                bound, f"security.credential.{column}")))
        entry.revoked.update(str(v).strip() for v in _list(row.value("revoked_key")))
        rotation = row.subject("rotation")
        if rotation is not None and rotation.path not in entry.rotations:
            entry.rotations[rotation.path] = HeldRotation(
                bound=rotation, progress=row.value("progress"),
                verification=row.value("verification"),
                verification_claim=row.claim_id(rotation, "security.work.verification"),
                revokes_key=row.value("revokes_key"), window_start=row.value("window_start"))
    return held


def credential_state(text: str, held_rows: list[Row]) -> dict[str, Any]:
    zero = {"keys": 0, "added": 0, "revised": 0, "verified": 0, "failed": 0, "changed": 0}
    try:
        state = read_credential(text)
    except SecretShape as error:
        item = {"kind": "secret_shape", "why": str(error),
                "repair": "Nothing was proposed, but the Capture's bytes are retained: rotate "
                          "anything it exposed, erase its body (cruxible capture erase; the "
                          "contract authorizes it), and acquire an allow-listed body (key ids "
                          "or fp: fingerprints only)."}
        return {**zero, "credential": "", "read": "", "items": [], "inbox": [item],
                "posted": 1}
    held = held_credentials(held_rows).get((state["issuer"].casefold(), state["name"]))
    items = _Items()
    credential: Any = held.bound if held else key_ref(CREDENTIAL, issuer=state["issuer"],
                                                      name=state["name"])
    label = f"{state['issuer']}/{state['name']}"
    said = f"A {state['read'].replace('_', ' ')} of {label}"
    if held is None:
        items.subject(CREDENTIAL, {"issuer": state["issuer"], "name": state["name"]},
                      f"{said} names the credential.")
    active = sorted((k for k in state["keys"] if k["state"] == "active"),
                    key=lambda k: k.get("created_at") or "", reverse=True)
    current = active[0] if active else None
    if current is not None:
        for column, value in (("key_id", current["key_id"]),
                              ("issued_at", current.get("created_at")),
                              ("issued_by", current.get("created_by"))):
            if value is None:
                continue
            old, claim = held.fields.get(column, (None, None)) if held else (None, None)
            if old != value:
                items.add(credential, f"security.credential.{column}", value,
                          f"{said}: the current key's {column.replace('_', ' ')} is {value}.",
                          revises=claim if old is not None else None)
    summary: dict[str, Any] = {"credential": label, "read": state["read"],
                               "keys": len(state["keys"]), "verified": 0, "failed": 0}
    if state["read"] == "state_read":
        listed = {k["key_id"]: k for k in state["keys"]}
        retired = {k["key_id"] for k in state["keys"] if k["state"] in ("revoked", "deleted")}
        for key_id in sorted(retired - (held.revoked if held else set())):
            items.add(credential, "security.credential.revoked_key", key_id,
                      f"{said} lists {key_id} {listed[key_id]['state']}.")
        for _path, rotation in sorted((held.rotations if held else {}).items()):
            old = rotation.revokes_key
            if not old:
                continue
            gone = old not in listed or old in retired
            fresh = [k for k in active if k["key_id"] != old and k.get("created_at")
                     and (rotation.window_start is None
                          or k["created_at"] > rotation.window_start)]
            ref = _ref(rotation.bound)
            if gone and fresh and rotation.verification != "verified":
                items.add(rotation.bound, "security.work.verification", "verified",
                          f"{said}: {old} is {'gone' if old not in listed else 'retired'} and "
                          f"{fresh[0]['key_id']} was issued {fresh[0]['created_at']} (rotation "
                          f"{ref}).",
                          revises=rotation.verification_claim if rotation.verification else None)
                summary["verified"] += 1
            elif (not gone and rotation.progress == "completed"
                  and rotation.verification != "failed"):
                items.add(rotation.bound, "security.work.verification", "failed",
                          f"{said}: rotation {ref} is claimed completed, but {old} is still "
                          f"{listed[old]['state']}.",
                          revises=rotation.verification_claim if rotation.verification else None)
                summary["failed"] += 1
    return {**summary, "added": items.counts["added"], "revised": items.counts["revised"],
            "items": items.output(), "inbox": [], "posted": 0, "changed": len(items.claims)}


def classify_credential(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not isinstance(payload.get("state_text"), str) or not isinstance(payload.get("held"),
                                                                        list):
        return None
    return {"state": "present"}


class CredentialState:
    """The ``security.credential-state`` implementation."""

    interface_id = "security.credential-state"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            _refuse_truncated(context.input.get("truncated"), ("held",))
            result = credential_state(str(context.input.get("state_text") or ""),
                                      parse_rows(context.input.get("held")))
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        return ProviderResult.ok(result, metrics={"items": float(len(result["items"])),
                                                  "posted": float(result["posted"])})


# --- respond: the five questions ------------------------------------------------------

RESPOND_TAPS = ("exposure", "patches", "overdue", "exceptions", "audits", "credentials")


@dataclass
class Params:
    incident: str = ""
    inventory_pull: str = "security.inventory-acquire"
    log_pull: str = "security.log-acquire"
    credential_pull: str = "security.credential-acquire"
    record_pull: str = "security.cve-record-acquire"


def _params(value: object) -> Params:
    defaults = Params()
    if not isinstance(value, Mapping):
        return defaults
    return Params(**{name: str(value.get(name) or getattr(defaults, name))
                     for name in ("incident", "inventory_pull", "log_pull", "credential_pull",
                                  "record_pull")})


@dataclass
class Asset:
    bound: Bound
    hostname: str
    internet_exposed: bool = False
    current: bool = False
    looked_for: set[str] = field(default_factory=set)
    services: dict[str, str] = field(default_factory=dict)

    def covers(self, product: str) -> bool:
        return self.current and ("*" in self.looked_for or name_form(product) in self.looked_for)


@dataclass
class Release:
    bound: Bound
    label: str
    product: str
    status: str
    cves: set[str] = field(default_factory=set)
    assessments: set[str] = field(default_factory=set)


@dataclass
class Patch:
    bound: Bound
    asset: str
    release: str
    progress: str | None
    verification: str | None
    due_at: str | None


@dataclass
class Audit:
    bound: Bound
    service: str
    sources: set[str] = field(default_factory=set)
    reads: set[str] = field(default_factory=set)
    window_end: str | None = None
    result: tuple[str, Any] = ("absent", None)


@dataclass
class Credential:
    bound: Bound
    label: str
    key_id: str | None = None
    issued_at: str | None = None
    services: set[str] = field(default_factory=set)
    rotations: dict[str, dict[str, Any]] = field(default_factory=dict)


def _service_sources(found: dict[str, set[str]], row: Row) -> None:
    """The service's standing log sources (``service.log_source``) a tap row carries."""

    service = row.subject("service")
    if service is not None:
        found.setdefault(service.path, set()).update(
            str(v).strip() for v in _list(row.value("service_log_source")) if str(v).strip())


def _merge(asset: Asset, row: Row, prefix: str, binding: str) -> None:
    if row.value(f"{prefix}coverage_revision") is not None:
        asset.current = True
        asset.looked_for.update(name_form(v) for v in _list(row.value(f"{prefix}looked_for")))
    service = row.subject(binding)
    if service is not None:
        asset.services[service.path] = str(row.value("service_name") or _ref(service))


def uncovered(reads: Iterable[str], source: str, start: str, end: str) -> list[list[str]]:
    """The parts of [start, end] that no complete read of ``source`` covers."""

    spans = []
    for read in reads:
        name, _, interval = read.partition(" ")
        begin, _, finish = interval.partition("/")
        if name == source and _DATETIME.fullmatch(begin) and _DATETIME.fullmatch(finish):
            spans.append((begin, finish))
    gaps: list[list[str]] = []
    cursor = start
    for begin, finish in sorted(spans):
        if finish < cursor:
            continue
        if begin > cursor:
            gaps.append([cursor, min(begin, end)])
        cursor = max(cursor, finish)
        if cursor >= end:
            break
    if cursor < end:
        gaps.append([cursor, end])
    return [gap for gap in gaps if gap[0] < gap[1]]


class _Answers:
    def __init__(self, params: Params) -> None:
        self.params = params
        self.answers: list[dict[str, Any]] = []
        self.posts: list[dict[str, Any]] = []
        self.gaps: dict[str, dict[str, Any]] = {}

    def answer(self, question: str, subject: str, state: str, why: str,
               post: dict[str, Any] | None = None) -> None:
        self.answers.append({"question": question, "subject": subject, "state": state,
                             "why": why})
        if post is not None:
            self.posts.append({"question": question, "incident": self.params.incident, **post})

    def unknown(self, question: str, subject: str, why: str, pull: str,
                payload: dict[str, Any], *, about: str | None = None) -> None:
        """An unknown answer and its gap: one item per (what it is about, pull, input)
        however many questions wait on it."""

        gap = {"kind": "gap", "incident": self.params.incident, "subject": about or subject,
               "pull": pull, "input": payload}
        key = json.dumps(gap, sort_keys=True)
        self.gaps.setdefault(key, gap)
        self.answers.append({"question": question, "subject": subject, "state": "unknown",
                             "why": why, "pull": pull})

    def states(self, question: str, subject: str | None = None) -> set[str]:
        return {a["state"] for a in self.answers if a["question"] == question
                and (subject is None or a["subject"] == subject)}


def respond(payload: Mapping[str, Any]) -> dict[str, Any]:
    _refuse_truncated(payload.get("truncated"), RESPOND_TAPS)
    rows = {name: parse_rows(payload.get(name)) for name in RESPOND_TAPS}
    params = _params(payload.get("params"))
    out = _Answers(params)
    first = next((row for name in RESPOND_TAPS for row in rows[name]
                  if row.subject("incident") is not None), None)
    status = str(first.value("incident_status") or "open") if first else "open"
    window_start = first.value("window_start") if first else None
    policy = str(first.value("rotation_policy") or "on_found_or_unknown") if first else (
        "on_found_or_unknown")
    base = {"incident": params.incident, "status": status}
    if status == "closed" or first is None:
        return {**base, "items": [], "answers": [], "posted": 0, "found": 0, "none": 0,
                "unknown": 0, "ready_to_close": 0}

    # RQ1 inputs: releases, assets running them, assets declaring them.
    releases: dict[str, Release] = {}
    running: dict[str, Asset] = {}
    runs: set[tuple[str, str]] = set()  # (asset path, release path)
    declared: dict[str, tuple[Asset, set[str]]] = {}
    service_sources: dict[str, set[str]] = {}
    for name in ("exposure", "patches", "audits"):
        for row in rows[name]:
            _service_sources(service_sources, row)
    for row in rows["exposure"]:
        release, assessment = row.subject("release"), row.subject("assessment")
        if release is None or assessment is None:
            continue
        held = releases.setdefault(release.path, Release(
            bound=release, label=f"{row.value('product_name')} {row.value('version')}",
            product=str(row.value("product_name") or ""), status="affected"))
        if row.value("status") == "inconclusive" and held.status != "affected":
            held.status = "inconclusive"
        elif row.value("status") == "affected":
            held.status = "affected"
        if isinstance(row.value("cve_id"), str):
            held.cves.add(row.value("cve_id"))
        held.assessments.add(_ref(assessment))
        asset = row.subject("asset")
        if asset is not None:
            entry = running.setdefault(asset.path, Asset(
                bound=asset, hostname=str(row.value("hostname") or _ref(asset)),
                internet_exposed=row.value("internet_exposed") is True))
            _merge(entry, row, "", "service")
            runs.add((asset.path, release.path))
        other = row.subject("declared")
        if other is not None:
            entry, names = declared.setdefault(other.path, (Asset(
                bound=other, hostname=str(row.value("declared_hostname") or _ref(other))),
                set()))
            if row.value("declared_coverage_revision") is not None:
                entry.current = True
                entry.looked_for.update(name_form(v) for v in _list(
                    row.value("declared_looked_for")))
            names.add(release.path)
    # RQ2 inputs: every patch of the incident, with its asset; the overdue ones.
    patches: dict[str, Patch] = {}
    patched: dict[str, Asset] = {}
    patch_release: dict[str, Release] = {}
    for row in rows["patches"]:
        patch, asset, release = row.subject("patch"), row.subject("asset"), row.subject(
            "release")
        if patch is None or asset is None or release is None:
            continue
        patches.setdefault(patch.path, Patch(
            bound=patch, asset=asset.path, release=release.path, progress=row.value("progress"),
            verification=row.value("verification"), due_at=row.value("due_at")))
        entry = patched.setdefault(asset.path, Asset(
            bound=asset, hostname=str(row.value("hostname") or _ref(asset)),
            internet_exposed=row.value("internet_exposed") is True))
        _merge(entry, row, "", "service")
        held = patch_release.setdefault(release.path, Release(
            bound=release, label=f"{row.value('product_name')} {row.value('version')}",
            product=str(row.value("product_name") or ""), status="affected"))
        if isinstance(row.value("cve_id"), str):
            held.cves.add(row.value("cve_id"))
    overdue = {row.subject("patch").path for row in rows["overdue"]  # type: ignore[union-attr]
               if row.subject("patch") is not None}
    for path, release in patch_release.items():
        releases.setdefault(path, release)
    # RQ2's accepted risks: (asset, release) -> CVE -> the latest expiry of an active
    # exception for it (the tap holds only approved, unexpired ones).
    excepted: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows["exceptions"]:
        asset, release, cve = row.subject("asset"), row.subject("release"), row.value("cve_id")
        expires = row.value("expires_at")
        if asset is None or release is None or not isinstance(cve, str) or not isinstance(
                expires, str):
            continue
        held_until = excepted.setdefault((asset.path, release.path), {})
        held_until[cve] = max(held_until.get(cve, expires), expires)

    def excepted_until(key: tuple[str, str]) -> str | None:
        """The expiry until which every incident CVE of the exposure is excepted, if any."""

        held_until = excepted.get(key, {})
        cves = releases[key[1]].cves
        if not cves or not cves <= set(held_until):
            return None
        return min(held_until[cve] for cve in cves)

    # RQ1.
    for asset_path, release_path in sorted(runs):
        asset, release = running[asset_path], releases[release_path]
        subject = f"{asset.hostname}: {release.label}"
        if release.status == "affected":
            out.answer("RQ1", subject, "found", "runs an affected release", {
                "kind": "exposed", "asset": asset.hostname, "release": release.label,
                "cves": sorted(release.cves), "internet_exposed": asset.internet_exposed})
        else:
            out.unknown("RQ1", subject, "the release's assessment is inconclusive", "statement",
                        {"state": "security.assessment.status",
                         "assessments": sorted(release.assessments)}, about=release.label)
    seen = {asset for asset, _ in runs}
    for path, (asset, names) in sorted(declared.items()):
        if path in seen:
            continue
        for release_path in sorted(names):
            release = releases[release_path]
            subject = f"{asset.hostname}: {release.label}"
            if asset.covers(release.product):
                out.answer("RQ1", subject, "none", "declared, but a current full scan shows it "
                           "not running")
            else:
                out.unknown("RQ1", subject, "declared, under no current inventory coverage",
                            params.inventory_pull, {"covering": asset.hostname},
                            about=asset.hostname)
    for patch in sorted(patches.values(), key=lambda p: p.bound.path):
        if (patch.asset, patch.release) in runs or patch.asset in declared:
            continue
        asset, release = patched[patch.asset], releases[patch.release]
        subject = f"{asset.hostname}: {release.label}"
        if asset.covers(release.product):
            out.answer("RQ1", subject, "none", "a current full scan shows it not running")
        else:
            out.unknown("RQ1", subject, "no current inventory coverage", params.inventory_pull,
                        {"covering": asset.hostname}, about=asset.hostname)

    # RQ2.
    by_exposure: dict[tuple[str, str], list[Patch]] = {}
    for patch in patches.values():
        by_exposure.setdefault((patch.asset, patch.release), []).append(patch)
    exposures = {key for key in runs if releases[key[1]].status == "affected"}
    for key in sorted(exposures | set(by_exposure)):
        asset = running.get(key[0]) or patched[key[0]]
        release = releases[key[1]]
        subject = f"{asset.hostname}: {release.label}"
        exposed = key in exposures
        found = {"asset": asset.hostname, "release": release.label,
                 "internet_exposed": asset.internet_exposed}
        candidates = sorted(by_exposure.get(key, ()), key=lambda p: p.bound.path)
        until = excepted_until(key) if exposed else None
        if not candidates:
            if until is not None:
                out.answer("RQ2", subject, "excepted", f"no patch; a risk exception holds "
                           f"until {until}")
                continue
            out.answer("RQ2", subject, "found", "no patch", {
                "kind": "patch_missing", **found, "cves": sorted(release.cves)})
            continue
        patch = candidates[-1]
        ref = _ref(patch.bound)
        if patch.verification == "failed":
            out.answer("RQ2", subject, "found", "a scan disagrees with the claim", {
                "kind": "patch_disputed", **found, "patch": ref, "why": "verification_failed"})
        elif exposed and patch.verification == "verified":
            out.answer("RQ2", subject, "found", "running again after it was verified", {
                "kind": "patch_regressed", **found, "patch": ref})
        elif exposed and patch.bound.path in overdue and until is not None:
            out.answer("RQ2", subject, "excepted", f"past due; a risk exception holds until "
                       f"{until}")
        elif exposed and patch.bound.path in overdue:
            out.answer("RQ2", subject, "found", "past due", {
                "kind": "patch_overdue", **found, "patch": ref, "due_at": patch.due_at})
        elif exposed and patch.progress == "completed":
            out.unknown("RQ2", subject, "claimed completed; no scan has read it since",
                        params.inventory_pull, {"covering": asset.hostname},
                        about=asset.hostname)
        elif exposed:
            out.answer("RQ2", subject, "pending", "approved, on schedule")
        elif patch.verification == "verified" and asset.covers(release.product):
            out.answer("RQ2", subject, "none", "a full scan verified it")
        elif patch.verification == "verified":
            out.unknown("RQ2", subject, "verified, but the coverage is no longer current",
                        params.inventory_pull, {"covering": asset.hostname},
                        about=asset.hostname)
        else:
            out.unknown("RQ2", subject, "no scan has verified it", params.inventory_pull,
                        {"covering": asset.hostname}, about=asset.hostname)

    # RQ3: every service of an exposed or patched asset, and every audited one.
    services: dict[str, str] = {}
    exposed_services: set[str] = set()
    for asset_path, release_path in exposures:
        exposed_services.update(running[asset_path].services)
    services.update({path: name for asset_path, _ in exposures
                     for path, name in running[asset_path].services.items()})
    for patch in patches.values():
        services.update(patched[patch.asset].services)
        exposed_services.update(patched[patch.asset].services)
    audits: dict[str, Audit] = {}
    for row in rows["audits"]:
        audit, service = row.subject("audit"), row.subject("service")
        if audit is None:
            continue
        name = str(row.value("service_name") or row.value("service_ref") or _ref(audit))
        entry = audits.setdefault(audit.path, Audit(
            bound=audit, service=service.path if service else f"ref:{name}"))
        services.setdefault(entry.service, name)
        entry.sources.update(str(v).strip() for v in _list(row.value("log_source")))
        entry.reads.update(str(v).strip() for v in _list(row.value("read")))
        entry.window_end = row.value("window_end") or entry.window_end
        entry.result = (row.state("result"), row.value("result"))
    by_service = {audit.service: audit for audit in audits.values()}
    rq3: dict[str, str] = {}
    for path, name in sorted(services.items(), key=lambda item: item[1]):
        audit = by_service.get(path)
        statement = {"audit": {"incident": params.incident, "service": name}}
        listed = sorted(service_sources.get(path, ()))
        if audit is None:
            # The audit starts from the service's standing list: the gap names it.
            out.unknown("RQ3", name, "no audit stated", "statement",
                        {"state": "security.audit.log_source", **statement,
                         **({"sources": listed} if listed else {})})
            rq3[path] = "unknown"
            continue
        unstated = sorted(set(listed) - audit.sources)
        state, result = audit.result
        if state == "conflict":
            out.unknown("RQ3", name, "contended result", "statement",
                        {"state": "security.audit.result", "resolve": "conflict", **statement})
        elif result == "exploited":
            out.answer("RQ3", name, "found", "the auditor found exploitation", {
                "kind": "exploited", "service": name, "audit": _ref(audit.bound)})
        elif not audit.sources and not unstated:
            out.unknown("RQ3", name, "no log source stated", "statement",
                        {"state": "security.audit.log_source", **statement})
        elif unstated:
            out.unknown("RQ3", name, f"the service lists {', '.join(unstated)}; the audit does "
                        "not state it", "statement",
                        {"state": "security.audit.log_source", **statement,
                         "sources": unstated})
        elif audit.window_end is None:
            out.unknown("RQ3", name, "the window is open (no window_end)", "statement",
                        {"state": "security.audit.window_end", **statement})
        elif result is None:
            out.unknown("RQ3", name, "no result", "statement",
                        {"state": "security.audit.result", **statement})
        elif result == "inconclusive":
            out.unknown("RQ3", name, "the auditor's result is inconclusive", params.log_pull,
                        {**statement, "sources": sorted(audit.sources)})
        elif not isinstance(window_start, str):
            out.unknown("RQ3", name, "the incident states no window_start", "statement",
                        {"state": "security.incident.window_start",
                         "incident": params.incident})
        else:
            missing = {source: uncovered(audit.reads, source, window_start, audit.window_end)
                       for source in sorted(audit.sources)}
            missing = {source: gaps for source, gaps in missing.items() if gaps}
            if not missing:
                out.answer("RQ3", name, "none", "not_exploited, every source read in full "
                           "over the window")
            for source, gaps in missing.items():
                out.unknown("RQ3", name, f"{source} is not read in full: uncovered {gaps}",
                            params.log_pull, {**statement, "source": source,
                                              "from": gaps[0][0], "to": gaps[-1][1]})
        rq3[path] = next(iter(sorted(out.states("RQ3", name) & {"found", "unknown"})), "none")

    # RQ4: the credentials of every warranted service.
    warranted = ({path for path, state in rq3.items() if state in ("found", "unknown")}
                 if policy != "all_exposed" else set(exposed_services) | set(
                     path for path, state in rq3.items() if state == "found"))
    credentials: dict[str, Credential] = {}
    incident_audits = {audit.bound.path for audit in audits.values()}
    for row in rows["credentials"]:
        credential, service = row.subject("credential"), row.subject("service")
        if credential is None or service is None:
            continue
        entry = credentials.setdefault(credential.path, Credential(
            bound=credential, label=f"{row.value('issuer')}/{row.value('name')}",
            key_id=row.value("key_id"), issued_at=row.value("issued_at")))
        entry.services.add(service.path)
        rotation, audit = row.subject("rotation"), row.subject("rotation_audit")
        if rotation is not None and audit is not None and audit.path in incident_audits:
            entry.rotations.setdefault(rotation.path, {
                "ref": _ref(rotation), "progress": row.value("progress"),
                "verification": row.value("verification"),
                "revokes_key": row.value("revokes_key")})
    patch_state = {}
    for path in services:
        states = set()
        for patch in patches.values():
            if path in patched[patch.asset].services:
                states |= out.states("RQ2", f"{patched[patch.asset].hostname}: "
                                            f"{releases[patch.release].label}")
        for asset_path, release_path in exposures:
            if path in running[asset_path].services and not by_exposure.get(
                    (asset_path, release_path)):
                states.add("found")
        patch_state[path] = ("open" if states & {"found", "unknown", "pending", "excepted"}
                             else "verified" if states else "none_recorded")
    for path, credential in sorted(credentials.items(), key=lambda item: item[1].label):
        why = sorted(credential.services & warranted)
        if not why:
            out.answer("RQ4", credential.label, "none", "no service it is used by warrants "
                       "rotation")
            continue
        state = {services.get(s, s): {"audit": rq3.get(s, "unknown"),
                                      "patch": patch_state.get(s, "none_recorded")}
                 for s in why}
        rotations = sorted(credential.rotations.values(), key=lambda r: r["ref"])
        if not rotations:
            out.answer("RQ4", credential.label, "found", "rotation warranted", {
                "kind": "rotate", "credential": credential.label, "services": state,
                "key_id": credential.key_id,
                "because": "a service using it has an audit that found exploitation or cannot "
                           "rule it out" if policy != "all_exposed"
                           else "the incident's policy rotates every exposed service's "
                                "credentials"})
            continue
        rotation = rotations[-1]
        if rotation["verification"] == "failed":
            out.answer("RQ4", credential.label, "found", "a state read disagrees", {
                "kind": "rotation_disputed", "credential": credential.label,
                "rotation": rotation["ref"], "revokes_key": rotation["revokes_key"]})
        elif rotation["verification"] == "verified" and isinstance(window_start, str) and (
                isinstance(credential.issued_at, str) and credential.issued_at > window_start):
            out.answer("RQ4", credential.label, "none", "rotated and verified by a state read")
        elif rotation["verification"] == "verified":
            out.unknown("RQ4", credential.label, "verified, but the current key's issued_at "
                        "is not after window_start", params.credential_pull,
                        {"read": "state_read", "credential": credential.label})
        elif rotation["progress"] == "completed":
            out.unknown("RQ4", credential.label, "claimed rotated; no separate state read yet",
                        params.credential_pull,
                        {"read": "state_read", "credential": credential.label})
        else:
            out.answer("RQ4", credential.label, "pending", "rotation approved, in progress")

    # RQ5.
    blocking = [a for a in out.answers if a["state"] in ("found", "unknown", "pending",
                                                         "excepted")
                and not (a["question"] == "RQ3" and a["state"] in ("found", "unknown"))]
    if not blocking and out.answers:
        residue = sorted({a["subject"] for a in out.answers
                          if a["question"] == "RQ3" and a["state"] == "unknown"})
        exploited = sorted({a["subject"] for a in out.answers
                            if a["question"] == "RQ3" and a["state"] == "found"})
        out.answer("RQ5", params.incident, "found", "every exposure patched and verified, "
                   "every warranted rotation verified", {
                       "kind": "ready_to_close", "residue": [
                           {"service": name, "audit": "unknown"} for name in residue],
                       "exploited": exploited,
                       "rotations": sorted(a["subject"] for a in out.answers
                                           if a["question"] == "RQ4" and a["state"] == "none")})
    items = sorted_items(out.posts) + sorted_items(out.gaps.values())
    counts = {state: sum(1 for a in out.answers if a["state"] == state)
              for state in ("found", "none", "unknown")}
    return {**base, "items": items[:MAX_POSTS], "posted": min(len(items), MAX_POSTS),
            "answers": sorted(out.answers, key=lambda a: (a["question"], a["subject"],
                                                          a["state"])),
            "ready_to_close": int(any(a["question"] == "RQ5" for a in out.answers)),
            **counts}


def classify_respond(payload: Mapping[str, Any]) -> Mapping[str, str] | None:
    if not all(isinstance(payload.get(name), list) for name in RESPOND_TAPS):
        return None
    rows = sum(len(payload[name]) for name in RESPOND_TAPS)
    return {"rows": "small" if rows <= 5000 else "large"}


class Respond:
    """The ``security.respond`` implementation: posted findings and gaps, never Claims."""

    interface_id = "security.respond"

    def __call__(self, context: ProviderRunContext) -> ProviderResult:
        try:
            result = respond(context.input)
        except InputError as error:
            return ProviderResult.refused(RefusalCode.PROVIDER_DECLINED, str(error))
        return ProviderResult.ok(result, metrics={"posted": float(result["posted"])})
