"""Render the security kit's generated reference from its own definitions.

    python source/reference.py [KIT_DIR]           # rewrite the README sections and reference.md
    python source/reference.py [KIT_DIR] --check   # fail if either differs from the definitions

The reference is read from the release bundle (``cruxible-kit.json`` and
``artifacts/``, through ``cruxible_client.kits.read_kit_directory``) and the
example automation ChangeSet (``examples/automation.json``), never from an
instance. ``reference.md`` holds all of it (counts, Providers, two diagrams, every
kind, field, contract, Line, Procedure and query); ``README.md`` holds only a short
counts table between ``<!-- BEGIN GENERATED: glance -->`` and ``<!-- END
GENERATED: glance -->``, and the hand-written text outside it is kept. ``check``
also reads the README's hand-written concept map (the Mermaid block after
``CONCEPT_MAP``) and refuses one that names a kind or a field the kit does not
define, and the generator's small hand maps (a label per logical source, the logical
source an interface's Provider names, the Procedures the Lines you author per incident or
per source run) where they
disagree with the definitions. Output is byte-stable: everything is sorted and nothing depends on the
clock or the machine.

``build_release.py`` runs this after copying a release; ``scripts/kits.py check``
runs ``check`` for every kit that has a ``source/reference.py``.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cruxible_client.kits import read_kit_directory
from cruxible_client.contracts.procedures.artifacts import parse_procedure
from cruxible_client.contracts.query.definitions import parse_query_definition

KIT = Path(__file__).resolve().parents[1]
README = "README.md"
REFERENCE = "reference.md"
EXAMPLE = Path("examples") / "automation.json"
# The README carries only the short counts table; reference.md carries everything.
SECTIONS = ("glance",)
# The README's hand-written concept map follows this marker; ``check`` refuses a map that
# names a kind or a field the kit does not define.
CONCEPT_MAP = "<!-- concept-map: checked by source/reference.py -->"
SELF_SOURCE = "playbill.coordinator-self-source-v1"
# Every kit QueryDefinition description ends with the same scope sentence; it is
# stated once above the table instead of in every row.
QUERY_SCOPE = "Scoped to supported, current Claims; missing evidence is not a negative finding."
_MICROS_PER_HOUR = 3_600_000_000
# Procedures a Line you author per incident (declared with it, walkthroughs.md) or per
# source (intake.md's recipe) runs, not an example Line: the source node that Line feeds
# from its landing (None: it has none), what each such Line is for, and the page that
# authors it. ``check`` refuses an entry that is not a Procedure, names no source node, or
# an example Line runs.
PER_LINE: dict[str, tuple[str | None, str, str]] = {
    "security.log-import": ("log", "incident", "walkthroughs.md"),
    "security.respond": (None, "incident", "walkthroughs.md"),
    "security.repo-acquire": (None, "repository", "intake.md#add-a-repository"),
    "security.repo-parse": ("snapshot", "repository", "intake.md#add-a-repository"),
    "security.sarif-import": ("sarif", "scanned repository", "intake.md#its-scans"),
    "security.sarif-attention": ("sarif", "scanned repository", "intake.md#its-scans"),
    "security.registry-acquire": (None, "PyPI project", "intake.md#add-a-pypi-project"),
    "security.registry-parse": ("registry", "PyPI project", "intake.md#add-a-pypi-project"),
}


def _per_line_text(definition: str) -> str:
    """Where a per-incident or per-source Line comes from, as a table cell."""

    _alias, owner, page = PER_LINE[definition]
    return f"a Line per {owner} ([{page.partition('.')[0]}]({page}))"


def _per_line_who(definition: str) -> str:
    """Who runs a per-incident or per-source Procedure, in a sentence."""

    owner = PER_LINE[definition][1]
    return f"each {owner}'s `{definition}` Line"
# What a reader calls each logical source (the name a Capture is retained under, which a
# landing Trigger selects). ``check`` refuses a logical source the definitions or the example
# name that is missing here, and an entry nothing names.
SOURCE_LABELS = {
    "cisa.kev.catalog": "CISA KEV catalog",
    "cve.record": "CVE record",
    "cyclonedx.sbom": "CycloneDX SBOM",
    "first.epss.daily": "FIRST EPSS daily scores file",
    "github.api": "GitHub API response",
    "github.release": "GitHub release record",
    "github.release.asset": "GitHub release asset",
    "github.repo.snapshot": "GitHub repository snapshot",
    "osv.dev.ecosystems": "OSV ecosystem list",
    "osv.dev.query": "OSV query answer",
    "pypi.release": "PyPI release read",
    "sarif.log": "SARIF scan log",
    "security.analysis.evidence": "workspace evidence file",
    "security.credential-state": "credential key-state read",
    "security.inventory": "runtime-inventory scan",
    "security.log-read": "log read",
    "security.reproduction": "proof-of-concept run report",
}
# Provider interfaces whose Provider names the logical source itself (the source node's
# request carries none). ``check`` refuses a source node it cannot place, and an entry no
# such node uses.
INTERFACE_SOURCES = {
    "security.epss-daily": "first.epss.daily",
    "security.osv-ecosystems": "osv.dev.ecosystems",
    "security.osv-query": "osv.dev.query",
    "security.pypi-release": "pypi.release",
    "security.release-asset": "github.release.asset",
    "security.repo-snapshot": "github.repo.snapshot",
}
_CRON = re.compile(r"([0-9]{1,2}) ([0-9]{1,2}|\*/[0-9]{1,2}) \* \* \*")

Json = dict[str, Any]


# --- the definitions, read once into small typed records ---------------------------------


@dataclass(frozen=True)
class ClaimTypeDoc:
    predicate: str
    description: str
    kinds: tuple[str, ...]
    value: str
    cardinality: str
    roles: tuple[str, ...]
    default_role: str
    contracts: tuple[str, ...]
    source_uses: tuple[tuple[str, tuple[str, ...]], ...]
    requirement: str
    freshness: str
    contention: str
    members: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class KindDoc:
    name: str
    description: str
    keys: str


@dataclass(frozen=True)
class SourceNode:
    """A source or emit node of a Procedure: where a Capture is made."""

    definition: str
    definition_kind: str  # "Procedure"
    alias: str | None
    contract: str
    interface: str | None
    provider: str | None
    emitted: bool  # an emit_capture terminal: the run's own output, retained
    logical_source: str | None  # the request's, literal or an ``$input.`` reference


@dataclass(frozen=True)
class DefinitionDoc:
    name: str
    kind: str  # "Procedure"
    summary: str
    node_kinds: frozenset[str]
    pinned: bool  # a node names its Provider instead of binding one by fit


@dataclass(frozen=True)
class ContractDoc:
    name: str
    shape: str
    replay: str
    grade: str


@dataclass(frozen=True)
class QueryDoc:
    name: str
    question: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class LineDoc:
    name: str
    procedure: str
    max_authority: str
    trigger_input: str | None
    parameters: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TriggerDoc:
    name: str
    line: str
    cron: str | None
    landing: str | None
    logical_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class MandateDoc:
    name: str
    procedure: str
    grants: str
    namespace: tuple[str, ...]


@dataclass(frozen=True)
class ProviderDoc:
    package: str
    version: str
    delivery: str
    interfaces: tuple[str, ...]


@dataclass
class KitDocs:
    kit_id: str
    version: str
    owns: tuple[str, ...]
    providers: list[ProviderDoc]
    kinds: dict[str, KindDoc]
    claim_types: dict[str, ClaimTypeDoc]
    contracts: dict[str, ContractDoc]
    definitions: dict[str, DefinitionDoc]
    source_nodes: list[SourceNode]
    queries: dict[str, QueryDoc]
    interfaces: set[str]
    policies: set[str]
    lines: dict[str, LineDoc] = field(default_factory=dict)
    triggers: dict[str, TriggerDoc] = field(default_factory=dict)
    mandates: dict[str, MandateDoc] = field(default_factory=dict)
    example_policies: dict[str, str] = field(default_factory=dict)


def _hours(duration: Mapping[str, Any]) -> str:
    micros = int(duration["microseconds"])
    if micros % _MICROS_PER_HOUR == 0:
        hours = micros // _MICROS_PER_HOUR
        return f"{hours // 24} d" if hours % 24 == 0 and hours >= 48 else f"{hours} h"
    return f"{micros / 1_000_000:g} s"


def _value(raw: Json) -> str:
    if raw["object_kind"] == "subject":
        targets = ", ".join(f"`{kind}`" for kind in sorted(raw["allowed_object_subject_kinds"]))
        return f"Subject: {targets}" if targets else "Subject"
    schema = raw["literal_schema"] or {}
    if "enum" in schema and raw["member_descriptions"]:
        return f"one of {len(schema['enum'])} (below)"
    if "enum" in schema:
        return " / ".join(f"`{member}`" for member in schema["enum"])
    if "format" in schema:
        return str(schema["format"])
    if "pattern" in schema:
        return f"text `{schema['pattern']}`"
    return {"boolean": "true / false", "string": "text"}.get(str(schema.get("type")), "literal")


def _contention(raw: Json) -> str:
    policy = raw["resolution_policy"]
    if policy["selector"] == "all":
        return "all held"
    return str(policy["conflict_result"])


def _claim_type(raw: Json) -> ClaimTypeDoc:
    contracts = sorted(
        {
            contract["target"]["name"]
            for rule in raw["evidence_admission_policy"]["rules"]
            for contract in rule["capture_contracts"]
        }
    )
    freshness = raw["evidence_freshness"]
    return ClaimTypeDoc(
        predicate=raw["predicate"],
        description=raw["description"],
        kinds=tuple(sorted(raw["allowed_subject_kinds"])),
        value=_value(raw),
        cardinality=raw["cardinality"],
        roles=tuple(sorted(raw["permitted_roles"])),
        default_role=raw["default_role"],
        contracts=tuple(contracts),
        source_uses=tuple(sorted({(use["target"]["name"], tuple(use.get("logical_sources", ())))
                                 for rule in raw["evidence_admission_policy"]["rules"]
                                 for use in rule["capture_contracts"]})),
        requirement=raw["evidence_requirement"],
        freshness=f"stale after {_hours(freshness['stale_after'])}" if freshness else "",
        contention=_contention(raw),
        members=tuple((item["member"], item["description"]) for item in raw["member_descriptions"]),
    )


def _kind(raw: Json) -> KindDoc:
    rule = raw["identity_rule"]
    if rule["rule"] == "keys":
        name = raw["identity"]["name"]
        keys = " + ".join(f"`{key.removeprefix(name + '.')}`" for key in rule["keys"])
        keys += f" (uniqueness `{rule['uniqueness']}`)"
    else:
        keys = "minted id"
    return KindDoc(name=raw["identity"]["name"], description=raw["description"], keys=keys)


def _first_sentence(text: str) -> str:
    match = re.search(r"(?<=[a-z0-9)`])\.\s+(?=[A-Z])", text)
    return text[: match.start() + 1] if match else text


_TERMINALS = (
    ("propose_change_set", "proposes a ChangeSet"),
    ("settle_change_set", "settles a ChangeSet"),
    ("post_inbox", "posts inbox items"),
)


def _definition(raw: Json, kind: str) -> tuple[DefinitionDoc, list[SourceNode]]:
    definition = raw["definition"]
    name = definition["name"]
    node_kinds = frozenset(node["kind"] for node in definition["nodes"])
    nodes = []
    for node in definition["nodes"]:
        if node["kind"] not in {"source", "emit_capture"}:
            continue
        provider = node.get("provider") or {}
        interface = node.get("interface") or {}
        nodes.append(
            SourceNode(
                definition=name,
                definition_kind=kind,
                alias=node.get("as"),
                contract=node["capture_contract"]["target"]["name"],
                interface=interface.get("target", {}).get("name", "").split("/")[0] or None,
                provider=provider.get("target", {}).get("name", "").split("/")[0] or None,
                emitted=node["kind"] == "emit_capture",
                logical_source=(
                    source
                    if isinstance(source := (node.get("request") or {}).get("logical_source"), str)
                    else None
                ),
            )
        )
    summary = _first_sentence(definition["description"])
    pinned = any((node.get("provider") or {}).get("target") for node in definition["nodes"])
    doc = DefinitionDoc(
        name=name, kind=kind, summary=summary, node_kinds=node_kinds, pinned=pinned
    )
    return doc, nodes


def _query(raw: Json) -> QueryDoc:
    question = raw["description"].removesuffix(QUERY_SCOPE).strip()
    parameters = tuple(
        f"`{item['name']}` ({item['value_type'].replace('_', ' ')}"
        + (")" if item["required"] else ", optional)")
        for item in raw["parameters"]
    )
    return QueryDoc(name=raw["identity"]["name"], question=question, parameters=parameters)


def load(kit_dir: Path) -> KitDocs:
    """Read the bundle's definitions and the example ChangeSet."""

    bundle = read_kit_directory(kit_dir)
    manifest = bundle.manifest
    docs = KitDocs(
        kit_id=manifest.kit_id,
        version=manifest.version,
        owns=tuple(manifest.owns),
        providers=sorted(
            (
                ProviderDoc(
                    package=item.package,
                    version=item.version,
                    delivery=item.delivery,
                    interfaces=tuple(sorted(item.interfaces)),
                )
                for item in manifest.providers
            ),
            key=lambda item: item.package,
        ),
        kinds={},
        claim_types={},
        contracts={},
        definitions={},
        source_nodes=[],
        queries={},
        interfaces=set(),
        policies=set(),
    )
    for artifact in bundle.artifacts:
        raw = json.loads(artifact.content)
        top = artifact.path.split("/")[0]
        if top in {"procedures", "query-definitions"}:
            parse = {"procedures": parse_procedure,
                     "query-definitions": parse_query_definition}[top]
            raw = parse(artifact.content, path=artifact.path).model_dump(mode="json", by_alias=True)
        if top == "subject-kinds":
            kind = _kind(raw)
            docs.kinds[kind.name] = kind
        elif top == "claim-types":
            claim_type = _claim_type(raw)
            docs.claim_types[claim_type.predicate] = claim_type
        elif top == "capture-contracts":
            docs.contracts[raw["identity"]["name"]] = ContractDoc(
                name=raw["identity"]["name"],
                shape=raw.get("shape", "http_response"),
                replay=raw.get("replay", "attested"),
                grade=raw["epistemic_grade"],
            )
        elif top == "procedures":
            definition, nodes = _definition(
                raw, "Procedure"
            )
            docs.definitions[definition.name] = definition
            docs.source_nodes.extend(nodes)
        elif top == "query-definitions":
            query = _query(raw)
            docs.queries[query.name] = query
        elif top == "provider-interfaces":
            docs.interfaces.add(raw.get("interface", raw)["interface_id"])
        elif top == "source-acquisition-policies":
            docs.policies.add(raw["identity"]["name"])
    example = kit_dir / EXAMPLE
    if example.is_file():
        _load_example(docs, json.loads(example.read_text()))
    docs.source_nodes.sort(key=lambda node: (node.contract, node.definition, node.alias or ""))
    return docs


def _load_example(docs: KitDocs, change_set: Json) -> None:
    for member in change_set["members"]:
        kind = member["kind"]
        if kind == "line":
            docs.lines[member["name"]] = LineDoc(
                name=member["name"],
                procedure=member["procedure_name"],
                max_authority=member["max_authority"],
                trigger_input=member.get("trigger_input"),
                parameters=member.get("parameters") or {},
            )
        elif kind == "trigger":
            schedule = member["schedule"]
            docs.triggers[member["name"]] = TriggerDoc(
                name=member["name"],
                line=member["line_name"],
                cron=schedule.get("expression") if schedule["kind"] == "cron" else None,
                landing=(
                    schedule["capture_contract"] if schedule["kind"] == "capture_landing" else None
                ),
                logical_sources=tuple(schedule.get("logical_sources") or ()),
            )
        elif kind == "acquisition_policy":
            policy = member["acquisition_policy"]
            docs.example_policies[policy["identity"]["name"]] = policy["max_age"]
        elif kind == "procedure_mandate":
            docs.mandates[member["name"]] = MandateDoc(
                name=member["name"],
                procedure=member["procedure_name"],
                grants=member["grants"],
                namespace=tuple(member["namespace"]),
            )


# --- derived relations ---------------------------------------------------------------------


def _definition_of(docs: KitDocs, procedure: str) -> str:
    """The Procedure a Line's Procedure name runs."""

    return procedure


def _reads_landing(docs: KitDocs, node: SourceNode) -> bool:
    """A source node a Line feeds from the Capture that started it: an example Line's, or
    the Line each incident or source declares."""

    if node.alias is None:
        return False
    if node.definition in PER_LINE:
        return PER_LINE[node.definition][0] == node.alias
    return any(
        _definition_of(docs, line.procedure) == node.definition and line.trigger_input == node.alias
        for line in docs.lines.values()
    )


def _effects(docs: KitDocs, definition: DefinitionDoc) -> tuple[str, ...]:
    """What a definition's run does: what it retains (a source node no Line feeds from its
    landing, or an emit node) and its terminals."""

    retained = []
    for node in docs.source_nodes:
        if node.definition != definition.name or _reads_landing(docs, node):
            continue
        source = _node_source(node, None)
        if node.emitted:
            text = "its run's output"
        elif source:
            text = _a(_label(source))
        else:
            text = "a Capture under the logical source it is given"
        if text not in retained:
            retained.append(text)
    effects = ["retains " + _and(retained)] if retained else []
    effects += [label for kind, label in _TERMINALS if kind in definition.node_kinds]
    return tuple(effects)


def _and(items: list[str], word: str = "and") -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + f" {word} " + items[-1]


def _producers(docs: KitDocs) -> dict[str, list[SourceNode]]:
    produced: dict[str, list[SourceNode]] = defaultdict(list)
    for node in docs.source_nodes:
        if not _reads_landing(docs, node):
            produced[node.contract].append(node)
    return produced


def _by_definition(nodes: Iterable[SourceNode]) -> list[tuple[str, list[SourceNode]]]:
    grouped: dict[str, list[SourceNode]] = defaultdict(list)
    for node in nodes:
        grouped[node.definition].append(node)
    return sorted(grouped.items())


def _landings(docs: KitDocs) -> dict[str, list[TriggerDoc]]:
    landed: dict[str, list[TriggerDoc]] = defaultdict(list)
    for trigger in sorted(docs.triggers.values(), key=lambda item: item.name):
        if trigger.landing:
            landed[trigger.landing].append(trigger)
    return landed


@dataclass(frozen=True)
class Retention:
    """One Capture a run retains: its contract and logical source, and who runs it."""

    contract: str
    source: str | None  # None: the logical source a direct run is given (or a run's output)
    definition: str
    line: str | None  # the example Line that runs it; None for a direct or per-incident/source run
    interface: str | None
    emitted: bool
    given: bool  # the request takes its logical source from the run's input


def _node_source(node: SourceNode, line: LineDoc | None) -> str | None:
    raw = node.logical_source
    if raw and raw.startswith("$input."):
        value = (line.parameters if line else {}).get(raw.removeprefix("$input."))
        return value if isinstance(value, str) else None
    if raw or node.emitted:
        return raw
    return INTERFACE_SOURCES.get(node.interface or "")


def _retentions(docs: KitDocs) -> list[Retention]:
    """Every Capture a run retains (a source node no Line feeds from its landing, or an emit)."""

    out = []
    for node in docs.source_nodes:
        lines = sorted(
            (line for line in docs.lines.values() if line.procedure == node.definition),
            key=lambda item: item.name,
        )
        runs: list[LineDoc | None] = list(lines) or [None]
        for line in runs:
            if line is None and _reads_landing(docs, node):
                continue
            if line is not None and line.trigger_input is not None and line.trigger_input == node.alias:
                continue
            out.append(
                Retention(
                    contract=node.contract,
                    source=_node_source(node, line),
                    definition=node.definition,
                    line=line.name if line else None,
                    interface=node.interface,
                    emitted=node.emitted,
                    given=(node.logical_source or "").startswith("$input."),
                )
            )
    return out


def _retained_by(
    retentions: Iterable[Retention], contract: str, source: str | None
) -> list[Retention]:
    """Who retains a logical source under a contract: the runs that name it, else the direct
    runs that are given their logical source."""

    candidates = [item for item in retentions if item.contract == contract and not item.emitted]
    named = [item for item in candidates if source is None or item.source == source]
    return named or [item for item in candidates if item.source is None]


def _who(retentions: Iterable[Retention]) -> str:
    retentions = list(retentions)
    lines = sorted({item.line for item in retentions if item.line})
    parts = []
    if lines:
        parts.append(("Line " if len(lines) == 1 else "Lines ") + " or ".join(f"`{n}`" for n in lines))
    direct = sorted(
        {(item.definition, item.interface) for item in retentions if item.line is None}
    )
    for definition, interface in direct:
        if definition in PER_LINE:
            parts.append(_per_line_who(definition))
        elif interface == "workspace.file":
            parts.append(f"a direct `{definition}` run on an agent's workspace file")
        else:
            parts.append(f"a direct `{definition}` run")
    return " or ".join(parts) or "nothing the kit runs"


def _label(source: str) -> str:
    return SOURCE_LABELS.get(source, f"`{source}`")


def _a(text: str) -> str:
    return ("an " if text[:1].lower() in "aeio" else "a ") + text


def _cron_words(expression: str) -> str | None:
    """A cron the reference can say in words (daily, or every N hours), else None."""

    match = _CRON.fullmatch(expression)
    if match is None:
        return None
    minute, hour = int(match[1]), match[2]
    if hour.startswith("*/"):
        return f"every {int(hour[2:])} hours at :{minute:02d} UTC"
    return f"daily at {int(hour):02d}:{minute:02d} UTC"


def _trigger_words(docs: KitDocs, trigger: TriggerDoc) -> str:
    """What starts a Line, in words: when, or which logical source landing and who retains it."""

    if trigger.cron:
        return _cron_words(trigger.cron) or f"on the cron `{trigger.cron}`"
    if trigger.landing is None:
        return "on its schedule"
    retentions = _retentions(docs)
    sources: tuple[str | None, ...] = trigger.logical_sources or (None,)
    what = " or ".join(
        _a(_label(source)) if source else f"a Capture under `{trigger.landing}`" for source in sources
    )
    who = _who(item for source in sources for item in _retained_by(retentions, trigger.landing, source))
    return f"when {what} lands, retained by {who}"


def _trigger_raw(trigger: TriggerDoc) -> str:
    if trigger.cron:
        return f"`{trigger.name}`: cron `{trigger.cron}`"
    return f"`{trigger.name}`: " + " ".join(
        f"`{item}`" for item in (trigger.landing or "", *trigger.logical_sources) if item
    )


def _evidenced(docs: KitDocs) -> dict[str, list[ClaimTypeDoc]]:
    by_contract: dict[str, list[ClaimTypeDoc]] = defaultdict(list)
    for claim_type in sorted(docs.claim_types.values(), key=lambda item: item.predicate):
        for contract in claim_type.contracts:
            by_contract[contract].append(claim_type)
    return by_contract


def _owned_contracts(docs: KitDocs) -> list[str]:
    """The kit's own Capture contracts (core's self-source is not one)."""

    return sorted(
        name for name in docs.contracts if any(name.startswith(prefix) for prefix in docs.owns)
    )


def _short(docs: KitDocs, name: str) -> str:
    for prefix in docs.owns:
        if name.startswith(prefix):
            return name.removeprefix(prefix)
    return name


def _node_id(prefix: str, name: str) -> str:
    return prefix + "_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _table(header: Iterable[str], rows: Iterable[Iterable[str]]) -> list[str]:
    header = list(header)
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(_cell(value) or "-" for value in row) + " |" for row in rows]
    return lines


def _code(names: Iterable[str]) -> str:
    return ", ".join(f"`{name}`" for name in names)


# --- sections --------------------------------------------------------------------------------


def _glance(docs: KitDocs) -> list[str]:
    shared = sum(1 for item in docs.claim_types.values() if len(item.kinds) > 1)
    owned = _owned_contracts(docs)
    core = sorted(name for name in docs.contracts if name not in owned)
    procedures = [d for d in docs.definitions.values() if d.kind == "Procedure"]
    pinned = sum(1 for d in procedures if d.pinned)
    if pinned:
        binding = f"{pinned} name their Provider; the rest bind theirs by fit"
    else:
        binding = (
            "each binds its Providers by fit (the installed Provider serving each "
            "interface), so none needs a binding"
        )
    policies = (
        _code(sorted(docs.policies))
        if docs.policies
        else "none in the kit; the example ChangeSet sets "
        + ", ".join(
            f"`{name}` (`max_age` {age})" for name, age in sorted(docs.example_policies.items())
        )
        if docs.example_policies
        else ""
    )
    counts = [
        ("Subject kinds", len(docs.kinds), "[What it models](#what-it-models)"),
        (
            "ClaimTypes",
            len(docs.claim_types),
            f"{shared} shared by several kinds" if shared else "",
        ),
        (
            "Capture contracts",
            len(owned),
            "the kit's own"
            + (f", plus core's {_code(core)} for a statement on its author's own word" if core else "")
            + ": [Where evidence comes from](#where-evidence-comes-from)",
        ),
        ("Procedures", len(procedures), binding),
        ("Queries", len(docs.queries), "[What you can ask](#what-you-can-ask)"),
        ("Provider interfaces", len(docs.interfaces), ""),
        ("Acquisition policies", len(docs.policies), policies),
        (
            "Example Lines",
            len(docs.lines),
            f"with {len(docs.triggers)} Triggers and {len(docs.mandates)} Mandates in "
            f"`{EXAMPLE.as_posix()}`: [What runs on its own](#what-runs-on-its-own)",
        ),
    ]
    out = [
        "## At a glance",
        "",
        f"Kit `{docs.kit_id}` version **{docs.version}**, defining every name under "
        f"{_code(docs.owns)}.",
        "",
    ]
    out += _table(("Definitions", "Count", "Notes"), ((n, str(c), note) for n, c, note in counts))
    out += ["", "Providers `kit add` installs:", ""]
    out += _table(
        ("Package", "Version", "Delivery", "Interfaces"),
        (
            (
                f"`{item.package}`",
                item.version,
                "bundled wheel" if item.delivery == "bundled" else "by name from the index",
                _code(item.interfaces),
            )
            for item in docs.providers
        ),
    )
    return out


_EVIDENCE_GROUPS = {
    "http_response": "HTTP and file captures",
    "procedure_output": "Procedure outputs",
    "sbom_document": "SBOM documents",
    "workspace_file": "Workspace files an analyst cites",
    "sarif_log": "Scan results (SARIF)",
    "test_report": "Reproductions (PoC runs)",
    "inventory_scan": "Runtime inventory scans",
    "log_query": "Log reads",
    "credential_state": "Credential key states (non-secret)",
}


def _evidence_diagram(docs: KitDocs) -> list[str]:
    evidenced = _evidenced(docs)
    out = [
        "### How evidence reaches each kind",
        "",
        "Each box on the left is one of the kit's Capture contracts, grouped by the shape of "
        "what it holds, with its replay (`exact`, or `attested`); the logical sources under each "
        "are in [Logical sources](#logical-sources). An arrow points to a Subject kind whose "
        "ClaimTypes may cite it. A thick arrow carries at least one ClaimType that requires a "
        "Capture (`captured`); a dotted arrow only ClaimTypes that may cite one. The number is "
        "how many of that kind's ClaimTypes the contract backs. Names drop the "
        f"{_code(docs.owns)} prefix. Not drawn: core's self-source (a statement citing its "
        "author's own word, Evidence `own word` below) and the kinds none of whose ClaimTypes "
        "cite one of the kit's contracts.",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    # Only the kit's own contracts: a statement citing its author's word (core's self-source)
    # is noted in the text, not drawn.
    owned = _owned_contracts(docs)
    contracts = sorted(name for name in evidenced if name in owned)
    groups: dict[str, list[str]] = defaultdict(list)
    for contract in contracts:
        doc = docs.contracts[contract]
        for kind in (doc.shape,):
            groups[_EVIDENCE_GROUPS.get(kind, kind)].append(contract)
    for index, title in enumerate(sorted(groups)):
        out.append(f'  subgraph g{index}["{title}"]')
        out.append("    direction TB")
        for contract in groups[title]:
            label = f"{_short(docs, contract)}<br/>{docs.contracts[contract].replay}"
            out.append(f'    {_node_id("c", contract)}["{label}"]')
        out.append("  end")
    kinds = sorted({kind for name in contracts for item in evidenced[name] for kind in item.kinds})
    out.append('  subgraph kinds["ClaimTypes, by Subject kind"]')
    out.append("    direction TB")
    for kind in kinds:
        out.append(f'    {_node_id("k", kind)}["{_short(docs, kind)}"]')
    out.append("  end")
    for contract in contracts:
        per_kind: dict[str, list[ClaimTypeDoc]] = defaultdict(list)
        for item in evidenced[contract]:
            for kind in item.kinds:
                per_kind[kind].append(item)
        for kind in sorted(per_kind):
            items = per_kind[kind]
            captured = sum(1 for item in items if item.requirement == "captured")
            source, target = _node_id("c", contract), _node_id("k", kind)
            if not captured:
                out.append(f'  {source} -. "{len(items)}" .-> {target}')
                continue
            label = str(len(items))
            if captured != len(items):
                label += f", {captured} captured"
            out.append(f'  {source} == "{label}" ==> {target}')
    out.append("```")
    return out


def _line_label(docs: KitDocs, line: LineDoc) -> str:
    crons = sorted(t.cron for t in docs.triggers.values() if t.line == line.name and t.cron)
    parts = [line.max_authority] + [_cron_words(cron) or f"cron {cron}" for cron in crons]
    return f"{_short(docs, line.name)}<br/>{'; '.join(parts)}"


def _automation_diagram(docs: KitDocs) -> list[str]:
    retentions = _retentions(docs)
    landing = sorted((t for t in docs.triggers.values() if t.landing), key=lambda item: item.name)
    # The logical sources drawn: each one a landing Trigger selects, and each one an example
    # Line retains (keyed with its contract; None: any Capture under the contract).
    keys: set[tuple[str, str | None]] = {
        (trigger.landing or "", source)
        for trigger in landing
        for source in (trigger.logical_sources or (None,))
    }
    keys |= {
        (item.contract, item.source)
        for item in retentions
        if item.line and item.source and not item.emitted
    }
    feeds = {key: _retained_by(retentions, *key) for key in sorted(keys, key=str)}
    reacting = {trigger.line for trigger in landing}
    pulls = sorted(name for name in docs.lines if name not in reacting)
    direct = sorted({item.definition for items in feeds.values() for item in items if not item.line})
    out = [
        "### What starts what",
        "",
        "From the example ChangeSet. On the left, the Lines a schedule starts and the "
        "Procedures you run directly or from a Line you author per source ([intake](intake.md)); "
        "each retains Captures under a logical source (middle: "
        "what was read, over the Capture contract it is kept under, without the "
        f"{_code(docs.owns)} prefix). A landing Trigger selects a logical source and starts "
        "the Lines on the right; the arrow label is the Trigger's name. Each Line shows its "
        "max authority and any schedule.",
        "",
        "```mermaid",
        "flowchart LR",
    ]

    def source_id(key: tuple[str, str | None]) -> str:
        return _node_id("s", f"{key[0]}_{key[1] or 'any'}")

    out.append('  subgraph pulls["Lines on a schedule"]')
    out.append("    direction TB")
    for name in pulls:
        out.append(f'    {_node_id("l", name)}["{_line_label(docs, docs.lines[name])}"]')
    out.append("  end")
    if direct:
        title = "Run directly, or a Line per source" if set(direct) & set(PER_LINE) else "Run directly"
        out.append(f'  subgraph direct["{title}"]')
        out.append("    direction TB")
        for name in direct:
            how = f"a Line per {PER_LINE[name][1]}" if name in PER_LINE else "procedure run"
            out.append(f'    {_node_id("d", name)}["{_short(docs, name)}<br/>{how}"]')
        out.append("  end")
    out.append('  subgraph sources["Logical sources"]')
    out.append("    direction TB")
    for key in feeds:
        contract, source = key
        what = SOURCE_LABELS.get(source, source) if source else "any Capture"
        out.append(f'    {source_id(key)}[("{what}<br/>{_short(docs, contract)}")]')
    out.append("  end")
    out.append('  subgraph reacts["Lines a landing starts"]')
    out.append("    direction TB")
    for name in sorted(reacting):
        out.append(f'    {_node_id("l", name)}["{_line_label(docs, docs.lines[name])}"]')
    out.append("  end")
    for key, items in feeds.items():
        starts = sorted(
            {_node_id("l", item.line) if item.line else _node_id("d", item.definition) for item in items}
        )
        out += [f"  {start} --> {source_id(key)}" for start in starts]
    for trigger in landing:
        for source in trigger.logical_sources or (None,):
            key = (trigger.landing or "", source)
            label = _short(docs, trigger.name)
            out.append(f'  {source_id(key)} -- "{label}" --> {_node_id("l", trigger.line)}')
    out.append("```")
    return out


def _requirement(claim_type: ClaimTypeDoc) -> str:
    return {"captured": "yes", "self": "no (per rule)", "none": "no"}[claim_type.requirement]


def _roles(claim_type: ClaimTypeDoc) -> str:
    if len(claim_type.roles) == 1:
        return claim_type.roles[0]
    others = [role for role in claim_type.roles if role != claim_type.default_role]
    return f"{claim_type.default_role} (or {', '.join(others)})"


def _evidence(claim_type: ClaimTypeDoc) -> str:
    """The Captures a Claim may cite, in words: what was read, then the contract it is kept
    under (any source under a contract whose rule names none)."""

    return "; ".join(
        "own word"
        if name == SELF_SOURCE
        else (_and([_label(source) for source in sources], "or") + f" (`{name}`)")
        if sources
        else f"`{name}`"
        for name, sources in claim_type.source_uses
    )


def _claim_rows(docs: KitDocs, items: Iterable[ClaimTypeDoc], prefix: str) -> list[str]:
    out = _table(
        (
            "Field",
            "Meaning",
            "Value",
            "Cardinality",
            "Role",
            "Evidence",
            "Captured required",
            "Freshness",
            "Contention",
        ),
        (
            (
                f"`{item.predicate.removeprefix(prefix)}`",
                item.description,
                item.value,
                item.cardinality,
                _roles(item),
                _evidence(item),
                _requirement(item),
                item.freshness,
                item.contention,
            )
            for item in items
        ),
    )
    for item in items:
        if item.members:
            out += ["", f"`{item.predicate.removeprefix(prefix)}` is one of:", ""]
            out += [f"- `{member}`: {text}" for member, text in item.members]
    return out


def _models(docs: KitDocs) -> list[str]:
    out = [
        "## What it models",
        "",
        "One section per Subject kind: what it is, how core names it (its key), and the "
        "ClaimTypes that can be stated about it. **Role**: an `observation` is a source's word, "
        "a `normative` statement is someone's decision. **Evidence**: the Captures a Claim may "
        "cite: what was read, and the contract it is kept under (`own word`: its author's "
        "statement; each logical source's id is in [Logical sources](#logical-sources)). "
        "**Captured required**: a Claim must cite a retained Capture under one of them (`per rule`: the evidence rules "
        "decide). **Contention**: what the slot reads when two current, supported answers "
        "compete: `unresolved` (a one-valued slot then reads contested, with no value) or "
        "`all held` (a many-valued slot keeps every answer).",
        "",
    ]
    shared = sorted(
        (item for item in docs.claim_types.values() if len(item.kinds) > 1),
        key=lambda item: item.predicate,
    )
    for kind in sorted(docs.kinds.values(), key=lambda item: item.name):
        own = sorted(
            (item for item in docs.claim_types.values() if item.kinds == (kind.name,)),
            key=lambda item: item.predicate,
        )
        out += [f"### {kind.name}", "", kind.description, "", f"Key: {kind.keys}.", ""]
        if own:
            out += _claim_rows(docs, own, kind.name + ".")
        also = [item.predicate for item in shared if kind.name in item.kinds]
        if also:
            out += [
                "",
                f"Also the shared {_code(also)} (see [Shared ClaimTypes](#shared-claimtypes)).",
            ]
        out.append("")
    if shared:
        out += ["### Shared ClaimTypes", ""]
        kinds = {item.kinds for item in shared}
        if len(kinds) == 1:
            out += [f"Each of {_code(next(iter(kinds)))} accepts these.", ""]
        else:
            out += _table(
                ("ClaimType", "Kinds"),
                ((f"`{item.predicate}`", _code(item.kinds)) for item in shared),
            )
            out.append("")
        out += _claim_rows(docs, shared, "")
        out.append("")
    return out[:-1]


def _server(docs: KitDocs, interface: str | None) -> str:
    """Who serves an interface: the installed Provider package, or core's built-in reader."""

    packages = [item.package for item in docs.providers if interface in item.interfaces]
    return f"{_code(packages)} serving" if packages else "core's built-in"


def _where_run(definition: str, lines: Mapping[str, list[str]]) -> str:
    named = sorted(lines.get(definition, []))
    if named:
        return ("Line " if len(named) == 1 else "Lines ") + _code(named)
    if definition in PER_LINE:
        return _per_line_text(definition)
    return "run directly"


def _producer_text(
    docs: KitDocs, definition: str, nodes: list[SourceNode], lines: Mapping[str, list[str]]
) -> str:
    """One Procedure's retention of a contract: where it runs and what serves each read."""

    served: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        if node.emitted:
            served["its run's own output"] = []
        elif node.provider:
            served[f"`{node.provider}`"] = []
        else:
            served[_server(docs, node.interface)].append(f"`{node.interface}`")
    via = [" ".join([server, ", ".join(sorted(set(items)))]).strip() for server, items in served.items()]
    return f"`{definition}` ({_where_run(definition, lines)}; {'; '.join(via)})"


def _contracts(docs: KitDocs) -> list[str]:
    producers = _producers(docs)
    landings = _landings(docs)
    evidenced = _evidenced(docs)
    by_definition: dict[str, list[str]] = defaultdict(list)
    for line in docs.lines.values():
        by_definition[_definition_of(docs, line.procedure)].append(line.name)
    out = [
        "## Where evidence comes from",
        "",
        "One row per Capture contract. **Produced by**: the Procedures that "
        "retain it, where they run (an example Line, a direct `cruxible procedure run`, or a "
        "Line you author per incident or per source) and what serves each read. **Landings start**: the example Lines a landing Trigger on it starts. "
        "**Supports**: the ClaimTypes that may cite it.",
        "",
    ]
    rows = []
    for contract in sorted(docs.contracts.values(), key=lambda item: item.name):
        backs = evidenced.get(contract.name, [])
        captured = sum(1 for item in backs if item.requirement == "captured")
        started = sorted({t.line for t in landings.get(contract.name, [])})
        rows.append(
            (
                f"`{contract.name}`",
                f"{contract.shape}, {contract.replay}",
                contract.grade,
                "; ".join(
                    _producer_text(docs, definition, nodes, by_definition)
                    for definition, nodes in _by_definition(producers.get(contract.name, []))
                )
                or (
                    "core: the statement itself, which a Claim supplies as its own source"
                    if contract.name == SELF_SOURCE
                    else ""
                ),
                _code(started),
                f"{len(backs)} ClaimTypes; {captured} {'requires' if captured == 1 else 'require'} a Capture"
                if backs
                else "",
            )
        )
    out += _table(
        ("Contract", "Shape, replay", "Grade", "Produced by", "Landings start", "Supports"),
        rows,
    )
    return out + ["", *_logical_sources(docs)]


def _named_sources(docs: KitDocs) -> dict[str, set[str]]:
    """Every logical source the definitions and the example name, with its contracts."""

    named: dict[str, set[str]] = defaultdict(set)
    for item in _retentions(docs):
        if item.source:
            named[item.source].add(item.contract)
    for trigger in docs.triggers.values():
        for source in trigger.logical_sources:
            named[source].add(trigger.landing or "")
    for claim_type in docs.claim_types.values():
        for contract, sources in claim_type.source_uses:
            for source in sources:
                named[source].add(contract)
    return named


def _logical_sources(docs: KitDocs) -> list[str]:
    retentions = _retentions(docs)
    out = [
        "### Logical sources",
        "",
        "A Capture is retained under a contract and a logical source: what was read. A "
        "landing Trigger selects logical sources, and a ClaimType's evidence rule names the "
        "ones it admits. **Retained by**: the runs that retain it (an example Line, a direct "
        "`cruxible procedure run`, or a Line you author per incident or per source). **Starts**: the Lines "
        "its landing starts. **Cited by**: how many ClaimTypes admit it.",
        "",
    ]
    rows = []
    for source, contracts in sorted(_named_sources(docs).items()):
        starts = sorted(
            {t.line for t in docs.triggers.values() if source in t.logical_sources}
        )
        per_line = sorted(
            {
                node.definition
                for node in docs.source_nodes
                if node.definition in PER_LINE
                and PER_LINE[node.definition][0] == node.alias
                and node.alias is not None
                and _node_source(node, None) == source
            }
        )
        cited = sum(
            1
            for item in docs.claim_types.values()
            if any(source in sources for _, sources in item.source_uses)
        )
        rows.append(
            (
                f"`{source}`",
                _label(source) if source in SOURCE_LABELS else "",
                _code(sorted(contracts)),
                "; ".join(
                    _who(_retained_by(retentions, contract, source)) for contract in sorted(contracts)
                ),
                ", ".join(
                    [_code(starts)] * bool(starts)
                    + [_per_line_who(name) for name in per_line]
                ),
                f"{cited} ClaimType{'s' if cited != 1 else ''}" if cited else "",
            )
        )
    out += _table(
        ("Logical source", "What it is", "Contract", "Retained by", "Starts", "Cited by"), rows
    )
    return out


# How a kind reads in a sentence when its plural is not the name plus "s".
_PLURALS = {"change": "changes (commits)", "coverage": "coverage records"}


def _plural(docs: KitDocs, kind: str) -> str:
    short = _short(docs, kind)
    if short in _PLURALS:
        return _PLURALS[short]
    return short[:-1] + "ies" if short.endswith("y") else short + "s"


def _run_does(docs: KitDocs, line: LineDoc) -> str:
    """What one run of a Line does, in words: what it retains, proposes, settles or posts."""

    definition = docs.definitions.get(_definition_of(docs, line.procedure))
    kinds = definition.node_kinds if definition else frozenset()
    retained = []
    for item in _retentions(docs):
        if item.line != line.name:
            continue
        text = (
            "its run's output"
            if item.emitted
            else _a(_label(item.source))
            if item.source
            else "a Capture"
        )
        if text not in retained:
            retained.append(text)
    parts = ["retains " + _and(retained)] if retained else []
    if kinds & {"propose_change_set", "settle_change_set"}:
        mandates = [m for m in docs.mandates.values() if m.procedure == line.procedure]
        scope = sorted({entry for m in mandates for entry in m.namespace})
        subjects = [entry.removeprefix("subjects/") for entry in scope if entry.startswith("subjects/")]
        creates = f" and new {_and([_plural(docs, k) for k in subjects])}" if subjects else ""
        if line.max_authority == "settle":
            text = f"settles Claim changes{creates}" if mandates else "settles (needs a settle Mandate)"
        elif line.max_authority == "propose":
            text = f"proposes Claim changes{creates} for review"
            if not mandates:
                text += " (needs a propose Mandate)"
            if "settle_change_set" in kinds:
                text += (
                    "; it can settle them itself once you grant it a settle Mandate and raise "
                    "its max authority to `settle`"
                )
        else:
            text = "proposes nothing at max authority `observe`"
        parts.append(text)
    if "post_inbox" in kinds:
        parts.append("posts inbox items")
    if line.max_authority == "observe":
        parts.append("changes nothing the instance holds")
    text = "; ".join(parts) or "nothing"
    return text[:1].upper() + text[1:]


def _started_by(docs: KitDocs, line: str) -> str:
    parts = [
        f"{_trigger_words(docs, trigger)} ({_trigger_raw(trigger)})"
        for trigger in sorted(docs.triggers.values(), key=lambda item: item.name)
        if trigger.line == line
    ]
    text = "; or ".join(parts) or "only when run (`cruxible line run`)"
    return text[:1].upper() + text[1:]


def _runs(docs: KitDocs) -> list[str]:
    out = [
        "## What runs on its own",
        "",
        f"The example ChangeSet (`{EXAMPLE.as_posix()}`) authors these Lines disabled; you adapt, "
        "approve and enable them. **Started by**: each Trigger in words (a schedule, or which "
        "logical source landing and who retains it), its name and raw form after it. **Max "
        "authority** caps what a run may do (`observe`, `propose`, `settle`). **What a run "
        "does**: what it retains, proposes (a ChangeSet that waits for review), settles or "
        "posts to the inbox, and the Subjects it may create (its Mandates' scope).",
        "",
    ]
    out += _table(
        ("Line", "Started by", "Procedure", "Max authority", "What a run does"),
        (
            (
                f"`{line.name}`",
                _started_by(docs, line.name),
                f"`{line.procedure}`",
                line.max_authority,
                _run_does(docs, line),
            )
            for line in sorted(docs.lines.values(), key=lambda item: item.name)
        ),
    )
    by_definition: dict[str, list[str]] = defaultdict(list)
    for line in docs.lines.values():
        by_definition[_definition_of(docs, line.procedure)].append(line.name)
    out += [
        "",
        "Every Procedure, what its terminal does, and the example Lines that run it "
        "(`direct`: `cruxible procedure run`):",
        "",
    ]
    out += _table(
        ("Definition", "Kind", "Does", "What it is", "Example Lines"),
        (
            (
                f"`{item.name}`",
                item.kind,
                ", ".join(_effects(docs, item)),
                item.summary,
                _code(sorted(by_definition[item.name]))
                or (_per_line_text(item.name) if item.name in PER_LINE else "direct"),
            )
            for item in sorted(docs.definitions.values(), key=lambda item: item.name)
        ),
    )
    return out


def _asks(docs: KitDocs) -> list[str]:
    out = [
        "## What you can ask",
        "",
        "`cruxible query --name NAME`. Every query is scoped to supported, current Claims, and "
        "missing evidence is not a negative finding.",
        "",
    ]
    out += _table(
        ("Query", "The question it answers", "Parameters"),
        (
            (f"`{item.name}`", item.question, ", ".join(item.parameters))
            for item in sorted(docs.queries.values(), key=lambda item: item.name)
        ),
    )
    return out


def _short_glance(docs: KitDocs) -> list[str]:
    """The README's counts: what the kit defines, each row linking into reference.md."""

    procedures = sum(1 for d in docs.definitions.values() if d.kind == "Procedure")
    rows = [
        ("Kinds of thing it models", str(len(docs.kinds)), "what-it-models"),
        ("Fields (ClaimTypes) across them", str(len(docs.claim_types)), "what-it-models"),
        (
            "Capture contracts (plus core's self-source)",
            f"{len(_owned_contracts(docs))} + {len(docs.contracts) - len(_owned_contracts(docs))}",
            "where-evidence-comes-from",
        ),
        ("Procedures", str(procedures), "what-runs-on-its-own"),
        ("Queries", str(len(docs.queries)), "what-you-can-ask"),
        (
            "Example Lines / Triggers / Mandates",
            f"{len(docs.lines)} / {len(docs.triggers)} / {len(docs.mandates)}",
            "what-runs-on-its-own",
        ),
    ]
    return _table(
        (f"`{docs.kit_id}` {docs.version}", "Count"),
        ((f"[{label}]({REFERENCE}#{anchor})", count) for label, count, anchor in rows),
    )


def render(docs: KitDocs) -> dict[str, str]:
    """The README's generated sections, by marker name."""

    return {"glance": "\n".join(_short_glance(docs))}


def reference_file(docs: KitDocs) -> str:
    parts = [
        [
            f"# {docs.kit_id} kit {docs.version} reference",
            "",
            "Every kind, field, contract, Line, Procedure and query in this release, generated "
            "from its definitions (`cruxible-kit.json`, `artifacts/`) and the example "
            f"ChangeSet (`{EXAMPLE.as_posix()}`) by `source/reference.py`; do not edit. "
            "`scripts/kits.py check` fails when it is out of date. Start with the kit's "
            f"[README]({README}).",
        ],
        _glance(docs),
        _evidence_diagram(docs),
        _automation_diagram(docs),
        _models(docs),
        _contracts(docs),
        _runs(docs),
        _asks(docs),
    ]
    return "\n\n".join("\n".join(part) for part in parts) + "\n"


_MAP_BLOCK = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
_MAP_NODE = re.compile(r"\w+\(?\[\(?\"([^\"]*)\"")
_MAP_EDGE = re.compile(r"\|([^|]*)\|")


def concept_map_problems(docs: KitDocs, readme: str) -> list[str]:
    """Names in the README's concept map the kit does not define.

    A node label naming an owned kind (``security.job``) must be a defined SubjectKind;
    an edge label lists fields as ``kind.field`` (``job.uses``), each a defined ClaimType.
    """

    at = readme.find(CONCEPT_MAP)
    block = _MAP_BLOCK.search(readme, at) if at >= 0 else None
    if block is None:
        return [f"{README} has no concept map after {CONCEPT_MAP}"]
    text = block.group(1)
    problems = []
    owned = "|".join(re.escape(prefix) for prefix in docs.owns)
    for label in _MAP_NODE.findall(text):
        for name in re.findall(rf"(?:{owned})[a-z0-9_]+", label):
            if name not in docs.kinds:
                problems.append(f"concept map names kind {name}, which the kit does not define")
    for label in _MAP_EDGE.findall(text):
        for field_name in re.findall(r"[a-z0-9_]+\.[a-z0-9_]+", label):
            if not any(prefix + field_name in docs.claim_types for prefix in docs.owns):
                problems.append(
                    f"concept map names field {field_name}, which the kit does not define"
                )
    return sorted(set(problems))


def _markers(name: str) -> tuple[str, str]:
    return f"<!-- BEGIN GENERATED: {name} -->", f"<!-- END GENERATED: {name} -->"


def splice(readme: str, sections: Mapping[str, str]) -> str:
    """``readme`` with each generated section replaced; refuses missing markers."""

    for name in SECTIONS:
        begin, end = _markers(name)
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        if len(pattern.findall(readme)) != 1:
            raise ValueError(f"{README} needs exactly one {begin} ... {end} pair")
        block = f"{begin}\n<!-- Generated by source/reference.py from the definitions. -->\n\n"
        block += sections[name] + f"\n\n{end}"
        readme = pattern.sub(lambda _: block, readme)
    return readme


def expected(kit_dir: Path) -> dict[Path, str]:
    docs = load(kit_dir)
    return {
        kit_dir / README: splice((kit_dir / README).read_text(), render(docs)),
        kit_dir / REFERENCE: reference_file(docs),
    }


def write(kit_dir: Path) -> list[Path]:
    changed = []
    for path, text in expected(kit_dir).items():
        if not path.is_file() or path.read_text() != text:
            path.write_text(text)
            changed.append(path)
    return changed


def check(kit_dir: Path) -> list[str]:
    """The generated files that differ from the kit's definitions, and the concept map's
    undefined names."""

    problems = [
        f"{path.relative_to(kit_dir)} is out of date: run python source/reference.py"
        for path, text in expected(kit_dir).items()
        if not path.is_file() or path.read_text() != text
    ]
    docs = load(kit_dir)
    return (
        problems
        + concept_map_problems(docs, (kit_dir / README).read_text())
        + derivation_problems(docs)
    )


def derivation_problems(docs: KitDocs) -> list[str]:
    """Hand-kept maps the generator reads that disagree with the definitions."""

    problems = []
    run_by_example = {line.procedure for line in docs.lines.values()}
    for name, (alias, _owner, _page) in sorted(PER_LINE.items()):
        if name not in docs.definitions:
            problems.append(f"PER_LINE names {name}, which is not a Procedure of the kit")
        elif name in run_by_example:
            problems.append(f"PER_LINE names {name}, which an example Line runs")
        elif alias is not None and not any(
            node.definition == name and node.alias == alias for node in docs.source_nodes
        ):
            problems.append(f"PER_LINE names source {alias!r} of {name}, which it lacks")
    named = _named_sources(docs)
    for source in sorted(set(named) - set(SOURCE_LABELS)):
        problems.append(f"logical source {source} has no label in SOURCE_LABELS")
    for source in sorted(set(SOURCE_LABELS) - set(named)):
        problems.append(f"SOURCE_LABELS labels {source}, which nothing names")
    placed = {node.interface for node in docs.source_nodes if not node.logical_source}
    for interface in sorted(set(INTERFACE_SOURCES) - placed):
        problems.append(f"INTERFACE_SOURCES maps {interface}, which no source node reads")
    for item in _retentions(docs):
        if item.source is None and not item.emitted and (item.line or not item.given):
            problems.append(
                f"{item.line or item.definition} retains a Capture whose logical source is unknown"
            )
    for trigger in sorted(docs.triggers.values(), key=lambda item: item.name):
        if trigger.cron and _cron_words(trigger.cron) is None:
            problems.append(f"Trigger {trigger.name}: cron {trigger.cron} has no words")
    return problems


def main(argv: list[str]) -> int:
    args = [arg for arg in argv if arg != "--check"]
    kit_dir = Path(args[0]).resolve() if args else KIT
    if "--check" in argv:
        problems = check(kit_dir)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    for path in write(kit_dir):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
