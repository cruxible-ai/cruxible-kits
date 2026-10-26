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
define. Output is byte-stable: everything is sorted and nothing depends on the
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
# Procedures a Line declared with each incident runs (walkthroughs.md), not an example
# Line: the source node that Line feeds from its landing (None: it has none). ``check``
# refuses an entry that is not a Procedure, names no source node, or an example Line runs.
PER_INCIDENT = {"security.log-import": "log", "security.respond": None}
PER_INCIDENT_TEXT = "a Line per incident ([walkthroughs](walkthroughs.md))"

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
    the Line each incident declares."""

    if node.alias is None:
        return False
    if node.definition in PER_INCIDENT:
        return PER_INCIDENT[node.definition] == node.alias
    return any(
        _definition_of(docs, line.procedure) == node.definition and line.trigger_input == node.alias
        for line in docs.lines.values()
    )


def _effects(docs: KitDocs, definition: DefinitionDoc) -> tuple[str, ...]:
    """What a definition's run does: retain a Capture (a source node no example Line feeds
    from its landing, or an emit node) and its terminals."""

    retains = any(
        node.definition == definition.name and not _reads_landing(docs, node)
        for node in docs.source_nodes
    )
    effects = ["retains a Capture"] if retains else []
    effects += [label for kind, label in _TERMINALS if kind in definition.node_kinds]
    return tuple(effects)


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
    "coordinator_self_source": "Core self-source dependency",
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
        "Each box on the left is one source and the Capture contract it is retained under, "
        "grouped by shape; ClaimType rules below name the permitted logical sources. An arrow points to a Subject kind whose "
        "ClaimTypes may cite it. A thick arrow carries at least one ClaimType that requires a "
        "Capture (`captured`); a dotted arrow only ClaimTypes that may cite one. The number is "
        "how many of that kind's ClaimTypes the contract backs. Names drop the "
        f"{_code(docs.owns)} prefix. Not drawn: the statements that may instead cite their "
        "author's own word (Evidence `own word` below), and kinds that hold only statements "
        "their author's origin supports.",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    # Only the kit's own contracts: a statement citing its author's word (core's self-source)
    # is noted in the text, not drawn.
    contracts = sorted(name for name in evidenced if name in docs.contracts)
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
    parts = [line.max_authority] + [f"cron {cron}" for cron in crons]
    return f"{_short(docs, line.name)}<br/>{', '.join(parts)}"


def _automation_diagram(docs: KitDocs) -> list[str]:
    landings = _landings(docs)
    producers = _producers(docs)
    landing_lines = {t.line for items in landings.values() for t in items}
    out = [
        "### What starts what",
        "",
        "From the example ChangeSet: pull Lines (on a cron) and Procedures you run directly "
        "retain Captures; a landing Trigger on a contract starts the Lines that read it. Each "
        "Line shows its max authority and any cron. The arrow label is the Trigger.",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    contracts = sorted(landings)
    pulls = sorted(name for name in docs.lines if name not in landing_lines)
    reacts = sorted(landing_lines)
    by_definition: dict[str, list[str]] = defaultdict(list)
    for line in docs.lines.values():
        by_definition[_definition_of(docs, line.procedure)].append(line.name)
    direct = sorted(
        {
            node.definition
            for contract in contracts
            for node in producers.get(contract, [])
            if node.definition not in by_definition
        }
    )
    out.append('  subgraph pulls["Pull Lines"]')
    out.append("    direction TB")
    for name in pulls:
        out.append(f'    {_node_id("l", name)}["{_line_label(docs, docs.lines[name])}"]')
    out.append("  end")
    if direct:
        out.append('  subgraph direct["Run directly"]')
        out.append("    direction TB")
        for name in direct:
            kind = docs.definitions[name].kind if name in docs.definitions else "Procedure"
            out.append(f'    {_node_id("d", name)}["{_short(docs, name)}<br/>{kind.lower()} run"]')
        out.append("  end")
    out.append('  subgraph captures["Capture contracts"]')
    out.append("    direction TB")
    for contract in contracts:
        out.append(f'    {_node_id("c", contract)}[("{_short(docs, contract)}")]')
    out.append("  end")
    out.append('  subgraph reacts["Lines a landing starts"]')
    out.append("    direction TB")
    for name in reacts:
        out.append(f'    {_node_id("l", name)}["{_line_label(docs, docs.lines[name])}"]')
    out.append("  end")
    for contract in contracts:
        for definition in sorted({node.definition for node in producers.get(contract, [])}):
            for line_name in sorted(by_definition.get(definition, [])):
                out.append(f"  {_node_id('l', line_name)} --> {_node_id('c', contract)}")
            if definition not in by_definition:
                out.append(f"  {_node_id('d', definition)} --> {_node_id('c', contract)}")
    for contract in contracts:
        for trigger in landings[contract]:
            label = _short(docs, trigger.name)
            out.append(
                f'  {_node_id("c", contract)} -- "{label}" --> {_node_id("l", trigger.line)}'
            )
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
    return ", ".join(
        "own word" if name == SELF_SOURCE else (
            f"`{name}`" + (f" from {', '.join(sources)}" if sources else ""))
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
        "a `normative` statement is someone's decision. **Evidence**: the Capture contracts a "
        "Claim may cite (`own word`: its author's statement). **Captured required**: a Claim "
        "must cite a retained Capture under one of them (`per rule`: the evidence rules "
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
    if definition in PER_INCIDENT:
        return PER_INCIDENT_TEXT
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
        "Line each incident declares) and what serves each read. **Landings start**: the example Lines a landing Trigger on it starts. "
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
                ),
                _code(started),
                f"{len(backs)} ClaimTypes; {captured} {'requires' if captured == 1 else 'require'} a Capture"
                if backs
                else "",
            )
        )
    out += _table(
        ("Contract", "Captures", "Grade", "Produced by", "Landings start", "Supports"),
        rows,
    )
    return out


def _may_settle(docs: KitDocs, line: LineDoc) -> str:
    definition = docs.definitions.get(_definition_of(docs, line.procedure))
    effects = _effects(docs, definition) if definition else ()
    mandates = sorted(
        (m for m in docs.mandates.values() if m.procedure == line.procedure),
        key=lambda item: item.name,
    )
    scope = sorted({entry for m in mandates for entry in m.namespace})
    if line.max_authority == "settle":
        return f"settles within {_code(scope)}" if scope else "settles (needs a settle Mandate)"
    if line.max_authority == "propose":
        text = (
            f"nothing: proposes for review within {_code(scope)}"
            if scope
            else "nothing: proposes for review"
        )
        if "settles a ChangeSet" in effects:
            text += "; its terminal settles once a settle Mandate and a `settle` cap graduate it"
        return text
    done = [effect for effect in effects if effect != "settles a ChangeSet"]
    return "nothing: " + ", ".join(done) if done else "nothing"


def _triggers_of(docs: KitDocs, line: str) -> str:
    parts = []
    for trigger in sorted(docs.triggers.values(), key=lambda item: item.name):
        if trigger.line != line:
            continue
        if trigger.cron:
            parts.append(f"`{trigger.name}`: cron `{trigger.cron}`")
        elif trigger.landing:
            parts.append(f"`{trigger.name}`: lands `{trigger.landing}`")
    return "; ".join(parts) or "line run"


def _runs(docs: KitDocs) -> list[str]:
    out = [
        "## What runs on its own",
        "",
        f"The example ChangeSet (`{EXAMPLE.as_posix()}`) authors these Lines disabled; you adapt, "
        "approve and enable them. **Max authority** caps what a run may do (`observe`, "
        "`propose`, `settle`).",
        "",
    ]
    out += _table(
        ("Line", "Procedure", "Triggers", "Max authority", "What it may settle"),
        (
            (
                f"`{line.name}`",
                f"`{line.procedure}`",
                _triggers_of(docs, line.name),
                line.max_authority,
                _may_settle(docs, line),
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
                or (PER_INCIDENT_TEXT if item.name in PER_INCIDENT else "direct"),
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
    for name, alias in sorted(PER_INCIDENT.items()):
        if name not in docs.definitions:
            problems.append(f"PER_INCIDENT names {name}, which is not a Procedure of the kit")
        elif name in run_by_example:
            problems.append(f"PER_INCIDENT names {name}, which an example Line runs")
        elif alias is not None and not any(
            node.definition == name and node.alias == alias for node in docs.source_nodes
        ):
            problems.append(f"PER_INCIDENT names source {alias!r} of {name}, which it lacks")
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
