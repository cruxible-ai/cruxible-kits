"""Independent light-artifact oracles and exact lowering checks for the release sources.

Procedure oracle: kitcore 63947cbff tests/fixtures/procedures/security-p1.json.
Query oracle: the same core's test_query/fixtures/security_authored_queries.json tree hashes.
The semantic oracles are independent of decompilation. Decompile/lower checks
cover readback consistency alongside the hand-authored input checks.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cruxible_client.contracts.authoring.inputs import lower_authoring_input
from cruxible_client.contracts.canonical import canonical_bytes
from cruxible_client.contracts.procedures.artifacts import (
    parse_procedure,
    render_procedure,
)
from cruxible_client.contracts.procedures.authored import lower_procedure_spec
from cruxible_client.contracts.procedures.decompile import decompile_procedure
from cruxible_client.contracts.procedures.graph import (
    compute_procedure_definition_digest,
)
from cruxible_client.contracts.procedures.named_models import NamedProcedureDefinition
from cruxible_client.contracts.provider_contracts import ProviderOperationContract
from cruxible_client.contracts.query.authored import lower_query_spec
from cruxible_client.contracts.query.definitions import render_query_definition
from cruxible_core.service.discovery.authored_query import (
    AuthoredQueryResolver,
    candidate_query_vocabulary,
)

KIT = Path(__file__).parents[1]
MODULE = KIT / "source/authoring/security_definitions.py"
module_spec = importlib.util.spec_from_file_location("security_definitions", MODULE)
defs = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(defs)
ORACLE = json.loads(
    (Path(__file__).parent / "data/version-history/procedures.json").read_text()
)
QUERY_ORACLE = json.loads(
    (Path(__file__).parent / "data/light-artifacts/query-trees.json").read_text()
)
SPECS = {spec.procedure: spec for spec in defs.procedure_specs()}


def _operation(interface):
    interface = interface.partition("/")[0]
    for provider in ("security-analysis-provider", "security-sources-provider"):
        path = (
            KIT
            / f"source/providers/{provider}/src/{provider.replace('-', '_')}/contracts/{interface}.json"
        )
        if path.is_file():
            return ProviderOperationContract.model_validate(
                json.loads(path.read_text())["contracts"]
            )
    # The built-in and web schemas are carried by the source's explicitly declared return fields.
    return None


@pytest.mark.parametrize("name", sorted(SPECS))
def test_authored_procedure_has_consistent_stored_bytes(name):
    """Consistency only; the core-fixture semantic comparison below is independent."""
    path = f"procedures/{name}.json"
    wire = (KIT / "artifacts" / path).read_bytes()
    stored = parse_procedure(wire, path=path)
    nodes = {node.as_: node for node in stored.definition.nodes if hasattr(node, "as_")}

    def resolve(kind, step):
        node = nodes[getattr(step, "call", None) or getattr(step, "source", None)]
        op = _operation(node.interface.target.name)
        output = (
            None
            if op is None
            else (op.material if node.kind == "source" else op.output)
        )
        return {
            "bindings": {
                "provider": node.provider.model_dump(mode="json"),
                "interface": node.interface.model_dump(mode="json"),
            },
            "output": None if output is None else output.fields,
        }

    for spec in (SPECS[name], decompile_procedure(stored)):
        assert spec.slots == SPECS[name].slots
        lowered = lower_procedure_spec(spec, resolve=resolve)
        payload = lower_authoring_input(lowered)
        definition = NamedProcedureDefinition.model_validate(payload.definition)
        actual = stored.model_copy(
            update={
                "definition": definition,
                "definition_digest": compute_procedure_definition_digest(
                    definition
                ).tagged,
                "owned_contracts": payload.owned_contracts,
            }
        )
        assert render_procedure(actual) == wire


def _semantic(value):
    if isinstance(value, list):
        return [_semantic(item) for item in value]
    if isinstance(value, dict):
        # Provider choices become slots. Verify their interfaces independently below;
        # the core oracle remains the independent behavior/evidence/topology reference.
        if "provider" in value and "interface" in value:
            value = {**value, "provider": {"by_interface": value["interface"]}}
        value = {k: v for k, v in value.items() if k != "pin_slots"}
        # New provider builds and named interface versions are acceptance coordinates.
        if set(value) == {"kind", "name"} and value["kind"] in {
            "Provider",
            "ProviderInterface",
        }:
            return {**value, "name": value["name"].partition("/")[0]}
        if (
            value.get("role") == "query"
            and value.get("target", {}).get("name") == "security.kev_triage_backlog"
        ):
            return {"role": "query", "target": value["target"]}
        return {
            key: _semantic(item)
            for key, item in value.items()
            if key != "definition_digest"
        }
    if isinstance(value, str):
        replacements = json.loads(
            (
                Path(__file__).parent
                / "data/version-history/contract-replacements.json"
            ).read_text()
        )
        for old, (new, _) in replacements.items():
            value = value.replace(old, new)
    return value


@pytest.mark.parametrize("filename", sorted(ORACLE))
def test_procedure_semantics_match_independent_core_oracle(filename):
    actual = json.loads((KIT / "artifacts/procedures" / filename).read_text())
    expected = ORACLE[filename]
    # G7 intentionally extends two import summaries and parse requests.
    if filename in {"security.inventory-import.json", "security.sbom-import.json"}:

        def strip_extensions(item):
            if isinstance(item, dict):
                for key in ("osv_unindexed", "osv_not_indexed", "osv_ecosystems"):
                    item.pop(key, None)
                for child in item.values():
                    strip_extensions(child)
            elif isinstance(item, list):
                for child in item:
                    strip_extensions(child)

        strip_extensions(actual)
    assert _semantic(actual) == _semantic(expected)


@pytest.mark.parametrize(
    "spec", defs.query_definitions(defs.RELEASE), ids=lambda spec: spec.query
)
def test_authored_query_matches_tree_oracle_and_stored_bytes(spec):
    tree = {
        str(path.relative_to(KIT / "artifacts")): path.read_bytes()
        for path in (KIT / "artifacts/claim-types").rglob("*.json")
    }
    resolver = AuthoredQueryResolver(candidate_query_vocabulary(tree))
    query = lower_query_spec(spec, resolver)
    body = query.model_dump(mode="json")
    body.pop("pins", None)
    assert hashlib.sha256(canonical_bytes(body)).hexdigest() == QUERY_ORACLE[spec.query]
    assert (
        render_query_definition(query)
        == (KIT / f"artifacts/query-definitions/{spec.query}.json").read_bytes()
    )


def test_capture_contracts_are_shared_shapes_with_use_site_sources():
    contracts = defs.capture_contracts()
    assert len(contracts) == 5
    assert {contract.shape for contract in contracts} == {
        "http_response",
        "procedure_output",
    }
    for contract in contracts:
        body = contract.model_dump(mode="json")
        assert (
            not {
                "evidence_kinds",
                "allowed_source_kinds",
                "logical_source_identities",
                "pins",
            }
            & body.keys()
        )
    for claim_type in defs.claim_types(defs.RELEASE):
        for rule in claim_type.evidence_admission_policy.rules:
            for use in rule.capture_contracts:
                if use.target.name in {
                    "security.fetched-v1",
                    "security.fetched-large-v1",
                    "security.file-v1",
                    "security.file-erasable-v1",
                }:
                    assert use.logical_sources


def test_all_21_triggers_name_contracts_and_sources():
    members = json.loads((KIT / "examples/automation.json").read_text())["members"]
    triggers = [member for member in members if member["kind"] == "trigger"]
    assert len(triggers) == 21
    assert all(
        "acquisition_policy_name" not in member and "acquisition_policy" not in member
        for member in members
        if member["kind"] == "line"
    )
    names = {contract.identity.name for contract in defs.capture_contracts()}
    for trigger in triggers:
        schedule = trigger["schedule"]
        if schedule["kind"] == "capture_landing":
            assert schedule["capture_contract"] in names
            assert schedule["logical_sources"]
            assert not any("digest" in key for key in schedule)


def test_measurement_keeps_exact_accepted_query_evidence():
    from cruxible_client.contracts.query.definitions import (
        parse_query_definition,
        query_definition_digest,
    )

    path = "query-definitions/security.kev_triage_backlog.json"
    query = parse_query_definition((KIT / "artifacts" / path).read_bytes(), path=path)
    spec = SPECS["security.kev-triage"]
    (measurement,) = spec.measurements
    assert (
        measurement.measurement.query.artifact_digest
        == query_definition_digest(query).tagged
    )


def test_claim_type_defaults_preserve_all_137_structural_and_admission_decisions():
    oracle = json.loads(
        (
            Path(__file__).parent / "data/light-artifacts/claim-type-semantics.json"
        ).read_text()
    )
    types = defs.claim_types(defs.RELEASE)
    assert len(types) == len(oracle["hashes"]) == 137
    from cruxible_client.contracts.claim_types import claim_type_path, parse_claim_type

    for claim_type in types:
        path = claim_type_path(claim_type.predicate)
        stored = parse_claim_type((KIT / "artifacts" / path).read_bytes(), path=path)
        assert stored == claim_type
        body = claim_type.model_dump(mode="json")
        assert (
            hashlib.sha256(
                canonical_bytes(body["evidence_admission_policy"])
            ).hexdigest()
            == oracle["evidence_hashes"][claim_type.predicate]
        ), claim_type.predicate
        data = {field: body.get(field) for field in oracle["fields"]}
        repairs = json.loads(
            (
                Path(__file__).parent / "data/version-history/description-repairs.json"
            ).read_text()
        )
        if claim_type.predicate in repairs:
            repair = repairs[claim_type.predicate]
            assert data["description"] == repair["after"]
            data["description"] = repair["before"]
        # Nonliteral inputs omit canonical_form; None and [] both mean no transforms.
        if body["object_kind"] == "subject" and data["canonical_form"] is None:
            data["canonical_form"] = []
        assert (
            hashlib.sha256(canonical_bytes(data)).hexdigest()
            == oracle["hashes"][claim_type.predicate]
        ), claim_type.predicate


def test_shared_contracts_refuse_a_different_providers_source():
    for old, (contract, source) in defs.CONTRACT_USES.items():
        if source is None:
            continue
        rule = defs._rule("source", "observation", (old,))
        identity = "CaptureContract:" + contract
        assert rule.admits_source(identity=identity, logical_source=source)
        assert not rule.admits_source(
            identity=identity, logical_source="other.provider.source"
        )
        assert not rule.admits_source(identity=identity, logical_source=None)


def test_unannotated_inventory_context_is_not_invented_by_a_landing_line():
    assert "asset" not in SPECS["security.inventory-import"].input
    assert set(SPECS["security.inventory-acquire"].input) == {"relative_path"}


def test_direct_fetch_contract_limits_sources_without_restricting_governed_lines():
    from cruxible_client.contracts.procedures.contracts import (
        ProcedureContractValidationError,
        validate_contract_schema,
    )

    spec = SPECS["security.fetch"]
    assert spec.input["logical_source"].enum == [
        "cve.record",
        "github.api",
        "github.release",
    ]
    for release in (KIT, KIT / "source/variants/1.3.1-gate"):
        path = "procedures/security.fetch.json"
        stored = parse_procedure((release / "artifacts" / path).read_bytes(), path=path)
        contract = next(
            c.contract_schema
            for c in stored.owned_contracts
            if c.identity == stored.definition.contract_in.target
        )
        for source in ("cve.record", "github.api", "github.release"):
            validate_contract_schema(
                contract,
                {
                    "url": "https://example.invalid/response.json",
                    "logical_source": source,
                    "max_bytes": 1048576,
                },
            )
        for source in (
            "cisa.kev.catalog",
            "first.epss.daily",
            "github.repo.snapshot",
            "pypi.release",
        ):
            with pytest.raises(
                ProcedureContractValidationError, match="outside the declared enum"
            ):
                validate_contract_schema(
                    contract,
                    {
                        "url": "https://example.invalid/response.json",
                        "logical_source": source,
                        "max_bytes": 1048576,
                    },
                )
    observed_source = SPECS["security.fetch-observed"].input["logical_source"]
    assert observed_source.type == "string" and observed_source.enum is None


def test_direct_fetch_retains_release_and_history_time_budgets():
    assert SPECS["security.fetch"].budget.wall_clock == "PT120S"
    assert SPECS["security.fetch"].caps.wall_clock == "PT300S"
    assert SPECS["security.fetch-observed"].budget.wall_clock == "PT60S"
    assert SPECS["security.fetch-observed"].caps.wall_clock == "PT120S"


def test_folded_inventory_and_slot_interfaces_are_explicit():
    assert len(SPECS) == 28
    assert not list((KIT / "artifacts/blueprints").rglob("*.json"))
    variant = KIT / "source/variants/1.3.1-gate/artifacts/procedures"
    assert {
        path.stem
        for path in (KIT / "artifacts/procedures").glob("*.json")
        if path.read_bytes() != (variant / path.name).read_bytes()
    } == {"security.fetch-observed", "security.kev-triage"}
    assert set(SPECS) - {name.removesuffix(".json") for name in ORACLE} == {
        "security.fetch",
        "security.fetch-observed",
        "security.epss-acquire",
        "security.asset-fetch",
        "security.registry-acquire",
        "security.repo-acquire",
        "security.osv-applicability",
    }
    assert SPECS["security.osv-applicability"].activation == "drain"
    assert len(SPECS["security.osv-applicability"].slots) == 3
    for spec in SPECS.values():
        assert spec.source is None  # No source-compiled parent of a slotted child.
        for step in spec.steps:
            if hasattr(step, "provider"):
                assert step.provider in spec.slots
                interface = spec.slots[step.provider]
                assert interface.partition("@")[0] == step.interface
    members = json.loads((KIT / "examples/automation.json").read_text())["members"]
    assert not [m for m in members if m["kind"] == "blueprint_instance"]
    lines = [m for m in members if m["kind"] == "line"]
    assert len(lines) == 19
    assert all("bindings" not in line for line in lines)
    assert sum(m["kind"] == "trigger" for m in members) == 21
    assert sum(m["kind"] == "procedure_mandate" for m in members) == 11
