"""Author the security kit's definitions in a fresh authoring instance.

    python security_definitions.py definitions [--release 1.0.0|1.1.0]
    python security_definitions.py procedures  [--release 1.0.0|1.1.0]

``definitions`` proposes and activates the CaptureContracts, ClaimTypes, the
SubjectKinds that name every security Subject, the QueryDefinitions and the
acquisition policy. ``procedures`` (after ``cruxible-provider-web`` and the
bundled ``security-analysis-provider`` and ``security-sources-provider`` are
installed) proposes the acquisition Blueprints and the triage, attention,
import and applicability Procedures. Then ``cruxible kit build`` exports the
release (the kit README's "Building a release").

The connection comes from the CLI context (``cruxible init`` remembered it).
Nothing here writes Subjects, Claims, Lines, Triggers or mandates: a kit
carries definitions only; the README is the consumer recipe for the rest.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cruxible_client import Cruxible
from cruxible_client.authoring.inputs import CarriedContractInput
from cruxible_client.authoring.procedures import (
    Call,
    EmitCapture,
    Guard,
    Halt,
    Output,
    PostInbox,
    Project,
    ProposeChangeSet,
    Sequence,
    SettleChangeSet,
    Source,
    StateTap,
)
from cruxible_client.contracts.acquisition_policies import SourceAcquisitionPolicy
from cruxible_client.contracts.artifacts import ArtifactIdentity, ArtifactLifecycle, ArtifactRef
from cruxible_client.contracts.authoring.inputs import BlueprintInput, QueryDefinitionInput
from cruxible_client.contracts.canonical import canonical_bytes
from cruxible_client.contracts.captures import CanonicalDuration, CaptureContract
from cruxible_client.contracts.claim_types import ClaimType, ClaimTypeMemberDescription
from cruxible_client.contracts.policies import (
    ClaimAdmissionPolicy,
    ClaimEvidenceAdmissionPolicy,
    ClaimEvidenceAdmissionRule,
    ClaimResolutionPolicy,
)
from cruxible_client.contracts.procedures.contract_schema import PropertySchema
from cruxible_client.contracts.procedures.models import (
    GuardPredicate,
    PredicateOperand,
    ProcedureBudget,
    ProcedureHardCaps,
)
from cruxible_client.contracts.query.definitions import QueryDefinitionSpec, QueryEvaluationPolicy
from cruxible_client.contracts.query.grammar import (
    QueryBudgets,
    QueryClaimPresenceFilter,
    QueryClaimValueRef,
    QueryComparisonFilter,
    QueryConjunctionFilter,
    QueryDisjunctionFilter,
    QueryEntry,
    QueryEvaluationTimeRef,
    QueryLiteralRef,
    QueryOrdering,
    QueryParameterDeclaration,
    QueryParameterRef,
    QueryProjection,
    QueryProjectionField,
    QuerySubjectFieldRef,
    QueryTraversalStep,
)

DATA = Path(__file__).resolve().parent / "data"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_SOURCE = "cisa.kev.catalog"
KEV_CONTRACT = "security.kev-http-v1"
CVE_CONTRACT = "security.cve-record-http-v1"
OSV_CONTRACT = "security.osv-query-v1"
EPSS_CONTRACT = "security.epss-daily-v1"
SBOM_CONTRACT = "security.cyclonedx-sbom-v1"
OUTPUT_CONTRACT = "security.observation-output-v1"
POLICY = "security.acquisition"
WEB_PROVIDER = "cruxible-provider-web"
ANALYSIS_PROVIDER = "security-analysis-provider"
SOURCES_PROVIDER = "security-sources-provider"
BUILTIN_PROVIDER = "cruxible-builtin"
KEV_MAX_BYTES = 4_194_304  # the catalog is ~1.7 MB; web.fetch defaults to 256 KiB
CVE_MAX_BYTES = 1_048_576
DATE = {"type": "string", "pattern": r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$"}
DATETIME = {
    "format": "date-time",
    "pattern": (
        r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$"
    ),
    "type": "string",
}
CVE_ID = {"type": "string", "pattern": r"^CVE-[0-9]{4}-[0-9]{4,}$"}
TEXT = {"minLength": 1, "type": "string"}
PROBABILITY = {"type": "string", "pattern": r"^(0(\.[0-9]+)?|1(\.0+)?)$"}
PURL = {"type": "string", "pattern": r"^pkg:[a-z0-9.+-]+/.+@.+$"}
#: The canonical form of every name key: two spellings of one name are one key.
NAME_FORM = ("nfkc", "trim", "collapse_whitespace", "casefold")
STATUS = ("affected", "inconclusive", "not_affected")
JUSTIFICATIONS = {
    "component_not_present": "The vulnerable component is not in the release.",
    "inline_mitigations_already_exist": "Built-in protections prevent exploitation.",
    "vulnerable_code_cannot_be_controlled_by_adversary": "The vulnerable code cannot be "
    "reached with adversary-controlled input.",
    "vulnerable_code_not_in_execute_path": "The vulnerable code is present but never runs.",
    "vulnerable_code_not_present": "The component is present but not the vulnerable code "
    "(for example, a fixed version).",
}
WORKSPACE_EVIDENCE_CONTRACT = "security.workspace-evidence-v1"
SELF_SOURCE_CONTRACT = "playbill.coordinator-self-source-v1"
#: every other kit contract: http_response
EVIDENCE_KINDS = {SBOM_CONTRACT: "sbom_document", WORKSPACE_EVIDENCE_CONTRACT: "workspace_file",
                  SELF_SOURCE_CONTRACT: "self_asserted"}
#: What an analyst's judgment may cite: their own words, or a workspace file
#: retained by security.evidence-acquire.
JUDGMENT_EVIDENCE = (SELF_SOURCE_CONTRACT, WORKSPACE_EVIDENCE_CONTRACT)

# --- ClaimTypes ---------------------------------------------------------------
# (predicate, subject kinds, object, literal schema or object kinds, cardinality,
#  role, evidence contracts, canonical form, description). Observations need a
# Capture under one of their contracts; normative statements are supported by
# their own origin. Every literal ClaimType is v8: its canonical form is how its
# values are stored and compared (the key ClaimTypes' forms are their identity).
WORK = ("security.control", "security.exception", "security.remediation")
ClaimRow = tuple[str, tuple[str, ...], str, Any, str, str, tuple[str, ...], tuple[str, ...], str]
CLAIM_TYPES: list[ClaimRow] = [
    # Identity: the key ClaimTypes the SubjectKinds name (see SUBJECT_KINDS).
    ("security.vulnerability.cve_id", ("security.vulnerability",), "literal", CVE_ID, "one",
     "normative", (), ("trim", "upper"), "The CVE identifier; the vulnerability's key."),
    ("security.release.product_name", ("security.release",), "literal", TEXT, "one",
     "normative", (), NAME_FORM, "The product's name; with version, the release's key."),
    ("security.release.version", ("security.release",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The release's version string; with product_name, the release's key."),
    ("security.assessment.release_id", ("security.assessment",), "literal", TEXT, "one",
     "normative", (), ("trim",),
     "The id of the release this assessment is about; with cve_id, the assessment's key."),
    ("security.assessment.cve_id", ("security.assessment",), "literal", CVE_ID, "one",
     "normative", (), ("trim", "upper"),
     "The CVE this assessment is about; with release_id, the assessment's key."),
    ("security.asset.hostname", ("security.asset",), "literal", TEXT, "one", "normative", (),
     ("trim", "casefold"), "The asset's hostname; its key."),
    ("security.product.name", ("security.product",), "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The product's name; its key."),
    ("security.supplier.name", ("security.supplier",), "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The supplier's name; its key."),
    ("security.team.name", ("security.team",), "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The team's name; its key."),
    ("security.service.name", ("security.service",), "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The service's name; its key."),
    # Inventory.
    ("security.asset.environment", ("security.asset",), "literal",
     {"enum": ["production", "staging"], "type": "string"}, "one", "normative", (), (),
     "The environment the asset runs in."),
    ("security.asset.installs", ("security.asset",), "subject", ("security.release",), "many",
     "normative", (), (), "A software release installed on the asset."),
    ("security.asset.internet_exposed", ("security.asset",), "literal", {"type": "boolean"},
     "one", "normative", (), (), "Whether the asset is reachable from the internet."),
    ("security.asset.serves", ("security.asset",), "subject", ("security.service",), "many",
     "normative", (), (), "A service the asset serves."),
    ("security.release.product", ("security.release",), "subject", ("security.product",), "one",
     "sourced", (SBOM_CONTRACT,), (), "The product this release is a version of."),
    ("security.release.component", ("security.release",), "literal", PURL, "many",
     "observation", (SBOM_CONTRACT,), ("trim",),
     "A component of the release, as its package URL with version (purl@version), observed "
     "in an SBOM."),
    ("security.product.supplied_by", ("security.product",), "subject", ("security.supplier",),
     "one", "sourced", (SBOM_CONTRACT,), (), "The supplier of the product."),
    ("security.service.criticality", ("security.service",), "literal",
     {"enum": ["critical", "standard"], "type": "string"}, "one", "normative", (), (),
     "How critical the service is to the organization."),
    ("security.service.owned_by", ("security.service",), "subject", ("security.team",), "one",
     "normative", (), (), "The team accountable for the service."),
    # Applicability.
    ("security.assessment.release", ("security.assessment",), "subject", ("security.release",),
     "one", "sourced", (CVE_CONTRACT, OSV_CONTRACT), (),
     "The release this applicability assessment is about."),
    ("security.assessment.vulnerability", ("security.assessment",), "subject",
     ("security.vulnerability",), "one", "sourced", (CVE_CONTRACT, OSV_CONTRACT), (),
     "The vulnerability this applicability assessment is about."),
    ("security.assessment.status", ("security.assessment",), "literal",
     {"enum": list(STATUS), "type": "string"}, "one", "judged",
     (CVE_CONTRACT, OSV_CONTRACT, OUTPUT_CONTRACT), (),
     "Whether the release is affected by the vulnerability. An observation is a source's verdict "
     "(OSV, a CVE record) citing its Capture; a normative Claim is an analyst's judgment citing "
     "their own words or a workspace file, and comes with security.assessment.judgment."),
    ("security.assessment.justification", ("security.assessment",), "literal",
     {"enum": sorted(JUSTIFICATIONS), "type": "string"}, "one", "judged",
     (CVE_CONTRACT, OSV_CONTRACT, OUTPUT_CONTRACT), (),
     "Why a not_affected release is not affected (the VEX/CSAF justification): an observation "
     "from a source, or (normative) an analyst's judgment. Required in practice with every "
     "not_affected status; core cannot require it."),
    ("security.assessment.judgment", ("security.assessment",), "literal", TEXT, "one",
     "analyst", (), (),
     "An analyst's reasoning when the assessment's status (and justification) are their own "
     "judgment rather than a source's verdict. Present means: this status is a judgment. The "
     "kit's Procedures never revise an assessment that carries one; retire it to hand the "
     "assessment back to them."),
    ("security.assessment.expected_status", ("security.assessment",), "literal",
     {"enum": ["affected", "not_affected"], "type": "string"}, "one", "normative", (), (),
     "An agent's stated bet on the assessment's status before a source observes it; "
     "predictions test it against security.assessment.status."),
    # Vulnerability facts.
    ("security.vulnerability.kev_listed", ("security.vulnerability",), "literal",
     {"type": "boolean"}, "one", "observation", (KEV_CONTRACT, OUTPUT_CONTRACT), (),
     "Whether the CISA Known Exploited Vulnerabilities catalog lists the vulnerability."),
    ("security.vulnerability.kev_date_added", ("security.vulnerability",), "literal", DATE,
     "one", "observation", (KEV_CONTRACT, OUTPUT_CONTRACT), (),
     "The date CISA added the vulnerability to the KEV catalog (dateAdded)."),
    ("security.vulnerability.kev_due_date", ("security.vulnerability",), "literal", DATE, "one",
     "observation", (KEV_CONTRACT, OUTPUT_CONTRACT), (),
     "The KEV remediation due date for federal agencies (dueDate)."),
    ("security.vulnerability.kev_ransomware_use", ("security.vulnerability",), "literal",
     {"enum": ["known", "unknown"], "type": "string"}, "one", "observation",
     (KEV_CONTRACT, OUTPUT_CONTRACT), (),
     "Whether KEV reports known ransomware campaign use (knownRansomwareCampaignUse)."),
    ("security.vulnerability.epss_score", ("security.vulnerability",), "literal", PROBABILITY,
     "one", "observation", (EPSS_CONTRACT,), ("trim",),
     "FIRST's EPSS probability of exploitation in the next 30 days, as the daily file states it."),
    ("security.vulnerability.epss_percentile", ("security.vulnerability",), "literal",
     PROBABILITY, "one", "observation", (EPSS_CONTRACT,), ("trim",),
     "The EPSS score's percentile among all scored CVEs, as the daily file states it."),
    ("security.vulnerability.title", ("security.vulnerability",), "literal", TEXT,
     "one", "observation", (CVE_CONTRACT, KEV_CONTRACT), (),
     "The vulnerability's title as a retained source states it."),
    ("security.vulnerability.vendor_product", ("security.vulnerability",), "literal",
     TEXT, "one", "observation", (CVE_CONTRACT, KEV_CONTRACT), (),
     "The affected vendor and product as a retained source states it."),
    ("security.vulnerability.watch_reason", ("security.vulnerability",), "literal", TEXT,
     "one", "normative", (), (),
     "The decision to track the vulnerability, and why. A vulnerability is tracked when it has "
     "one, or when an affected or inconclusive assessment links it to a release in inventory; "
     "a bare vulnerability Subject is tracked by nothing."),
    # Remediation work.
    ("security.control.activation", ("security.control",), "literal",
     {"enum": ["declared_active", "planned", "retired"], "type": "string"}, "one", "normative",
     (), (), "Whether the compensating control is active."),
    ("security.control.kind", ("security.control",), "literal",
     {"enum": ["access_restriction", "monitoring", "network_isolation"], "type": "string"},
     "one", "normative", (), (), "The kind of compensating control."),
    ("security.exception.approval", ("security.exception",), "literal",
     {"enum": ["approved", "revoked"], "type": "string"}, "one", "normative", (), (),
     "Whether the risk exception is approved."),
    ("security.exception.expires_at", ("security.exception",), "literal", DATETIME, "one",
     "normative", (), (), "When the risk exception expires."),
    ("security.remediation.due_at", ("security.remediation",), "literal", DATETIME, "one",
     "normative", (), (), "When the remediation is due."),
    ("security.remediation.progress", ("security.remediation",), "literal",
     {"enum": ["cancelled", "completed", "in_progress", "planned"], "type": "string"}, "one",
     "normative", (), (), "Where the remediation stands."),
    ("security.remediation.target_release", ("security.remediation",), "subject",
     ("security.release",), "one", "normative", (), (), "The release the remediation moves to."),
    ("security.work.assessment", WORK, "subject", ("security.assessment",), "one", "normative",
     (), (), "The assessment this work item answers."),
    ("security.work.asset", WORK, "subject", ("security.asset",), "one", "normative", (), (),
     "The asset this work item covers."),
    ("security.work.owner", WORK, "subject", ("security.team",), "one", "normative", (), (),
     "The team accountable for this work item."),
    ("security.work.rationale", WORK, "literal", TEXT, "one", "normative", (), (),
     "Why this work item exists."),
    ("security.work.review_at", WORK, "literal", DATETIME, "one", "normative", (), (),
     "When this work item is next reviewed."),
    ("security.work.verification", WORK, "literal",
     {"enum": ["failed", "inconclusive", "verified"], "type": "string"}, "one", "observation",
     (OUTPUT_CONTRACT,), (), "Whether the work was verified, as observed from retained evidence."),
]
# 1.1.0 adds the CWE identifiers KEV lists (a gate fixture for kit upgrades).
CLAIM_TYPES_1_1: list[ClaimRow] = [
    ("security.vulnerability.kev_cwes", ("security.vulnerability",), "literal", TEXT, "many",
     "observation", (KEV_CONTRACT, OUTPUT_CONTRACT), ("trim",),
     "A CWE identifier the KEV catalog lists for the vulnerability (cwes)."),
]

#: kind -> (key predicates in key order, uniqueness) or None for a minted kind.
SUBJECT_KINDS: dict[str, tuple[tuple[str, ...], str] | None] = {
    "security.vulnerability": (("security.vulnerability.cve_id",), "unique"),
    "security.release": (("security.release.product_name", "security.release.version"), "unique"),
    "security.assessment": (
        ("security.assessment.release_id", "security.assessment.cve_id"), "unique"),
    "security.asset": (("security.asset.hostname",), "unique"),
    "security.product": (("security.product.name",), "hint"),
    "security.supplier": (("security.supplier.name",), "hint"),
    "security.team": (("security.team.name",), "hint"),
    "security.service": (("security.service.name",), "hint"),
    "security.remediation": None,
    "security.exception": None,
    "security.control": None,
}
SUBJECT_KIND_DESCRIPTIONS = {
    "security.vulnerability": "A CVE, named by its id. Tracked when it has a watch_reason or an "
    "affected/inconclusive assessment; existing alone tracks nothing.",
    "security.release": "One version of a product, named by product name and version.",
    "security.assessment": "Whether one release is affected by one CVE: one per pair.",
    "security.asset": "A host, named by its hostname.",
    "security.product": "A software product, named by its name.",
    "security.supplier": "A product's supplier, named by its name.",
    "security.team": "An accountable team, named by its name.",
    "security.service": "A business service, named by its name.",
    "security.remediation": "A remediation work item (minted id).",
    "security.exception": "A risk exception (minted id).",
    "security.control": "A compensating control (minted id).",
}


def _rule(rule_id: str, role: str, contracts: tuple[str, ...]) -> ClaimEvidenceAdmissionRule:
    return ClaimEvidenceAdmissionRule(
        rule_id=rule_id,
        claim_roles=(role,),  # type: ignore[arg-type]
        capture_contracts=tuple(
            ArtifactRef(
                role="capture-contract",
                target=ArtifactIdentity(kind="CaptureContract", name=name),
            )
            for name in sorted(contracts)
        ),
        evidence_kinds=tuple(sorted({EVIDENCE_KINDS.get(c, "http_response") for c in contracts})),
        admission="direct",
        subject_binding="exact_claim_subject",
    )


def _evidence(role: str, contracts: tuple[str, ...]) -> tuple[
    tuple[str, ...], str, tuple[ClaimEvidenceAdmissionRule, ...], str
]:
    """(permitted roles, default role, evidence rules, evidence requirement) for a row.

    ``judged``: a source's verdict (observation, citing a kit Capture) or an analyst's
    judgment (normative, citing their own words or a workspace file); writes default to
    the judgment. ``analyst``: normative only, judgment evidence. ``sourced``: a
    normative relationship citing its author's words or the source Capture a Procedure
    read it from. Otherwise one role:
    an observation needs a Capture under its contracts, a normative statement is
    supported by its own origin.
    """

    if role == "judged":
        return (
            ("normative", "observation"), "normative",
            (_rule("analyst-judgment", "normative", JUDGMENT_EVIDENCE),
             _rule("source-verdict", "observation", contracts)),
            "self",
        )
    if role == "sourced":
        # A relationship a Procedure reads from a source (an SBOM, an OSV answer, a
        # CVE record) cites that Capture; one a person states cites their own words.
        return (
            ("normative",), "normative",
            (_rule("own-words", "normative", (SELF_SOURCE_CONTRACT,)),
             _rule("stated-by-source", "normative", contracts)),
            "self",
        )
    if role == "analyst":
        return (("normative",), "normative",
                (_rule("analyst-judgment", "normative", JUDGMENT_EVIDENCE),), "self")
    if not contracts:
        return (role,), role, (), "none"
    return (role,), role, (_rule("retained-security-evidence", role, contracts),), "captured"


def claim_types(release: str) -> list[ClaimType]:
    rows = CLAIM_TYPES + (CLAIM_TYPES_1_1 if release != "1.0.0" else [])
    result = []
    for predicate, kinds, obj, shape, cardinality, role, contracts, form, description in rows:
        roles, default_role, rules, requirement = _evidence(role, contracts)
        members = ()
        if predicate == "security.assessment.justification":
            members = tuple(
                ClaimTypeMemberDescription(member=name, description=text)
                for name, text in sorted(JUSTIFICATIONS.items())
            )
        result.append(
            ClaimType(
                artifact_format="playbill-claim-type-v8",
                identity=ArtifactIdentity(kind="ClaimType", name=predicate),
                predicate=predicate,
                allowed_subject_kinds=tuple(sorted(kinds)),
                object_kind=obj,  # type: ignore[arg-type]
                literal_schema=shape if obj == "literal" else None,
                allowed_object_subject_kinds=tuple(shape) if obj == "subject" else (),
                cardinality=cardinality,  # type: ignore[arg-type]
                permitted_roles=roles,  # type: ignore[arg-type]
                evidence_admission_policy=ClaimEvidenceAdmissionPolicy(rules=rules),
                admission_policy=ClaimAdmissionPolicy(),
                resolution_policy=ClaimResolutionPolicy(
                    cardinality=cardinality,  # type: ignore[arg-type]
                    eligible_verdicts=("supported",),
                    selector="only_contender" if cardinality == "one" else "all",
                ),
                description=description,
                member_descriptions=members,
                default_role=default_role,  # type: ignore[arg-type]
                evidence_requirement=requirement,  # type: ignore[arg-type]
                revision_evidence="replace",
                canonical_form=tuple(form) if obj == "literal" else (),
            )
        )
    return result


# --- QueryDefinitions ---------------------------------------------------------

VULNERABILITY_PARAMETER = QueryParameterDeclaration(
    name="vulnerability", value_type="subject_reference"
)


def _field(name: str, binding: str, predicate: str | None = None) -> QueryProjectionField:
    return QueryProjectionField(
        name=name,
        value=QueryClaimValueRef(binding=binding, predicate=predicate)
        if predicate
        else QuerySubjectFieldRef(binding=binding, field="subject_id"),
    )


def _cmp(binding: str, predicate: str, value: Any, value_type: str = "string") -> Any:
    return QueryComparisonFilter(
        left=QueryClaimValueRef(binding=binding, predicate=predicate),
        operator="eq",
        right=QueryLiteralRef(value=value),
        value_type=value_type,  # type: ignore[arg-type]
    )


def _sorted(filters: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple(sorted(filters, key=lambda f: canonical_bytes(f.model_dump(mode="json"))))


def _all(*filters: Any) -> QueryConjunctionFilter:
    return QueryConjunctionFilter(filters=_sorted(filters))


def _any(*filters: Any) -> QueryDisjunctionFilter:
    return QueryDisjunctionFilter(filters=_sorted(filters))


def _missing(binding: str, predicate: str) -> QueryClaimPresenceFilter:
    return QueryClaimPresenceFilter(binding=binding, predicate=predicate, negated=True)


def _hop(
    binding: str, source: str, predicate: str, target: str, *, required: bool = False,
    reverse: bool = False, where: Any = None,
) -> QueryTraversalStep:
    return QueryTraversalStep(
        binding=binding,
        from_binding=source,
        predicate=predicate,
        direction="reverse" if reverse else "forward",
        required=required,
        target_subject_kinds=("security." + target,),
        where=where,
    )


def _query(
    name: str, description: str, entry: str, kind: str, hops: list[Any], fields: list[Any],
    where: Any = None, *, parameters: tuple[QueryParameterDeclaration, ...] = (),
    shape: str = "path", max_results: int = 200, orderings: tuple[QueryOrdering, ...] = (),
    dedupe: str | None = None,
) -> QueryDefinitionSpec:
    return QueryDefinitionSpec(
        identity=ArtifactIdentity(kind="QueryDefinition", name=name),
        description=description
        + ". Scoped to supported, current Claims; missing evidence is not a negative finding.",
        entry=QueryEntry(binding=entry, subject_kinds=("security." + kind,)),
        traversal=tuple(hops),
        where=where,
        result_binding=entry,
        result_shape=shape,  # type: ignore[arg-type]
        result_cardinality="many",
        dedupe=dedupe or ("path" if shape == "path" else "subject"),  # type: ignore[arg-type]
        projection=QueryProjection(fields=tuple(sorted(fields, key=lambda x: x.name))),
        parameters=parameters,
        orderings=orderings,
        evaluation_policy=QueryEvaluationPolicy(
            visible_verdicts=("supported",),
            visible_currency=("current",),
            conflict_behavior="surface_conflicts",
        ),
        default_budgets=QueryBudgets(
            max_results=max_results, max_traversal_depth=10, max_paths=20000,
            max_paths_per_result=100,
        )
        if shape == "path"
        else QueryBudgets(max_results=max_results, max_traversal_depth=1),
        maximum_budgets=QueryBudgets(
            max_results=2000, max_traversal_depth=10, max_paths=20000, max_paths_per_result=1000
        )
        if shape == "path"
        else QueryBudgets(max_results=2000, max_traversal_depth=1),
    )


def _work_predicate(kind: str, field: str) -> str:
    aliases = {"status": {"remediation": "remediation.progress", "exception": "exception.approval",
                          "control": "control.activation"}}
    if field == "status":
        return "security." + aliases["status"][kind]
    if field in {"asset", "assessment", "owner", "rationale", "review_at", "verification"}:
        return "security.work." + field
    return f"security.{kind}.{field}"


def _order(binding: str, predicate: str, value_type: str) -> QueryOrdering:
    return QueryOrdering(
        key=QueryClaimValueRef(binding=binding, predicate=predicate),
        direction="descending",
        value_type=value_type,  # type: ignore[arg-type]
    )


VULNERABILITY_FACTS = ("kev_listed", "kev_due_date", "epss_score", "epss_percentile")


def query_definitions(release: str) -> list[QueryDefinitionSpec]:
    q: list[QueryDefinitionSpec] = []
    vuln_ref = QueryParameterRef(parameter="vulnerability")
    on_vulnerability = QueryComparisonFilter(
        left=QueryClaimValueRef(
            binding="assessment", predicate="security.assessment.vulnerability"
        ),
        operator="eq",
        right=vuln_ref,
        value_type="subject_reference",
    )
    # Inventory joins.
    inventory_hops = [
        _hop("release", "asset", "security.asset.installs", "release"),
        _hop("product", "release", "security.release.product", "product"),
        _hop("supplier", "product", "security.product.supplied_by", "supplier"),
        _hop("service", "asset", "security.asset.serves", "service"),
        _hop("team", "service", "security.service.owned_by", "team"),
    ]
    q.append(_query(
        "security.inventory_context", "Assets with their releases, products, suppliers, services "
        "and owning teams", "asset", "asset", inventory_hops,
        [_field(b, b) for b in ("asset", "release", "product", "supplier", "service", "team")]
        + [_field("environment", "asset", "security.asset.environment"),
           _field("internet_exposed", "asset", "security.asset.internet_exposed"),
           _field("version", "release", "security.release.version"),
           _field("criticality", "service", "security.service.criticality")],
    ))
    # Every release with its key, product, supplier and SBOM components: the
    # import, applicability and attention Procedures' state tap.
    q.append(_query(
        "security.release_inventory", "Every release with its product, supplier and components",
        "release", "release",
        [_hop("product", "release", "security.release.product", "product"),
         _hop("supplier", "product", "security.product.supplied_by", "supplier")],
        [_field("release", "release"), _field("product", "product"),
         _field("supplier", "supplier"),
         _field("product_name", "release", "security.release.product_name"),
         _field("version", "release", "security.release.version"),
         _field("supplier_name", "supplier", "security.supplier.name"),
         _field("components", "release", "security.release.component")],
        max_results=2000,
    ))
    # Every assessment with its key, status and justification: what applicability
    # and attention compare with.
    q.append(_query(
        "security.assessment_index", "Every assessment with its key, status and justification",
        "assessment", "assessment",
        [_hop("release", "assessment", "security.assessment.release", "release"),
         _hop("vulnerability", "assessment", "security.assessment.vulnerability",
              "vulnerability")],
        [_field("assessment", "assessment"), _field("release", "release"),
         _field("vulnerability", "vulnerability"),
         _field("release_id", "assessment", "security.assessment.release_id"),
         _field("cve_id", "assessment", "security.assessment.cve_id"),
         _field("status", "assessment", "security.assessment.status"),
         _field("justification", "assessment", "security.assessment.justification"),
         _field("expected_status", "assessment", "security.assessment.expected_status"),
         _field("judgment", "assessment", "security.assessment.judgment")],
        max_results=2000,
    ))
    # Applicability for one vulnerability: every installed release with its assessment.
    applicability = [
        _hop("release", "asset", "security.asset.installs", "release", required=True),
        _hop("assessment", "release", "security.assessment.release", "assessment", reverse=True,
             where=on_vulnerability),
        _hop("vulnerability", "assessment", "security.assessment.vulnerability", "vulnerability"),
        _hop("service", "asset", "security.asset.serves", "service"),
        _hop("team", "service", "security.service.owned_by", "team"),
    ]
    applicability_fields = [_field(b, b) for b in ("asset", "release", "assessment", "service",
                                                   "team")] + [
        _field("internet_exposed", "asset", "security.asset.internet_exposed"),
        _field("criticality", "service", "security.service.criticality"),
        _field("status", "assessment", "security.assessment.status"),
        _field("justification", "assessment", "security.assessment.justification"),
        _field("judgment", "assessment", "security.assessment.judgment"),
        _field("version", "release", "security.release.version"),
    ]
    q.append(_query(
        "security.applicability_coverage", "Every installed release with its assessment for one "
        "vulnerability", "asset", "asset", applicability, applicability_fields,
        parameters=(VULNERABILITY_PARAMETER,),
    ))
    # KEV exposure: affected, internet-facing assets of any KEV-listed vulnerability.
    exposure_hops = [
        _hop("release", "asset", "security.asset.installs", "release", required=True),
        _hop("assessment", "release", "security.assessment.release", "assessment", reverse=True,
             required=True),
        _hop("vulnerability", "assessment", "security.assessment.vulnerability", "vulnerability",
             required=True),
        _hop("service", "asset", "security.asset.serves", "service"),
        _hop("team", "service", "security.service.owned_by", "team"),
    ]
    q.append(_query(
        "security.kev_exposure", "Internet-facing assets with a release assessed affected by a "
        "KEV-listed vulnerability", "asset", "asset", exposure_hops,
        [_field(b, b) for b in ("asset", "release", "assessment", "vulnerability", "service",
                                "team")]
        + [_field("status", "assessment", "security.assessment.status"),
           _field("kev_due_date", "vulnerability", "security.vulnerability.kev_due_date"),
           _field("criticality", "service", "security.service.criticality")],
        _all(_cmp("assessment", "security.assessment.status", "affected"),
             _cmp("asset", "security.asset.internet_exposed", True, "boolean"),
             _cmp("vulnerability", "security.vulnerability.kev_listed", True, "boolean")),
        max_results=100 if release == "1.0.0" else 500,
    ))
    # Urgent exposures: every release assessed affected, KEV-listed first, then by EPSS,
    # with the assets that install it.
    q.append(_query(
        "security.urgent_exposures", "Every release assessed affected, KEV-listed first, then by "
        "EPSS score, with the assets that install it", "assessment", "assessment",
        [_hop("vulnerability", "assessment", "security.assessment.vulnerability",
              "vulnerability", required=True),
         _hop("release", "assessment", "security.assessment.release", "release", required=True),
         _hop("asset", "release", "security.asset.installs", "asset", reverse=True),
         _hop("service", "asset", "security.asset.serves", "service"),
         _hop("team", "service", "security.service.owned_by", "team")],
        [_field(b, b) for b in ("assessment", "vulnerability", "release", "asset", "service",
                                "team")]
        + [_field("cve_id", "vulnerability", "security.vulnerability.cve_id"),
           _field("product_name", "release", "security.release.product_name"),
           _field("version", "release", "security.release.version"),
           _field("internet_exposed", "asset", "security.asset.internet_exposed"),
           _field("criticality", "service", "security.service.criticality"),
           _field("judgment", "assessment", "security.assessment.judgment")]
        + [_field(name, "vulnerability", "security.vulnerability." + name)
           for name in VULNERABILITY_FACTS],
        _cmp("assessment", "security.assessment.status", "affected"),
        orderings=(_order("vulnerability", "security.vulnerability.kev_listed", "boolean"),
                   _order("vulnerability", "security.vulnerability.epss_score", "decimal")),
        max_results=500,
    ))
    # Operations worklists.
    rh = [
        _hop("asset", "action", "security.work.asset", "asset"),
        _hop("assessment", "action", "security.work.assessment", "assessment"),
        _hop("owner", "action", "security.work.owner", "team"),
        _hop("target", "action", "security.remediation.target_release", "release"),
    ]
    rf = [_field("action", "action"), _field("asset", "asset"),
          _field("assessment", "assessment"), _field("owner", "owner"),
          _field("target_release", "target")] + [
        _field(n, "action", _work_predicate("remediation", n))
        for n in ("status", "due_at", "rationale", "verification")
    ]
    q.append(_query("security.remediation_work", "Remediation actions and verification",
                    "action", "remediation", rh, rf))
    q.append(_query(
        "security.incomplete_work", "Remediation actions missing accountable information",
        "action", "remediation", rh, rf,
        _any(*[_missing("action", _work_predicate("remediation", n))
               for n in ("asset", "assessment", "owner", "target_release", "status", "due_at")]),
    ))
    for kind in ("exception", "control"):
        hops = [_hop(b, kind, _work_predicate(kind, b), t)
                for b, t in (("asset", "asset"), ("assessment", "assessment"), ("owner", "team"))]
        names = (("status", "rationale", "review_at", "expires_at") if kind == "exception"
                 else ("kind", "status", "rationale", "review_at", "verification"))
        fields = ([_field(kind, kind)] + [_field(b, b) for b in ("asset", "assessment", "owner")]
                  + [_field(n, kind, _work_predicate(kind, n)) for n in names])
        q.append(_query(
            "security.exceptions" if kind == "exception" else "security.controls",
            "Scoped risk exceptions and expiry" if kind == "exception"
            else "Compensating controls and evidence", kind, kind, hops, fields))
        if kind == "exception":
            expired = QueryComparisonFilter(
                left=QueryClaimValueRef(binding="exception",
                                        predicate="security.exception.expires_at"),
                operator="lte", right=QueryEvaluationTimeRef(), value_type="timestamp")
            q.append(_query(
                "security.expired_exceptions", "Expired approved exceptions requiring review",
                kind, kind, hops, fields,
                _all(expired, _cmp(kind, "security.exception.approval", "approved"))))
    # Vulnerability-scoped worklists.
    triage_fields = applicability_fields + [
        _field("vulnerability", "vulnerability")] + [
        _field(name, "vulnerability", "security.vulnerability." + name)
        for name in VULNERABILITY_FACTS]
    q.append(_query("security.triage", "Applicability, exposure, KEV and EPSS facts for one "
                    "vulnerability", "asset", "asset", applicability, triage_fields,
                    parameters=(VULNERABILITY_PARAMETER,)))
    q.append(_query(
        "security.coverage_gaps", "Installed releases unassessed or inconclusive for one "
        "vulnerability", "asset", "asset", applicability, applicability_fields,
        _any(_missing("assessment", "security.assessment.status"),
             _cmp("assessment", "security.assessment.status", "inconclusive")),
        parameters=(VULNERABILITY_PARAMETER,)))
    q.append(_query("security.ownership_gaps", "Assets serving a service with no owning team",
                    "asset", "asset", applicability[:1] + applicability[3:4],
                    [_field("asset", "asset"), _field("release", "release"),
                     _field("service", "service")],
                    _missing("service", "security.service.owned_by")))
    q.append(_query("security.supplier_concentration", "Shared component and supplier "
                    "dependencies", "asset", "asset", inventory_hops,
                    [_field(b, b) for b in ("asset", "release", "product", "supplier", "service",
                                            "team")]))
    impact = applicability + [
        _hop("action", "asset", "security.work.asset", "remediation", reverse=True)]
    q.append(_query(
        "security.change_impact", "Asset links to one vulnerability's assessments and "
        "remediation", "asset", "asset", impact,
        applicability_fields + [_field("action", "action"),
                                _field("action_status", "action",
                                       "security.remediation.progress")],
        parameters=(VULNERABILITY_PARAMETER,)))
    # Watched is derived, never implied by existence: a vulnerability is watched when
    # an agent decided to track it (a watch_reason Claim) or when an affected or
    # inconclusive assessment links it to a release in inventory.
    tracked_hop = _hop("assessment", "vulnerability", "security.assessment.vulnerability",
                       "assessment", reverse=True)
    tracked = _any(
        QueryClaimPresenceFilter(binding="vulnerability",
                                 predicate="security.vulnerability.watch_reason"),
        _all(QueryClaimPresenceFilter(binding="assessment",
                                      predicate="security.assessment.release"),
             _any(_cmp("assessment", "security.assessment.status", "affected"),
                  _cmp("assessment", "security.assessment.status", "inconclusive"))),
    )
    # The triage and applicability Procedures' state tap.
    q.append(_query(
        "security.watched_vulnerabilities", "Every watched vulnerability (a watch_reason, or an "
        "affected or inconclusive assessment of a release in inventory) with its current KEV "
        "and EPSS Claims", "vulnerability", "vulnerability", [tracked_hop],
        [_field("vulnerability", "vulnerability"),
         _field("cve_id", "vulnerability", "security.vulnerability.cve_id"),
         _field("watch_reason", "vulnerability", "security.vulnerability.watch_reason")] + [
            _field(name, "vulnerability", "security.vulnerability." + name)
            for name in ("kev_listed", "kev_date_added", "kev_due_date", "kev_ransomware_use",
                         "epss_score", "epss_percentile")],
        # Path-shaped (core admits an optional hop only there), so a vulnerability with
        # several qualifying assessments is several rows: the Procedures read it once.
        tracked, max_results=2000))
    # The settle mandates' condition: the changed Claim's Subject is a keyed
    # vulnerability. Core requires a condition on every settle grant, and that it
    # return exactly one row per target. "Watched" (a watch_reason OR an affected or
    # inconclusive assessment) needs an optional hop, which core admits only in a
    # path-shaped query, whose rows are per path, not per Subject; so the condition
    # cannot re-derive it. The triage Procedures only ever change watched
    # vulnerabilities (their state tap is the derivation), so the grant's scope (the
    # verbatim KEV and EPSS fields) is what decides what settles.
    q.append(QueryDefinitionSpec(
        identity=ArtifactIdentity(kind="QueryDefinition", name="security.settle_condition"),
        description=(
            "One vulnerability by id with its CVE key; the condition the KEV and EPSS triage "
            "settle mandates evaluate per changed Claim (triage only changes watched ones)."
        ),
        entry=QueryEntry(binding="vulnerability", subject_kinds=("security.vulnerability",),
                         subject_id=QueryParameterRef(parameter="vulnerability_id")),
        result_binding="vulnerability",
        result_shape="subject",
        result_cardinality="many",
        dedupe="subject",
        projection=QueryProjection(fields=(
            _field("cve_id", "vulnerability", "security.vulnerability.cve_id"),
            _field("vulnerability", "vulnerability"),
        )),
        parameters=(QueryParameterDeclaration(name="vulnerability_id", value_type="string"),),
        evaluation_policy=QueryEvaluationPolicy(
            visible_verdicts=("supported",), visible_currency=("current",),
            conflict_behavior="surface_conflicts"),
        default_budgets=QueryBudgets(max_results=1, max_traversal_depth=1),
        maximum_budgets=QueryBudgets(max_results=10, max_traversal_depth=1),
    ))
    # The triage measurement target: open assessments of KEV-listed vulnerabilities.
    q.append(_query(
        "security.kev_triage_backlog", "Assessments of KEV-listed vulnerabilities still "
        "unresolved (no status, or inconclusive)", "assessment", "assessment",
        [_hop("vulnerability", "assessment", "security.assessment.vulnerability",
              "vulnerability", required=True),
         _hop("release", "assessment", "security.assessment.release", "release")],
        [_field("assessment", "assessment"), _field("vulnerability", "vulnerability"),
         _field("release", "release"),
         _field("status", "assessment", "security.assessment.status")],
        _all(_cmp("vulnerability", "security.vulnerability.kev_listed", True, "boolean"),
             _any(_missing("assessment", "security.assessment.status"),
                  _cmp("assessment", "security.assessment.status", "inconclusive")))))
    return q


# --- CaptureContracts and the acquisition policy -------------------------------


def capture_contracts() -> list[CaptureContract]:
    raw = json.loads((DATA / "capture_contracts.json").read_text())
    template = next(item for item in raw if item["identity"]["name"] == KEV_CONTRACT)

    def derived(name: str, source: str, kinds: list[str], evidence: str) -> dict[str, Any]:
        item = json.loads(json.dumps(template))
        item["identity"]["name"] = name
        item["logical_source_identities"] = [source]
        item["allowed_source_kinds"] = kinds
        item["evidence_kinds"] = [evidence]
        return item

    raw += [
        derived(OSV_CONTRACT, "osv.dev.query", ["external"], "http_response"),
        derived(EPSS_CONTRACT, "first.epss.daily", ["external"], "http_response"),
        derived(SBOM_CONTRACT, "cyclonedx.sbom", ["external"], "sbom_document"),
        derived(WORKSPACE_EVIDENCE_CONTRACT, "security.analysis.evidence", ["external"],
                "workspace_file"),
    ]
    return [CaptureContract.model_validate(item) for item in raw]


def acquisition_policy() -> SourceAcquisitionPolicy:
    """`security.acquisition` covers every Source alias the kit uses: `catalog` (KEV),
    `record` (CVE record), `epss`, `osv`, `sbom` and `evidence` (an analyst's
    workspace file). Each is required, at most 24 h
    old, refused when stale, unavailable or oversized. Network Captures replay as
    attested; the SBOM, a workspace file, replays exactly."""

    def rule(alias: str, replayability: str = "attested_only") -> dict[str, Any]:
        return {
            "conservative_default": None,
            "correlation_keys": [],
            "input_name": alias,
            "join_semantics_digest": None,
            "max_age": {"microseconds": 24 * 3_600_000_000},
            "on_conflict": "preserve",
            "on_oversized": "refuse",
            "on_stale": "refuse",
            "on_unavailable": "refuse",
            "permitted_replayability": [replayability],
            "requirement": "required",
        }

    return SourceAcquisitionPolicy.model_validate(
        {
            "coherence": {"kind": "independent"},
            "identity": {"kind": "SourceAcquisitionPolicy", "name": POLICY},
            "inputs": [rule("catalog"), rule("epss"), rule("evidence", "exact"), rule("osv"),
                       rule("record"), rule("sbom", "exact")],
        }
    )


# --- Blueprints and Procedures ------------------------------------------------


def _contract(name: str, **fields: PropertySchema) -> CarriedContractInput:
    return CarriedContractInput(name=name, fields=fields, allow_extra=False)


def _ints(*names: str) -> dict[str, PropertySchema]:
    return {name: PropertySchema(type="integer") for name in names}


EMPTY = _contract("security-empty-input")
URL_INPUT = _contract("security-url-input", url=PropertySchema(type="string"))
PATH_INPUT = _contract("security-path-input", relative_path=PropertySchema(type="string"))
HTTP_SUMMARY = _contract(
    "security-http-evidence",
    url=PropertySchema(type="string"),
    status=PropertySchema(type="int"),
    body_digest=PropertySchema(type="string"),
)
FILE_SUMMARY = _contract(
    "security-file-evidence",
    bytes_digest=PropertySchema(type="string"),
    byte_length=PropertySchema(type="integer"),
)
KEV_REQUEST = _contract(
    "security-kev-catalog-request",
    catalog_base64=PropertySchema(type="string"),
    watched=PropertySchema(type="json"),
)
KEV_RESULT = _contract(
    "security-kev-catalog-result",
    items=PropertySchema(type="json"),
    catalog_version=PropertySchema(type="string"),
    **_ints("changed", "watched", "listed", "catalog_count"),
)
TRIAGE_SUMMARY = _contract(
    "security-kev-triage-summary",
    catalog_version=PropertySchema(type="string"),
    **_ints("changed", "watched", "listed"),
)
ATTENTION_REQUEST = _contract(
    "security-kev-attention-request",
    catalog_base64=PropertySchema(type="string"),
    releases=PropertySchema(type="json"),
    watched=PropertySchema(type="json"),
    assessments=PropertySchema(type="json"),
)
ATTENTION_RESULT = _contract(
    "security-kev-attention-result",
    items=PropertySchema(type="json"),
    catalog_version=PropertySchema(type="string"),
    **_ints("posted", "newly_listed"),
)
ATTENTION_SUMMARY = _contract(
    "security-kev-attention-summary",
    catalog_version=PropertySchema(type="string"),
    **_ints("posted", "newly_listed"),
)
EPSS_REQUEST = _contract(
    "security-epss-request",
    daily_base64=PropertySchema(type="string"),
    watched=PropertySchema(type="json"),
)
EPSS_RESULT = _contract(
    "security-epss-result",
    items=PropertySchema(type="json"),
    model_version=PropertySchema(type="string"),
    score_date=PropertySchema(type="string"),
    **_ints("changed", "watched", "scored"),
)
EPSS_SUMMARY = _contract(
    "security-epss-summary",
    model_version=PropertySchema(type="string"),
    score_date=PropertySchema(type="string"),
    **_ints("changed", "watched", "scored"),
)
SBOM_REQUEST = _contract(
    "security-sbom-request",
    sbom_text=PropertySchema(type="string"),
    releases=PropertySchema(type="json"),
)
SBOM_RESULT = _contract(
    "security-sbom-result",
    items=PropertySchema(type="json"),
    product=PropertySchema(type="string"),
    version=PropertySchema(type="string"),
    **_ints("changed", "components", "added", "skipped"),
)
SBOM_SUMMARY = _contract(
    "security-sbom-summary",
    product=PropertySchema(type="string"),
    version=PropertySchema(type="string"),
    **_ints("changed", "components", "added", "skipped"),
)
OSV_REQUEST = _contract(
    "security-osv-applicability-request",
    osv=PropertySchema(type="json"),
    releases=PropertySchema(type="json"),
    watched=PropertySchema(type="json"),
    assessments=PropertySchema(type="json"),
)
OSV_RESULT = _contract(
    "security-osv-applicability-result",
    items=PropertySchema(type="json"),
    unkeyed=PropertySchema(type="json"),
    **_ints("changed", "affected", "not_affected", "inconclusive", "unchanged", "judged"),
)
OSV_SUMMARY = _contract(
    "security-osv-applicability-summary",
    unkeyed=PropertySchema(type="json"),
    **_ints("changed", "affected", "not_affected", "inconclusive", "unchanged", "judged"),
)
CVE_REQUEST = _contract(
    "security-cve-applicability-request",
    record_base64=PropertySchema(type="string"),
    releases=PropertySchema(type="json"),
    watched=PropertySchema(type="json"),
    assessments=PropertySchema(type="json"),
)
CVE_RESULT = _contract(
    "security-cve-applicability-result",
    items=PropertySchema(type="json"),
    cve_id=PropertySchema(type="string"),
    **_ints("changed", "affected", "not_affected", "inconclusive", "unchanged", "judged"),
)
CVE_SUMMARY = _contract(
    "security-cve-applicability-summary",
    cve_id=PropertySchema(type="string"),
    **_ints("changed", "affected", "not_affected", "inconclusive", "unchanged", "judged"),
)
EPSS_ACQUIRE_SUMMARY = _contract(
    "security-epss-evidence",
    url=PropertySchema(type="string"),
    status=PropertySchema(type="int"),
    body_digest=PropertySchema(type="string"),
)


def _seconds(value: int) -> CanonicalDuration:
    return CanonicalDuration(microseconds=value * 1_000_000)


def _fetch(url: object, logical_source: str, max_bytes: int) -> dict[str, object]:
    return {
        "url": url,
        "logical_source": logical_source,
        "expected_format": "json",
        "render": False,
        "extract": False,
        "max_bytes": max_bytes,
    }


def _summary(source: str, next: str | None = None) -> Project:
    return Project(
        "summary",
        next=next,
        fields={
            "url": f"$steps.{source}.retrieved.final_url",
            "status": f"$steps.{source}.retrieved.status_code",
            "body_digest": f"$steps.{source}.retrieved.body_sha256",
        },
        contract_out=HTTP_SUMMARY,
    )


def _changed(alias: str, field: str = "changed") -> GuardPredicate:
    return GuardPredicate(
        left=PredicateOperand(kind="step", alias=alias, path=(field,)),
        operator="gt",
        right=PredicateOperand(kind="literal", value=0),
    )


def _caps(seconds: int, calls: int, capture_bytes: int, items: int) -> ProcedureHardCaps:
    return ProcedureHardCaps(max_wall_clock=_seconds(seconds), max_provider_calls=calls,
                             max_capture_bytes=capture_bytes, max_items=items,
                             max_repeat_attempts=1)


def _budget(seconds: int, calls: int, capture_bytes: int) -> ProcedureBudget:
    return ProcedureBudget(wall_clock=_seconds(seconds), max_provider_calls=calls,
                           max_capture_bytes=capture_bytes)


def _project(summary: CarriedContractInput, alias: str, next: str) -> Project:
    return Project("summary", next=next, contract_out=summary,
                   fields={name: f"$steps.{alias}.{name}" for name in summary.fields})


def _blueprint(sequence: Sequence, interface: dict[str, Any], slot: str) -> BlueprintInput:
    """Open the Sequence's ``slot`` Source as a slot typed by ``interface``."""

    built = sequence.build()
    definition = dict(built.definition)
    nodes = []
    for node in definition["nodes"]:
        node = dict(node)
        if node["kind"] == "source" and node.get("as", node.get("node_id")) == slot:
            node["provider"] = {"kind": "slot", "slot_name": slot}
            node.pop("implementation_digest", None)
        nodes.append(node)
    definition["nodes"] = nodes
    definition["pin_slots"] = [
        {
            "slot_name": slot,
            "pin_role": "provider",
            "artifact_kind": "Provider",
            "interface_digest": interface["interface_digest"],
        }
    ]
    return BlueprintInput(kind="blueprint", definition=definition, contracts=built.contracts)


def _interface(cx: Cruxible, name: str) -> dict[str, Any]:
    from cruxible_client.contracts.get_reads import GetRequest

    read = cx._client.get(cx._instance_id, request=GetRequest(ref=f"ProviderInterface:{name}",
                                                                detail="proof"))
    assert read.proof is not None
    return dict(read.proof["entry"])


def kev_acquire(cx: Cruxible, release: str) -> BlueprintInput:
    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    budget_seconds = 60 if release == "1.0.0" else 90
    sequence = Sequence(
        [
            Source("catalog", capture_contract=KEV_CONTRACT, next="summary",
                   request=_fetch(KEV_URL, KEV_SOURCE, KEV_MAX_BYTES)),
            _summary("catalog", next="emit"),
            EmitCapture("emit", capture_contract=OUTPUT_CONTRACT, input=Output("summary"),
                        result=Output("summary")),
        ],
        name="security.kev-acquire",
        description=(
            "Fetch the CISA KEV catalog (static JSON, no rendering) and retain it under "
            "security.kev-http-v1. Interpretation is security.kev-triage's and "
            "security.kev-attention's job."
            + ("" if release == "1.0.0" else " 1.1.0: a 90 s budget.")
        ),
        contract_in=EMPTY,
        contract_out=HTTP_SUMMARY,
        acquisition_policy=POLICY,
        budget=_budget(budget_seconds, 1, 16_777_216),
        hard_caps=_caps(120, 1, 16_777_216, 1),
    ).bind(catalog=web)
    return _blueprint(sequence, _interface(cx, "web.fetch"), "catalog")


def cve_record_acquire(cx: Cruxible) -> BlueprintInput:
    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    sequence = Sequence(
        [
            Source("record", capture_contract=CVE_CONTRACT, next="summary",
                   request=_fetch("$input.url", "cve.record", CVE_MAX_BYTES)),
            _summary("record"),
        ],
        name="security.cve-record-acquire",
        description=(
            "Fetch one CVE record (pass the full https://cveawg.mitre.org/api/cve/<CVE> URL "
            "as input.url) and retain it under security.cve-record-http-v1; "
            "security.cve-applicability reads it when it lands."
        ),
        contract_in=URL_INPUT,
        contract_out=HTTP_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(60, 1, 4_194_304),
        hard_caps=_caps(120, 1, 4_194_304, 1),
    ).bind(record=web)
    return _blueprint(sequence, _interface(cx, "web.fetch"), "record")


def epss_acquire(cx: Cruxible) -> BlueprintInput:
    epss = cx.provider_interface("security.epss-daily", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("epss", capture_contract=EPSS_CONTRACT, next="summary", request={}),
            _summary("epss", next="emit"),
            EmitCapture("emit", capture_contract=OUTPUT_CONTRACT, input=Output("summary"),
                        result=Output("summary")),
        ],
        name="security.epss-acquire",
        description=(
            "Fetch FIRST's current EPSS daily scores file (gzip CSV) and retain it under "
            "security.epss-daily-v1. Interpretation is security.epss-triage's job."
        ),
        contract_in=EMPTY,
        contract_out=HTTP_SUMMARY,
        acquisition_policy=POLICY,
        budget=_budget(120, 1, 33_554_432),
        hard_caps=_caps(300, 1, 33_554_432, 1),
    ).bind(epss=epss)
    return _blueprint(sequence, _interface(cx, "security.epss-daily"), "epss")


def sbom_acquire(cx: Cruxible) -> Any:
    builtin = cx.provider_interface("workspace.file", provider=BUILTIN_PROVIDER)
    sequence = Sequence(
        [
            Source("sbom", capture_contract=SBOM_CONTRACT, next="summary", request={
                "tag": "playbill-workspace-file-source-request-v2",
                "logical_source": "cyclonedx.sbom",
                "relative_path": "$input.relative_path",
                "coordinate_type": "http-response-v1",
                "coordinate": {"revision": "working"},
                "selector_type": "whole-response-v1",
                "selector": {"whole": True},
                "replayability": "exact",
            }),
            Project("summary", contract_out=FILE_SUMMARY, fields={
                "bytes_digest": "$steps.sbom.source.bytes_digest",
                "byte_length": "$steps.sbom.source.byte_length",
            }),
        ],
        name="security.sbom-acquire",
        description=(
            "Read one CycloneDX JSON SBOM from the attached workspace (input.relative_path) and "
            "retain it under security.cyclonedx-sbom-v1; security.sbom-import reads it when it "
            "lands."
        ),
        contract_in=PATH_INPUT,
        contract_out=FILE_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(60, 1, 16_777_216),
        hard_caps=_caps(120, 1, 16_777_216, 1),
    ).bind(sbom=builtin)
    return sequence.build()


def evidence_acquire(cx: Cruxible) -> Any:
    builtin = cx.provider_interface("workspace.file", provider=BUILTIN_PROVIDER)
    sequence = Sequence(
        [
            Source("evidence", capture_contract=WORKSPACE_EVIDENCE_CONTRACT, next="summary",
                   request={
                "tag": "playbill-workspace-file-source-request-v2",
                "logical_source": "security.analysis.evidence",
                "relative_path": "$input.relative_path",
                "coordinate_type": "http-response-v1",
                "coordinate": {"revision": "working"},
                "selector_type": "whole-response-v1",
                "selector": {"whole": True},
                "replayability": "exact",
            }),
            Project("summary", contract_out=FILE_SUMMARY, fields={
                "bytes_digest": "$steps.evidence.source.bytes_digest",
                "byte_length": "$steps.evidence.source.byte_length",
            }),
        ],
        name="security.evidence-acquire",
        description=(
            "Read one workspace file an analyst cites for a judgment (input.relative_path: code, "
            "a config, an analysis note) and retain it under security.workspace-evidence-v1; "
            "cite the Capture with `cruxible set ... --capture CAP-...`."
        ),
        contract_in=PATH_INPUT,
        contract_out=FILE_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(60, 1, 16_777_216),
        hard_caps=_caps(120, 1, 16_777_216, 1),
    ).bind(evidence=builtin)
    return sequence.build()


def kev_triage(cx: Cruxible) -> Any:
    """The KEV triage Procedure. Its terminal is settle_change_set: under a Line capped
    at propose (or with only a propose mandate) it proposes, and a Line graduates to
    settling by raising max_authority and adding a settle mandate, with the same
    Procedure digest and so the same track record."""

    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    kev = cx.provider_interface("security.kev-catalog", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("catalog", capture_contract=KEV_CONTRACT, next="watched",
                   request=_fetch(KEV_URL, KEV_SOURCE, KEV_MAX_BYTES)),
            StateTap("watched", query="security.watched_vulnerabilities", next="parse"),
            Call("parse", contract_in=KEV_REQUEST, contract_out=KEV_RESULT, next="summary",
                 input={"catalog_base64": "$steps.catalog.retrieved.body_base64",
                        "watched": "$steps.watched.result.rows"}),
            _project(TRIAGE_SUMMARY, "parse", "changed"),
            Guard("changed", predicate=_changed("parse"), on_true="settle", on_false="nochange",
                  refusal_code="no_change", message="The catalog changes no watched Claim."),
            SettleChangeSet("settle", candidate_templates={"items": "$steps.parse.items"},
                            result=Output("summary")),
            Halt("nochange", reason="no_change"),
        ],
        name="security.kev-triage",
        description=(
            "Read the KEV catalog Capture that triggered the Line (security.kev-http-v1) and "
            "the watched vulnerabilities, and settle one observation Claim per KEV field that "
            "changed (kev_listed, kev_date_added, kev_due_date, kev_ransomware_use) under a "
            "settle mandate, or propose it under a propose cap. Halts no_change when nothing "
            "changed. Runs as a Line with trigger_input catalog."
        ),
        contract_in=EMPTY,
        contract_out=TRIAGE_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 5000),
    ).bind(catalog=web, parse=kev)
    built = sequence.build()
    definition = dict(built.definition)
    definition["measurements"] = [_backlog_measurement()]
    return built.model_copy(update={"definition": definition})


def kev_attention(cx: Cruxible) -> Any:
    """KEV attention: inbox items for newly listed CVEs matching unwatched or unassessed
    inventory. Observe-only (post_inbox), so its Line needs no mandate."""

    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    attention = cx.provider_interface("security.kev-attention", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("catalog", capture_contract=KEV_CONTRACT, next="releases",
                   request=_fetch(KEV_URL, KEV_SOURCE, KEV_MAX_BYTES)),
            StateTap("releases", query="security.release_inventory", next="watched"),
            StateTap("watched", query="security.watched_vulnerabilities", next="assessments"),
            StateTap("assessments", query="security.assessment_index", next="match"),
            Call("match", contract_in=ATTENTION_REQUEST, contract_out=ATTENTION_RESULT,
                 next="summary",
                 input={"catalog_base64": "$steps.catalog.retrieved.body_base64",
                        "releases": "$steps.releases.result.rows",
                        "watched": "$steps.watched.result.rows",
                        "assessments": "$steps.assessments.result.rows"}),
            _project(ATTENTION_SUMMARY, "match", "posted"),
            Guard("posted", predicate=_changed("match", "posted"), on_true="post",
                  on_false="quiet", refusal_code="nothing_to_post",
                  message="No newly listed CVE matches unwatched or unassessed inventory."),
            PostInbox("post", input={"items": Output("match", "items")}, max_items=1000),
            Halt("quiet", reason="nothing_to_post"),
        ],
        name="security.kev-attention",
        description=(
            "Read the KEV catalog Capture that triggered the Line and post one inbox item per "
            "CVE added in the catalog's last 7 days whose vendor/product matches a release in "
            "inventory that nobody watches the CVE for or nobody has assessed: possibly "
            "exposed, nobody has looked. Never changes accepted state. Runs as a Line with "
            "trigger_input catalog."
        ),
        contract_in=EMPTY,
        contract_out=ATTENTION_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 1000),
    ).bind(catalog=web, match=attention)
    return sequence.build()


def epss_triage(cx: Cruxible) -> Any:
    sources = cx.provider_interface("security.epss-daily", provider=SOURCES_PROVIDER)
    scores = cx.provider_interface("security.epss-scores", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("epss", capture_contract=EPSS_CONTRACT, next="watched", request={}),
            StateTap("watched", query="security.watched_vulnerabilities", next="parse"),
            Call("parse", contract_in=EPSS_REQUEST, contract_out=EPSS_RESULT, next="summary",
                 input={"daily_base64": "$steps.epss.retrieved.body_base64",
                        "watched": "$steps.watched.result.rows"}),
            _project(EPSS_SUMMARY, "parse", "changed"),
            Guard("changed", predicate=_changed("parse"), on_true="settle", on_false="nochange",
                  refusal_code="no_change", message="The EPSS file changes no watched Claim."),
            SettleChangeSet("settle", candidate_templates={"items": "$steps.parse.items"},
                            result=Output("summary")),
            Halt("nochange", reason="no_change"),
        ],
        name="security.epss-triage",
        description=(
            "Read the EPSS daily file Capture that triggered the Line (security.epss-daily-v1) "
            "and the watched vulnerabilities, and settle epss_score and epss_percentile for each "
            "watched CVE whose scores changed, exactly as the file states them (or propose them "
            "under a propose cap). Halts no_change when nothing changed. Runs as a Line with "
            "trigger_input epss."
        ),
        contract_in=EMPTY,
        contract_out=EPSS_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 33_554_432),
        hard_caps=_caps(300, 2, 33_554_432, 5000),
    ).bind(epss=sources, parse=scores)
    return sequence.build()


def sbom_import(cx: Cruxible) -> Any:
    builtin = cx.provider_interface("workspace.file", provider=BUILTIN_PROVIDER)
    parse = cx.provider_interface("security.cyclonedx-components", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("sbom", capture_contract=SBOM_CONTRACT, next="releases", request={
                "tag": "playbill-workspace-file-source-request-v2",
                "logical_source": "cyclonedx.sbom",
                "relative_path": "sbom.cdx.json",
                "coordinate_type": "http-response-v1",
                "coordinate": {"revision": "working"},
                "selector_type": "whole-response-v1",
                "selector": {"whole": True},
                "replayability": "exact",
            }),
            StateTap("releases", query="security.release_inventory", next="parse"),
            Call("parse", contract_in=SBOM_REQUEST, contract_out=SBOM_RESULT, next="summary",
                 input={"sbom_text": "$steps.sbom.content.text",
                        "releases": "$steps.releases.result.rows"}),
            _project(SBOM_SUMMARY, "parse", "changed"),
            Guard("changed", predicate=_changed("parse"), on_true="propose", on_false="nochange",
                  refusal_code="no_change", message="The SBOM adds nothing inventory lacks."),
            ProposeChangeSet("propose", candidate_templates={"items": "$steps.parse.items"},
                             result=Output("summary")),
            Halt("nochange", reason="no_change"),
        ],
        name="security.sbom-import",
        description=(
            "Read the CycloneDX SBOM Capture that triggered the Line "
            "(security.cyclonedx-sbom-v1) and propose its product and release (created by key, "
            "or the held ones), the release's product link, supplier, and one "
            "security.release.component observation per component purl the release does not "
            "hold yet. Propose-only. Runs as a Line with trigger_input sbom."
        ),
        contract_in=EMPTY,
        contract_out=SBOM_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 5000),
    ).bind(sbom=builtin, parse=parse)
    return sequence.build()


def osv_applicability(cx: Cruxible) -> BlueprintInput:
    osv = cx.provider_interface("security.osv-query", provider=SOURCES_PROVIDER)
    decide = cx.provider_interface("security.osv-applicability", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            StateTap("releases", query="security.release_inventory", next="watched"),
            StateTap("watched", query="security.watched_vulnerabilities", next="assessments"),
            StateTap("assessments", query="security.assessment_index", next="osv"),
            Source("osv", capture_contract=OSV_CONTRACT, next="decide",
                   request={"releases": "$steps.releases.result.rows",
                            "watched": "$steps.watched.result.rows"}),
            Call("decide", contract_in=OSV_REQUEST, contract_out=OSV_RESULT, next="summary",
                 input={"osv": "$steps.osv", "releases": "$steps.releases.result.rows",
                        "watched": "$steps.watched.result.rows",
                        "assessments": "$steps.assessments.result.rows"}),
            _project(OSV_SUMMARY, "decide", "changed"),
            Guard("changed", predicate=_changed("decide"), on_true="propose",
                  on_false="nochange", refusal_code="no_change",
                  message="OSV changes no assessment."),
            ProposeChangeSet("propose", candidate_templates={"items": "$steps.decide.items"},
                             result=Output("summary")),
            Halt("nochange", reason="no_change"),
        ],
        name="security.osv-applicability",
        description=(
            "Ask OSV.dev about every SBOM component (purl@version) of every release and every "
            "watched CVE, retain the answer under security.osv-query-v1, and propose an "
            "assessment per (release, CVE) whose answer changed: affected (watching the CVE "
            "when it is new), not_affected with its VEX justification, or inconclusive. "
            "Propose-only; never settles. Runs as a Line (daily, or `line run` after an SBOM "
            "import is accepted)."
        ),
        contract_in=EMPTY,
        contract_out=OSV_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(300, 2, 67_108_864),
        hard_caps=_caps(600, 2, 67_108_864, 5000),
    ).bind(osv=osv, decide=decide)
    return _blueprint(sequence, _interface(cx, "security.osv-query"), "osv")


def cve_applicability(cx: Cruxible) -> Any:
    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    decide = cx.provider_interface("security.cve-applicability", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("record", capture_contract=CVE_CONTRACT, next="releases",
                   request=_fetch("https://cveawg.mitre.org/api/cve/", "cve.record",
                                  CVE_MAX_BYTES)),
            StateTap("releases", query="security.release_inventory", next="watched"),
            StateTap("watched", query="security.watched_vulnerabilities", next="assessments"),
            StateTap("assessments", query="security.assessment_index", next="decide"),
            Call("decide", contract_in=CVE_REQUEST, contract_out=CVE_RESULT, next="summary",
                 input={"record_base64": "$steps.record.retrieved.body_base64",
                        "releases": "$steps.releases.result.rows",
                        "watched": "$steps.watched.result.rows",
                        "assessments": "$steps.assessments.result.rows"}),
            _project(CVE_SUMMARY, "decide", "changed"),
            Guard("changed", predicate=_changed("decide"), on_true="propose",
                  on_false="nochange", refusal_code="no_change",
                  message="The CVE record changes no assessment."),
            ProposeChangeSet("propose", candidate_templates={"items": "$steps.decide.items"},
                             result=Output("summary")),
            Halt("nochange", reason="no_change"),
        ],
        name="security.cve-applicability",
        description=(
            "Read the CVE record Capture that triggered the Line (security.cve-record-http-v1) "
            "and propose an assessment for every release whose product (and supplier) the "
            "record's affected entries name: affected / not_affected by the record's version "
            "ranges, inconclusive when the match or the ranges are ambiguous. Propose-only. "
            "Runs as a Line with trigger_input record."
        ),
        contract_in=EMPTY,
        contract_out=CVE_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 5000),
    ).bind(record=web, decide=decide)
    return sequence.build()


def _backlog_measurement() -> dict[str, Any]:
    return {
        "name": "kev-backlog-cleared",
        "subject_grain": "procedure_unit",
        "measurement": {
            "kind": "accepted_query",
            "query": {
                "kind": "accepted",
                "role": "query",
                "target": "QueryDefinition:security.kev_triage_backlog",
            },
            "parameters": {},
            "execution_options": {},
            "expect": {"max_count": 0},
        },
        "check_after": {"microseconds": 3 * 86_400_000_000},
        "expires_after": {"microseconds": 10 * 86_400_000_000},
        "review_when": [
            {
                "name": "satisfied-rate-low",
                "metric": "satisfied_rate",
                "operator": "lt",
                "threshold": {"$decimal": "0.8"},
                "min_readings": 5,
            }
        ],
    }


# --- submission ----------------------------------------------------------------


def submit(cx: Cruxible, draft: Any, label: str) -> None:
    intent = draft.prepare()
    if intent.refused:
        for item in intent.diagnostics:
            print(f"  {item.code}: {item.message}")
        raise SystemExit(f"{label}: refused")
    submitted = intent.submit()
    status = submitted.status()
    proposal_id = status.proposal_id
    print(f"{label}: {status.state} proposal={proposal_id}")
    if status.state == "ready_to_activate" and proposal_id is not None:
        receipt = cx.activate(proposal_id)
        print(f"{label}: activated {getattr(receipt, 'accepted_git_oid', '')}")


def definitions(cx: Cruxible, release: str) -> None:
    draft = cx.changes(rationale=f"security kit {release}: vocabulary, identity, evidence "
                       "contracts and the acquisition policy. No Claims, Lines or authority.")
    for contract in capture_contracts():
        draft.capture_contract(contract)
    draft.acquisition_policy(acquisition_policy())
    for claim_type in claim_types(release):
        draft.claim_type(claim_type)
    for kind, rule in SUBJECT_KINDS.items():
        if rule is None:
            draft.subject_kind(name=kind, minted=True,
                               description=SUBJECT_KIND_DESCRIPTIONS[kind])
        else:
            draft.subject_kind(name=kind, keys=rule[0], uniqueness=rule[1],  # type: ignore[arg-type]
                               description=SUBJECT_KIND_DESCRIPTIONS[kind])
    submit(cx, draft, "claim types, subject kinds, contracts, policy")
    cx.refresh()
    draft = cx.changes(rationale=f"security kit {release}: named queries.")
    world = cx.world()
    for spec in query_definitions(release):
        held = _held_query(cx, spec.identity.name)
        if held is not None:
            envelope, digest = held
            current = QueryDefinitionSpec.model_validate(envelope)
            ignore = {"pins", "lifecycle"}
            if current.model_dump(mode="json", exclude=ignore) == spec.model_dump(
                mode="json", exclude=ignore
            ):
                continue  # unchanged
            spec = spec.model_copy(
                update={"lifecycle": ArtifactLifecycle(predecessor_digest=digest)}
            )
        draft.query_definition(
            QueryDefinitionInput(kind="query_definition", query_definition=spec),
            vocabulary=tuple(world.claim_type(p) for p in sorted(spec.referenced_predicates)),
        )
    submit(cx, draft, "queries")


def _held_query(cx: Cruxible, name: str) -> tuple[dict[str, Any], str] | None:
    """The live QueryDefinition's envelope and digest, or None when there is none."""

    from cruxible_client.contracts.get_reads import GetRequest
    from cruxible_client.errors import CoreError

    try:
        read = cx._client.get(
            cx._instance_id, request=GetRequest(ref=f"QueryDefinition:{name}", detail="proof")
        )
    except CoreError:
        return None
    proof = read.proof
    if proof is None:
        return None
    return dict(proof["envelope"]), str(proof["artifact_digest"])


def procedures(cx: Cruxible, release: str) -> None:
    draft = cx.changes(rationale=f"security kit {release}: acquisition Blueprints, triage, "
                       "attention, SBOM import and applicability Procedures.")
    draft.procedure(definition=kev_acquire(cx, release))
    draft.procedure(definition=cve_record_acquire(cx))
    draft.procedure(definition=epss_acquire(cx))
    draft.procedure(definition=sbom_acquire(cx))
    draft.procedure(definition=evidence_acquire(cx))
    draft.procedure(definition=kev_triage(cx))
    draft.procedure(definition=kev_attention(cx))
    draft.procedure(definition=epss_triage(cx))
    draft.procedure(definition=sbom_import(cx))
    draft.procedure(definition=osv_applicability(cx))
    draft.procedure(definition=cve_applicability(cx))
    submit(cx, draft, "procedures")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stage", choices=("definitions", "procedures"))
    parser.add_argument("--release", default="1.0.0", choices=("1.0.0", "1.1.0"))
    args = parser.parse_args()
    with Cruxible.connect() as cx:
        if args.stage == "definitions":
            definitions(cx, args.release)
        else:
            procedures(cx, args.release)


if __name__ == "__main__":
    main()
