"""Author the security kit's definitions in a fresh authoring instance.

    python security_definitions.py definitions [--release 1.0.0|1.1.0]
    python security_definitions.py procedures  [--release 1.0.0|1.1.0]

``definitions`` proposes and activates the CaptureContracts, ClaimTypes,
QueryDefinitions and the acquisition policy. ``procedures`` (after
``cruxible-provider-web`` and the bundled ``security-kev-provider`` are
installed) proposes the two acquisition Blueprints and the triage Procedure.
Then ``cruxible kit build --id security --version X.Y.Z --owns security.
--provider ../providers/security-kev-provider --provider
../providers/cruxible-provider-web --out DIR`` exports the release.

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
from cruxible_client.contracts.claim_types import ClaimType
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
    QueryParameterDeclaration,
    QueryParameterRef,
    QueryProjection,
    QueryProjectionField,
    QuerySubjectFieldRef,
    QueryTraversalStep,
)

DATA = Path(__file__).resolve().parent / "data"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_SOURCE = "cisa.kev.catalog"
KEV_CONTRACT = "security.kev-http-v1"
CVE_CONTRACT = "security.cve-record-http-v1"
OUTPUT_CONTRACT = "security.observation-output-v1"
POLICY = "security.kev-acquisition"
WEB_PROVIDER = "cruxible-provider-web"
KEV_PROVIDER = "security-kev-provider"
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

# --- ClaimTypes ---------------------------------------------------------------
# (predicate, subject kinds, object, literal schema or object kinds, cardinality,
#  role, evidence contracts, description). Observations need a Capture under one of
# their contracts; normative statements are supported by their own origin.
WORK = ("security.control", "security.exception", "security.remediation")
CLAIM_TYPES: list[tuple[str, tuple[str, ...], str, Any, str, str, tuple[str, ...], str]] = [
    ("security.asset.environment", ("security.asset",), "literal",
     {"enum": ["production", "staging"], "type": "string"}, "one", "normative", (),
     "The environment the asset runs in."),
    ("security.asset.hostname", ("security.asset",), "literal", {"type": "string"}, "one",
     "normative", (), "The asset's hostname."),
    ("security.asset.installs", ("security.asset",), "subject", ("security.release",), "many",
     "normative", (), "A software release installed on the asset."),
    ("security.asset.internet_exposed", ("security.asset",), "literal", {"type": "boolean"},
     "one", "normative", (), "Whether the asset is reachable from the internet."),
    ("security.asset.serves", ("security.asset",), "subject", ("security.service",), "many",
     "normative", (), "A service the asset serves."),
    ("security.release.product", ("security.release",), "subject", ("security.product",), "one",
     "normative", (), "The product this release is a version of."),
    ("security.release.version", ("security.release",), "literal", {"type": "string"}, "one",
     "normative", (), "The release's version string."),
    ("security.product.supplied_by", ("security.product",), "subject", ("security.supplier",),
     "one", "normative", (), "The supplier of the product."),
    ("security.service.criticality", ("security.service",), "literal",
     {"enum": ["critical", "standard"], "type": "string"}, "one", "normative", (),
     "How critical the service is to the organization."),
    ("security.service.owned_by", ("security.service",), "subject", ("security.team",), "one",
     "normative", (), "The team accountable for the service."),
    ("security.assessment.release", ("security.assessment",), "subject", ("security.release",),
     "one", "normative", (), "The release this applicability assessment is about."),
    ("security.assessment.vulnerability", ("security.assessment",), "subject",
     ("security.vulnerability",), "one", "normative", (),
     "The vulnerability this applicability assessment is about."),
    ("security.assessment.status", ("security.assessment",), "literal",
     {"enum": ["affected", "inconclusive", "not_affected"], "type": "string"}, "one",
     "observation", (CVE_CONTRACT, OUTPUT_CONTRACT),
     "Whether the release is affected by the vulnerability, as observed from retained evidence."),
    ("security.vulnerability.kev_listed", ("security.vulnerability",), "literal",
     {"type": "boolean"}, "one", "observation", (KEV_CONTRACT, OUTPUT_CONTRACT),
     "Whether the CISA Known Exploited Vulnerabilities catalog lists the vulnerability."),
    ("security.vulnerability.kev_date_added", ("security.vulnerability",), "literal", DATE,
     "one", "observation", (KEV_CONTRACT, OUTPUT_CONTRACT),
     "The date CISA added the vulnerability to the KEV catalog (dateAdded)."),
    ("security.vulnerability.kev_due_date", ("security.vulnerability",), "literal", DATE, "one",
     "observation", (KEV_CONTRACT, OUTPUT_CONTRACT),
     "The KEV remediation due date for federal agencies (dueDate)."),
    ("security.vulnerability.kev_ransomware_use", ("security.vulnerability",), "literal",
     {"enum": ["known", "unknown"], "type": "string"}, "one", "observation",
     (KEV_CONTRACT, OUTPUT_CONTRACT),
     "Whether KEV reports known ransomware campaign use (knownRansomwareCampaignUse)."),
    ("security.vulnerability.kev_listing_expected", ("security.vulnerability",), "literal",
     {"type": "boolean"}, "one", "normative", (),
     "The agent's belief that the vulnerability is or will be KEV-listed; predictions test it."),
    ("security.vulnerability.title", ("security.vulnerability",), "literal", {"type": "string"},
     "one", "observation", (CVE_CONTRACT, KEV_CONTRACT),
     "The vulnerability's title as a retained source states it."),
    ("security.vulnerability.vendor_product", ("security.vulnerability",), "literal",
     {"type": "string"}, "one", "observation", (CVE_CONTRACT, KEV_CONTRACT),
     "The affected vendor and product as a retained source states it."),
    ("security.control.activation", ("security.control",), "literal",
     {"enum": ["declared_active", "planned", "retired"], "type": "string"}, "one", "normative",
     (), "Whether the compensating control is active."),
    ("security.control.kind", ("security.control",), "literal",
     {"enum": ["access_restriction", "monitoring", "network_isolation"], "type": "string"},
     "one", "normative", (), "The kind of compensating control."),
    ("security.exception.approval", ("security.exception",), "literal",
     {"enum": ["approved", "revoked"], "type": "string"}, "one", "normative", (),
     "Whether the risk exception is approved."),
    ("security.exception.expires_at", ("security.exception",), "literal", DATETIME, "one",
     "normative", (), "When the risk exception expires."),
    ("security.remediation.due_at", ("security.remediation",), "literal", DATETIME, "one",
     "normative", (), "When the remediation is due."),
    ("security.remediation.progress", ("security.remediation",), "literal",
     {"enum": ["cancelled", "completed", "in_progress", "planned"], "type": "string"}, "one",
     "normative", (), "Where the remediation stands."),
    ("security.remediation.target_release", ("security.remediation",), "subject",
     ("security.release",), "one", "normative", (), "The release the remediation moves to."),
    ("security.work.assessment", WORK, "subject", ("security.assessment",), "one", "normative",
     (), "The assessment this work item answers."),
    ("security.work.asset", WORK, "subject", ("security.asset",), "one", "normative", (),
     "The asset this work item covers."),
    ("security.work.owner", WORK, "subject", ("security.team",), "one", "normative", (),
     "The team accountable for this work item."),
    ("security.work.rationale", WORK, "literal", {"minLength": 1, "type": "string"}, "one",
     "normative", (), "Why this work item exists."),
    ("security.work.review_at", WORK, "literal", DATETIME, "one", "normative", (),
     "When this work item is next reviewed."),
    ("security.work.verification", WORK, "literal",
     {"enum": ["failed", "inconclusive", "verified"], "type": "string"}, "one", "observation",
     (OUTPUT_CONTRACT,), "Whether the work was verified, as observed from retained evidence."),
]
# 1.1.0 adds the CWE identifiers KEV lists (a gate fixture for kit upgrades).
CLAIM_TYPES_1_1 = [
    ("security.vulnerability.kev_cwes", ("security.vulnerability",), "literal",
     {"type": "string"}, "many", "observation", (KEV_CONTRACT, OUTPUT_CONTRACT),
     "A CWE identifier the KEV catalog lists for the vulnerability (cwes)."),
]


def claim_types(release: str) -> list[ClaimType]:
    rows = CLAIM_TYPES + (CLAIM_TYPES_1_1 if release != "1.0.0" else [])
    result = []
    for predicate, kinds, obj, shape, cardinality, role, contracts, description in rows:
        rules: tuple[ClaimEvidenceAdmissionRule, ...] = ()
        if contracts:
            rules = (
                ClaimEvidenceAdmissionRule(
                    rule_id="retained-security-evidence",
                    claim_roles=(role,),  # type: ignore[arg-type]
                    capture_contracts=tuple(
                        ArtifactRef(
                            role="capture-contract",
                            target=ArtifactIdentity(kind="CaptureContract", name=name),
                        )
                        for name in sorted(contracts)
                    ),
                    evidence_kinds=("http_response",),
                    admission="direct",
                    subject_binding="exact_claim_subject",
                ),
            )
        result.append(
            ClaimType(
                identity=ArtifactIdentity(kind="ClaimType", name=predicate),
                predicate=predicate,
                allowed_subject_kinds=tuple(sorted(kinds)),
                object_kind=obj,  # type: ignore[arg-type]
                literal_schema=shape if obj == "literal" else None,
                allowed_object_subject_kinds=tuple(shape) if obj == "subject" else (),
                cardinality=cardinality,  # type: ignore[arg-type]
                permitted_roles=(role,),  # type: ignore[arg-type]
                evidence_admission_policy=ClaimEvidenceAdmissionPolicy(rules=rules),
                admission_policy=ClaimAdmissionPolicy(),
                resolution_policy=ClaimResolutionPolicy(
                    cardinality=cardinality,  # type: ignore[arg-type]
                    eligible_verdicts=("supported",),
                    selector="only_contender" if cardinality == "one" else "all",
                ),
                description=description,
                default_role=role,  # type: ignore[arg-type]
                evidence_requirement="captured" if contracts else "none",
                revision_evidence="replace",
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
    shape: str = "path", max_results: int = 200,
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
        dedupe="path" if shape == "path" else "subject",
        projection=QueryProjection(fields=tuple(sorted(fields, key=lambda x: x.name))),
        parameters=parameters,
        evaluation_policy=QueryEvaluationPolicy(
            visible_verdicts=("supported",),
            visible_currency=("current",),
            conflict_behavior="surface_conflicts",
        ),
        default_budgets=QueryBudgets(
            max_results=max_results, max_traversal_depth=10, max_paths=2000,
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


def query_definitions(release: str) -> list[QueryDefinitionSpec]:
    q: list[QueryDefinitionSpec] = []
    vuln_ref = QueryParameterRef(parameter="vulnerability")
    on_vulnerability = QueryComparisonFilter(
        left=QueryClaimValueRef(binding="assessment", predicate="security.assessment.vulnerability"),
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
    # Applicability for one vulnerability: every installed release with its assessment.
    applicability = [
        _hop("release", "asset", "security.asset.installs", "release", required=True),
        _hop("assessment", "release", "security.assessment.release", "assessment", reverse=True,
             where=on_vulnerability),
        _hop("service", "asset", "security.asset.serves", "service"),
        _hop("team", "service", "security.service.owned_by", "team"),
    ]
    applicability_fields = [_field(b, b) for b in ("asset", "release", "assessment", "service",
                                                   "team")] + [
        _field("internet_exposed", "asset", "security.asset.internet_exposed"),
        _field("criticality", "service", "security.service.criticality"),
        _field("status", "assessment", "security.assessment.status"),
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
    q.append(_query("security.triage", "Applicability and prioritization facts for one "
                    "vulnerability", "asset", "asset", applicability, applicability_fields,
                    parameters=(VULNERABILITY_PARAMETER,)))
    q.append(_query(
        "security.urgent_exposures", "Assets affected by one vulnerability that are "
        "internet-facing and serve a critical service", "asset", "asset", applicability,
        applicability_fields,
        _all(_cmp("assessment", "security.assessment.status", "affected"),
             _cmp("asset", "security.asset.internet_exposed", True, "boolean"),
             _cmp("service", "security.service.criticality", "critical")),
        parameters=(VULNERABILITY_PARAMETER,)))
    q.append(_query(
        "security.coverage_gaps", "Installed releases unassessed or inconclusive for one "
        "vulnerability", "asset", "asset", applicability, applicability_fields,
        _any(_missing("assessment", "security.assessment.status"),
             _cmp("assessment", "security.assessment.status", "inconclusive")),
        parameters=(VULNERABILITY_PARAMETER,)))
    q.append(_query("security.ownership_gaps", "Assets serving a service with no owning team",
                    "asset", "asset", applicability[:1] + applicability[2:3],
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
    # The triage Procedure's state tap: every watched vulnerability with its KEV Claims.
    q.append(_query(
        "security.watched_vulnerabilities", "Every watched vulnerability with its current KEV "
        "Claims", "vulnerability", "vulnerability", [],
        [_field("vulnerability", "vulnerability")] + [
            _field(name, "vulnerability", "security.vulnerability." + name)
            for name in ("kev_listed", "kev_date_added", "kev_due_date", "kev_ransomware_use")],
        shape="subject", max_results=1000))
    # The settle mandate's condition: one watched vulnerability, by id, with the
    # agent's stated KEV expectation. A vulnerability nobody stated a belief about
    # lacks kev_listing_expected, so its changes fall back to review.
    q.append(QueryDefinitionSpec(
        identity=ArtifactIdentity(kind="QueryDefinition", name="security.kev_settle_condition"),
        description=(
            "One vulnerability by id with its stated KEV expectation; the condition a KEV "
            "triage settle mandate evaluates per changed Claim."
        ),
        entry=QueryEntry(binding="vulnerability", subject_kinds=("security.vulnerability",),
                         subject_id=QueryParameterRef(parameter="vulnerability_id")),
        result_binding="vulnerability",
        result_shape="subject",
        result_cardinality="many",
        dedupe="subject",
        projection=QueryProjection(fields=(
            _field("kev_listing_expected", "vulnerability",
                   "security.vulnerability.kev_listing_expected"),
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
    return [CaptureContract.model_validate(raw)
            for raw in json.loads((DATA / "capture_contracts.json").read_text())]


def acquisition_policy() -> SourceAcquisitionPolicy:
    """One rule per Source alias: `catalog` (kev-acquire and the triage Line's
    trigger-fed input) and `record` (cve-record-acquire)."""

    def rule(name: str, max_age_hours: int) -> dict[str, Any]:
        return {
            "conservative_default": None,
            "correlation_keys": [],
            "input_name": name,
            "join_semantics_digest": None,
            "max_age": {"microseconds": max_age_hours * 3_600_000_000},
            "on_conflict": "preserve",
            "on_oversized": "refuse",
            "on_stale": "refuse",
            "on_unavailable": "refuse",
            "permitted_replayability": ["attested_only"],
            "requirement": "required",
        }

    return SourceAcquisitionPolicy.model_validate(
        {
            "coherence": {"kind": "independent"},
            "identity": {"kind": "SourceAcquisitionPolicy", "name": POLICY},
            "inputs": [rule("catalog", 24), rule("record", 24)],
        }
    )


# --- Blueprints and the triage Procedure -------------------------------------


def _contract(name: str, **fields: PropertySchema) -> CarriedContractInput:
    return CarriedContractInput(name=name, fields=fields, allow_extra=False)


EMPTY = _contract("security-empty-input")
URL_INPUT = _contract("security-url-input", url=PropertySchema(type="string"))
HTTP_SUMMARY = _contract(
    "security-http-evidence",
    url=PropertySchema(type="string"),
    status=PropertySchema(type="int"),
    body_digest=PropertySchema(type="string"),
)
KEV_REQUEST = _contract(
    "security-kev-catalog-request",
    catalog_base64=PropertySchema(type="string"),
    watched=PropertySchema(type="json"),
)
KEV_RESULT = _contract(
    "security-kev-catalog-result",
    items=PropertySchema(type="json"),
    changed=PropertySchema(type="integer"),
    watched=PropertySchema(type="integer"),
    listed=PropertySchema(type="integer"),
    catalog_version=PropertySchema(type="string"),
    catalog_count=PropertySchema(type="integer"),
)
TRIAGE_SUMMARY = _contract(
    "security-kev-triage-summary",
    changed=PropertySchema(type="integer"),
    watched=PropertySchema(type="integer"),
    listed=PropertySchema(type="integer"),
    catalog_version=PropertySchema(type="string"),
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


def _blueprint(sequence: Sequence, interface: dict[str, Any]) -> BlueprintInput:
    """Open the Sequence's `fetch` Provider as a slot typed by web.fetch."""

    built = sequence.build()
    definition = dict(built.definition)
    nodes = []
    for node in definition["nodes"]:
        node = dict(node)
        if node["kind"] == "source":
            node["provider"] = {"kind": "slot", "slot_name": "fetch"}
            node.pop("implementation_digest", None)
        nodes.append(node)
    definition["nodes"] = nodes
    definition["pin_slots"] = [
        {
            "slot_name": "fetch",
            "pin_role": "provider",
            "artifact_kind": "Provider",
            "interface_digest": interface["interface_digest"],
        }
    ]
    return BlueprintInput(kind="blueprint", definition=definition, contracts=built.contracts)


def kev_acquire(cx: Cruxible, release: str) -> BlueprintInput:
    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    budget_seconds = 60 if release == "1.0.0" else 90
    sequence = Sequence(
        [
            Source("catalog", capture_contract=KEV_CONTRACT, next="summary",
                   request=_fetch(KEV_URL, KEV_SOURCE, KEV_MAX_BYTES)),
            _summary("catalog", next="emit"),
            EmitCapture("emit", capture_contract=OUTPUT_CONTRACT, input=Output("catalog"),
                        result=Output("summary")),
        ],
        name="security.kev-acquire",
        description=(
            "Fetch the CISA KEV catalog (static JSON, no rendering) and retain it under "
            "security.kev-http-v1. Interpretation is security.kev-triage's job."
            + ("" if release == "1.0.0" else " 1.1.0: a 90 s budget.")
        ),
        contract_in=EMPTY,
        contract_out=HTTP_SUMMARY,
        acquisition_policy=POLICY,
        budget=ProcedureBudget(wall_clock=_seconds(budget_seconds), max_provider_calls=1,
                               max_capture_bytes=16_777_216),
        hard_caps=ProcedureHardCaps(max_wall_clock=_seconds(120), max_provider_calls=1,
                                    max_capture_bytes=16_777_216, max_items=1,
                                    max_repeat_attempts=1),
    ).bind(catalog=web)
    return _blueprint(sequence, _interface(cx, "web.fetch"))


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
            "as input.url) and retain it under security.cve-record-http-v1."
        ),
        contract_in=URL_INPUT,
        contract_out=HTTP_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=ProcedureBudget(wall_clock=_seconds(60), max_provider_calls=1,
                               max_capture_bytes=4_194_304),
        hard_caps=ProcedureHardCaps(max_wall_clock=_seconds(120), max_provider_calls=1,
                                    max_capture_bytes=4_194_304, max_items=1,
                                    max_repeat_attempts=1),
    ).bind(record=web)
    return _blueprint(sequence, _interface(cx, "web.fetch"))


def kev_triage(cx: Cruxible, *, settle: bool = False) -> Any:
    """The KEV triage Procedure; ``settle=True`` is security.kev-triage-settle, the same
    graph ending in settle_change_set (a Line graduates to it under a settle mandate)."""

    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    kev = cx.provider_interface("security.kev-catalog", provider=KEV_PROVIDER)
    changed = GuardPredicate(
        left=PredicateOperand(kind="step", alias="parse", path=("changed",)),
        operator="gt",
        right=PredicateOperand(kind="literal", value=0),
    )
    sequence = Sequence(
        [
            Source("catalog", capture_contract=KEV_CONTRACT, next="watched",
                   request=_fetch(KEV_URL, KEV_SOURCE, KEV_MAX_BYTES)),
            StateTap("watched", query="security.watched_vulnerabilities", next="parse"),
            Call("parse", contract_in=KEV_REQUEST, contract_out=KEV_RESULT, next="summary",
                 input={"catalog_base64": "$steps.catalog.retrieved.body_base64",
                        "watched": "$steps.watched.result.rows"}),
            Project("summary", next="changed", contract_out=TRIAGE_SUMMARY,
                    fields={"changed": "$steps.parse.changed",
                            "watched": "$steps.parse.watched",
                            "listed": "$steps.parse.listed",
                            "catalog_version": "$steps.parse.catalog_version"}),
            Guard("changed", predicate=changed, on_true="propose", on_false="nochange",
                  refusal_code="no_change", message="The catalog changes no watched Claim."),
            (SettleChangeSet if settle else ProposeChangeSet)(
                "propose", candidate_templates={"items": "$steps.parse.items"},
                result=Output("summary")),
            Halt("nochange", reason="no_change"),
        ],
        name="security.kev-triage-settle" if settle else "security.kev-triage",
        description=(
            ("Settle variant: " if settle else "")
            + "Read the KEV catalog Capture that triggered the Line (security.kev-http-v1) and "
            "the watched vulnerabilities, and propose one observation Claim per KEV field that "
            "changed (kev_listed, kev_date_added, kev_due_date, kev_ransomware_use). Halts "
            "no_change when nothing changed. Runs as a Line with trigger_input catalog."
        ),
        contract_in=EMPTY,
        contract_out=TRIAGE_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=ProcedureBudget(wall_clock=_seconds(120), max_provider_calls=2,
                               max_capture_bytes=16_777_216),
        hard_caps=ProcedureHardCaps(max_wall_clock=_seconds(300), max_provider_calls=2,
                                    max_capture_bytes=16_777_216, max_items=1000,
                                    max_repeat_attempts=1),
    ).bind(catalog=web, parse=kev)
    built = sequence.build()
    definition = dict(built.definition)
    definition["measurements"] = [_backlog_measurement(cx)]
    return built.model_copy(update={"definition": definition})


def _interface(cx: Cruxible, name: str) -> dict[str, Any]:
    from cruxible_client.contracts.get_reads import GetRequest

    read = cx._client.get(cx._instance_id, request=GetRequest(ref=f"ProviderInterface:{name}",
                                                                detail="proof"))
    assert read.proof is not None
    return dict(read.proof["entry"])


def _backlog_measurement(cx: Cruxible) -> dict[str, Any]:
    del cx
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
    draft = cx.changes(rationale=f"security kit {release}: vocabulary, evidence contracts, "
                       "queries and the acquisition policy. No Claims, Lines or authority.")
    for contract in capture_contracts():
        draft.capture_contract(contract)
    draft.acquisition_policy(acquisition_policy())
    for claim_type in claim_types(release):
        draft.claim_type(claim_type)
    submit(cx, draft, "claim types, contracts, policy")
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
    draft = cx.changes(rationale=f"security kit {release}: acquisition Blueprints and the "
                       "KEV triage Procedure.")
    draft.procedure(definition=kev_acquire(cx, release))
    draft.procedure(definition=cve_record_acquire(cx))
    draft.procedure(definition=kev_triage(cx))
    draft.procedure(definition=kev_triage(cx, settle=True))
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
