"""Author the security kit's definitions in a fresh authoring instance.

    python security_definitions.py definitions [--release 1.2.0|1.2.1]
    python security_definitions.py procedures  [--release 1.2.0|1.2.1]

``1.2.1`` is the release gate's upgrade variant (``source/variants/1.2.1-gate``,
never published); any other release is the base.

``definitions`` proposes and activates the CaptureContracts, ClaimTypes, the
SubjectKinds that name every security Subject, the QueryDefinitions and the
acquisition policy. ``procedures`` (after ``cruxible-provider-web`` and the
bundled ``security-analysis-provider`` and ``security-sources-provider`` are
installed) proposes the acquisition Blueprints and the triage, attention,
import and applicability Procedures, the system model's pull Blueprints, parse
Procedures and the hardening Procedure, and the code findings' acquisition, import
and attention Procedures. Then ``cruxible kit build`` exports the
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
from cruxible_client.contracts.claim_types import (
    ClaimEvidenceFreshness,
    ClaimFreshnessDuration,
    ClaimType,
    ClaimTypeMemberDescription,
)
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
    QueryClaimFieldRef,
    QueryClaimPresenceFilter,
    QueryClaimValueRef,
    QueryComparisonFilter,
    QueryConjunctionFilter,
    QueryDisjunctionFilter,
    QueryEntry,
    QueryEvaluationTimeRef,
    QueryInclude,
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
REPO_CONTRACT = "security.repo-snapshot-v1"
PYPI_CONTRACT = "security.pypi-release-v1"
GH_RELEASE_CONTRACT = "security.github-release-v1"
GH_API_CONTRACT = "security.github-api-v1"
ASSET_CONTRACT = "security.release-asset-v1"
SARIF_CONTRACT = "security.sarif-v1"
REPRO_CONTRACT = "security.reproduction-v1"
#: The system model's pull contracts: every fact about the organization's systems
#: cites a Capture under one of them.
SYSTEM_CONTRACTS = (REPO_CONTRACT, PYPI_CONTRACT, GH_RELEASE_CONTRACT, GH_API_CONTRACT,
                    ASSET_CONTRACT)
POLICY = "security.acquisition"
RELEASE = "1.2.0"  # the kit release
VARIANT = "1.2.1"  # the release gate's upgrade variant (not published)
WEB_PROVIDER = "cruxible-provider-web"
ANALYSIS_PROVIDER = "security-analysis-provider"
SOURCES_PROVIDER = "security-sources-provider"
BUILTIN_PROVIDER = "cruxible-builtin"
KEV_MAX_BYTES = 4_194_304  # the catalog is ~1.7 MB; web.fetch defaults to 256 KiB
CVE_MAX_BYTES = 1_048_576
GITHUB_MAX_BYTES = 4_194_304
ASSET_MAX_BYTES = 33_554_432  # security.release-asset's ceiling
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
SHA256 = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
COMMIT = {"type": "string", "pattern": r"^[0-9a-f]{40}$"}
FULL_NAME = {"type": "string", "pattern": r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}
PERMISSION = {"type": "string", "pattern": r"^[A-Za-z*_-]+:[A-Za-z_-]+$"}
REGISTRIES = ("ghcr", "github_pages", "github_release", "pypi")
COVERAGE_SCOPES = ("ci.workflows", "registry.files", "release.manifest")
#: Coverage reads unknown unless re-read within twice the pull cadence (6 h cron).
COVERAGE_STALE_AFTER_HOURS = 12
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
                  SELF_SOURCE_CONTRACT: "self_asserted", SARIF_CONTRACT: "sarif_log",
                  REPRO_CONTRACT: "test_report"}
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
SEVERITY = ("critical", "high", "low", "medium")
VERDICTS = {
    "confirmed": "The weakness is real and exploitable: a reproduction (the PoC run) or the "
    "code read shows it. Needs retained evidence, never own words.",
    "false_positive": "The tool or finder was wrong: there is no such weakness here.",
    "not_exploitable": "The weakness is in the code but cannot be exploited here; the "
    "justification says why (for example not_reachable).",
}
FINDING_JUSTIFICATIONS = {
    "not_attacker_controlled": "The input reaching the sink is not attacker-controlled.",
    "not_reachable": "No path from an entry point reaches the code.",
    "rule_misfire": "The rule matched code that is not the pattern it describes.",
    "sanitized": "The input is sanitized or validated before the sink.",
    "test_or_dead_code": "The code is a test, an example or never shipped.",
}
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
     "their own words or a workspace file, with their reasoning in its because. The kit's "
     "Procedures never revise a normative status; retire it to hand the assessment back to "
     "them."),
    ("security.assessment.justification", ("security.assessment",), "literal",
     {"enum": sorted(JUSTIFICATIONS), "type": "string"}, "one", "judged",
     (CVE_CONTRACT, OSV_CONTRACT, OUTPUT_CONTRACT), (),
     "Why a not_affected release is not affected (the VEX/CSAF justification): an observation "
     "from a source, or (normative) an analyst's judgment. Required in practice with every "
     "not_affected status; core cannot require it."),
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

# The system model (1.1.0): a symbolic model of the organization's systems. Every
# fact is a per-source observation citing the Capture it was read from; policy
# (a target's publish gate) is the only normative statement; absence is an answer
# only inside a current coverage belief. Keys are literal, so each hop also has a
# Subject-valued twin. A key that names another Subject names it by its locator
# text (``github.com/owner/repo@ref``), never by an id: a Procedure creates the
# workflow and its jobs in one terminal, before any id exists.
REPO_FACT = (REPO_CONTRACT,)
SYSTEM: list[ClaimRow] = [
    # Identity.
    ("security.repo.forge_host", ("security.repo",), "literal", TEXT, "one", "normative", (),
     ("trim", "casefold"), "The forge host (github.com); with full_name, the repository's key."),
    ("security.repo.full_name", ("security.repo",), "literal", FULL_NAME, "one", "normative", (),
     ("trim", "casefold"), "owner/repository; with forge_host, the repository's key."),
    ("security.workflow.source", ("security.workflow",), "literal", TEXT, "one", "normative",
     (), ("trim",), "The source the workflow was read from (host/owner/repo@ref); with path, "
     "the workflow's key."),
    ("security.workflow.path", ("security.workflow",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The workflow file's path in the repository; with source, the workflow's key."),
    ("security.job.workflow_ref", ("security.job",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The job's workflow as source:path; with job_key, the job's key."),
    ("security.job.job_key", ("security.job",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The job's key in its workflow file; with workflow_ref, the job's key."),
    ("security.target.registry", ("security.target",), "literal",
     {"enum": list(REGISTRIES), "type": "string"}, "one", "normative", (), (),
     "Where artifacts land (pypi, ghcr, github_release, github_pages); with name, the "
     "target's key."),
    ("security.target.name", ("security.target",), "literal", TEXT, "one", "normative", (),
     ("trim", "casefold"), "The target's name in its registry (a PyPI project, an image, "
     "owner/repo for a release or Pages site); with registry, the target's key."),
    ("security.artifact.target_ref", ("security.artifact",), "literal", TEXT, "one",
     "normative", (), ("trim",), "The artifact's target as registry/name; with name, the "
     "artifact's key."),
    ("security.artifact.name", ("security.artifact",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The published file's name (a release asset as tag/asset); with target_ref, "
     "the artifact's key."),
    ("security.change.repo_ref", ("security.change",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The change's repository as host/owner/repo; with commit_sha, its key."),
    ("security.change.commit_sha", ("security.change",), "literal", COMMIT, "one", "normative",
     (), ("trim", "casefold"), "The commit SHA; with repo_ref, the change's key."),
    ("security.coverage.source", ("security.coverage",), "literal", TEXT, "one", "normative",
     (), ("trim",), "The fully read source (host/owner/repo@ref:path, or registry/name); with "
     "scope, the coverage's key."),
    ("security.coverage.scope", ("security.coverage",), "literal",
     {"enum": list(COVERAGE_SCOPES), "type": "string"}, "one", "normative", (), (),
     "What was read in full: ci.workflows, release.manifest or registry.files."),
    ("security.signal.detector", ("security.signal",), "literal", TEXT, "one", "normative", (),
     ("trim",), "What observed the signal (a question such as security.hq5, or manual); with "
     "fingerprint, the signal's key."),
    ("security.signal.fingerprint", ("security.signal",), "literal", TEXT, "one", "normative",
     (), ("trim",), "What identifies the observation; with detector, the signal's key."),
    # What a repository declares, per source (observations of a repo snapshot).
    ("security.workflow.repo", ("security.workflow",), "subject", ("security.repo",), "one",
     "observation", REPO_FACT, (), "The repository the workflow file is in."),
    ("security.workflow.coverage", ("security.workflow",), "subject", ("security.coverage",),
     "one", "observation", REPO_FACT, (), "The coverage (source at a revision) the workflow "
     "was read under."),
    ("security.workflow.trigger", ("security.workflow",), "literal", TEXT, "many",
     "observation", REPO_FACT, ("trim",), "An event that triggers the workflow, as "
     "event[:filter:pattern] (push:tags:v*, workflow_dispatch, schedule:cron:0 6 * * *)."),
    ("security.job.workflow", ("security.job",), "subject", ("security.workflow",), "one",
     "observation", REPO_FACT, (), "The workflow the job is declared in."),
    ("security.job.permission", ("security.job",), "literal", PERMISSION, "many",
     "observation", REPO_FACT, ("trim",), "An effective token permission as scope:level (the "
     "workflow default applied; token:repository-default when none is declared)."),
    ("security.job.secret", ("security.job",), "literal", TEXT, "many", "observation",
     REPO_FACT, ("trim",), "A secret the job references (GITHUB_TOKEN included; *inherit for "
     "secrets: inherit)."),
    ("security.job.environment", ("security.job",), "literal", TEXT, "one", "observation",
     REPO_FACT, ("trim",), "The deployment environment the job runs in, or none."),
    ("security.job.uses", ("security.job",), "literal", PURL, "many", "observation", REPO_FACT,
     ("trim",), "An action or reusable workflow the job runs, as "
     "pkg:githubactions/owner/repo[/path]@ref."),
    ("security.job.needs", ("security.job",), "subject", ("security.job",), "many",
     "observation", REPO_FACT, (), "A job this job waits for."),
    ("security.job.publishes_to", ("security.job",), "subject", ("security.target",), "many",
     "observation", REPO_FACT, (), "A target the job can publish to: it holds the credential "
     "the registry accepts (the analysis provider's publish rule table)."),
    # What a registry serves (observations of a registry pull, a release, an asset).
    ("security.artifact.target", ("security.artifact",), "subject", ("security.target",),
     "one", "observation", (REPO_CONTRACT, PYPI_CONTRACT, GH_RELEASE_CONTRACT), (),
     "The target the artifact is published to."),
    ("security.artifact.declared_sha256", ("security.artifact",), "literal", SHA256, "one",
     "observation", REPO_FACT, ("trim", "casefold"),
     "The digest a release manifest in the repository declares for the artifact."),
    ("security.artifact.sha256", ("security.artifact",), "literal", SHA256, "one",
     "observation", (ASSET_CONTRACT, GH_RELEASE_CONTRACT, PYPI_CONTRACT), ("trim", "casefold"),
     "The digest of the bytes the target serves (PyPI's digest, or a fetched asset's)."),
    ("security.artifact.published_by", ("security.artifact",), "subject",
     ("security.workflow",), "one", "observation", (GH_RELEASE_CONTRACT, PYPI_CONTRACT), (),
     "The workflow (at the commit it ran from) that published the artifact, as its provenance "
     "states."),
    ("security.artifact.publish_environment", ("security.artifact",), "literal", TEXT, "one",
     "observation", (PYPI_CONTRACT,), ("trim",),
     "The deployment environment the publishing run used, as provenance states it, or none."),
    ("security.artifact.built_from", ("security.artifact",), "subject", ("security.change",),
     "one", "observation", (GH_API_CONTRACT, GH_RELEASE_CONTRACT, PYPI_CONTRACT), (),
     "The commit the artifact was built from."),
    ("security.artifact.uploaded_by", ("security.artifact",), "literal", TEXT, "one",
     "observation", (GH_RELEASE_CONTRACT,), ("trim",), "Who uploaded the release asset (login)."),
    ("security.artifact.release", ("security.artifact",), "subject", ("security.release",),
     "one", "sourced", (GH_RELEASE_CONTRACT, PYPI_CONTRACT), (),
     "The release the artifact is a file of: joins the SBOM, OSV and KEV path."),
    ("security.target.source_repo", ("security.target",), "subject", ("security.repo",), "one",
     "sourced", (PYPI_CONTRACT, REPO_CONTRACT), (), "The repository the target is published "
     "from: its provenance's, or the owner's words."),
    # Coverage: the fully-read-source belief. A stale revision reads absent, so every
    # answer resting on it reads unknown.
    ("security.coverage.of", ("security.coverage",), "subject",
     ("security.repo", "security.target"), "one", "observation",
     (PYPI_CONTRACT, REPO_CONTRACT), (), "What the source belongs to: a repository, or a "
     "registry target."),
    ("security.coverage.revision", ("security.coverage",), "literal", TEXT, "one",
     "observation", (PYPI_CONTRACT, REPO_CONTRACT), ("trim",),
     "The revision every file was read at: a commit SHA, or the digest of a registry's served "
     "file set, re-read on every pull and stale 12 h after the last. Absence inside current "
     "coverage is an answer; outside it, unknown."),
    # Policy and investigation.
    ("security.target.publish_gate", ("security.target",), "literal", TEXT, "many",
     "normative", (), ("trim",), "A trigger the organization allows to publish to the target "
     "(push:tags:v*). Stating a gate is what asks the hardening questions about the target."),
    ("security.signal.observed", ("security.signal",), "subject",
     ("security.artifact", "security.job", "security.target", "security.workflow"), "many",
     "judged", SYSTEM_CONTRACTS + (OUTPUT_CONTRACT,), (),
     "What the signal was observed on: a source's observation, or someone's own words."),
    ("security.signal.explained_by", ("security.signal",), "subject",
     ("security.change", "security.finding", "security.job", "security.target",
      "security.workflow"), "one", "sourced", SYSTEM_CONTRACTS, (),
     "A hypothesis for the signal: what is responsible (a finding: the anomaly is "
     "exploitation of that weakness). Competing hypotheses contend (set --contend); the slot "
     "resolves when one remains."),
    ("security.work.job", WORK, "subject", ("security.job",), "one", "normative", (), (),
     "The job this work item changes."),
]
# First-party code findings (1.2.0): one weakness of one kind at one place in one
# repository's code, keyed by repository, weakness and locus (never a line number).
# What finders report is an observation of their SARIF; what reviewers decide (the
# verdict) is normative and needs retained evidence; the location is an origin-only
# file citation, so it drifts when the code changes. Status is derived, never stored.
FINDING_KIND = ("security.finding",)
FINDINGS: list[ClaimRow] = [
    ("security.finding.repo_ref", FINDING_KIND, "literal", TEXT, "one", "normative", (),
     ("trim", "casefold"), "The repository as host/owner/repo (github.com/owner/repo); with "
     "weakness and locus, the finding's key."),
    ("security.finding.weakness", FINDING_KIND, "literal", TEXT, "one", "normative", (),
     ("trim", "upper"), "CWE-<n>, the smallest CWE the reporting rule names, else "
     "RULE:<tool>/<ruleId>; with repo_ref and locus, the finding's key."),
    ("security.finding.locus", FINDING_KIND, "literal", TEXT, "one", "normative", (),
     ("trim",), "Where in the code: <repo-relative path>#<locator>, the first tier that "
     "applies (the symbol, snippet:<12 hex of the sink line>, line-hash:<the tool's>). Never "
     "a line number; with repo_ref and weakness, the finding's key."),
    ("security.finding.repo", FINDING_KIND, "subject", ("security.repo",), "one", "sourced",
     (SARIF_CONTRACT,), (), "The repository the finding is in (the key's repo_ref as a "
     "Subject)."),
    ("security.finding.rule", FINDING_KIND, "literal", TEXT, "many", "observation",
     (SARIF_CONTRACT,), ("trim",), "A tool rule that reported the finding, as tool:ruleId "
     "(semgrep:python.lang.security...), observed in a SARIF scan."),
    ("security.finding.reported_by", FINDING_KIND, "literal", TEXT, "many", "observation",
     (SARIF_CONTRACT,), ("trim", "casefold"), "A finder that reported the finding: a tool "
     "(semgrep, codeql) or an agent's principal; the grain of the finder track record."),
    ("security.finding.severity", FINDING_KIND, "literal",
     {"enum": list(SEVERITY), "type": "string"}, "one", "judged", (SARIF_CONTRACT,), (),
     "How severe the finding is: a scan's severity (security-severity, else the level) "
     "citing its SARIF, or (normative) an analyst's judgment."),
    ("security.finding.location", FINDING_KIND, "literal", TEXT, "many", "normative", (),
     ("trim",), "Where the sink is now, as path:start-end, cited by a file citation of the "
     "sink line (PATH#ANCHOR): origin-only, so `cruxible next` resurfaces it "
     "(citation_drifted) when the cited code changes. One per sink."),
    ("security.finding.verdict", FINDING_KIND, "literal",
     {"enum": sorted(VERDICTS), "type": "string"}, "one", "normative",
     (REPRO_CONTRACT, WORKSPACE_EVIDENCE_CONTRACT), (),
     "The adjudicated verdict: confirmed, not_exploitable or false_positive, citing a "
     "reproduction (the PoC run) or the code read (workspace evidence); own words are "
     "refused. A disputed verdict contends (set --contend) and reads conflict until one "
     "contender remains. Never settled by a Mandate."),
    ("security.finding.justification", FINDING_KIND, "literal",
     {"enum": sorted(FINDING_JUSTIFICATIONS), "type": "string"}, "one", "judged",
     (SARIF_CONTRACT,), (), "Why a finding is not_exploitable or a false_positive: an "
     "analyst's judgment (normative), or a scan's stated suppression."),
    ("security.finding.reproduction", FINDING_KIND, "literal", TEXT, "one", "sourced",
     (REPRO_CONTRACT,), ("trim",), "The proof-of-concept test that reproduces the finding "
     "(tests/security/test_x.py::test_y), in the writer's own words or a section of the "
     "finding's note; the PoC run is the verdict's evidence."),
    ("security.finding.affects", FINDING_KIND, "subject",
     ("security.artifact", "security.job", "security.release", "security.service"), "many",
     "sourced", (GH_API_CONTRACT, GH_RELEASE_CONTRACT), (),
     "What the finding is in: a release, a service, a job or an artifact (joins the system "
     "model; HQ6 asks it of every gated target)."),
    ("security.finding.vulnerability", FINDING_KIND, "subject", ("security.vulnerability",),
     "one", "sourced", (CVE_CONTRACT, OSV_CONTRACT), (),
     "The known CVE the finding is (vendored code with a published vulnerability)."),
    ("security.finding.fixed_by", FINDING_KIND, "subject", ("security.change",), "one",
     "sourced", (GH_API_CONTRACT,), (), "The commit that fixes the finding."),
    ("security.finding.verification", FINDING_KIND, "literal",
     {"enum": ["fixed", "present"], "type": "string"}, "one", "observation",
     (REPRO_CONTRACT, SARIF_CONTRACT), (),
     "Whether a fix is verified: fixed when a full scan of the finder's rules no longer "
     "reports it or the PoC passes; present when a full scan reports it after it was fixed "
     "(a regression)."),
    ("security.work.finding", WORK, "subject", FINDING_KIND, "one", "normative", (), (),
     "The finding this work item answers (a remediation fixes it; an approved exception "
     "accepts its risk)."),
]
#: predicate -> {member: description} for the enum ClaimTypes that describe their values.
MEMBERS = {"security.assessment.justification": JUSTIFICATIONS,
           "security.finding.verdict": VERDICTS,
           "security.finding.justification": FINDING_JUSTIFICATIONS}

#: predicate -> evidence freshness horizon in hours.
#: Only the revision carries freshness: it is restated on every pull (an unchanged
#: source re-observes it), and every answer reads it, so a stale revision reads
#: absent and the answer unknown. ``coverage.of`` is stated once, like any fact; a
#: moved source revises the one revision Claim.
FRESHNESS = {"security.coverage.revision": COVERAGE_STALE_AFTER_HOURS}

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
    "security.repo": (("security.repo.forge_host", "security.repo.full_name"), "unique"),
    "security.workflow": (("security.workflow.source", "security.workflow.path"), "unique"),
    "security.job": (("security.job.workflow_ref", "security.job.job_key"), "unique"),
    "security.target": (("security.target.registry", "security.target.name"), "unique"),
    "security.artifact": (("security.artifact.target_ref", "security.artifact.name"), "unique"),
    "security.change": (("security.change.repo_ref", "security.change.commit_sha"), "unique"),
    "security.coverage": (("security.coverage.source", "security.coverage.scope"), "unique"),
    "security.signal": (("security.signal.detector", "security.signal.fingerprint"), "unique"),
    "security.finding": (("security.finding.repo_ref", "security.finding.weakness",
                          "security.finding.locus"), "unique"),
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
    "security.repo": "A source repository, named by forge host and owner/repository.",
    "security.workflow": "One CI workflow file, named by the source it was read from "
    "(host/owner/repo@ref) and its path.",
    "security.job": "One job of a workflow, named by its workflow (source:path) and job key: "
    "it holds the permissions, secrets, environment and actions.",
    "security.target": "Where artifacts land (a PyPI project, a GHCR image, a GitHub release or "
    "Pages site): the trust boundary a publish gate guards.",
    "security.artifact": "One published file of a target, named by target and file name.",
    "security.change": "A commit of a repository, created when an investigation needs it.",
    "security.coverage": "The belief that a source was read in full at a revision: absence "
    "is an answer only inside current coverage.",
    "security.signal": "An observation an investigation starts from, named by its detector "
    "and fingerprint.",
    "security.finding": "One weakness of one kind at one place in one repository's code, named "
    "by repository, weakness (CWE) and locus (path#symbol, snippet or line hash): every finder "
    "that reports it meets on the key.",
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
    the judgment. ``sourced``: a normative relationship citing its author's words or the
    source Capture a Procedure read it from. Otherwise one role: an observation needs a
    Capture under its contracts, a normative statement is supported by its own origin.
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
    if not contracts:
        return (role,), role, (), "none"
    return (role,), role, (_rule("retained-security-evidence", role, contracts),), "captured"


def claim_types(release: str) -> list[ClaimType]:
    rows = CLAIM_TYPES + SYSTEM + FINDINGS + (CLAIM_TYPES_1_1 if release == VARIANT else [])
    result = []
    for predicate, kinds, obj, shape, cardinality, role, contracts, form, description in rows:
        roles, default_role, rules, requirement = _evidence(role, contracts)
        members = tuple(
            ClaimTypeMemberDescription(member=name, description=text)
            for name, text in sorted(MEMBERS.get(predicate, {}).items())
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
                evidence_freshness=ClaimEvidenceFreshness(stale_after=ClaimFreshnessDuration(
                    microseconds=FRESHNESS[predicate] * 3_600_000_000))
                if predicate in FRESHNESS else None,
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


def _role(name: str, binding: str, predicate: str) -> QueryProjectionField:
    """The role of the bound Subject's Claim of ``predicate``: normative marks a judgment."""

    return QueryProjectionField(
        name=name,
        value=QueryClaimFieldRef(binding=binding, predicate=predicate, field="role"),
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
    dedupe: str | None = None, includes: tuple[QueryInclude, ...] = (),
    paths_per_result: int = 100, evaluation: QueryEvaluationPolicy | None = None,
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
        includes=tuple(sorted(includes, key=lambda item: item.name)),
        evaluation_policy=evaluation or QueryEvaluationPolicy(
            visible_verdicts=("supported",),
            visible_currency=("current",),
            conflict_behavior="surface_conflicts",
        ),
        default_budgets=QueryBudgets(
            max_results=max_results, max_traversal_depth=10, max_paths=20000,
            max_paths_per_result=paths_per_result,
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
    if field in {"asset", "assessment", "finding", "owner", "rationale", "review_at",
                 "verification"}:
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
    # Every assessment with its key, status (and its role: normative is an analyst's
    # judgment) and justification: what applicability and attention compare with.
    q.append(_query(
        "security.assessment_index", "Every assessment with its key, status, the status's role "
        "(normative: an analyst's judgment) and justification",
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
         _role("status_role", "assessment", "security.assessment.status")],
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
        _role("status_role", "assessment", "security.assessment.status"),
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
        max_results=500 if release == VARIANT else 100,
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
           _role("status_role", "assessment", "security.assessment.status")]
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
    return q + system_queries() + finding_queries()


# --- the system model's queries ------------------------------------------------


def _param(name: str) -> QueryParameterDeclaration:
    return QueryParameterDeclaration(name=name, value_type="string")


def _is(binding: str, predicate: str, parameter: str) -> QueryComparisonFilter:
    """The bound Subject's ``predicate`` equals the query parameter ``parameter``."""

    return QueryComparisonFilter(
        left=QueryClaimValueRef(binding=binding, predicate=predicate), operator="eq",
        right=QueryParameterRef(parameter=parameter), value_type="string")


def _include(name: str, source: str, predicate: str) -> QueryInclude:
    return QueryInclude(name=name, binding="included_" + name, from_binding=source,
                        predicate=predicate, direction="forward", many=True, max_items=500)


#: The parse Procedures read held state for one source, so they see a held coverage
#: even when it went stale (to revise it); the hardening questions never do.
HELD = QueryEvaluationPolicy(visible_verdicts=("stale", "supported"),
                             visible_currency=("current", "stale"),
                             conflict_behavior="surface_conflicts")
GATED = QueryClaimPresenceFilter(binding="target", predicate="security.target.publish_gate")
TARGET_FIELDS = [_field("target", "target"), _field("repo", "repo"),
                 _field("coverage", "coverage"),
                 _field("target_registry", "target", "security.target.registry"),
                 _field("target_name", "target", "security.target.name"),
                 _field("gate", "target", "security.target.publish_gate"),
                 _field("repo_host", "repo", "security.repo.forge_host"),
                 _field("repo_name", "repo", "security.repo.full_name"),
                 _field("coverage_source", "coverage", "security.coverage.source"),
                 _field("coverage_revision", "coverage", "security.coverage.revision")]


def _target_hops(*, coverage: bool = True) -> list[QueryTraversalStep]:
    hops = [_hop("repo", "target", "security.target.source_repo", "repo")]
    if coverage:
        hops.append(_hop("coverage", "repo", "security.coverage.of", "coverage", reverse=True,
                         where=_cmp("coverage", "security.coverage.scope", "ci.workflows")))
    return hops


def _job_fields(*names: str) -> list[QueryProjectionField]:
    predicates = {"permissions": "security.job.permission", "secrets": "security.job.secret",
                  "environment": "security.job.environment", "uses": "security.job.uses"}
    return [_field("job", "job"), _field("job_key", "job", "security.job.job_key"),
            _field("workflow_path", "workflow", "security.workflow.path"),
            _field("triggers", "workflow", "security.workflow.trigger")] + [
        _field(name, "job", predicates[name]) for name in names]


def system_queries() -> list[QueryDefinitionSpec]:
    q: list[QueryDefinitionSpec] = []
    q.append(_query(
        "security.coverage_index", "One source's coverage (source, scope) with the revision it "
        "was read at and what it belongs to, stale or current: the parse Procedures' tap",
        "coverage", "coverage", [],
        [_field("coverage", "coverage"),
         _field("source", "coverage", "security.coverage.source"),
         _field("scope", "coverage", "security.coverage.scope"),
         _field("revision", "coverage", "security.coverage.revision"),
         _field("of", "coverage", "security.coverage.of")],
        _all(_is("coverage", "security.coverage.source", "source"),
             _is("coverage", "security.coverage.scope", "scope")),
        parameters=(_param("scope"), _param("source")), shape="subject", max_results=10,
        evaluation=HELD))
    q.append(_query(
        "security.source_facts", "Every workflow read from one source (host/owner/repo@ref) "
        "and its jobs, with each many-valued fact's Claims: the repo parse's tap",
        "workflow", "workflow",
        [_hop("job", "workflow", "security.job.workflow", "job", reverse=True)],
        [_field("workflow", "workflow"), _field("job", "job"),
         _field("path", "workflow", "security.workflow.path"),
         _field("repo", "workflow", "security.workflow.repo"),
         _field("coverage", "workflow", "security.workflow.coverage"),
         _field("job_key", "job", "security.job.job_key"),
         _field("environment", "job", "security.job.environment")],
        _is("workflow", "security.workflow.source", "source"),
        parameters=(_param("source"),), max_results=2000,
        includes=(_include("trigger", "workflow", "security.workflow.trigger"),
                  _include("permission", "job", "security.job.permission"),
                  _include("secret", "job", "security.job.secret"),
                  _include("uses", "job", "security.job.uses"),
                  _include("needs", "job", "security.job.needs"),
                  _include("publishes_to", "job", "security.job.publishes_to"))))
    q.append(_query(
        "security.repo_targets", "One repository (by forge host and owner/repository) and the "
        "targets published from it: the repo parse's tap", "repo", "repo",
        [_hop("target", "repo", "security.target.source_repo", "target", reverse=True)],
        [_field("repo", "repo"), _field("target", "target"),
         _field("forge_host", "repo", "security.repo.forge_host"),
         _field("full_name", "repo", "security.repo.full_name"),
         _field("registry", "target", "security.target.registry"),
         _field("name", "target", "security.target.name")],
        _all(_is("repo", "security.repo.forge_host", "forge_host"),
             _is("repo", "security.repo.full_name", "full_name")),
        parameters=(_param("forge_host"), _param("full_name")), max_results=500))
    q.append(_query(
        "security.registry_facts", "One target (by registry and name) with every artifact it "
        "serves and what each was published by and built from: the parse Procedures' tap",
        "target", "target",
        [_hop("artifact", "target", "security.artifact.target", "artifact", reverse=True),
         _hop("workflow", "artifact", "security.artifact.published_by", "workflow"),
         _hop("change", "artifact", "security.artifact.built_from", "change"),
         _hop("release", "artifact", "security.artifact.release", "release"),
         _hop("repo", "target", "security.target.source_repo", "repo")],
        [_field("target", "target"), _field("artifact", "artifact"),
         _field("artifact_name", "artifact", "security.artifact.name"),
         _field("sha256", "artifact", "security.artifact.sha256"),
         _field("declared_sha256", "artifact", "security.artifact.declared_sha256"),
         _field("publish_environment", "artifact", "security.artifact.publish_environment"),
         _field("workflow_source", "workflow", "security.workflow.source"),
         _field("workflow_path", "workflow", "security.workflow.path"),
         _field("built_from_sha", "change", "security.change.commit_sha"),
         _field("release_version", "release", "security.release.version"),
         _field("repo_full_name", "repo", "security.repo.full_name")],
        _all(_is("target", "security.target.registry", "registry"),
             _is("target", "security.target.name", "name")),
        parameters=(_param("name"), _param("registry")), max_results=2000,
        paths_per_result=1000))
    # The five hardening questions, each over the gated targets only (stating a
    # publish gate is what asks them), each row carrying its coverage's state.
    publish_path = _target_hops() + [
        _hop("job", "target", "security.job.publishes_to", "job", reverse=True),
        _hop("workflow", "job", "security.job.workflow", "workflow"),
        _hop("job_coverage", "workflow", "security.workflow.coverage", "coverage")]
    per_job = _target_hops() + [
        _hop("workflow", "coverage", "security.workflow.coverage", "workflow", reverse=True),
        _hop("job", "workflow", "security.job.workflow", "job", reverse=True)]
    hq = dict(max_results=2000, paths_per_result=1000)
    q.append(_query(
        "security.publish_paths", "HQ1: every job that can publish to a gated target, with "
        "its workflow's triggers, beside the coverage of the target's repository",
        "target", "target", publish_path,
        TARGET_FIELDS + _job_fields() + [_field("job_coverage", "job_coverage")], GATED, **hq))
    q.append(_query(
        "security.credentialed_jobs", "HQ2: every job of a covered source of a gated target's "
        "repository, with its permissions, secrets, environment and triggers",
        "target", "target", per_job,
        TARGET_FIELDS + _job_fields("permissions", "secrets", "environment"), GATED, **hq))
    q.append(_query(
        "security.mutable_actions", "HQ3: every job of a covered source of a gated target's "
        "repository, with the actions it runs and the credentials it holds",
        "target", "target", per_job,
        TARGET_FIELDS + _job_fields("uses", "permissions", "secrets"), GATED, **hq))
    q.append(_query(
        "security.shared_dependencies", "HQ4: every publishing job of a gated target, with the "
        "actions and secrets it runs on", "target", "target", publish_path,
        TARGET_FIELDS + _job_fields("uses", "secrets") + [_field("job_coverage", "job_coverage")],
        GATED, **hq))
    q.append(_query(
        "security.served_vs_declared", "HQ5: every artifact a gated target serves, its served "
        "and declared digests, and the workflow and jobs that published it at the commit it "
        "was built from", "target", "target",
        _target_hops(coverage=False) + [
            _hop("registry_coverage", "target", "security.coverage.of", "coverage",
                 reverse=True,
                 where=_cmp("registry_coverage", "security.coverage.scope", "registry.files")),
            _hop("artifact", "target", "security.artifact.target", "artifact", reverse=True),
            _hop("workflow", "artifact", "security.artifact.published_by", "workflow"),
            _hop("workflow_coverage", "workflow", "security.workflow.coverage", "coverage"),
            _hop("job", "workflow", "security.job.workflow", "job", reverse=True)],
        TARGET_FIELDS[:2] + TARGET_FIELDS[3:6] + TARGET_FIELDS[6:8] + [
            _field("registry_coverage", "registry_coverage"),
            _field("registry_coverage_source", "registry_coverage", "security.coverage.source"),
            _field("registry_coverage_revision", "registry_coverage",
                   "security.coverage.revision"),
            _field("artifact", "artifact"),
            _field("artifact_name", "artifact", "security.artifact.name"),
            _field("sha256", "artifact", "security.artifact.sha256"),
            _field("declared_sha256", "artifact", "security.artifact.declared_sha256"),
            _field("publish_environment", "artifact", "security.artifact.publish_environment"),
            _field("workflow", "workflow"),
            _field("workflow_source", "workflow", "security.workflow.source"),
            _field("workflow_path", "workflow", "security.workflow.path"),
            _field("workflow_coverage", "workflow_coverage"),
            _field("workflow_coverage_source", "workflow_coverage", "security.coverage.source"),
            _field("workflow_coverage_revision", "workflow_coverage",
                   "security.coverage.revision"),
            _field("job", "job"), _field("job_key", "job", "security.job.job_key"),
            _field("job_environment", "job", "security.job.environment"),
            _field("job_publishes", "job", "security.job.publishes_to")],
        GATED, **hq))
    return q


# --- the code findings' queries -------------------------------------------------

F = "security.finding."


def _finding_fields(*names: str) -> list[QueryProjectionField]:
    """The finding binding's subject id and the named finding fields (rules: finding.rule)."""

    predicates = {"rules": F + "rule"}
    return [_field("finding", "finding")] + [
        _field(name, "finding", predicates.get(name, F + name)) for name in names]


def _open() -> QueryDisjunctionFilter:
    """Not verified fixed: no verification yet, or one that says present."""

    return _any(_missing("finding", F + "verification"),
                QueryComparisonFilter(left=QueryClaimValueRef(binding="finding",
                                                              predicate=F + "verification"),
                                      operator="ne", right=QueryLiteralRef(value="fixed"),
                                      value_type="string"))


def finding_queries() -> list[QueryDefinitionSpec]:
    q: list[QueryDefinitionSpec] = []
    in_repo = _is("finding", F + "repo_ref", "repo_ref")
    repo = (_param("repo_ref"),)
    q.append(_query(
        "security.finding_index", "Every finding of one repository (repo_ref, host/owner/repo) "
        "with its key, the rules and finders that reported it, its severity, verification and "
        "verdict: the SARIF import's tap", "finding", "finding", [],
        _finding_fields("repo_ref", "weakness", "locus", "rules", "reported_by", "severity",
                        "verification", "verdict"),
        in_repo, parameters=repo, shape="subject", max_results=2000))
    q.append(_query(
        "security.open_findings", "Every finding of one repository not verified fixed, with its "
        "verdict (conflict while disputed), justification, severity, location, finders and "
        "remediation", "finding", "finding",
        [_hop("remediation", "finding", "security.work.finding", "remediation", reverse=True)],
        _finding_fields("weakness", "locus", "severity", "verdict", "justification",
                        "location", "reported_by", "rules", "reproduction", "verification")
        + [_field("remediation", "remediation"),
           _field("progress", "remediation", "security.remediation.progress")],
        _all(in_repo, _open()), parameters=repo, max_results=2000))
    # HQ6: what a gated target serves, through the release its files are of, joined to
    # the findings that affect that release.
    q.append(_query(
        "security.published_findings", "HQ6: every confirmed finding not verified fixed that "
        "affects a release a gated target serves a file of, with the target, the artifact "
        "and the release", "target", "target",
        [_hop("artifact", "target", "security.artifact.target", "artifact", reverse=True,
              required=True),
         _hop("release", "artifact", "security.artifact.release", "release", required=True),
         _hop("finding", "release", F + "affects", "finding", reverse=True, required=True,
              where=_all(_cmp("finding", F + "verdict", "confirmed"), _open()))],
        [_field("target", "target"), _field("artifact", "artifact"),
         _field("release", "release"),
         _field("target_registry", "target", "security.target.registry"),
         _field("target_name", "target", "security.target.name"),
         _field("gate", "target", "security.target.publish_gate"),
         _field("artifact_name", "artifact", "security.artifact.name"),
         _field("release_version", "release", "security.release.version")]
        + _finding_fields("weakness", "locus", "severity", "verdict", "verification"),
        GATED, max_results=2000, paths_per_result=1000))
    q.append(_query(
        "security.unverified_fixes", "Findings with a fix commit (fixed_by) that no full scan "
        "or passing PoC has verified fixed yet", "finding", "finding", [],
        _finding_fields("repo_ref", "weakness", "locus", "fixed_by", "verification",
                        "verdict"),
        _all(QueryClaimPresenceFilter(binding="finding", predicate=F + "fixed_by"), _open()),
        shape="subject", max_results=2000))
    # The finder track record. A comparison on a many-valued field matches only a field
    # holding exactly one value, so the reader filters reported_by (and counts).
    q.append(_query(
        "security.finder_record", "Every finding of one repository with the finders and rules "
        "that reported it and its verdict (conflict while disputed): the reader counts upheld "
        "(confirmed, not_exploitable) against overturned (false_positive) per finder or rule",
        "finding", "finding", [],
        _finding_fields("weakness", "locus", "reported_by", "rules", "verdict",
                        "justification", "verification"),
        in_repo, parameters=repo, shape="subject", max_results=2000))
    q.append(QueryDefinitionSpec(
        identity=ArtifactIdentity(kind="QueryDefinition",
                                  name="security.finding_settle_condition"),
        description=(
            "One finding by id with its key: the condition a settle grant on the SARIF "
            "import's report observations (rule, reported_by, severity) evaluates per "
            "changed Claim. Never grant the verdict, justification, verification or affects."
        ),
        entry=QueryEntry(binding="finding", subject_kinds=FINDING_KIND,
                         subject_id=QueryParameterRef(parameter="finding_id")),
        result_binding="finding",
        result_shape="subject",
        result_cardinality="many",
        dedupe="subject",
        projection=QueryProjection(fields=tuple(sorted(
            _finding_fields("locus", "repo_ref", "weakness"), key=lambda x: x.name))),
        parameters=(QueryParameterDeclaration(name="finding_id", value_type="string"),),
        evaluation_policy=QueryEvaluationPolicy(
            visible_verdicts=("supported",), visible_currency=("current",),
            conflict_behavior="surface_conflicts"),
        default_budgets=QueryBudgets(max_results=1, max_traversal_depth=1),
        maximum_budgets=QueryBudgets(max_results=10, max_traversal_depth=1),
    ))
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
        # The system model's pulls: what a repository declares, what a registry serves.
        derived(REPO_CONTRACT, "github.repo.snapshot", ["external"], "http_response"),
        derived(PYPI_CONTRACT, "pypi.release", ["external"], "http_response"),
        derived(GH_RELEASE_CONTRACT, "github.release", ["external"], "http_response"),
        derived(GH_API_CONTRACT, "github.api", ["external"], "http_response"),
        derived(ASSET_CONTRACT, "github.release.asset", ["external"], "http_response"),
        # Code findings: a scan's SARIF log, and a reproduction's test report.
        derived(SARIF_CONTRACT, "sarif.log", ["external"], "sarif_log"),
        derived(REPRO_CONTRACT, "security.reproduction", ["external"], "test_report"),
    ]
    for item in raw:
        if item["identity"]["name"] == ASSET_CONTRACT:
            # The retained bundle is the asset base64-encoded inside canonical JSON.
            item["selection_budget"]["max_bytes"] = ASSET_MAX_BYTES * 2
    return [CaptureContract.model_validate(item) for item in raw]


def acquisition_policy() -> SourceAcquisitionPolicy:
    """`security.acquisition` covers every Source alias the kit uses: `catalog` (KEV),
    `record` (CVE record), `epss`, `osv`, `sbom` and `evidence` (an analyst's
    workspace file), the system model's `snapshot` (a repository), `registry`
    (PyPI), `release`, `asset` and `history` (GitHub), and the code findings' `sarif`
    (a scan's log) and `reproduction` (a PoC run's report). Each is required, at most
    24 h old, refused when stale, unavailable or oversized. Network Captures replay as
    attested; workspace files (the SBOM, evidence, SARIF, reproductions) replay
    exactly."""

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
            "inputs": [rule("asset"), rule("catalog"), rule("epss"), rule("evidence", "exact"),
                       rule("history"), rule("osv"), rule("record"), rule("registry"),
                       rule("release"), rule("reproduction", "exact"),
                       rule("sarif", "exact"), rule("sbom", "exact"), rule("snapshot")],
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


_S = PropertySchema(type="string")
_J = PropertySchema(type="json")
_I = PropertySchema(type="integer")
REPO_INPUT = _contract("security-repo-input", forge_host=_S, full_name=_S, ref=_S, scope=_S,
                       path=_S)
SNAPSHOT_SUMMARY = _contract("security-repo-snapshot-summary", locator=_S, revision=_S)
REGISTRY_INPUT = _contract("security-registry-input", project=_S, versions=_I)
REGISTRY_SUMMARY = _contract("security-registry-summary", project=_S, versions=_J)
REPO_PARSE_INPUT = _contract("security-repo-parse-input", source=_S, repo_source=_S,
                             forge_host=_S, full_name=_S, ref=_S, scope=_S, path=_S)
_FACT_COUNTS = _ints("changed", "added", "revised", "retired", "restated")
WORKFLOW_FACTS_REQUEST = _contract("security-workflow-facts-request", snapshot=_J, coverage=_J,
                                   held=_J, targets=_J, releases=_J)
WORKFLOW_FACTS_RESULT = _contract("security-workflow-facts-result", items=_J, locator=_S,
                                  revision=_S, scope=_S, unparsed=_J, **_FACT_COUNTS,
                                  **_ints("workflows", "jobs"))
REPO_PARSE_SUMMARY = _contract("security-repo-parse-summary", locator=_S, revision=_S,
                               scope=_S, unparsed=_J, **_FACT_COUNTS,
                               **_ints("workflows", "jobs"))
REGISTRY_PARSE_INPUT = _contract("security-registry-parse-input", source=_S, project=_S,
                                 versions=_I)
REGISTRY_FACTS_REQUEST = _contract("security-registry-facts-request", release=_J, coverage=_J,
                                   held=_J)
REGISTRY_FACTS_RESULT = _contract("security-registry-facts-result", items=_J, locator=_S,
                                  revision=_S, **_FACT_COUNTS, **_ints("files"))
REGISTRY_PARSE_SUMMARY = _contract("security-registry-parse-summary", locator=_S, revision=_S,
                                   **_FACT_COUNTS, **_ints("files"))
HARDEN_INPUT = _contract("security-harden-input", default_ref=_S, repo_pull=_S,
                         registry_pull=_S, release_pull=_S, versions=_I)
HARDEN_REQUEST = _contract("security-harden-request", hq1=_J, hq2=_J, hq3=_J, hq4=_J, hq5=_J,
                           hq6=_J, params=_J, truncated=_J)
HARDEN_RESULT = _contract("security-harden-result", items=_J, answers=_J,
                          **_ints("posted", "targets", "gaps", "found", "none", "unknown"))
HARDEN_SUMMARY = _contract("security-harden-summary", answers=_J,
                           **_ints("posted", "targets", "gaps", "found", "none", "unknown"))
#: Hardening question -> the QueryDefinition the harden Procedure taps for it.
HARDEN_QUERIES = {
    "hq1": "security.publish_paths",
    "hq2": "security.credentialed_jobs",
    "hq3": "security.mutable_actions",
    "hq4": "security.shared_dependencies",
    "hq5": "security.served_vs_declared",
    "hq6": "security.published_findings",
}
SARIF_INPUT = _contract("security-sarif-import-input", repo_ref=_S)
_SARIF_COUNTS = _ints("mine", "results", "findings", "gaps", "routed_to_assessment", "new",
                      "added", "fixed", "regressed", "changed", "posted")
SARIF_REQUEST = _contract("security-sarif-request", sarif_text=_S, held=_J, repo_ref=_S,
                          truncated=_J)
SARIF_RESULT = _contract("security-sarif-result", items=_J, inbox=_J, repo_ref=_S, tools=_J,
                         revisions=_J, full=_J, **_SARIF_COUNTS)
SARIF_SUMMARY = _contract("security-sarif-summary", repo_ref=_S, tools=_J, revisions=_J,
                          full=_J, **_SARIF_COUNTS)


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
    budget_seconds = 90 if release == VARIANT else 60
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
            + (" 1.1.0: a 90 s budget." if release == VARIANT else "")
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


def _workspace_file(logical_source: str, relative_path: str) -> dict[str, Any]:
    return {
        "tag": "playbill-workspace-file-source-request-v2",
        "logical_source": logical_source,
        "relative_path": relative_path,
        "coordinate_type": "http-response-v1",
        "coordinate": {"revision": "working"},
        "selector_type": "whole-response-v1",
        "selector": {"whole": True},
        "replayability": "exact",
    }


def _file_acquire(cx: Cruxible, name: str, alias: str, contract: str, logical_source: str,
                  description: str) -> Any:
    """Read one workspace file (input.relative_path) and retain it under ``contract``."""

    builtin = cx.provider_interface("workspace.file", provider=BUILTIN_PROVIDER)
    sequence = Sequence(
        [
            Source(alias, capture_contract=contract, next="summary",
                   request=_workspace_file(logical_source, "$input.relative_path")),
            Project("summary", contract_out=FILE_SUMMARY, fields={
                "bytes_digest": f"$steps.{alias}.source.bytes_digest",
                "byte_length": f"$steps.{alias}.source.byte_length",
            }),
        ],
        name=name,
        description=description,
        contract_in=PATH_INPUT,
        contract_out=FILE_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(60, 1, 16_777_216),
        hard_caps=_caps(120, 1, 16_777_216, 1),
    ).bind(**{alias: builtin})
    return sequence.build()


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


def sarif_acquire(cx: Cruxible) -> Any:
    return _file_acquire(
        cx, "security.sarif-acquire", "sarif", SARIF_CONTRACT, "sarif.log",
        "Read one SARIF 2.1.0 scan log from the attached workspace (input.relative_path) and "
        f"retain it under {SARIF_CONTRACT}; the repository's security.sarif-import Line reads "
        "it when it lands. Annotate each run first: versionControlProvenance (repositoryUri, "
        "revisionId) and properties[\"cruxible.coverage\"] (full or partial).")


def reproduction_acquire(cx: Cruxible) -> Any:
    return _file_acquire(
        cx, "security.reproduction-acquire", "reproduction", REPRO_CONTRACT,
        "security.reproduction",
        "Read one proof-of-concept run's report from the attached workspace "
        f"(input.relative_path: a JUnit XML or a test log) and retain it under {REPRO_CONTRACT}; "
        "cite the Capture for security.finding.verdict (confirmed: the PoC fails while "
        "vulnerable) or verification (fixed: it passes).")


def _sarif_steps(terminal: list[Any], guard: Guard) -> list[Any]:
    """The landed SARIF log, the Line repository's held findings, the analysis, then the
    repository guard (another repository's log halts wrong_repo) and ``terminal``."""

    return [
        Source("sarif", capture_contract=SARIF_CONTRACT, next="held",
               request=_workspace_file("sarif.log", "scan.sarif")),
        StateTap("held", query="security.finding_index", next="parse",
                 parameters={"repo_ref": "$input.repo_ref"}),
        Call("parse", contract_in=SARIF_REQUEST, contract_out=SARIF_RESULT, next="summary",
             input={"sarif_text": "$steps.sarif.content.text",
                    "held": "$steps.held.result.rows", "repo_ref": "$input.repo_ref",
                    "truncated": "$steps.held.truncated"}),
        _project(SARIF_SUMMARY, "parse", "mine"),
        Guard("mine", predicate=_changed("parse", "mine"), on_true=guard.name,
              on_false="other", refusal_code="wrong_repo",
              message="The landed SARIF log has no run of the Line's repository."),
        guard,
        *terminal,
        Halt("other", reason="wrong_repo"),
    ]


def sarif_import(cx: Cruxible) -> Any:
    builtin = cx.provider_interface("workspace.file", provider=BUILTIN_PROVIDER)
    parse = cx.provider_interface("security.sarif-findings", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        _sarif_steps(
            [ProposeChangeSet("propose", candidate_templates={"items": "$steps.parse.items"},
                              result=Output("summary")),
             Halt("nochange", reason="no_change")],
            Guard("changed", predicate=_changed("parse"), on_true="propose",
                  on_false="nochange", refusal_code="no_change",
                  message="The scan reports nothing the held findings lack.")),
        name="security.sarif-import",
        description=(
            "Read the SARIF log Capture that triggered the Line (security.sarif-v1) for the "
            "Line's repository (parameter repo_ref, host/owner/repo) and propose what changed: "
            "each new finding by key (repository, weakness, locus) with the rules and finders "
            "that reported it and its severity; rules and finders a held finding lacks; "
            "verification fixed for a held finding a full scan of its rules no longer reports, "
            "present for a fixed one it reports again. Never a verdict. Halts wrong_repo for "
            "another repository's log, no_change when nothing changed. Propose-only. Runs as a "
            "Line with trigger_input sarif."
        ),
        contract_in=SARIF_INPUT,
        contract_out=SARIF_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 5000),
    ).bind(sarif=builtin, parse=parse)
    return sequence.build()


def sarif_attention(cx: Cruxible) -> Any:
    builtin = cx.provider_interface("workspace.file", provider=BUILTIN_PROVIDER)
    parse = cx.provider_interface("security.sarif-findings", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        _sarif_steps(
            [PostInbox("post", input={"items": Output("parse", "inbox")}, max_items=1000),
             Halt("quiet", reason="nothing_to_post")],
            Guard("posted", predicate=_changed("parse", "posted"), on_true="post",
                  on_false="quiet", refusal_code="nothing_to_post",
                  message="The scan has no location gap and no regression.")),
        name="security.sarif-attention",
        description=(
            "Read the SARIF log Capture that triggered the Line for the Line's repository "
            "(parameter repo_ref) and post one inbox item per location gap (a result with no "
            "repository-relative path or no stable locus: one per tool, rule and path) and "
            "per regression (a fixed finding a full scan reports again). Never changes "
            "accepted state. Runs as a Line with trigger_input sarif, beside "
            "security.sarif-import."
        ),
        contract_in=SARIF_INPUT,
        contract_out=SARIF_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 1000),
    ).bind(sarif=builtin, parse=parse)
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


# --- the system model: pull, parse, harden -------------------------------------


def repo_acquire(cx: Cruxible) -> BlueprintInput:
    snapshot = cx.provider_interface("security.repo-snapshot", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("snapshot", capture_contract=REPO_CONTRACT, next="summary", request={
                name: f"$input.{name}" for name in ("forge_host", "full_name", "ref", "scope",
                                                    "path")}),
            Project("summary", contract_out=SNAPSHOT_SUMMARY, fields={
                "locator": "$steps.snapshot.locator",
                "revision": "$steps.snapshot.revision"}),
        ],
        name="security.repo-acquire",
        description=(
            "Read what one GitHub repository declares at one ref for one scope (input: "
            "forge_host, full_name, ref, scope ci.workflows or release.manifest, path) and "
            "retain it under security.repo-snapshot-v1: the revision R and every file at R. "
            "An unchanged source is the same bytes. A parse Line for that source reads it "
            "when it lands."
        ),
        contract_in=REPO_INPUT,
        contract_out=SNAPSHOT_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(120, 1, 16_777_216),
        hard_caps=_caps(300, 1, 16_777_216, 1),
    ).bind(snapshot=snapshot)
    return _blueprint(sequence, _interface(cx, "security.repo-snapshot"), "snapshot")


def registry_acquire(cx: Cruxible) -> BlueprintInput:
    registry = cx.provider_interface("security.pypi-release", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("registry", capture_contract=PYPI_CONTRACT, next="summary", request={
                "project": "$input.project", "versions": "$input.versions"}),
            Project("summary", contract_out=REGISTRY_SUMMARY, fields={
                "project": "$steps.registry.project",
                "versions": "$steps.registry.versions"}),
        ],
        name="security.registry-acquire",
        description=(
            "Read what PyPI serves for one project (input: project, versions = the newest N, "
            "default 3): each file's digest and provenance, retained under "
            "security.pypi-release-v1. A parse Line for that project reads it when it lands."
        ),
        contract_in=REGISTRY_INPUT,
        contract_out=REGISTRY_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(120, 1, 16_777_216),
        hard_caps=_caps(300, 1, 16_777_216, 1),
    ).bind(registry=registry)
    return _blueprint(sequence, _interface(cx, "security.pypi-release"), "registry")


def _github_fetch(cx: Cruxible, name: str, slot: str, contract: str, logical_source: str,
                  description: str, *, max_bytes: int) -> BlueprintInput:
    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    request = _fetch("$input.url", logical_source, max_bytes)
    sequence = Sequence(
        [
            Source(slot, capture_contract=contract, next="summary", request=request),
            _summary(slot),
        ],
        name=name,
        description=description,
        contract_in=URL_INPUT,
        contract_out=HTTP_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(120, 1, max_bytes),
        hard_caps=_caps(300, 1, max_bytes, 1),
    ).bind(**{slot: web})
    return _blueprint(sequence, _interface(cx, "web.fetch"), slot)


def release_acquire(cx: Cruxible) -> BlueprintInput:
    return _github_fetch(
        cx, "security.release-acquire", "release", GH_RELEASE_CONTRACT, "github.release",
        "Fetch one GitHub release (input.url: https://api.github.com/repos/OWNER/REPO/"
        f"releases/tags/TAG) and retain it under {GH_RELEASE_CONTRACT}: its assets, their "
        "digests, uploader and update times. Cite the Capture for artifact facts.",
        max_bytes=GITHUB_MAX_BYTES)


def asset_fetch(cx: Cruxible) -> BlueprintInput:
    """A kit Source, not web.fetch: web.fetch leaves archives to the document plane."""

    asset = cx.provider_interface("security.release-asset", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("asset", capture_contract=ASSET_CONTRACT, next="summary",
                   request={"url": "$input.url"}),
            _summary("asset"),
        ],
        name="security.asset-fetch",
        description=(
            "Read the bytes one GitHub release asset serves (input.url: its download URL, "
            "https://github.com/OWNER/REPO/releases/download/TAG/NAME) and retain them under "
            f"{ASSET_CONTRACT}; the summary's body_digest is the served digest "
            "(security.artifact.sha256)."
        ),
        contract_in=URL_INPUT,
        contract_out=HTTP_SUMMARY,
        returns="summary",
        acquisition_policy=POLICY,
        budget=_budget(120, 1, ASSET_MAX_BYTES * 2),
        hard_caps=_caps(300, 1, ASSET_MAX_BYTES * 2, 1),
    ).bind(asset=asset)
    return _blueprint(sequence, _interface(cx, "security.release-asset"), "asset")


def history_acquire(cx: Cruxible) -> BlueprintInput:
    return _github_fetch(
        cx, "security.history-acquire", "history", GH_API_CONTRACT, "github.api",
        "Fetch one GitHub API answer about history (input.url: commits?path=...&sha=..., or "
        "actions/workflows/W/runs?branch=...) and retain it under "
        f"{GH_API_CONTRACT}: which commit changed a path, which runs ran.",
        max_bytes=GITHUB_MAX_BYTES)


def _mine(alias: str, field: str, parameter: str) -> GuardPredicate:
    """The landed Capture is the one this Line's source names."""

    return GuardPredicate(
        left=PredicateOperand(kind="step", alias=alias, path=(field,)),
        operator="eq",
        right=PredicateOperand(kind="input", input_name=parameter),
    )


def repo_parse(cx: Cruxible) -> Any:
    """One Line per (repository, ref, scope), bound by its parameters: every tap is keyed by
    them (a tap cannot depend on the landed Capture), so a landing for another source
    halts other_source before reading anything."""

    snapshot = cx.provider_interface("security.repo-snapshot", provider=SOURCES_PROVIDER)
    facts = cx.provider_interface("security.workflow-facts", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("snapshot", capture_contract=REPO_CONTRACT, next="mine", request={
                name: f"$input.{name}" for name in ("forge_host", "full_name", "ref", "scope",
                                                    "path")}),
            Guard("mine", predicate=_mine("snapshot", "locator", "source"), on_true="coverage",
                  on_false="other", refusal_code="other_source",
                  message="The landed snapshot is another source's."),
            StateTap("coverage", query="security.coverage_index", next="held", parameters={
                "source": "$input.source", "scope": "$input.scope"}),
            StateTap("held", query="security.source_facts", next="targets",
                     parameters={"source": "$input.repo_source"}),
            StateTap("targets", query="security.repo_targets", next="releases", parameters={
                "forge_host": "$input.forge_host", "full_name": "$input.full_name"}),
            StateTap("releases", query="security.registry_facts", next="parse", parameters={
                "registry": "github_release", "name": "$input.full_name"}),
            Call("parse", contract_in=WORKFLOW_FACTS_REQUEST, contract_out=WORKFLOW_FACTS_RESULT,
                 next="summary", input={
                     "snapshot": "$steps.snapshot",
                     "coverage": "$steps.coverage.result.rows",
                     "held": "$steps.held.result.rows",
                     "targets": "$steps.targets.result.rows",
                     "releases": "$steps.releases.result.rows"}),
            _project(REPO_PARSE_SUMMARY, "parse", "propose"),
            ProposeChangeSet("propose", candidate_templates={"items": "$steps.parse.items"},
                             result=Output("summary")),
            Halt("other", reason="other_source"),
        ],
        name="security.repo-parse",
        description=(
            "Read the repository snapshot that triggered the Line (security.repo-snapshot-v1) "
            "for the Line's source (parameters: source, repo_source, forge_host, full_name, "
            "ref, scope, path) and propose what changed: workflows, jobs and their triggers, "
            "permissions, secrets, environment, actions and publish targets, or a manifest's "
            "declared digests, plus the source's coverage restated (an unchanged snapshot "
            "re-observes it; a new revision revises it). Halts other_source for another "
            "source's snapshot. Runs as a Line with trigger_input snapshot."
        ),
        contract_in=REPO_PARSE_INPUT,
        contract_out=REPO_PARSE_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 5000),
    ).bind(snapshot=snapshot, parse=facts)
    return sequence.build()


def registry_parse(cx: Cruxible) -> Any:
    registry = cx.provider_interface("security.pypi-release", provider=SOURCES_PROVIDER)
    facts = cx.provider_interface("security.registry-facts", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            Source("registry", capture_contract=PYPI_CONTRACT, next="mine", request={
                "project": "$input.project", "versions": "$input.versions"}),
            Guard("mine", predicate=_mine("registry", "project", "project"), on_true="coverage",
                  on_false="other", refusal_code="other_source",
                  message="The landed release is another project's."),
            StateTap("coverage", query="security.coverage_index", next="held", parameters={
                "source": "$input.source", "scope": "registry.files"}),
            StateTap("held", query="security.registry_facts", next="parse", parameters={
                "registry": "pypi", "name": "$input.project"}),
            Call("parse", contract_in=REGISTRY_FACTS_REQUEST,
                 contract_out=REGISTRY_FACTS_RESULT, next="summary", input={
                     "release": "$steps.registry",
                     "coverage": "$steps.coverage.result.rows",
                     "held": "$steps.held.result.rows"}),
            _project(REGISTRY_PARSE_SUMMARY, "parse", "propose"),
            ProposeChangeSet("propose", candidate_templates={"items": "$steps.parse.items"},
                             result=Output("summary")),
            Halt("other", reason="other_source"),
        ],
        name="security.registry-parse",
        description=(
            "Read the PyPI release Capture that triggered the Line (security.pypi-release-v1) "
            "for the Line's project (parameters: source pypi/PROJECT, project, versions) and "
            "propose what changed: each served file as an artifact with its digest, release, "
            "and (from provenance) the workflow at the commit that published it, its "
            "environment and the commit; the target's source repository; the coverage "
            "restated. Halts other_source for another project. Runs as a Line with "
            "trigger_input registry."
        ),
        contract_in=REGISTRY_PARSE_INPUT,
        contract_out=REGISTRY_PARSE_SUMMARY,
        returns="summary",
        activation_policy="drain",
        acquisition_policy=POLICY,
        budget=_budget(120, 2, 16_777_216),
        hard_caps=_caps(300, 2, 16_777_216, 5000),
    ).bind(registry=registry, parse=facts)
    return sequence.build()


def harden_procedure(cx: Cruxible) -> Any:
    classify = cx.provider_interface("security.harden", provider=ANALYSIS_PROVIDER)
    taps: list[Any] = []
    names = list(HARDEN_QUERIES)
    for index, alias in enumerate(names):
        taps.append(StateTap(alias, query=HARDEN_QUERIES[alias],
                             next=names[index + 1] if index + 1 < len(names) else "classify"))
    sequence = Sequence(
        [
            *taps,
            Call("classify", contract_in=HARDEN_REQUEST, contract_out=HARDEN_RESULT,
                 next="summary", input={
                     **{alias: f"$steps.{alias}.result.rows" for alias in names},
                     "params": "$input",
                     "truncated": {alias: f"$steps.{alias}.truncated" for alias in names}}),
            _project(HARDEN_SUMMARY, "classify", "posted"),
            Guard("posted", predicate=_changed("classify", "posted"), on_true="post",
                  on_false="quiet", refusal_code="nothing_to_post",
                  message="Every hardening answer is none: nothing to post."),
            PostInbox("post", input={"items": Output("classify", "items")}, max_items=200),
            Halt("quiet", reason="nothing_to_post"),
        ],
        name="security.harden",
        description=(
            "Ask the six hardening questions (HQ1-HQ6) about every gated target (a target "
            "with a security.target.publish_gate) and answer each in three states: found "
            "(posted as a finding), none (a current coverage answers it; run summary only) or "
            "unknown (posted as one gap item per source, naming the pull: {source, pull, "
            "input}). HQ6 (an open confirmed code finding in a release the target serves) is "
            "found or not recorded, never none. Observe-only. Runs as a Line (parameters: "
            "default_ref, repo_pull, "
            "registry_pull, release_pull, versions): daily, on a pull landing, or line run."
        ),
        contract_in=HARDEN_INPUT,
        contract_out=HARDEN_SUMMARY,
        returns="summary",
        activation_policy="drain",
        budget=_budget(120, 1, 1_048_576),
        hard_caps=_caps(300, 1, 1_048_576, 200),
    ).bind(classify=classify)
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
                       "attention, SBOM import and applicability Procedures; the system "
                       "model's pull Blueprints, parse Procedures and hardening Procedure; "
                       "the code findings' acquisition, import and attention Procedures.")
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
    draft.procedure(definition=repo_acquire(cx))
    draft.procedure(definition=registry_acquire(cx))
    draft.procedure(definition=release_acquire(cx))
    draft.procedure(definition=asset_fetch(cx))
    draft.procedure(definition=history_acquire(cx))
    draft.procedure(definition=repo_parse(cx))
    draft.procedure(definition=registry_parse(cx))
    draft.procedure(definition=harden_procedure(cx))
    draft.procedure(definition=sarif_acquire(cx))
    draft.procedure(definition=reproduction_acquire(cx))
    draft.procedure(definition=sarif_import(cx))
    draft.procedure(definition=sarif_attention(cx))
    submit(cx, draft, "procedures")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stage", choices=("definitions", "procedures"))
    parser.add_argument("--release", default=RELEASE, choices=(RELEASE, VARIANT))
    args = parser.parse_args()
    with Cruxible.connect() as cx:
        if args.stage == "definitions":
            definitions(cx, args.release)
        else:
            procedures(cx, args.release)


if __name__ == "__main__":
    main()
