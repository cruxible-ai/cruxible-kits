"""Author the security kit's definitions in a fresh authoring instance.

    python security_definitions.py definitions [--release 1.3.0|1.3.1]
    python security_definitions.py procedures  [--release 1.3.0|1.3.1]

``1.3.1`` is the release gate's upgrade variant (``source/variants/1.3.1-gate``,
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
from cruxible_core.claims.claim_type_inputs import ClaimTypeInputRecord, lower_claim_type_input
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
    Source,
    StateTap,
)
from cruxible_client.contracts.acquisition_policies import SourceAcquisitionPolicy
from cruxible_client.contracts.artifacts import ArtifactIdentity
from cruxible_client.contracts.authoring.inputs import BlueprintInput, ProcedureInput, QueryDefinitionInput
from cruxible_client.contracts.procedures.authored import ProcedureSpec, lower_procedure_spec
from cruxible_client.contracts.query.authored import QuerySpecInput
from cruxible_client.contracts.captures import (
    CanonicalDuration,
)
from cruxible_client.contracts.capture_contract_inputs import (CaptureContractInputRecord, lower_capture_contract_input)
from cruxible_client.contracts.claim_types import (
    ClaimFreshnessDuration,
    ClaimInverse,
    ClaimInverseObjectKeyPart,
    ClaimType,
    ClaimTypeMemberDescription,
)
from cruxible_client.contracts.policies import (
    CaptureContractAdmission,
    ClaimEvidenceAdmissionPolicy,
    ClaimEvidenceAdmissionRule,
)
from cruxible_client.contracts.procedures.contract_schema import PropertySchema
from cruxible_client.contracts.procedures.models import (
    GuardPredicate,
    PredicateOperand,
    ProcedureBudget,
    ProcedureHardCaps,
)

DATA = Path(__file__).resolve().parent / "data"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_SOURCE = "cisa.kev.catalog"
KEV_CONTRACT = "security.kev-http-v1"
CVE_CONTRACT = "security.cve-record-http-v1"
OSV_CONTRACT = "security.osv-query-v1"
#: OSV's published ecosystem list (ecosystems.txt): what OSV indexes, OSV's own word.
OSV_ECOSYSTEMS_CONTRACT = "security.osv-ecosystems-v1"
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
#: Incident response (1.3.0): what runs where, a log read, a credential's key state.
INVENTORY_CONTRACT = "security.runtime-inventory-v1"
LOG_CONTRACT = "security.log-read-v1"
CREDENTIAL_CONTRACT = "security.credential-state-v1"
#: Contracts whose Captures may carry a secret by accident: erasure-authorized.
ERASABLE_CONTRACTS = (INVENTORY_CONTRACT, LOG_CONTRACT, CREDENTIAL_CONTRACT)
#: The system model's pull contracts: every fact about the organization's systems
#: cites a Capture under one of them.
SYSTEM_CONTRACTS = (REPO_CONTRACT, PYPI_CONTRACT, GH_RELEASE_CONTRACT, GH_API_CONTRACT,
                    ASSET_CONTRACT)
POLICY = "default"
RELEASE = "1.3.0"  # the kit release
VARIANT = "1.3.1"  # the release gate's upgrade variant (not published)
WEB_PROVIDER = "cruxible-provider-web"
ANALYSIS_PROVIDER = "security-analysis-provider"
SOURCES_PROVIDER = "security-sources-provider"
BUILTIN_PROVIDER = "cruxible-builtin"
KEV_MAX_BYTES = 4_194_304  # the catalog is ~1.7 MB; web.fetch defaults to 256 KiB
CVE_MAX_BYTES = 1_048_576
GITHUB_MAX_BYTES = 4_194_304
ASSET_MAX_BYTES = 33_554_432  # security.release-asset's ceiling
#: The built-in workspace.file structures at most 1 MiB (core
#: providers/builtin_workspace_file.py MAX_STRUCTURED_BYTES): every workspace-file
#: Procedure's budget says so.
WORKSPACE_FILE_MAX_BYTES = 1_048_576
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
#: A package without version or qualifiers: what a vulnerability affects.
PACKAGE = {"type": "string", "pattern": r"^pkg:[a-z0-9.+-]+/[^@?#\s]+$"}
#: A release's OSV coverage: whether OSV answered every component, and why not.
OSV_COVERAGE = {"type": "string", "pattern": (
    r"^(complete|partial): [0-9]+ of [0-9]+ components answered"
    r"(; not indexed: [a-z0-9.+-]+ [0-9]+(, [a-z0-9.+-]+ [0-9]+)*)?(; unanswered [0-9]+)?"
    r"(; unidentified [0-9]+)?; set [0-9a-f]{16}$")}
#: Kit data (cited, editable by authoring a successor of the Procedure that carries it):
#: which OSV ecosystem answers for a purl type.
PURL_OSV_ECOSYSTEMS = json.loads((DATA / "purl_osv_ecosystems.json").read_text())
#: Kit data: how a CVE record's collectionURL names a package (cve-applicability carries it).
CVE_COLLECTIONS = json.loads((DATA / "cve_collections.json").read_text())
#: Another name a release's product goes by in vulnerability records.
ALIAS = {"type": "string", "pattern": (
    r"^(pkg:[a-z0-9.+-]+/[^@?#\s]+|cpe:2\.3:[aho]:[^:\s]+:[^:\s]+|https?://\S+"
    r"|[^/\s][^/]*/[^/]*[^/\s])$")}
SHA256 = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
COMMIT = {"type": "string", "pattern": r"^[0-9a-f]{40}$"}
FULL_NAME = {"type": "string", "pattern": r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}
PERMISSION = {"type": "string", "pattern": r"^[A-Za-z*_-]+:[A-Za-z_-]+$"}
REGISTRIES = ("ghcr", "github_pages", "github_release", "pypi")
COVERAGE_SCOPES = ("ci.workflows", "inventory.runtime", "registry.files", "release.manifest")
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
# Each use keeps its provider's source restriction when contract shapes coalesce.
CONTRACT_USES = {
    KEV_CONTRACT: ("security.fetched-v1", "cisa.kev.catalog"),
    CVE_CONTRACT: ("security.fetched-v1", "cve.record"),
    OSV_CONTRACT: ("security.fetched-v1", "osv.dev.query"),
    OSV_ECOSYSTEMS_CONTRACT: ("security.fetched-v1", "osv.dev.ecosystems"),
    EPSS_CONTRACT: ("security.fetched-v1", "first.epss.daily"),
    REPO_CONTRACT: ("security.fetched-v1", "github.repo.snapshot"),
    PYPI_CONTRACT: ("security.fetched-v1", "pypi.release"),
    GH_RELEASE_CONTRACT: ("security.fetched-v1", "github.release"),
    GH_API_CONTRACT: ("security.fetched-v1", "github.api"),
    ASSET_CONTRACT: ("security.fetched-large-v1", "github.release.asset"),
    SBOM_CONTRACT: ("security.file-v1", "cyclonedx.sbom"),
    WORKSPACE_EVIDENCE_CONTRACT: ("security.file-v1", "security.analysis.evidence"),
    SARIF_CONTRACT: ("security.file-v1", "sarif.log"),
    REPRO_CONTRACT: ("security.file-v1", "security.reproduction"),
    INVENTORY_CONTRACT: ("security.file-erasable-v1", "security.inventory"),
    LOG_CONTRACT: ("security.file-erasable-v1", "security.log-read"),
    CREDENTIAL_CONTRACT: ("security.file-erasable-v1", "security.credential-state"),
    OUTPUT_CONTRACT: (OUTPUT_CONTRACT, None),
    SELF_SOURCE_CONTRACT: (SELF_SOURCE_CONTRACT, None),
}


def _capture(use: str) -> str:
    return CONTRACT_USES.get(use, (use, None))[0]


#: What an analyst's judgment may cite: their own words, or a workspace file
#: retained by security.evidence-acquire.
JUDGMENT_EVIDENCE = (SELF_SOURCE_CONTRACT, WORKSPACE_EVIDENCE_CONTRACT)

# --- ClaimTypes ---------------------------------------------------------------
# (predicate, subject kinds, object, literal schema or object kinds, cardinality,
#  role, evidence contracts, canonical form, description). Observations need a
# Capture under one of their contracts; normative statements are supported by
# their own origin. Every ClaimType is v8 (security.asset.runs v9: v8 plus the inverse in
# INVERSES); a literal one's canonical form is how its
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
     "normative", (), NAME_FORM, "The product's name; with version, the release's key. A "
     "release a runtime scan observed is named by its purl's whole namespace and name "
     "(debian/php8.2, github.com/cli/cli/v2), never a last segment."),
    ("security.release.version", ("security.release",), "literal", TEXT, "one", "normative", (),
     ("trim",), "The release's version string; with product_name, the release's key."),
    ("security.assessment.release_id", ("security.assessment",), "literal", TEXT, "one",
     "normative", (), ("trim",),
     "The id of the release this assessment is about; with cve_id, the assessment's key."),
    ("security.assessment.cve_id", ("security.assessment",), "literal", CVE_ID, "one",
     "normative", (), ("trim", "upper"),
     "The CVE this assessment is about; with release_id, the assessment's key."),
    ("security.asset.hostname", ("security.asset",), "literal", TEXT, "one", "normative", (),
     ("trim", "casefold"), "The asset's hostname (a host, or a workload such as "
     "k8s:prod/storefront-a); its key."),
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
     {"enum": ["ci", "development", "production", "staging", "workstation"], "type": "string"},
     "one", "normative", (), (),
     "The environment the asset runs in: production, staging, development, a workstation (a "
     "developer's or maintainer's machine) or ci (a CI runner)."),
    ("security.asset.installs", ("security.asset",), "subject", ("security.release",), "many",
     "normative", (), (), "A software release installed on the asset."),
    ("security.asset.internet_exposed", ("security.asset",), "literal", {"type": "boolean"},
     "one", "normative", (), (), "Whether the asset is reachable from the internet."),
    ("security.asset.serves", ("security.asset",), "subject", ("security.service",), "many",
     "normative", (), (), "A service the asset serves."),
    ("security.release.product", ("security.release",), "subject", ("security.product",), "one",
     "sourced", (SBOM_CONTRACT,), (), "The product this release is a version of."),
    ("security.release.component", ("security.release",), "literal", PURL, "many",
     "observation", (INVENTORY_CONTRACT, SBOM_CONTRACT), ("trim",),
     "A component of the release, as its package URL with version (purl@version), observed "
     "in an SBOM; for a runtime a scan observed running, the runtime's own purl (OSV decides "
     "distro builds by it)."),
    ("security.product.supplied_by", ("security.product",), "subject", ("security.supplier",),
     "one", "sourced", (SBOM_CONTRACT,), (), "The supplier of the product."),
    ("security.service.criticality", ("security.service",), "literal",
     {"enum": ["critical", "standard"], "type": "string"}, "one", "normative", (), (),
     "How critical the service is to the organization."),
    ("security.service.owned_by", ("security.service",), "subject", ("security.team",), "one",
     "normative", (), (), "The team accountable for the service."),
    ("security.service.log_source", ("security.service",), "literal", TEXT, "many", "normative",
     (), ("trim",), "Where one of the service's logs lives, as a short identifier "
     "(caddy:app-1:/var/log/caddy/access.log): a pointer, nothing else. Retention, how to query "
     "it, who owns it and any reasoning go in a doc section the Claim cites, never in the "
     "value. An incident's audit of the service starts from this list (the respond Line names "
     "it); audit.log_source is the set that incident audits."),
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
     "their own words or a workspace file (security.workspace-evidence-v1, retained by "
     "security.evidence-acquire: a source's Capture is not citable for a judgment), with their "
     "reasoning in its because. The kit's Procedures never revise a normative status; retire "
     "it to hand the assessment back to them."),
    ("security.assessment.justification", ("security.assessment",), "literal",
     {"enum": sorted(JUSTIFICATIONS), "type": "string"}, "one", "judged",
     (CVE_CONTRACT, OSV_CONTRACT, OUTPUT_CONTRACT), (),
     "Why a not_affected release is not affected (the VEX/CSAF justification): an observation "
     "from a source, or (normative) an analyst's judgment citing their own words or a "
     "workspace file (security.workspace-evidence-v1). Required in practice with every "
     "not_affected status; core cannot require it."),
    ("security.assessment.component", ("security.assessment",), "literal", PURL, "many",
     "judged", (CVE_CONTRACT, OSV_CONTRACT), ("trim",),
     "The release's component that brings the vulnerability in (purl@version): which "
     "dependency an affected release needs to change. An observation is a source's word (OSV's "
     "answer for the component, or a CVE record whose packageName names it); a normative Claim "
     "is an analyst's, citing their own words or a workspace file "
     "(security.workspace-evidence-v1, via security.evidence-acquire)."),
    ("security.release.product_alias", ("security.release",), "literal", ALIAS, "many",
     "normative", (WORKSPACE_EVIDENCE_CONTRACT,), ("trim",),
     "Another name the release's product goes by in vulnerability records, as an analyst "
     "states it citing evidence (a workspace file retained by security.evidence-acquire: the "
     "formula, the project page): vendor/product as a CVE record's affected entry names it "
     "(cli/cli for a Homebrew gh release), a package URL without version "
     "(pkg:golang/github.com/cli/cli/v2), a repository URL (https://github.com/cli/cli) or a "
     "CPE prefix (cpe:2.3:a:github:cli). security.cve-applicability matches a record by it "
     "as by the release's own name; re-acquire the record after stating it."),
    ("security.release.osv_coverage", ("security.release",), "literal", OSV_COVERAGE, "one",
     "observation", (OSV_CONTRACT,), ("trim",),
     "Whether OSV answered for every component of the release, as the OSV query Capture shows: "
     "complete (N of N components answered), or partial with how many it answered, the purl "
     "types it does not index (brew, generic: never asked, since OSV's empty answer there "
     "would read as no advisories) and how many went unanswered. What OSV indexes is its own "
     "word (its ecosystems.txt, captured beside every query) read through the kit's purl type "
     "map. An empty OSV answer is a negative only under complete coverage. It is bound to the "
     "exact component set OSV answered for (set: 16 hex of the sha256 of the sorted component "
     "purls): another set, even of the same size, is unanswered until OSV answers again. "
     "Components the SBOM lists without a purl (unidentified) keep it partial."),
    ("security.release.unidentified_components", ("security.release",), "literal",
     {"type": "integer", "minimum": 0}, "one", "observation", (SBOM_CONTRACT,), (),
     "How many components the release's SBOM lists without a package URL with a version (an "
     "operating-system component too): what they are is unknown, OSV is never asked about "
     "them, so the release's OSV coverage stays partial and no negative rests on OSV's "
     "silence. Restated (revised) when a later SBOM of the release counts differently."),
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
    ("security.vulnerability.package", ("security.vulnerability",), "literal", PACKAGE, "many",
     "observation", (OSV_CONTRACT,), ("trim",),
     "A package OSV's records say the vulnerability affects, as a package URL without version "
     "(pkg:deb/debian/php8.2, pkg:pypi/jinja2): OSV knows the CVE. A release whose components "
     "OSV answered in full and that holds none of these packages is not affected (an "
     "incident's RQ1 reads it none, citing both); with none stated, OSV's silence decides "
     "nothing."),
    ("security.vulnerability.affected_product", ("security.vulnerability",), "literal", TEXT,
     "many", "observation", (CVE_CONTRACT,), NAME_FORM,
     "A product the vulnerability's CVE record names as affected, named as the kit names "
     "releases (an affected entry's product, or its packageName: php, cli/cli), whether or not "
     "inventory holds it: with OSV's packages and the releases assessed affected, the "
     "products an incident's RQ1 must rule out on an asset before it answers the asset none. "
     "A release the record names by another name is matched through its product_alias."),
    ("security.vulnerability.watch_reason", ("security.vulnerability",), "literal", TEXT,
     "one", "normative", (), (),
     "The decision to track the vulnerability, and why. A vulnerability is tracked when it has "
     "one, when an affected or inconclusive assessment links it to a release in inventory, or "
     "when an incident responds to it; a bare vulnerability Subject is tracked by nothing."),
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
     (CREDENTIAL_CONTRACT, INVENTORY_CONTRACT, OUTPUT_CONTRACT), (),
     "Whether the work was verified, as observed from retained evidence: a patch by a full "
     "runtime-inventory scan (the asset no longer runs the affected release), a rotation by a "
     "separate state read of the credential (the old key revoked, a new one issued). A "
     "self-report (remediation.progress completed) never sets it."),
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
     (), ("trim",), "The fully read source (host/owner/repo@ref:path, registry/name, or an "
     "inventory scope's name); with scope, the coverage's key."),
    ("security.coverage.scope", ("security.coverage",), "literal",
     {"enum": list(COVERAGE_SCOPES), "type": "string"}, "one", "normative", (), (),
     "What was read in full: ci.workflows, release.manifest, registry.files, or "
     "inventory.runtime (every asset of one inventory scope, with what it runs)."),
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
     "observation", (INVENTORY_CONTRACT, PYPI_CONTRACT, REPO_CONTRACT), ("trim",),
     "The revision every file was read at: a commit SHA, the digest of a registry's served "
     "file set, or the digest of a full runtime-inventory scan's (asset, runs) set; re-read on "
     "every pull and stale 12 h after the last. Absence inside current coverage is an answer; "
     "outside it, unknown."),
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
# Incident response (1.3.0): patch, audit, rotate. Cruxible holds what needs doing and
# why, who approved it and the evidence it is done; the user's agent acts with its own
# tools. Closure is evidence (a scan, a separate state read), never a self-report.
# Secrets never enter: credentials carry non-secret key ids only.
ROTATION_POLICIES = {
    "all_exposed": "Rotate every credential a service of an exposed asset uses.",
    "on_found_or_unknown": "Rotate the credentials of a service whose audit found "
    "exploitation or cannot rule it out (unknown).",
}
AUDIT_RESULTS = {
    "exploited": "The window's logs show exploitation: cite the decisive read.",
    "inconclusive": "The logs cannot decide it (a gap, a missing source, ambiguous matches).",
    "not_exploited": "Every stated log source (the audit's, which must include every source "
    "the service lists) was read in full over the window and shows no exploitation; counts as "
    "none only when the reads cover [window_start, window_end].",
}
INCIDENT_KIND = ("security.incident",)
AUDIT_KIND = ("security.audit",)
CREDENTIAL_KIND = ("security.credential",)
CRED_FACT = (CREDENTIAL_CONTRACT,)
RESPONSE: list[ClaimRow] = [
    # The incident: the CVEs of one response and the window it is answered over.
    ("security.incident.name", INCIDENT_KIND, "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The incident's name (PHP2Shell); its key."),
    ("security.incident.vulnerability", INCIDENT_KIND, "subject", ("security.vulnerability",),
     "many", "normative", (), (), "A CVE this incident responds to: one response, one audit "
     "per service, however many CVEs."),
    ("security.incident.window_start", INCIDENT_KIND, "literal", DATETIME, "one", "normative",
     (), (), "The start of the exposure window (the lead's call, e.g. the earliest known "
     "exploitation minus a margin): audits read from it, rotations must post-date it."),
    ("security.incident.rotation_policy", INCIDENT_KIND, "literal",
     {"enum": sorted(ROTATION_POLICIES), "type": "string"}, "one", "normative", (), (),
     "What raises a rotation: on_found_or_unknown (a service's audit found or cannot rule out "
     "exploitation) or all_exposed."),
    ("security.incident.status", INCIDENT_KIND, "literal",
     {"enum": ["closed", "open"], "type": "string"}, "one", "normative", (), (),
     "Whether the incident is open; close it only after its respond Line posts "
     "ready_to_close."),
    # What runs where: observed by a runtime-inventory scan, beside the declared installs.
    ("security.asset.runs", ("security.asset",), "subject", ("security.release",), "many",
     "observation", (INVENTORY_CONTRACT,), (), "A release a runtime-inventory scan observed "
     "running on the asset (beside the declared installs). A full scan retires a run it no "
     "longer sees. Its none (an inverse, keyed by the release's product_name) says the asset "
     "runs no release of that product: only a full scan that looked for the product states "
     "it (never for a product it did not look for), it goes stale on the coverage horizon, "
     "and a run of the product seen again retires it. No run and no current none is "
     "unknown."),
    ("security.asset.scanned_in", ("security.asset",), "subject", ("security.coverage",),
     "many", "observation", (INVENTORY_CONTRACT,), (), "The inventory scope coverage that read "
     "the asset: its runs are complete there while that coverage is current."),
    ("security.coverage.looked_for", ("security.coverage",), "literal", TEXT, "many",
     "observation", (INVENTORY_CONTRACT,), NAME_FORM, "A product a full runtime-inventory "
     "scan looked for, named as its releases are (php, debian/php8.2: a purl's namespace and "
     "name), or * for everything: the record of the question the scan asked. The scan states "
     "each asset's absence as an asset.runs none, only for a product it looked for (under *: "
     "a product the asset ran before or declares installing; name any other in looked_for); "
     "which versions of a looked-for product an asset runs are its runs, complete while the "
     "coverage is current."),
    # The audit: were we exploited during the window, for one service.
    ("security.audit.incident_ref", AUDIT_KIND, "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The incident's name; with service_ref, the audit's key."),
    ("security.audit.service_ref", AUDIT_KIND, "literal", TEXT, "one", "normative", (),
     NAME_FORM, "The service's name; with incident_ref, the audit's key."),
    ("security.audit.incident", AUDIT_KIND, "subject", INCIDENT_KIND, "one", "sourced",
     (LOG_CONTRACT,), (), "The incident the audit answers (the key's incident_ref as a "
     "Subject)."),
    ("security.audit.service", AUDIT_KIND, "subject", ("security.service",), "one", "sourced",
     (LOG_CONTRACT,), (), "The service the audit answers for (the key's service_ref as a "
     "Subject)."),
    ("security.audit.log_source", AUDIT_KIND, "literal", TEXT, "many", "normative", (),
     ("trim",), "A log source this incident's audit reads in full over the window "
     "(storefront/nginx-access). Stating it is what asks the question. Start from the "
     "service's service.log_source list (the respond Line names it): a source the service "
     "lists and the audit does not state leaves the answer unknown."),
    ("security.audit.read", AUDIT_KIND, "literal", TEXT, "many", "observation",
     (LOG_CONTRACT,), ("trim",), "One complete read of a log source, as SOURCE FROM/TO (ISO "
     "8601, Z): the tool searched every record in the interval. Only the log import writes "
     "these; an incomplete read is posted, never recorded."),
    ("security.audit.window_end", AUDIT_KIND, "literal", DATETIME, "one", "normative", (), (),
     "When the service's last affected asset was verified patched (the verifying scan's "
     "time): the audit's window is [incident.window_start, window_end]."),
    ("security.audit.result", AUDIT_KIND, "literal",
     {"enum": sorted(AUDIT_RESULTS), "type": "string"}, "one", "normative",
     (LOG_CONTRACT, WORKSPACE_EVIDENCE_CONTRACT), (),
     "The auditor's judgment: exploited, not_exploited or inconclusive, citing the decisive "
     "log read (security.log-read-v1) or a workspace file (security.workspace-evidence-v1); "
     "own words are refused. Reasoning goes in a section of "
     "the incident's note. A disagreeing auditor contends (set --contend): while the slot "
     "reads conflict the answer is unknown. Never settled by a Mandate."),
    # The credential: a logical credential; its keys rotate under it. Non-secret only.
    ("security.credential.issuer", CREDENTIAL_KIND, "literal", TEXT, "one", "normative", (),
     ("trim", "casefold"), "Who issues the credential (aws-iam/111122223333, stripe, "
     "postgres/partners-db); with name, the credential's key."),
    ("security.credential.name", CREDENTIAL_KIND, "literal", TEXT, "one", "normative", (),
     ("trim",), "The credential's name at its issuer (storefront-app); with issuer, its key."),
    ("security.credential.used_by", CREDENTIAL_KIND, "subject", ("security.service",), "many",
     "normative", (), (), "A service that uses the credential: whoever compromised the service "
     "could read it."),
    ("security.credential.reaches", CREDENTIAL_KIND, "subject", ("security.service",), "many",
     "normative", (), (), "A service the credential grants access to: the blast radius."),
    ("security.credential.key_id", CREDENTIAL_KIND, "literal", TEXT, "one", "observation",
     CRED_FACT, ("trim",), "The current key's non-secret id: the issuer's key id, or fp: and "
     "16 hex of the secret's sha256. Never the secret."),
    ("security.credential.issued_at", CREDENTIAL_KIND, "literal", DATETIME, "one",
     "observation", CRED_FACT, (), "When the current key was issued, as the issuer states it: "
     "a rotation must post-date incident.window_start."),
    ("security.credential.issued_by", CREDENTIAL_KIND, "literal", TEXT, "one", "observation",
     CRED_FACT, ("trim",), "Who issued the current key, as the issuer states it."),
    ("security.credential.revoked_key", CREDENTIAL_KIND, "literal", TEXT, "many",
     "observation", CRED_FACT, ("trim",), "A key id a separate state read observed revoked or "
     "deleted."),
    # Rotation linkage on a remediation (a patch has work.asset + work.assessment).
    ("security.work.credential", WORK, "subject", CREDENTIAL_KIND, "one", "normative", (), (),
     "The credential this work item rotates."),
    ("security.work.audit", WORK, "subject", AUDIT_KIND, "one", "normative", (), (),
     "The audit whose answer raised this work item (a rotation)."),
    ("security.remediation.revokes_key", ("security.remediation",), "literal", TEXT, "one",
     "normative", (), ("trim",), "The key id a rotation must retire: the credential's key_id "
     "when the rotation was raised."),
]
#: predicate -> {member: description} for the enum ClaimTypes that describe their values.
MEMBERS = {"security.assessment.justification": JUSTIFICATIONS,
           "security.finding.verdict": VERDICTS,
           "security.finding.justification": FINDING_JUSTIFICATIONS,
           "security.incident.rotation_policy": ROTATION_POLICIES,
           "security.audit.result": AUDIT_RESULTS}

#: predicate -> evidence freshness horizon in hours.
#: Only the revision carries freshness: it is restated on every pull (an unchanged
#: source re-observes it), and every answer reads it, so a stale revision reads
#: absent and the answer unknown. ``coverage.of`` is stated once, like any fact; a
#: moved source revises the one revision Claim.
FRESHNESS = {"security.coverage.revision": COVERAGE_STALE_AFTER_HOURS}
#: ClaimType v9 inverses: predicate -> (key predicate (object_key), evidence rule, stale
#: after hours, what a none means). A run's none ages on the inventory coverage horizon.
INVERSES = {
    "security.asset.runs": (
        "security.release.product_name", "retained-security-evidence",
        COVERAGE_STALE_AFTER_HOURS,
        "The asset runs no release of this product, as a full runtime-inventory scan that "
        "looked for it shows."),
}

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
    "security.incident": (("security.incident.name",), "unique"),
    "security.audit": (("security.audit.incident_ref", "security.audit.service_ref"), "unique"),
    "security.credential": (("security.credential.issuer", "security.credential.name"),
                            "unique"),
}
SUBJECT_KIND_DESCRIPTIONS = {
    "security.vulnerability": "A CVE, named by its id. Tracked when it has a watch_reason, an "
    "affected/inconclusive assessment or an incident responding to it; existing alone tracks "
    "nothing.",
    "security.release": "One version of a product, named by product name and version.",
    "security.assessment": "Whether one release is affected by one CVE: one per pair.",
    "security.asset": "A host or workload (k8s:prod/storefront-a), named by its hostname.",
    "security.product": "A software product, named by its name.",
    "security.supplier": "A product's supplier, named by its name.",
    "security.team": "An accountable team, named by its name.",
    "security.service": "A business service, named by its name: its owning team, its "
    "criticality and where its logs live.",
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
    "security.incident": "One response to one or more CVEs (PHP2Shell), named by its name: its "
    "window, rotation policy and status; its respond Line asks the five questions.",
    "security.audit": "Were we exploited during an incident's window, for one service: named "
    "by incident and service. Its log sources, complete reads and result answer it in three "
    "states.",
    "security.credential": "A logical credential (an API key, a database login), named by "
    "issuer and name: where it is used, what it reaches, and its current key's non-secret id. "
    "Its keys rotate under it; a secret never enters.",
}


def _rule(rule_id: str, role: str, contracts: tuple[str, ...]) -> ClaimEvidenceAdmissionRule:
    grouped: dict[str, set[str]] = {}
    for use in contracts:
        contract, source = CONTRACT_USES[use]
        sources = grouped.setdefault(contract, set())
        if source is not None:
            sources.add(source)
    return ClaimEvidenceAdmissionRule(
        rule_id=rule_id,
        claim_roles=(role,),
        capture_contracts=tuple(
            CaptureContractAdmission(
                role="capture-contract",
                target=ArtifactIdentity(kind="CaptureContract", name=name),
                logical_sources=tuple(sorted(sources)),
            ) for name, sources in sorted(grouped.items())
        ),
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
    rows = (CLAIM_TYPES + SYSTEM + FINDINGS + RESPONSE
            + (CLAIM_TYPES_1_1 if release == VARIANT else []))
    result = []
    for predicate, kinds, obj, shape, cardinality, role, contracts, form, description in rows:
        roles, default_role, rules, requirement = _evidence(role, contracts)
        members = tuple(
            ClaimTypeMemberDescription(member=name, description=text)
            for name, text in sorted(MEMBERS.get(predicate, {}).items())
        )
        inverse = None
        if predicate in INVERSES:
            key, rule, hours, meaning = INVERSES[predicate]
            inverse = ClaimInverse(
                key=ClaimInverseObjectKeyPart(kind="object_key", predicate=key),
                evidence_rules=(rule,),
                stale_after=ClaimFreshnessDuration(microseconds=hours * 3_600_000_000),
                description=meaning)
        record: dict[str, Any] = {
            "predicate": predicate, "cardinality": cardinality, "description": description,
            "default_role": default_role,
        }
        if tuple(kinds) != (predicate.rpartition(".")[0],):
            record["allowed_subject_kinds"] = tuple(sorted(kinds))
        if obj == "subject":
            record["allowed_object_subject_kinds"] = tuple(shape)
        elif obj == "literal":
            if shape != {"type": "string"}:
                record["literal_schema"] = shape
            if tuple(form) != ("nfc", "trim"):
                record["canonical_form"] = tuple(form)
        else:
            record["object_kind"] = obj
        if roles != (default_role,):
            record["permitted_roles"] = roles
        if rules:
            record["evidence_admission_policy"] = ClaimEvidenceAdmissionPolicy(rules=rules).model_dump(mode="json")
        default_requirement = "captured" if roles == ("observation",) else "self"
        if requirement != default_requirement:
            record["evidence_requirement"] = requirement
        if members:
            record["member_descriptions"] = [m.model_dump(mode="json") for m in members]
        if predicate in FRESHNESS:
            record["evidence_freshness"] = {"stale_after": {"microseconds": FRESHNESS[predicate] * 3_600_000_000}}
        if inverse is not None:
            record["inverse"] = inverse.model_dump(mode="json", exclude={"tag"})
        result.append(lower_claim_type_input(ClaimTypeInputRecord.model_validate(record),
                                            tree={}, identity_rules=True))
    return result


# --- Authored Queries ---------------------------------------------------------


def query_definitions(release: str) -> list[QuerySpecInput]:
    records = json.loads((DATA / "queries.json").read_text())
    if release == VARIANT:
        for record in records:
            if record["query"] == "security.kev_exposure":
                record["limit"] = 500
    return [QuerySpecInput.model_validate(record) for record in records]


# --- CaptureContracts and the acquisition policy -------------------------------


def capture_contracts() -> list[Any]:
    """Shapes carry storage/replay decisions; provenance belongs to each use."""
    records = [
        {"name": "security.fetched-v1", "shape": "http_response"},
        {"name": "security.fetched-large-v1", "shape": "http_response",
         "max_bytes": 64 * 1024 * 1024},
        {"name": "security.file-v1", "shape": "http_response", "replay": "exact"},
        {"name": "security.file-erasable-v1", "shape": "http_response", "replay": "exact",
         "erasable": True},
        {"name": OUTPUT_CONTRACT, "shape": "procedure_output"},
    ]
    return [lower_capture_contract_input(CaptureContractInputRecord.model_validate(record),
                                        named=True) for record in records]


def acquisition_policy() -> SourceAcquisitionPolicy:
    """The instance default: every source is required, with one age bound."""
    return SourceAcquisitionPolicy(
        identity=ArtifactIdentity(kind="SourceAcquisitionPolicy", name=POLICY),
        max_age="P1D",
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
    **_ints("changed", "affected", "not_affected", "inconclusive", "unchanged", "judged",
            "coverage", "packages"),
)
OSV_SUMMARY = _contract(
    "security-osv-applicability-summary",
    unkeyed=PropertySchema(type="json"),
    **_ints("changed", "affected", "not_affected", "inconclusive", "unchanged", "judged",
            "coverage", "packages"),
)
CVE_REQUEST = _contract(
    "security-cve-applicability-request",
    record_base64=PropertySchema(type="string"),
    releases=PropertySchema(type="json"),
    watched=PropertySchema(type="json"),
    assessments=PropertySchema(type="json"),
    sources=PropertySchema(type="json"),
    collections=PropertySchema(type="json"),
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
# Incident response.
INVENTORY_INPUT = _contract("security-inventory-import-input", scope=_S)
_INVENTORY_COUNTS = _ints("mine", "assets", "runs", "unidentified", "added", "retired",
                          "revised", "restated", "verified", "failed", "changed", "proposes",
                          "nones")
INVENTORY_REQUEST = _contract("security-runtime-inventory-request", inventory_text=_S, held=_J,
                              runs=_J, patches=_J, scope=_S, truncated=_J)
INVENTORY_RESULT = _contract("security-runtime-inventory-result", items=_J, scope=_S,
                             format=_S, coverage=_S, revision=_S, regressions=_J,
                             **_INVENTORY_COUNTS)
INVENTORY_SUMMARY = _contract("security-runtime-inventory-summary", scope=_S, format=_S,
                              coverage=_S, revision=_S, regressions=_J, **_INVENTORY_COUNTS)
LOG_INPUT = _contract("security-log-import-input", incident=_S)
_LOG_COUNTS = _ints("mine", "recordable", "matches", "added", "changed", "posted")
LOG_REQUEST = _contract("security-log-read-request", read_text=_S, held=_J, incident=_S,
                        truncated=_J)
LOG_RESULT = _contract("security-log-read-result", items=_J, inbox=_J, incident=_S,
                       service=_S, source=_S, read=_S, **_LOG_COUNTS)
LOG_SUMMARY = _contract("security-log-read-summary", incident=_S, service=_S, source=_S,
                        read=_S, **_LOG_COUNTS)
_CREDENTIAL_COUNTS = _ints("keys", "added", "revised", "verified", "failed", "unproven",
                           "changed", "posted")
CREDENTIAL_REQUEST = _contract("security-credential-state-request", state_text=_S, held=_J,
                               truncated=_J)
CREDENTIAL_RESULT = _contract("security-credential-state-result", items=_J, inbox=_J,
                              credential=_S, read=_S, **_CREDENTIAL_COUNTS)
CREDENTIAL_SUMMARY = _contract("security-credential-state-summary", credential=_S, read=_S,
                               **_CREDENTIAL_COUNTS)
RESPOND_INPUT = _contract("security-respond-input", incident=_S, inventory_pull=_S,
                          log_pull=_S, credential_pull=_S, record_pull=_S,
                          osv_line=PropertySchema(type="string", optional=True))
RESPOND_REQUEST = _contract("security-respond-request", exposure=_J, hosts=_J,
                            deployments=_J, patches=_J, overdue=_J, exceptions=_J, audits=_J,
                            credentials=_J, params=_J, truncated=_J)
_RESPOND_COUNTS = _ints("posted", "found", "none", "unknown", "ready_to_close")
RESPOND_RESULT = _contract("security-respond-result", items=_J, answers=_J, incident=_S,
                           status=_S, **_RESPOND_COUNTS)
RESPOND_SUMMARY = _contract("security-respond-summary", answers=_J, incident=_S, status=_S,
                            **_RESPOND_COUNTS)
#: respond's taps, in order: alias -> QueryDefinition.
RESPOND_QUERIES = {
    "exposure": "security.incident_exposure",
    "hosts": "security.scanned_runs",
    "deployments": "security.deployments",
    "patches": "security.incident_patches",
    "overdue": "security.overdue_patches",
    "exceptions": "security.incident_exceptions",
    "audits": "security.audit_status",
    "credentials": "security.incident_credentials",
}


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


def _blueprint(sequence: Sequence, interface: dict[str, Any], slot: str,
               also: dict[str, dict[str, Any]] | None = None) -> BlueprintInput:
    """Open the Sequence's ``slot`` Source (and each Source ``also`` names) as a slot typed
    by its interface: every network Source is the consumer's to bind."""

    slots = {slot: interface, **(also or {})}
    built = lower_procedure_spec(sequence.build().spec, named=False)
    definition = dict(built.definition)
    nodes = []
    for node in definition["nodes"]:
        node = dict(node)
        name = node.get("as", node.get("node_id", node.get("id")))
        if node["kind"] == "source" and name in slots:
            node["provider"] = {"kind": "slot", "slot_name": name}
            node.pop("implementation_digest", None)
        nodes.append(node)
    definition["nodes"] = nodes
    definition["pin_slots"] = [
        {
            "slot_name": name,
            "pin_role": "provider",
            "artifact_kind": "Provider",
        }
        for name in sorted(slots)
    ]
    return BlueprintInput(kind="blueprint", definition=definition, contracts=built.contracts,
                          activation_policy=built.activation_policy)


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
            Source("catalog", capture_contract=_capture(KEV_CONTRACT), next="summary",
                   request=_fetch(KEV_URL, KEV_SOURCE, KEV_MAX_BYTES)),
            _summary("catalog", next="emit"),
            EmitCapture("emit", capture_contract=_capture(OUTPUT_CONTRACT), input=Output("summary"),
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
        budget=_budget(budget_seconds, 1, 16_777_216),
        hard_caps=_caps(120, 1, 16_777_216, 1),
    ).bind(catalog=web)
    return _blueprint(sequence, _interface(cx, "web.fetch"), "catalog")


def cve_record_acquire(cx: Cruxible) -> BlueprintInput:
    web = cx.provider_interface("web.fetch", provider=WEB_PROVIDER)
    sequence = Sequence(
        [
            Source("record", capture_contract=_capture(CVE_CONTRACT), next="summary",
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
        budget=_budget(60, 1, 4_194_304),
        hard_caps=_caps(120, 1, 4_194_304, 1),
    ).bind(record=web)
    return _blueprint(sequence, _interface(cx, "web.fetch"), "record")


def epss_acquire(cx: Cruxible) -> BlueprintInput:
    epss = cx.provider_interface("security.epss-daily", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("epss", capture_contract=_capture(EPSS_CONTRACT), next="summary", request={}),
            _summary("epss", next="emit"),
            EmitCapture("emit", capture_contract=_capture(OUTPUT_CONTRACT), input=Output("summary"),
                        result=Output("summary")),
        ],
        name="security.epss-acquire",
        description=(
            "Fetch FIRST's current EPSS daily scores file (gzip CSV) and retain it under "
            "security.epss-daily-v1. Interpretation is security.epss-triage's job."
        ),
        contract_in=EMPTY,
        contract_out=HTTP_SUMMARY,
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
            Source(alias, capture_contract=_capture(contract), next="summary",
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
        budget=_budget(60, 1, WORKSPACE_FILE_MAX_BYTES),
        hard_caps=_caps(120, 1, WORKSPACE_FILE_MAX_BYTES, 1),
    ).bind(**{alias: builtin})
    return sequence.build()


def _sarif_steps(terminal: list[Any], guard: Guard) -> list[Any]:
    """The landed SARIF log, the Line repository's held findings, the analysis, then the
    repository guard (another repository's log halts wrong_repo) and ``terminal``."""

    return [
        Source("sarif", capture_contract=_capture(SARIF_CONTRACT), next="held",
               request=_workspace_file("sarif.log", "scan.sarif")),
        StateTap("held", query="security.finding_index", next="parse",
                 parameters={"repo_ref": "$input.repo_ref"}),
        Call("parse", next="summary",
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


def osv_applicability(cx: Cruxible) -> BlueprintInput:
    osv = cx.provider_interface("security.osv-query", provider=SOURCES_PROVIDER)
    ecosystems = cx.provider_interface("security.osv-ecosystems", provider=SOURCES_PROVIDER)
    decide = cx.provider_interface("security.osv-applicability", provider=ANALYSIS_PROVIDER)
    sequence = Sequence(
        [
            StateTap("releases", query="security.release_inventory", next="watched"),
            StateTap("watched", query="security.watched_vulnerabilities", next="assessments"),
            StateTap("assessments", query="security.assessment_index", next="ecosystems"),
            # What OSV indexes, in its own words, retained as its own Capture.
            Source("ecosystems", capture_contract=_capture(OSV_ECOSYSTEMS_CONTRACT), next="osv",
                   request={}),
            # The purl type map is kit data (its sources cited): edit it by authoring a
            # successor of this Procedure.
            Source("osv", capture_contract=_capture(OSV_CONTRACT), next="decide",
                   request={"releases": "$steps.releases.result.rows",
                            "watched": "$steps.watched.result.rows",
                            "ecosystems": "$steps.ecosystems",
                            "purl_types": {"osv_ecosystems": PURL_OSV_ECOSYSTEMS["osv_ecosystems"],
                                           "sources": PURL_OSV_ECOSYSTEMS["sources"]}}),
            Call("decide", next="summary",
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
            "Retain OSV's ecosystem list (ecosystems.txt, under security.osv-ecosystems-v1), "
            "then ask OSV.dev about every SBOM component (purl@version) of every release whose "
            "ecosystem OSV indexes (by the kit's purl type map, carried in this Procedure; the "
            "rest are recorded not_indexed, never asked) and every watched CVE, retain the "
            "answer under security.osv-query-v1, and propose what changed: each release's OSV "
            "coverage (complete, or partial with the purl types not indexed), the packages "
            "OSV says each watched CVE affects, and an assessment per (release, CVE): affected "
            "(watching the CVE when it is new), not_affected with its VEX justification, or "
            "inconclusive. Propose-only; never settles. Runs as a Line (daily, or `line run` "
            "after an SBOM or inventory import is accepted)."
        ),
        contract_in=EMPTY,
        contract_out=OSV_SUMMARY,
        returns="summary",
        activation_policy="drain",
        budget=_budget(300, 3, 67_108_864),
        hard_caps=_caps(600, 3, 67_108_864, 5000),
    ).bind(osv=osv, ecosystems=ecosystems, decide=decide)
    return _blueprint(sequence, _interface(cx, "security.osv-query"), "osv",
                      also={"ecosystems": _interface(cx, "security.osv-ecosystems")})


# --- the system model: pull, parse, harden -------------------------------------


def repo_acquire(cx: Cruxible) -> BlueprintInput:
    snapshot = cx.provider_interface("security.repo-snapshot", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("snapshot", capture_contract=_capture(REPO_CONTRACT), next="summary", request={
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
        budget=_budget(120, 1, 16_777_216),
        hard_caps=_caps(300, 1, 16_777_216, 1),
    ).bind(snapshot=snapshot)
    return _blueprint(sequence, _interface(cx, "security.repo-snapshot"), "snapshot")


def registry_acquire(cx: Cruxible) -> BlueprintInput:
    registry = cx.provider_interface("security.pypi-release", provider=SOURCES_PROVIDER)
    sequence = Sequence(
        [
            Source("registry", capture_contract=_capture(PYPI_CONTRACT), next="summary", request={
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
            Source(slot, capture_contract=_capture(contract), next="summary", request=request),
            _summary(slot),
        ],
        name=name,
        description=description,
        contract_in=URL_INPUT,
        contract_out=HTTP_SUMMARY,
        returns="summary",
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
            Source("asset", capture_contract=_capture(ASSET_CONTRACT), next="summary",
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


# --- incident response: acquire, import, respond ----------------------------------


def _backlog_measurement(digest: str) -> dict[str, Any]:
    return {
        "name": "kev-backlog-cleared",
        "subject_grain": "procedure_unit",
        "measurement": {
            "kind": "accepted_query",
            "query": {
                "role": "query",
                "target": {"kind": "QueryDefinition", "name": "security.kev_triage_backlog"},
                "artifact_digest": digest,
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
    for spec in query_definitions(release):
        draft.query_definition(QueryDefinitionInput(kind="query_definition", query_definition=spec))
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


def procedure_specs(cx: Cruxible | None = None) -> list[ProcedureSpec]:
    records = json.loads((DATA / "procedures.json").read_text())
    if cx is not None:
        # K1b will make these provider positions slots. K1a retains the selected builds.
        bindings = {}
        for record in records:
            for step in record["steps"]:
                if "call" in step or "source" in step:
                    key = (step["interface"], step["provider"])
                    if key not in bindings:
                        bindings[key] = cx.provider_interface(key[0], provider=key[1])
                    step["provider"] = bindings[key].provider
    from cruxible_client.contracts.query.definitions import parse_query_definition, query_definition_digest
    if cx is not None:
        _, digest = _held_query(cx, "security.kev_triage_backlog")
    else:
        path = "query-definitions/security.kev_triage_backlog.json"
        digest = query_definition_digest(parse_query_definition(
            (Path(__file__).parents[2] / "artifacts" / path).read_bytes(), path=path)).tagged
    for record in records:
        if record["procedure"] == "security.kev-triage":
            record["measurements"] = [_backlog_measurement(digest)]
    return [ProcedureSpec.model_validate(record) for record in records]


def procedures(cx: Cruxible, release: str) -> None:
    draft = cx.changes(rationale=f"security kit {release}: authored Procedures and acquisition Blueprints.")
    for factory in (lambda cx: kev_acquire(cx, release), cve_record_acquire, epss_acquire,
                    osv_applicability, repo_acquire, registry_acquire, release_acquire,
                    asset_fetch, history_acquire):
        draft.procedure(definition=factory(cx))
    for spec in procedure_specs(cx):
        draft.procedure(definition=ProcedureInput(kind="procedure", spec=spec))
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
