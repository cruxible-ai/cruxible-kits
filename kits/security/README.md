# security kit

Definitions for software-security state: inventory (assets, releases, products,
suppliers, services, teams), applicability assessments, vulnerabilities with their
CISA KEV status, and remediation work (remediations, exceptions, controls). It
ships the automation to keep KEV status current: a KEV acquisition Blueprint, a
CVE record Blueprint, and a KEV triage Procedure that turns each retained KEV
catalog into proposed Claims.

A kit carries definitions only. It never carries authority (Lines, Triggers,
mandates), bindings or state (Subjects, Claims); the recipe below is what a
consumer authors.

## What 1.0.0 contains

| Kind | Count | Notes |
|---|---:|---|
| ClaimType | 33 | `security.` inventory, assessment, vulnerability and work vocabulary. Observations (`assessment.status`, `vulnerability.kev_*`, `title`, `vendor_product`, `work.verification`) require a Capture under a security CaptureContract; normative statements are supported by their own origin. `vulnerability.kev_listing_expected` is the belief predictions test. |
| CaptureContract | 3 | `security.kev-http-v1` (source `cisa.kev.catalog`), `security.cve-record-http-v1` (source `cve.record`), `security.observation-output-v1` (the acquisition terminal). |
| QueryDefinition | 17 | Inventory, applicability and worklist queries; the CVE-scoped ones (`applicability_coverage`, `triage`, `urgent_exposures`, `coverage_gaps`, `change_impact`) take a `vulnerability` parameter (`Subject:security.vulnerability/<id>`). `watched_vulnerabilities` is triage's state tap, `kev_triage_backlog` its measurement target, `kev_settle_condition` the condition a settle mandate evaluates. |
| SourceAcquisitionPolicy | 1 | `security.kev-acquisition` covers both Source aliases: `catalog` (kev-acquire and the triage Line's trigger-fed input) and `record` (cve-record-acquire). Each is required, at most 24 h old, attested replay, refuse on stale/unavailable/oversized. |
| Blueprint | 2 | `security.kev-acquire` and `security.cve-record-acquire`, each with slot `fetch` typed by `web.fetch`. |
| Procedure | 1 | `security.kev-triage`, ending in `settle_change_set`: under a Line capped at `propose` it proposes (fallback `cruxible.settle.authority_capped_by_line_max_authority`), under a settle mandate it settles. It pins the bundled `security-kev-provider` and the default `cruxible-provider-web`. |
| ProviderInterface | 2 | `web.fetch` (core's registration), `security.kev-catalog` (carried, never owned). |
| Providers | 2 | Bundled: `security-kev-provider` 1.0.0, the KEV catalog parser (domain code, shipped as wheel plus lock). Default by name: `cruxible-provider-web` 0.2.1 from PyPI, pinned to its published wheel and lock hashes; the kit carries none of its files. |

## Install

```sh
cruxible kit add security:1.0.0              # preview
cruxible kit add security:1.0.0 --commit --at <OID>
cruxible kit status
```

`kit add` installs the bundled KEV provider and the default `cruxible-provider-web`
first: web by name and exact version from the daemon's provider index (PyPI unless
`provider_index_urls` says otherwise), verified against the recorded wheel and lock
hashes before anything runs. Registry dependencies resolve from the same index. The
definitions land once the providers are installed, at once when the approval policy
needs no approval. `kit status` lists each provider with its delivery (`bundled` or
`index`) and state (`installed`, or `satisfied` when another live Provider stands in
for the default).

## Consumer recipe

1. **Instantiate the acquisition Blueprints** on the installed web provider:

   ```json
   {"kind": "change_set", "rationale": "Instantiate the security acquisition Blueprints.", "members": [
    {"kind": "blueprint_instance", "name": "security.kev-acquire", "blueprint": "security.kev-acquire",
     "bindings": {"fetch": "cruxible-provider-web"}, "acquisition_policy": "security.kev-acquisition"},
    {"kind": "blueprint_instance", "name": "security.cve-record-acquire", "blueprint": "security.cve-record-acquire",
     "bindings": {"fetch": "cruxible-provider-web"}, "acquisition_policy": "security.kev-acquisition"}]}
   ```

   `cruxible authoring submit FILE --and-activate`. `cruxible get Blueprint:security.kev-acquire`
   lists the Providers that fit the slot: any implementation bound to core's `web.fetch`
   registration does.

2. **Author the automation** (Lines, Triggers, the propose mandate) in one change set.
   `CAPTURE_DIGEST` is `cruxible get CaptureContract:security.kev-http-v1 --detail proof`'s
   `artifact_digest`:

   ```json
   {"kind": "change_set", "rationale": "Automate KEV acquisition and propose-only triage.", "members": [
    {"kind": "line", "name": "security.kev-daily", "procedure_name": "security.kev-acquire",
     "acquisition_policy_name": "security.kev-acquisition", "max_authority": "observe"},
    {"kind": "line", "name": "security.kev-triage", "procedure_name": "security.kev-triage",
     "acquisition_policy_name": "security.kev-acquisition", "max_authority": "propose", "trigger_input": "catalog"},
    {"kind": "trigger", "name": "security.kev-daily", "line_name": "security.kev-daily",
     "schedule": {"kind": "cron", "expression": "17 14 * * *"}},
    {"kind": "trigger", "name": "security.kev-landed", "line_name": "security.kev-triage",
     "schedule": {"kind": "capture_landing", "event": {
       "capture_contract_identity": {"kind": "CaptureContract", "name": "security.kev-http-v1"},
       "capture_contract_digest": "CAPTURE_DIGEST"}}},
    {"kind": "procedure_mandate", "name": "security.kev-triage-propose", "procedure_name": "security.kev-triage",
     "grants": "propose", "namespace": ["claims"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2,
       "max_capture_bytes": 16777216, "max_items": 1000, "max_repeat_attempts": 1}}]}
   ```

   Cron is UTC; CISA publishes on US business days, so one fetch a day is enough.
   Then `cruxible line enable security.kev-daily` and `cruxible line enable security.kev-triage`.
   A change to a Line or to the Triggers aimed at it stops its enablement; `cruxible next`
   names the `line enable` that restarts it.

3. **Watch vulnerabilities.** Triage only reads `security.vulnerability` Subjects that
   exist. Create one per CVE you care about, id lowercase (`cve-2021-44228`). Each
   KEV-listed one gets `kev_listed = true` plus `kev_date_added`, `kev_due_date` and
   `kev_ransomware_use`; one the catalog does not list gets `kev_listed = false` once.
   An identical catalog proposes nothing (the run halts `no_change`).

4. **Review triage proposals.** Open proposals show in `cruxible orient`
   (`open_proposals`) and `cruxible proposal list`; review with `cruxible proposal
   review ID`, then `cruxible proposal activate ID`. The Claims cite the KEV catalog
   Capture that triggered the run.

5. **Fetch a CVE record** (direct run, no Line): pass the full URL.

   ```sh
   echo '{"url": "https://cveawg.mitre.org/api/cve/CVE-2021-44228"}' > cve.json
   cruxible procedure run security.cve-record-acquire cve.json --evaluation-time NOW
   ```

   CVE Services throttles bursts; run these per CVE.

6. **Predictions.** State a belief (`kev_listing_expected = true`, normative), then
   `cruxible prediction propose FILE` with observation selector
   `{subject: subjects/security.vulnerability/<id>.json, predicate:
   security.vulnerability.kev_listed}`, an equality rule and a fixed window; activate
   it. Settlement is manual in v1: once the window closes `cruxible next` shows a
   `prediction_settleable` row; run `cruxible prediction settle NAME --observation CLM-...`
   with the `kev_listed` Claim triage produced. An observation must be accepted after
   the contract and inside its window, so a "not listed by D" bet settles only if
   triage observes `false` inside the window (the first time it sees the CVE absent).

7. **Measure.** `security.kev-triage` declares `kev-backlog-cleared`: the
   `kev_triage_backlog` query must be empty 3 days after the Procedure is accepted
   (expires after 10 days; review when the satisfied rate drops below 0.8 over 5
   readings). Measurement is manual in v1:
   `cruxible procedure measure security.kev-triage --run-id RUN-...` and
   `cruxible procedure readings security.kev-triage --subject-grain procedure_unit`.

8. **Graduate to settle.** When the readings justify it, author a settle mandate for
   `security.kev-triage` and raise the triage Line's `max_authority` to `settle`. The
   Procedure does not change, so its digest and track record carry through:

   ```json
   {"kind": "change_set", "rationale": "Graduate KEV triage to settle under a mandate.", "members": [
    {"kind": "procedure_mandate", "name": "security.kev-triage-settle", "procedure_name": "security.kev-triage",
     "grants": "settle", "namespace": ["claims"], "valid_from": "NOW", "expires_at": "NOW+90d",
     "resource_ceiling": {"max_wall_clock": {"microseconds": 300000000}, "max_provider_calls": 2,
       "max_capture_bytes": 16777216, "max_items": 1000, "max_repeat_attempts": 1},
     "scope": [{"claim_type": "security.vulnerability.kev_listed", "change_kinds": ["create", "revise"]},
               {"claim_type": "security.vulnerability.kev_date_added", "change_kinds": ["create", "revise"]},
               {"claim_type": "security.vulnerability.kev_due_date", "change_kinds": ["create", "revise"]},
               {"claim_type": "security.vulnerability.kev_ransomware_use", "change_kinds": ["create", "revise"]}],
     "condition": {"query_name": "security.kev_settle_condition", "binding_parameter": "vulnerability_id",
       "required_fields": ["kev_listing_expected"], "fallback": "propose"}},
    {"kind": "line", "name": "security.kev-triage", "procedure_name": "security.kev-triage",
     "acquisition_policy_name": "security.kev-acquisition", "max_authority": "settle", "trigger_input": "catalog"}]}
   ```

   Re-enable the Line. A change to a vulnerability with a stated `kev_listing_expected`
   settles under the mandate; any other falls back to an ordinary proposal.

## Operating notes

- **web.fetch** fetches static JSON only (`render: false`); the requests set
  `max_bytes` (4 MiB for the ~1.7 MB catalog; the default is 256 KiB) and
  `extract: false`. web.fetch refuses private addresses and needs direct outbound
  access to cisa.gov and cveawg.mitre.org.
- **Staleness.** The policy refuses a Capture older than 24 h, so triage of a
  backfilled catalog after a long outage refuses; run `cruxible line run
  security.kev-daily` for a fresh one.
- **Storage.** Each acquisition retains the ~2.4 MB catalog Capture for at least
  30 days (erasure prohibited).
- **Blueprint drift.** Upgrading the kit changes Blueprints, not the Procedures
  instantiated from them; re-instantiate after an upgrade that changes one.
- **Mandates expire.** The propose and settle mandates above last 90 days; renew them
  before automation stops.

## Building a release

From a fresh authoring instance:

```sh
cruxible provider install cruxible-provider-web==0.2.1
cruxible provider install source/providers/security-kev-provider/dist/security_kev_provider-1.0.0-py3-none-any.whl \
  --lock source/providers/security-kev-provider/uv.lock
python source/authoring/security_definitions.py definitions --release 1.0.0
python source/authoring/security_definitions.py procedures --release 1.0.0
cruxible kit build --id security --version 1.0.0 --owns security. \
  --provider source/providers/security-kev-provider \
  --default-provider source/providers/cruxible-provider-web --out OUT
```

then replace `cruxible-kit.json`, `artifacts/` and `providers/` here with OUT's.
`source/providers/cruxible-provider-web` holds the published 0.2.1 wheel, the lock it
embeds and the runtime wheel that lock names by path, so `kit build` can record the
default's hashes; none of those files ship in the kit. After changing the KEV
provider, run its
`build_registration.py`, `uv lock`, its tests and `uv build --wheel --out-dir dist`,
and bump its version. `source/variants/1.1.0` is a release-gate fixture (changes
`kev_exposure`, adds `vulnerability.kev_cwes`, changes the kev-acquire Blueprint),
not a published version.

## Release gate

`gate/test_security_kit_gate.py` runs the v1 release gate end to end on a fresh
daemon with a scratch state root and HOME: the kit is published to a throwaway
HTTPS OCI registry on 127.0.0.1, installed, instantiated, automated (Lines,
Triggers, mandates), run on a cadence, restarted, graduated to settle and
upgraded to `source/variants/1.1.0`, asserting each step's observable. It is
offline from cisa.gov and cveawg.mitre.org: `gate/fixture-web` (package
`kev-gate-web`) is cruxible-provider-web's own `WebFetch` adapter serving the
vendored KEV catalog and CVE record from its `responses/`, bound to the
Blueprints' `fetch` slot. Provider installs still need PyPI. With the `cruxible`
package under test installed in the interpreter:

```sh
CRUXIBLE_BIN=$(command -v cruxible) python -m pytest kits/security/gate -x -q
```

It needs `git` and `openssl`, takes about ten minutes, and writes
`gate-results.md` and the command log to its scratch root
(`SECURITY_KIT_GATE_ROOT` to choose one). After changing the fixture, run its
`build_registration.py`, `uv lock` and `uv build --wheel --out-dir dist`.
