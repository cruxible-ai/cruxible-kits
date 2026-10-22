---
name: security-intake
description: Pull an organization's state into the Cruxible security kit - an SBOM per repository, a runtime inventory per scope, services and their credentials, log sources - in one first pass, then fetch whatever an unknown answer names
---

# Security intake

Use this skill when the security kit is installed and its example automation
adopted, but the instance doesn't yet know what you ship and run; then again
whenever an answer comes back **unknown**. The kit's [README](../../README.md)
is the source for every name below. Once the state is in, the [security
analyst skill](../security-analyst/SKILL.md) works the answers. The core
guides are at https://docs.cruxible.ai.

Everything you acquire is proposed, never written directly. Review each
proposal (`cruxible proposal review ID`) and approve it (`cruxible proposal
approve ID --yes`) only when it matches what you read and the user has agreed.
Approve one import before you acquire the next: two imports that touch the
same release can't both land, and the second goes stale (acquire its file
again).

## Ground rules

- **Never put a secret in a Capture.** Every file you acquire is kept. Record
  key ids or `fp:` fingerprints, never keys, tokens or passwords, and cut
  credentials out of a config before you retain it. If a secret lands anyway,
  stop, have it rotated, and erase the Capture: `cruxible capture erase CAP-...
  --because "..."` previews, then `--commit --at` erases, with a reason that
  doesn't repeat the secret. Only inventory, log-read and credential-state
  Captures can be erased; SBOMs and evidence files keep their bytes for good
  ([Secrets never enter](../../README.md#respond-to-an-incident)).
- **A failed fetch is unknown, never none.** A run that fails proposes nothing.
  Report what wasn't read and why.
- **Check the last run before trusting an empty answer.** `cruxible get
  Line:NAME` shows a Line's recent runs; an empty answer after a failed or
  halted run is unknown.

## First pass

Ask the user what to cover: the repositories, the inventory scopes (prod,
staging) and the scanner behind each, the services, their credentials, and
their logs. Keep the files you write under `intake/` so the next pass can
repeat them.

The pass uses these Lines: `security.sbom-import`, `security.osv-applicability`,
`security.kev-daily`, `security.kev-triage`, `security.epss-daily`,
`security.epss-triage`, `security.inventory-import.<scope>` for each scope and
`security.credential-import`. `cruxible get Line:NAME` lists a running
enablement for each one that's on. Turning a Line on is the user's decision:
name any that are off and ask.

### 1. An SBOM per repository

~~~bash
mkdir -p sboms
uvx --from cyclonedx-bom cyclonedx-py requirements requirements.txt \
    --pyproject pyproject.toml --of JSON -o sboms/myapp.cdx.json          # Python
~~~

<!-- maintainer: check the syft and uv lines (not run here) -->
~~~bash
syft dir:. -o cyclonedx-json > sboms/myapp.cdx.json                       # any ecosystem
uv export --format cyclonedx1.5 > sboms/myapp.cdx.json                    # a uv project
~~~

Check that `metadata.component` names the product and version people know it
by: the import records it as the release (`security.release/myapp--1.0.0`).
For another repository, generate its SBOM there and copy it into this
workspace's `sboms/` (at most 1 MiB per file). Then read each one in:

~~~bash
echo '{"relative_path": "sboms/myapp.cdx.json"}' > sbom.json
cruxible procedure run security.sbom-acquire sbom.json
~~~

Then ask the sources now instead of waiting for the daily runs, approving each
proposal (KEV and EPSS facts come from their triage Lines' proposals):

~~~bash
cruxible line run security.osv-applicability
cruxible line run security.kev-daily
cruxible line run security.epss-daily
~~~

### 2. Services

A value never creates the Subject it names, so state the services before
anything points at them:

~~~yaml
because: Service map from the platform runbook, 2026-10-22.
changes:
  - {op: set, subject: security.service/storefront, field: criticality, value: critical}
  - {op: set, subject: security.service/payments, field: criticality, value: critical}
~~~

`cruxible write intake/services.yaml`.

### 3. Credentials

Acquire one credential-state read per credential: a list of the issuer's
current keys, by non-secret id. `key_id` is the issuer's key id, or `fp:` and
the first 16 hex of the secret's sha256, computed where the secret already
lives.

~~~json
{"issuer": "stripe", "name": "storefront-live", "read": "state_read",
 "keys": [{"key_id": "fp:3f9a1c0d22b84e6a", "state": "active",
           "created_at": "2026-03-02T10:00:00Z", "created_by": "ops"}]}
~~~

~~~bash
echo '{"relative_path": "creds/stripe-storefront-live.json"}' > cred.json
cruxible procedure run security.credential-acquire cred.json
~~~

Any other field, or a key id shaped like a secret, refuses the whole body and
posts `secret_shape`; the bytes are kept, so erase the Capture. The import
creates the credential (`security.credential/stripe--storefront-live`).
Approve it, then state where it's used and what it reaches:

~~~yaml
because: Where the Stripe live key is used, from the payments runbook.
changes:
  - {op: add, subject: security.credential/stripe--storefront-live, field: used_by, value: security.service/storefront}
  - {op: add, subject: security.credential/stripe--storefront-live, field: reaches, value: security.service/payments}
~~~

### 4. A runtime inventory per scope

A scope is the set of hosts one scan reads in full. Each scope needs its own
import Line; the example automation has `security.inventory-import.prod`. For
another scope, submit this pair (`cruxible authoring submit
intake/scope-staging.json`) and ask the user to enable the Line:

~~~json
{"kind": "change_set", "rationale": "Inventory scope staging.", "members": [
  {"kind": "line", "name": "security.inventory-import.staging", "procedure_name": "security.inventory-import",
   "acquisition_policy_name": "security.acquisition", "max_authority": "propose",
   "trigger_input": "inventory", "parameters": {"scope": "staging"}},
  {"kind": "trigger", "name": "security.inventory-landed.staging", "line_name": "security.inventory-import.staging",
   "schedule": {"kind": "capture_landing", "capture_contract": "security.runtime-inventory-v1"}}
]}
~~~

Write each scope's scan in the kit's format, from whatever its scanner
outputs:

~~~json
{"scope": "prod", "looked_for": ["*"], "coverage": "full",
 "assets": [{"hostname": "app-1.example.com", "runs": ["pkg:generic/myapp@1.0.0"]},
            {"hostname": "app-2.example.com", "runs": ["pkg:generic/myapp@1.0.0"]}]}
~~~

- **`runs`** holds package URLs. Name your own software
  `pkg:generic/<product>@<version>`, matching the SBOM's `metadata.component`,
  so the host joins that release. Third-party packages keep their own purls
  (`pkg:deb/debian/php8.2@8.2.20-1~deb12u1`).
- **`coverage: full`** only when the scan read every host of the scope for
  everything in `looked_for` (`["*"]`, or product names). That's what lets the
  kit answer **none** for the scope; a `partial` scan only adds.
- **A CycloneDX SBOM of one host** (Syft, Trivy) also works, with metadata
  properties `cruxible.scope` and `cruxible.asset`. It never states the scope's
  coverage, so none answers still need a full scan in the kit's format.

~~~bash
echo '{"relative_path": "scans/prod.json"}' > scan.json
cruxible procedure run security.inventory-acquire scan.json
~~~

Every scope's Line sees every scan; the other scopes' Lines halt
`other_scope`. Then state what you know about each host, from deploy config or
the user:

~~~yaml
because: Host roles from deploy/prod.yaml, 2026-10-22.
changes:
  - {op: add, subject: security.asset/app-1.example.com, field: installs, value: security.release/myapp--1.0.0}
  - {op: add, subject: security.asset/app-1.example.com, field: serves, value: security.service/storefront}
  - {op: set, subject: security.asset/app-1.example.com, field: internet_exposed, value: true}
  - {op: set, subject: security.asset/app-1.example.com, field: environment, value: production}
~~~

`installs` is what a host is meant to run, beside what scans see it run.
`security.urgent_exposures` joins it to show each exposure's host, service
criticality and internet exposure. A host that declares a release but sits in
no current scan is answered **unknown**, so declare the hosts nobody scans
too.

### 5. Log sources

The kit records log sources on an incident's audit, where stating one asks
whether you were exploited; nothing holds them between incidents. So list them
now in a note, `security/log-sources.md`: for each service, each source
(`storefront/nginx-access`), the tool that queries it, and its retention.

### 6. Ask

~~~bash
cruxible query --name security.urgent_exposures
cruxible next
~~~

Report what's in, what isn't, and the fetch that would fill each gap.

## Then, on demand

Every unknown names what answers it. Fetch exactly that, approve what it
proposes, and ask again.

- **An incident's gaps.** `cruxible inbox list --line
  security.respond.INCIDENT --status unread` shows items of kind `gap`, whose
  `pull` and `input` say what to fetch:
  - `security.inventory-acquire` with `{"covering": "HOST"}`: scan the scope
    that holds that host (add a scope if none does) and acquire it.
  - `statement` with `"state": "security.audit.log_source"`: state the
    service's log sources from your note, creating its audit:

    ~~~yaml
    because: storefront's logs to read in full over the window (security/log-sources.md).
    changes:
      - op: create
        label: audit
        subject_kind: security.audit
        key:
          - {predicate: security.audit.incident_ref, value: Langflow RCE}
          - {predicate: security.audit.service_ref, value: storefront}
      - {op: set, subject: {created: audit}, field: incident, value: security.incident/langflow-rce}
      - {op: set, subject: {created: audit}, field: service, value: security.service/storefront}
      - {op: add, subject: {created: audit}, field: log_source, value: storefront/nginx-access}
    ~~~

  - Any other pull: its input is the body that Procedure reads ([The evidence
    each action lands](../../README.md#the-evidence-each-action-lands)).

  Then `cruxible line run security.respond.INCIDENT`.
- **An ageing scan.** A scope's coverage goes stale 12 h after its last full
  scan, and its none answers turn unknown; `cruxible next` flags the coverage
  `revision` first (`evidence_expiring`, then `claim_stale_evidence`).
  Re-scan that scope. Don't take the `set` or `retire` repair `next` offers
  for it: a hand-set revision isn't a scan, and retiring it drops the
  coverage.
- **A failed run.** Run it again once the source is reachable; until then its
  answers are unknown.

Report each answer as found, none or unknown, with the fetch that would answer
each unknown.
