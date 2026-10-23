---
name: security-intake
description: Pull an organization's state into the Cruxible security kit - an SBOM per repository, a runtime inventory per scope, services and their credentials, log sources - in one first pass, then fetch whatever an unknown answer names
---

# Security intake

Use this skill when the security kit is installed and its example automation
adopted, but the instance doesn't yet know what you ship and run; then again
whenever an answer comes back **unknown**. The kit's README
(`cruxible kit docs security --out DIR` writes it) is the source for every name
below. Once the state is in, the [security analyst skill](../security-analyst/SKILL.md) works the answers. The core
guides are at https://docs.cruxible.ai.

Everything you acquire is proposed, never written directly. Review each
proposal (`cruxible proposal review ID`) and approve it (`cruxible proposal
approve ID --yes`) only when it matches what you read and the user has agreed.
Approve one import before you acquire the next: two imports that touch the
same release can't both land, and the second goes stale (acquire its file
again).

## Before you start

- **`uv` on `PATH`.** The kit's bundled Providers install and run through uv;
  without it, installing or running them fails (core reports
  `network_disabled` without the real cause). Check `uv --version`.
- **`npm`/`npx`** for JavaScript SBOMs, and Python 3.11+ (with `uvx`) for
  Python ones.

## Ground rules

- **Never put a secret in a Capture.** Every file you acquire is kept. Record
  key ids or `fp:` fingerprints, never keys, tokens or passwords, and cut
  credentials out of a config before you retain it. If a secret lands anyway,
  stop, have it rotated, and erase the Capture: `cruxible capture erase CAP-...
  --because "..."` previews, then `--commit --at` erases, with a reason that
  doesn't repeat the secret. Only inventory, log-read and credential-state
  Captures can be erased; SBOMs and evidence files keep their bytes for good
  (*Respond to an incident*: secrets never enter).
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
mkdir -p sboms intake
# A uv project (Python): pin the lock to requirements, then build the SBOM from them.
uv export --format requirements.txt --no-dev --no-hashes --no-emit-project \
    > intake/myapp-requirements.txt
uvx --from cyclonedx-bom cyclonedx-py requirements intake/myapp-requirements.txt \
    --pyproject pyproject.toml --of JSON -o sboms/myapp.cdx.json
# A JavaScript project (needs npm):
npx @cyclonedx/cdxgen -t js -o sboms/web.cdx.json .
~~~

`cyclonedx-py requirements` ignores environment markers, so a Windows-only pin
(`pywin32`) lands as a component too; drop it from the requirements file if you
never ship it. `uv export --format cyclonedx1.5` doesn't work on every uv (0.8
refuses it); the requirements route does.

<!-- maintainer: check the syft line (not run here) -->
~~~bash
syft dir:. -o cyclonedx-json > sboms/myapp.cdx.json                       # any ecosystem
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
{"issuer": "stripe", "name": "storefront-live", "read": "state_read", "complete": true,
 "keys": [{"key_id": "fp:3f9a1c0d22b84e6a", "state": "active",
           "created_at": "2026-03-02T10:00:00Z", "created_by": "ops"}]}
~~~

`complete: true` says the listing holds every key the issuer has for the
credential (every page read). Only then does a key's absence from it count: a
rotation verifies when the old key is listed `revoked` or `deleted`, or is absent
from a complete listing.

~~~bash
echo '{"relative_path": "creds/stripe-storefront-live.json"}' > cred.json
cruxible procedure run security.credential-acquire cred.json
~~~

Any other field, or a key id, issuer, name or `created_by` shaped like a secret,
refuses the whole body and posts `secret_shape` (a fixed message: nothing from the
body is echoed); the bytes are kept, so erase the Capture. The import
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
  (`pkg:deb/debian/php8.2@8.2.20-1~deb12u1`). The release is named by the purl's
  whole namespace and name (`debian/php8.2`), and `looked_for` names products
  the same way.
- **Prefer a native purl OSV indexes.** OSV answers only for the purl types its
  ecosystem list covers; the kit's map (carried in `security.osv-applicability`)
  reads `pypi`, `npm`, `maven`, `golang`, `cargo`, `gem`, `nuget`, `composer`,
  `pub`, `hex`, `hackage`, `cran`, `swift`, `conan`, `bitnami`,
  `githubactions`, `deb/debian`, `deb/ubuntu`, `apk/alpine`, `apk/wolfi`,
  `apk/chainguard` and `rpm/` for Red Hat, AlmaLinux, Rocky Linux, openSUSE,
  SUSE, Mageia and openEuler, each only while OSV's captured `ecosystems.txt`
  lists its ecosystem. `pkg:brew`, `pkg:generic`, `pkg:docker` and the rest
  are never asked: their releases read `osv_coverage` `partial`, and an
  incident keeps them **unknown**. So name a binary by what it is: a Go binary
  by its module (`go version -m $(command -v gh)` prints `path
  github.com/cli/cli/v2` and `mod ... v2.86.0`: run
  `pkg:golang/github.com/cli/cli/v2@v2.86.0`), a Python or Node tool by its
  PyPI or npm package. Keep `pkg:brew/<formula>@<version>` (from `brew list
  --versions`) only where there's nothing better, and state a product alias
  when a CVE record names its upstream (the analyst skill).
  After the OSV run, `cruxible query --name security.release_inventory` shows
  each release's `osv_coverage`; each OSV query Capture lists its
  `not_indexed` components with why.
- **`coverage: full`** only when the scan read every host of the scope for
  everything in `looked_for` (`["*"]`, or product names). That's what lets the
  kit answer **none** for the scope; a `partial` scan only adds.
- **A CycloneDX SBOM of one host** (Syft, Trivy) also works, with metadata
  properties `cruxible.scope` and `cruxible.asset`. It never states the scope's
  coverage, so none answers still need a full scan in the kit's format. A
  component without a purl and version (the OS component aside) makes the SBOM
  add only: it could be any product, so it never retires a run or verifies a
  patch. Generate SBOMs with purls.
- **Look for what the incident affects.** A deployment's **none** needs a current
  full scan of the host that looked for the release's product (`["*"]` covers
  everything). A scan that looked only for `php` can't say a host doesn't run
  `debian/php8.2`: the incident keeps that host unknown, its gap naming the
  products to look for (`input.looking_for`).

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
`security.urgent_exposures` shows both: `asset` is a host that declares the
release (`asset_observed` set when a scan also sees it running there), and
`observed` is a host only a scan sees, each with its service criticality and
internet exposure. Every host is enumerated in an incident (`security.deployments`),
whatever it declares: one in no current scan (never scanned, stale, or its scan's
evidence erased) is answered **unknown** with a gap naming the inventory pull, so
declare the hosts nobody scans too, and scan them.

### 5. Log sources

State where each service's logs live, so an incident's audit starts from the
list instead of a hunt. The value is a pointer only, a short identifier such
as `caddy:app-1:/var/log/caddy/access.log` or `storefront/nginx-access`.
Retention, the tool and query that read it, and who owns it go in a section of
`security/log-sources.md` that the Claim cites:

~~~yaml
because: Where storefront's logs live, from the platform runbook, 2026-10-22.
changes:
  - {op: add, subject: security.service/storefront, field: log_source, value: storefront/nginx-access,
     evidence: {kind: section, file: security/log-sources.md, section: [storefront], own_words: true}}
  - {op: add, subject: security.service/storefront, field: log_source, value: storefront/php-fpm,
     evidence: {kind: section, file: security/log-sources.md, section: [storefront], own_words: true}}
docs:
  - op: append
    file: security/log-sources.md
    text: |
      # storefront

      storefront/nginx-access: Loki, `{app="storefront", log="access"}`, 30-day retention, platform team.
      storefront/php-fpm: Loki, `{app="storefront", log="php-fpm"}`, 30-day retention, platform team.
~~~

`cruxible write intake/log-sources.yaml`. When a source moves or a new one
appears, change the list the same way (`retire` an old value, `add` a new one).

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
  - `statement` with `"state": "security.audit.log_source"`: create the
    service's audit with the log sources its `input.sources` names (the
    service's `log_source` list), or add the ones it names to an existing
    audit. A source the service lists and its audit leaves out keeps the
    answer unknown:

    ~~~yaml
    because: storefront's logs to read in full over the window (its log_source list).
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
      - {op: add, subject: {created: audit}, field: log_source, value: storefront/php-fpm}
    ~~~

  - `security.cve-record-acquire` with `{"url": ...}`: no record of an incident
    CVE was read yet. Acquire it with exactly that input.
  - `statement` with `"state": "security.assessment.status"` and
    `osv_not_indexed`: OSV doesn't index the release's components (a
    `pkg:brew` or `pkg:generic` purl). Re-scan naming the binary by a purl OSV
    indexes (above), state a product alias the record names, or record an
    analyst's judgment (the analyst skill).
  - `security.osv-applicability` with `{"release": ...}`: OSV hasn't answered
    the release yet: `cruxible line run security.osv-applicability`.
  - `statement` with `input.missing` (an audit): each piece is one thing to
    state (`state`) or read (`source`, `from`, `to`).
  - Any other pull: its input is the body that Procedure reads (*The evidence
    each action lands*).

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
