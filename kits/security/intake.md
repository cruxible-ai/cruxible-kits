# Intake recipes

Commands and bodies for bringing your state into the kit, with the gaps each
generator leaves; the README's [Install and first
answers](README.md#install-and-first-answers) comes first.

These are reference recipes for the intake skill. The user chooses sources,
scopes and enabled Lines; state records what is waiting.

## An SBOM per repository

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
refuses it); the requirements route does. Two lines the requirements route
mishandles, so fix them before building the SBOM:

- **A uv workspace member** (`-e ./packages/client`) comes out as a component
  with no purl, which leaves the release's coverage `partial` (an unidentified
  component). Leave members out (`--no-emit-workspace`) and give each member
  its own SBOM; or replace the line with the member's pinned name
  (`client==0.3.2`) when it is published.
- **A git dependency** (`pkg @ git+https://github.com/org/pkg@<sha>`) is dropped:
  it never reaches the SBOM. List it yourself: add a component with the package
  URL OSV knows it by (`pkg:pypi/<name>@<version>` when the commit is a released
  version; otherwise `pkg:github/<org>/<repo>@<sha>`, which OSV doesn't index, so
  the release stays honestly partial until an analyst judges it).

The user should check the generated purls and versions against the installed
software; the Syft command below is a generator recipe, not a verified host scan.
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

## Services

A value never creates the Subject it names, so state the services before
anything points at them. The examples on this page use the Python SDK
(`cruxible-client`, which `cruxible` installs), connected once:

~~~python
from cruxible_client import Cruxible

cx = Cruxible.connect()
services = cx.changes(because="Service map from the platform runbook, 2026-10-22.")
for service in ("storefront", "payments"):
    services.set(f"security.service/{service}", "criticality", "critical")
outcome = services.write()
outcome.status   # 'accepted'
~~~

For an MCP-only client the same write is `cruxible_write` with these arguments
(on the CLI, `cruxible write FILE` takes them as a JSON or YAML file):

~~~json
{
  "because": "Service map from the platform runbook, 2026-10-22.",
  "changes": [
    {
      "op": "set",
      "subject": "security.service/storefront",
      "field": "criticality",
      "value": "critical"
    },
    {
      "op": "set",
      "subject": "security.service/payments",
      "field": "criticality",
      "value": "critical"
    }
  ]
}
~~~

## Credentials

Acquire one credential-state read per credential: a list of the issuer's
current keys, by non-secret id. `key_id` is the issuer's key id, or `fp:` and
the first 16 hex of the secret's sha256, computed where the secret already
lives.

~~~json
{
  "issuer": "stripe",
  "name": "storefront-live",
  "read": "state_read",
  "complete": true,
  "keys": [
    {
      "key_id": "fp:3f9a1c0d22b84e6a",
      "state": "active",
      "created_at": "2026-03-02T10:00:00Z",
      "created_by": "ops"
    }
  ]
}
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

~~~python
key = cx.changes(because="Where the Stripe live key is used, from the payments runbook.",
                 subject="security.credential/stripe--storefront-live")
key.add("used_by", "security.service/storefront")
key.add("reaches", "security.service/payments")
outcome = key.write()
~~~

## A runtime inventory per scope

A scope is the set of hosts one scan reads in full. Each scope needs its own
import Line; the example automation has `security.inventory-import.prod`. For
another scope, submit this pair and ask the user to enable the Line:

~~~python
from cruxible_client.contracts.authoring.models import CaptureLandingByNameSchedule

scope = cx.changes(rationale="Inventory scope staging.")
scope.line(name="security.inventory-import.staging", procedure="security.inventory-import",
           max_authority="propose", trigger_input="inventory", parameters={"scope": "staging"})
scope.trigger(name="security.inventory-landed.staging", line="security.inventory-import.staging",
              schedule=CaptureLandingByNameSchedule(capture_contract="security.file-erasable-v1",
                                                    logical_sources=("security.inventory",)))
intent = scope.submit()
intent.outcome.status   # 'landed'
~~~

Write each scope's scan in the kit's format, from whatever its scanner
outputs:

~~~json
{
  "scope": "prod",
  "looked_for": ["*"],
  "coverage": "full",
  "assets": [
    {"hostname": "app-1.example.com", "runs": ["pkg:generic/myapp@1.0.0"]},
    {"hostname": "app-2.example.com", "runs": ["pkg:generic/myapp@1.0.0"]}
  ]
}
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
  `pkg:golang/github.com/cli/cli/v2@v2.86.0`). Without Go: `brew info --json=v2
  gh` gives `formulae[0].installed[0].version`, the version on this host (never
  `formulae[0].versions.stable`, which is the newest formula). Read the upstream project's `go.mod` at that installed version's tag for its module path
  (`module github.com/cli/cli/v2`); a Go module's version is the release tag
  (`v2.86.0`). A Python or Node tool is named by its PyPI or npm package. Keep `pkg:brew/<formula>@<version>` (from `brew list
  --versions`) only where there's nothing better, and state a product alias
  when a CVE record names its upstream (the analyst skill).
  After the OSV run, `cruxible query --name security.release_inventory` shows
  each release's `osv_coverage`; each OSV query Capture lists its
  `not_indexed` components with why.
- **`coverage: full`** only when the scan read every host of the scope for
  everything in `looked_for` (`["*"]`, or product names). A full scan states
  each host's **nones** (`asset.runs` inverses: "this host runs no php"), the
  only way the kit answers **none** for a host; a `partial` scan only adds.
- **A CycloneDX SBOM of one host** (Syft, Trivy) also works, with metadata
  properties `cruxible.scope` and `cruxible.asset`. It never states the scope's
  coverage, so none answers still need a full scan in the kit's format. A
  component without a purl and version (an operating-system component included)
  makes the SBOM add only: it could be any product, so it never retires a run or verifies a
  patch. Generate SBOMs with purls.
- **Name what the incident affects in `looked_for`.** A host's **none** for a
  product is a none the scan stated, and a scan states one only for a product it
  looked for: every product `looked_for` names that the host doesn't run, and,
  under `"*"`, only a product the host ran before (it vanished: the run retires
  and the none lands in one change) or declares installing. `"*"` alone never
  says a host runs no `php` it never saw, so list the products whose absence
  you need beside it: `["*", "php", "debian/php8.2"]`. A scan that looked only for
  `php` can't say a host doesn't run `debian/php8.2`: the incident keeps that host
  unknown, its gap naming the products to look for (`input.looking_for`). A none
  goes stale with the coverage (12 h); each full scan restates it. A host that
  joins a scope gets the nones of what it declares from the scan after.

~~~bash
echo '{"relative_path": "scans/prod.json"}' > scan.json
cruxible procedure run security.inventory-acquire scan.json
~~~

Every scope's Line sees every scan; the other scopes' Lines halt
`other_scope`. **Then ask OSV again**: `cruxible line run
security.osv-applicability` after every scan that adds releases, and after an
incident or a watch adds a CVE. The import's run returns before its proposal is
approved, and OSV answers only the releases and CVEs it held when it ran; until it
runs again those pairs stay unknown (`osv_line`). Then state what you know about each host, from deploy config or
the user:

~~~python
host = cx.changes(because="Host roles from deploy/prod.yaml, 2026-10-22.",
                  subject="security.asset/app-1.example.com")
host.add("installs", "security.release/myapp--1.0.0")
host.add("serves", "security.service/storefront")
host.set("internet_exposed", True)
host.set("environment", "production")
outcome = host.write()
~~~

`installs` is what a host is meant to run, beside what scans see it run.
`security.urgent_exposures` shows both: `asset` is a host that declares the
release (`asset_observed` set when a scan also sees it running there), and
`observed` is a host only a scan sees, each with its service criticality and
internet exposure. Every host is enumerated in an incident (`security.deployments`),
whatever it declares: one in no current scan (never scanned, stale, or its scan's
evidence erased) is answered **unknown** with a gap naming the inventory pull, so
declare the hosts nobody scans too, and scan them.

## Log sources

State where each service's logs live, so an incident's audit starts from the
list instead of a hunt. The value is a pointer only, a short identifier such
as `caddy:app-1:/var/log/caddy/access.log` or `storefront/nginx-access`.
Retention, the tool and query that read it, and who owns it go in a section of
`security/log-sources.md` that the Claim cites, written in the same change set:

~~~python
logs = cx.changes(because="Where storefront's logs live, from the platform runbook, 2026-10-22.",
                  subject="security.service/storefront")
logs.append_section("security/log-sources.md", id="storefront", text=(
    "# storefront\n\n"
    'storefront/nginx-access: Loki, `{app="storefront", log="access"}`, 30-day retention, '
    "platform team.\n"
    'storefront/php-fpm: Loki, `{app="storefront", log="php-fpm"}`, 30-day retention, '
    "platform team.\n"))
for source in ("storefront/nginx-access", "storefront/php-fpm"):
    logs.add("log_source", source, supported_by=logs.section("storefront"))
outcome = logs.write()
~~~

When a source moves or a new one appears, change the list the same way
(`retire` an old value, `add` a new one).

## Generic HTTP reads

`security.fetch` takes `url`, `logical_source` and `max_bytes`. Its direct-read
contract allows exactly `cve.record`, `github.api` and `github.release`. A CVE record uses
`cve.record` and 1,048,576 bytes; a GitHub release uses `github.release`, and API
history uses `github.api`, both with 4,194,304 bytes. For example:

~~~json
{
  "url": "https://cveawg.mitre.org/api/cve/CVE-2021-44228",
  "logical_source": "cve.record",
  "max_bytes": 1048576
}
~~~

Save it as `intake/cve.json` and run
`cruxible procedure run security.fetch intake/cve.json`. The KEV daily Line uses
`security.fetch-observed` with the CISA URL, source `cisa.kev.catalog` and
`max_bytes: 4194304`; its emitted summary makes it Line-only.

## Host SBOM context

The file Source retains the bytes it reads. A host SBOM therefore names its scope
and asset in `cruxible.scope` and `cruxible.asset` metadata properties. An acquire
input cannot currently carry those values into the landing import. A Line's fixed
asset parameter cannot safely supply them: every inventory Line sees every landing.
An unannotated host SBOM refuses. Repair it by annotating `cruxible.asset` and
`cruxible.scope` in the retained SBOM before acquiring it.

The inventory and SBOM import summaries include `osv_unindexed` and
`osv_not_indexed` (counts by purl type). Their proposal rationales name these
counts; the kit map describes candidate ecosystems, while captured OSV responses
remain the authority for coverage.
