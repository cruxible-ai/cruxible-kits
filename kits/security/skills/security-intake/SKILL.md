---
name: security-intake
description: Bring an organization's state into the Cruxible security kit - what it ships (an SBOM per product), what runs where (a scan per inventory scope), its services, credentials and log sources - and read what each kind of unknown is asking for.
---

# Security intake

Use this skill when the security kit is installed but the instance doesn't yet hold what the user ships and
runs, and whenever an answer comes back **unknown**. The state says what to do next: `cruxible next`, the
inbox and each Line's runs name what is waiting, failing or missing, with the fetch or repair for each. This
skill says what those things mean and what only the user can tell you. The kit's README is the source for
every name, body format and recipe (*Intake recipes*, *The evidence each action lands*); the [security
analyst skill](../security-analyst/SKILL.md) works the answers.

## What only the user can tell you

Ask; never infer these from what you happen to find:

- which products matter, and the name and version people know each release by;
- the inventory scopes (a scope is the set of hosts one scan reads in full: prod, staging, one laptop) and
  what scans each;
- the services, how critical each is, which hosts serve them and which face the internet;
- each credential: its issuer and name, where it is used, what it reaches;
- where each service's logs live, how long they are kept, and who can read them;
- which Lines run. Enabling a Line is the user's consent to its definition and Triggers: name the ones that
  are off and ask.

## Invariants

- **A secret never enters a Capture.** Every file you acquire is retained, most for good. Record key ids or
  `fp:` fingerprints (the first 16 hex of the secret's sha256, computed where the secret lives), never keys,
  tokens or passwords; cut credentials out of a file before you retain it. If one lands anyway it is
  exposed: have it rotated, then erase the Capture with a reason that doesn't repeat it (only inventory,
  log-read and credential-state Captures can be erased).
- **A failed fetch is unknown, never none.** A run that failed or halted read nothing; an empty answer after
  it is unknown. Say what wasn't read and why.
- **An import states what its file says.** If the file is wrong, fix the file and read it again; never
  hand-write the observation it should have made. What you state yourself (services, host roles, where a
  credential is used, log sources) is yours: say where you learned it.
- **An approval means it matches.** Approve an import's proposal only when it says what the file says and
  the user has agreed to it landing.
- **Only a read answers a read.** An ageing or stale scan coverage is answered by a new scan. A repair that
  hand-sets or retires the coverage revision makes the answer look current without anyone looking.

## What the answers mean

- **found, none, unknown.** None means a current coverage says the source was read and nothing matched.
  Anything nobody read is unknown, and every unknown names the fetch that would answer it.
- **A release** is the product and version an SBOM's `metadata.component` names, or in a scan a purl's whole
  namespace and name with its version (`debian/php8.2`). A host joins a release by that name.
- **OSV coverage** (on each release): `complete` means OSV answered every component; `partial` names the
  purl types OSV never indexes and the components with no purl. It answers only for the component set its
  digest names: a release, component or watched CVE added since OSV last ran has no answer yet.
- **A scan's coverage.** `full` says the scan read every host of its scope for everything in `looked_for`.
  Only a full scan states **nones** ("this host runs no php"), and only for a product it looked for, or under
  `"*"` for one the host ran before or declares. A partial scan, or a CycloneDX SBOM of one host, only adds.
  A none goes stale with its coverage (12 h).
- **installs and runs.** `installs` is what you say a host is meant to run; `runs` is what a scan saw there.
  A host nobody scans is unknown, never clean: declare it, and get it scanned.
- **A complete credential listing** holds every key the issuer has for that credential; only then does a
  key's absence count, which is how a rotation verifies.
- **A log source** is a short pointer; what reads it, its retention and its owner go in a section of
  `security/log-sources.md` that the Claim cites.

## Conventions the kit can't check

- **Name software the way OSV knows it.** OSV answers only for the purl types it indexes (the README lists
  the kit's map). A `pkg:brew`, `pkg:generic` or `pkg:docker` release stays partial and its incident pairs
  unknown, so name a binary by what it is: a Go binary by its module, a Python or Node tool by its PyPI or
  npm package, each at the version installed on that host, never the newest one a package manager offers.
  Keep `pkg:brew` only where nothing better exists.
- **Name your own software** in a scan as `pkg:generic/<product>@<version>`, matching its SBOM's
  `metadata.component`, so the host joins that release.
- **An SBOM lists what ships.** A component without a purl (a workspace member, an unnamed OS component)
  leaves the release partial; a dependency the generator dropped (a git dependency) is simply absent. Add it
  by the purl OSV knows it by, or leave the release honestly partial. The README has generator routes and
  their known gaps.
- **Look for what an incident needs.** A host's none for a product exists only if its scan looked for that
  product: name the products whose absence matters beside `"*"`.
- **State a Subject before pointing at it.** A value never creates the Subject it names.

## What each unknown is asking for

Gaps arrive as inbox items with a `pull` and an `input`; that pull with that input is the fetch.

| Gap | What it is asking for |
|---|---|
| `security.inventory-acquire` (`covering`, `looking_for`) | a current full scan of the scope that holds the host, looking for the named products; a new scope if none holds it |
| `security.fetch` (`url`, `logical_source`, `max_bytes`) | the CVE's record, with source `cve.record` and the supplied byte limit |
| `security.osv-applicability` | OSV's answer for this release's current components, or for a CVE it hasn't decided |
| `statement`: `security.assessment.status` | a judgment, because no source can decide: OSV doesn't index these releases' components. A purl OSV indexes (a re-scan), a product alias the record names, or an analyst's judgment answers it |
| `statement`: `security.release.unidentified_components` | two Claims disagree about the count; resolve it before a none rests on it |
| `statement`: `security.audit.log_source` | the audit's log sources: every source the service lists, or the answer stays unknown |
| `statement` with `input.missing` | each missing piece: a value to state, or a span of a source to read |
| any other pull | the body that Procedure reads (README) |

A source that no longer exists (logs past retention, HTTP 410) can't be fetched: it is residue to report,
not a gap to close. Report each answer as found, none or unknown; for each unknown, the fetch that answers
it, or why nothing can.
