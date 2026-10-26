# Security kit: for maintainers

How the maintainer builds and gates a release of the security kit, and the
self-dogfood runs over Cruxible's own dependencies. This page lives in the kits
repository and is not part of the kit bundle; the kit's reader starts at the
[README](../README.md).

## Building a release

```sh
python source/build_release.py SCRATCH_DIR --providers
```

with the interpreter of the cruxible build the release targets. It rebuilds both
bundled providers (registration, tests, wheel), starts a daemon on a fresh state
root under `SCRATCH_DIR`, installs `cruxible-provider-web` 0.2.2 and the bundled
wheels, runs `source/authoring/security_definitions.py definitions` and
`procedures` for 1.3.0, `kit build`s it, authors the 1.3.1 successors on the
same instance and builds those, then copies 1.3.0 over `cruxible-kit.json`,
`artifacts/` and `providers/` in the kit directory and 1.3.1 over `source/variants/1.3.1-gate`,
and regenerates `reference.md` and the README's counts table from the copied
release (`python source/reference.py` does only that step; after editing
`examples/automation.json` run it too, and `--check` also refuses a concept map
that names a kind or field the kit does not define). The same sources build the same kit
digest. After changing a provider, bump its
version. `source/providers/cruxible-provider-web` holds the published 0.2.2
wheel, the lock it embeds and the runtime wheel that lock names by path, so
`kit build` can record the default's hashes; none of those files ship.
`source/variants/1.3.1-gate` is a release-gate fixture (changes `kev_exposure`,
adds `vulnerability.kev_cwes`, changes fetch-observed from 60 to 90 seconds and KEV triage from 120 to 150
seconds, and changes the analysis Provider's KEV rationale), not a published version.

## Release gate

`gate/test_security_kit_gate.py` runs the v1 release gate end to end on a fresh
daemon with a scratch state root and HOME: the kit is published to a throwaway
HTTPS OCI registry on 127.0.0.1, installed, automated, fed an
inventory and an SBOM, run through OSV and CVE-record applicability, applicability
bets, KEV triage and attention, EPSS, a restart, measurement, graduation to
settle, the upgrade to `source/variants/1.3.1-gate` and the re-import of a changed
SBOM and a new release, then the system model: gates asked with every answer
unknown and one gap per source, pulls and parses, an unchanged re-pull
(re-observation), a moved `main`, fail-closed freshness, a declared/running
disagreement and a full investigation, then the code findings under independent
approval: a Semgrep report, an agent's duplicate, CodeQL's own key, a located,
triaged, contended and confirmed finding, HQ6, and a fix that drifts the location,
verifies by full re-scan and regresses, then an incident (PHP2Shell) under
independent approval: a KEV listing reaching exposure through a Syft SBOM and a
scope's inventory, distro builds left to OSV, patches closed only by a scan (a
claimed patch the scan disagrees with disputed), unchanged re-scans and stale
coverage, audits in three states (an incomplete read, a contended result, own words
refused), rotations verified only by a separate state read (an old key still
active, a secret-shaped body refused), a window-close re-ask, the status page and
closure, asserting each step's observable. The SARIF fixtures are in the analysis
Provider's `tests/data/sarif` (Semgrep's recorded, CodeQL's hand-built in its
shape), the incident's in `tests/data/incident` (recorded shapes: CVE JSON 5.1, an
NVD answer with null configurations, a Syft CycloneDX SBOM, log reads and key
listings). It is
offline from every security source: `gate/fixture-sources` (package
`security-gate-sources`) is cruxible-provider-web's own `WebFetch` and the kit's
own OSV, EPSS, repository and PyPI adapters (vendored by its
`build_registration.py`) answering from `responses/` (recorded once by
`record_responses.py` and `record_system_model.py`). Provider installs still
need PyPI.

The upgrade recovery probe deliberately retires and restores an EPSS score.
Core correctly reports `line_settled_prior_refusals` for that settlement on the
same evidence. The gate inspects its retirement receipt, submits the repair's
ready payload (the same EPSS Line capped at `propose`; `cruxible next` prints it
as a `cruxible authoring submit` command), and re-enables the Line before
checking that `next` is empty.

```sh
CRUXIBLE_BIN=$(command -v cruxible) python -m pytest kits/security/gate -x -q
```

It needs `git` and `openssl`, takes about forty minutes, and writes
`gate-results.md` and the command log to its scratch root
(`SECURITY_KIT_GATE_ROOT` to choose one). After changing the fixture, run its
`build_registration.py`, `uv lock` and `uv build --wheel --out-dir dist`.

## Self-dogfood

`examples/self-dogfood/` (at the repository root) runs the whole loop live over
Cruxible's own dependency tree: `sbom_from_uv_lock.py` writes a CycloneDX SBOM
per package from a uv.lock, and `run.py` imports them into a fresh instance,
asks OSV, KEV and EPSS, reads `urgent_exposures`, and times settle batches of
~400 KEV Claims.

A persistent instance runs the kit daily over the same dependencies:
`setup_persistent.py` creates it (KEV and EPSS triage graduated to settle,
applicability propose-only: the review queue), `daemon.sh` starts, stops and
checks its daemon, `refresh_sboms.py` re-imports the SBOMs whose bytes changed
after a dependency change, and `snapshot.py` appends one daily metrics line.
The instance root's `OPERATING.md` says how to run and read it.

Setup and refresh require `--core-repo PATH --core-sha FULL_SHA
--providers-repo PATH --providers-sha FULL_SHA`; no branch defaults are used.
Setup prints and retains these exact inputs in `source-pins.json` before
importing the SBOMs. Choose the actual repositories and reviewed commits; the
scripts never change those repositories.
