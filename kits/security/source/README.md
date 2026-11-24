# Building the security kit for Cruxible 0.6

The release is the dependency loop in `pilot/`: SBOM import, OSV, KEV, EPSS,
pair Subjects, triage queries and the governed dependency-judgment guidance;
and the audit extension (`pilot/findings.py`): code findings, coverage units,
the SARIF import Procedures and provider, the audit Queries and the hunter,
verifier and coverage guidance. The reference pages (`../reference/`) ship as
plain kit files.
The former 1.3 release's system-model/incident recipes, gates and upgrade variant
have been retired. Kit version 1.4.0 (1.3.0 was never published) is built on
Cruxible 0.6.0 with the same artifact format as 1.3.0 (capabilities, CaptureKind
layouts, thin EXTRACT nodes, `requires: base`) and protocol-2 provider packages
at registration schema 3; it adds `it.asset` (the build owns `it.` beside
`security.`), and its automation template needs 0.6 (`expires`, `scope:
observations`). Nothing here publishes it.

From `kits/security`, use the Python interpreter with the target core and its
client available. `PYTHONPATH` must include that core checkout, its `src`, its
`packages/cruxible-client/src`, and the selected provider runtime's `src`.
`cruxible` beside that interpreter (or `CRUXIBLE_BIN`) must use the same core.

```sh
python source/build_release.py /short/new/scratch --providers-checkout /path/to/cruxible-providers \
    --published-wheels DIR   # until cruxible-provider-runtime 0.6.0 is on PyPI
```

The scratch directory must not exist. Its daemon socket requires a short path.
Only scratch and this kit directory are written; the core and providers
checkouts are read-only (the builder reads other commits with `git archive`).
`uv` and cached hatchling 1.33.0 are needed (1.32.1 was yanked): the kit's own
providers build with `uv build --offline`, and the three committed locks are
checked, never re-resolved.

The kit's own providers, OSV and SARIF (each 0.2.0.dev0; their pure operations
are `@derive` functions), are bundled: the kit carries their wheels and locks
with the `cruxible-provider-runtime` 0.6.0 wheel their locks name by path. The
general-purpose `cruxible-provider-web` 0.7.0 is a published dependency: `kit
build --default-provider` records the published wheel's sha256 and the lock it
embeds, the kit carries none of its files, and `kit add` installs it by name
from the consumer's provider index (its own environment, on the runtime 0.5.0
its lock pins). The builder downloads the published wheels from PyPI into
scratch (or copies them from `--published-wheels DIR`) and refuses unless each
has the sha256 `build_release` records (`PUBLISHED`, `WEB_RUNTIME`) and its
package files are the reviewed source byte for byte. The providers checkout
must be at `build_release.PROVIDERS_COMMIT` (`ca12589`, runtime 0.6.0), whose
runtime source the 0.6.0 wheel is checked against; web and its runtime are
checked against `WEB_COMMIT` (`b3fa37a`, where web 0.7.0 was published), read
with `git archive`, and the web package vendored under
`providers/cruxible-provider-web` (its `src/`, `pyproject.toml` and `uv.lock`,
which must be the lock the published wheel embeds) must be that commit's copy.
Runtime 0.6.0 is not on PyPI yet: `PUBLISHED` records the sha256 of the
reproducible build of `PROVIDERS_COMMIT`'s runtime source (`uv build --wheel`
with `SOURCE_DATE_EPOCH=1794009600` and hatchling 1.33.0, `dcdb2646…`), passed
with `--published-wheels`; once PyPI serves 0.6.0, record the sha256 it
publishes and rebuild. Each runtime wheel also sits beside its package in the
build's scratch, so the automation-template check can seed the web build the
template binds by name. Provider installation fetches locked
registry dependencies from PyPI. No manual pip install or development
environment is created.

The builder uses the public CLI to initialize a fresh publisher (which holds the
base kit from `init`), install the three provider builds, author the CaptureKinds
(without their layouts), the vocabulary, the kit's four capabilities, the
layouts, the Procedures for both loops, and store/author the four guidance
Documents. It does not author adopter Lines, Mandates, Triggers or Runbooks.
Production `kit build` validates the exact committed automation template against
the exported closure, leaves out every definition the base kit owns (`web.`,
`workspace.`) and records `requires: base >= 1.0.0`; the builder refuses any
other `requires`. Only then are the manifest, artifacts, provider files and
Document bodies copied into the kit.

The two kit providers' `registration.json` files are written from the kit's own
definitions by `providers/build_registrations.py` (each operation names the kit
capability it serves and carries byte-for-byte copies of its Contracts and
layouts). The builder refuses a stale registration; after changing a capability,
a Contract or a layout, run it first:

```sh
python providers/build_registrations.py
```
`SOURCE_DATE_EPOCH` fixes the kit providers' wheel timestamps. The inert-file manifest is refreshed
last; command receipts and daemon logs remain under scratch. The daemon is
stopped even when authoring/building fails.

After changing docs/examples, refresh only this kit's inert files:

```sh
python -c 'import runpy; runpy.run_path("../../scripts/kits.py")["write_files"](__import__("pathlib").Path("."))'
python ../../scripts/kits.py check
```

Run `pilot/test_*.py` with the same core on `PYTHONPATH` and
`CRUXIBLE_PROVIDERS_CHECKOUT` set. `test_start_gate.py` exercises production kit
build and a fresh consumer install of the actual committed directory, including
its guidance body and exported template. Other pilot gates test the dependency
loop and the SARIF/audit extension using recorded bytes; `test_pilot_gate.py` and
`test_findings_gate.py` also check that each thin EXTRACT node resolves through
its kind's layout to the full spec it replaced (`pilot/fixtures/extracts/`).
`python pilot/template.py --check` checks the committed template. Changing its
settlement authority requires a separate maintainer ruling.
