# Building the security kit for Cruxible 0.5

The release is the dependency loop in `pilot/`: SBOM import, OSV, KEV, EPSS,
pair Subjects, triage queries and the governed dependency-judgment guidance;
and the audit extension (`pilot/findings.py`): code findings, coverage units,
the SARIF import Procedures and provider, the audit Queries and the hunter,
verifier and coverage guidance. The reference pages (`../reference/`) ship as
plain kit files.
The former 1.3 release's system-model/incident recipes, gates and upgrade variant
have been retired. Kit version 1.3.0 is still unpublished; this rebuild uses the
0.5 artifact format (capabilities, CaptureKind layouts, thin EXTRACT nodes,
`requires: base`) and protocol-2 provider packages at registration schema 3.
Nothing here publishes it.

From `kits/security`, use the Python interpreter with the target core and its
client available. `PYTHONPATH` must include that core checkout, its `src`, its
`packages/cruxible-client/src`, and the selected provider runtime's `src`.
`cruxible` beside that interpreter (or `CRUXIBLE_BIN`) must use the same core.

```sh
python source/build_release.py /short/new/scratch --providers-checkout /path/to/cruxible-providers
```

The scratch directory must not exist. Its daemon socket requires a short path.
Only scratch and this kit directory are written; the core and providers
checkouts are read-only. `uv` and cached hatchling 1.32.1 are needed: wheels build
with `uv build --offline`, and the three committed locks are checked, never
re-resolved. The runtime wheel is built from the explicit providers checkout
(version 0.5.0 for this release), which must be at the reviewed commit
`build_release.PROVIDERS_COMMIT` records (`b3fa37a`); the web source vendored
under `providers/cruxible-provider-web` (0.7.0) must be that commit's
`src/` byte for byte, and the build refuses otherwise. OSV retains its own
0.1.0.dev0 identity, as does SARIF (`providers/security-sarif-provider`). Provider installation can fetch locked registry dependencies
from PyPI. No manual pip install or development environment is created.

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
`SOURCE_DATE_EPOCH` fixes wheel timestamps. The inert-file manifest is refreshed
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
