# Building the security kit for Cruxible 0.5

The release is the dependency loop in `pilot/`: SBOM import, OSV, KEV, EPSS,
pair Subjects, triage queries and the governed dependency-judgment guidance.
The former 1.3 release's system-model/incident recipes, gates and upgrade variant
have been retired. Kit version 1.3.0 is still unpublished; this rebuild uses the
0.5 artifact format and protocol-2 provider packages. Nothing here publishes it.

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
with `uv build --offline`, and the two committed locks are checked, never
re-resolved. The runtime wheel is built from the explicit providers checkout
(version 0.4.0 for this release); select its reviewed commit. The web source
vendored under `providers/cruxible-provider-web` is 0.5.0; OSV retains its own
0.1.0.dev0 identity. Provider installation can fetch locked registry dependencies
from PyPI. No manual pip install or development environment is created.

The builder uses the public CLI to initialize a fresh publisher, accept provider
Contracts, install the two provider builds, author CaptureContracts/vocabulary/
Procedures, and store/author the dependency guidance. It does not author adopter
Lines, Mandates, Triggers or Runbooks. Production `kit build` validates the exact
committed automation template against the exported closure. Only then are the
manifest, artifacts, provider files and Document bodies copied into the kit.
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
loop and the optional SARIF/audit extension using recorded bytes. The SARIF
source remains for that extension; it is not a bundled provider in this release.
`python pilot/template.py --check` checks the committed template. Changing its
settlement authority requires a separate maintainer ruling.
