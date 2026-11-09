# Example SBOMs

These are inputs for the Cruxible 0.5 dependency kit:

| File | Meaning |
|---|---|
| `sboms/log4j-demo-app.cdx.json` | Demo application containing log4j-core 2.14.1; a useful live OSV/KEV example, not real deployed software |
| `sboms/cruxible-env.cdx.json` | A recorded Python environment inventory, not a statement of your current environment |
| `sboms/env_sbom.py` | Write an inventory from the Python environment running it |

Install the local kit directory first, then copy the template and example into
your attached Git workspace:

```sh
cp /path/to/cruxible-kits/kits/security/automation.json automation.json
cp /path/to/cruxible-kits/kits/security/examples/sboms/log4j-demo-app.cdx.json sbom.cdx.json
```

Tailor the Line names and references, UTC cron times and Mandate dates. The
SBOM Line must read `sbom.cdx.json` (or the workspace-relative path you choose).
Submit with `cruxible authoring submit automation.json --no-accept`, have a
second actor review and approve it, activate the proposal, then run
`cruxible runbook preview security.start`. Review its availability, order and
settlement scopes before `cruxible runbook run security.start`.

The Runbook makes real OSV, CISA and FIRST network calls. Refusals or incomplete
answers remain gaps. No recorded responses are substituted by this example.
See [the installation instructions](../README.md#install-and-first-answers).
