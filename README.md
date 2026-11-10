# Cruxible kits

First-party kits: releases of definitions (ClaimTypes, CaptureContracts,
QueryDefinitions) that a Cruxible instance installs on demand through one
governed change set. Nothing here ships inside Cruxible itself.

```text
kits/<id>/
  cruxible-kit.json        release manifest (id, version, owned prefixes, artifact digests)
  artifacts/...            the exact snapshot bytes, lineage-free
```

## Using a kit

```sh
cruxible kit add project-state:1.0.0   # proposes the diff for this instance
cruxible kit status
```

`kit add` only proposes; approve and activate like any other change.

Supported: Linux x86-64 and macOS on Apple silicon; on Windows, use WSL2.

## Making a release

1. In an instance that holds the definitions, export them:
   `cruxible kit build --id <id> --version X.Y.Z --owns <prefix>. --out kits/<id>`
   (replace the directory's contents for a new version).
2. List the kit's inert files in its manifest: `python scripts/kits.py files`. A
   kit's top-level Markdown (README.md, reference.md), `examples/` and `skills/<name>/`
   travel in the bundle for its reader (`kit pull`, `kit docs`) but stay out of its
   content digest, so a docs fix keeps every definition digest (the image digest
   still changes, so a published version needs a patch bump). A skill installs as its
   own `<kit>-<skill>/` directory, so its relative links stay inside the kit's skills.
3. Open a pull request. CI checks that every kit reads cleanly and packs
   deterministically, and that a kit's generated reference (a kit with
   `source/reference.py`) matches its definitions, that the
   manifest lists the current inert files, and that skill links resolve once installed.
4. Publishing (currently started by hand from the Actions tab) pushes each version
   the registry does not hold to `ghcr.io/cruxible-ai/kits/<id>:<version>`. A published version never changes: a
   different build under an existing version fails, so bump the version.

Check locally with `python scripts/kits.py check`, and preview publishing with
`python scripts/kits.py publish --dry-run`.

## Security kit for Cruxible 0.5

Use the committed [security directory](kits/security/README.md) for local
installation. The registry tag becomes available after release.
[Its release builder](kits/security/source/README.md) rebuilds the dependency
kit from pilot definitions and schema-2 OSV/web provider sources. Retired
1.3 authoring, upgrade gates and persistent self-dogfood recipes have been
removed; the current pilot gates cover the supported path.

## License

The kits in this repository are released under the Apache License 2.0; see
[LICENSE](LICENSE). That covers what this repository authors: the
definitions, guidance, provider source and tooling. Content adapted from
elsewhere keeps its own license and says so where it appears (for example, a
guidance body adapted from an MIT-licensed project names it). The reference
data below is not covered by this license.

## Reference data: where it comes from and its terms

The security kit reads three public sources at run time. Small excerpts of the
first two are committed as test fixtures in
`kits/security/source/pilot/fixtures/` (`kev-catalog.json`, 20 entries;
`epss-api.json`, 10 rows). The kit does not redistribute either catalogue in
full; each install fetches its own copy from the source. Each source's terms
apply to the data it serves; check them before you build on that data.

| Source | What the kit reads | Terms, as the source publishes them |
|---|---|---|
| CISA Known Exploited Vulnerabilities (KEV) catalog | the catalogue JSON from `www.cisa.gov` | Released under Creative Commons CC0 1.0 (a public-domain dedication). The license adds that information at third-party links in the catalogue is bound by those sites' own terms, and that use of the data does not authorise use of the CISA logo or DHS seal, or imply endorsement. Source: <https://www.cisa.gov/sites/default/files/licenses/kev/license.txt>, repeated in <https://github.com/cisagov/kev-data>. |
| FIRST Exploit Prediction Scoring System (EPSS) | scores for watched CVE IDs from `api.first.org` | The EPSS FAQ says EPSS is free to use, published with no registration, and that attribution is requested when EPSS data is used in publications or products (<https://www.first.org/epss/faq>). FIRST's Services Terms of Use (<https://www.first.org/about/policies/terms>) list "API (Public)" among FIRST's services and grant a limited license to copy and distribute content retrieved from them for vulnerability disclosure, incident response and preventive cybersecurity use. **[unverified]** whether those Services terms govern the EPSS API, and what form of attribution FIRST asks for: the FAQ points to its "Get the Data" page for attribution guidance, and that page states none. |
| OSV (`api.osv.dev`) | advisory records for the package URLs in your SBOM | OSV aggregates advisories from many databases, each under its own license; OSV lists them per source at <https://google.github.io/osv.dev/data/>. Most are CC-BY 4.0, CC0 1.0, MIT or Apache 2.0; some are not (for example Ubuntu is CC-BY-SA 4.0 and Chainguard/Wolfi is CC-BY-NC-ND 4.0). A record's terms are those of the database it came from. **[unverified]** any terms of service for the `api.osv.dev` service itself, separate from the data licenses. |

Terms were read from the pages above on 2026-11-10 and can change; the
source's current page governs.
