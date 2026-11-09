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
