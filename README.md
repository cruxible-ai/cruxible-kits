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
cruxible playbill kit add project-state:1.0.0   # proposes the diff for this instance
cruxible playbill kit status
```

`kit add` only proposes; approve and activate like any other change.

## Making a release

1. In an instance that holds the definitions, export them:
   `cruxible playbill kit build --id <id> --version X.Y.Z --owns <prefix>. --out kits/<id>`
   (replace the directory's contents for a new version).
2. Open a pull request. CI checks that every kit reads cleanly and packs
   deterministically.
3. Publishing (currently started by hand from the Actions tab) pushes each version
   the registry does not hold to `ghcr.io/cruxible-ai/kits/<id>:<version>`. A published version never changes: a
   different build under an existing version fails, so bump the version.

Check locally with `python scripts/kits.py check`, and preview publishing with
`python scripts/kits.py publish --dry-run`.
