# Car parts kit

## What it is

An example kit: a small parts catalog, the vehicles parts fit, and the notes
and decisions a parts counter keeps about them. The Cruxible guides at
https://docs.cruxible.ai use it for every worked example, because everyone
already knows how parts, cars and fitments relate. It is a teaching domain,
not a product catalog.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which parts fit this car? | `catalog.parts_for_vehicle` (parameter `vehicle`, such as `honda-civic-2019`) |
| What is a part, and what does it replace? | `cruxible query catalog.part --select title,category,replaces` |
| Which notes are about a part? | `cruxible query catalog.part --follow-in catalog.note.about:note --select title,note.title` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `catalog.part` | its part number (`bp-1142`) | `title`, `category` (`brakes`, `filters`, `lighting`, `wipers`), `price` (an integer; must cite a quote), `fits` (vehicles), `replaces` (older parts) |
| `catalog.vehicle` | make, model and year (`honda-civic-2019`) | `make`, `model`, `year` |
| `catalog.note` | a short slug | `title`, `about` (parts and vehicles) |
| `catalog.decision` | a short slug | `status`, `summary`, `governs` (parts and vehicles), `amends` (earlier decisions) |

A part's `price` must cite captured evidence, such as a passage of a quote
file in the workspace catalog, and its evidence goes stale after two minutes, so
the guides' freshness examples show quickly. For real use, change it with an
edit (`stale_after: P30D`, say). `fits`, a note's `about` and a decision's
`governs` and `amends` also admit a passage of any catalogued workspace file
besides your own words. Text fields hold at most 256 characters; longer prose
belongs in a document section the Claim cites.

## Install and first answers

```sh
cruxible kit add car-parts:2.0.0                  # preview
cruxible kit add car-parts:2.0.0 --commit --at OID
cruxible set catalog.vehicle/honda-civic-2019 make Honda --because "Acme catalog 2026."
cruxible set catalog.part/bp-1142 title "Front brake pads" --because "Acme catalog 2026."
cruxible add catalog.part/bp-1142 fits catalog.vehicle/honda-civic-2019 --because "Acme catalog 2026."
cruxible query --name catalog.parts_for_vehicle --param vehicle=honda-civic-2019
```

The kit carries definitions only: no values, Lines or automation.

## Upgrading

2.0.0 carries 1.1.0's definitions in the formats Cruxible 0.5 reads
(ClaimType `cruxible-claim-type-v11`, SubjectKind `cruxible-subject-kind-v2`,
QueryDefinition `cruxible-query-definition-v3`); 1.1.0 and earlier do not
install on 0.5. The fields, kinds, cardinality and evidence rules are the same,
except where 0.5 has no way to say the old thing: a rule that admitted a file
catalogued under one name (`quotes`, `catalog`, `fitment`, `decisions`) now
admits any catalogued workspace file; the text fields 1.1.0 left unbounded
(`title`, `make`, `model` and each kind's `name`) hold at most 256 characters;
and `catalog.parts_for_vehicle` returns one row per matching part's path to the
vehicle, which is one row per part. In the kits repository the release
rebuilds from `kits/car-parts/source/definitions.py` with
`python scripts/build_kit.py kits/car-parts SCRATCH`.

1.1.0 adds `catalog.part.weight_grams` and rewords the description of
`catalog.part.title`. An instance that edited `catalog.part.title` keeps its
version with `--keep ClaimType:catalog.part.title`.
