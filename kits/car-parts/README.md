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
file catalogued as `quotes`, and its evidence goes stale after two minutes, so
the guides' freshness examples show quickly. For real use, change it with an
edit (`stale_after: P30D`, say).

## Install and first answers

```sh
cruxible kit add car-parts:1.0.0                  # preview
cruxible kit add car-parts:1.0.0 --commit --at OID
cruxible set catalog.vehicle/honda-civic-2019 make Honda --because "Acme catalog 2026."
cruxible set catalog.part/bp-1142 title "Front brake pads" --because "Acme catalog 2026."
cruxible add catalog.part/bp-1142 fits catalog.vehicle/honda-civic-2019 --because "Acme catalog 2026."
cruxible query --name catalog.parts_for_vehicle --param vehicle=honda-civic-2019
```

The kit carries definitions only: no values, Lines or automation.

## Upgrading

1.1.0 adds `catalog.part.weight_grams` and rewords the description of
`catalog.part.title`. An instance that edited `catalog.part.title` keeps its
version with `--keep ClaimType:catalog.part.title`.
