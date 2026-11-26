# Legal research kit

## What it is

A starter vocabulary for case law research: courts, cases, the holdings drawn
from them, client matters and the arguments made in them. Facts about an
opinion (its citation, court, date and later treatment) are observations;
a holding's rule and status and an argument's readiness are governed
judgments. Prose stays in memos and briefs: Claims hold the short rule, the
pin cite and the status, and cite the passage they rest on.

A holding is synthesized once and reused across every brief that relies on
it. Each argument pins the holdings it relies on, so when an opinion is
distinguished or overruled, exactly the arguments built on it are flagged for
re-verification.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which arguments rely on weakened law? | `legal.affected_arguments` (any relied-on holding worse than `good_law`) |
| What did a case hold? | `legal.holdings_by_case` (parameter `case`, such as `smith-v-acme`) |
| Where do a matter's arguments stand? | `legal.arguments_by_matter` (parameter `matter`) |
| Which judgments rest on a changed holding? | `cruxible next` lists each as `claim_dependency_stale` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `legal.court` | its slug (`9th-cir`) | `title`, `jurisdiction`, `level` |
| `legal.case` | its slug (`smith-v-acme`) | `caption`, `citation`, `court`, `decided_on`, `status` |
| `legal.holding` | its case and issue (`smith-v-acme--duty-of-care`) | `rule`, `pin_cite`, `status` |
| `legal.matter` | its slug | `title`, `forum` (a court), `stage` |
| `legal.argument` | its slug (`motion-section-3b`) | `matter`, `title`, `relies_on` (holdings), `status` (`draft`, `verified`, `filed`, `withdrawn`) |

A case's `status` and a holding's `status` share one ordered treatment scale:
`good_law`, `distinguished`, `criticized`, `limited`, `overruled`. The case's
is what later courts did (cite the opinion or citator report); the holding's
is the researcher's verdict on it. `level` (`trial`, `intermediate_appellate`,
`supreme`) and `stage` (`intake` to `closed`) are ordered too. A holding's
`rule` holds one sentence of at most 200 characters; the full analysis lives
in the memo section the Claim cites.

## Recording a judgment

An argument marked verified, pinned to the holding it relies on:

```python
from cruxible_client import Cruxible, FileEvidence

with Cruxible.connect() as cx:
    w = cx.world()  # closed types from .cruxible/world.pyi
    w.legal.argument["motion-section-3b"].set(
        status="verified",
        because="Duty-of-care holding checked against the slip opinion.",
        evidence=FileEvidence(file="memos/smith-v-acme.md#slip op. at 14"),
        based_on=["legal.holding/smith-v-acme--duty-of-care#status"],
    )
```

## Install

```sh
cruxible kit add /path/to/cruxible-kits/kits/legal-research                  # preview; prints the coordinate
cruxible kit add /path/to/cruxible-kits/kits/legal-research --commit --at OID
```

`cruxible kit add legal-research:1.0.0` installs the same release from the
registry once it is published. The kit carries definitions only: no values,
Providers, Procedures or Lines. It records research state, not legal advice.
In the kits repository the release rebuilds from
`kits/legal-research/source/definitions.py` with
`python scripts/build_kit.py kits/legal-research SCRATCH`.
