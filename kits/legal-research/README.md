# Legal research kit

## What it is

A starter vocabulary for case-law and statutory research: clients, matters,
courts, cases, holdings, statutes, and brief arguments. Facts about an opinion
or statute (citation, court, date, later treatment) are observations; a
holding's rule, weight (`holding`, `dicta`, `concurrence`, `dissent`), and
treatment verdict, along with an argument's readiness, are governed judgments.
Prose stays in memos and briefs: Claims hold the verifiable structure and cite
the exact passage they rest on.

A holding is synthesized once and reused across every brief that relies on or
distinguishes it. Case treatment (`legal.case.status`) expires after 30 days so
citator checks never go silently stale before filing, and every argument pins
the authorities it relies on or distinguishes.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which arguments rely on weakened law? | `legal.affected_arguments` (relied-on holding worse than `good_law`) |
| Which draft arguments in active matters still need verification? | `legal.arguments_to_verify` |
| What did a case hold? | `legal.holdings_by_case` (parameter `case`, such as `smith-v-acme`) |
| Where do a matter's arguments stand? | `legal.arguments_by_matter` (parameter `matter`) |
| Which matters are open for a client? | `legal.matters_by_client` (parameter `client`) |
| Which judgments rest on a changed authority? | `cruxible next` lists each as `claim_dependency_stale` |

## How it models your world

| Kind | Named by | Fields |
|---|---|---|
| `legal.client` | its slug (`acme-corp`) | `title`, `entity_type`, `status`, `conflict_status` |
| `legal.matter` | its slug (`acme-v-globex`) | `client`, `title`, `forum`, `stage` |
| `legal.court` | its slug (`9th-cir`) | `title`, `jurisdiction`, `level` |
| `legal.case` | its slug (`smith-v-acme`) | `caption`, `citation`, `court`, `decided_on`, `status` (stale after 30 days) |
| `legal.holding` | its case and issue (`smith-v-acme--duty-of-care`) | `rule`, `pin_cite`, `weight`, `status` |
| `legal.statute` | its slug (`15-usc-78j-b`) | `title`, `citation`, `jurisdiction`, `status` |
| `legal.argument` | its matter and section (`acme-v-globex--motion-section-3b`) | `title`, `relies_on`, `distinguishes`, `status` |

A case's `status` and a holding's `status` share one ordered treatment scale:
`good_law`, `distinguished`, `criticized`, `limited`, `overruled`. `level`
(`trial` to `supreme`), `stage` (`intake` to `closed`), and `legal.statute.status`
(`in_force` to `repealed`) are ordered too. The kit also installs one governed
review guidance Document (`document:legal.guidance.review-guidance`) attached
to `holding.rule`, `holding.weight`, `holding.status`, and `argument.status`.

## Recording a judgment

An argument marked verified, pinned to the supporting holding it relies on:

```python
from cruxible_client import Cruxible, FileEvidence

with Cruxible.connect() as cx:
    w = cx.world()  # closed types from .cruxible/world.pyi
    w.legal.argument["acme-v-globex--motion-section-3b"].set(
        status="verified",
        because="Duty-of-care holding checked against the slip opinion.",
        evidence=FileEvidence(file="memos/smith-v-acme.md#slip op. at 14"),
        based_on=["legal.holding/smith-v-acme--duty-of-care#status"],
    )
```

## Install

```sh
cruxible kit add legal-research
```

The kit carries definitions and review guidance only: no values, Providers,
Procedures, or Lines. It records research state, not legal advice. In the kits
repository the release rebuilds from `kits/legal-research/source/definitions.py`
with `python scripts/build_kit.py kits/legal-research SCRATCH`.
