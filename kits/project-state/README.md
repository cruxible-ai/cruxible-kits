# Project state kit

## What it is

The vocabulary a software project keeps its working state in: roadmap items
and recommendations, batches of work and the tracks they belong to, review
cards, decisions, laws and product feedback. It carries definitions only: no
values, Lines or automation. Each kind is named by its slug
(`dev.roadmap_item/port-kits`), its `slug` field.

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which roadmap items exist? | `project.roadmap-membership` (watch it so new work cannot drop out of a view) |
| Where does an item stand? | `dev.roadmap_item.adoption_state`, `implementation_state`, `proposed_release` |
| What blocks a batch, and where did it land? | `dev.batch.blocked_by`, `state`, `landed_at`, `tip`, `verdict` |
| What was decided, and in which batch? | `dev.decision.ruling`, `standing`, `decided_in` |

## How it models your world

Every kind below also has `slug`, its key.

| Kind | Fields |
|---|---|
| `dev.roadmap_item` | `task_title`, `adoption_state`, `implementation_state`, `proposed_release`, `completion_criterion`, `justification`, `original_recommendation`, `strategic_bucket`, `audit_baseline`, `historical_audit_class`, `reconciliation_note`, `refines` (items) |
| `dev.recommendation` | `rule`, `rationale` |
| `dev.batch` | `state`, `verdict`, `tip`, `landed_at`, `blocked_by` (batches), `belongs_to_track` |
| `dev.track` | `status`, `dev.program.prose` |
| `dev.card` | `disposition`, `lane`, `closed_by` (a batch) |
| `dev.decision` | `ruling`, `standing`, `decided_in` (a batch) |
| `dev.law` | `text`, `origin` (a batch or card) |
| `dev.product_feedback` | `finding_text`, `follow_up` (roadmap items) |

Roadmap items, recommendations and feedback follow-ups are written in your own
words. Batch, track, card, decision and law fields are meant to cite a passage
of a catalogued workspace file (an agent report, a dispatch contract, a friction
log, the program register); the core admits a workspace citation or your own
words on any field that does not require captured evidence, so cite where you
can. Feedback findings take either. Text fields hold at most 256 characters.

A ruling (`dev.decision.ruling`), a law's text (`dev.law.text`) and program
prose (`dev.program.prose`) are short summaries; the prose itself lives in a
Document section the Claim cites. A citation takes a registered file name or a
path:

```sh
cruxible set dev.decision/kit-versions ruling "Kits that changed meaning for 0.5 ship as 2.0.0." \
  --because "The maintainer's ruling." \
  --evidence-file "docs/decisions.md#Kits whose meaning changed for 0.5 ship as 2.0.0"
```

On a core with `cruxible link`, `--section "docs/decisions.md#Kit versions"`
cites the whole section the same way.

## Install

```sh
cruxible kit add project-state:2.0.0                  # preview
cruxible kit add project-state:2.0.0 --commit --at OID
```

## Upgrading

2.0.0 carries 1.0.0's definitions in the formats Cruxible 0.5 reads (ClaimType
`cruxible-claim-type-v11`, SubjectKind `cruxible-subject-kind-v2`,
QueryDefinition `cruxible-query-definition-v3`); 1.0.0 does not install on 0.5.
The fields, cardinality and roles are the same, except where 0.5
has no way to say the old thing:

- 1.0.0 declared no SubjectKinds, and 0.5 creates a Subject only of a declared
  kind; 2.0.0 declares each kind, keyed by a new `slug` field;

- each 1.0.0 rule named one workspace file's own source contract
  (`agent-reports`, `dispatch-contracts`, `friction-log`, `program-register`,
  `feedback-*`, `program-*`); 2.0.0 states no rule on those fields, so the
  core's default admits any catalogued workspace file or section, and own words
  too (a kit can no longer author a file-only rule), and no longer ships those
  twenty source contracts;
- `dev.decision.ruling`, `dev.law.text` and `dev.program.prose` held exact
  file content, which 0.5 retires (prose lives in Documents); they are short
  summaries of at most 256 characters citing the Document section;
- every other text field 1.0.0 left unbounded holds at most 256 characters.

In the kits repository the release rebuilds from
`kits/project-state/source/definitions.py` with
`python scripts/build_kit.py kits/project-state SCRATCH`.
