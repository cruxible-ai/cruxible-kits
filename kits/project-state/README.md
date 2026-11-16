# Project state kit

## What it is

The vocabulary a software project keeps its working state in: roadmap items
and recommendations, batches of work and the tracks they belong to, review
cards, decisions, laws and product feedback. It carries definitions only: no
values, Lines or automation, and, as in 1.0.0, no SubjectKinds. Cruxible 0.5
creates a Subject only of a declared kind (`cruxible.subject.kind_undeclared`),
so before the first write of a kind, author its SubjectKind: keyed by a key
ClaimType of your own, or `minted: true` (`cruxible authoring example
subject-kind` prints one).

## What it answers

| Question | Where the answer comes from |
|---|---|
| Which roadmap items exist? | `project.roadmap-membership` (watch it so new work cannot drop out of a view) |
| Where does an item stand? | `dev.roadmap_item.adoption_state`, `implementation_state`, `proposed_release` |
| What blocks a batch, and where did it land? | `dev.batch.blocked_by`, `state`, `landed_at`, `tip`, `verdict` |
| What was decided, and in which batch? | `dev.decision.ruling`, `standing`, `decided_in` |

## How it models your world

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
words. Batch, track, card, decision and law fields must cite a passage of a
catalogued workspace file (an agent report, a dispatch contract, a friction log,
the program register). Feedback findings take either. Text fields hold at most
256 characters: for a ruling, a law or program prose, the Claim states it in
short and cites the passage that holds the full text.

## Install

```sh
cruxible kit add project-state:1.1.0                  # preview
cruxible kit add project-state:1.1.0 --commit --at OID
```

## Upgrading

1.1.0 carries 1.0.0's definitions in the formats Cruxible 0.5 reads (ClaimType
`cruxible-claim-type-v11`, QueryDefinition `cruxible-query-definition-v3`);
1.0.0 does not install on 0.5. The fields, kinds, cardinality, roles and
evidence rules are the same, except where 0.5 has no way to say the old thing:

- each 1.0.0 rule named one workspace file's own source contract
  (`agent-reports`, `dispatch-contracts`, `friction-log`, `program-register`,
  `feedback-*`, `program-*`); 1.1.0 has one `file` rule per field admitting any
  catalogued workspace file, and no longer ships those twenty source contracts;
- `dev.decision.ruling`, `dev.law.text` and `dev.program.prose` held exact
  file content, which 0.5 retires (prose lives in Documents); they are strings
  of at most 256 characters that still cite the file passage;
- every other text field 1.0.0 left unbounded holds at most 256 characters.

In the kits repository the release rebuilds from
`kits/project-state/source/definitions.py` with
`python scripts/build_kit.py kits/project-state SCRATCH`.
