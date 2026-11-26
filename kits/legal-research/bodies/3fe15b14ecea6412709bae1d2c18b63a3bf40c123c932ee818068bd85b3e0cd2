# Legal research review guidance

Guides: `legal.holding.rule`, `legal.holding.weight`, `legal.holding.status`, `legal.argument.status`.

## Prose stays in memos and briefs

Full legal analysis, factual comparisons, and brief text belong in workspace Markdown memos and drafts. Cruxible holds the verifiable structure that links them: courts, cases, holdings, statutes, client matters, arguments, and the treatment status each argument depends on.

## Synthesizing a holding (`legal.holding.rule`, `legal.holding.weight`, `legal.holding.status`)

- Keep `rule` to one concise sentence (at most 200 characters) and cite the supporting memo section or opinion passage (`FileEvidence`) alongside `pin_cite`.
- Classify `weight` accurately (`holding`, `dicta`, `concurrence`, `dissent`). Never treat dicta, a concurrence, or a dissent as a binding holding.
- Pin (`based_on`) `legal.holding.status` to `legal.case.status` so a later negative treatment on the opinion flags every holding drawn from it.

## Citator freshness (`legal.case.status`)

- `legal.case.status` expires 30 days after its last citator check (`stale_after: P30D`). Before filing, clear any stale case-status rows surfaced by `cruxible next`.

## Verifying an argument (`legal.argument.status`)

- Link supporting authorities in `relies_on` and adverse authorities distinguished in the brief in `distinguishes` (both accept `legal.holding` and `legal.statute`).
- Before setting `status` to `verified` or `filed`, pin (`based_on`) every relied-on and distinguished holding's `status` and statute's `status`. If any authority changes treatment or is amended/enjoined, `cruxible next` flags the argument for re-verification.
- This kit records research state, not legal advice.
