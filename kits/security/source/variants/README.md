# Gate-only upgrade variant

`1.1.0/` is not a published release. The gate installs the current-core 1.0.2
bundle first, then upgrades to this variant with one `kit add`.

`analysis-1.1.0.patch` is applied to a scratch copy of the 1.0.2 analysis Provider
source by `build_release.py`. It versions that copy as 1.1.0 and changes real
KEV output: each proposed Claim's rationale explicitly names its predicate
(`Field: security.vulnerability.kev_listed.`). Registration is regenerated,
the preserved dependency lock is checked, and the wheel is rebuilt. The gate
compares the old/new wheel's KEV source and verifies the new rationale on an
accepted Claim after re-granting settlement. The release Provider source and
1.0.2 wheel are unchanged.

The variant also changes the KEV acquisition Blueprint budget, adds `kev_cwes`
vocabulary, and changes the exposure query budget for the kept-local-edit check.
The obsolete historical 1.0.1 fixture was removed; no other consumer used it.
