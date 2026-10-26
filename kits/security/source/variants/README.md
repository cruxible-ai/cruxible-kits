# Gate-only upgrade variant

`1.3.1-gate/` is not a published release: it is security 1.3.1, built only for
the release gate. The gate installs the 1.3.0 release bundle first, then
upgrades to this variant with one `kit add`. (Its version is numeric because
core accepts only MAJOR.MINOR.PATCH kit versions, and it sorts above the
release so the gate exercises an upgrade.)

`analysis-1.3.1.patch` is applied to a scratch copy of the 1.3.0 analysis Provider
source by `build_release.py`. It versions that copy as 1.3.1 and changes real
KEV output: each proposed Claim's rationale explicitly names its predicate
(`Field: security.vulnerability.kev_listed.`). Registration is regenerated,
the preserved dependency lock is checked, and the wheel is rebuilt. The gate
compares the old/new wheel's KEV source and verifies the new rationale on an
accepted Claim after re-granting settlement. The release Provider source and
1.3.0 wheel are unchanged.

The variant also changes the slotted `security.fetch-observed` budget from 60 to
90 seconds and `security.kev-triage` from 120 to 150 seconds, adds `kev_cwes`
vocabulary, and changes the exposure query limit for the kept-local-edit check.
