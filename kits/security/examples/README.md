# Consumer automation example

`automation.json` is an inert authoring ChangeSet. Installing the kit does not
submit it. Copy it into your workspace and let your agent adapt the four
Blueprint instance names and Provider bindings, eight Line names and inputs,
Trigger targets and UTC cron times, and five Mandate namespaces. Update all
references when renaming. Replace `NOW` and `EXPIRES` with UTC timestamps
(e.g. now and 90 days later). Landing Triggers use CaptureContract names only.

Submit with `cruxible authoring submit automation.json`, inspect the resulting
proposal, obtain the consumer's required approvals and activate it through the
ordinary proposal flow. Enable each Line explicitly with `cruxible line enable
NAME`. Start with these propose grants; review the resulting SBOM, KEV, EPSS and
applicability proposals.

For KEV/EPSS graduation, review the field scopes and keyed-vulnerability
condition in the main README's **Measure and graduate** section and
`gate/recipe.py`'s `graduate()`. Submit that separate ChangeSet through the same
approval flow and re-enable the two changed Lines. Applicability stays propose-only.
After an upgrade, D8 carries affected Lines disabled and Mandates propose-only;
repeat enable and the explicit settle re-grant. The gate loads this file for
both Blueprint instantiation and automation, changing only fixture Provider
bindings and validity timestamps.

For an observation window anchored on a landing, author a window-close Trigger
by contract name too (choose the Line/action and duration for your workflow):

```json
{"kind": "trigger", "name": "consumer.kev-window-close",
 "line_name": "security.kev-triage",
 "schedule": {"kind": "window_close", "window": {"kind": "capture_event",
   "capture_contract": "security.kev-http-v1", "duration_seconds": 86400}}}
```

Prepare resolves the current CaptureContract; retained Triggers and windows
still pin exact digests.
