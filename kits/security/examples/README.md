# Examples

The kit's automation template is not here: it is [../automation.json](../automation.json),
the one change set you tailor and submit as your own (the kit's
[README](../README.md#install-and-first-answers), steps 2 to 5). This directory holds:

- `sboms/`: CycloneDX SBOMs to import (`log4j-demo-app.cdx.json`, the dependency
  loop's demo application; `cruxible-env.cdx.json` and the `env_sbom.py` that
  writes one for a Python environment);
- `incident-status.md`: an example status page with a projection block the
  incident's status query renders.

For an observation window anchored on a landing, author a window-close Trigger
by contract name too (choose the Line/action and duration for your workflow). From
the Python SDK (`cruxible-client`, which `cruxible` installs):

```python
from cruxible_client import Cruxible
from cruxible_client.contracts.authoring.models import (
    CaptureEventByNameWindow,
    WindowCloseAuthoringSchedule,
)

cx = Cruxible.connect()
draft = cx.changes(rationale="Re-ask KEV triage a day after each KEV catalog lands.")
draft.trigger(
    name="consumer.kev-window-close", line="security.kev-triage",
    schedule=WindowCloseAuthoringSchedule(window=CaptureEventByNameWindow(
        capture_contract="security.fetched-v1", logical_sources=("cisa.kev.catalog",),
        duration_seconds=86400)))
intent = draft.submit()
intent.outcome.status   # 'landed'
```

Prepare resolves the current CaptureContract; retained Triggers and windows
retain their source filters; execution records resolved exact digests.
