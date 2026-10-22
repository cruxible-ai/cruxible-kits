# PHP2Shell: where we stand

The incident status page: one row per CVE, exposed asset and credential of its
service, rendered from `security.incident_status` (parameter `incident`). An empty
cell is unknown (nothing recorded), never none; the respond Line
(`security.respond.php2shell`) posts the derived answers. Catalog this page and stamp
the block:

    cruxible files add php2shell-status incidents/php2shell-status.md
    cruxible block repin php2shell-status status \
      --query QueryDefinition:security.incident_status \
      --params '{"incident": "PHP2Shell"}' --render

`cruxible next` lists `projection_backing_stale` when the state behind it moves;
`cruxible block sync --all` re-renders it. Write notes outside the block: a
projection block is never evidence.

## Exposure, patch, audit and rotation

<!-- cruxible:block:status -->
<!-- /cruxible:block:status -->

## Notes

Decisions and their reasons live in `incidents/php2shell.md` (the Audit and Closure
sections the auditor's and lead's writes cite).
