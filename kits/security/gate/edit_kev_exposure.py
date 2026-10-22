"""A consumer's local edit: raise security.kev_exposure's default max_results.

    python edit_kev_exposure.py MAX_RESULTS

Authored through the SDK as a successor of the live QueryDefinition; the submit
lands it when policy allows. The gate uses it to give the 1.3.1 upgrade an edit to overwrite.
"""

from __future__ import annotations

import sys

from cruxible_client import Cruxible
from cruxible_client.contracts.artifacts import ArtifactLifecycle
from cruxible_client.contracts.authoring.inputs import QueryDefinitionInput
from cruxible_client.contracts.get_reads import GetRequest
from cruxible_client.contracts.query.definitions import QueryDefinitionSpec

NAME = "security.kev_exposure"


def main() -> None:
    max_results = int(sys.argv[1])
    with Cruxible.connect() as cx:
        proof = cx._client.get(
            cx._instance_id, request=GetRequest(ref=f"QueryDefinition:{NAME}", detail="proof")
        ).proof
        assert proof is not None
        spec = QueryDefinitionSpec.model_validate(proof["envelope"])
        spec = spec.model_copy(
            update={
                "default_budgets": spec.default_budgets.model_copy(
                    update={"max_results": max_results}
                ),
                "lifecycle": ArtifactLifecycle(predecessor_digest=proof["artifact_digest"]),
            }
        )
        world = cx.world()
        draft = cx.changes(rationale=f"Show up to {max_results} KEV exposures by default.")
        draft.query_definition(
            QueryDefinitionInput(kind="query_definition", query_definition=spec),
            vocabulary=tuple(world.claim_type(p) for p in sorted(spec.referenced_predicates)),
        )
        intent = draft.prepare()
        if intent.refused:
            raise SystemExit(f"refused: {intent.diagnostics}")
        status = intent.submit().status()  # lands in this call when policy allows
        assert status.proposal_id is not None, status
        if status.state == "ready_to_activate":
            cx.activate(status.proposal_id)
        print(status.proposal_id)


if __name__ == "__main__":
    main()
