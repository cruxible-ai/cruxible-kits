"""Gate support: run the kit's dependency-plane provider in-process on recorded bytes.

The gate answers core's provider calls with the REAL security-osv-provider code
(``sbom.components``, ``osv.query``, ``osv.match``): core passes the run context
(Capture inputs as wire, b1), this builds the provider's own
``ProviderRunContext``, calls the operation and hands back the result with its
``incomplete_captures`` (R-ON2). ``osv.query`` talks to an ``httpx``
transport the test supplies (recorded OSV exchanges), so no test opens a
socket.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROVIDER = HERE.parent / "providers" / "security-osv-provider"
RECORDINGS = PROVIDER / "tests" / "recordings"
if str(PROVIDER / "src") not in sys.path:
    sys.path.insert(0, str(PROVIDER / "src"))

OPERATIONS = frozenset({"sbom.components", "osv.query", "osv.match"})


def provider_context(context: Any) -> Any:
    from cruxible_provider_runtime.egress import EgressRecorder
    from cruxible_provider_runtime.protocol import Budgets
    from cruxible_provider_runtime.provider_api import ProviderRunContext

    return ProviderRunContext(
        run_id=context.run_id,
        input=dict(context.input),
        operation=context.operation,
        operation_signature_digest=context.operation_signature_digest,
        build_digest=context.build_digest,
        implementation_digest=context.implementation_digest,
        declared_endpoints=tuple(context.declared_endpoints),
        budgets=Budgets(wall_clock_seconds=30, output_bytes=64_000_000),
        coordinates={},
        capture_contract=None,
        secrets={},
        egress=EgressRecorder(),
    )


def run_operation(
    context: Any,
    *,
    osv_transport: Callable[[], Any] | None = None,
    now: Any = None,
) -> Any:
    """The provider's ProviderResult for one core run context.

    ``now`` is the run's daemon clock: osv.query stamps its members with it, so a
    later run's reads (at its own clock) see this run's evidence as current.
    """

    from security_osv_provider.osv import OsvMatch, OsvQuery
    from security_osv_provider.sbom import SbomComponents

    if context.operation == "sbom.components":
        provider: Any = SbomComponents()
    elif context.operation == "osv.match":
        provider = OsvMatch()
    elif context.operation == "osv.query":
        if osv_transport is None:
            raise AssertionError("osv.query ran but the scenario gave no OSV origin")
        provider = OsvQuery(
            transport_factory=osv_transport, clock=None if now is None else (lambda: now)
        )
    else:
        raise AssertionError(f"not a dependency-plane operation: {context.operation}")
    return provider(provider_context(context))


class RecordedOsv:
    """An OSV origin answering from the provider's recordings (method + URL + body).

    ``overrides`` answer a URL with (status, bytes) or a ``callable(request) ->
    (status, bytes)``; ``drop`` URLs raise a transport error (no response).
    """

    def __init__(
        self,
        overrides: Mapping[str, Any] | None = None,
        *,
        drop: tuple[str, ...] = (),
    ) -> None:
        index = json.loads((RECORDINGS / "index.json").read_text())["exchanges"]
        self.answers: dict[tuple[str, str, str], tuple[int, bytes]] = {}
        for item in index:
            body = "" if item["request"] is None else json.dumps(item["request"], sort_keys=True)
            self.answers[(item["method"], item["url"], body)] = (
                item["status"],
                (RECORDINGS / item["body"]).read_bytes(),
            )
        self.overrides = dict(overrides or {})
        self.drop = drop
        self.requests: list[str] = []

    def transport(self) -> Any:
        import httpx

        def handle(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            self.requests.append(f"{request.method} {url}")
            if url in self.drop:
                raise httpx.ConnectError("dropped", request=request)
            override = self.overrides.get(url)
            if override is not None:
                status, content = override(request) if callable(override) else override
                return httpx.Response(
                    status, headers={"content-type": "application/json"}, content=content
                )
            body = request.content.decode() if request.content else ""
            if body:
                body = json.dumps(json.loads(body), sort_keys=True)
            status, content = self.answers[(request.method, url, body)]
            return httpx.Response(
                status, headers={"content-type": "application/json"}, content=content
            )

        return httpx.MockTransport(handle)


def provider_build(instance: Any, *, sha: str = "d1") -> Any:
    """A build of security-osv-provider as an install lowers it, pinned to the
    accepted Contracts (the same lowering the web build gets in the gate)."""

    from cruxible_client.contracts.providers import (
        ProviderLocalDistributionPin,
        ProviderLocalEnvBackendPin,
    )
    from cruxible_core.providers.package_metadata import read_package_registration
    from cruxible_core.service.procedures.provider_installation import tree_contract_digests

    root = PROVIDER / "src" / "security_osv_provider"
    digests = tree_contract_digests(instance.tree_at(instance.accepted_coordinate().git_oid))
    registration = read_package_registration(root)
    return registration.provider_definition(
        distribution=ProviderLocalDistributionPin(
            name=registration.manifest.distribution.name,
            version=registration.manifest.distribution.version,
            filename=f"security_osv_provider-{sha}-py3-none-any.whl",
            sha256="sha256:" + sha * 32,
        ),
        local_env=ProviderLocalEnvBackendPin(
            lock_sha256="sha256:" + "b" * 64,
            materialization_digests={"linux-cp311": "sha256:" + "c" * 64},
        ),
        control_domain="security-osv-provider",
        operations=registration.pinned_operations(digests),
    )
