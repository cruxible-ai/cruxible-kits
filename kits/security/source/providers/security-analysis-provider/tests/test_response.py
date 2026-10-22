"""Incident response: runtime inventory, log reads, credential state and the five questions.

Fixtures (``data/incident``) are PHP2Shell at Acme in recorded shapes: the two CVE
records (CVE JSON 5.1), NVD API 2.0 answers (one with ``"configurations": null``),
kit-format inventories of the prod and ops scopes, a Syft-style CycloneDX SBOM of one
workload, the agent's log reads and credential-state reads (key ids and fp:
fingerprints only; two bodies that must be refused as secret-shaped).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cruxible_provider_runtime.egress import EgressRecorder
from cruxible_provider_runtime.protocol import Budgets
from cruxible_provider_runtime.provider_api import ProviderRunContext

from security_analysis_provider.applicability import CveApplicability
from security_analysis_provider.common import parse_rows
from security_analysis_provider.response import (
    CredentialState,
    Respond,
    RuntimeInventory,
    credential_state,
    inventory,
    log_reads,
    parse_purl,
    read_inventory,
    respond,
    revision,
    secret_shaped,
    uncovered,
)

DATA = Path(__file__).parent / "data" / "incident"
WINDOW = ("2026-09-01T00:00:00Z", "2026-10-17T00:00:00Z")


def _text(name: str) -> str:
    return (DATA / name).read_text()


def _inventory(text: str, held: list[dict[str, Any]] | None = None,
               patches: list[dict[str, Any]] | None = None, scope: str = "prod"
               ) -> dict[str, Any]:
    return inventory(text, parse_rows(held or []), parse_rows(patches or []), scope)


def _context(provider: Any, payload: dict[str, Any]) -> Any:
    return provider(ProviderRunContext(
        run_id="test", input=payload, interface_id=provider.interface_id,
        interface_digest="sha256:" + "0" * 64, implementation_digest="sha256:" + "1" * 64,
        declared_endpoints=(), input_bucket="test",
        budgets=Budgets(wall_clock_seconds=30, output_bytes=10_000_000), coordinates={},
        capture_contract=None, secrets={}, egress=EgressRecorder()))


def _bound(kind: str, subject_id: str) -> dict[str, str]:
    return {"subject_kind": kind, "subject_id": subject_id,
            "subject_path": f"subjects/{kind}/{subject_id}.json",
            "subject_identity": f"{kind}/{subject_id}"}


def _row(bindings: dict[str, tuple[str, str]], *, claims: dict[tuple[str, str], str] | None = None,
         includes: dict[str, list[tuple[Any, str]]] | None = None,
         **fields: Any) -> dict[str, Any]:
    """A state-tap row. ``includes``: name -> [(literal value or ``kind/id`` object, claim)]."""

    def item(value: Any, claim: str) -> dict[str, Any]:
        visibility = {"claim_path": f"claims/00/{claim}.json"}
        if isinstance(value, tuple):
            return {"claim_object": {"kind": "subject", "address": {
                "artifact_path": f"subjects/{value[0]}/{value[1]}.json"}},
                "visibility": visibility}
        return {"claim_object": {"kind": "literal", "value": value}, "visibility": visibility}

    return {
        "bindings": [{"binding": name, **_bound(*spec)} for name, spec in bindings.items()],
        "fields": [{"name": k, "state": "absent" if v is None else
                    "conflict" if v == "<conflict>" else "present",
                    "value": None if v == "<conflict>" else v} for k, v in fields.items()],
        "read_claims": [{"claim_path": f"claims/00/{claim}.json", "predicate": predicate,
                         "subject_identity": "/".join(bindings[binding])}
                        for (binding, predicate), claim in (claims or {}).items()],
        "includes": [{"name": name, "items": [item(v, c) for v, c in values]}
                     for name, values in (includes or {}).items()],
    }


def _statements(items: list[dict[str, Any]]) -> list[tuple[Any, str, Any]]:
    found = []
    for item in items:
        statement = item.get("statement")
        if statement is None:
            if "retires" in item:
                found.append(("retire", item["retires"], item["reason"]))
            continue
        subject = statement["subject"]
        who = (json.dumps(subject["key"], sort_keys=True) if "key" in subject
               else subject["artifact_path"])
        obj = statement["object"]
        value = obj.get("value", obj.get("subject", (obj.get("address") or {}).get(
            "artifact_path")))
        found.append((who, statement["predicate"].rsplit(".", 1)[-1], value))
    return sorted(found, key=json.dumps)


COVERAGE = ("security.coverage", "prod--inventory.runtime")


def _held_prod(revision_value: str | None = None, *, assets: dict[str, list[tuple[str, str]]]
               ) -> list[dict[str, Any]]:
    """inventory_index rows: the prod coverage, each asset scanned in it and its runs."""

    rows = []
    for index, (host, runs) in enumerate(sorted(assets.items())):
        asset = ("security.asset", f"asset-{index}")
        run_items = [(("security.release", f"{n}--{v}"), f"CLM-run-{index}-{n}-{v}")
                     for n, v in runs]
        for name, version in runs or [(None, None)]:
            bindings = {"coverage": COVERAGE, "asset": asset}
            if name:
                bindings["run"] = ("security.release", f"{name}--{version}")
            rows.append(_row(
                bindings, claims={("coverage", "security.coverage.revision"): "CLM-rev"},
                includes={"runs": run_items,
                          "scanned_in": [(COVERAGE, f"CLM-scanned-{index}")],
                          "looked_for": [("php", "CLM-looked-php"),
                                         ("php8.2", "CLM-looked-php82")]},
                source="prod", revision=revision_value, looked_for=["php", "php8.2"],
                hostname=host,
                run_product=name, run_version=version))
    return rows


# --- runtime inventory -------------------------------------------------------------


def test_purls_name_the_release_and_drop_qualifiers() -> None:
    run = parse_purl("pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12")
    assert run is not None and (run.name, run.version) == ("libc6", "2.36-9+deb12u7")
    assert run.purl == "pkg:deb/debian/libc6@2.36-9+deb12u7"
    assert parse_purl("pkg:generic/php") is None and parse_purl("php@8") is None


def test_a_first_full_scan_states_coverage_assets_and_runs() -> None:
    result = _inventory(_text("prod-before.json"), [], [])
    assert (result["mine"], result["format"], result["coverage"]) == (1, "kit", "full")
    statements = _statements(result["items"])
    runs = sorted(s[2]["key"]["product_name"] + " " + s[2]["key"]["version"]
                  for s in statements if s[1] == "runs")
    assert runs == ["php 8.3.10", "php 8.3.10", "php8.2 8.2.20-1~deb12u1"]
    components = sorted(s[2] for s in statements if s[1] == "component")
    assert components == ["pkg:deb/debian/php8.2@8.2.20-1~deb12u1", "pkg:generic/php@8.3.10"]
    assert [s[2] for s in statements if s[1] == "looked_for"] == ["php", "php8.2"]
    (rev,) = [s[2] for s in statements if s[1] == "revision"]
    assert rev == result["revision"] and rev.startswith("sha256:")
    assert sum(1 for s in statements if s[1] == "scanned_in") == 3
    subjects = [i for i in result["items"] if "subject_kind" in i]
    assert {i["subject_kind"] for i in subjects} == {"security.asset", "security.coverage",
                                                     "security.release"}


def test_an_unchanged_scan_restates_only_the_revision_in_any_order() -> None:
    first = _inventory(_text("prod-before.json"), [], [])
    held = _held_prod(first["revision"], assets={
        "k8s:prod/storefront-a": [("php", "8.3.10")], "k8s:prod/storefront-b": [("php", "8.3.10")],
        "app-1.acme.internal": [("php8.2", "8.2.20-1~deb12u1")]})
    again = _inventory(_text("prod-before-reordered.json"), held, [])
    assert again["revision"] == first["revision"]
    assert (again["changed"], again["restated"], again["proposes"]) == (0, 1, 1)
    (only,) = _statements(again["items"])
    assert only[1] == "revision" and only[2] == first["revision"]


def test_another_scopes_scan_is_not_mine() -> None:
    result = _inventory(_text("ops-before.json"), [], [])
    assert result["mine"] == 0 and result["items"] == []


def _patch_row(patch: str, host: str, *, progress: str | None, verification: str | None = None,
               affected: tuple[str, str] = ("php", "8.3.10")) -> dict[str, Any]:
    claims = {("patch", "security.work.verification"): f"CLM-ver-{patch}"} if verification else {}
    return _row({"coverage": COVERAGE, "asset": ("security.asset", host.replace("/", "-")),
                 "patch": ("security.remediation", patch),
                 "affected": ("security.release", f"{affected[0]}--{affected[1]}")},
                claims=claims, hostname=host, progress=progress, verification=verification,
                affected_product=affected[0], affected_version=affected[1],
                cve_id="CVE-2026-109618")


def test_a_full_scan_retires_old_runs_verifies_patches_and_disputes_a_false_claim() -> None:
    held = _held_prod("sha256:old", assets={
        "k8s:prod/storefront-a": [("php", "8.3.10")], "k8s:prod/storefront-b": [("php", "8.3.10")],
        "app-1.acme.internal": [("php8.2", "8.2.20-1~deb12u1")]})
    patches = [_patch_row("rem-a", "k8s:prod/storefront-a", progress="completed"),
               _patch_row("rem-b", "k8s:prod/storefront-b", progress="completed"),
               _patch_row("rem-app", "app-1.acme.internal", progress="in_progress",
                          affected=("php8.2", "8.2.20-1~deb12u1"))]
    result = _inventory(_text("prod-mid.json"), held, patches)
    statements = _statements(result["items"])
    verifications = {s[0].rsplit("/", 1)[-1].removesuffix(".json"): s[2]
                     for s in statements if s[1] == "verification"}
    # storefront-a and app-1 no longer run it: verified, however far the claim got;
    # storefront-b is claimed completed but still runs it: failed.
    assert verifications == {"rem-a": "verified", "rem-app": "verified", "rem-b": "failed"}
    # A new version of a product revises the run it replaces (one terminal cannot both
    # add to a many-valued slot and retire from it).
    assert not [s for s in statements if s[0] == "retire"]
    revised = {i["revises"]: i["statement"]["object"]["subject"]["key"]["version"]
               for i in result["items"] if i.get("statement", {}).get("predicate") ==
               "security.asset.runs"}
    assert revised == {"CLM-run-1-php-8.3.10": "8.3.36",
                       "CLM-run-0-php8.2-8.2.20-1~deb12u1": "8.2.29-1~deb12u1"}
    assert any(s[1] == "revision" and s[2] == result["revision"] for s in statements)
    assert (result["verified"], result["failed"]) == (2, 1)


def test_a_verified_patch_seen_running_again_is_a_regression_never_revised() -> None:
    held = _held_prod("sha256:old", assets={"k8s:prod/storefront-b": [("php", "8.3.36")]})
    patch = _patch_row("rem-b", "k8s:prod/storefront-b", progress="completed",
                       verification="verified")
    text = json.dumps({"scope": "prod", "looked_for": ["php"], "coverage": "full", "assets": [
        {"hostname": "k8s:prod/storefront-b", "runs": ["pkg:generic/php@8.3.10"]}]})
    result = _inventory(text, held, [patch])
    assert result["regressions"] == [{"patch": "security.remediation/rem-b",
                                      "asset": "k8s:prod/storefront-b", "release": "php 8.3.10"}]
    assert not [s for s in _statements(result["items"]) if s[1] == "verification"]


def test_a_partial_scan_only_adds_and_never_verifies() -> None:
    held = _held_prod("sha256:old", assets={"k8s:prod/storefront-a": [("php", "8.3.10")]})
    patch = _patch_row("rem-a", "k8s:prod/storefront-a", progress="completed")
    result = _inventory(_text("prod-partial.json"), held, [patch])
    statements = _statements(result["items"])
    assert result["coverage"] == "partial" and not [s for s in statements if s[0] == "retire"]
    assert not [s for s in statements if s[1] in ("revision", "verification")]
    assert [s[1] for s in statements if s[1] == "runs"] == ["runs"]  # storefront-b's run


def test_a_cyclonedx_sbom_is_one_assets_complete_run_set() -> None:
    scan = read_inventory(_text("storefront-a.syft.cdx.json"))
    assert (scan.format, scan.scope) == ("cyclonedx", "prod")
    result = _inventory(_text("storefront-a.syft.cdx.json"), [], [])
    statements = _statements(result["items"])
    runs = sorted(s[2]["key"]["product_name"] for s in statements if s[1] == "runs")
    assert runs == ["libc6", "libssl3", "libxml2", "php"]  # the OS entry has no purl
    assert not [s for s in statements if s[1] in ("revision", "looked_for")]
    assert result["coverage"] == "asset" and result["revision"] == ""
    # A re-scan with its own timestamp and serial number: the same run set, nothing proposed.
    held = _held_prod(None, assets={"k8s:prod/storefront-a": [
        ("php", "8.3.10"), ("libc6", "2.36-9+deb12u7"), ("libxml2", "2.9.14+dfsg-1.3~deb12u1"),
        ("libssl3", "3.0.15-1~deb12u1")]})
    again = _inventory(_text("storefront-a.syft.rescan.cdx.json"), held, [])
    assert (again["proposes"], again["items"]) == (0, [])
    # The patched image: php's run is replaced, the patch on that asset verified.
    patch = _patch_row("rem-a", "k8s:prod/storefront-a", progress="completed")
    patched = _inventory(_text("storefront-a.syft.patched.cdx.json"), held, [patch])
    statements = _statements(patched["items"])
    (run,) = [i for i in patched["items"] if i.get("statement", {}).get("predicate") ==
              "security.asset.runs"]
    assert run["revises"] == "CLM-run-0-php-8.3.10"
    assert [s[2] for s in statements if s[1] == "verification"] == ["verified"]
    # A product that is gone with nothing replacing it is retired, once nothing is added.
    gone = json.loads(_text("storefront-a.syft.patched.cdx.json"))
    gone["components"] = [c for c in gone["components"] if c["name"] != "libxml2"]
    statements = _statements(_inventory(json.dumps(gone), held, [patch])["items"])
    assert not [s for s in statements if s[0] == "retire"]  # waits: php is revised now
    held_after = _held_prod(None, assets={"k8s:prod/storefront-a": [
        ("php", "8.3.36"), ("libc6", "2.36-9+deb12u7"), ("libxml2", "2.9.14+dfsg-1.3~deb12u1"),
        ("libssl3", "3.0.15-1~deb12u1")]})
    later = _statements(_inventory(json.dumps(gone), held_after)["items"])
    assert later == [("retire", "CLM-run-0-libxml2-2.9.14+dfsg-1.3~deb12u1", "superseded")]


def test_a_cyclonedx_sbom_without_its_annotations_is_refused() -> None:
    document = json.loads(_text("storefront-a.syft.cdx.json"))
    del document["metadata"]["properties"]
    output = _context(RuntimeInventory(), {"inventory_text": json.dumps(document), "held": [],
                                           "patches": [], "scope": "prod", "truncated": {}})
    assert output.status == "refused" and "cruxible.asset" in output.refusal.message


def test_the_revision_is_the_fleet_not_the_bytes() -> None:
    assert revision(read_inventory(_text("prod-before.json"))) == revision(
        read_inventory(_text("prod-before-reordered.json")))
    assert revision(read_inventory(_text("prod-before.json"))) != revision(
        read_inventory(_text("prod-after.json")))


# --- log reads ---------------------------------------------------------------------


def _audits(*services: str, reads: dict[str, list[str]] | None = None) -> list[dict[str, Any]]:
    return [_row({"incident": ("security.incident", "php2shell"),
                  "audit": ("security.audit", f"php2shell--{name}"),
                  "service": ("security.service", name)},
                 service_ref=name, service_name=name, read=(reads or {}).get(name))
            for name in services]


def test_a_complete_read_of_a_stated_audit_is_one_read_claim() -> None:
    held = _audits("storefront", "partner-portal")
    result = log_reads(_text("log-storefront-nginx.json"), parse_rows(held), "PHP2Shell")
    (statement,) = _statements(result["items"])
    assert statement == ("subjects/security.audit/php2shell--storefront.json", "read",
                         "storefront/nginx-access 2026-09-01T00:00:00Z/2026-10-17T00:00:00Z")
    assert (result["recordable"], result["posted"], result["matches"]) == (1, 0, 1)
    again = log_reads(_text("log-storefront-nginx.json"), parse_rows(_audits(
        "storefront", reads={"storefront": [statement[2]]})), "PHP2Shell")
    assert again["items"] == [] and again["changed"] == 0


def test_an_incomplete_read_or_an_unstated_audit_is_posted_never_recorded() -> None:
    held = parse_rows(_audits("ops-wiki"))
    incomplete = log_reads(_text("log-ops-wiki-nginx-window.json"), held, "PHP2Shell")
    assert incomplete["items"] == [] and incomplete["recordable"] == 0
    (item,) = incomplete["inbox"]
    assert item["kind"] == "read_incomplete" and "retention is 14 days" in item["why"]
    unstated = log_reads(_text("log-partner-portal-apache.json"), held, "PHP2Shell")
    assert [i["kind"] for i in unstated["inbox"]] == ["audit_not_stated"]
    other = log_reads(_text("log-other-incident.json"), held, "PHP2Shell")
    assert other["mine"] == 0


# --- credential state ----------------------------------------------------------------


AWS = ("aws-iam/111122223333", "storefront-app")


def _credential(issuer: str, name: str, *, key_id: str | None = None,
                issued_at: str | None = None, rotation: dict[str, Any] | None = None
                ) -> dict[str, Any]:
    bindings = {"credential": ("security.credential", f"{issuer}--{name}".replace("/", "-"))}
    claims = {("credential", "security.credential.key_id"): "CLM-key",
              ("credential", "security.credential.issued_at"): "CLM-issued"}
    fields: dict[str, Any] = {"issuer": issuer, "name": name, "key_id": key_id,
                              "issued_at": issued_at, "issued_by": None, "revoked_key": None}
    if rotation is not None:
        bindings["rotation"] = ("security.remediation", "rot-1")
        if rotation.get("verification"):
            claims[("rotation", "security.work.verification")] = "CLM-rot-ver"
        fields.update(progress=rotation.get("progress"), verification=rotation.get(
            "verification"), revokes_key=rotation.get("revokes_key"),
            window_start=WINDOW[0])
    return _row(bindings, claims=claims, **fields)


def test_the_first_state_read_states_the_current_key() -> None:
    result = credential_state(_text("cred-aws-initial.json"), [])
    statements = {s[1]: s[2] for s in _statements(result["items"])}
    assert statements == {"key_id": "AKIAQ3EXAMPLEOLDKEY1", "issued_at": "2026-03-02T10:00:00Z",
                          "issued_by": "platform-admin"}


def test_a_receipt_never_verifies_a_state_read_does_and_an_active_old_key_fails() -> None:
    rotation = {"progress": "completed", "revokes_key": "AKIAQ3EXAMPLEOLDKEY1"}
    held = [_credential(*AWS, key_id="AKIAQ3EXAMPLEOLDKEY1", issued_at="2026-03-02T10:00:00Z",
                        rotation=rotation)]
    receipt = credential_state(_text("cred-aws-receipt.json"), parse_rows(held))
    statements = _statements(receipt["items"])
    assert {s[1] for s in statements} == {"key_id", "issued_at", "issued_by"}
    assert receipt["verified"] == 0 and receipt["failed"] == 0
    still = credential_state(_text("cred-aws-state-still-active.json"), parse_rows(held))
    assert [s[2] for s in _statements(still["items"]) if s[1] == "verification"] == ["failed"]
    done = credential_state(_text("cred-aws-state.json"), parse_rows(held))
    statements = _statements(done["items"])
    assert [s[2] for s in statements if s[1] == "verification"] == ["verified"]
    assert [s[2] for s in statements if s[1] == "revoked_key"] == ["AKIAQ3EXAMPLEOLDKEY1"]
    # The failed verification is revised by the later read.
    held_failed = [_credential(*AWS, key_id="AKIAQ3EXAMPLENEWKEY2",
                               issued_at="2026-10-18T09:00:00Z",
                               rotation={**rotation, "verification": "failed"})]
    revised = credential_state(_text("cred-aws-state.json"), parse_rows(held_failed))
    (item,) = [i for i in revised["items"] if i.get("statement", {}).get("predicate", "")
               .endswith("verification")]
    assert item["revises"] == "CLM-rot-ver"


def test_secret_shaped_bodies_propose_nothing_and_echo_nothing() -> None:
    for name in ("cred-aws-leaky.json", "cred-stripe-secret-key-id.json"):
        result = credential_state(_text(name), [])
        assert result["items"] == [] and result["posted"] == 1, name
        (item,) = result["inbox"]
        assert item["kind"] == "secret_shape"
        assert "wJalrXUtnFEMI" not in json.dumps(item) and "sk_live_51" not in json.dumps(item)
    assert not secret_shaped("AKIAQ3EXAMPLEOLDKEY1") and not secret_shaped("fp:3a9c1e0b7d2f4a68")
    assert not secret_shaped("key-71839201") and not secret_shaped(
        "3f9b6b3c-1d7c-4b1e-9a49-2f4d1a2c8e11")
    assert secret_shaped("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") and secret_shaped(
        "ghp_016fK2dX0aZq9pLmNoPqRsTuVwXyZ01234") and secret_shaped("fp:not-hex")
    output = _context(CredentialState(), {"state_text": "not json", "held": [],
                                          "truncated": False})
    assert output.status == "ok" and output.output["posted"] == 1


# --- respond ---------------------------------------------------------------------------

INCIDENT = ("security.incident", "php2shell")
INCIDENT_FIELDS = {"window_start": WINDOW[0], "rotation_policy": "on_found_or_unknown",
                   "incident_status": "open"}
PHP = ("security.release", "php--8.3.10")
DEB = ("security.release", "php8.2--8.2.20-1-deb12u1")


def _exposure(release: tuple[str, str], label: tuple[str, str], *, asset: str | None = None,
              service: str | None = None, current: bool = True, declared: str | None = None,
              status: str = "affected") -> dict[str, Any]:
    bindings = {"incident": INCIDENT, "vulnerability": ("security.vulnerability",
                                                        "cve-2026-109618"),
                "assessment": ("security.assessment", f"{release[1]}--cve"), "release": release}
    fields: dict[str, Any] = {**INCIDENT_FIELDS, "cve_id": "CVE-2026-109618", "status": status,
                              "product_name": label[0], "version": label[1]}
    if asset:
        bindings["asset"] = ("security.asset", asset.replace("/", "-").replace(":", "-"))
        fields.update(hostname=asset, internet_exposed=True,
                      coverage_revision="sha256:x" if current else None, looked_for=["php"])
        if current:
            bindings["coverage"] = COVERAGE
    if service:
        bindings["service"] = ("security.service", service)
        fields["service_name"] = service
    if declared:
        bindings["declared"] = ("security.asset", declared)
        fields.update(declared_hostname=declared, declared_coverage_revision=None)
    return _row(bindings, **fields)


def _patch(patch: str, asset: str, service: str, release: tuple[str, str],
           label: tuple[str, str], **fields: Any) -> dict[str, Any]:
    bindings = {"incident": INCIDENT, "assessment": ("security.assessment", "x"),
                "release": release, "patch": ("security.remediation", patch),
                "asset": ("security.asset", asset.replace("/", "-").replace(":", "-")),
                "service": ("security.service", service), "coverage": COVERAGE}
    return _row(bindings, **{**INCIDENT_FIELDS, "cve_id": "CVE-2026-109618",
                             "product_name": label[0], "version": label[1], "hostname": asset,
                             "internet_exposed": True, "service_name": service,
                             "coverage_revision": "sha256:x", "looked_for": ["php"], **fields})


def _audit(service: str, **fields: Any) -> dict[str, Any]:
    return _row({"incident": INCIDENT, "audit": ("security.audit", f"php2shell--{service}"),
                 "service": ("security.service", service)},
                **{**INCIDENT_FIELDS, "service_ref": service, "service_name": service,
                   **fields})


def _cred(service: str, label: tuple[str, str], *, rotation: dict[str, Any] | None = None,
          **fields: Any) -> dict[str, Any]:
    bindings = {"incident": INCIDENT, "audit": ("security.audit", f"php2shell--{service}"),
                "service": ("security.service", service),
                "credential": ("security.credential", label[1])}
    values: dict[str, Any] = {**INCIDENT_FIELDS, "service_name": service, "issuer": label[0],
                              "name": label[1], **fields}
    if rotation is not None:
        bindings["rotation"] = ("security.remediation", f"rot-{label[1]}")
        bindings["rotation_audit"] = ("security.audit", f"php2shell--{service}")
        values.update(rotation)
    return _row(bindings, **values)


def _ask(**taps: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {name: taps.get(name, []) for name in ("exposure", "patches", "overdue", "audits",
                                                     "credentials")}
    return respond({**payload, "params": {"incident": "PHP2Shell"}, "truncated": {}})


def _by(result: dict[str, Any], question: str) -> dict[str, dict[str, Any]]:
    return {a["subject"]: a for a in result["answers"] if a["question"] == question}


def _posted(result: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [item for item in result["items"] if item["kind"] == kind]


def test_rq1_and_rq2_exposure_found_declared_unknown_and_missing_patches() -> None:
    result = _ask(exposure=[
        _exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-a", service="storefront",
                  declared="wiki-1"),
        _exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-b", service="storefront"),
        _exposure(DEB, ("php8.2", "8.2.20-1~deb12u1"), asset="app-1.acme.internal",
                  service="partner-portal")])
    rq1 = _by(result, "RQ1")
    assert {s: a["state"] for s, a in rq1.items()} == {
        "app-1.acme.internal: php8.2 8.2.20-1~deb12u1": "found",
        "k8s:prod/storefront-a: php 8.3.10": "found",
        "k8s:prod/storefront-b: php 8.3.10": "found",
        "wiki-1: php 8.3.10": "unknown"}
    assert rq1["wiki-1: php 8.3.10"]["pull"] == "security.inventory-acquire"
    assert len(_posted(result, "exposed")) == 3 and len(_posted(result, "patch_missing")) == 3
    gaps = {g["subject"]: g for g in _posted(result, "gap")}
    assert gaps["wiki-1"]["input"] == {"covering": "wiki-1"}
    # Every exposed service is asked RQ3 (no audit yet: a statement answers it).
    assert {s: a["state"] for s, a in _by(result, "RQ3").items()} == {
        "partner-portal": "unknown", "storefront": "unknown"}
    assert result["ready_to_close"] == 0


def test_rq2_patch_states_from_the_scan_never_from_the_claim() -> None:
    sa = ("k8s:prod/storefront-a", "storefront")
    exposures = [_exposure(PHP, ("php", "8.3.10"), asset=sa[0], service=sa[1])]
    claimed = _ask(exposure=exposures, patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"),
                                                       progress="completed")])
    # A claim alone is never a closure: unknown until a scan reads the asset.
    assert _by(claimed, "RQ2")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "unknown"
    assert [g["pull"] for g in _posted(claimed, "gap")
            if g["subject"] == "k8s:prod/storefront-a"] == ["security.inventory-acquire"]
    failed = _ask(exposure=exposures, patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"),
                                                      progress="completed",
                                                      verification="failed")])
    (disputed,) = _posted(failed, "patch_disputed")
    assert disputed["why"] == "verification_failed"
    pending = _ask(exposure=exposures, patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"),
                                                       progress="in_progress")])
    assert _by(pending, "RQ2")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "pending"
    overdue_row = _patch("rem-a", *sa, PHP, ("php", "8.3.10"), progress="in_progress",
                         due_at="2026-10-18T00:00:00Z")
    late = _ask(exposure=exposures, patches=[overdue_row], overdue=[overdue_row])
    assert _posted(late, "patch_overdue")[0]["due_at"] == "2026-10-18T00:00:00Z"
    # The scan verified it and no longer sees the release: RQ1 and RQ2 none.
    verified = _ask(patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"), progress="completed",
                                    verification="verified")])
    assert _by(verified, "RQ1")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "none"
    assert _by(verified, "RQ2")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "none"
    # Seen running again after it was verified: a regression.
    again = _ask(exposure=exposures, patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"),
                                                     progress="completed",
                                                     verification="verified")])
    assert len(_posted(again, "patch_regressed")) == 1
    # The coverage went stale: none turns unknown.
    stale = _patch("rem-a", *sa, PHP, ("php", "8.3.10"), progress="completed",
                   verification="verified")
    for field in stale["fields"]:
        if field["name"] == "coverage_revision":
            field.update(state="absent", value=None)
    stale_result = _ask(patches=[stale])
    assert _by(stale_result, "RQ2")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "unknown"


def test_the_window_is_unioned_per_source() -> None:
    reads = ["a 2026-09-01T00:00:00Z/2026-09-20T00:00:00Z",
             "a 2026-09-19T00:00:00Z/2026-10-17T00:00:00Z",
             "b 2026-10-04T00:00:00Z/2026-10-17T00:00:00Z"]
    assert uncovered(reads, "a", *WINDOW) == []
    assert uncovered(reads, "b", *WINDOW) == [["2026-09-01T00:00:00Z", "2026-10-04T00:00:00Z"]]
    assert uncovered([], "c", *WINDOW) == [list(WINDOW)]


def _full(source: str) -> str:
    return f"{source} {WINDOW[0]}/{WINDOW[1]}"


def test_rq3_three_states_and_rq4_rotations() -> None:
    audits = [
        _audit("storefront", log_source=["storefront/nginx-access", "storefront/php-fpm"],
               read=[_full("storefront/nginx-access"), _full("storefront/php-fpm")],
               window_end=WINDOW[1], result="exploited"),
        _audit("partner-portal", log_source=["partner-portal/apache"],
               read=[_full("partner-portal/apache")], window_end=WINDOW[1],
               result="not_exploited"),
        _audit("ops-wiki", log_source=["ops-wiki/nginx"],
               read=["ops-wiki/nginx 2026-10-04T00:00:00Z/2026-10-17T00:00:00Z"],
               window_end=WINDOW[1], result="not_exploited")]
    credentials = [_cred("storefront", ("stripe", "storefront-live"), key_id="fp:91b2"),
                   _cred("storefront", AWS, key_id="AKIAQ3EXAMPLEOLDKEY1"),
                   _cred("partner-portal", ("postgres/partners-db", "portal")),
                   _cred("ops-wiki", ("github/acme-ops", "wiki-deploy"))]
    result = _ask(audits=audits, credentials=credentials)
    assert {s: a["state"] for s, a in _by(result, "RQ3").items()} == {
        "ops-wiki": "unknown", "partner-portal": "none", "storefront": "found"}
    assert "uncovered" in _by(result, "RQ3")["ops-wiki"]["why"]
    (gap,) = [g for g in _posted(result, "gap") if g["subject"] == "ops-wiki"]
    assert gap["input"]["source"] == "ops-wiki/nginx" and gap["pull"] == "security.log-acquire"
    rotate = {item["credential"]: item for item in _posted(result, "rotate")}
    assert sorted(rotate) == ["aws-iam/111122223333/storefront-app", "github/acme-ops/wiki-deploy",
                              "stripe/storefront-live"]
    assert rotate["github/acme-ops/wiki-deploy"]["services"] == {
        "ops-wiki": {"audit": "unknown", "patch": "none_recorded"}}
    assert _by(result, "RQ4")["postgres/partners-db/portal"]["state"] == "none"
    # A contended result is unknown, and warrants rotation.
    contended = _ask(audits=[_audit("partner-portal", log_source=["partner-portal/apache"],
                                    read=[_full("partner-portal/apache")], window_end=WINDOW[1],
                                    result="<conflict>")],
                     credentials=[_cred("partner-portal", ("postgres/partners-db", "portal"))])
    assert _by(contended, "RQ3")["partner-portal"]["state"] == "unknown"
    assert len(_posted(contended, "rotate")) == 1


def test_rq4_rotation_states_and_rq5_ready_to_close_with_residue() -> None:
    audits = [_audit("ops-wiki", log_source=["ops-wiki/nginx"], window_end=WINDOW[1],
                     result="inconclusive")]
    rotation = {"progress": "completed", "revokes_key": "key-71839201"}
    claimed = _ask(audits=audits, credentials=[_cred(
        "ops-wiki", ("github/acme-ops", "wiki-deploy"), rotation=rotation)])
    assert _by(claimed, "RQ4")["github/acme-ops/wiki-deploy"]["state"] == "unknown"
    assert [g["pull"] for g in _posted(claimed, "gap") if g["subject"] ==
            "github/acme-ops/wiki-deploy"] == ["security.credential-acquire"]
    disputed = _ask(audits=audits, credentials=[_cred(
        "ops-wiki", ("github/acme-ops", "wiki-deploy"),
        rotation={**rotation, "verification": "failed"})])
    assert len(_posted(disputed, "rotation_disputed")) == 1
    done = _ask(audits=audits, patches=[_patch(
        "rem-w", "wiki-1.ops.acme.internal", "ops-wiki", PHP, ("php", "8.3.10"),
        progress="completed", verification="verified")], credentials=[_cred(
            "ops-wiki", ("github/acme-ops", "wiki-deploy"), issued_at="2026-10-18T09:00:00Z",
            rotation={**rotation, "verification": "verified"})])
    assert _by(done, "RQ4")["github/acme-ops/wiki-deploy"]["state"] == "none"
    (ready,) = _posted(done, "ready_to_close")
    assert ready["residue"] == [{"service": "ops-wiki", "audit": "unknown"}]
    assert done["ready_to_close"] == 1
    closed = _ask(audits=[_audit("ops-wiki", incident_status="closed")])
    assert closed["items"] == [] and closed["status"] == "closed"


def test_payloads_are_stable_so_a_resighting_dedupes() -> None:
    rows = {"exposure": [_exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-a",
                                   service="storefront")],
            "audits": [_audit("storefront")]}
    assert _ask(**rows)["items"] == _ask(**rows)["items"]


def test_a_truncated_tap_is_refused() -> None:
    output = _context(Respond(), {"exposure": [], "patches": [], "overdue": [], "audits": [],
                                  "credentials": [], "params": {},
                                  "truncated": {"exposure": True}})
    assert output.status == "refused"


# --- the CVE record reader: PHP2Shell, ADP, NVD with null configurations -------------


def _releases(*rows: tuple[str, str, list[str]]) -> list[dict[str, Any]]:
    return [_row({"release": ("security.release", f"{p}--{v}".replace("~", "-"))},
                 product_name=p, version=v, components=c or None) for p, v, c in rows]


INVENTORY_RELEASES = _releases(
    ("php", "8.3.10", ["pkg:generic/php@8.3.10"]), ("php", "8.3.36", ["pkg:generic/php@8.3.36"]),
    ("php", "8.2.34", []), ("php8.2", "8.2.20-1~deb12u1",
                            ["pkg:deb/debian/php8.2@8.2.20-1~deb12u1"]))


def _decide(record: bytes) -> Any:
    return _context(CveApplicability(), {
        "record_base64": base64.b64encode(record).decode(), "releases": INVENTORY_RELEASES,
        "watched": [], "assessments": []})


def _status(output: Any) -> dict[str, str]:
    return {json.loads(s[0])["release_id"]: s[2] for s in _statements(output.output["items"])
            if s[1] == "status"}


def test_php2shell_ranges_decide_upstream_builds_and_leave_the_distro_build_to_osv() -> None:
    output = _decide((DATA / "CVE-2026-109618.json").read_bytes())
    assert output.status == "ok"
    assert _status(output) == {"php--8.3.10": "affected", "php--8.3.36": "not_affected",
                               "php--8.2.34": "affected"}


def test_an_nvd_answer_with_null_configurations_is_no_answer_not_a_crash() -> None:
    output = _decide((DATA / "nvd-CVE-2026-109618-configurations-null.json").read_bytes())
    assert output.status == "ok" and output.output["items"] == []
    analysed = _decide((DATA / "nvd-CVE-2026-109618.json").read_bytes())
    assert _status(analysed) == {"php--8.3.10": "affected", "php--8.3.36": "not_affected",
                                 "php--8.2.34": "affected"}
    truncated = _decide((DATA / "nvd-CVE-2026-109618-truncated.json").read_bytes())
    assert truncated.status == "refused" and "incomplete" in truncated.refusal.message
    empty = json.loads(_text("nvd-CVE-2026-109618.json"))
    empty.update(totalResults=0, vulnerabilities=[])
    assert _decide(json.dumps(empty).encode()).status == "refused"
    record = json.loads(_text("CVE-2026-109618.json"))
    record["containers"]["cna"]["affected"] = None
    record["containers"]["adp"] = None
    assert _decide(json.dumps(record).encode()).output["items"] == []


# --- the KEV and OSV readers: a truncated answer is incomplete, never none --------


def test_a_kev_catalog_whose_count_disagrees_with_its_entries_is_refused() -> None:
    from security_analysis_provider.kev import KevTriage

    catalog = {"catalogVersion": "x", "dateReleased": "2026-10-17T00:00:00Z", "count": 3,
               "vulnerabilities": [{"cveID": "CVE-2026-109618", "dateAdded": "2026-10-15"}]}
    output = _context(KevTriage(), {
        "catalog_base64": base64.b64encode(json.dumps(catalog).encode()).decode(),
        "watched": []})
    assert output.status == "refused" and "incomplete" in output.refusal.message


def _osv_exchange(method: str, path: str, body: object, request: object = None) -> dict:
    return {"method": method, "path": path, "request": request, "status": 200,
            "body_sha256": "sha256:" + "0" * 64,
            "body_base64": base64.b64encode(json.dumps(body).encode()).decode()}


def test_a_distro_record_names_its_cve_upstream_and_a_truncated_page_is_inconclusive() -> None:
    from security_analysis_provider.applicability import OsvApplicability

    old, new = ("pkg:deb/debian/php8.2@8.2.20-1~deb12u1", "pkg:deb/debian/php8.2@8.2.26-1~deb12u1")
    records = {cve: json.loads(_text(f"osv-DEBIAN-{cve}.json"))
               for cve in ("CVE-2026-109618", "CVE-2026-109619")}
    osv = {"exchanges": [
        _osv_exchange("POST", "/v1/querybatch", {"results": [
            {"vulns": [{"id": f"DEBIAN-{cve}"} for cve in records]},
            {"vulns": [], "next_page_token": "page-2"}]}, {"purls": [old, new]}),
        *(_osv_exchange("GET", f"/v1/vulns/DEBIAN-{cve}", record)
          for cve, record in records.items())]}
    releases = [_row({"release": ("security.release", "php8.2--a")}, product_name="php8.2",
                     version="8.2.20-1~deb12u1", components=[old]),
                _row({"release": ("security.release", "php8.2--b")}, product_name="php8.2",
                     version="8.2.26-1~deb12u1", components=[new])]
    watched = [_row({"vulnerability": ("security.vulnerability", cve.lower())}, cve_id=cve)
               for cve in records]
    output = _context(OsvApplicability(), {"osv": osv, "releases": releases,
                                           "watched": watched, "assessments": []})
    assert output.status == "ok", output
    status = {(json.loads(s[0])["release_id"], json.loads(s[0])["cve_id"]): s[2]
              for s in _statements(output.output["items"]) if s[1] == "status"}
    assert status == {("php8.2--a", "CVE-2026-109618"): "affected",
                      ("php8.2--a", "CVE-2026-109619"): "affected",
                      ("php8.2--b", "CVE-2026-109618"): "inconclusive",
                      ("php8.2--b", "CVE-2026-109619"): "inconclusive"}
