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
from security_analysis_provider.common import component_set, parse_rows, secret_in_text
from security_analysis_provider.response import (
    MAX_POSTS,
    CredentialState,
    LogReads,
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
        if isinstance(value, dict) and "none" in value:  # a none: {"none": key value}
            return {"claim_object": {"kind": "none", "of": {"kind": "literal",
                                                             "value": value["none"]}},
                    "visibility": visibility}
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
        if obj.get("kind") == "none":  # an asset.runs none: ("none", the product)
            found.append((who, "none", obj["of"]["value"]))
            continue
        value = obj.get("value", obj.get("subject", (obj.get("address") or {}).get(
            "artifact_path")))
        found.append((who, statement["predicate"].rsplit(".", 1)[-1], value))
    return sorted(found, key=json.dumps)


COVERAGE = ("security.coverage", "prod--inventory.runtime")


def _slug(name: str, version: str) -> str:
    """A release id as core renders one from its key (the tests need only uniqueness)."""

    return f"{name}--{version}".replace("/", "-").replace("~", "-")


def _held_prod(revision_value: str | None = None, *, assets: dict[str, list[tuple[str, str]]],
               nones: dict[str, list[str]] | None = None) -> list[dict[str, Any]]:
    """inventory_index rows: the prod coverage, each asset scanned in it, its runs and its
    nones (``nones``: host -> products, Claim ``CLM-none-<index>-<product>``)."""

    rows = []
    for index, (host, runs) in enumerate(sorted(assets.items())):
        asset = ("security.asset", f"asset-{index}")
        run_items: list[tuple[Any, str]] = [
            (("security.release", _slug(n, v)), f"CLM-run-{index}-{n.replace('/', '-')}-{v}")
            for n, v in runs]
        run_items += [({"none": product}, f"CLM-none-{index}-{product.replace('/', '-')}")
                      for product in (nones or {}).get(host, [])]
        for name, version in runs or [(None, None)]:
            purl = None if name is None else (
                f"pkg:deb/{name}@{version}" if name.startswith("debian/")
                else f"pkg:generic/{name}@{version}")
            bindings = {"coverage": COVERAGE, "asset": asset}
            if name:
                bindings["run"] = ("security.release", _slug(name, version))
            rows.append(_row(
                bindings, claims={("coverage", "security.coverage.revision"): "CLM-rev"},
                includes={"runs": run_items,
                          "run_component": [(purl, f"CLM-comp-{purl}")] if purl else [],
                          "scanned_in": [(COVERAGE, f"CLM-scanned-{index}")],
                          "looked_for": [("php", "CLM-looked-php"),
                                         ("debian/php8.2", "CLM-looked-php82")]},
                source="prod", revision=revision_value, looked_for=["php", "debian/php8.2"],
                hostname=host,
                run_product=name, run_version=version))
    return rows


# --- runtime inventory -------------------------------------------------------------


def test_purls_name_the_release_and_drop_qualifiers() -> None:
    run = parse_purl("pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12")
    # The whole namespace and name is the identity: no segment is dropped.
    assert run is not None and (run.name, run.version) == ("debian/libc6", "2.36-9+deb12u7")
    assert run.purl == "pkg:deb/debian/libc6@2.36-9+deb12u7"
    assert parse_purl("pkg:generic/php") is None and parse_purl("php@8") is None
    # A Go major-version module keeps its path: the product is never "v2".
    gh = parse_purl("pkg:golang/github.com/cli/cli/v2@v2.86.0")
    assert gh is not None and (gh.name, gh.version) == ("github.com/cli/cli/v2", "v2.86.0")
    scoped = parse_purl("pkg:npm/%40angular/core@17.0.0")
    assert scoped is not None and scoped.name == "@angular/core"


def test_a_first_full_scan_states_coverage_assets_and_runs() -> None:
    result = _inventory(_text("prod-before.json"), [], [])
    assert (result["mine"], result["format"], result["coverage"]) == (1, "kit", "full")
    statements = _statements(result["items"])
    runs = sorted(s[2]["key"]["product_name"] + " " + s[2]["key"]["version"]
                  for s in statements if s[1] == "runs")
    assert runs == ["debian/php8.2 8.2.20-1~deb12u1", "php 8.3.10", "php 8.3.10"]
    components = sorted(s[2] for s in statements if s[1] == "component")
    assert components == ["pkg:deb/debian/php8.2@8.2.20-1~deb12u1", "pkg:generic/php@8.3.10"]
    assert [s[2] for s in statements if s[1] == "looked_for"] == ["debian/php8.2", "php"]
    (rev,) = [s[2] for s in statements if s[1] == "revision"]
    assert rev == result["revision"] and rev.startswith("sha256:")
    assert sum(1 for s in statements if s[1] == "scanned_in") == 3
    subjects = [i for i in result["items"] if "subject_kind" in i]
    assert {i["subject_kind"] for i in subjects} == {"security.asset", "security.coverage",
                                                     "security.release"}


PROD_NONES = {"k8s:prod/storefront-a": ["debian/php8.2"],
              "k8s:prod/storefront-b": ["debian/php8.2"], "app-1.acme.internal": ["php"]}


def test_an_unchanged_scan_restates_only_the_revision_in_any_order() -> None:
    first = _inventory(_text("prod-before.json"), [], [])
    # The first scan states each asset's nones: every looked-for product it doesn't run.
    assert sorted((json.loads(s[0])["hostname"], s[2]) for s in _statements(first["items"])
                  if s[1] == "none") == sorted((h, p) for h, ps in PROD_NONES.items()
                                               for p in ps)
    assert first["nones"] == 3
    held = _held_prod(first["revision"], assets={
        "k8s:prod/storefront-a": [("php", "8.3.10")], "k8s:prod/storefront-b": [("php", "8.3.10")],
        "app-1.acme.internal": [("debian/php8.2", "8.2.20-1~deb12u1")]}, nones=PROD_NONES)
    again = _inventory(_text("prod-before-reordered.json"), held, [])
    assert again["revision"] == first["revision"]
    # The revision and each held none are restated (a none names its lineage: core
    # re-observes it, or refreshes its evidence when the scan's content is new).
    assert (again["changed"], again["restated"], again["proposes"]) == (0, 4, 4)
    statements = _statements(again["items"])
    assert [s[2] for s in statements if s[1] == "revision"] == [first["revision"]]
    assert sorted(i["revises"] for i in again["items"]
                  if i["statement"]["object"]["kind"] == "none") == [
        "CLM-none-0-php", "CLM-none-1-debian-php8.2", "CLM-none-2-debian-php8.2"]


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
        "app-1.acme.internal": [("debian/php8.2", "8.2.20-1~deb12u1")]}, nones=PROD_NONES)
    patches = [_patch_row("rem-a", "k8s:prod/storefront-a", progress="completed"),
               _patch_row("rem-b", "k8s:prod/storefront-b", progress="completed"),
               _patch_row("rem-app", "app-1.acme.internal", progress="in_progress",
                          affected=("debian/php8.2", "8.2.20-1~deb12u1"))]
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
               "security.asset.runs" and i["statement"]["object"]["kind"] != "none"}
    assert revised == {"CLM-run-1-php-8.3.10": "8.3.36",
                       "CLM-run-0-debian-php8.2-8.2.20-1~deb12u1": "8.2.29-1~deb12u1"}
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


def _no_os(name: str) -> str:
    """A Syft SBOM without its operating-system component (one without a purl is
    unidentified: it could be the product a patch moved off)."""

    document = json.loads(_text(name))
    document["components"] = [c for c in document["components"]
                              if c.get("type") != "operating-system"]
    return json.dumps(document)


def test_a_cyclonedx_sbom_is_one_assets_complete_run_set() -> None:
    scan = read_inventory(_text("storefront-a.syft.cdx.json"))
    assert (scan.format, scan.scope) == ("cyclonedx", "prod")
    result = _inventory(_text("storefront-a.syft.cdx.json"), [], [])
    statements = _statements(result["items"])
    runs = sorted(s[2]["key"]["product_name"] for s in statements if s[1] == "runs")
    assert runs == ["debian/libc6", "debian/libssl3", "debian/libxml2", "php"]  # no OS purl
    assert not [s for s in statements if s[1] in ("revision", "looked_for")]
    assert result["coverage"] == "asset" and result["revision"] == ""
    # A re-scan with its own timestamp and serial number: the same run set, nothing proposed.
    held = _held_prod(None, assets={"k8s:prod/storefront-a": [
        ("php", "8.3.10"), ("debian/libc6", "2.36-9+deb12u7"),
        ("debian/libxml2", "2.9.14+dfsg-1.3~deb12u1"), ("debian/libssl3", "3.0.15-1~deb12u1")]})
    again = _inventory(_text("storefront-a.syft.rescan.cdx.json"), held, [])
    assert (again["proposes"], again["items"]) == (0, [])
    # The patched image: php's run is replaced, the patch on that asset verified.
    patch = _patch_row("rem-a", "k8s:prod/storefront-a", progress="completed")
    patched = _inventory(_no_os("storefront-a.syft.patched.cdx.json"), held, [patch])
    statements = _statements(patched["items"])
    (run,) = [i for i in patched["items"] if i.get("statement", {}).get("predicate") ==
              "security.asset.runs"]
    assert run["revises"] == "CLM-run-0-php-8.3.10"
    assert [s[2] for s in statements if s[1] == "verification"] == ["verified"]
    # A product that is gone with nothing replacing it flips to none: its run retires and
    # its none is added in the same change, beside php's revision.
    gone = json.loads(_no_os("storefront-a.syft.patched.cdx.json"))
    gone["components"] = [c for c in gone["components"] if c["name"] != "libxml2"]
    flip = [("retire", "CLM-run-0-debian-libxml2-2.9.14+dfsg-1.3~deb12u1", "superseded"),
            ("subjects/security.asset/asset-0.json", "none", "debian/libxml2")]
    statements = _statements(_inventory(json.dumps(gone), held, [patch])["items"])
    assert all(item in statements for item in flip)
    held_after = _held_prod(None, assets={"k8s:prod/storefront-a": [
        ("php", "8.3.36"), ("debian/libc6", "2.36-9+deb12u7"),
        ("debian/libxml2", "2.9.14+dfsg-1.3~deb12u1"), ("debian/libssl3", "3.0.15-1~deb12u1")]})
    later = _statements(_inventory(json.dumps(gone), held_after)["items"])
    assert later == flip


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


def test_an_incomplete_read_says_why_in_words() -> None:
    held = parse_rows(_audits("github-actions-ci"))
    read = {"audit": {"incident": "PHP2Shell", "service": "github-actions-ci"},
            "source": "gha:acme/app", "query": "token", "from": "2026-01-21T00:00:00Z",
            "to": "2026-07-24T08:06:00Z", "complete": False, "records_scanned": 0,
            "matches": [], "missing": [{"from": "2026-01-21T00:00:00Z",
                                        "to": "2026-07-24T08:06:00Z", "reason": "expired",
                                        "status": 410}]}
    (item,) = log_reads(json.dumps(read), held, "PHP2Shell")["inbox"]
    assert item["why"] == ("records 2026-01-21T00:00:00Z to 2026-07-24T08:06:00Z expired "
                           "(HTTP 410)")
    assert item["missing"][0]["status"] == 410
    del read["missing"]
    (item,) = log_reads(json.dumps(read), held, "PHP2Shell")["inbox"]
    assert "no reason given" in item["why"]


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
DEB = ("security.release", "debian-php8.2--8.2.20-1-deb12u1")


def _exposure(release: tuple[str, str], label: tuple[str, str], *, asset: str | None = None,
              service: str | None = None, current: bool = True,
              status: str = "affected") -> dict[str, Any]:
    bindings = {"incident": INCIDENT, "vulnerability": ("security.vulnerability",
                                                        "cve-2026-109618"),
                "assessment": ("security.assessment", f"{release[1]}--cve"), "release": release}
    fields: dict[str, Any] = {**INCIDENT_FIELDS, "cve_id": "CVE-2026-109618", "status": status,
                              "product_name": label[0], "version": label[1],
                              "cve_title": "PHP2Shell"}
    if asset:
        bindings["asset"] = ("security.asset", asset.replace("/", "-").replace(":", "-"))
        fields.update(hostname=asset, internet_exposed=True,
                      coverage_revision="sha256:x" if current else None,
                      looked_for=["php", "debian/php8.2"])
        if current:
            bindings["coverage"] = COVERAGE
    if service:
        bindings["service"] = ("security.service", service)
        fields["service_name"] = service
    return _row(bindings, **fields)


def _deployment(host: str, *, declared: tuple[tuple[str, str], tuple[str, str]] | None = None,
                current: bool = False, looked_for: list[str] | None = None,
                components: list[str] | None = None, coverage: str | None = None,
                nones: tuple[str, ...] = ()) -> dict[str, Any]:
    """A security.deployments row: an asset, its inventory coverage, its current nones
    (asset.runs inverses: products it runs none of) and one release it declares ((kind,
    id), (product, version))."""

    bindings = {"asset": ("security.asset", host.replace("/", "-").replace(":", "-"))}
    fields: dict[str, Any] = {"hostname": host,
                              "coverage_revision": "sha256:x" if current else None,
                              "looked_for": looked_for if current else None}
    if current:
        bindings["coverage"] = COVERAGE
    if declared is not None:
        bindings["declared"] = declared[0]
        fields.update(declared_product_name=declared[1][0], declared_version=declared[1][1],
                      declared_components=components, declared_osv_coverage=coverage)
    slug = host.replace("/", "-").replace(":", "-")
    runs = [({"none": product}, f"CLM-none-{slug}-{product.replace('/', '-')}")
            for product in nones]
    return _row(bindings, includes={"runs": runs} if runs else None, **fields)


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


TAPS = ("exposure", "hosts", "deployments", "patches", "overdue", "exceptions", "audits",
        "credentials")


def _ask(**taps: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {name: taps.get(name, []) for name in TAPS}
    return respond({**payload, "params": {"incident": "PHP2Shell"}, "truncated": {}})


def _by(result: dict[str, Any], question: str) -> dict[str, dict[str, Any]]:
    return {a["subject"]: a for a in result["answers"] if a["question"] == question}


def _posted(result: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [item for item in result["items"] if item["kind"] == kind]


def test_rq1_and_rq2_exposure_found_declared_unknown_and_missing_patches() -> None:
    result = _ask(exposure=[
        _exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-a", service="storefront"),
        _exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-b", service="storefront"),
        _exposure(DEB, ("debian/php8.2", "8.2.20-1~deb12u1"), asset="app-1.acme.internal",
                  service="partner-portal")],
        deployments=[_deployment("wiki-1", declared=(PHP, ("php", "8.3.10")))] + [
            _deployment(host, current=True, looked_for=["php", "debian/php8.2"],
                        nones=(none,))
            for host, none in (("k8s:prod/storefront-a", "debian/php8.2"),
                               ("k8s:prod/storefront-b", "debian/php8.2"),
                               ("app-1.acme.internal", "php"))])
    rq1 = _by(result, "RQ1")
    assert {s: a["state"] for s, a in rq1.items()} == {
        "app-1.acme.internal: debian/php8.2 8.2.20-1~deb12u1": "found",
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
    # The scan verified it and no longer sees the release (the asset runs 8.3.36 under a
    # current scan that looked for php): RQ1 and RQ2 none.
    upgraded = _scanned(sa[0], "php", "8.3.36", ["pkg:generic/php@8.3.36"], None,
                        looked_for=("php",))
    verified = _ask(patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"), progress="completed",
                                    verification="verified")], hosts=[upgraded])
    assert _by(verified, "RQ1")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "none"
    assert _by(verified, "RQ2")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "none"
    # No scan says what it runs now (no run, no none): RQ1 unknown, never derived.
    blind = _ask(patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"), progress="completed",
                                 verification="verified")])
    assert _by(blind, "RQ1")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "unknown"
    # It runs no php at all: the asset's current none answers it, cited.
    removed = _ask(patches=[_patch("rem-a", *sa, PHP, ("php", "8.3.10"), progress="completed",
                                   verification="verified")],
                   deployments=[_deployment(sa[0], current=True, looked_for=["php"],
                                            nones=("php",))])
    answer = _by(removed, "RQ1")["k8s:prod/storefront-a: php 8.3.10"]
    assert answer["state"] == "none" and answer["cites"] == ["CLM-none-k8s-prod-storefront-a-php"]
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


def _exception(asset: str, release: tuple[str, str], cve: str, expires_at: str
               ) -> dict[str, Any]:
    """A row of security.incident_exceptions: approved and unexpired at evaluation time."""

    return _row({"incident": INCIDENT, "assessment": ("security.assessment", f"{release[1]}--{cve}"),
                 "release": release, "exception": ("security.exception", f"exc-{cve}"),
                 "asset": ("security.asset", asset.replace("/", "-").replace(":", "-"))},
                **{**INCIDENT_FIELDS, "cve_id": cve, "hostname": asset,
                   "expires_at": expires_at})


def test_an_active_exception_holds_rq2_until_it_expires() -> None:
    host = "app-1.acme.internal"
    exposures = [_exposure(DEB, ("debian/php8.2", "8.2.20-1~deb12u1"), asset=host,
                           service="partner-portal")]
    second = _exposure(DEB, ("debian/php8.2", "8.2.20-1~deb12u1"), asset=host, service="partner-portal")
    for item in second["fields"]:
        if item["name"] == "cve_id":
            item["value"] = "CVE-2026-109619"
    exposures.append(second)
    subject = f"{host}: debian/php8.2 8.2.20-1~deb12u1"
    both = [_exception(host, DEB, cve, "2026-11-01T00:00:00Z")
            for cve in ("CVE-2026-109618", "CVE-2026-109619")]
    # Every one of the release's incident CVEs excepted: excepted, nothing posted for RQ2.
    held = _ask(exposure=exposures, exceptions=both)
    assert _by(held, "RQ2")[subject]["state"] == "excepted"
    assert "2026-11-01T00:00:00Z" in _by(held, "RQ2")[subject]["why"]
    assert not _posted(held, "patch_missing") and held["ready_to_close"] == 0
    # One CVE left out, or the exception expired (the tap drops it): patch_missing again.
    for exceptions in (both[:1], []):
        missing = _ask(exposure=exposures, exceptions=exceptions)
        assert _by(missing, "RQ2")[subject]["state"] == "found"
        assert len(_posted(missing, "patch_missing")) == 1
    # An overdue patch under the exception is excepted too; a disputed one is not.
    patch = _patch("rem-a", host, "partner-portal", DEB, ("debian/php8.2", "8.2.20-1~deb12u1"),
                   progress="planned", due_at="2026-10-18T00:00:00Z")
    overdue = _ask(exposure=exposures, patches=[patch], overdue=[patch], exceptions=both)
    assert _by(overdue, "RQ2")[subject]["state"] == "excepted"
    failed = _patch("rem-a", host, "partner-portal", DEB, ("debian/php8.2", "8.2.20-1~deb12u1"),
                    progress="completed", verification="failed")
    disputed = _ask(exposure=exposures, patches=[failed], exceptions=both)
    assert len(_posted(disputed, "patch_disputed")) == 1


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
    # Intervals in words, never a list's repr.
    assert _by(result, "RQ3")["ops-wiki"]["why"] == (
        "ops-wiki/nginx is not read in full: uncovered 2026-09-01T00:00:00Z to "
        "2026-10-04T00:00:00Z")
    (gap,) = [g for g in _posted(result, "gap") if g["subject"] == "ops-wiki"]
    assert gap["pull"] == "security.log-acquire"
    assert gap["input"]["missing"] == [{
        "pull": "security.log-acquire", "source": "ops-wiki/nginx",
        "from": "2026-09-01T00:00:00Z", "to": "2026-10-04T00:00:00Z",
        "uncovered": ["2026-09-01T00:00:00Z to 2026-10-04T00:00:00Z"]}]
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


def test_an_audit_starts_from_the_services_log_sources() -> None:
    listed = ["storefront/nginx-access", "storefront/php-fpm"]
    exposure = _exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-a",
                         service="storefront")
    exposure["fields"].append({"name": "service_log_source", "state": "present",
                               "value": listed})
    # No audit yet: the gap that asks for one names the service's standing list.
    (gap,) = [g for g in _posted(_ask(exposure=[exposure]), "gap")
              if g["subject"] == "storefront"]
    assert gap["input"] == {"state": "security.audit.log_source", "sources": listed,
                            "audit": {"incident": "PHP2Shell", "service": "storefront"}}
    # An audit that leaves one of them out is unknown, naming it, however complete its reads.
    partial = _audit("storefront", service_log_source=listed,
                     log_source=["storefront/nginx-access"],
                     read=[_full("storefront/nginx-access")], window_end=WINDOW[1],
                     result="not_exploited")
    result = _ask(exposure=[exposure], audits=[partial])
    assert _by(result, "RQ3")["storefront"]["state"] == "unknown"
    (gap,) = [g for g in _posted(result, "gap") if g["subject"] == "storefront"]
    assert gap["pull"] == "statement" and gap["input"]["missing"] == [
        {"pull": "statement", "state": "security.audit.log_source",
         "sources": ["storefront/php-fpm"]}]
    # Stated and read in full over the window: none.
    whole = _audit("storefront", service_log_source=listed, log_source=listed,
                   read=[_full(source) for source in listed], window_end=WINDOW[1],
                   result="not_exploited")
    assert _by(_ask(exposure=[exposure], audits=[whole]), "RQ3")["storefront"]["state"] == "none"
    # The audit's own extra source still needs its reads.
    extra = _audit("storefront", service_log_source=listed,
                   log_source=[*listed, "storefront/waf"],
                   read=[_full(source) for source in listed], window_end=WINDOW[1],
                   result="not_exploited")
    (gap,) = [g for g in _posted(_ask(audits=[extra]), "gap") if g["subject"] == "storefront"]
    assert [piece["source"] for piece in gap["input"]["missing"]] == ["storefront/waf"]
    # Every missing piece in one item: no result, no window_end and an unread source.
    bare = _audit("storefront", service_log_source=listed, log_source=listed)
    (gap,) = [g for g in _posted(_ask(audits=[bare]), "gap") if g["subject"] == "storefront"]
    assert [piece.get("state") for piece in gap["input"]["missing"]] == [
        "security.audit.window_end", "security.audit.result"]


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
        progress="completed", verification="verified")], deployments=[_deployment(
            "wiki-1.ops.acme.internal", current=True, looked_for=["php"], nones=("php",))],
        credentials=[_cred(
            "ops-wiki", ("github/acme-ops", "wiki-deploy"), issued_at="2026-10-18T09:00:00Z",
            rotation={**rotation, "verification": "verified"})])
    assert _by(done, "RQ4")["github/acme-ops/wiki-deploy"]["state"] == "none"
    (ready,) = _posted(done, "ready_to_close")
    assert ready["residue"] == [{"service": "ops-wiki", "audit": "unknown"}]
    assert done["ready_to_close"] == 1
    closed = _ask(audits=[_audit("ops-wiki", incident_status="closed")])
    assert closed["items"] == [] and closed["status"] == "closed"


def _incident_cve(cve: str, *, title: bool = True, packages: tuple[str, ...] = (),
                  products: tuple[str, ...] = ()) -> dict[str, Any]:
    """An incident_exposure row for one incident CVE nobody has assessed yet (``products``:
    what its record names as affected)."""

    row = _row({"incident": INCIDENT, "vulnerability": ("security.vulnerability", cve.lower())},
               includes={"package": [(p, f"CLM-pkg-{cve}-{n}") for n, p in enumerate(packages)]},
               **{**INCIDENT_FIELDS, "cve_id": cve, "cve_title": "PHP2Shell" if title else None,
                  "cve_products": list(products) or None})
    return row


def _scanned(host: str, product: str, version: str, components: list[str],
             coverage: str | None, *, current: bool = True,
             looked_for: tuple[str, ...] = ("*",), bound: bool = True) -> dict[str, Any]:
    """A security.scanned_runs row: a release a scan observed on an asset, under its scope's
    coverage (current: the revision is fresh). ``coverage`` is bound to ``components``
    unless ``bound`` is False (it then names no set)."""

    release = ("security.release", _slug(product, version))
    claims = ({("release", "security.release.osv_coverage"): "CLM-cov-" + _slug(product, version)}
              if coverage else {})
    if coverage and bound:
        coverage = f"{coverage}; set {component_set(components)}"
    return _row({"asset": ("security.asset", host.replace("/", "-").replace(":", "-")),
                 "coverage": COVERAGE, "release": release}, claims=claims,
                includes={"component": [(c, f"CLM-comp-{n}") for n, c in enumerate(components)]},
                hostname=host, product_name=product, version=version, components=components,
                osv_coverage=coverage, coverage_revision="sha256:x" if current else None,
                looked_for=list(looked_for) if current else None)


LIBC = ("debian/libc6", "2.36-9+deb12u7", ["pkg:deb/debian/libc6@2.36-9+deb12u7"])


def test_rq1_answers_every_scanned_release_for_each_incident_cve_never_silently() -> None:
    php82 = ("pkg:deb/debian/php8.2",)
    hosts = [
        _scanned("k8s:prod/storefront-a", *LIBC, "complete: 1 of 1 components answered"),
        _scanned("dev-mac.local", "gh", "2.86.0", ["pkg:brew/gh@2.86.0"],
                 "partial: 0 of 1 components answered; not indexed: brew 1"),
        _scanned("dev-mac.local", "jq", "1.7.1", ["pkg:brew/jq@1.7.1"], None),
        _scanned("app-2", "debian/php8.2", "8.2.99-1", ["pkg:deb/debian/php8.2@8.2.99-1"],
                 "complete: 1 of 1 components answered")]
    result = _ask(exposure=[_incident_cve("CVE-2026-109618", packages=php82)], hosts=hosts)
    rq1 = _by(result, "RQ1")
    # OSV answered libc6 in full and none of its components is a package the CVE affects:
    # none, citing the coverage, component and package Claims.
    libc = rq1["k8s:prod/storefront-a: debian/libc6 2.36-9+deb12u7"]
    assert libc["state"] == "none"
    assert libc["cites"] == ["CLM-comp-0", "CLM-cov-debian-libc6--2.36-9+deb12u7",
                             "CLM-pkg-CVE-2026-109618-0"]
    # Homebrew is never indexed: unknown, never none, naming what OSV doesn't index.
    gh = rq1["dev-mac.local: gh 2.86.0"]
    assert gh["state"] == "unknown" and "OSV doesn't index 1 component" in gh["why"]
    gaps = {(g["subject"], g["pull"]): g["input"] for g in _posted(result, "gap")}
    # The judgment a release waits on is one gap per CVE, carrying its releases.
    assert gaps[("CVE-2026-109618", "statement")] == {
        "state": "security.assessment.status", "cve": "CVE-2026-109618",
        "releases": ["gh 2.86.0"], "osv_not_indexed": {"brew": 1},
        "alternatives": ["security.release.product_alias", "security.inventory-acquire"]}
    # No coverage yet, or the CVE's own package with no assessment: the OSV Line answers.
    assert gaps[("jq 1.7.1", "security.osv-applicability")] == {}  # The Procedure accepts no release parameter.
    assert gaps[("debian/php8.2 8.2.99-1", "security.osv-applicability")] == {}
    # A scan of everything states no none for a product it never saw: storefront-a and
    # dev-mac hold none of debian/php8.2, so each asset is unknown, naming it.
    assert result["posted"] > 0 and result["unknown"] == 5 and result["none"] == 1
    assert gaps[("k8s:prod/storefront-a", "security.inventory-acquire")] == {
        "covering": "k8s:prod/storefront-a", "looking_for": ["debian/php8.2"]}
    # A CVE no record was read for: its record pull first, one item per CVE.
    unread = _ask(exposure=[_incident_cve("CVE-2026-109619", title=False, packages=php82)],
                  hosts=hosts[1:2])
    (gap,) = _posted(unread, "gap")
    assert (gap["subject"], gap["pull"], gap["input"]) == (
        "CVE-2026-109619", "security.cve-record-acquire",
        {"url": "https://cveawg.mitre.org/api/cve/CVE-2026-109619"})
    # OSV doesn't know the CVE (no package): only an analyst's judgment decides it.
    unknown = _ask(exposure=[_incident_cve("CVE-2026-109619")], hosts=hosts[:1])
    (gap,) = [g for g in _posted(unknown, "gap") if g["pull"] == "statement"]
    assert gap["subject"] == "CVE-2026-109619" and gap["input"]["releases"] == [
        "debian/libc6 2.36-9+deb12u7"]
    # The SBOM moved since OSV answered (2 components now, coverage counts 1): unknown.
    moved = _scanned("k8s:prod/storefront-a", "debian/libc6", "2.36-9+deb12u7",
                     ["pkg:deb/debian/libc6@2.36-9+deb12u7", "pkg:deb/debian/zlib1g@1.2"],
                     "complete: 1 of 1 components answered; set "
                     + component_set(["pkg:deb/debian/libc6@2.36-9+deb12u7"]), bound=False)
    stale = _ask(exposure=[_incident_cve("CVE-2026-109618", packages=php82)], hosts=[moved])
    assert _by(stale, "RQ1")["k8s:prod/storefront-a: debian/libc6 2.36-9+deb12u7"][
        "state"] == "unknown"


def test_rq1_uses_an_assessment_and_skips_what_the_exposure_answers() -> None:
    not_affected = _exposure(PHP, ("php", "8.3.36"), status="not_affected")
    not_affected["fields"].append({"name": "cve_products", "state": "present",
                                   "value": ["php"]})
    hosts = [_scanned("k8s:prod/storefront-a", "php", "8.3.36", ["pkg:generic/php@8.3.36"],
                      "partial: 0 of 1 components answered; not indexed: generic 1")]
    for row in hosts:  # the release the assessment is about
        for item in row["bindings"]:
            if item["binding"] == "release":
                item.update(_bound(*PHP))
    result = _ask(exposure=[not_affected], hosts=hosts)
    assert _by(result, "RQ1")["k8s:prod/storefront-a: php 8.3.36"]["state"] == "none"
    assert [item["kind"] for item in result["items"]] == ["ready_to_close"]
    exposed = _exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-a",
                        service="storefront")
    found = _ask(exposure=[exposed], hosts=hosts)
    assert _by(found, "RQ1")["k8s:prod/storefront-a: php 8.3.10"]["state"] == "found"


def test_payloads_are_stable_so_a_resighting_dedupes() -> None:
    rows = {"exposure": [_exposure(PHP, ("php", "8.3.10"), asset="k8s:prod/storefront-a",
                                   service="storefront")],
            "audits": [_audit("storefront")]}
    assert _ask(**rows)["items"] == _ask(**rows)["items"]


def test_a_truncated_tap_is_refused() -> None:
    output = _context(Respond(), {**{name: [] for name in TAPS}, "params": {},
                                  "truncated": {"exposure": True}})
    assert output.status == "refused"


# --- the CVE record reader: PHP2Shell, ADP, NVD with null configurations -------------


def _releases(*rows: tuple[str, str, list[str]]) -> list[dict[str, Any]]:
    return [_row({"release": ("security.release", f"{p}--{v}".replace("~", "-"))},
                 product_name=p, version=v, components=c or None) for p, v, c in rows]


INVENTORY_RELEASES = _releases(
    ("php", "8.3.10", ["pkg:generic/php@8.3.10"]), ("php", "8.3.36", ["pkg:generic/php@8.3.36"]),
    ("php", "8.2.34", []), ("debian/php8.2", "8.2.20-1~deb12u1",
                            ["pkg:deb/debian/php8.2@8.2.20-1~deb12u1"]))


COLLECTIONS = json.loads((Path(__file__).resolve().parents[3] / "authoring" / "data" /
                          "cve_collections.json").read_text())


def _decide(record: bytes) -> Any:
    return _context(CveApplicability(), {
        "record_base64": base64.b64encode(record).decode(), "releases": INVENTORY_RELEASES,
        "watched": [], "assessments": [], "sources": [], "collections": COLLECTIONS})


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
    releases = [_row({"release": ("security.release", "php8.2--a")},
                     product_name="debian/php8.2", version="8.2.20-1~deb12u1", components=[old]),
                _row({"release": ("security.release", "php8.2--b")},
                     product_name="debian/php8.2", version="8.2.26-1~deb12u1", components=[new])]
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


# --- K1 review regressions ------------------------------------------------------------


GHOST = ("security.release", "ghost--1.0")


def test_declared_unscanned_unassessed_and_erased_deployments_are_gaps() -> None:
    """F-003: deployments are enumerated from the inventory, never through assessments."""

    cve = _incident_cve("CVE-2026-109618", packages=("pkg:deb/debian/php8.2",))
    clean = _scanned("k8s:prod/storefront-a", *LIBC, "complete: 1 of 1 components answered")
    # A declared release nobody assessed, on an asset no scan read: unknown, never silent;
    # and it blocks closure even with every other deployment clean.
    declared = _deployment("web-1.example.com", declared=(GHOST, ("ghost", "1.0")))
    result = _ask(exposure=[cve], hosts=[clean], deployments=[declared])
    rq1 = _by(result, "RQ1")
    assert rq1["web-1.example.com: ghost 1.0"]["state"] == "unknown"
    assert rq1["web-1.example.com: ghost 1.0"]["pull"] == "security.inventory-acquire"
    assert {g["subject"]: g["input"] for g in _posted(result, "gap")}[
        "web-1.example.com"] == {"covering": "web-1.example.com"}
    assert result["ready_to_close"] == 0
    # An asset with nothing declared and no current scan (never scanned, or its scan's
    # evidence erased: scanned_in reads absent, so no coverage row): unknown.
    bare = _ask(exposure=[cve], hosts=[clean], deployments=[_deployment("db-9")])
    assert _by(bare, "RQ1")["db-9"]["state"] == "unknown" and bare["ready_to_close"] == 0
    # Under a current scan that looked for everything and doesn't see it: none.
    # Under a current scan that looked for it and states its none: none (citing it). Every
    # asset also holds a none of what the incident affects, so the incident can close.
    covered = _deployment("web-1.example.com", declared=(GHOST, ("ghost", "1.0")),
                          current=True, looked_for=["ghost", "debian/php8.2"],
                          nones=("ghost", "debian/php8.2"))
    cleaned = _deployment("k8s:prod/storefront-a", current=True, looked_for=["*", "debian/php8.2"],
                          nones=("debian/php8.2",))
    done = _ask(exposure=[cve], hosts=[clean], deployments=[covered, cleaned])
    ghost = _by(done, "RQ1")["web-1.example.com: ghost 1.0"]
    assert ghost["state"] == "none" and ghost["cites"] == ["CLM-none-web-1.example.com-ghost"]
    assert done["ready_to_close"] == 1
    # Looked for everything but states no none of ghost: unknown, never derived.
    wide = _deployment("web-1.example.com", declared=(GHOST, ("ghost", "1.0")),
                       current=True, looked_for=["*"], nones=("debian/php8.2",))
    open_ = _ask(exposure=[cve], hosts=[clean], deployments=[wide, cleaned])
    assert _by(open_, "RQ1")["web-1.example.com: ghost 1.0"]["state"] == "unknown"
    assert open_["ready_to_close"] == 0
    # No deployment known at all: a gap, never answers=[].
    empty = _ask(exposure=[cve])
    (gap,) = _posted(empty, "gap")
    assert (gap["subject"], gap["input"]) == ("PHP2Shell", {"covering": "*"})


def test_a_scanned_negative_needs_current_coverage_that_looked_for_the_product() -> None:
    """F-005: an old observed run and OSV coverage never make a none on their own."""

    cve = _incident_cve("CVE-2026-109618", packages=("pkg:deb/debian/php8.2",))
    subject = "k8s:prod/storefront-a: debian/libc6 2.36-9+deb12u7"
    stale = _scanned("k8s:prod/storefront-a", *LIBC, "complete: 1 of 1 components answered",
                     current=False)
    result = _ask(exposure=[cve], hosts=[stale])
    assert _by(result, "RQ1")[subject]["state"] == "unknown"
    assert [g["input"] for g in _posted(result, "gap")] == [
        {"covering": "k8s:prod/storefront-a"}]
    narrow = _scanned("k8s:prod/storefront-a", *LIBC, "complete: 1 of 1 components answered",
                      looked_for=("php", "debian/php8.2"))
    result = _ask(exposure=[cve], hosts=[narrow], deployments=[_deployment(
        "k8s:prod/storefront-a", current=True, looked_for=["php", "debian/php8.2"],
        nones=("debian/php8.2",))])
    assert _by(result, "RQ1")[subject]["state"] == "unknown"
    assert [g["input"] for g in _posted(result, "gap")] == [
        {"covering": "k8s:prod/storefront-a", "looking_for": ["debian/libc6"]}]
    # A current scan that didn't look for a product the incident affects can't rule it out.
    php = _scanned("wiki-1", "php", "8.3.36", ["pkg:generic/php@8.3.36"],
                   "partial: 0 of 1 components answered; not indexed: generic 1",
                   looked_for=("php",))
    assessed = _exposure(("security.release", "php--8.3.36"), ("php", "8.3.36"),
                         status="not_affected")
    for row in [php]:
        for item in row["bindings"]:
            if item["binding"] == "release":
                item.update(_bound("security.release", "php--8.3.36"))
    result = _ask(exposure=[cve, assessed], hosts=[php])
    assert _by(result, "RQ1")["wiki-1"]["state"] == "unknown"
    assert "debian/php8.2" in _by(result, "RQ1")["wiki-1"]["why"]


def test_a_negative_is_bound_to_the_component_set_it_was_decided_on() -> None:
    """F-006: same-count replacement, and a retained assessment after the set changed."""

    cve = _incident_cve("CVE-2026-109618", packages=("pkg:deb/debian/php8.2",))
    # Coverage stated for libc6; the release now holds zlib1g instead (one component both
    # times): the coverage is about another set.
    replaced = _scanned("k8s:prod/storefront-a", "debian/libc6", "2.36-9+deb12u7",
                        ["pkg:deb/debian/zlib1g@1.2"],
                        "complete: 1 of 1 components answered; set "
                        + component_set(["pkg:deb/debian/libc6@2.36-9+deb12u7"]), bound=False)
    result = _ask(exposure=[cve], hosts=[replaced])
    assert _by(result, "RQ1")["k8s:prod/storefront-a: debian/libc6 2.36-9+deb12u7"][
        "state"] == "unknown"
    # A not_affected assessment resting on the fixed Debian build: none while it is there,
    # unknown once the release holds another copy of the package.
    fixed = "pkg:deb/debian/php8.2@8.2.29-1~deb12u1"
    release = ("security.release", "debian-php8.2--8.2.29")
    assessment = _row({"incident": INCIDENT, "vulnerability": ("security.vulnerability",
                                                               "cve-2026-109618"),
                       "assessment": ("security.assessment", "deb-fixed"), "release": release},
                      includes={"assessed_component": [(fixed, "CLM-rests")],
                                "package": [("pkg:deb/debian/php8.2", "CLM-pkg")]},
                      **{**INCIDENT_FIELDS, "cve_id": "CVE-2026-109618", "cve_title": "x",
                         "status": "not_affected", "product_name": "debian/php8.2",
                         "version": "8.2.29-1~deb12u1"})

    def host(components: list[str]) -> dict[str, Any]:
        row = _scanned("app-1", "debian/php8.2", "8.2.29-1~deb12u1", components,
                       "complete: 1 of 1 components answered")
        for item in row["bindings"]:
            if item["binding"] == "release":
                item.update(_bound(*release))
        return row

    subject = "app-1: debian/php8.2 8.2.29-1~deb12u1"
    held = _ask(exposure=[assessment], hosts=[host([fixed])])
    assert _by(held, "RQ1")[subject]["state"] == "none"
    moved = _ask(exposure=[assessment], hosts=[host([fixed, "pkg:deb/debian/php8.2@8.2.20-1"])])
    assert _by(moved, "RQ1")[subject]["state"] == "unknown"
    assert "no longer has as they were" in _by(moved, "RQ1")[subject]["why"]
    gone = _ask(exposure=[assessment], hosts=[host(["pkg:deb/debian/php8.2@8.2.30-1"])])
    assert _by(gone, "RQ1")[subject]["state"] == "unknown"


def test_unidentified_sbom_components_never_verify_a_patch_or_retire_a_run() -> None:
    """F-004: a component without a usable purl could be the product a patch moved off."""

    held = _held_prod(None, assets={"k8s:prod/storefront-a": [
        ("php", "8.3.10"), ("debian/libc6", "2.36-9+deb12u7"),
        ("debian/libxml2", "2.9.14+dfsg-1.3~deb12u1"), ("debian/libssl3", "3.0.15-1~deb12u1")]})
    patch = _patch_row("rem-a", "k8s:prod/storefront-a", progress="completed")
    for broken in ({"type": "application", "name": "php", "version": "8.3.10"},
                   {"type": "application", "name": "php", "purl": "pkg:generic/php"},
                   {"type": "library", "name": "php", "purl": "not a purl"}):
        document = json.loads(_no_os("storefront-a.syft.patched.cdx.json"))
        document["components"] = [c for c in document["components"]
                                  if c.get("purl") != "pkg:generic/php@8.3.36"] + [broken]
        result = _inventory(json.dumps(document), held, [patch])
        statements = _statements(result["items"])
        assert result["unidentified"] == 1, broken
        assert not [s for s in statements if s[1] == "verification" or s[0] == "retire"], broken
    # With every component identified, the patch verifies.
    plain = _inventory(_no_os("storefront-a.syft.patched.cdx.json"), held, [patch])
    assert plain["unidentified"] == 0
    assert [s[2] for s in _statements(plain["items"]) if s[1] == "verification"] == ["verified"]
    # R-004: an operating-system component without a purl is unidentified too: it can be
    # the affected product itself (a patch of ubuntu 22.04), so it never verifies.
    osheld = _held_prod(None, assets={"h": [("ubuntu", "22.04")]})
    ospatch = _patch_row("rem-os", "h", progress="completed", affected=("ubuntu", "22.04"))
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"properties": [
        {"name": "cruxible.scope", "value": "prod"}, {"name": "cruxible.asset", "value": "h"}]},
        "components": [{"type": "operating-system", "name": "ubuntu", "version": "22.04"}]}
    result = _inventory(json.dumps(sbom), osheld, [ospatch])
    assert result["unidentified"] == 1 and result["verified"] == 0


def test_two_ecosystems_packages_of_one_name_are_both_kept() -> None:
    """F-011: pkg:npm/foo@1.0 and pkg:pypi/foo@1.0 are one release with two components."""

    text = json.dumps({"scope": "prod", "looked_for": ["*"], "coverage": "full", "assets": [
        {"hostname": "app-9", "runs": ["pkg:npm/foo@1.0", "pkg:pypi/foo@1.0",
                                        "pkg:npm/%40angular/core@17.0.0"]}]})
    statements = _statements(_inventory(text)["items"])
    assert sorted(s[2] for s in statements if s[1] == "component") == [
        "pkg:npm/%40angular/core@17.0.0", "pkg:npm/foo@1.0", "pkg:pypi/foo@1.0"]
    assert sorted(s[2]["key"]["product_name"] for s in statements if s[1] == "runs") == [
        "@angular/core", "foo"]


def test_refusals_never_echo_what_they_refuse() -> None:
    """F-010: field names and values from a refused body never reach an output."""

    marker = "ghp_016fK2dX0aZq9pLmNoPqRsTuVwXyZ01234"
    body = json.loads(_text("cred-aws-state.json"))
    keyed = {**body, marker: "x"}
    for text in (json.dumps(keyed), json.dumps({**body, "issuer": f"aws/{marker}"}),
                 json.dumps({**body, "name": "storefront " + marker}),
                 json.dumps({**body, "keys": [{**body["keys"][0], marker: 1}]}),
                 json.dumps({**body, "keys": [{**body["keys"][0], "created_by": marker}]})):
        result = credential_state(text, [])
        assert result["posted"] == 1 and result["items"] == []
        assert marker not in json.dumps(result), text
    inventory_body = {"scope": "prod", "looked_for": ["*"], "coverage": "full",
                      "assets": [{"hostname": "h", "runs": [marker]}], marker: 1}
    for text in (json.dumps(inventory_body), json.dumps({
            **{k: v for k, v in inventory_body.items() if k != marker}})):
        output = _context(RuntimeInventory(), {"inventory_text": text, "held": [],
                                               "patches": [], "scope": "prod",
                                               "truncated": {}})
        assert output.status == "refused" and marker not in output.refusal.message
    read = json.loads(_text("log-storefront-nginx.json"))
    for text in (json.dumps({**read, marker: 1}),
                 json.dumps({**read, "source": f"storefront/{marker}"})):
        output = _context(LogReads(), {"read_text": text, "held": _audits("storefront"),
                                       "incident": "PHP2Shell", "truncated": False})
        assert output.status == "refused" and marker not in output.refusal.message


def test_a_read_that_says_complete_and_names_unread_spans_is_refused() -> None:
    """F-008: complete: true beside missing spans or an incomplete reason is never a read."""

    read = json.loads(_text("log-storefront-nginx.json"))
    for extra in ({"missing": [{"from": read["from"], "to": read["to"], "reason": "expired",
                                "status": 410}]},
                  {"incomplete_reason": "the index rolled over"}):
        output = _context(LogReads(), {"read_text": json.dumps({**read, **extra}),
                                       "held": _audits("storefront"), "incident": "PHP2Shell",
                                       "truncated": False})
        assert output.status == "refused" and "complete" in output.refusal.message


def test_rotation_verification_needs_the_old_key_listed_retired_or_a_complete_listing() -> None:
    """F-009: a receipt relabelled state_read (new key only) verifies nothing."""

    rotation = {"progress": "completed", "revokes_key": "AKIAQ3EXAMPLEOLDKEY1"}
    held = parse_rows([_credential(*AWS, key_id="AKIAQ3EXAMPLEOLDKEY1",
                                   issued_at="2026-03-02T10:00:00Z", rotation=rotation)])
    relabelled = json.loads(_text("cred-aws-leaky.json"))
    del relabelled["secret_access_key"]
    relabelled["read"] = "state_read"
    result = credential_state(json.dumps(relabelled), held)
    assert result["verified"] == 0 and result["unproven"] == 1
    assert not [s for s in _statements(result["items"]) if s[1] == "verification"]
    # The listing says it is complete (every key, every page): absence is then an answer.
    complete = credential_state(json.dumps({**relabelled, "complete": True}), held)
    assert [s[2] for s in _statements(complete["items"]) if s[1] == "verification"] == [
        "verified"]


def test_more_items_than_the_cap_refuse_instead_of_cutting() -> None:
    """F-014: 201 distinct gaps never post the same first 200 forever."""

    cve = _incident_cve("CVE-2026-109619")
    # Every asset unscanned: one inventory gap each (judgments coalesce per CVE instead).
    hosts = [_deployment(f"host-{n:03}") for n in range(MAX_POSTS + 1)]
    output = _context(Respond(), {**{name: [] for name in TAPS}, "exposure": [cve],
                                  "deployments": hosts, "params": {"incident": "PHP2Shell"},
                                  "truncated": {}})
    assert output.status == "refused" and "overflow" in output.refusal.message
    assert f"{MAX_POSTS + 1} items" in output.refusal.message
    fits = _ask(exposure=[cve], deployments=hosts[:MAX_POSTS])
    assert fits["posted"] == MAX_POSTS


# --- K1 recheck regressions (R-001..R-007) ---------------------------------------------


def test_every_enumerated_asset_is_answered_even_under_a_narrow_scan() -> None:
    """R-001: a current scan of an unrelated product, with the incident's affected products
    not established, never leaves the asset silent or lets the incident close."""

    cve = _incident_cve("CVE-2026-109619")  # no OSV package, no assessment: scope unknown
    narrow = _deployment("h", current=True, looked_for=["unrelated"])
    result = _ask(exposure=[cve], deployments=[narrow])
    assert _by(result, "RQ1")["h"]["state"] == "unknown" and result["posted"] > 0
    assert {g["subject"]: g["input"] for g in _posted(result, "gap")}["h"] == {
        "covering": "h", "looking_for": ["*"]}
    clean = _scanned("k8s:prod/storefront-a", *LIBC, "complete: 1 of 1 components answered")
    closure = _ask(exposure=[cve, _exposure(("security.release", _slug(*LIBC[:2])), LIBC[:2],
                                            status="not_affected")],
                   hosts=[clean], deployments=[narrow])
    assert _by(closure, "RQ1")["h"]["state"] == "unknown" and closure["ready_to_close"] == 0
    # Looked for everything and lists nothing: still unknown while what the incident
    # affects is not established, and then only its nones answer.
    wide = _ask(exposure=[cve], deployments=[_deployment("h", current=True, looked_for=["*"])])
    assert _by(wide, "RQ1")["h"]["state"] == "unknown"
    named = _incident_cve("CVE-2026-109619", products=("php",))
    assert _by(_ask(exposure=[named], deployments=[_deployment(
        "h", current=True, looked_for=["*"])]), "RQ1")["h"]["state"] == "unknown"
    ruled_out = _ask(exposure=[named], deployments=[_deployment(
        "h", current=True, looked_for=["*", "php"], nones=("php",))])
    assert _by(ruled_out, "RQ1")["h"]["state"] == "none"
    assert ruled_out["ready_to_close"] == 1


def _held_negative(fixed: str, release: tuple[str, str], label: tuple[str, str],
                   role: str = "observation") -> dict[str, Any]:
    return _row({"incident": INCIDENT, "vulnerability": ("security.vulnerability",
                                                         "cve-2024-34064"),
                 "assessment": ("security.assessment", "neg"), "release": release},
                includes={"assessed_component": [(fixed, "CLM-rests")],
                          "package": [("pkg:pypi/jinja2", "CLM-pkg")]},
                **{**INCIDENT_FIELDS, "cve_id": "CVE-2024-34064", "cve_title": "x",
                   "status": "not_affected", "status_role": role, "product_name": label[0],
                   "version": label[1]})


def _on(row: dict[str, Any], release: tuple[str, str]) -> dict[str, Any]:
    for item in row["bindings"]:
        if item["binding"] == "release":
            item.update(_bound(*release))
    return row


def test_a_retained_negative_needs_its_whole_basis() -> None:
    """R-002 and R-003: a component OSV never answered, or a newly unidentified one,
    leaves a retained source negative unproven; an analyst's judgment stands."""

    fixed, release, label = ("pkg:pypi/jinja2@3.1.4", ("security.release", "app--1.0"),
                             ("app", "1.0"))
    subject = "h: app 1.0"
    plain = _on(_scanned("h", *label, [fixed], "complete: 1 of 1 components answered"),
                release)
    assert _by(_ask(exposure=[_held_negative(fixed, release, label)], hosts=[plain]),
               "RQ1")[subject]["state"] == "none"
    added = _on(_scanned("h", *label, [fixed, "pkg:brew/unknown@1.0"],
                         "partial: 1 of 2 components answered; not indexed: brew 1"), release)
    result = _ask(exposure=[_held_negative(fixed, release, label)], hosts=[added])
    assert _by(result, "RQ1")[subject]["state"] == "unknown" and result["ready_to_close"] == 0
    judged = _ask(exposure=[_held_negative(fixed, release, label, "normative")], hosts=[added])
    assert _by(judged, "RQ1")[subject]["state"] == "none"
    # The SBOM now lists a component without a purl: the old coverage and the negative
    # are about another set.
    unidentified = _on(_scanned("h", *label, [fixed], "complete: 1 of 1 components answered"),
                       release)
    unidentified["fields"].append({"name": "unidentified", "state": "present", "value": 1})
    result = _ask(exposure=[_held_negative(fixed, release, label)], hosts=[unidentified])
    assert _by(result, "RQ1")[subject]["state"] == "unknown" and result["ready_to_close"] == 0
    bare = _scanned("k8s:prod/storefront-a", *LIBC, "complete: 1 of 1 components answered")
    bare["fields"].append({"name": "unidentified", "state": "present", "value": 1})
    cve = _incident_cve("CVE-2026-109618", packages=("pkg:deb/debian/php8.2",))
    assert _by(_ask(exposure=[cve], hosts=[bare]), "RQ1")[
        "k8s:prod/storefront-a: debian/libc6 2.36-9+deb12u7"]["state"] == "unknown"


def test_a_second_ecosystem_of_a_held_release_is_stated() -> None:
    """R-005: the component is stated even when the asset's run is unchanged."""

    held = _held_prod("sha256:old", assets={"h": [("foo", "1.0")]})
    for row in held:
        for include in row["includes"]:
            if include["name"] == "run_component":
                include["items"][0]["claim_object"]["value"] = "pkg:npm/foo@1.0"
    text = json.dumps({"scope": "prod", "looked_for": ["*"], "coverage": "full", "assets": [
        {"hostname": "h", "runs": ["pkg:npm/foo@1.0", "pkg:pypi/foo@1.0"]}]})
    statements = _statements(_inventory(text, held)["items"])
    assert [s[2] for s in statements if s[1] == "component"] == ["pkg:pypi/foo@1.0"]
    assert not [s for s in statements if s[1] == "runs"]


def test_secret_prefixes_are_found_at_any_boundary_and_inventory_ids_are_checked() -> None:
    """R-007: a parenthesized known-prefix token, in a credential name or a hostname."""

    marker = "ghp_" + "A" * 32
    body = json.loads(_text("cred-aws-state.json"))
    result = credential_state(json.dumps({**body, "name": f"storefront ({marker})"}), [])
    assert result["posted"] == 1 and marker not in json.dumps(result)
    for text in (json.dumps({"scope": "prod", "looked_for": ["*"], "coverage": "full",
                             "assets": [{"hostname": marker, "runs": []}]}),
                 json.dumps({"scope": "prod", "looked_for": ["*"], "coverage": "full",
                             "assets": [{"hostname": "h", "runs": [f"pkg:npm/{marker}@1"]}]})):
        output = _context(RuntimeInventory(), {"inventory_text": text, "held": [],
                                               "patches": [], "scope": "prod",
                                               "truncated": {}})
        assert output.status == "refused" and marker not in output.refusal.message
    assert not secret_in_text("aws-iam/111122223333") and not secret_in_text(
        "k8s:prod/storefront-7d9f8b6c5d-x2k4p", name=True)


# --- K2: inverses (asset.runs nones), coalesced gaps, K1 recheck 2 (R2-001..R2-005) ------


def _scan(looked_for: list[str], assets: dict[str, list[str]], coverage: str = "full") -> str:
    return json.dumps({"scope": "prod", "looked_for": looked_for, "coverage": coverage,
                       "assets": [{"hostname": h, "runs": r} for h, r in assets.items()]})


def test_a_full_scan_states_nones_only_for_what_it_looked_for() -> None:
    """A none for every named product the asset doesn't run; under * only for a product it
    ran before (a flip); never for a product the scan did not look for."""

    named = _statements(_inventory(_scan(["php", "debian/php8.2"], {
        "a": ["pkg:generic/php@8.3.36"], "b": []}))["items"])
    assert sorted((json.loads(s[0])["hostname"], s[2]) for s in named if s[1] == "none") == [
        ("a", "debian/php8.2"), ("b", "debian/php8.2"), ("b", "php")]
    # A scan of everything that never saw a product states nothing about it.
    wide = _statements(_inventory(_scan(["*"], {"a": ["pkg:generic/php@8.3.36"], "b": []}))[
        "items"])
    assert not [s for s in wide if s[1] == "none"]
    # A partial scan states no none at all.
    partial = _statements(_inventory(_scan(["php"], {"b": []}, "partial"))["items"])
    assert not [s for s in partial if s[1] == "none"]


def test_a_vanished_run_flips_to_none_and_a_reappearing_one_flips_back() -> None:
    held = _held_prod("sha256:old", assets={"h": [("php", "8.3.10"), ("jq", "1.7.1")]})
    # Under *, jq is gone: its run retires and its none is added in one change, beside
    # php's revision to a new version (one terminal: core dispositions the sibling).
    gone = _inventory(_scan(["*"], {"h": ["pkg:generic/php@8.3.36"]}), held)
    statements = _statements(gone["items"])
    assert ("retire", "CLM-run-0-jq-1.7.1", "superseded") in statements
    assert ("subjects/security.asset/asset-0.json", "none", "jq") in statements
    assert [i["revises"] for i in gone["items"] if i.get("statement", {}).get("object", {})
            .get("kind") == "subject_key"] == ["CLM-run-0-php-8.3.10"]
    # jq runs again (even a partial scan sees it): its none retires, the run is added.
    back_held = _held_prod("sha256:old", assets={"h": [("php", "8.3.36")]},
                           nones={"h": ["jq"]})
    for coverage in ("full", "partial"):
        back = _statements(_inventory(_scan(["*"], {"h": ["pkg:generic/php@8.3.36",
                                                          "pkg:generic/jq@1.7.1"]}, coverage),
                                      back_held)["items"])
        assert ("retire", "CLM-none-0-jq", "superseded") in back, coverage
        assert [s[2]["key"]["product_name"] for s in back if s[1] == "runs"] == ["jq"]
        assert not [s for s in back if s[1] == "none"]


def test_a_held_none_retires_when_the_scan_stops_asking_or_the_asset_leaves() -> None:
    held = _held_prod("sha256:old", assets={"h": [], "gone-1": []},
                      nones={"h": ["php", "debian/php8.2"], "gone-1": ["php"]})
    result = _inventory(_scan(["php"], {"h": []}), held)
    statements = _statements(result["items"])
    # debian/php8.2 is no longer asked about: its none retires; php's is restated.
    assert ("retire", "CLM-none-1-debian-php8.2", "superseded") in statements
    assert [i["revises"] for i in result["items"] if i.get("statement", {}).get(
        "object", {}).get("kind") == "none"] == ["CLM-none-1-php"]
    # gone-1 left the scope: its none retires with its runs.
    assert ("retire", "CLM-none-0-php", "superseded") in statements


def test_an_inventory_tap_row_with_a_none_reads_as_its_product() -> None:
    (row,) = parse_rows([_row({"asset": ("security.asset", "h")},
                              includes={"runs": [({"none": "php"}, "CLM-n")]})])
    (item,) = row.included("runs")
    assert (item.is_none, item.none_of, item.value, item.object_path) == (
        True, "php", None, None)


def test_judgment_gaps_are_one_per_cve_carrying_every_release() -> None:
    """Run 2: 101 Homebrew releases posted 101 statement gaps; now one per CVE."""

    cve = _incident_cve("CVE-2026-109618", packages=("pkg:deb/debian/php8.2",))
    brew = [_scanned("dev-mac.local", f"tool{n}", "1.0", [f"pkg:brew/tool{n}@1.0"],
                     "partial: 0 of 1 components answered; not indexed: brew 1")
            for n in range(3)]
    other = [_scanned("dev-2", "tool0", "1.0", ["pkg:brew/tool0@1.0"],
                      "partial: 0 of 1 components answered; not indexed: brew 1")]
    result = _ask(exposure=[cve], hosts=brew + other)
    (gap,) = [g for g in _posted(result, "gap") if g["pull"] == "statement"]
    assert (gap["subject"], gap["input"]) == ("CVE-2026-109618", {
        "state": "security.assessment.status", "cve": "CVE-2026-109618",
        "releases": ["tool0 1.0", "tool1 1.0", "tool2 1.0"], "osv_not_indexed": {"brew": 3},
        "alternatives": ["security.release.product_alias", "security.inventory-acquire"]})


def test_r2_001_an_observed_package_is_not_the_whole_affected_roster() -> None:
    """The record names upstream PHP; OSV names the Debian build; a scan that looked only
    for the Debian build never makes the host none."""

    cve = _incident_cve("CVE-2026-109618", packages=("pkg:deb/debian/php8.2",),
                        products=("php",))
    narrow = _deployment("h", current=True, looked_for=["debian/php8.2"],
                         nones=("debian/php8.2",))
    result = _ask(exposure=[cve], deployments=[narrow])
    assert _by(result, "RQ1")["h"]["state"] == "unknown" and result["ready_to_close"] == 0
    assert {g["subject"]: g["input"] for g in _posted(result, "gap")}["h"] == {
        "covering": "h", "looking_for": ["php"]}
    both = _deployment("h", current=True, looked_for=["debian/php8.2", "php"],
                       nones=("debian/php8.2", "php"))
    assert _by(_ask(exposure=[cve], deployments=[both]), "RQ1")["h"]["state"] == "none"


def test_r2_002_a_contended_unidentified_count_is_unresolved_never_zero() -> None:
    fixed, release, label = ("pkg:pypi/jinja2@3.1.4", ("security.release", "app--1.0"),
                             ("app", "1.0"))
    for negative in ("retained", "inverse"):
        row = _on(_scanned("h", *label, [fixed], "complete: 1 of 1 components answered"),
                  release)
        row["fields"].append({"name": "unidentified", "state": "conflict", "value": None})
        exposure = ([_held_negative(fixed, release, label)] if negative == "retained" else
                    [_incident_cve("CVE-2024-34064", packages=("pkg:pypi/jinja2",))])
        result = _ask(exposure=exposure, hosts=[row])
        answer = _by(result, "RQ1")["h: app 1.0"]
        assert answer["state"] == "unknown", negative
        assert "contended" in answer["why"] and result["ready_to_close"] == 0


def test_r2_004_prefixes_after_hyphens_and_encoded_names_are_secret_shaped() -> None:
    marker = "ghp_" + "A" * 32
    assert secret_in_text("storefront-" + marker) and secret_in_text("x_" + marker)
    assert secret_in_text(f"pkg:npm/foo-{marker}@1", name=True)
    assert secret_in_text("pkg:npm/%67hp_" + "A" * 32 + "@1", name=True)
    body = json.loads(_text("cred-aws-state.json"))
    result = credential_state(json.dumps({**body, "name": "storefront-" + marker}), [])
    assert result["posted"] == 1 and marker not in json.dumps(result)
    for run in (f"pkg:npm/foo-{marker}@1", "pkg:npm/%67hp_" + "A" * 32 + "@1"):
        output = _context(RuntimeInventory(), {
            "inventory_text": _scan(["*"], {"h": [run]}), "held": [], "patches": [],
            "scope": "prod", "truncated": {}})
        assert output.status == "refused" and marker not in output.refusal.message
    assert not secret_in_text("k8s:prod/storefront-7d9f8b6c5d-x2k4p", name=True)


def test_a_scan_of_everything_states_the_nones_of_what_the_asset_declares() -> None:
    held = _held_prod("sha256:old", assets={"web-1": []})
    for row in held:
        row["fields"].append({"name": "declared_product", "state": "present",
                              "value": "zammad"})
    wide = _statements(_inventory(_scan(["*"], {"web-1": []}), held)["items"])
    assert [s[2] for s in wide if s[1] == "none"] == ["zammad"]
    narrow = _statements(_inventory(_scan(["php"], {"web-1": []}), held)["items"])
    assert [s[2] for s in narrow if s[1] == "none"] == ["php"]  # zammad: not looked for
