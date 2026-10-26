"""The kit pages' Python snippets, run as written against a gate world, one world per page.

    CRUXIBLE_BIN=/path/to/cruxible python -m pytest kits/security/gate/test_doc_snippets.py

Every ```python (or ~~~python) block of a page runs in page order in one interpreter
(the page's later blocks reuse its ``cx``), as the owner, in the world's attached
workspace. A block fails the page when it raises, or when a submit, write or Procedure
run it makes does not land, accept or succeed. Each world is a fresh daemon with the
kit installed from a throwaway registry and the example automation submitted, plus
what the page assumes already exists (a CVE the incident names, a credential an
import would have created). After the snippets:

- every kept write body (a JSON block with ``because`` and ``changes``, the MCP and
  CLI form) dry-runs as ``would_accept`` against the state the snippets wrote;
- README's graduation lands exactly the mandates and Lines ``recipe.graduate()``
  describes, and in-depth's watch the watches ``recipe.watch()`` describes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_security_kit_gate import KIT, RELEASE_1_0, VERSION, Gate, _field  # noqa: E402

import recipe  # noqa: E402

PAGES = ("README.md", "walkthroughs.md", "intake.md", "in-depth.md", "examples/README.md")
FENCE = re.compile(r"^( *)(```|~~~)(python|json)[ \t]*\n(.*?)\n\1\2[ \t]*$", re.M | re.S)

#: What each page assumes exists before its first snippet, as Subjects created by key.
SETUP: dict[str, list[tuple[str, Any]]] = {
    "walkthroughs.md": [
        ("security.vulnerability", "CVE-2026-109618"),
        ("security.vulnerability", "CVE-2026-109619"),
    ],
    "intake.md": [
        ("security.credential", {"issuer": "stripe", "name": "storefront-live"}),
        ("security.release", {"product_name": "myapp", "version": "1.0.0"}),
    ],
    "in-depth.md": [
        ("security.vulnerability", "CVE-2024-56201"),
        ("security.vulnerability", "CVE-2026-109618"),
        ("security.release", {"product_name": "gate-app", "version": "1.0.0"}),
        ("security.release", {"product_name": "jq", "version": "1.7.1"}),
        ("security.assessment", {"release_id": "gate-app--1.0.0", "cve_id": "CVE-2024-56201"}),
    ],
}
#: Workspace files a page's snippets read.
FILES = {"in-depth.md": {"analysis/jinja2.md": "# Jinja2\n\nWe compile only packaged templates.\n"}}

DRIVER = r'''
import json, sys, traceback
from cruxible_client.authoring.sdk import Intent, ProcedureRun
from cruxible_client.contracts.write import WriteOutcome

page, blocks = sys.argv[1], json.load(open(sys.argv[2]))
namespace = {"__name__": "__main__"}
for number, code in enumerate(blocks, 1):
    before = {name: id(value) for name, value in namespace.items()}
    try:
        exec(compile(code, f"<{page} python block {number}>", "exec"), namespace)
    except Exception:
        traceback.print_exc()
        sys.exit(f"{page} python block {number} raised")
    for name, value in namespace.items():
        if before.get(name) == id(value):
            continue
        if isinstance(value, Intent) and (value.refused or value.outcome.status != "landed"):
            sys.exit(f"{page} python block {number}: {name} did not land: {value.outcome!r} "
                     f"{value.diagnostics!r}")
        if isinstance(value, WriteOutcome) and value.status != "accepted":
            sys.exit(f"{page} python block {number}: {name} is {value.status}")
        if isinstance(value, ProcedureRun) and not value.succeeded:
            sys.exit(f"{page} python block {number}: {name} is {value.status}")
    print(f"{page} python block {number}: ok", flush=True)
'''


def blocks(page: str, language: str) -> list[str]:
    """The page's fenced blocks of one language, dedented by their fence's indent."""

    text = (KIT / page).read_text()
    found = []
    for match in FENCE.finditer(text):
        indent, _, kind, body = match.groups()
        if kind == language:
            found.append("\n".join(line[len(indent):] for line in body.splitlines()))
    return found


def test_every_converted_page_has_snippets() -> None:
    counts = {page: len(blocks(page, "python")) for page in PAGES}
    assert all(counts.values()), counts


@contextmanager
def _world(page: str) -> Iterator[Gate]:
    explicit = os.environ.get("SECURITY_KIT_GATE_ROOT")
    parent = Path(explicit).parent if explicit else None
    if parent is not None:
        parent.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", page.lower()).strip("-")
    root = Path(tempfile.mkdtemp(prefix=f"doc-snippets-{slug}-", dir=parent))
    print(f"doc snippets {page}: {root}")
    gate = Gate(root)
    try:
        gate.start_registry()
        subprocess.run([sys.executable, str(HERE / "publish_kit.py"), str(RELEASE_1_0),
                        f"{gate.registry}:{VERSION}"], env=gate.env, check=True,
                       capture_output=True)
        gate.start_daemon()
        for args in (["init", "-q", "-b", "main", "."],
                     ["commit", "-q", "--allow-empty", "-m", "init"]):
            subprocess.run(["git", *args], cwd=gate.ws, env=gate.env, check=True)
        gate.out("init", "--principal-id", "gate-owner")
        gate.load_settings()
        preview = gate.json("kit", "add", f"{gate.registry}:{VERSION}", "--dry-run")
        installed = gate.json("kit", "add", f"{gate.registry}:{VERSION}", "--commit",
                              "--at", preview["coordinate"]["git_oid"])
        assert installed["status"] == "accepted", installed
        # As a consumer submits it: no fixture bindings, every slot bound by fit.
        _submit(gate, "automation", recipe.automation())
        if page in SETUP:
            _submit(gate, "setup", {
                "kind": "change_set", "rationale": f"What {page} assumes exists.",
                "members": [recipe.subject(kind, key, f"Exists before {page}.")
                            for kind, key in SETUP[page]]})
        for relative, text in FILES.get(page, {}).items():
            (gate.ws / relative).parent.mkdir(parents=True, exist_ok=True)
            (gate.ws / relative).write_text(text)
        yield gate
    finally:
        gate.close()


def _submit(gate: Gate, name: str, value: dict[str, Any]) -> None:
    result = json.loads(gate.out("authoring", "submit", gate.payload(name, value)))
    assert result["outcome"]["status"] == "landed", result


def _run_snippets(gate: Gate, page: str) -> None:
    driver = gate.root / "snippet_driver.py"
    driver.write_text(DRIVER)
    source = gate.payload("snippets", blocks(page, "python"))
    result = subprocess.run([sys.executable, str(driver), page, source], env=gate.env,
                            cwd=gate.ws, capture_output=True, text=True, timeout=1800)
    gate.log.write(f"$ python snippets {page}\n{result.stdout}{result.stderr}\n")
    gate.log.flush()
    assert result.returncode == 0, (result.stdout + result.stderr)[-4000:]


def _write_bodies(page: str) -> list[dict[str, Any]]:
    """The page's kept write bodies (MCP ``cruxible_write`` arguments, ``cruxible write``
    files), without the ``"..."`` placeholders that stand for more of the same."""

    bodies = []
    for text in blocks(page, "json"):
        value = json.loads(text)
        if isinstance(value, dict) and {"because", "changes"} <= value.keys():
            value["changes"] = [c for c in value["changes"] if isinstance(c, dict)]
            bodies.append(value)
    return bodies


def _strip_tags(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_tags(v) for k, v in value.items() if k != "tag"}
    if isinstance(value, list):
        return [_strip_tags(v) for v in value]
    return value


def _days(member: dict[str, Any]) -> int:
    span = (datetime.fromisoformat(member["expires_at"].replace("Z", "+00:00"))
            - datetime.fromisoformat(member["valid_from"].replace("Z", "+00:00")))
    return span.days


def _check_graduation(gate: Gate) -> None:
    """README's snippet lands the mandates and Lines ``recipe.graduate()`` describes."""

    for member in recipe.graduate()["members"]:
        if member["kind"] == "procedure_mandate":
            held = gate.json("get", f"ProcedureMandate:{member['name']}",
                             "--detail", "proof")["proof"]["envelope"]
            condition = held["condition"]
            assert {
                "procedure": held["procedure"]["target"]["name"],
                "grants": held["grants"],
                "namespace": held["namespace"],
                "resource_ceiling": _strip_tags(held["resource_ceiling"]),
                "scope": [{"claim_type": s["claim_type"]["target"]["name"],
                           "change_kinds": s["change_kinds"]} for s in held["scope"]],
                "condition": {"query_name": condition["query"]["target"]["name"],
                              "binding_parameter": condition["binding_parameter"],
                              "required_fields": condition["required_fields"],
                              "fallback": condition["fallback"]},
                "days": _days(held),
            } == {
                "procedure": member["procedure_name"],
                "grants": member["grants"],
                "namespace": member["namespace"],
                "resource_ceiling": member["resource_ceiling"],
                "scope": member["scope"],
                "condition": member["condition"],
                "days": _days(member),
            }, member["name"]
        else:
            held = gate.json("get", f"Line:{member['name']}",
                             "--detail", "proof")["proof"]["envelope"]
            assert (held["procedure"]["target"]["name"], held["max_authority"],
                    held["trigger_input"], held["parameters"]) == (
                member["procedure_name"], member["max_authority"],
                member.get("trigger_input"), member.get("parameters", {})), member["name"]


def _check_watches(gate: Gate) -> None:
    """in-depth's watch snippet holds the watches ``recipe.watch()`` describes."""

    reasons = {subject: value for subject, (value, _) in
               gate.claims("security.vulnerability",
                           "security.vulnerability.watch_reason").items()}
    ids = {value: subject for subject, (value, _) in
           gate.claims("security.vulnerability", "security.vulnerability.cve_id").items()}
    watched = {_field(row, "cve_id") for row in gate.rows("security.watched_vulnerabilities")}
    for member in recipe.watch("CVE-2021-44228", "CVE-2021-44832")["members"]:
        if member["kind"] != "claim":
            continue
        cve = member["subject"]["key"]["cve_id"]
        assert cve in ids, (cve, ids)
        assert reasons.get(ids[cve]) == member["object"]["value"], (cve, reasons)
        assert cve in watched, (cve, watched)


@pytest.mark.parametrize("page", PAGES)
def test_page_snippets_run(page: str) -> None:
    with _world(page) as gate:
        _run_snippets(gate, page)
        for number, body in enumerate(_write_bodies(page), 1):
            dry = gate.json("write", gate.payload(f"write-body-{number}", body), "--dry-run")
            assert dry["status"] == "would_accept", (page, number, dry)
        if page == "README.md":
            _check_graduation(gate)
        if page == "in-depth.md":
            _check_watches(gate)
