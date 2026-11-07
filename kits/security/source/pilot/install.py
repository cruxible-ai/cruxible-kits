"""Install the KEV + EPSS slice into a fresh instance through the served CLI.

Every step is an ordinary governed write the instance's approval policy admits
(an owner with self-approval lands each at once):

1. the Contracts cruxible-provider-web's operations pin (``web_contracts.py``);
2. ``provider install`` of the web wheel (its lock and the runtime wheel beside it);
3. the Contracts security-osv-provider's operations pin, and ``provider install``
   of its wheel (``--osv-wheel``/``--osv-lock``; batch 2, the dependency loop);
4. the CaptureKinds (``capture-contract propose``);
5. vocabulary, Procedures, vulnerability Subjects and the Lines/Mandates/Triggers
   (``authoring submit`` of the change sets ``definitions.py`` writes);
6. with ``--sarif-wheel``, code findings (see the block at the end).

A ``seed.json`` (own-word affected_by, labelled seed) is NOT installed here: it is
state an agent states, submitted by hand after the SBOM import Lines have run
(see the instance README).

    python install.py PAYLOADS --providers PROVIDERS_CHECKOUT --wheels WHEEL_DIR \
        --osv-wheel SECURITY_OSV_PROVIDER.whl --osv-lock SECURITY_OSV_PROVIDER_uv.lock

``cruxible`` must be on PATH and already pointed at the instance (``cruxible
init`` in the workspace, or CRUXIBLE_SERVER_SOCKET + --instance-id).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import definitions as kit  # noqa: E402
import web_contracts  # noqa: E402


def cruxible(*args: str) -> str:
    done = subprocess.run(["cruxible", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"cruxible {' '.join(args)} failed:\n{done.stdout}\n{done.stderr}")
    return done.stdout


def submit(path: Path) -> None:
    out = cruxible("authoring", "submit", str(path), "--brief")
    if "outcome: accepted" not in out:
        raise SystemExit(f"{path.name} did not land:\n{out}")
    print(f"{path.name}: accepted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("payloads", type=Path, help="the directory definitions.py wrote")
    parser.add_argument("--providers", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--osv-wheel", type=Path, required=True)
    parser.add_argument("--osv-lock", type=Path, required=True)
    parser.add_argument(
        "--sarif-wheel", type=Path, default=None, help="install code findings: the provider wheel"
    )
    parser.add_argument("--sarif-lock", type=Path, default=None, help="its uv.lock")
    args = parser.parse_args()

    contracts = args.payloads / "web-contracts.json"
    contracts.write_text(
        json.dumps(
            {
                "kind": "change_set",
                "rationale": "The Contracts cruxible-provider-web's operations pin, as shipped.",
                "members": web_contracts.members(args.providers),
            },
            indent=1,
        )
        + "\n"
    )
    submit(contracts)
    web = next(args.wheels.glob("cruxible_provider_web-*.whl"))
    runtime = next(args.wheels.glob("cruxible_provider_runtime-*.whl"))
    installed = json.loads(
        cruxible(
            "provider",
            "install",
            str(web),
            "--lock",
            str(args.providers / "packages/cruxible-provider-web/uv.lock"),
            "--dependency",
            str(runtime),
            "--control-domain",
            "cruxible-provider-web",
            "--commit",
            "--json",
        )
    )
    ready = {row["operation"]: row["installed"] for row in installed["operations"]}
    if not (installed["registered"] and ready.get("web.fetch")):
        raise SystemExit(f"web.fetch is not installed: {installed}")
    print(f"provider: {installed['build']} (web.fetch installed)")
    # -- Batch 2, dependency loop: security-osv-provider (sbom.components, osv.*).
    submit(args.payloads / "osv-contracts.json")
    installed = json.loads(
        cruxible(
            "provider",
            "install",
            str(args.osv_wheel),
            "--lock",
            str(args.osv_lock),
            "--dependency",
            str(runtime),
            "--control-domain",
            "security-osv-provider",
            "--commit",
            "--json",
        )
    )
    ready = {row["operation"]: row["installed"] for row in installed["operations"]}
    wanted = ("sbom.components", "osv.query", "osv.match")
    if not (installed["registered"] and all(ready.get(name) for name in wanted)):
        raise SystemExit(f"security-osv-provider is not installed: {installed}")
    print(f"provider: {installed['build']} ({', '.join(wanted)} installed)")
    for name in kit.capture_kinds():
        path = args.payloads / f"capture-kind.{name}.json"
        cruxible("capture-contract", "propose", "--input", str(path), "--commit")
        print(f"capture kind {name}: accepted")
    for name in ("vocabulary", "procedures", "watch", "automation"):
        submit(args.payloads / f"{name}.json")
    if args.sarif_wheel is not None:
        install_findings(args.payloads, args.sarif_wheel, args.sarif_lock, runtime)


# -- Code findings (kit batch 2, lane 2): SARIF import ------------------------------------
#
# ``findings.py OUT_DIR --scan NAME=host/owner/repo=RELATIVE_PATH`` writes these
# payloads into the same directory: the Contracts security-sarif-provider pins
# (``sarif-contracts.json``), its two CaptureKinds, and the findings vocabulary,
# Procedures and Lines. The provider wheel and its lock come from the package
# (``uv lock`` then ``uv build`` in source/providers/security-sarif-provider).
#
# Security audits (K-CA1..K-CA4) ride on the same vocabulary: the coverage unit,
# found_in and the ``file`` evidence rule, which admits any catalogued workspace
# file (the ``workspace_file`` family, D1).


def install_findings(payloads: Path, wheel: Path, lock: Path | None, runtime: Path) -> None:
    import findings

    submit(payloads / "sarif-contracts.json")
    installed = json.loads(
        cruxible(
            "provider",
            "install",
            str(wheel),
            *(("--lock", str(lock)) if lock is not None else ()),
            "--dependency",
            str(runtime),
            "--control-domain",
            findings.PROVIDER_PACKAGE,
            "--commit",
            "--json",
        )
    )
    ready = {row["operation"]: row["installed"] for row in installed["operations"]}
    if not (installed["registered"] and ready.get("sarif.findings")):
        raise SystemExit(f"sarif.findings is not installed: {installed}")
    print(f"provider: {installed['build']} (sarif.findings installed)")
    for name in findings.capture_kinds():
        path = payloads / f"capture-kind.{name}.json"
        cruxible("capture-contract", "propose", "--input", str(path), "--commit")
        print(f"capture kind {name}: accepted")
    for name in ("findings-vocabulary", "findings-procedures", "findings-automation"):
        submit(payloads / f"{name}.json")


# -- Audit guidance (K-CA4) ---------------------------------------------------------------
#
# TODO(core-surface item 11: kits ship Documents): install these as governed
# Documents through ``kit add``. Until core ships Documents in a kit, nothing here
# is installed; ``test_audit_gate`` pins the member list with a strict xfail
# (owner: core-surface item 11). Guidance attaches to the ClaimTypes its reader
# writes (``guides``, read off each Document's own ``Guides:`` header); reference
# Documents are optional strategy and guide nothing.

SOURCE = HERE.parent
GUIDANCE = ("hunter", "verifier", "coverage")


def guided_claim_types(path: Path) -> list[str]:
    """The ClaimTypes a guidance Document's ``Guides:`` header names, in order."""

    lines = path.read_text(encoding="utf-8").splitlines()
    (start,) = [index for index, line in enumerate(lines) if line.startswith("Guides:")]
    # The list may wrap; it ends at its full stop.
    text = lines[start].removeprefix("Guides:").strip()
    for line in lines[start + 1 :]:
        if text.endswith("."):
            break
        text += " " + line.strip()
    return [name.strip() for name in text.removesuffix(".").split(",")]


def guidance_members() -> list[dict[str, object]]:
    """The planned Document members: three guidance Documents, then the references."""

    def member(path: Path, document_kind: str, guides: list[str]) -> dict[str, object]:
        title = path.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
        return {
            "kind": "document",
            "document_id": f"security.{document_kind}.{path.stem}",
            "document_kind": f"security.{document_kind}",
            "title": title,
            "media_type": "text/markdown",
            "path": path.relative_to(SOURCE).as_posix(),
            "links": [
                {"relation": "guides", "target_identity": f"ClaimType:{name}"} for name in guides
            ],
        }

    members = []
    for name in GUIDANCE:
        path = SOURCE / "guidance" / f"{name}.md"
        members.append(member(path, "guidance", guided_claim_types(path)))
    for path in sorted((SOURCE / "reference").glob("*.md")):
        members.append(member(path, "reference", []))
    return members


if __name__ == "__main__":
    main()
