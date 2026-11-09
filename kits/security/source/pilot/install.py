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
6. the dependency-judgment guidance Document (``../guidance/dependency.md``,
   K-CF2a), which guides the two justification ClaimTypes;
7. with ``--sarif-wheel``, code findings and the audit guidance and reference
   Documents (see the blocks at the end).

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
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

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
    install_guidance(args.payloads, names=DEPENDENCY_GUIDANCE, references=False)
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
    install_guidance(payloads)


# -- Guidance (K-CA4, K-CF2a): governed Documents ---------------------------------------
#
# ``../guidance/*.md`` and ``../../reference/*.md`` install as governed Documents
# after the vocabulary they guide, so ``kit build`` ships them as ``documents/``
# kit artifacts (bodies under ``bodies/``) and ``kit add`` installs them. A
# guidance Document ``guides`` the ClaimTypes its reader writes, read off its own
# ``Guides:`` header; a reference Document (optional hunting strategy) guides
# nothing and is found by its document_kind (``security.reference``). The
# dependency guidance installs with the dependency vocabulary; the audit
# guidance and the references with the findings vocabulary.

SOURCE = HERE.parent
#: The reference pages: plain kit files in the release (``reference/``); the pilot
#: can also install them as governed Documents (``references=True``).
REFERENCES = SOURCE.parent / "reference"
#: Judging a dependency exposure: the two justification ClaimTypes (K-CF2a).
DEPENDENCY_GUIDANCE = ("dependency",)
#: Security audits (K-CA4).
GUIDANCE = ("hunter", "verifier", "coverage")
GUIDANCE_KIND = "security.guidance"
REFERENCE_KIND = "security.reference"
SCOPE = ("security",)


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


def guidance_sources(
    names: Sequence[str] = GUIDANCE, *, references: bool = True
) -> list[tuple[Path, str, list[str]]]:
    """(path, document_kind, guided ClaimTypes): the guidance, then the references."""

    out = [
        (path, GUIDANCE_KIND, guided_claim_types(path))
        for path in (SOURCE / "guidance" / f"{name}.md" for name in names)
    ]
    if references:
        out += [(path, REFERENCE_KIND, []) for path in sorted(REFERENCES.glob("*.md"))]
    return out


def guidance_documents(
    store_body: Callable[[Path], str],
    names: Sequence[str] = GUIDANCE,
    *,
    references: bool = True,
) -> list[dict[str, Any]]:
    """Each Document's envelope (a ``DocumentShell``); ``store_body`` stores a
    file's bytes in the instance's body store and returns their digest."""

    documents = []
    for path, document_kind, guides in guidance_sources(names, references=references):
        title = path.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
        links = sorted(
            ({"relation": "guides", "target_identity": f"ClaimType:{name}"} for name in guides),
            key=lambda link: link["target_identity"].encode("utf-8"),
        )
        documents.append(
            {
                "kind": "document",
                "identity": f"document:{document_kind}.{path.stem}",
                "document_kind": document_kind,
                "title": title,
                "media_type": "text/markdown",
                "body_digest": store_body(path),
                "links": links,
                "governance_scope": list(SCOPE),
                "lifecycle": {"revision": 1},
            }
        )
    return documents


def install_guidance(
    payloads: Path, names: Sequence[str] = GUIDANCE, *, references: bool = True
) -> None:
    """Store each body, then propose its Document (``cruxible document propose``)."""

    def store_body(path: Path) -> str:
        return json.loads(cruxible("body", "store", str(path), "--json"))["digest"]

    for document in guidance_documents(store_body, names, references=references):
        name = document["identity"].removeprefix("document:")
        path = payloads / f"document.{name}.json"
        path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
        out = json.loads(
            cruxible("document", "propose", "--envelope", str(path), "--name", name, "--json")
        )
        if (out.get("outcome") or {}).get("status") != "landed":
            raise SystemExit(f"Document {name} did not land:\n{json.dumps(out, indent=1)}")
        print(f"document {name}: accepted")


if __name__ == "__main__":
    main()
