"""``build_kit.adoption_args``: declared recipe and script files are staged only from
inside the kit, never through a symbolic link, and only under their role's directory.

    python -m pytest scripts/test_build_kit.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from cruxible_client._safe_files import ContainmentError

_spec = importlib.util.spec_from_file_location(
    "build_kit", Path(__file__).resolve().with_name("build_kit.py")
)
assert _spec is not None and _spec.loader is not None
build_kit = importlib.util.module_from_spec(_spec)
sys.modules["build_kit"] = build_kit
_spec.loader.exec_module(build_kit)

RECIPE = {"name": "default", "path": "recipes/default.json"}
SCRIPT = {"name": "plan", "path": "scripts/plan.py", "mode": "read_only"}


def kit(tmp_path: Path, recipes: list[dict] | None = None, scripts: list[dict] | None = None) -> Path:
    root = tmp_path / "kit"
    (root / "source").mkdir(parents=True)
    (root / "recipes").mkdir()
    (root / "scripts").mkdir()
    (root / "recipes" / "default.json").write_text('{"kind": "change_set", "members": []}\n')
    (root / "scripts" / "plan.py").write_text("print('plan')\n")
    (root / "source" / "recipes.json").write_text(json.dumps(recipes or [RECIPE]))
    (root / "source" / "scripts.json").write_text(json.dumps(scripts or [SCRIPT]))
    return root


def stage(tmp_path: Path, root: Path) -> tuple[list[str], Path]:
    workspace = tmp_path / "scratch" / "workspace"
    workspace.mkdir(parents=True)
    return build_kit.adoption_args(root, workspace), workspace


def test_declared_files_are_staged_beside_their_declarations(tmp_path: Path) -> None:
    root = kit(tmp_path)
    args, workspace = stage(tmp_path, root)
    assert args == [
        "--recipes",
        str(workspace.parent / "kit-recipes.json"),
        "--scripts",
        str(workspace.parent / "kit-scripts.json"),
    ]
    assert (workspace / "recipes" / "default.json").read_bytes() == (
        root / "recipes" / "default.json"
    ).read_bytes()
    assert (workspace / "scripts" / "plan.py").read_text() == "print('plan')\n"


def test_a_symlinked_declared_file_is_refused(tmp_path: Path) -> None:
    root = kit(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("private key\n")
    (root / "scripts" / "plan.py").unlink()
    os.symlink(secret, root / "scripts" / "plan.py")
    with pytest.raises(ContainmentError):
        stage(tmp_path, root)


def test_a_symlinked_role_directory_is_refused(tmp_path: Path) -> None:
    root = kit(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "default.json").write_text("{}\n")
    for item in (root / "recipes").iterdir():
        item.unlink()
    (root / "recipes").rmdir()
    os.symlink(elsewhere, root / "recipes")
    with pytest.raises(ContainmentError):
        stage(tmp_path, root)


def test_a_symlinked_declaration_list_is_refused(tmp_path: Path) -> None:
    root = kit(tmp_path)
    outside = tmp_path / "recipes.json"
    outside.write_text(json.dumps([RECIPE]))
    (root / "source" / "recipes.json").unlink()
    os.symlink(outside, root / "source" / "recipes.json")
    with pytest.raises(ContainmentError):
        stage(tmp_path, root)


@pytest.mark.parametrize(
    ("recipes", "scripts"),
    [
        ([{"name": "x", "path": "../outside.json"}], None),
        ([{"name": "x", "path": "/etc/passwd"}], None),
        ([{"name": "x", "path": "recipes/../scripts/plan.py"}], None),
        ([{"name": "x", "path": "recipes/./default.json"}], None),
        ([{"name": "x", "path": "scripts/plan.py"}], None),  # a script declared as a recipe
        (None, [{"name": "x", "path": "recipes/default.json", "mode": "read_only"}]),
        ([{"name": "x", "path": "recipes"}], None),
        ([{"name": "x"}], None),
        (["recipes/default.json"], None),
    ],
)
def test_a_declared_path_outside_its_role_directory_is_refused_before_copying(
    tmp_path: Path, recipes: list | None, scripts: list | None
) -> None:
    root = kit(tmp_path, recipes, scripts)
    with pytest.raises(ValueError, match="kit"):
        stage(tmp_path, root)
    assert list((tmp_path / "scratch" / "workspace").iterdir()) == []


def test_a_kit_declaring_neither_list_passes_no_options(tmp_path: Path) -> None:
    root = kit(tmp_path)
    (root / "source" / "recipes.json").unlink()
    (root / "source" / "scripts.json").unlink()
    assert stage(tmp_path, root)[0] == []
