"""Explicit SBOM source pins must survive branch movement and refuse drifting refs."""

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("refresh_sboms", HERE / "refresh_sboms.py")
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          text=True, capture_output=True).stdout.strip()


def test_requires_all_four_inputs():
    parser = argparse.ArgumentParser()
    refresh.add_source_arguments(parser)
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_exact_commit_keeps_old_lock_after_head_moves(tmp_path):
    git(tmp_path, "init", "-q")
    lock = tmp_path / "uv.lock"
    lock.write_text('version = 1\n')
    git(tmp_path, "add", "uv.lock")
    git(tmp_path, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "first")
    sha = git(tmp_path, "rev-parse", "HEAD")
    lock.write_text('version = 2\n')
    git(tmp_path, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
        "commit", "-qam", "second")
    args = argparse.Namespace(core_repo=tmp_path, providers_repo=tmp_path,
                              core_sha=sha, providers_sha=sha)
    assert refresh.source_pins(args)["core_sha"] == sha
    assert refresh._lock(tmp_path, sha)["version"] == 1
    args.core_sha = "HEAD"
    with pytest.raises(ValueError, match="full 40-character"):
        refresh.source_pins(args)
