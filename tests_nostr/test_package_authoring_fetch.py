"""Tests for fetching a native package manifest straight from its repository."""

import subprocess
from pathlib import Path

import pytest

from nostrhost.package_authoring import (
    _clone_and_read_manifest,
    _validate_revision,
    fetch_manifest_from_repository,
)

MANIFEST = '[app]\nid = "example-app"\nversion = "0.1.0"\n'


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(autouse=True)
def _isolated_clone_paths(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """_clone_and_read_manifest now goes through yunohost.utils.app_utils's
    real _make_tmp_workdir_for_app/_git_clone_light (the same helpers the
    legacy app-install flow uses), which default to root-owned system paths
    (/var/cache/yunohost/...) - fine on a real host, but this test suite
    doesn't run as root. Point both at a writable temp directory instead,
    and pre-create the git-clone cache dir: _git_clone_light chown()s it to
    root the first time it sees the dir missing, which only root can do."""
    import yunohost.utils.app_utils as app_utils_module

    isolated = tmp_path_factory.mktemp("yunohost-cache")
    workdirs = isolated / "app_tmp_work_dirs"
    gitclones = isolated / "gitclones"
    gitclones.mkdir(parents=True)
    monkeypatch.setattr(app_utils_module, "APPS_TMP_WORKDIRS", str(workdirs))
    monkeypatch.setattr(app_utils_module, "GIT_CLONE_CACHE", str(gitclones))


@pytest.fixture()
def local_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "package.toml").write_text(MANIFEST, encoding="utf-8")
    _git(repo, "add", "package.toml")
    _git(repo, "commit", "--quiet", "-m", "initial")
    return repo


def test_clone_and_read_manifest_reads_package_toml(local_repo: Path) -> None:
    content, commit = _clone_and_read_manifest(str(local_repo), "", "")
    assert content == MANIFEST
    assert len(commit) == 40


def test_clone_and_read_manifest_reads_package_path(tmp_path: Path, local_repo: Path) -> None:
    sub = local_repo / "packages" / "example-app"
    sub.mkdir(parents=True)
    (sub / "package.toml").write_text(MANIFEST, encoding="utf-8")
    _git(local_repo, "add", "packages/example-app/package.toml")
    _git(local_repo, "commit", "--quiet", "-m", "add subdir")
    content, _ = _clone_and_read_manifest(str(local_repo), "", "packages/example-app")
    assert content == MANIFEST


def test_clone_and_read_manifest_missing_file_raises(local_repo: Path) -> None:
    (local_repo / "package.toml").unlink()
    _git(local_repo, "add", "-A")
    _git(local_repo, "commit", "--quiet", "-m", "remove manifest")
    with pytest.raises(ValueError, match="package.toml not found"):
        _clone_and_read_manifest(str(local_repo), "", "")


def test_clone_and_read_manifest_bad_repository_raises() -> None:
    with pytest.raises(ValueError, match="could not clone"):
        _clone_and_read_manifest("/nonexistent/path/to/nowhere", "", "")


def test_validate_revision_rejects_leading_dash() -> None:
    with pytest.raises(ValueError, match="must not start with"):
        _validate_revision("--upload-pack=evil")


def test_validate_revision_rejects_control_characters() -> None:
    with pytest.raises(ValueError, match="whitespace or control"):
        _validate_revision("main\nrm -rf /")


def test_validate_revision_accepts_normal_names() -> None:
    _validate_revision("main")
    _validate_revision("v1.2.3")
    _validate_revision("a1b2c3d")


def test_fetch_manifest_from_repository_rejects_non_https() -> None:
    with pytest.raises(ValueError, match="https://"):
        fetch_manifest_from_repository("git@github.com:example/repo.git")


def test_fetch_manifest_from_repository_rejects_traversal_package_path() -> None:
    with pytest.raises(ValueError, match="package_path"):
        fetch_manifest_from_repository("https://example.invalid/repo.git", package_path="../etc")
