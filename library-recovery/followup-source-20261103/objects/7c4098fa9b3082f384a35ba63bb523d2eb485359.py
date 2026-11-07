"""Isolated Linux smoke tests for the proposed source-exact P4 atomic writer.

The test suite here covers the extracted helper only, NOT the full Hepta repo.
"""
import json
import os
import secrets
import stat
from pathlib import Path

import pytest


def _write_report_atomically(output: Path, report: dict[str, object]) -> None:
    """Fsync report contents and its pinned parent directory after atomic rename."""
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        directory_fd = os.open(
            output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
    except OSError as error:
        raise ValueError("matrix report parent must be a real directory") from error
    temporary_name = f".{output.name}.{secrets.token_hex(16)}.tmp"
    staged = False
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        staged = True
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(
            temporary_name,
            output.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        staged = False
        os.fsync(directory_fd)
    finally:
        if staged:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def test_report_file_and_directory_are_both_fsynced(tmp_path, monkeypatch):
    original = os.fsync
    kinds = []

    def watched(fd):
        kinds.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        original(fd)

    monkeypatch.setattr(os, "fsync", watched)
    target = tmp_path / "reports" / "receipt.json"
    _write_report_atomically(target, {"authority": "DENY_ALL", "status": "blocked"})
    assert kinds == ["file", "directory"]
    assert json.loads(target.read_text()) == {"authority": "DENY_ALL", "status": "blocked"}
    assert list(target.parent.glob(".receipt.json.*.tmp")) == []


def test_atomic_repeat_update_never_leaves_partial_file(tmp_path):
    path = tmp_path / "matrix.json"
    for revision in (1, 2, 3):
        _write_report_atomically(path, {"revision": revision})
        assert json.loads(path.read_bytes()) == {"revision": revision}
    assert sorted(x.name for x in tmp_path.iterdir()) == ["matrix.json"]


def test_symlink_report_parent_is_rejected_before_staging(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    shortcut = tmp_path / "alias"
    shortcut.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="real directory"):
        _write_report_atomically(shortcut / "signed.json", {"qualified": False})
    assert list(real.iterdir()) == []


def test_replace_failure_retains_old_bytes_and_removes_temp(tmp_path, monkeypatch):
    path = tmp_path / "matrix.json"
    path.write_text("old-report", encoding="utf-8")

    def failing_replace(src, dst, *, src_dir_fd, dst_dir_fd):
        assert src_dir_fd == dst_dir_fd
        assert (tmp_path / src).is_file()
        raise OSError("simulated rename failure")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError, match="simulated rename failure"):
        _write_report_atomically(path, {"forged": False})
    assert path.read_text(encoding="utf-8") == "old-report"
    assert sorted(x.name for x in tmp_path.iterdir()) == ["matrix.json"]


def test_dangling_output_symlink_replaced_without_touching_victim(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    output = tmp_path / "matrix.json"
    output.symlink_to(victim)
    _write_report_atomically(output, {"status": "blocked"})
    assert not output.is_symlink()
    assert victim.read_text() == "unchanged"
    assert json.loads(output.read_text()) == {"status": "blocked"}


def test_parent_swap_during_rename_cannot_redirect_write(tmp_path, monkeypatch):
    """The pinned directory fd prevents a changed path from writing to attacker dir."""
    real = tmp_path / "original"
    real.mkdir()
    shifted = tmp_path / "shifted"
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    target = real / "matrix.json"
    original_replace = os.replace

    def raced_replace(src, dst, *, src_dir_fd, dst_dir_fd):
        real.rename(shifted)
        real.symlink_to(attacker, target_is_directory=True)
        return original_replace(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
        )

    monkeypatch.setattr(os, "replace", raced_replace)
    _write_report_atomically(target, {"authority": "DENY_ALL"})
    assert json.loads((shifted / "matrix.json").read_text()) == {
        "authority": "DENY_ALL"
    }
    assert list(attacker.iterdir()) == []
