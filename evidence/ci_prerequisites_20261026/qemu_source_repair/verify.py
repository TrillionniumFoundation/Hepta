"""Verify retained observations; do not download or execute any tool."""
from pathlib import Path
import hashlib
import json


def verify(root):
    inventory = json.loads((root / "MANIFEST.json").read_text())
    for name, expected in inventory["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe retained path")
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("missing regular retained file")
        data = path.read_bytes()
        if {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} != expected:
            raise ValueError("retained file identity differs: " + name)
    lock = json.loads((root / "qemu-toolchain-lock.json").read_text())
    observation = json.loads((root / "source-observation.json").read_text())
    snapshot, archive = observation["observations"]
    assert snapshot["name"] == "snapshot" and snapshot["http_status"] == 503
    assert archive["name"] == "ubuntu_archive" and archive["http_status"] == 200
    assert archive["url"] == archive["final_url"] == lock["source"]
    assert archive["sha256"] == observation["locked_package_sha256"] == lock["package_sha256"]
    assert archive["bytes"] == 14709858 and archive["hash_matches_locked"] is True
    fresh = json.loads((root / "fresh-install.json").read_text())
    assert fresh["returncode"] == 0 and fresh["fresh_target_before_execution"] is True
    assert fresh["binary_sha256"] == lock["binary_sha256"]
    assert fresh["binary_digest_matches_lock"] is True and fresh["executable"] is True
    assert fresh["version_returncode"] == 0 and fresh["version_matches_lock"] is False
    assert fresh["ok"] is False
    raw = (root / "qemu-version.stdout.log").read_bytes()
    assert raw == lock["version"].encode() + b"\n"
    assert raw.decode().strip() == lock["version"]
    review = json.loads((root / "review.json").read_text())
    assert review["ok"] is True and review["first_observation_ok"] is False
    assert review["native_qualification_repeated"] is False
    for key, name in (("stdout_sha256", "install.stdout.log"),
                      ("stderr_sha256", "install.stderr.log"),
                      ("version_stdout_sha256", "qemu-version.stdout.log"),
                      ("version_stderr_sha256", "qemu-version.stderr.log"),
                      ("lock_sha256", "qemu-toolchain-lock.json")):
        assert fresh[key] == hashlib.sha256((root / name).read_bytes()).hexdigest()
    print(json.dumps({"ok": True, "retained_files": len(inventory["files"]),
                      "scope": "retained byte and observation consistency; no new execution"}))


if __name__ == "__main__":
    verify(Path(__file__).resolve().parent)
