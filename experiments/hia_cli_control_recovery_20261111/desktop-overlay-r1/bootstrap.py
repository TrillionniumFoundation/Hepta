"""Create a new private CLI control root and exec the unchanged guardian."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

os.umask(0o077)
BASE = Path("/home/qian-qi/he26v66devr2")
ROOT = BASE / "cli/run-r4-r1"
SOURCE = BASE / "cli/s"
PYTHON = Path("/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python")
HEAD = "2963cfbffffd9c2d1e87dafbb82466c0daf21615"
TREE = "3e22e800f7dce50e0731736732715f33cc09ba3f"
STABLE_KEY = "hia-e26e-desktop-cli-2963cfbf-development-r4-r1"
required = {
    "driver.py": "fa40782e68ded1744aef9987b9e1c9ce29529aa0dcae9c7f14d8e304c9e8f4bd",
    "source-pins.json": "f3060a690a34ead098518a04aa45fdaaaf22361ceab0de3df27758efafd75ee3",
}
shared = {
    str(BASE / "control/guardian.py"): "d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023",
    str(BASE / "control/process_owner_impl.py"): "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2",
    str(BASE / "control/workflow_process.py"): "f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80",
    str(BASE / "control/old-input-pins.json"): "abff0927d89f94bfdac0d600315e45dca0ceb719b7d3c28c0af17a7e270c1ffc",
    str(BASE / "preparation.json"): "51eabb5fd13572cf981c70cf60b1da1ade05b389651350c031ad715aa798b6dd",
    str(BASE / "guard/guardian.json"): "8e9ffe07b423f20538efea124f7e1666e6ed8823bd0076ec985eaf4a4be2f060",
    str(BASE / "inputs/canonical-e09-development-package.json"): "7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af",
    str(BASE / "inputs/B3.image.bin"): "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8",
}


def identity(s):
    return s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def read_input(path, expected):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
        assert before.st_size <= 32 << 20
        raw = stream.read((32 << 20) + 1)
        assert len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
    assert identity(before) == identity(path.lstat())
    assert sha256(raw).hexdigest() == expected
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert read_input(path, sha256(raw).hexdigest()) == raw


raw_payload = sys.stdin.buffer.read(262145)
assert len(raw_payload) <= 262144
payload = json.loads(raw_payload)
assert payload["stable_key"] == STABLE_KEY and payload["head"] == HEAD and payload["tree"] == TREE
assert set(payload["files"]) == set(required) | {"bootstrap.py"}
assert tuple(sys.version_info[:3]) == (3, 14, 4) and Path(sys.executable).resolve() == PYTHON.resolve()
shared[str(PYTHON.resolve())] = "b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
for item in (BASE, SOURCE, ROOT.parent, *BASE.parents):
    assert not item.is_symlink()
assert not os.path.lexists(ROOT)
for directory in (BASE, SOURCE, ROOT.parent):
    value = directory.lstat()
    assert stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700
capacity = os.statvfs(ROOT.parent)
assert capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000
for path, expected in shared.items():
    read_input(path, expected)
for name, item in payload["files"].items():
    assert Path(name).name == name
    raw = item["source"].encode("utf-8")
    assert sha256(raw).hexdigest() == item["sha256"]
    if name in required:
        assert required[name] == item["sha256"]
pins = json.loads(payload["files"]["source-pins.json"]["source"])
assert pins["source_commit"] == HEAD and pins["source_tree"] == TREE and len(pins["files"]) == 11
old_pins = json.loads(read_input(BASE / "control/old-input-pins.json", shared[str(BASE / "control/old-input-pins.json")]))
assert len(old_pins) == 12
for path, expected in old_pins.items():
    read_input(path, expected)
shared.update(old_pins)

ROOT.mkdir(mode=0o700)
for name in ("control", "guard", "downloads", "receipts", "originals", "home", "tmp"):
    (ROOT / name).mkdir(mode=0o700)
identities = dict(shared)
for name, item in payload["files"].items():
    path = ROOT / "control" / name
    create(path, item["source"].encode("utf-8"))
    identities[str(path)] = item["sha256"]
config = {"schema": "hia-external-guardian-request.v1", "controller_seconds": 900,
          "command": [str(PYTHON), "-B", str(ROOT / "control/driver.py")],
          "cwd": str(ROOT), "source_identities": identities}
raw_config = (json.dumps(config, sort_keys=True, indent=2) + "\n").encode()
create(ROOT / "guard/request.json", raw_config)
intent = {"schema": "hia.cli.desktop-development-launch-intent.v1", "stable_key": STABLE_KEY,
          "source_commit": HEAD, "source_tree": TREE, "source": str(SOURCE), "root": str(ROOT),
          "control_files": {name: item["sha256"] for name, item in payload["files"].items()},
          "planned_download_file_count": 11, "all_downloads_required_before_source_mutation": True,
          "network": "one bounded public GET per exact fixed canonical path; no retry or redirect",
          "preparation_sha256": shared[str(BASE / "preparation.json")],
          "preparation_guard_sha256": shared[str(BASE / "guard/guardian.json")],
          "scope": "EXPLICIT_DEVELOPMENT_ONLY", "whole_native_delivery_qualified": False,
          "complete_git_object_closure": False, "checked_global_contract_current": False,
          "outer_controller_seconds": 900, "cold_180_second_gate_modified": False,
          "old_r3_observations_reused": False, "final_full_source_root_touched": False,
          "source_population": "exact 1666-member base plus ten new files and one declared replacement",
          "capacity_before": {"available_bytes": capacity.f_bavail * capacity.f_frsize,
                              "free_inodes": capacity.f_favail}}
create(ROOT / "launch-intent.json", (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode())
for directory in [ROOT / name for name in ("control", "guard", "downloads", "receipts", "originals", "home", "tmp")] + [ROOT, ROOT.parent]:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
for name in list(os.environ):
    if name.startswith("HEPTA_HIA_") or name in ("PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE"):
        os.environ.pop(name, None)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONUNBUFFERED"] = "1"
print(json.dumps({"stage": "CLI_DEVELOPMENT_GUARDIAN_LAUNCH", "root": str(ROOT),
                  "source_commit": HEAD, "controller_seconds": 900}), flush=True)
os.execv(str(PYTHON), [str(PYTHON), "-B", str(BASE / "control/guardian.py"),
                     "--config", str(ROOT / "guard/request.json"),
                     "--config-sha256", sha256(raw_config).hexdigest(),
                     "--implementation", str(BASE / "control/process_owner_impl.py")])
