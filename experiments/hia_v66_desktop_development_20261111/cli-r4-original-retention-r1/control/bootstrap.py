"""Create a new private evidence root and exec the unchanged process guardian."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
os.umask(0o077)
ROOT = Path("/home/qian-qi/he26-cli-r4-retention-r1")
SOURCE = Path("/home/qian-qi/he26v66devr2/cli/run-r4-r1")
PYTHON = Path("/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python")
KEY = "hia-e26e-desktop-cli-2963cfbf-r4-originals-retention-r1"
PINNED = {
    "driver.py": "775ede1e5d7c546f025fb0e53379b55d1b11bf1279d29def7885556a5fee81fa",
    "retain_typed_directory.py": "eedc066713a42c23caaa0bd6b0593a626181ef29ac3f24f4a36535a4c11e8de9",
    "original-job-status.json": "010f64a8959bdfb1790ddf1018b91849c0d45767f2fd532da22186917bd85f14",
    "guardian.py": "d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023",
    "process_owner_impl.py": "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2",
}
def identity(s):
    return s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns
def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
        raw = stream.read()
        assert len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
    assert identity(before) == identity(path.lstat())
    return raw
def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    assert read(path) == raw
raw = sys.stdin.buffer.read(262145)
assert len(raw) <= 262144
payload = json.loads(raw)
assert payload["stable_key"] == KEY and set(payload["files"]) == set(PINNED) | {"bootstrap.py"}
for name, value in payload["files"].items():
    content = value["source"].encode()
    assert sha256(content).hexdigest() == value["sha256"]
    if name in PINNED:
        assert value["sha256"] == PINNED[name]
assert sys.version_info[:3] == (3, 14, 4) and Path(sys.executable).resolve() == PYTHON.resolve()
python_file = PYTHON.resolve()
assert sha256(read(python_file)).hexdigest() == "b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
for path in (ROOT.parent, *ROOT.parent.parents, SOURCE, *SOURCE.parents):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and not path.is_symlink()
assert not os.path.lexists(ROOT)
assert SOURCE.lstat().st_uid == os.geteuid()
assert SOURCE != ROOT and SOURCE not in ROOT.parents
guard_raw = read(SOURCE / "guard/guardian.json")
guard = json.loads(guard_raw)
assert guard["status"] == "HOLD" and guard["input_identity_preserved"] is True
assert guard["lifecycle"]["returncode"] == 1
assert guard["lifecycle"]["cleanup"]["complete"] is True
assert guard["lifecycle"]["cleanup"]["observed_echild"] is True
assert guard["lifecycle"]["cleanup"]["remaining_direct_children"] == []
ROOT.mkdir(mode=0o700)
for name in ("control", "guard", "home", "tmp"):
    (ROOT / name).mkdir(mode=0o700)
identities = {str(python_file): "b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493",
              str(SOURCE / "guard/guardian.json"): sha256(guard_raw).hexdigest()}
for name, value in payload["files"].items():
    path = ROOT / "control" / name
    create(path, value["source"].encode())
    identities[str(path)] = value["sha256"]
config = {"schema": "hia-external-guardian-request.v1", "controller_seconds": 600,
          "command": [str(PYTHON), "-B", str(ROOT / "control/driver.py")],
          "cwd": str(ROOT), "source_identities": identities}
request = (json.dumps(config, sort_keys=True, indent=2) + "\n").encode()
create(ROOT / "guard/request.json", request)
intent = {"schema": "hia.cli.failure-retention-launch.v1", "stable_key": KEY,
          "original_job_id": "1a1cb04f203-2564-996", "original_source": str(SOURCE),
          "original_product_status": "HOLD", "destination": str(ROOT),
          "controller_seconds": 600, "source_identities": identities,
          "product_tests_run": False, "product_sources_modified": False,
          "archive_type": "PAX tar+gzip; typed regular/directory/symlink target text",
          "archive_extracted": False, "source_originals_deleted": False,
          "hard_sigkill_or_host_loss_cleanup_claimed": False}
create(ROOT / "launch-intent.json", (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode())
for directory in [ROOT / name for name in ("control", "guard", "home", "tmp")] + [ROOT, ROOT.parent]:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)
os.environ.clear()
os.environ.update(PATH=os.defpath, HOME=str(ROOT / "home"), TMPDIR=str(ROOT / "tmp"),
                  LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC",
                  PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
print(json.dumps({"stage": "CLI_ORIGINALS_RETENTION_LAUNCH", "stable_key": KEY, "root": str(ROOT)}), flush=True)
os.execv(str(PYTHON), [str(PYTHON), "-B", str(ROOT / "control/guardian.py"),
                     "--config", str(ROOT / "guard/request.json"),
                     "--config-sha256", sha256(request).hexdigest(),
                     "--implementation", str(ROOT / "control/process_owner_impl.py")])
