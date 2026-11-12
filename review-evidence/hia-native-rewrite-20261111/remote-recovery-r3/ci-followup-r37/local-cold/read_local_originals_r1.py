"""Read the complete preserved local failed cold archive; execute no subject."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import stat
import subprocess
import tarfile
import time

PREFIX = "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
MANIFEST = PREFIX + "ci-followup-r37/local-cold/archive-parts.json"

def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                gitsha=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())

def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def main():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.alarm(180)
    affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(affinity)})
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    out = Path(os.environ["HIA_CI_OUTPUT"]).resolve()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    before_manifest = (root / MANIFEST).read_bytes()
    index = json.loads(before_manifest)
    head = subprocess.check_output(["git", "--no-replace-objects", "-c",
        "core.packedGitWindowSize=16m", "-c", "core.packedGitLimit=64m",
        "rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert head == os.environ["GITHUB_SHA"]
    archive = out / index["archive_name"]
    parts = index["parts"]
    assert len(parts) == 43
    position = 0
    paths = set()
    with archive.open("xb") as stream:
        for row in parts:
            name = PurePosixPath(row["path"])
            assert not name.is_absolute() and ".." not in name.parts
            assert row["path"] not in paths and row["offset"] == position
            paths.add(row["path"])
            path = root / row["path"]
            assert path.is_file() and not path.is_symlink()
            raw = path.read_bytes()
            assert identity(raw) == {k: row[k] for k in ("bytes", "sha256", "gitsha")}
            assert format(path.stat().st_mode, "o") == row["mode"]
            stream.write(raw)
            position += len(raw)
    assert position == index["archive_bytes"]
    with archive.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == index["archive_sha256"]
    selected = {
        "drivers/restoration37-cold.json", "prerequisites/summary.json",
        "prerequisites/unittest.stderr.log", "qualification/process-owner.json",
        "qualification/qualification.evidence/phase-index.json",
        "qualification/qualification.evidence/B3.receipt.json",
        "qualification/qualification.evidence/B3.request.json",
        "qualification/qualification.evidence/B3.stdout.log",
    }
    rows, saved = {}, {}
    with tarfile.open(archive, mode="r|xz") as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and ".." not in name.parts
            assert member.name not in rows
            row = dict(mode=member.mode)
            if member.isfile():
                with tar.extractfile(member) as stream:
                    if member.name in selected:
                        raw = stream.read()
                        digest = hashlib.sha256(raw).hexdigest()
                        target = out / "exact-originals" / member.name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(raw)
                        target.chmod(member.mode)
                        saved[member.name] = identity(raw)
                    else:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                row.update(kind="file", bytes=member.size, sha256=digest)
            elif member.issym():
                row.update(kind="symlink", target=member.linkname)
            elif member.isdir():
                row.update(kind="directory")
            else:
                raise ValueError("unsupported tar member")
            rows[member.name] = row
            tar.members.clear()
    original_index = json_bytes(rows)
    assert len(original_index) == index["original_member_index_bytes"]
    assert hashlib.sha256(original_index).hexdigest() == index["original_member_index_sha256"]
    (out / "exact-original-member-index.json").write_bytes(original_index)
    assert len(rows) == index["original_members"]
    assert sum(r["kind"] == "file" for r in rows.values()) == index["original_regular_files"]
    assert sum(r.get("bytes", 0) for r in rows.values()) == index["original_regular_bytes"]
    assert selected <= saved.keys()
    cold = json.loads((out / "exact-originals/drivers/restoration37-cold.json").read_bytes())
    tests = json.loads((out / "exact-originals/prerequisites/summary.json").read_bytes())
    phases = json.loads((out / "exact-originals/qualification/qualification.evidence/phase-index.json").read_bytes())
    assert cold["status"] == "FAIL" and cold["returncode"] == -9
    assert sum(value is True for value in cold["checks"].values()) == 6 and len(cold["checks"]) == 11
    assert cold["wall_elapsed_ns"] == index["original_cold_wall_ns"]
    assert phases["completed"] == 26 and len(phases["phases"]) == 38
    assert tests["status"] == "PASS" and tests["tests_loaded"] == tests["tests_run"] == 13
    assert all(tests[key] == [] for key in ("errors", "failures", "skipped", "expected_failures", "unexpected_successes"))
    for row in parts:
        assert identity((root / row["path"]).read_bytes()) == {k: row[k] for k in ("bytes", "sha256", "gitsha")}
    assert (root / MANIFEST).read_bytes() == before_manifest
    report = dict(schema="hia-complete-local-cold-original-readback-v1",
        status="PASS_READBACK_ONLY", source_head=head, archive_sha256=index["archive_sha256"],
        members=len(rows), original_bytes=index["original_regular_bytes"],
        original_member_index_exact_sha256=index["original_member_index_sha256"],
        every_original_archive_byte_mode_link_checked=True,
        current_original_filesystem_available=False,
        original_cold_status="FAIL", original_cold_checks_passed=6,
        original_cold_checks_total=11, original_completed_phases=26,
        original_total_phases=38, original_source_controls=13,
        B3_image=rows["qualification/qualification.evidence/B3.image.bin"],
        exact_original_records=saved, native_entries=0, B3_compiles=0,
        whole_stack_closed=False, wall_ns=time.monotonic_ns() - started)
    (out / "summary.json").write_bytes(json_bytes(report))
    print("HIA_LOCAL_COLD_COMPLETE_READBACK " + json.dumps(report, sort_keys=True), flush=True)
    signal.alarm(0)

if __name__ == "__main__":
    main()
