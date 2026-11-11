"""Preserve one terminal CLI HOLD tree; never run or edit product sources."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import traceback

ROOT = Path("/home/qian-qi/he26-cli-r4-retention-r1")
SOURCE = Path("/home/qian-qi/he26v66devr2/cli/run-r4-r1")
HELPER_SHA = "eedc066713a42c23caaa0bd6b0593a626181ef29ac3f24f4a36535a4c11e8de9"

def key(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
        raw = stream.read()
        assert key(before) == key(os.fstat(stream.fileno())) and len(raw) == before.st_size
    assert key(before) == key(path.lstat())
    return raw

def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    assert read(path) == raw

def natural_failure(value, outer=False):
    x = value["lifecycle"] if outer else value
    cleanup = x["cleanup"]
    return (x["returncode"] == 1 and x["exit_observed_before_deadline"] is True
            and x["timed_out"] is False and not x.get("interrupted_signals")
            and not x.get("owner_error") and not x.get("event_overflow")
            and bool(x["events"])
            and all(e["kind"] in {"qualification_started", "owned_child_observed",
                                 "qualification_exit_observed", "owned_child_reaped"} for e in x["events"])
            and cleanup["attempted"] is True and cleanup["complete"] is True
            and cleanup["leader_reaped"] is True and cleanup["observed_echild"] is True
            and cleanup["remaining_direct_children"] == [] and not cleanup["errors"]
            and not cleanup["deadline_exceeded"]
            and (not outer or value["status"] == "HOLD" and value["input_identity_preserved"] is True))

report = {"schema": "hia.cli.original-failure-retention.v1", "status": "HOLD",
          "original_job": "1a1cb04f203-2564-996",
          "original_product_commit": "2963cfbffffd9c2d1e87dafbb82466c0daf21615",
          "original_product_status": "HOLD", "source": str(SOURCE),
          "retention_helper_sha256": HELPER_SHA, "product_tests_rerun": False,
          "product_source_modified": False, "whole_native_delivery_qualified": False}
try:
    status = json.loads(read(ROOT / "control/original-job-status.json"))
    assert status["job_id"] == report["original_job"] and status["state"] == "failed"
    assert status["exit_code"] == 1 and status["output_complete"] is True and status["output_durable"] is True
    assert status["terminal_publication_confirmed"] is True and status["timed_out"] is False
    source_stat = SOURCE.lstat()
    assert stat.S_ISDIR(source_stat.st_mode) and source_stat.st_uid == os.geteuid()
    root_identity = key(source_stat)
    originals = {name: read(SOURCE / name) for name in
                 ("guard/guardian.json", "q/process-owner.json", "q/owned-suite.json",
                  "q/suite.json", "q/stderr.log", "report.json")}
    assert natural_failure(json.loads(originals["guard/guardian.json"]), outer=True)
    assert natural_failure(json.loads(originals["q/process-owner.json"]))
    assert json.loads(originals["report.json"])["status"] == "HOLD"
    helper = ROOT / "control/retain_typed_directory.py"
    assert sha256(read(helper)).hexdigest() == HELPER_SHA
    spec = importlib.util.spec_from_file_location("pinned_typed_retention", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.argv = [str(helper), "--source", str(SOURCE), "--output", str(ROOT / "originals")]
    module.main()
    receipt_raw = read(ROOT / "originals/retention.json")
    receipt = json.loads(receipt_raw)
    assert receipt["status"] == "EXACT_MEMBER_READBACK_PASS"
    assert receipt["source"] == str(SOURCE)
    assert receipt["archive"] == str(ROOT / "originals/originals.tar.gz")
    assert receipt["original_tree_preserved"] is True and receipt["original_tree_read_again_after_archive"] is True
    assert receipt["symlink_targets_preserved_as_text_not_followed_or_extracted"] is True
    archive = ROOT / "originals/originals.tar.gz"
    digest = sha256(); size = 0
    fd = os.open(archive, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        initial = key(os.fstat(stream.fileno()))
        while part := stream.read(1 << 20):
            size += len(part); digest.update(part)
        assert key(os.fstat(stream.fileno())) == initial
    assert key(archive.lstat()) == initial
    assert size == receipt["archive_bytes"] and digest.hexdigest() == receipt["archive_sha256"]
    assert key(SOURCE.lstat()) == root_identity
    assert all(read(SOURCE / name) == raw for name, raw in originals.items())
    report.update(status="ORIGINALS_PRESERVED_PENDING_OUTER_GUARDIAN",
                  source_root_identity=list(root_identity),
                  original_record_pins={name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
                                        for name, raw in originals.items()},
                  typed_manifest={"path": str(ROOT / "originals/retention.json"),
                                  "bytes": len(receipt_raw), "sha256": sha256(receipt_raw).hexdigest()},
                  archive={k: receipt[k] for k in ("archive", "archive_bytes", "archive_sha256",
                           "members", "regular_members", "independently_read_regular_bytes",
                           "symlink_members", "directory_members")},
                  independently_rehashed_archive=True, original_root_and_terminal_records_preserved=True)
except BaseException as error:
    report.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
finally:
    write(ROOT / "preservation.json", (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    for directory in (ROOT / "originals", ROOT / "control", ROOT / "guard", ROOT, ROOT.parent):
        if not directory.exists():
            continue
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    print(json.dumps(report, sort_keys=True), flush=True)
raise SystemExit(0 if report["status"] == "ORIGINALS_PRESERVED_PENDING_OUTER_GUARDIAN" else 1)
