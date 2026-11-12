"""Read the completed source4 originals; never execute a product or control."""
from pathlib import Path
import hashlib
import io
import json
import stat
import tarfile

BASE = Path("/workspace/scratch/e26ed3e2edcf/core-numeric-source83-generator-repair-r2")
ACTUAL = BASE / "actual-source4-r2"
OUT = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
    raw = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    assert all(getattr(before, key) == getattr(after, key) for key in fields)
    return raw, before


def main():
    request = json.loads((BASE / "SOURCE4-REQUEST.json").read_bytes())
    report = json.loads((ACTUAL / "SOURCE4.json").read_bytes())
    life = json.loads((ACTUAL / "lifecycle.json").read_bytes())
    wrapper = json.loads((ACTUAL / "owner-wrapper.json").read_bytes())
    final = json.loads((ACTUAL / "FINAL.json").read_bytes())
    assert wrapper["receipt_sha256"] == sha((ACTUAL / "lifecycle.json").read_bytes())
    assert {key: value for key, value in wrapper.items() if key not in {"receipt_sha256", "supervisor_returncode"}} == life
    assert final["status"] == "SOURCE4_PASS" and final["closed_owner_confirmed"] is True
    assert report["expected_ids"] == report["loaded_ids"] == report["executed_ids"] == request["expected_ids"]
    assert len(request["expected_ids"]) == 4
    anomaly_names = ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses",
                     "native_or_compiler_or_process_attempts")
    assert all(report[key] == [] for key in anomaly_names)
    assert life["status"] == "OWNED_PROCESS_COMPLETED" and life["returncode"] == wrapper["supervisor_returncode"] == 0
    assert life["timed_out"] is False and life["cleanup"]["complete"] and life["cleanup"]["observed_echild"]
    assert life["cleanup"]["leader_reaped"] and life["cleanup"]["remaining_direct_children"] == [] and life["cleanup"]["errors"] == []
    assert [row["kind"] for row in life["events"]] == ["qualification_started", "owned_child_observed",
                                                       "qualification_exit_observed", "owned_child_reaped"]
    before = (ACTUAL / "cases/INPUTS-BEFORE.json").read_bytes()
    after = (ACTUAL / "cases/INPUTS-AFTER.json").read_bytes()
    assert before == after and len(json.loads(before)) == len(request["input_pins"]) == 1685
    indexed = json.loads((ACTUAL / "ORIGINALS.json").read_bytes())["files"]
    seen = set()
    for row in indexed:
        path = Path(row["path"])
        raw, st = read(path)
        assert path.is_relative_to(ACTUAL) and len(raw) == row["size"] and sha(raw) == row["sha256"]
        assert blob(raw) == row["git_blob_sha1"]
        actual = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid, "nlink": st.st_nlink,
                  "device": st.st_dev, "inode": st.st_ino, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}
        assert all(row[key] == value for key, value in actual.items())
        seen.add(path)
    paths = sorted(path for path in ACTUAL.rglob("*") if path.is_file())
    assert set(paths) == seen | {ACTUAL / "ORIGINALS.json"} and len(paths) == 33
    outputs = json.loads((ACTUAL / "cases/test_all_four_hia_outputs_reproduce_with_external_entries_poisoned/OUTPUTS.json").read_bytes())
    assert len(outputs) == 4
    for row in outputs:
        owner = "artifact_publication" if "artifact_publication" in row["path"] else "release_install"
        path = ACTUAL / "cases/test_all_four_hia_outputs_reproduce_with_external_entries_poisoned" / owner / row["path"]
        raw, _ = read(path)
        assert raw == (BASE / "reference" / row["path"]).read_bytes()
        assert len(raw) == row["bytes"] and sha(raw) == row["sha256"]
    records = []
    for path in paths:
        raw, st = read(path)
        records.append({"path": str(path.relative_to(ACTUAL)), "size": len(raw), "sha256": sha(raw),
                        "git_blob_sha1": blob(raw), "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid,
                        "gid": st.st_gid, "device": st.st_dev, "inode": st.st_ino,
                        "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns, "nlink": st.st_nlink})
    manifest_raw = (json.dumps({"schema": "hepta.hia.fixed-transport-source4-actual-originals.v1",
                                "files": records}, indent=2, sort_keys=True) + "\n").encode()
    with (OUT / "MANIFEST.json").open("xb") as stream:
        stream.write(manifest_raw)
    archive = OUT / "originals.tar.xz"
    with tarfile.open(archive, "x:xz", preset=6) as tar:
        for row, path in zip(records, paths):
            raw, st = read(path)
            info = tarfile.TarInfo(row["path"])
            info.size, info.mode, info.uid, info.gid, info.mtime = len(raw), row["mode"], row["uid"], row["gid"], st.st_mtime
            tar.addfile(info, io.BytesIO(raw))
        info = tarfile.TarInfo("MANIFEST.json")
        info.size, info.mode = len(manifest_raw), 0o644
        tar.addfile(info, io.BytesIO(manifest_raw))
    with tarfile.open(archive, "r:xz") as tar:
        assert [entry.name for entry in tar.getmembers()] == [row["path"] for row in records] + ["MANIFEST.json"]
        for row in records:
            raw = tar.extractfile(row["path"]).read()
            assert len(raw) == row["size"] and sha(raw) == row["sha256"]
            assert raw == (ACTUAL / row["path"]).read_bytes()
        assert tar.extractfile("MANIFEST.json").read() == manifest_raw
    raw = archive.read_bytes()
    audit = {
        "schema": "hepta.hia.fixed-transport-source4-actual-audit.v1",
        "status": "SOURCE4_ORIGINALS_READBACK_PASS", "source4_status": report["status"],
        "seconds": report["seconds"], "expected_ids": report["expected_ids"],
        "anomalies": {key: report[key] for key in anomaly_names},
        "input_pins_count": 1685, "separate_control_pin_checks": 6,
        "inputs_before_after_bytes": len(before), "inputs_sha256": sha(before),
        "indexed_originals": len(indexed), "indexed_bytes": sum(row["size"] for row in indexed),
        "all_original_files": len(records), "all_original_bytes": sum(row["size"] for row in records),
        "generated_outputs": outputs,
        "source4_request_sha256": sha((BASE / "SOURCE4-REQUEST.json").read_bytes()),
        "launch_sha256": sha((BASE / "SOURCE4-LAUNCH.json").read_bytes()),
        "frozen_code_canonical": "8c8506c76c9cf9ea85972ba091354a4fceb84720",
        "local_request_frozen_before_execution": True, "canonical_commit_ack_after_execution_message": True,
        "archive": {"path": str(archive), "size": len(raw), "sha256": sha(raw), "git_blob_sha1": blob(raw)},
        "archive_complete_readback": True, "new_execution_by_auditor": False,
        "native_executed": False, "source83_executed": False, "assembler_oracle_executed": False,
        "prior_reader_error": "r1 mistakenly required 1691 inputs; the original request has1685, while6 separate control-pin validations give1691 total checks.",
    }
    with (OUT / "AUDIT.json").open("x") as stream:
        json.dump(audit, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(audit))


if __name__ == "__main__":
    main()

