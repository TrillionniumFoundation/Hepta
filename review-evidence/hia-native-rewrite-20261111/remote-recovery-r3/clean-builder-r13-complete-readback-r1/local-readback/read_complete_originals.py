"""Independent complete local readback of the sealed FOLLOW55B R13 artifact.

No original project module, authoring, compiler, installer or target is run.
The ZIP transport modes and the original tar member modes are recorded separately.
"""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time
import traceback
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent
ZIP = ROOT.parent / "artifacts/follow55b-r13-original-readback.zip"
OUT = ROOT / "complete-original-readback-r1"
PREFIX = "hia-namespace-engine-original-sources/clean-build-r13-originals-r1/"
CHUNK = 1 << 20


def digest(path):
    before = path.stat()
    sh = sha256()
    gh = sha1(b"blob " + str(before.st_size).encode("ascii") + b"\0")
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(CHUNK):
            size += len(block)
            sh.update(block)
            gh.update(block)
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mode) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mode)
    assert size == before.st_size
    return {"bytes": size, "sha256": sh.hexdigest(), "gitsha": gh.hexdigest(),
            "mode": stat.S_IMODE(after.st_mode)}


def relative(name):
    pure = PurePosixPath(name)
    assert name and not pure.is_absolute() and pure.as_posix() == name
    assert all(part not in ("", ".", "..") for part in pure.parts)
    return pure


def save(path, obj):
    raw = (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    assert path.read_bytes() == raw


def require(actual, expected, keys=("bytes", "sha256", "mode")):
    for key in keys:
        assert actual[key] == expected[key], (key, actual, expected)


def main():
    OUT.mkdir()
    source_before = digest(Path(__file__))
    zip_before = digest(ZIP)
    assert zip_before["bytes"] == 209940236
    assert zip_before["sha256"] == "26c8578feb1cf2457895d3a8f025cc03639a2c98bd501291eff09d585041e223"
    started = time.monotonic_ns()
    result = {"schema": "hia-r13-independent-local-original-readback-r1", "status": "INCOMPLETE",
              "scope": "READONLY_ORIGINALS_NO_TARGET_EXECUTION_NOT_QUALIFICATION", "ZIP": zip_before}
    outer_rows = []
    tar_rows = []
    failure_exc = None
    failure_traceback = None
    try:
        with ZipFile(ZIP) as archive:
            seen = set()
            for info in archive.infolist():
                assert info.filename not in seen
                seen.add(info.filename)
                path = OUT / "outer" / relative(info.filename)
                assert not info.is_dir() and not info.flag_bits & 1
                assert stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, path.open("xb") as target:
                    while block := source.read(CHUNK):
                        target.write(block)
                actual = digest(path)
                assert actual["bytes"] == info.file_size
                outer_rows.append({"path": info.filename, "bytes": actual["bytes"],
                                   "sha256": actual["sha256"], "gitsha": actual["gitsha"],
                                   "ZIP_mode": (info.external_attr >> 16) & 0o7777,
                                   "ZIP_CRC32": info.CRC})
        assert len(outer_rows) == 667
        assert sum(row["bytes"] for row in outer_rows) == 209693034
        recovered = OUT / "outer" / PREFIX
        summary = json.loads((recovered / "summary.json").read_bytes())
        ledger = json.loads((recovered / "original-members.json").read_bytes())
        custody = json.loads((recovered / "originals/custody.json").read_bytes())
        config = json.loads((recovered / "original-inputs.json").read_bytes())
        outputs = json.loads((recovered / "retained-output-custody.json").read_bytes())
        assert summary["status"] == "PASS" and summary["primary_error"] is None
        assert summary["secondary_errors"] == [] and summary["pending_outputs"] == {}
        assert summary["complete_original_archive_and_814_members_retained_and_afterchecked"] is True
        assert summary["observed_members"] == 814 and summary["observed_files"] == 661
        assert summary["observed_directories"] == 153 and summary["observed_raw_file_bytes"] == 171212656
        assert summary["usage_after_output"]["aggregate_cpu_seconds"] < 90
        assert summary["usage_after_output"]["elapsed_ns"] < 180000000000
        for key in ("AST_executed", "B3_executed", "native_target_executed", "source_generation_executed",
                    "historical_target_results_replayed", "original_source_imported"):
            assert summary[key] is False
        assert json.loads((recovered / "pending-originals.json").read_bytes()) == {}
        assert json.loads((recovered / "primary-error.json").read_bytes()) is None
        require(digest(recovered / "reader-source.py"), {"bytes": 22753, "mode": 0o644,
            "sha256": "8339257f6031e5eea44dcf088f65ab494994194645b71dfea62755702f291b3e"})
        require(digest(recovered / "original-inputs.json"), {"bytes": 11485, "mode": 0o644,
            "sha256": "61a08494ceeb3b3142ecd312881375d206e0fe0ed8d5d685fd90a69f8051d9f5"})
        inner = recovered / "originals/hia-native-clean-build-r1-development.tar.xz"
        inner_pin = digest(inner)
        assert inner_pin["bytes"] == custody["archive_bytes"] == config["archive"]["bytes"] == 57162628
        assert inner_pin["sha256"] == custody["archive_sha256"] == config["archive"]["sha256"] == "721d89da963f863e3760d9577f3585b0cd9d6f3c71a36ee597d975baf12e388b"
        expected = {row["path"]: row for row in custody["members"]}
        observed = {row["path"]: row for row in ledger}
        assert len(expected) == len(custody["members"]) == len(observed) == len(ledger) == 814
        assert set(expected) == set(observed)
        original = ROOT / "original-r13"
        original.mkdir()
        dirs = []
        with tarfile.open(inner, "r:xz") as archive:
            seen = set()
            for item in archive:
                name = item.name.rstrip("/")
                assert name not in seen and name in expected
                seen.add(name)
                row = expected[name]
                path = original / relative(name)
                assert not item.issparse() and not item.issym() and not item.islnk()
                assert item.mode == row["mode"] == observed[name]["mode"]
                if row["kind"] == "directory":
                    assert item.isdir()
                    path.mkdir(parents=True, exist_ok=True)
                    dirs.append((path, item.mode))
                    actual = {"path": name, "kind": "directory", "mode": item.mode}
                else:
                    assert item.isfile() and item.size == row["bytes"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(item) as source, path.open("xb") as target:
                        while block := source.read(CHUNK):
                            target.write(block)
                    path.chmod(item.mode)
                    pin = digest(path)
                    require(pin, row)
                    require(pin, observed[name], ("bytes", "sha256", "gitsha", "mode"))
                    actual = {"path": name, "kind": "file", **pin}
                tar_rows.append(actual)
            assert seen == set(expected)
        for path, mode in sorted(dirs, key=lambda row: len(row[0].parts), reverse=True):
            path.chmod(mode)
        assert sum(row.get("bytes", 0) for row in tar_rows) == 171212656
        # Artifact upload may omit hidden loose duplicates. The full original
        # archive remains authoritative and has just been verified in full.
        present = []
        omitted = []
        for row in tar_rows:
            path = original / row["path"]
            assert stat.S_IMODE(path.stat().st_mode) == row["mode"]
            if row["kind"] != "file":
                continue
            require(digest(path), row, ("bytes", "sha256", "gitsha", "mode"))
            loose = recovered / "restored" / row["path"]
            if loose.is_file():
                require(digest(loose), row, ("bytes", "sha256", "gitsha"))
                present.append(row["path"])
            else:
                omitted.append({"path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"]})
        assert len(present) + len(omitted) == 661
        for row in config["exports"]:
            require(digest(original / row["path"]), row)
        assert len(config["exports"]) == len(summary["exports"]) == 21
        for row in summary["exports"]:
            require(digest(original / row["path"]), row, ("bytes", "sha256", "gitsha", "mode"))
        output_missing = []
        for absolute, pin in outputs.items():
            marker = "/hia-namespace-engine-original-sources/clean-build-r13-originals-r1/"
            assert absolute.count(marker) == 1
            relative_output = absolute.split(marker, 1)[1]
            path = recovered / relative(relative_output)
            if path.is_file():
                require(digest(path), pin, ("bytes", "sha256", "gitsha"))
            else:
                assert relative_output.startswith("restored/")
                require(digest(original / relative_output[len("restored/"):]), pin)
                output_missing.append(relative_output)
        result.update(status="PASS", outer_members=len(outer_rows), outer_raw_bytes=209693034,
                      inner=inner_pin, original_members=len(tar_rows), original_files=661,
                      original_directories=153, original_raw_file_bytes=171212656,
                      final_summary=digest(recovered / "summary.json"), final_summary_status=summary["status"],
                      reader_usage_after_output=summary["usage_after_output"],
                      original_text_exports=21, present_uploaded_loose_originals=len(present),
                      omitted_loose_duplicates_recovered_from_full_inner_tar=omitted,
                      retained_output_missing_loose_duplicates=output_missing,
                      all_original_bytes_and_modes_recovered=True,
                      original_target_executions=0, new_product_qualification=False)
    except BaseException as exc:
        result.update(status="FAIL", error_class=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
        failure_exc, failure_traceback = exc, exc.__traceback__
    finally:
        errors = []
        for label, path, pin in [("ZIP", ZIP, zip_before), ("reader", Path(__file__), source_before)]:
            try:
                assert digest(path) == pin
            except BaseException as exc:
                errors.append({"source": label, "error": repr(exc)})
        result["input_after_errors"] = errors
        result["elapsed_ns"] = time.monotonic_ns() - started
        if errors:
            result["status"] = "FAIL"
            if failure_exc is None:
                failure_exc = RuntimeError("source after-check failed: " + repr(errors))
        for path, payload in [(OUT / "outer-members.json", outer_rows),
                              (OUT / "original-members-independent.json", tar_rows),
                              (OUT / "summary.json", result)]:
            try:
                save(path, payload)
            except BaseException as exc:
                result["status"] = "FAIL"
                if failure_exc is None:
                    failure_exc, failure_traceback = exc, exc.__traceback__
                else:
                    failure_exc.add_note("Additional receipt failure: " + repr(exc))
        try:
            print(json.dumps({k: v for k, v in result.items() if k not in (
                "omitted_loose_duplicates_recovered_from_full_inner_tar", "retained_output_missing_loose_duplicates")}, sort_keys=True), flush=True)
        except BaseException as exc:
            if failure_exc is None:
                failure_exc, failure_traceback = exc, exc.__traceback__
            else:
                failure_exc.add_note("Additional stdout failure: " + repr(exc))
    if failure_exc is not None:
        raise failure_exc.with_traceback(failure_traceback)


if __name__ == "__main__":
    main()
