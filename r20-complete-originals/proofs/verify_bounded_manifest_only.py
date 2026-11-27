"""Read fixed R20 bounded originals; never import or execute product code."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import time
import traceback
import zipfile

from verify_source_execution import parse, pin, check_pin, safe


ROOT = Path(__file__).resolve().parent
HARNESS = ROOT.parent / "v120-source-parser-r20-harness/formal-preparation-r1/harness"
SOURCE_READBACK = ROOT / "source-manifest-readback-r1"
OUT = ROOT / "bounded-manifest-readback-r1"


def save(name, value):
    target = OUT / safe(name)
    assert not target.exists() and not target.is_symlink()
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with target.open("xb") as stream:
        stream.write(raw)
    assert target.read_bytes() == raw


def main():
    started = time.monotonic()
    config = parse((ROOT / "ARTIFACT-PINS.json").read_bytes())
    custody = parse((ROOT / "custody-stream-r1/REPORT.json").read_bytes())
    source_proof = parse((SOURCE_READBACK / "REPORT.json").read_bytes())
    restored = parse((SOURCE_READBACK / "CANDIDATE-MANIFEST.json").read_bytes())
    assert config["run"] == custody["run"] == source_proof["run"] == 43553551892
    assert config["job"] == custody["job"] == source_proof["job"] == 132321186937
    assert config["head"] == custody["head"] == source_proof["head"] == "28b8e6f5b44022f9d6e90d561573d41f0f7e8633"
    assert custody["status"] == "CUSTODY_PASS_EXECUTION_STATUS_RECORDED_SEPARATELY"
    assert source_proof["source_outcome"] == "PASS" and source_proof["source_tests_run"] == 1421
    assert len(restored) == source_proof["source_files"] == 3177
    changed = {row["path"] for row in source_proof["prepared_vs_formal_differences"]}
    def verified_source(name):
        name = str(safe(name))
        origin = SOURCE_READBACK / "changed-source" if name in changed else ROOT.parent / "v120-union-r20/source"
        path = origin / name
        assert path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        check_pin(raw, restored[name])
        assert (path.stat().st_mode & 0o777) == restored[name]["mode"]
        return raw
    assert not OUT.exists()
    OUT.mkdir()
    expected_raw = (HARNESS / "inputs/FORMAL-EXPECTED-IDS.json").read_bytes()
    expected = parse(expected_raw)
    controls_raw = (HARNESS / "inputs/PARSER-CONTROLS.json").read_bytes()
    controls = parse(controls_raw)
    source_root = ROOT / "custody-stream-r1/combined-source/raw"
    source_result_raw = (source_root / "RESULT.json").read_bytes()
    source_tests_raw = (source_root / "checks/SOURCE-TESTS.json").read_bytes()
    projected_source = {name: {key: row[key] for key in ("bytes", "sha256", "mode")}
                        for name, row in restored.items()}
    with zipfile.ZipFile(ROOT / config["artifacts"]["parser-bounded"]["file"]) as archive:
        bounded_raw = archive.read("RESULT.json")
        bounded = parse(bounded_raw)
        assert archive.read("PARSER-CONTROLS.json") == controls_raw
        assert archive.read("FORMAL-EXPECTED-IDS.json") == expected_raw
        assert archive.read("FULL-SOURCE-RESULT.json") == source_result_raw
        assert archive.read("FULL-SOURCE-TESTS.json") == source_tests_raw
        assert parse(archive.read("FIXED-SOURCE-MANIFEST.json")) == restored
        assert parse(archive.read("FINAL-SOURCE-MANIFEST.json")) == restored
        assert bounded["status"] == "PASS" and not bounded["failures"]
        assert bounded["source_unchanged"] is True and bounded["required_tests"] == bounded["tests_run"] == 62
        assert bounded["python"].startswith("3.14.4 ") and "/Python/3.14.4/" in bounded["executable"]
        assert bounded["compiler_scope"] == "EXPLICIT_DEVELOPMENT_B3_NOT_COLD"
        assert bounded["current_source_cold_qualification"] is False and bounded["whole_native"] is False
        assert bounded["product_refs_changed"] is False
        assert bounded["source_authority"]["source_tree"] == source_proof["source_tree"]
        assert bounded["source_authority"]["source_files"] == 3177
        assert bounded["source_authority"]["required_original_projection"] == 1329
        check_pin(source_result_raw, bounded["source_authority"]["result"])
        check_pin(source_tests_raw, bounded["source_authority"]["source_tests"])
        assert bounded["packaging_versions"]["setuptools"] == "78.1.1"
        assert bounded["packaging_versions"]["wheel"] == "0.46.3"
        for name, expected_pin in controls["harness_files"].items():
            actual = archive.read("harness/" + str(safe(name)))
            check_pin(actual, expected_pin)
            assert actual == (HARNESS / name).read_bytes()
        assert controls["budgets"] == {"capacity": 1048576, "cleanup_seconds": 3,
            "compile_seconds": 20, "qualification_seconds": 180, "vm_fuel": 10000000}
        compiler = bytearray()
        for part in controls["compiler"]["parts"]:
            encoded = (HARNESS / part["path"]).read_bytes()
            check_pin(encoded, part["encoded"])
            decoded = base64.b64decode(encoded, validate=True)
            check_pin(decoded, part["decoded"])
            compiler.extend(decoded)
        check_pin(bytes(compiler), controls["compiler"])
        assert len(compiler) == 673413
        assert hashlib.sha256(compiler).hexdigest() == "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
        assert archive.read("inputs/B3.image.bin") == compiler
        paths = {"source": "source10", "original43": "original43", "native": "native9", "build": "build", "fresh5": "fresh5"}
        group_summary = {}
        assert set(bounded["groups"]) == set(paths)
        for key, stem in paths.items():
            record = bounded["groups"][key]
            owner_raw = archive.read("evidence/" + stem + "-owner/owner.json")
            report_raw = archive.read("evidence/" + stem + "/REPORT.json")
            check_pin(owner_raw, record["owner_pin"])
            check_pin(report_raw, record["report_pin"])
            owner, report = parse(owner_raw), parse(report_raw)
            assert record["owner"] == owner and record["report"] == report
            assert record["status"] == "PASS" and record["owner_admitted"] is True
            assert type(record["command"]["returncode"]) is int and record["command"]["returncode"] == 0
            assert owner["qualification_seconds"] == 180 and owner["cleanup_seconds"] == 3
            assert owner["status"] == "OWNED_PROCESS_COMPLETED" and type(owner["returncode"]) is int and owner["returncode"] == 0
            assert owner["qualification_started"] is True and owner["subreaper_enabled"] is True
            assert owner["exit_observed_before_deadline"] is True and owner["timed_out"] is False
            assert not owner["interrupted_signals"] and owner["event_overflow"] is False
            cleanup = owner["cleanup"]
            assert cleanup["complete"] is True and cleanup["observed_echild"] is True and cleanup["leader_reaped"] is True
            assert cleanup["deadline_exceeded"] is False and not cleanup["errors"] and not cleanup["remaining_direct_children"]
            assert report["status"] == "PASS" and report["source_unchanged"] is True and report["python"].startswith("3.14.4 ")
            before = parse(archive.read("evidence/" + stem + "/SOURCE-BEFORE.json"))
            after = parse(archive.read("evidence/" + stem + "/SOURCE-AFTER.json"))
            assert before == after == projected_source
            if key in controls["groups"]:
                wanted = expected["bounded_groups"][key]
                assert type(report["loaded"]) is int and type(report["tests_run"]) is int
                assert report["loaded"] == report["tests_run"] == controls["groups"][key] == len(wanted)
                assert report["loaded_ids"] == report["started_ids"] == report["stopped_ids"] == wanted
                for field in ("errors", "failures", "skipped", "expected_failures", "unexpected_successes", "loader_errors"):
                    assert not report[field]
                assert bounded["fixed_test_admissions"][key] is True
            group_summary[key] = {"report": pin(report_raw), "owner": pin(owner_raw), "status": "PASS",
                                  "tests": report.get("tests_run"), "wall_ns": report.get("wall_ns")}
        original43 = parse(archive.read("evidence/original43/REPORT.json"))
        assert original43["declared_packaging_interpreter"] == bounded["executable"]
        assert original43["packaging_scope"] == "Actual CPython3.14.4 is used for packaging, original test bodies and installed children"
        for expected_pin in controls["original_test_files"]:
            check_pin(verified_source(expected_pin["path"]), expected_pin)
        fresh = parse(archive.read("evidence/fresh5/REPORT.json"))
        assert len(fresh["records"]) == 5
        assert all(type(row["returncode"]) is int and row["returncode"] == 2 for row in fresh["records"])
        requests = sorted(name for name in archive.namelist() if name.startswith("evidence/build/") and name.endswith(".request.json"))
        assert len(requests) == 5
        compiled = []
        for name in requests:
            request = parse(archive.read(name))
            assert request["capacity"] == request["workspace_size"] == 1048576
            assert request["image_sha256"] == controls["compiler"]["sha256"]
            stem = name.removesuffix(".request.json")
            receipt = parse(archive.read(stem + ".receipt.json"))
            stdout = parse(archive.read(stem + ".stdout.log"))
            extras = {"case", "input_sha256", "input_bytes", "artifact_sha256", "format",
                      "runner_sha256", "wall_elapsed_ns", "produced_image", "produced_bytes", "produced_sha256"}
            assert set(receipt) - set(stdout) == extras and not (set(stdout) - set(receipt))
            assert all(receipt[key] == value for key, value in stdout.items())
            assert archive.read(stem + ".stderr.log") == b""
            assert receipt["case"] == PurePosixPath(stem).name
            assert receipt["format"] == request["format"] == "flat-x86-64"
            assert receipt["runner_sha256"] == hashlib.sha256(verified_source("tools/hia_selfhost_child.py")).hexdigest()
            assert receipt["artifact_sha256"] == request["image_sha256"]
            assert receipt["produced_image"] == request["output"].removesuffix(".output.bin") + ".image.bin"
            assert receipt["produced_bytes"] == receipt["core_u32"]
            assert type(receipt["wall_elapsed_ns"]) is int and 0 < receipt["wall_elapsed_ns"] < 20_000_000_000
            assert receipt["status"] == "returned" and receipt["abi_status"] == 0 and receipt["source_unchanged"] is True
            assert receipt["limits"]["output_capacity"] == receipt["limits"]["workspace_bytes"] == 1048576
            assert not receipt["forbidden_compiler_modules_loaded"]
            input_raw, output_raw, image_raw = (archive.read(stem + suffix) for suffix in (".input.bin", ".output.bin", ".image.bin"))
            assert len(output_raw) == 1048576 and image_raw == output_raw[:receipt["produced_bytes"]]
            assert len(input_raw) == receipt["input_bytes"]
            assert hashlib.sha256(input_raw).hexdigest() == request["source_sha256"] == receipt["source_sha256"] == receipt["input_sha256"]
            assert hashlib.sha256(output_raw).hexdigest() == receipt["output_sha256"]
            assert hashlib.sha256(image_raw).hexdigest() == receipt["produced_sha256"]
            compiled.append({"path": stem, "input": pin(input_raw), "output": pin(output_raw), "image": pin(image_raw)})
    result = {"schema": "hepta.r20.bounded-original-manifest-readback.v1", "status": "BOUNDED_62_COMPLETE_ORIGINALS_VERIFIED",
              "run": config["run"], "job": config["job"], "head": config["head"],
              "source_tree": source_proof["source_tree"], "source_files": 3177,
              "source_tests": 1421, "bounded_tests": 62, "bounded_groups": group_summary,
              "bounded_result": pin(bounded_raw), "compiler": pin(bytes(compiler)), "compiled_records": compiled,
              "actual_python": bounded["python"], "packaging_interpreter": original43["declared_packaging_interpreter"],
              "packaging_versions": bounded["packaging_versions"], "all_five_source_snapshots_match_complete_source": True,
              "receipt_stdout_exact_producer_projection": sorted(extras), "current_source_cold_qualification": False,
              "whole_native": False, "source_physical_copy_deferred": True, "new_product_executions": 0, "seconds_for_evidence_only": time.monotonic() - started}
    save("REPORT.json", result)
    print(json.dumps({key: result[key] for key in ("status", "source_tree", "source_files", "bounded_tests", "seconds_for_evidence_only")}))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        if OUT.is_dir() and not (OUT / "VERIFIER-FAILURE.txt").exists():
            (OUT / "VERIFIER-FAILURE.txt").write_text(traceback.format_exc())
        raise
