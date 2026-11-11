#!/usr/bin/env python3
"""One create-only remote DEVELOPMENT run; never re-labels the unknown local r7."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import subprocess
import sys
import tarfile
import time
import traceback

BASE_COMMIT = "e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6"
BASE_TREE = "bfcbb39e22371cbb2292c89a2fa1ca010353a56f"
SOURCE_MANIFEST_SHA = "7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af"
COMPILER = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
ARCHIVE_SHA = "17c75343cc41f9505e748b790d3318f73ca4d431c11395b61116b244235f9f88"
ARCHIVE_PATH = "experiments/hia_json_wire_development_20261111/ordinary-r2-r5/raw-development-r2-r5.tar.xz"
BASE_FILES = {
    "tools/generate_hia_json_wire.py": "45683fce43ace4b42221ff064e758b794a27640c",
    "tests/test_hia_json_wire_native.py": "4412bf19e751890bd70317d5662205022a69f29e",
    "examples/hia_bootstrap/json_wire.hiaasm": "51fb939f26716b14e4bcd2b4cf602e2b79c8fbb1",
}
RECOVERY_FILES = {
    "generate_hia_json_wire.py":
        ("tools/generate_hia_json_wire.py", "f4e2648158896f26e46a2e8a7a0b22f94de50e7e"),
    "test_hia_json_wire_native.py":
        ("tests/test_hia_json_wire_native.py", "f4ece1f7d8e61d4e19c98b43a44843525a6b8eb8"),
}
CORE_IDS = [
    "tests.test_hia_json_wire_native.WireSourceTests.test_generated_source_and_lazy_exact_type_observer",
    "tests.test_hia_json_wire_native.WireSourceTests.test_word_helpers_preserve_bounds_and_partial_byte_stores",
    "tests.test_hia_json_wire_native.WireSourceTests.test_inlined_field_stores_keep_evaluation_and_partial_write_order",
]
BUDGET_IDS = ["tests.test_hia_agent_native_tools.NativeLifecycleTests." + suffix for suffix in (
    "test_expired_evaluation_is_rejected_before_any_reference_or_native_runner",
    "test_native_timeout_is_incomplete_terminated_and_not_adoptable",
    "test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline",
)]
PLANNED = ["generate", "compile-development", "core-controls", "packet-comparison", "original-budgets"]


def blob(raw):
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "git_blob_sha1": blob(raw)}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def replace_once(text, old, new):
    require(text.count(old) == 1, "ambiguous archived-script path substitution: " + repr(old))
    return text.replace(old, new)


def read_source_package_manifest(path):
    raw = path.read_bytes()
    require(sha256(raw).hexdigest() == SOURCE_MANIFEST_SHA, "canonical source manifest pin mismatch")
    manifest = json.loads(raw)
    require(manifest.get("schema") == "hepta.hia.canonical-development-source-package.v1",
            "unexpected source package schema")
    require(manifest.get("canonical_commit") == BASE_COMMIT and manifest.get("canonical_tree") == BASE_TREE,
            "source package canonical identity mismatch")
    require(manifest.get("complete_git_object_closure") is False,
            "this controller requires the explicit materialized-file profile")
    require(manifest.get("complete_declared_source_closure") is True,
            "source package lacks its complete declared closure")
    rows = manifest.get("files")
    require(type(rows) is list and bool(rows), "empty package inventory")
    files = {}
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "mode", "size", "git_blob_sha1", "sha256"},
                "malformed package file record")
        name = row["path"]
        require(type(name) is str and name and not name.startswith("/")
                and "\\" not in name and all(part not in ("", ".", "..") for part in name.split("/"))
                and str(PurePosixPath(name)) == name, "noncanonical package member path")
        require(name not in files, "duplicate package member")
        require(row["mode"] in ("100644", "100755"), "unsupported package member mode")
        require(type(row["size"]) is int and row["size"] >= 0, "invalid package member size")
        for key, length in (("git_blob_sha1", 40), ("sha256", 64)):
            value = row[key]
            require(type(value) is str and len(value) == length
                    and all(char in "0123456789abcdef" for char in value), "invalid package member digest")
        files[name] = row
    require(manifest.get("member_count") == len(files), "package inventory count mismatch")
    require(manifest.get("decoded_bytes") == sum(row["size"] for row in files.values()),
            "package inventory byte count mismatch")
    declared = manifest.get("declared_source_paths")
    require(type(declared) is list and len(declared) == manifest.get("declared_source_count")
            and len(set(declared)) == len(declared) and set(declared) <= files.keys(),
            "incomplete declared source paths")
    for name in files:
        require(not any(str(parent) in files for parent in PurePosixPath(name).parents if str(parent) != "."),
                "file used as a package directory prefix")
    return manifest, files


def materialized_snapshot(root, expected):
    require(expected is not None, "source package has not been admitted")
    directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents
                   if str(parent) != "."}
    files = {}
    for parent, children, names in os.walk(root, followlinks=False):
        children.sort()
        names.sort()
        for name in children:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            require(relative in directories and stat.S_ISDIR(path.lstat().st_mode),
                    "unexpected or linked source directory: " + relative)
        for name in names:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            require(relative in expected, "unexpected source member: " + relative)
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    "nonregular or hardlinked source member: " + relative)
            raw = path.read_bytes()
            files[relative] = {"path": relative, "mode": format(info.st_mode & 0o177777, "06o"),
                               "size": len(raw), "git_blob_sha1": blob(raw), "sha256": sha256(raw).hexdigest()}
    require(set(files) == set(expected), "materialized source member set mismatch")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--recovery-dir", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    package_manifest = args.source_manifest.resolve(strict=True)
    package_archive = args.source_archive.resolve(strict=True)
    package_files = None
    recovery = args.recovery_dir.resolve(strict=True)
    compiler = args.compiler.resolve(strict=True)
    evidence = args.evidence_dir.absolute()
    evidence.mkdir(mode=0o700)
    (evidence / "tmp").mkdir(mode=0o700)
    (evidence / "before").mkdir()
    report = {
        "schema": "hepta.hia.wire-remote-recovery-development.v2",
        "scope": "NEW_REMOTE_DEVELOPMENT_ONLY_NOT_OLD_LOCAL_R7_NOT_COLD_QUALIFICATION",
        "status": "RUNNING", "started_utc": datetime.now(timezone.utc).isoformat(),
        "unknown_old_local_session": 96283,
        "unknown_old_local_session_result_reused": False,
        "source_root": str(source), "recovery_dir": str(recovery),
        "source_identity_kind": "PINNED_CANONICAL_MATERIALIZED_FILE_SET_NOT_GIT_HISTORY",
        "complete_git_object_closure": False,
        "source_package_manifest_file": identity(package_manifest),
        "source_package_archive_file": identity(package_archive),
        "evidence_dir": str(evidence), "python": sys.version,
        "python_executable": identity(Path(sys.executable).resolve()),
        "compiler": identity(compiler), "steps": [], "planned_steps": PLANNED,
        "test_budget_or_compiler_limit_relaxed": False,
        "whole_89_qualification_claimed": False,
    }
    report_path = evidence / "audit.json"

    def save():
        temp = evidence / "audit.json.tmp"
        temp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os.replace(temp, report_path)

    def snapshot():
        return materialized_snapshot(source, package_files)

    environment = os.environ.copy()
    removed = sorted(name for name in environment if name.startswith("HEPTA_HIA_"))
    for name in removed:
        environment.pop(name)
    environment.pop("PYTHONPATH", None)
    environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                       PYTHONUNBUFFERED="1", TMPDIR=str(evidence / "tmp"))
    report["removed_selector_variable_names"] = removed
    report["pythonpath_removed"] = True

    def run(name, command, timeout):
        stdout = evidence / (name + ".stdout.log")
        stderr = evidence / (name + ".stderr.log")
        item = {"name": name, "command": command, "cwd": str(source),
                "wrapper_timeout_seconds": timeout, "started_utc": datetime.now(timezone.utc).isoformat()}
        report["steps"].append(item)
        save()
        print(json.dumps({"phase": name, "state": "started"}), flush=True)
        started = time.monotonic()
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(command, cwd=source, env=environment, stdout=out, stderr=err,
                                       start_new_session=True)
            item["pid"] = process.pid
            try:
                process.wait(timeout=timeout)
                item["wrapper_timed_out"] = False
            except subprocess.TimeoutExpired:
                item["wrapper_timed_out"] = True
                item["timeout_signals"] = ["SIGTERM"]
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    item["timeout_signals"].append("SIGKILL")
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
            item["returncode"] = process.returncode
        item["wall_seconds"] = time.monotonic() - started
        item["stdout"] = identity(stdout)
        item["stderr"] = identity(stderr)
        save()
        print(json.dumps({"phase": name, "state": "ended", "returncode": item["returncode"],
                          "wall_seconds": item["wall_seconds"]}), flush=True)
        require(not item["wrapper_timed_out"] and item["returncode"] == 0,
                name + " failed; no retry or threshold change")

    try:
        save()
        require(report["compiler"]["sha256"] == COMPILER, "development compiler pin mismatch")
        package, package_files = read_source_package_manifest(package_manifest)
        archive_metadata = package["archive"]
        for key in ("size", "sha256", "git_blob_sha1"):
            observed_key = "bytes" if key == "size" else key
            require(report["source_package_archive_file"][observed_key] == archive_metadata[key],
                    "canonical source archive identity mismatch: " + key)
        report["base_commit"], report["base_tree"] = BASE_COMMIT, BASE_TREE
        report["source_package_scope"] = package["scope"]
        report["source_package_members"] = package["member_count"]
        report["declared_source_count"] = package["declared_source_count"]
        report["source_contract_checked_document_current"] = package["source_contract_checked_document_current"]
        report["checked_contract_state"] = package["checked_contract_state"]
        before = snapshot()
        require(before == package_files, "initial materialized source differs from canonical package")
        (evidence / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
        report["source_before_snapshot"] = identity(evidence / "source-before.json")
        for relative, expected in BASE_FILES.items():
            raw = (source / relative).read_bytes()
            require(blob(raw) == expected, "baseline product-file drift: " + relative)
            target = evidence / "before" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        recovered = {}
        for name, (relative, expected) in RECOVERY_FILES.items():
            raw = (recovery / name).read_bytes()
            require(blob(raw) == expected, "recovery-text blob mismatch: " + name)
            recovered[relative] = raw
        # Both texts are checked before the private candidate is mutated.
        for relative, raw in recovered.items():
            (source / relative).write_bytes(raw)
        report["candidate_recovery_files"] = {relative: identity(source / relative) for relative in recovered}
        save()
        run("generate", [sys.executable, "-B", "-m", "tools.generate_hia_json_wire"], 90)
        candidate = snapshot()
        changed = {name for name in before if candidate[name] != before[name]}
        require(changed == set(BASE_FILES), "unexpected candidate mutation set")
        require(all(candidate[name]["mode"] == before[name]["mode"] for name in changed),
                "candidate file mode changed")
        report["candidate_deltas"] = {name: {"before": before[name], "after": candidate[name]}
                                      for name in sorted(changed)}
        (evidence / "source-candidate.json").write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n")
        report["source_candidate_snapshot"] = identity(evidence / "source-candidate.json")
        report["candidate_source_sha256"] = {name: identity(source / name)["sha256"] for name in BASE_FILES}
        run("compile-development", [sys.executable, "-B", "-m", "tools.build_hia_json_wire",
            "--development", "--compiler", str(compiler), "--output", str(evidence / "wire")], 120)
        manifest_path = evidence / "wire/manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        require(manifest["compiler_sha256"] == COMPILER, "built compiler identity drift")
        require(manifest["source_sha256"] == report["candidate_source_sha256"]["examples/hia_bootstrap/json_wire.hiaasm"],
                "built source identity drift")
        require(manifest["image_path"] == "json-wire.image.bin", "unexpected image path")
        image = evidence / "wire/json-wire.image.bin"
        require(identity(image)["sha256"] == manifest["image_sha256"], "built image identity drift")
        report["development_manifest"] = manifest
        report["development_manifest_file"] = identity(manifest_path)
        report["development_image_file"] = identity(image)
        report["development_build_file"] = identity(evidence / "wire/build.json")

        core = evidence / "core-controls.py"
        core.write_text(
            "import json,sys,unittest\n"
            "from pathlib import Path\n"
            "sys.path.insert(0," + repr(str(source)) + ")\n"
            "ids=" + repr(CORE_IDS) + "\n"
            "executed=[]\n"
            "class Result(unittest.TextTestResult):\n"
            " def startTest(self,test):\n"
            "  executed.append(test.id());super().startTest(test)\n"
            "suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in ids)\n"
            "result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)\n"
            "passed=(executed==ids and result.testsRun==len(ids) and not any((result.failures,result.errors,result.skipped,result.expectedFailures,result.unexpectedSuccesses)))\n"
            "report={'status':'PASS' if passed else 'FAIL','loaded_test_ids':ids,'executed_test_ids':executed,'tests_run':result.testsRun,"
            "'failures':[(t.id(),s) for t,s in result.failures],'errors':[(t.id(),s) for t,s in result.errors],"
            "'skipped':[(t.id(),s) for t,s in result.skipped],'expected_failures':[(t.id(),s) for t,s in result.expectedFailures],"
            "'unexpected_successes':[t.id() for t in result.unexpectedSuccesses]}\n"
            "Path(" + repr(str(evidence / "core-controls.json")) + ").write_text(json.dumps(report,indent=2)+'\\n')\n"
            "raise SystemExit(0 if passed else 1)\n")
        run("core-controls", [sys.executable, "-B", str(core)], 120)

        archive = source / ARCHIVE_PATH
        require(identity(archive)["sha256"] == ARCHIVE_SHA, "historical archive pin mismatch")
        historical = evidence / "historical"
        historical.mkdir()
        names = [
            "wire-entry-development-r1/manifest.json",
            "wire-entry-development-r1/json-wire.input.bin",
            "wire-entry-development-r1/json-wire.image.bin",
            "wire-entry-word-helper-packets-r5.py",
            "wire-entry-budget-recheck.py",
        ]
        historical_receipt = []
        with tarfile.open(archive, "r:xz") as archive_file:
            inventory = archive_file.getmembers()
            require(len({entry.name for entry in inventory}) == len(inventory), "duplicate archive member")
            for name in names:
                member = archive_file.getmember(name)
                require(member.isfile(), "historical member is not a regular file")
                raw = archive_file.extractfile(member).read()
                target = historical / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                historical_receipt.append({"archive_member": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                                           "original_mode": member.mode, "original_uid": member.uid, "original_gid": member.gid})
        (evidence / "historical-readback.json").write_text(json.dumps(historical_receipt, indent=2) + "\n")
        old_manifest = json.loads((historical / "wire-entry-development-r1/manifest.json").read_bytes())
        require(old_manifest["source_sha256"] == "f800c70356ef33fb986d510853b6594bcd28dde49365752ecf547251b4f881ab",
                "unexpected historical source")
        require(old_manifest["image_sha256"] == "249f133cd5429956c549917932b8b66ade8431bf47862a4b76e98fb4ea486e31",
                "unexpected historical image")
        require(identity(historical / "wire-entry-development-r1/json-wire.input.bin")["sha256"] == old_manifest["source_sha256"],
                "historical source bytes mismatch")
        require(identity(historical / "wire-entry-development-r1/json-wire.image.bin")["sha256"] == old_manifest["image_sha256"],
                "historical image bytes mismatch")
        comparison = (historical / "wire-entry-word-helper-packets-r5.py").read_text()
        substitutions = [
            ("sys.path.insert(0,'/workspace/scratch/e26ed3e2edcf/hia-native-wire-entry')", "sys.path.insert(0," + repr(str(source)) + ")"),
            ("root=Path('/workspace/scratch/e26ed3e2edcf')", "root=Path(" + repr(str(historical)) + ")"),
            ("root/'wire-entry-development-r5/manifest.json'", "Path(" + repr(str(manifest_path)) + ")"),
            ("old_source=subprocess.check_output(['git','show','fc94ba18c0402bcac557b8cc0cff6d606d4a1bef:examples/hia_bootstrap/json_wire.hiaasm'],cwd=SOURCE.parents[2])",
             "old_source=(root/'wire-entry-development-r1/json-wire.input.bin').read_bytes()"),
            ("p=root/'wire-entry-word-helper-packets-r5.json'", "p=Path(" + repr(str(evidence / "packet-comparison.json")) + ")"),
        ]
        for old, new in substitutions:
            comparison = replace_once(comparison, old, new)
        comparison_script = evidence / "packet-comparison.py"
        comparison_script.write_text(comparison)
        report["comparison_path_substitutions"] = substitutions
        run("packet-comparison", [sys.executable, "-B", str(comparison_script)], 90)
        packet = json.loads((evidence / "packet-comparison.json").read_bytes())
        require(packet["status"] == "PASS" and packet["cases_run"] == 19, "incomplete packet comparison")
        require(sum(case.get("native_steps", 2) for case in packet["cases"]) == 228, "packet-step denominator changed")
        require(packet["source_after"] == manifest["source_sha256"] and packet["image_after"] == manifest["image_sha256"],
                "packet comparison candidate identity drift")
        run("original-budgets", [sys.executable, "-B", str(historical / "wire-entry-budget-recheck.py"),
            "--source-root", str(source), "--manifest", str(manifest_path),
            "--output", str(evidence / "original-budgets.json")], 240)
        budget = json.loads((evidence / "original-budgets.json").read_bytes())
        require(budget["status"] == "PASS" and budget["loaded_test_ids"] == BUDGET_IDS
                and budget["executed_test_ids"] == BUDGET_IDS and budget["tests_run"] == len(BUDGET_IDS),
                "incomplete original budget group")
        require(not any(budget[key] for key in ("failures", "errors", "skipped", "expected_failures",
                "unexpected_successes", "retained_owner_entries", "host_encoder_entries")), "original budget anomaly")
        require(budget["source_stable"] and all(budget["per_test_native_wire_calls"].get(name, 0) > 0 for name in BUDGET_IDS),
                "original callers did not enter stable native wire")
        require(snapshot() == candidate, "source changed during the frozen run")
        require(identity(compiler) == report["compiler"], "compiler changed during the run")
        require(identity(manifest_path) == report["development_manifest_file"], "manifest changed during the run")
        require(identity(image) == report["development_image_file"], "image changed during the run")
        require(identity(package_manifest) == report["source_package_manifest_file"], "source package manifest changed")
        require(identity(package_archive) == report["source_package_archive_file"], "source package archive changed")
        report["source_manifest_image_compiler_stable"] = True
        report["source_package_manifest_archive_stable"] = True
        report["status"] = "PASS_LIMITED_DEVELOPMENT_CONTROLS"
    except BaseException as exc:
        report["status"] = "HOLD"
        report["exception"] = {"type": type(exc).__name__, "message": str(exc), "trace": traceback.format_exc()}
    finally:
        report["unexecuted_steps"] = [name for name in PLANNED if name not in [step["name"] for step in report["steps"]]]
        try:
            after = snapshot()
            after_path = evidence / "source-after.json"
            after_path.write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
            report["source_after_snapshot"] = identity(after_path)
            if "candidate" in locals():
                report["candidate_source_stable_at_end"] = after == candidate
                if not report["candidate_source_stable_at_end"]:
                    report["status"] = "HOLD"
                    report["terminal_gate_error"] = "candidate source changed at final observation"
        except BaseException as exc:
            report["source_after_snapshot_error"] = {"type": type(exc).__name__, "message": str(exc)}
            report["status"] = "HOLD"
            report["terminal_gate_error"] = "final source observation failed"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps({"status": report["status"], "report": str(report_path)}), flush=True)
    return 0 if report["status"] == "PASS_LIMITED_DEVELOPMENT_CONTROLS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
