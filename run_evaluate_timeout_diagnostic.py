"""Two original evaluate-timeout cases; observations only after their timed body.

The original method function object and every product byte remain unchanged.
No native run, request, artifact publication, or evaluation is replayed.
"""
from __future__ import annotations
import argparse
import ast
from contextlib import ExitStack
import hashlib
import importlib.metadata
import inspect
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import zipfile
import zlib
import base64

REPOSITORY = "TrillionniumFoundation/Hepta"
SOURCE_COMMIT = "4b19af89a766593f7d5f1cc2db256e81aba7afcb"
SOURCE_TREE = "1bc7c90996e1910ad66ba771b0bfee1d5bfa655c"
SOURCE_COUNT = 3153
ORIGINAL_RUN = 43197399906
ORIGINAL_ARTIFACT = 13940069535
ARTIFACT_BYTES = 174559729
ARTIFACT_SHA256 = "f7254bdb890efbca54b5964ee770e1954c1fc6a3d191eb097b171f1456556d2b"
ARTIFACT_MEMBERS = 12752
COMPILER_SHA256 = "81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109"
METHOD = "test_native_timeout_is_incomplete_terminated_and_not_adoptable"
ORIGINAL_ID = "tests.test_hia_agent_native_tools.NativeLifecycleTests." + METHOD
PINS = {"setuptools": "78.1.1", "wheel": "0.46.3", "z3-solver": "4.15.4.0", "jsonschema": "4.26.0"}
SCHEMA = "hepta.evaluate-timeout-observation.v1"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()


def put(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    require(path.read_bytes() == data, "output readback differs: " + str(path))
    return {"path": str(path), "bytes": len(data), "sha256": sha(data), "git_blob": blob(data)}


def put_json(path, value):
    return put(path, wire(value))


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def snapshot(root):
    require(git(root, "rev-parse", "HEAD").decode().strip() == SOURCE_COMMIT, "wrong checkout commit")
    require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == SOURCE_TREE, "wrong checkout tree")
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all"), "checkout is not clean")
    rows = {}
    for row in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not row:
            continue
        head, raw_name = row.split(b"\t", 1)
        mode, kind, expected = head.decode("ascii").split()
        name = raw_name.decode("utf-8")
        require(kind == "blob" and mode in ("100644", "100755"), "unexpected tracked type")
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe tracked path")
        path = root / name
        status = path.lstat()
        require(stat.S_ISREG(status.st_mode), "nonregular source: " + name)
        data = path.read_bytes()
        require(blob(data) == expected, "source Git blob mismatch: " + name)
        require(bool(status.st_mode & 0o111) == (mode == "100755"), "source executable mode mismatch")
        rows[name] = {"mode": mode, "git_blob": expected, "bytes": len(data), "sha256": sha(data)}
    require(len(rows) == SOURCE_COUNT, "wrong tracked source count")
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_original(output):
    token = os.environ.get("GITHUB_TOKEN")
    require(type(token) is str and bool(token), "read-only Actions token required")
    opener = urllib.request.build_opener(NoRedirect())
    base = "https://api.github.com/repos/" + REPOSITORY + "/actions/artifacts/" + str(ORIGINAL_ARTIFACT)
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "hia-evaluate-timeout-diagnostic"}
    with opener.open(urllib.request.Request(base, headers=headers), timeout=60) as response:
        metadata_raw = response.read()
    metadata = json.loads(metadata_raw)
    require(metadata["id"] == ORIGINAL_ARTIFACT and metadata["size_in_bytes"] == ARTIFACT_BYTES
            and metadata["workflow_run"]["id"] == ORIGINAL_RUN and not metadata["expired"],
            "original artifact API identity differs")
    put(output / "original-artifact.metadata.json", metadata_raw)
    try:
        opener.open(urllib.request.Request(base + "/zip", headers=headers), timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301, 302, 303, 307), "artifact redirect was refused")
        location = error.headers["Location"]
    else:
        raise AssertionError("expected signed artifact redirect")
    require(location.startswith("https://"), "non-HTTPS artifact location")
    path = output / "original-artifact.zip"
    digest = hashlib.sha256()
    count = 0
    # Never forward the GitHub token to the signed storage host.
    with urllib.request.urlopen(urllib.request.Request(location, headers={
            "User-Agent": "hia-evaluate-timeout-diagnostic"}), timeout=120) as response, path.open("xb") as stream:
        while True:
            part = response.read(1024 * 1024)
            if not part:
                break
            count += len(part)
            require(count <= ARTIFACT_BYTES, "artifact exceeded its exact size")
            digest.update(part)
            stream.write(part)
    require(count == ARTIFACT_BYTES and digest.hexdigest() == ARTIFACT_SHA256, "original artifact bytes differ")
    return path


def restore_cold(archive_path, output, source_rows):
    temporary = Path(os.environ["RUNNER_TEMP"])
    require(not (temporary / "hia-cold.json").exists()
            and not (temporary / "hia-cold.cold").exists(), "cold destination is not new")
    members = []
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        require(len(infos) == ARTIFACT_MEMBERS and len({r.filename for r in infos}) == len(infos),
                "original archive member inventory differs")
        for info in infos:
            name = PurePosixPath(info.filename)
            require(not name.is_absolute() and ".." not in name.parts, "unsafe artifact member")
            require(stat.S_IFMT(info.external_attr >> 16) not in (stat.S_IFLNK,), "artifact symlink refused")
            data = archive.read(info.filename)
            record = {"path": info.filename, "bytes": len(data), "sha256": sha(data), "zip_crc32": info.CRC}
            members.append(record)
            if info.filename == "hia-cold.json" or info.filename.startswith("hia-cold.cold/"):
                if info.is_dir():
                    (temporary / info.filename).mkdir(parents=True, exist_ok=True)
                else:
                    target = temporary / info.filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as stream:
                        stream.write(data)
                    os.chmod(target, 0o755 if info.external_attr >> 16 & 0o111 else 0o644)
        cold_path = temporary / "hia-cold.json"
        cold = json.loads(cold_path.read_bytes())
        require(cold["status"] == "COLD_SELFHOST_REPLAY_PASS" and cold["returncode"] == 0
                and all(v is True for v in cold["checks"].values()) and len(cold["checks"]) == 11,
                "original cold did not pass")
        nested_path = Path(cold["nested_report"])
        require(nested_path == temporary / "hia-cold.cold/qualification.json",
                "original absolute cold path is not this runner's exact restored path")
        raw = nested_path.read_bytes()
        require(sha(raw) == cold["nested_report_sha256"], "original nested report changed")
        nested = json.loads(raw)
        require(nested["status"] == "SELF_HOSTED_FIXED_CORE_PASS"
                and all(v is True for v in nested["checks"].values()) and len(nested["checks"]) == 5052,
                "original nested cold did not pass")
        require(cold["source_manifest"] == nested["source_manifest"], "cold source identities differ")
        require(len(cold["source_manifest"]) == 964, "original cold closure count changed")
        for name, expected in cold["source_manifest"].items():
            require(source_rows[name]["sha256"] == expected, "current checkout differs from original cold: " + name)
            require(sha((temporary / "hia-cold.cold/source" / name).read_bytes()) == expected,
                    "original cold source export changed: " + name)
        compiler = Path(nested["generations"][-1]["produced_image"])
        require(compiler == temporary / "hia-cold.cold/qualification.evidence/B3.image.bin",
                "compiler path differs from original receipt")
        require(sha(compiler.read_bytes()) == COMPILER_SHA256, "retained compiler bytes differ")
        put_json(output / "original-artifact.members.json", members)
        put_json(output / "cold-admission.json", {"schema": SCHEMA, "scope": "REUSED_EXACT_SOURCE_ORIGINAL_COLD",
            "original_run": ORIGINAL_RUN, "original_artifact": ORIGINAL_ARTIFACT,
            "original_archive_sha256": ARTIFACT_SHA256, "cold_path": str(cold_path),
            "source_count_including_support": len(cold["source_manifest"]),
            "compiler": str(compiler), "compiler_sha256": COMPILER_SHA256,
            "fresh_cold_executed_here": False, "whole_qualification": False})
    return cold_path


class Recorder:
    def __init__(self, output):
        self.output = output
        self.captured = False
        self.report = None

    def capture(self, case, event):
        if self.captured:
            return
        self.captured = True
        started = time.monotonic_ns()
        report = {"schema": SCHEMA, "event": event, "test_id": ORIGINAL_ID,
                  "capture_is_after_original_timed_method": True, "business_replayed": False,
                  "new_product_api_calls": 0, "files": [], "errors": []}
        try:
            records = getattr(getattr(case, "client", None), "records", None)
            report["records_file"] = put_json(self.output / "existing-client-records.json", records)
            root = getattr(case, "root", None)
            hash_paths = {}
            if root is not None:
                root = Path(root)
                report["original_temporary_root"] = str(root)
                for current, dirs, files in os.walk(root, followlinks=False):
                    for directory in dirs:
                        require(not (Path(current) / directory).is_symlink(), "temporary directory symlink refused")
                    for name in sorted(files):
                        path = Path(current) / name
                        before = path.lstat()
                        require(stat.S_ISREG(before.st_mode), "temporary nonregular file refused")
                        data = path.read_bytes()
                        after = path.lstat()
                        stable = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                        require(stable(before) == stable(after) and len(data) == before.st_size,
                                "temporary file changed during post-method capture")
                        relative = path.relative_to(root).as_posix()
                        item = put(self.output / "existing-temporary-files" / relative, data)
                        item.update(original_relative_path=relative, original_mode=stat.S_IMODE(before.st_mode))
                        report["files"].append(item)
                        hash_paths.setdefault(sha(data), []).append(item)
            evaluations = []
            for row in records or []:
                if row.get("tool") != "hia_evaluate":
                    continue
                entry = {"record": row, "existing_returned_artifacts": {}}
                response = row.get("response", {})
                result = response.get("result", {})
                for kind in ("measurements", "full_cost_ledger", "evaluation_receipt"):
                    ref = result.get(kind)
                    if isinstance(ref, dict):
                        matches = hash_paths.get(ref.get("sha256"), [])
                        require(matches, "returned artifact bytes not retained: " + kind)
                        raw = Path(matches[0]["path"]).read_bytes()
                        require(sha(raw) == ref["sha256"], "returned artifact content differs: " + kind)
                        entry["existing_returned_artifacts"][kind] = {
                            "reference": ref, "retained_files": matches, "decoded_existing_json": json.loads(raw)}
                evaluations.append(entry)
            report["evaluations"] = evaluations
        except BaseException:
            report["errors"].append(traceback.format_exc())
        report["post_method_capture_elapsed_ns"] = time.monotonic_ns() - started
        self.report = report
        put_json(self.output / "POST-METHOD-OBSERVATION.json", report)


def run_case(source, output, profile, cold):
    output.mkdir(parents=True, exist_ok=False)
    require(sys.version_info[:3] == (3, 14, 4), "CPython 3.14.4 required")
    os.chdir(source)
    sys.path.insert(0, str(source))
    retained_clang = os.environ.get("HEPTA_CLANG")
    for key in list(os.environ):
        if key.startswith("HEPTA_"):
            del os.environ[key]
    if retained_clang:
        os.environ["HEPTA_CLANG"] = retained_clang
    os.environ["HEPTA_HIA_ARTIFACT_NAMESPACE_COLD_REPORT"] = str(cold)
    os.environ["HEPTA_HIA_SLOT_LEDGER_COLD_REPORT"] = str(cold)
    os.environ["HEPTA_HIA_ARTIFACT_NAMESPACE_EVIDENCE"] = str(output / "fixture-builds")
    os.environ["HEPTA_HIA_SLOT_LEDGER_EVIDENCE"] = str(output / "fixture-builds")
    from tests.test_hia_agent_native_tools import NativeLifecycleTests
    from tests.test_hia_artifact_namespace_native import ArtifactNamespaceNativeTests
    from tests.test_hia_slot_ledger_native import SlotLedgerNativeTests
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_agent_store import AgentStore
    from hepta import hia_execution_budget as budget
    method = getattr(NativeLifecycleTests, METHOD)
    method_raw = inspect.getsource(method).encode()
    put(output / "original-method.py.txt", method_raw)
    recorder = Recorder(output)

    class ObservedOriginal(NativeLifecycleTests):
        def id(self):
            return ORIGINAL_ID
        def tearDown(self):
            recorder.capture(self, "before_original_tearDown")
            return super().tearDown()

    require(getattr(ObservedOriginal, METHOD) is method, "original method was replaced")

    class ObservedResult(unittest.TextTestResult):
        def startTest(self, test):
            self.executed.append(test.id())
            super().startTest(test)
        def addFailure(self, test, error):
            recorder.capture(test, "Result.addFailure_before_original_tearDown")
            super().addFailure(test, error)
        def addError(self, test, error):
            recorder.capture(test, "Result.addError_before_original_tearDown")
            super().addError(test, error)
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.executed = []

    report = {"schema": SCHEMA, "profile": profile, "original_test_id": ORIGINAL_ID,
              "scope": "TWO_PROFILE_SINGLE_ORIGINAL_CASE_DIAGNOSTIC_NOT_QUALIFICATION",
              "original_method_sha256": sha(method_raw), "method_object_unchanged": True,
              "original_5s_assertion_unchanged": True, "original_1ms_native_budget_unchanged": True,
              "source_bytes_changed": False, "fresh_cold": False, "whole_qualification": False}
    fixture_class = ArtifactNamespaceNativeTests if profile == "namespace" else SlotLedgerNativeTests
    fixture = None
    fixture_ready = False
    started = time.monotonic_ns()
    try:
        fixture_class.setUpClass()
        fixture_ready = True
        outer_method = ("test_original_agent_tools_and_campaign_with_all_three_owners_and_no_namespace_reference"
                        if profile == "namespace" else
                        "test_original_tools_campaign_buffers_and_lease_snapshot_with_four_native_owners")
        fixture = fixture_class(outer_method)
        fixture.setUp()
        def forbidden(*args, **kwargs):
            raise AssertionError("original selected owner entered")
        with ExitStack() as stack:
            if profile == "namespace":
                stack.enter_context(fixture.selected(joint=True))
                stack.enter_context(fixture.old_namespace_forbidden(hashing=False, payload_io=False))
            else:
                stack.enter_context(fixture.selected())
                stack.enter_context(fixture.old_ledger_forbidden())
                for name in ("put", "json", "get", "get_json", "resolve_uri", "profile", "check_profile", "transaction"):
                    stack.enter_context(patch.object(AgentStore, "_" + name + "_reference", side_effect=forbidden))
                stack.enter_context(patch.object(AgentStore, "_ref", side_effect=forbidden))
            stack.enter_context(patch.object(HIAAgentService, "_call_reference", side_effect=forbidden))
            for cls in (budget._ReferenceExecutionBudgetStore, budget._ReferenceBudgetClaim):
                stack.enter_context(patch.object(cls, "__init__", side_effect=forbidden))
            report["actual_native_selectors"] = {k: v for k, v in os.environ.items()
                if k.startswith("HEPTA_") and k.endswith("_MANIFEST")}
            suite = unittest.TestSuite([ObservedOriginal(METHOD)])
            require(suite.countTestCases() == 1, "diagnostic must run exactly one original case")
            with (output / "original-case.unittest.log").open("x", encoding="utf-8") as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=ObservedResult).run(suite)
            report.update(tests_run=result.testsRun, executed_ids=result.executed,
                failures=[{"id": test.id(), "traceback": text} for test, text in result.failures],
                errors=[{"id": test.id(), "traceback": text} for test, text in result.errors],
                skipped=[{"id": test.id(), "reason": reason} for test, reason in result.skipped],
                expected_failures=[{"id": test.id(), "traceback": text} for test, text in result.expectedFailures],
                unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
                original_case_successful=result.wasSuccessful())
            require(result.testsRun == 1 and result.executed == [ORIGINAL_ID], "case execution identity differs")
            require(not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses,
                    "skip/xfail cannot substitute for actual observation")
        require(recorder.captured and recorder.report is not None and not recorder.report["errors"],
                "post-method evidence capture was incomplete")
        report["status"] = "ORIGINAL_CASE_PASS" if result.wasSuccessful() else "ORIGINAL_CASE_FAIL"
    except BaseException:
        report["status"] = "DIAGNOSTIC_FAILURE"
        report["diagnostic_error"] = traceback.format_exc()
    finally:
        if fixture is not None:
            try:
                fixture.doCleanups()
            except BaseException:
                report["fixture_cleanup_error"] = traceback.format_exc()
                report["status"] = "DIAGNOSTIC_FAILURE"
        if fixture_ready:
            try:
                fixture_class.tearDownClass()
            except BaseException:
                report["fixture_class_cleanup_error"] = traceback.format_exc()
                report["status"] = "DIAGNOSTIC_FAILURE"
        report["elapsed_ns_including_fixture_and_post_method_copy"] = time.monotonic_ns() - started
        put_json(output / "RESULT.json", report)
    print(json.dumps({k: v for k, v in report.items() if k not in ("failures", "errors")}, sort_keys=True))
    return 0 if report["status"] == "ORIGINAL_CASE_PASS" else 1


def log_capsule(output, report):
    selected = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and (path.name in ("RESULT.json", "POST-METHOD-OBSERVATION.json",
                "original-case.unittest.log", "SUMMARY.json", "cold-admission.json")
                or path.name.endswith(".terminal.json")):
            raw = path.read_bytes()
            selected[path.relative_to(output).as_posix()] = {"bytes": len(raw), "sha256": sha(raw),
                                                            "base64": base64.b64encode(raw).decode()}
    raw = wire({"schema": SCHEMA, "scope": "LOSSLESS_SELECTED_DIAGNOSTIC_TEXT_NOT_FULL_ARTIFACT",
                "files": selected, "summary": report})
    compressed = zlib.compress(raw)
    encoded = base64.b64encode(compressed).decode()
    chunks = [encoded[index:index + 10000] for index in range(0, len(encoded), 10000)]
    header = {"schema": SCHEMA, "raw_bytes": len(raw), "raw_sha256": sha(raw),
              "zlib_bytes": len(compressed), "zlib_sha256": sha(compressed), "chunks": len(chunks)}
    print("HIA_EVALUATE_DIAGNOSTIC_CAPSULE " + json.dumps(header, sort_keys=True))
    for index, data in enumerate(chunks):
        print("HIA_EVALUATE_DIAGNOSTIC_CHUNK " + json.dumps({"index": index, "base64": data}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile-case", choices=("namespace", "ledger"))
    parser.add_argument("--cold", type=Path)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if args.profile_case:
        return run_case(source, output, args.profile_case, args.cold.resolve())
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "scope": "DIAGNOSTIC_ONLY_NO_PERFORMANCE_OR_WHOLE_QUALIFICATION",
              "source_commit": SOURCE_COMMIT, "source_tree": SOURCE_TREE,
              "original_run": ORIGINAL_RUN, "profiles": {}, "status": "DIAGNOSTIC_FAILURE",
              "fresh_cold_executed": False, "product_source_modified": False}
    before = None
    try:
        require(sys.version_info[:3] == (3, 14, 4), "CPython 3.14.4 required")
        versions = {name: importlib.metadata.version(name) for name in PINS}
        require(versions == PINS, "pinned dependency versions differ")
        report["runtime"] = {"python": sys.version, "executable": sys.executable, "dependencies": versions}
        before = snapshot(source)
        put_json(output / "SOURCE-BEFORE.json", before)
        archive = download_original(output)
        cold = restore_cold(archive, output, before)
        sys.path.insert(0, str(source))
        from tools.hia_selfhost_process_owner import run_owned
        for profile in ("namespace", "ledger"):
            env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR",
                "LD_LIBRARY_PATH", "CLANG", "HEPTA_CLANG") if key in os.environ}
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--source", str(source),
                       "--output", str(output / profile), "--profile-case", profile, "--cold", str(cold)]
            receipt = run_owned(command, cwd=source, env=env,
                stdout_path=output / (profile + ".stdout.log"), stderr_path=output / (profile + ".stderr.log"),
                receipt_path=output / (profile + ".owner.json"), qualification_seconds=180, cleanup_seconds=3)
            report["profiles"][profile] = {"owner_receipt": receipt}
            result_path = output / profile / "RESULT.json"
            if result_path.is_file():
                report["profiles"][profile]["result"] = json.loads(result_path.read_bytes())
            require(receipt.get("cleanup", {}).get("complete") is True,
                    "profile process cleanup is unconfirmed; no next profile is launched")
        report["status"] = "OBSERVATIONS_RETAINED"
        if any(x.get("owner_receipt", {}).get("status") not in ("OWNED_PROCESS_COMPLETED", "QUALIFICATION_FAILED")
                or x.get("result", {}).get("status") == "DIAGNOSTIC_FAILURE"
                or "result" not in x for x in report["profiles"].values()):
            report["status"] = "DIAGNOSTIC_FAILURE"
        report["all_original_cases_passed"] = all(
            x.get("result", {}).get("status") == "ORIGINAL_CASE_PASS" for x in report["profiles"].values())
    except BaseException:
        report["error"] = traceback.format_exc()
    finally:
        if before is not None:
            try:
                after = snapshot(source)
                put_json(output / "SOURCE-AFTER.json", after)
                require(after == before, "product source changed")
                report["all_product_source_bytes_and_modes_unchanged"] = True
            except BaseException:
                report["source_guard_error"] = traceback.format_exc()
                report["status"] = "DIAGNOSTIC_FAILURE"
        put_json(output / "SUMMARY.json", report)
        log_capsule(output, report)
    return 0 if report["status"] == "OBSERVATIONS_RETAINED" and report.get("all_original_cases_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
