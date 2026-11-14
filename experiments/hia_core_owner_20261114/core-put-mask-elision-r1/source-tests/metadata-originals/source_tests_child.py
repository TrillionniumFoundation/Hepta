"""Run one fixed original source group; each request gets one original 180/3 owner."""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import ctypes
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_common as C

GROUPS = {
    "source4": [
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_complete_original_Function_and_five_helpers_are_independent",
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_current_32_sources_keep_original_Core_caps_and_literal_VM",
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_unqualified_cold_refuses_before_output_creation",
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_unselected_constructor_subclass_and_early_target_errors_stay_original"
    ],
    "fixture6": [
        "tests.test_hia_core_unpack_native.UnpackCompositionSourceTests.test_original_39_units_and_Core_ABI_are_unchanged",
        "tests.test_hia_core_compare_source.ExactNumericComparisonSourceTests.test_complete_Core39_outer_protocol_and_original116_are_unchanged",
        "tests.test_hia_core_compare_integration.NumericComparisonIntegrationSourceTests.test_resource_inventory_preserves_original92_and_Core39",
        "tests.test_hia_core_integer_integration.IntegerIntegrationSourceTests.test_exact_completed_kernel_bridge_and_original_Core39_are_preserved",
        "tests.test_hia_core_integer_native_integration.IntegerNativeIntegrationSourceTests.test_original32_Core39_116_18_kernel_and_bridge_are_unchanged",
        "tests.test_hia_core_compare_integration.NumericComparisonIntegrationSourceTests.test_portable_fixture_keeps_all_eleven_original_method_bodies"
    ]
}
ORIGINAL_TEST_FILES = [
    {
        "path": "tests/test_hia_core_lowering_native.py",
        "bytes": 70301,
        "sha256": "10bea295225262ab2cf4cc132aa4eac41db0d707793aeebda1892d74bd8ccb01",
        "git_blob": "c9f3ee7f809b115a2d5d1a4f3104f75868936b81"
    },
    {
        "path": "tests/test_hia_core_unpack_native.py",
        "bytes": 18301,
        "sha256": "a6fb5e2415c36b1643a4623173c5c0457c1e01c3138442557715347a0ec1e2a4",
        "git_blob": "78440770409f25d238d8a9faa2d6743ed51fd55c"
    },
    {
        "path": "tests/test_hia_core_compare_source.py",
        "bytes": 28119,
        "sha256": "9309660e3a0a0bcb2c8dfc75a247e266325e569cdb002acd4a424c03e19a29e1",
        "git_blob": "e297801fc4e190c15c583031bcdcc7b814532ebf"
    },
    {
        "path": "tests/test_hia_core_compare_integration.py",
        "bytes": 27855,
        "sha256": "d3313caf24c23ce4fbdac5e49eaf4b3f5b0f88dbe282ed1311d24096fe084b27",
        "git_blob": "047ab11e33f0edb7272182543105887611099f08"
    },
    {
        "path": "tests/test_hia_core_integer_integration.py",
        "bytes": 22558,
        "sha256": "821e071dfc70abc4201a9b377062a16e752d01c394671299f8b0795f1ace6259",
        "git_blob": "ed0b7411307f60c1ba006035879187d83f18896f"
    },
    {
        "path": "tests/test_hia_core_integer_native_integration.py",
        "bytes": 52396,
        "sha256": "fd40a613324efe77aa58db9042a9ae079f2219cbcfc3103cbba86953f6a36897",
        "git_blob": "f62877c9c0c6bcefb3279fa95df2e098cc2426fe"
    }
]

def flatten(suite):
    result = []
    for item in suite:
        result.extend(flatten(item) if isinstance(item, unittest.TestSuite) else [item])
    return result

def test_pins(root):
    result = []
    for row in ORIGINAL_TEST_FILES:
        raw, pin = C.read_regular(root / row["path"])
        C.require(len(raw) == row["bytes"] and pin["sha256"] == row["sha256"]
            and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == row["git_blob"], "original complete test file differs: " + row["path"])
        result.append({"relative_path": row["path"], "pin": pin})
    return result

def project_origins(root):
    result = []
    for name, module in sorted(sys.modules.copy().items()):
        if name.split(".", 1)[0] not in {"hepta", "tools", "tests"} or module is None:
            continue
        file = getattr(module, "__file__", None)
        if file is None:
            locations = list(getattr(module, "__path__", ()))
            C.require(locations and all(Path(p).resolve(strict=True).is_relative_to(root)
                for p in locations), "foreign project namespace: " + name)
            result.append({"name": name, "namespace": [str(Path(p).resolve(strict=True))
                for p in locations]})
        else:
            path = Path(file).resolve(strict=True)
            C.require(path.is_relative_to(root), "foreign project import: " + name)
            result.append({"name": name, "path": str(path)})
    return result

class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, report, **kwargs):
        super().__init__(*args, **kwargs)
        self.report = report
        self.active_id = None

    def startTest(self, test):
        self.active_id = test.id()
        self.report["started_ids"].append(self.active_id)
        self.report["events"].append({"event": "start", "id": self.active_id,
                                     "monotonic_ns": time.monotonic_ns()})
        super().startTest(test)

    def stopTest(self, test):
        self.report["stopped_ids"].append(test.id())
        self.report["events"].append({"event": "stop", "id": test.id(),
                                     "monotonic_ns": time.monotonic_ns()})
        self.active_id = None
        super().stopTest(test)

    def addSuccess(self, test):
        self.report["success_ids"].append(test.id())
        super().addSuccess(test)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    request, materialization, request_pin = C.load_request(args.request, args.sha256)
    root = Path(request["source_root"])
    output = Path(request["output_root"])
    scratch = output / "scratch"
    report = {
        "schema": "hia.core-balanced-dispatch.original-source-tests-result.v1",
        "status": "HOLD", "request_sha256": request_pin["sha256"],
        "group": request["group"], "requested_ids": [], "loaded_ids": [],
        "started_ids": [], "stopped_ids": [], "success_ids": [], "events": [],
        "errors": [], "forbidden_attempts": [], "tests_run": 0,
        "test_failures": [], "test_errors": [], "test_skips": [],
        "test_expected_failures": [], "test_unexpected_successes": [],
        "VM": {"invoke_attempts": 0, "invoke_returns": 0, "invoke_exceptions": 0,
               "root_attempts": 0, "root_returns": 0, "root_exceptions": 0},
        "Core_author_write_executed": False,
        "native_image_or_compiler_execution": False,
        "original_python_object_emission_permitted": request["group"] == "source4",
        "original_python_compile_exec_binder_permitted": request["group"] == "source4",
        "is_full_standard_CI": False,
    }
    started = time.monotonic_ns()
    before = None
    result = None

    def deny(label):
        def fail(*unused_args, **unused_kwargs):
            report["forbidden_attempts"].append(label)
            raise RuntimeError("source group forbidden entry: " + label)
        return fail

    def resolve_event_path(path, directory_fd=None):
        if isinstance(path, int):
            C.require(directory_fd in (None, -1), "fd path with dir_fd")
            return Path(os.readlink("/proc/self/fd/" + str(path))).resolve(strict=False)
        name = os.fsdecode(os.fspath(path))
        if not os.path.isabs(name):
            base = (os.getcwd() if directory_fd in (None, -1)
                    else os.readlink("/proc/self/fd/" + str(directory_fd)))
            name = os.path.join(base, name)
        return Path(os.path.abspath(name)).resolve(strict=False)

    def in_scratch(path, directory_fd=None):
        resolved = resolve_event_path(path, directory_fd)
        return resolved == scratch or resolved.is_relative_to(scratch)

    evidence_files = {output / name for name in
        ("source-after.json", "source-tests-report.json")}

    def audit(event, arguments):
        if event in {"subprocess.Popen", "os.system", "os.posix_spawn",
                     "os.fork", "os.forkpty", "os.exec",
                     "ctypes.dlopen", "ctypes.dlsym", "mmap.__new__"} or event.startswith("socket."):
            deny("audit:" + event)()
        if event == "open":
            path, mode, flags = arguments
            writing = ((isinstance(mode, str) and any(c in mode for c in "wax+"))
                or (isinstance(flags, int) and
                    flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            if writing:
                resolved = resolve_event_path(path)
                if resolved not in evidence_files and not in_scratch(path):
                    deny("write:" + str(resolved))()
        if event == "os.mkdir" and not in_scratch(arguments[0], arguments[2]):
            deny("mkdir outside scratch")()
        if event in {"os.remove", "os.rmdir"} and not in_scratch(arguments[0], arguments[1]):
            deny("remove outside scratch")()
        if event == "os.chmod" and not in_scratch(arguments[0], arguments[2]):
            deny("chmod outside scratch")()
        if event == "os.truncate" and not in_scratch(arguments[0]):
            deny("truncate outside scratch")()
        if event in {"os.rename", "os.link", "os.symlink", "os.chown", "os.utime"}:
            deny("mutation:" + event)()

    try:
        C.require(type(request["group"]) is str and request["group"] in GROUPS,
                  "fixed source group")
        ids = GROUPS[request["group"]]
        C.require(request["requested_ids"] == ids
            and request["expected_tests"] == len(ids), "fixed complete method vector")
        C.require(request["generated_write_paths"] == []
            and request["allowed_changed_documents"] == []
            and request["unchanged_generated_paths"] == [], "no writable project source")
        C.require(sys.dont_write_bytecode is True, "source bytecode writes forbidden")
        C.require(scratch.resolve(strict=True) == scratch and scratch.is_dir(),
                  "fixed external scratch")
        C.require(not output.is_relative_to(root) and not root.is_relative_to(output),
                  "source and evidence roots must be disjoint")
        C.require(os.environ.get("TMPDIR") == str(scratch), "fixed TMPDIR")
        C.require(os.environ.get("HEPTA_COMPARE_BASE_ROOT") == str(root)
            and os.environ.get("HEPTA_COMPARE_CONTROL_EVIDENCE") ==
                str(scratch / "comparison-evidence"), "fixed original comparison fixture paths")
        C.require(not (scratch / "comparison-evidence").exists(),
                  "fresh original comparison evidence")
        C.require(not any(k.startswith("HEPTA_HIA_") and v for k, v in os.environ.items()),
                  "ambient native selector")
        C.require(not any(k.split(".", 1)[0] in {"hepta", "tools", "tests"}
                          for k in sys.modules), "fresh candidate import namespace")
        report["requested_ids"] = list(ids)
        before = C.source_snapshot(request, materialization)
        C.require_source_before(request, materialization, before)
        C.save_json(output / "source-before.json", before)
        report["original_test_files_before"] = test_pins(root)
        # These paths remain outside the immutable source. The original tests
        # own their TemporaryDirectory/addCleanup and class fixture lifecycles.
        tempfile.tempdir = str(scratch)
        sys.path.insert(0, str(root))
        sys.addaudithook(audit)
        with ExitStack() as stack:
            for module, name in ((subprocess, "Popen"), (os, "system"), (os, "fork"),
                                 (ctypes, "CDLL"), (ctypes, "PyDLL")):
                if hasattr(module, name):
                    stack.enter_context(patch.object(module, name,
                        side_effect=deny(module.__name__ + "." + name)))
            from hepta import hia_json_preflight_native as image
            stack.enter_context(patch.object(image.NativeHiaJsonImage, "__init__",
                                            side_effect=deny("NativeHiaJsonImage.__init__")))
            from tools import generate_hia_core_lowering as author
            stack.enter_context(patch.object(author, "write",
                                            side_effect=deny("Core_author.write")))
            from tools import qualify_hia_selfhost as compiler
            for name in ("build_seed", "compile_stage"):
                stack.enter_context(patch.object(compiler, name,
                                                side_effect=deny("compiler." + name)))
            from hepta.hia_program_runtime import _Machine
            original_invoke = _Machine.invoke
            depth = 0
            def observed_invoke(machine, *invoke_args, **invoke_kwargs):
                nonlocal depth
                if request["group"] != "source4":
                    deny("VM.invoke outside original Source4")()
                stats = report["VM"]
                outer = depth == 0
                stats["invoke_attempts"] += 1
                if outer:
                    stats["root_attempts"] += 1
                depth += 1
                try:
                    value = original_invoke(machine, *invoke_args, **invoke_kwargs)
                except BaseException:
                    stats["invoke_exceptions"] += 1
                    if outer:
                        stats["root_exceptions"] += 1
                    raise
                else:
                    stats["invoke_returns"] += 1
                    if outer:
                        stats["root_returns"] += 1
                    return value
                finally:
                    depth -= 1
            stack.enter_context(patch.object(_Machine, "invoke", observed_invoke))
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromNames(ids)
            report["loader_errors"] = list(loader.errors)
            actual = flatten(suite)
            report["loaded_ids"] = [test.id() for test in actual]
            C.require(not loader.errors and report["loaded_ids"] == ids
                and len(actual) == len(ids) and suite.countTestCases() == len(ids),
                "requested/loaded original methods differ")
            for test in actual:
                module = sys.modules[type(test).__module__]
                path = Path(module.__file__).resolve(strict=True)
                C.require(path.is_relative_to(root)
                    and path.relative_to(root).as_posix() in
                        {row["path"] for row in ORIGINAL_TEST_FILES},
                    "original method module origin")
            report["project_imports_before_tests"] = project_origins(root)
            def make_result(*result_args):
                return ObservedResult(*result_args, report=report)
            runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, failfast=False,
                                              buffer=False, resultclass=make_result)
            result = runner.run(suite)
            report["tests_run"] = result.testsRun
            for key, values in (
                ("test_failures", result.failures), ("test_errors", result.errors),
                ("test_skips", result.skipped),
                ("test_expected_failures", result.expectedFailures)):
                report[key] = [{"id": test.id(), "detail": detail} for test, detail in values]
            report["test_unexpected_successes"] = [test.id() for test in result.unexpectedSuccesses]
            report["project_imports_after_tests"] = project_origins(root)
            C.require(result.wasSuccessful() and not result.shouldStop
                and report["loaded_ids"] == report["started_ids"] == report["stopped_ids"]
                    == report["success_ids"] == ids
                and result.testsRun == len(ids)
                and not any(report[key] for key in
                    ("test_failures", "test_errors", "test_skips",
                     "test_expected_failures", "test_unexpected_successes"))
                and not report["forbidden_attempts"], "original complete group did not pass")
            if request["group"] == "source4":
                C.require(report["VM"]["root_attempts"] > 0
                    and report["VM"]["root_returns"] > 0, "original literal VM did not run")
            else:
                C.require(all(value == 0 for value in report["VM"].values()),
                          "fixture6 unexpectedly ran a VM")
                raw, fixture_pin = C.read_regular(scratch / "comparison-evidence" / "actual-VM-cases.json")
                fixture = C.decode(raw)
                C.require(fixture["native_executed"] is False
                    and fixture["compiler_executed"] is False
                    and type(fixture["case_count"]) is int and fixture["case_count"] == 0
                    and fixture["cases"] == [], "original fixture class evidence differs")
                report["comparison_class_evidence"] = fixture_pin
        report["candidate_status"] = "ORIGINAL_" + request["group"].upper() + "_PASS_ONLY"
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error),
                                "traceback": traceback.format_exc()})
        traceback.print_exc()
    finally:
        if before is not None:
            try:
                after = C.source_snapshot(request, materialization)
                report["changed_paths"] = C.require_source_after(request, before, after)
                C.require(report["changed_paths"] == [] and before == after,
                          "source must remain identical")
                C.save_json(output / "source-after.json", after)
                report["original_test_files_after"] = test_pins(root)
                C.require(report["original_test_files_before"] == report["original_test_files_after"],
                          "original test identities changed")
                for pin in request["inputs"]:
                    C.read_regular(pin["path"], pin)
            except BaseException as error:
                report["errors"].append({"type": type(error).__name__, "message": str(error),
                                        "traceback": traceback.format_exc()})
                traceback.print_exc()
        if (report.get("candidate_status") and not report["errors"]
                and not report["forbidden_attempts"]):
            report["status"] = report["candidate_status"]
        report["elapsed_ns"] = time.monotonic_ns() - started
        C.save_json(output / "source-tests-report.json", report)
    print(report["status"])
    return 0 if report["status"] != "HOLD" and not report["errors"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
