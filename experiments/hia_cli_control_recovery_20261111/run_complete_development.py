"""Single owned ordinary-CLI development suite; every original is retained.

This is an explicit development image build, not matching-source cold or
whole-native qualification. The exact original tests remain loaded and a
fresh process owner retains all stdout, stderr, timeout and cleanup facts.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest

COMPILER_SHA = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
SCHEMA = "hia.cli.complete-development-suite.v1"


def identity(path):
    raw = Path(path).read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def snapshot(source):
    return {path.relative_to(source).as_posix(): sha256(path.read_bytes()).hexdigest()
            for folder in ("hepta", "tools", "tests", "examples/hia_bootstrap")
            for path in sorted((source / folder).rglob("*"))
            if path.is_file() and path.suffix in (".py", ".hiaasm", ".json", ".S")}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def flatten(suite):
    for value in suite:
        if isinstance(value, unittest.TestSuite):
            yield from flatten(value)
        else:
            yield value


def child(args):
    source, output = args.source.resolve(strict=True), args.output.resolve(strict=True)
    started = time.monotonic_ns()
    report = {"schema": SCHEMA, "status": "HOLD", "scope": "EXPLICIT_DEVELOPMENT_ONLY",
              "source_revision": args.source_revision, "source": str(source),
              "python": sys.version, "loaded_test_ids": [], "executed_test_ids": [],
              "native_returns": [], "whole_native_delivery_qualified": False,
              "old_r3_observations_reused": False, "native_profile_expanded": False}
    report["source_before"] = snapshot(source)
    report["compiler_before"] = identity(args.compiler)
    save(output / "suite.json", report)
    try:
        if report["compiler_before"]["sha256"] != COMPILER_SHA:
            raise RuntimeError("explicit development compiler identity differs")
        compiler = output / "B3.image.bin"
        raw = args.compiler.read_bytes()
        with compiler.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if compiler.read_bytes() != raw:
            raise RuntimeError("development compiler copy differs")
        sys.path.insert(0, str(source))
        from tools.build_hia_cli_native import build_development
        manifest = build_development(output / "bundle", compiler)
        report["manifest"] = identity(manifest)
        from hepta.hia_cli_native import installed_cli
        owner = installed_cli(str(manifest))
        for label in ("control", "formatter"):
            image = getattr(owner, label)
            actual = image._entry
            def observe(*values, _actual=actual, _label=label):
                value = _actual(*values)
                report["native_returns"].append({"image": _label, "status": value})
                return value
            image._entry = observe
        os.environ["HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST"] = str(manifest)
        os.environ["HEPTA_HIA_CLI_FIXTURE_EVIDENCE"] = str(output / "fixtures")
        suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_hia_cli_native")
        report["loaded_test_ids"] = [test.id() for test in flatten(suite)]
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                report["executed_test_ids"].append(test.id())
                super().startTest(test)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun,
                      failures=[(test.id(), detail) for test, detail in result.failures],
                      errors=[(test.id(), detail) for test, detail in result.errors],
                      skipped=[(test.id(), detail) for test, detail in result.skipped],
                      expected_failures=[(test.id(), detail) for test, detail in result.expectedFailures],
                      unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        ids = report["loaded_test_ids"]
        report["checks"] = {
            "nonempty_unique_loaded": bool(ids) and len(ids) == len(set(ids)),
            "every_loaded_id_executed_in_order": ids == report["executed_test_ids"],
            "exact_tests_run": result.testsRun == len(ids),
            "zero_anomalies": not any(report[key] for key in
                ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")),
            "actual_native_returns_observed": bool(report["native_returns"]),
        }
        if all(report["checks"].values()):
            report["status"] = "PASS_DEVELOPMENT_ONLY"
    except BaseException as error:
        report.update(error_type=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
    finally:
        report["elapsed_ns"] = time.monotonic_ns() - started
        try:
            report["source_after"] = snapshot(source)
            report["source_preserved"] = report["source_after"] == report["source_before"]
            report["compiler_after"] = identity(args.compiler)
            report["compiler_preserved"] = report["compiler_before"] == report["compiler_after"]
            if not report["source_preserved"] or not report["compiler_preserved"]:
                report["status"] = "HOLD"
        except BaseException as error:
            report["status"] = "HOLD"
            report["final_observation_error"] = {"type": type(error).__name__, "message": str(error),
                                                "traceback": traceback.format_exc()}
        save(output / "suite.json", report)
        print(json.dumps({key: report.get(key) for key in
              ("status", "tests_run", "elapsed_ns", "source_preserved", "compiler_preserved", "checks")}))
    return 0 if report["status"] == "PASS_DEVELOPMENT_ONLY" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--child", action="store_true")
    args = parser.parse_args()
    if args.child:
        return child(args)
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    (output / "tmp").mkdir(mode=0o700)
    (output / "home").mkdir(mode=0o700)
    report = {"schema": SCHEMA, "status": "HOLD", "scope": "EXPLICIT_DEVELOPMENT_ONLY",
              "source_revision": args.source_revision, "source": str(source),
              "source_before": snapshot(source), "compiler_before": identity(args.compiler),
              "controller": identity(__file__), "whole_native_delivery_qualified": False,
              "old_r3_observations_reused": False, "qualification_seconds": 180,
              "native_profile_expanded": False}
    save(output / "owned-suite.json", report)
    started = time.monotonic_ns()
    try:
        sys.path.insert(0, str(source))
        from tools.hia_selfhost_process_owner import run_owned
        command = [sys.executable, "-B", str(Path(__file__).resolve()),
                   "--source", str(source), "--compiler", str(args.compiler.resolve(strict=True)),
                   "--output", str(output), "--source-revision", args.source_revision, "--child"]
        environment = {"PATH": os.defpath, "HOME": str(output / "home"),
                       "TMPDIR": str(output / "tmp"), "PYTHONPATH": str(source),
                       "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "TZ": "UTC"}
        report["process_owner"] = run_owned(
            command, cwd=source, env=environment, stdout_path=output / "stdout.log",
            stderr_path=output / "stderr.log", receipt_path=output / "process-owner.json")
        owner = report["process_owner"]
        if (output / "suite.json").is_file():
            report["suite_identity"] = identity(output / "suite.json")
            nested = json.loads((output / "suite.json").read_bytes())
        else:
            nested = {}
        cleanup = owner.get("cleanup", {})
        report["checks"] = {
            "owned_normal_completion": owner.get("status") == "OWNED_PROCESS_COMPLETED"
                and owner.get("returncode") == 0 and owner.get("supervisor_returncode") == 0
                and owner.get("exit_observed_before_deadline") is True
                and owner.get("timed_out") is False and not owner.get("interrupted_signals")
                and not owner.get("error") and not owner.get("errors") and not owner.get("event_overflow"),
            "complete_reaping": cleanup.get("attempted") is True and cleanup.get("complete") is True
                and cleanup.get("observed_echild") is True and cleanup.get("leader_reaped") is True
                and not cleanup.get("errors") and not cleanup.get("remaining")
                and not cleanup.get("deadline_exceeded"),
            "no_forced_descendant_cleanup": bool(owner.get("events")) and all(
                event.get("kind") in {"qualification_started", "owned_child_observed",
                                      "qualification_exit_observed", "owned_child_reaped"}
                for event in owner.get("events", [])),
            "complete_suite": nested.get("status") == "PASS_DEVELOPMENT_ONLY"
                and bool(nested.get("checks")) and all(nested.get("checks", {}).values()),
            "source_and_compiler_preserved_by_child": nested.get("source_preserved") is True
                and nested.get("compiler_preserved") is True,
        }
        if all(report["checks"].values()):
            report["status"] = "PASS_DEVELOPMENT_ONLY"
    except BaseException as error:
        report.update(error_type=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
    finally:
        report["elapsed_ns"] = time.monotonic_ns() - started
        try:
            report["source_after"] = snapshot(source)
            report["compiler_after"] = identity(args.compiler)
            report["source_preserved"] = report["source_after"] == report["source_before"]
            report["compiler_preserved"] = report["compiler_after"] == report["compiler_before"]
            report["controller_after"] = identity(__file__)
            report["controller_preserved"] = report["controller_after"] == report["controller"]
            if not report["source_preserved"] or not report["compiler_preserved"] or not report["controller_preserved"]:
                report["status"] = "HOLD"
        except BaseException as error:
            report["status"] = "HOLD"
            report["final_observation_error"] = {"type": type(error).__name__, "message": str(error),
                                                "traceback": traceback.format_exc()}
        save(output / "owned-suite.json", report)
        print(json.dumps({key: report.get(key) for key in
              ("status", "elapsed_ns", "source_preserved", "compiler_preserved", "checks")}))
    return 0 if report["status"] == "PASS_DEVELOPMENT_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
