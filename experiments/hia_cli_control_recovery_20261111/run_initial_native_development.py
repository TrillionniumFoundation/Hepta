"""One create-only CLI DEVELOPMENT compile and initial argv comparison.

The compiler originates in an earlier HOLD run. This script does not relabel
that run, claim matching-source cold qualification, or reuse unavailable r3
observations. Stop at the first new mismatch and retain its complete output.
"""
from __future__ import annotations
import argparse
import contextlib
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import time
import traceback
from unittest.mock import patch

COMPILER_SHA = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
SOURCE_NAMES = (
    "hepta/cli.py", "hepta/hia_cli_native.py", "tools/build_hia_cli_native.py",
    "tools/generate_hia_cli_control.py", "tools/hia_cli_control_phases.py",
    "tools/generate_hia_cli_format.py", "tools/hia_cli_unicode_tables.json",
    "examples/hia_bootstrap/cli_control.hiaasm", "examples/hia_bootstrap/cli_format.hiaasm",
)
ACTIONS = (
    "capabilities", "catalog", "import-assembly", "render-assembly", "check-assembly",
    "verify", "inspect", "normalize", "build", "patch", "impact", "edit-query",
    "edit-apply", "edit-batch-query", "edit-batch-apply",
)
CASES = [
    [], ["--version"], ["--help"], ["--he"], ["--help=oops"], ["-hv"],
    ["not-an-action"], ["verify", "x"], ["verify", "--", "-oops"],
    ["verify", "x", "-extra"], ["build", "x"],
    ["build", "x", "-ooutput", "--kind=object"],
    ["build", "x", "--output", "first", "-o", "second"],
    ["build", "x", "--backend", "llvm", "--help"],
    ["catalog", "--sch", "hepta.hia.program.v1"],
    ["edit-query", "x", "--function", "f", "--block", "b", "--value", "v", "--fields", "op,,args,"],
    ["edit-query", "--help", "--f", "x"],
] + [[action, "--help"] for action in ACTIONS]


class Accepted(BaseException):
    def __init__(self, namespace):
        self.namespace = namespace


def file_identity(path):
    raw = Path(path).read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    report = {
        "schema": "hia.cli.initial-native-development-observation.v1",
        "status": "HOLD", "source": str(source), "source_revision": args.source_revision,
        "base_commit": "e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6",
        "scope": "NEW_RECOVERY_REVISION_DEVELOPMENT_ONLY_NOT_COLD_NOT_WHOLE_CLI",
        "old_r3_observations_reused": False, "compiler_origin": "416 desktop B3; complete cold remained HOLD",
        "planned_argv_cases": [{"id": "argv-%03d" % i, "argv": argv} for i, argv in enumerate(CASES)],
        "argv_cases": [], "native_returns": [], "whole_native_delivery_qualified": False,
        "native_profile_expanded": False,
    }
    def snapshot():
        return {name: sha256((source / name).read_bytes()).hexdigest() for name in SOURCE_NAMES}
    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    started = time.monotonic_ns()
    report["source_before"] = snapshot()
    report["compiler_original_before"] = file_identity(args.compiler)
    save()
    try:
        if report["compiler_original_before"]["sha256"] != COMPILER_SHA:
            raise RuntimeError("development compiler pin mismatch")
        compiler = output / "B3.image.bin"
        raw = args.compiler.read_bytes()
        with compiler.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if compiler.read_bytes() != raw:
            raise RuntimeError("private compiler copy mismatch")
        report["compiler_copy"] = file_identity(compiler)
        sys.path.insert(0, str(source))
        from tools.build_hia_cli_native import build_development
        manifest = build_development(output / "bundle", compiler)
        report["bundle_manifest"] = file_identity(manifest)
        from hepta import cli
        from hepta.hia_cli_native import installed_cli, _print_parser_message
        owner = installed_cli(str(manifest))
        for name in ("control", "formatter"):
            image = getattr(owner, name)
            actual = image._entry
            def observe(*values, _actual=actual, _name=name):
                result = _actual(*values)
                report["native_returns"].append({"image": _name, "status": result})
                return result
            image._entry = observe
        original_parse = argparse.ArgumentParser.parse_args

        def reference(argv):
            stdout, stderr = io.StringIO(), io.StringIO()
            def capture(parser, *values, **keywords):
                raise Accepted(original_parse(parser, *values, **keywords))
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    with patch.object(argparse.ArgumentParser, "parse_args", capture):
                        cli._reference_hia_main(argv)
                except Accepted as result:
                    answer = {"kind": "namespace", "namespace": vars(result.namespace)}
                except SystemExit as error:
                    answer = {"kind": "exit", "code": error.code}
                except BaseException as error:
                    answer = {"kind": "error", "type": type(error).__name__, "message": str(error)}
            answer.update(stdout=stdout.getvalue(), stderr=stderr.getvalue())
            return answer

        def native(argv):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    with patch.object(argparse, "ArgumentParser", side_effect=AssertionError("retained argparse entered")):
                        session = owner.prepare(argv, cli)
                        if session.kind == 0:
                            answer = {"kind": "namespace", "namespace": vars(session.namespace)}
                        else:
                            first, second = owner.format_result(session)
                            if session.kind == 3:
                                _print_parser_message(first, sys.stderr)
                                _print_parser_message(second, sys.stderr)
                            else:
                                _print_parser_message(first + second, sys.stdout)
                            answer = {"kind": "exit", "code": session.exit_code}
                except BaseException as error:
                    answer = {"kind": "error", "type": type(error).__name__, "message": str(error)}
            answer.update(stdout=stdout.getvalue(), stderr=stderr.getvalue())
            return answer

        environment = dict(os.environ)
        for name in tuple(environment):
            if name.startswith("HEPTA_HIA_"):
                environment.pop(name)
        environment.update(COLUMNS="80", LINES="24", TERM="dumb", NO_COLOR="", FORCE_COLOR="", PYTHON_COLORS="0")
        with patch.dict(os.environ, environment, clear=True):
            for index, argv in enumerate(CASES):
                expected, actual = reference(argv), native(argv)
                item = {"id": "argv-%03d" % index, "argv": argv, "expected": expected, "actual": actual,
                        "pass": actual == expected}
                report["argv_cases"].append(item)
                save()
                if not item["pass"]:
                    raise AssertionError("new native argv mismatch: " + item["id"])
            def capabilities(selected):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    if selected:
                        with (patch.dict(os.environ, {"HEPTA_HIA_CLI_MANIFEST": str(manifest)}),
                              patch.object(argparse, "ArgumentParser", side_effect=AssertionError("retained argparse entered")),
                              patch.object(cli, "_reference_hia_main", side_effect=AssertionError("retained CLI entered"))):
                            code = cli.hia_main(["capabilities"])
                    else:
                        code = cli._reference_hia_main(["capabilities"])
                return {"code": code, "stdout": stdout.getvalue(), "stderr": stderr.getvalue()}
            expected, actual = capabilities(False), capabilities(True)
            report["actual_selected_entry_capabilities"] = {"expected": expected, "actual": actual,
                                                           "pass": actual == expected}
            if actual != expected:
                raise AssertionError("actual selected capabilities entry differs")
        report["status"] = "PASS_LIMITED_NATIVE_DEVELOPMENT"
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error),
                           "traceback": traceback.format_exc()}
    finally:
        report["elapsed_ns"] = time.monotonic_ns() - started
        report["source_after"] = snapshot()
        report["compiler_original_after"] = file_identity(args.compiler)
        report["source_preserved"] = report["source_before"] == report["source_after"]
        report["compiler_original_preserved"] = report["compiler_original_before"] == report["compiler_original_after"]
        if not report["source_preserved"] or not report["compiler_original_preserved"]:
            report["status"] = "HOLD"
        report["argv_cases_executed"] = len(report["argv_cases"])
        report["argv_cases_passed"] = sum(case["pass"] for case in report["argv_cases"])
        report["all_argv_cases_executed"] = len(report["argv_cases"]) == len(CASES)
        save()
        print(json.dumps({key: report[key] for key in ("status", "elapsed_ns", "argv_cases_executed",
              "argv_cases_passed", "source_preserved", "compiler_original_preserved")}))
    return 0 if report["status"] == "PASS_LIMITED_NATIVE_DEVELOPMENT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
