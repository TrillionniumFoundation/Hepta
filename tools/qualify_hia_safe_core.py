"""Retain exact Safe Core images, five raw SMT obligations and five SAT mutants.

The qualification also requires the complete targeted adversarial/native test
inventory with zero skips.  Finite native execution and all-input SMT model
results are reported separately; neither activates a production release.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_machine_x64 import Code
from hepta.hia_safe_core import validate_safe_core_image, SafeCoreRejected, _source_identity
from tools.build_hia_safe_core import build
from tools.check_hia_safe_core import check as check_artifact


def _identity():
    return {**{"hepta/" + key: value for key, value in _source_identity().items()},
            **{name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                "tools/build_hia_safe_core.py", "tools/qualify_hia_safe_core.py", "tests/test_hia_safe_core.py",
                "tools/check_hia_safe_core.py", "tests/test_hia_safe_core_artifact.py",
                "examples/hia_safe_core/scalar_add.hia.json", "examples/hia_safe_core/guarded_update.hia.json",
                "examples/hia_safe_core/read_byte.hia.json")}}


def _save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def _ids(suite):
    return [name for item in suite for name in (_ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])]


class _Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed, self.case_counts = [], {}

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        if getattr(test, "case_counts", None):
            self.case_counts[test.id()] = test.case_counts
        super().stopTest(test)


@contextmanager
def _mutant(name):
    if name == "addition_becomes_subtraction":
        with patch.object(Code, "add", Code.sub):
            yield
    elif name == "equal_extent_is_admitted":
        original = Code.jcc
        def wrong(code, condition, target):
            return original(code, "a" if condition == "ae" else condition, target)
        with patch.object(Code, "jcc", wrong):
            yield
    elif name == "byte_store_becomes_word_store":
        with patch.object(Code, "store_u8", Code.store):
            yield
    elif name == "callee_saved_rbx_is_clobbered":
        original = Code.ret
        def clobber(code):
            code.mov_imm("rbx", 123)
            original(code)
        with patch.object(Code, "ret", clobber):
            yield
    elif name == "nonreturning_abort_uses_invalid_stack":
        original = Code.call
        def corrupt_stack(code, symbol):
            if symbol == "abort":
                code.mov_imm("rsp", 0)
            return original(code, symbol)
        with patch.object(Code, "call", corrupt_stack):
            yield
    else:
        raise ValueError("unknown negative mutation")


def qualify(output):
    output = Path(output).absolute()
    output.mkdir(exist_ok=False)
    started = time.monotonic()
    source = _identity()
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    report = {"schema": "hepta.hia.safe-core-qualification.v1", "ok": False, "status": "running",
              "started_utc": datetime.now(timezone.utc).isoformat(), "git_head": git.stdout.strip() if git.returncode == 0 else None,
              "source_identity": source, "positive": [], "negative": [], "replay": [], "artifact_rechecks": [],
              "claims": {"complete_selected_model_validation": False, "finite_native_tests_passed": False,
                         "machine_checked_isa_refinement_proved": False, "whole_language_soundness_proved": False,
                         "default_release_or_production_admission_changed": False}}
    try:
        suite = unittest.defaultTestLoader.loadTestsFromNames(
            ["tests.test_hia_safe_core", "tests.test_hia_safe_core_artifact"])
        inventory = _ids(suite)
        log = io.StringIO()
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=_Result).run(suite)
        (output / "tests.stdout.log").write_text(log.getvalue())
        report["tests"] = {"inventory": inventory, "executed": result.executed, "count": result.testsRun,
                           "case_counts": result.case_counts,
                           "failures": [{"id": t.id(), "traceback": text} for t, text in result.failures],
                           "errors": [{"id": t.id(), "traceback": text} for t, text in result.errors],
                           "skipped": [{"id": t.id(), "reason": reason} for t, reason in result.skipped]}
        if not result.wasSuccessful() or result.skipped or len(inventory) != len(set(inventory)) or sorted(inventory) != sorted(result.executed):
            raise ValueError("targeted qualification test inventory did not pass completely")
        for name, extent in (("scalar_add", None), ("guarded_update", 4096), ("read_byte", 64)):
            attempt = build(ROOT / "examples/hia_safe_core" / (name + ".hia.json"), output / name, foreign_extent=extent)
            report["positive"].append({"case": name, "report": name + "/attempt.json", "ok": attempt["ok"],
                                       "elapsed_seconds": attempt["elapsed_seconds"]})
            if not attempt["ok"]:
                raise ValueError("selected positive failed: " + name)
            directory = output / name
            independent = check_artifact(directory / "source.hia.json", directory / "candidate.o",
                                         directory / "program.so", directory / "independent-check",
                                         foreign_extent=extent,
                                         expected_sha256={"source": attempt["source_sha256"],
                                             "object": attempt["result"]["validation"]["image_binding"]["object_sha256"],
                                             "image": attempt["result"]["artifact_sha256"]})
            report["artifact_rechecks"].append({"case": name, "ok": independent["ok"],
                "report": name + "/independent-check/attempt.json", "compiler_invoked": False})
            if not independent["ok"]:
                raise ValueError("independent supplied-artifact check failed: " + name)
        for name, case, extent in (("addition_becomes_subtraction", "scalar_add", None),
                                   ("equal_extent_is_admitted", "read_byte", 64),
                                   ("byte_store_becomes_word_store", "guarded_update", 4096),
                                   ("callee_saved_rbx_is_clobbered", "scalar_add", None),
                                   ("nonreturning_abort_uses_invalid_stack", "read_byte", 64)):
            path = output / name
            path.mkdir()
            tick = time.monotonic()
            original = (ROOT / "examples/hia_safe_core" / (case + ".hia.json")).read_bytes()
            (path / "source.hia.json").write_bytes(original)
            checked = verify_program(original)
            manifest = () if extent is None else ((checked.as_dict()["functions"][0]["name"], extent),)
            with _mutant(name):
                image = emit_program_machine(checked, foreign_buffer_exports=manifest)
                (path / "candidate.rejected.o").write_bytes(image.object_bytes)
                (path / "candidate.rejected.text.bin").write_bytes(image.text_bytes)
                compiled = compile_program_machine(image, program=checked, output=path / "candidate.rejected.so", linker="ld")
                (path / "compilation.json").write_text(json.dumps(compiled, sort_keys=True, indent=2) + "\n")
                try:
                    validate_safe_core_image(checked, image, (path / "candidate.rejected.so").read_bytes(),
                                             query_directory=path / "queries")
                except SafeCoreRejected as exc:
                    if exc.counterexample is None:
                        raise ValueError("faulty backend did not reach a semantic SAT counterexample: " + name) from exc
                    mutation = {"case": name, "status": "rejected_with_sat_counterexample",
                                "error": str(exc), "counterexample": exc.counterexample,
                                "core_sha256": checked.sha256, "object_sha256": image.sha256,
                                "final_image_sha256": compiled["artifact_sha256"],
                                "elapsed_seconds": time.monotonic() - tick}
                    _save(path / "rejection.json", mutation)
                    report["negative"].append(mutation)
                else:
                    raise ValueError("faulty backend was accepted: " + name)
        # Replay every retained raw query independently, including the SAT
        # counterexamples and nonvacuity checks, using fresh solver contexts.
        import z3
        for path in sorted(output.glob("*/queries/*.smt2")):
            expected = json.loads(path.with_suffix(".smt2.result.json").read_bytes())
            context = z3.Context()
            solver = z3.Solver(ctx=context)
            solver.set(timeout=15000)
            solver.from_file(str(path))
            tick = time.monotonic()
            observed = str(solver.check())
            row = {"query": str(path.relative_to(output)), "query_sha256": sha256(path.read_bytes()).hexdigest(),
                   "result": observed, "expected": expected["result"], "elapsed_seconds": time.monotonic() - tick}
            report["replay"].append(row)
            if observed != expected["result"] or row["query_sha256"] != expected["query_sha256"]:
                raise ValueError("raw SMT replay or source binding differs")
        report["source_unchanged"] = source == _identity()
        if not report["source_unchanged"]:
            raise ValueError("qualification source changed during the campaign")
        report.update(ok=True, status="passed")
        report["claims"].update(complete_selected_model_validation=True, finite_native_tests_passed=True)
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic() - started)
        _save(output / "qualification.json", report)
        manifest = {str(path.relative_to(output)): {"sha256": sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
                    for path in sorted(output.rglob("*")) if path.is_file()}
        _save(output / "original-files.json", manifest)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new raw-evidence directory")
    args = parser.parse_args(argv)
    report = qualify(args.output)
    print(json.dumps({"ok": report["ok"], "status": report["status"], "tests": report.get("tests", {}).get("count"),
                      "positive_cases": len(report["positive"]), "negative_cases": len(report["negative"]),
                      "replayed_queries": len(report["replay"]), "elapsed_seconds": report["elapsed_seconds"],
                      "error": report.get("error"), "output": str(Path(args.output).absolute())}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
