"""Independent original-first finite observer for the explicit div/rem slice.

The expected values are complete results of the retained original interpreter.
This observer never computes a quotient/remainder as an expected answer. Raw
tracebacks are retained separately and are not normalized into semantic PASS.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

CASE_PATH = "tests/fixtures/vm_integer_divrem_inputs_v1.json"
CASE_SHA256 = "325dbc6db74918277d4b1eb842e43de2cf83fcc5307d797e3e0d77f2f467086a"
RUNTIME_SHA256 = "ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56"
TEST_SHA256 = "73de53638397a1d564b3580551c83fa0ecf936c79af3ba1c5334b929aad45d3c"
SOURCE_PATHS = (
    "setup.py", "MANIFEST.in", "tests/test_hia_agent_installed_resources.py",
    "review-evidence/hia-native-rewrite-20261111/workflow_process.py",
    "examples/hia_bootstrap/vm_integer_divrem.hepta",
    "hepta/hia_vm_integer_divrem_protocol.py",
    "hepta/hia_vm_integer_divrem_native.py",
    "hepta/hia_vm_integer_divrem_runtime.py",
    "hepta/hia_program_runtime.py", "hepta/hia_program.py", "hepta/hia_opcodes.py",
    "hepta/hia_schema.py", "hepta/hia_bounded_memory.py",
    "hepta/hia_native_delivery.py", "hepta/hia_json_preflight_native.py",
    "hepta/hia_native_admission_io.py", "hepta/hia_native_helpers.py",
    "tools/build_hia_vm_integer_divrem.py", "tools/qualify_hia_vm_integer_divrem.py",
    "tools/read_hia_vm_integer_divrem.py",
    "tests/hia_vm_integer_divrem_cases.py", "tests/hia_vm_integer_divrem_controls.py",
    "tests/test_hia_vm_integer_divrem_native.py", "tests/test_hia_program.py",
    "tests/fixtures/vm_integer_divrem_runtime_ce39.py.txt", CASE_PATH,
)


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate evidence key")
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def source_capture():
    raw = {name: (ROOT / name).read_bytes() for name in SOURCE_PATHS}
    if (sha256(raw["hepta/hia_program_runtime.py"]).hexdigest() != RUNTIME_SHA256
            or raw["tests/fixtures/vm_integer_divrem_runtime_ce39.py.txt"] !=
               raw["hepta/hia_program_runtime.py"]
            or sha256(raw["tests/test_hia_program.py"]).hexdigest() != TEST_SHA256):
        raise ValueError("retained complete runtime/test source identity differs")
    return raw


def stable(raw):
    if any((ROOT / name).read_bytes() != value for name, value in raw.items()):
        raise ValueError("finite observation source changed")


def cases():
    raw = (ROOT / CASE_PATH).read_bytes()
    if sha256(raw).hexdigest() != CASE_SHA256:
        raise ValueError("finite inputs differ from their predeclared pin")
    document = decode(raw)
    rows = document["rows"]
    if (document["schema"] != "hepta.hia.vm-integer-divrem-finite-inputs.v1"
            or type(rows) is not list or len(rows) != 2500
            or len({row["id"] for row in rows}) != 2500):
        raise ValueError("complete div/rem finite inventory differs")
    for row in rows:
        if set(row) != {"id", "type", "operation", "lhs", "rhs"}:
            raise ValueError("finite input fields differ")
        if row["type"] not in ("i8", "u8", "i16", "u16", "i32", "u32",
                              "i64", "u64", "isize", "usize"):
            raise ValueError("finite scalar type differs")
        if row["operation"] not in ("int.div.checked", "int.rem.checked"):
            raise ValueError("finite operation differs")
        for name in ("lhs", "rhs"):
            value = row[name]
            if (type(value) is not str or not re.fullmatch(r"-?(0|[1-9][0-9]*)", value)
                    or value == "-0"):
                raise ValueError("finite integer must be an exact decimal string")
    return raw, rows


def exception_record(error):
    """Actual public fields; the full raw traceback is stored alongside."""
    return {"module": type(error).__module__, "type": type(error).__qualname__,
            "args": list(error.args), "message": str(error),
            "code": getattr(error, "code", None), "report": getattr(error, "report", None),
            "cause": None if error.__cause__ is None else exception_record(error.__cause__),
            "context": None if error.__context__ is None else exception_record(error.__context__),
            "suppress_context": error.__suppress_context__}


def observe(executor, program, function, arguments, limits=None):
    from hepta.hia_program import HIAProgramRejected
    from hepta.hia_program_runtime import HIAProgramTrap, HIAProgramBudgetExceeded
    try:
        result = executor(program, function, arguments, **(limits or {}))
    except (HIAProgramTrap, HIAProgramBudgetExceeded, HIAProgramRejected) as error:
        return {"outcome": "raised", "error": exception_record(error)}, "".join(
            traceback.format_exception(type(error), error, error.__traceback__))
    return {"outcome": "returned", "report": result}, ""


def finite(output, lane, manifest=None, manifest_sha256=None):
    output = Path(output)
    output.mkdir(mode=0o700)
    captured = source_capture()
    inputs_raw, rows = cases()
    # The two original processes do not import the candidate executor/image.
    from tests.test_hia_program import arithmetic
    from hepta.hia_program_runtime import execute_program
    if lane == "original":
        if manifest is not None or manifest_sha256 is not None:
            raise ValueError("original-only lane cannot select an image")
        executor, binding = execute_program, None
    elif lane == "native":
        from hepta.hia_vm_integer_divrem_runtime import NativeDivRemExecutor
        executor = NativeDivRemExecutor(manifest, manifest_sha256)
        binding = executor.binding
    else:
        raise ValueError("unknown finite lane")
    (output / "planned.json").write_bytes(canonical([row["id"] for row in rows]))
    count = 0
    with (output / "observations.jsonl").open("xb") as observed, (
            output / "raw-tracebacks.jsonl").open("xb") as traces:
        for row in rows:
            program = arithmetic(row["operation"], row["type"])
            args = [int(row["lhs"]), int(row["rhs"])]
            value, raw_trace = observe(executor, program, "calculate", args)
            # Only specified mathematical traps are within this finite domain.
            if value["outcome"] == "raised" and value["error"]["type"] != "HIAProgramTrap":
                raise AssertionError(("unexpected original/selected failure", row["id"], value))
            observed.write(canonical({"id": row["id"], "observation": value}))
            observed.flush()
            traces.write(canonical({"id": row["id"], "traceback": raw_trace}))
            traces.flush()
            count += 1
    stable(captured)
    if (ROOT / CASE_PATH).read_bytes() != inputs_raw:
        raise ValueError("finite input document changed")
    counts = None if binding is None else {
        "native_returns": binding.native_returns, "acknowledgements": binding.acknowledgements}
    if binding is not None:
        from hepta.hia_native_delivery import custody_snapshot
        binding.check()
        if counts != {"native_returns": 2500, "acknowledgements": 2500} or custody_snapshot():
            raise AssertionError(("selected finite delivery counts/custody differ", counts))
    report = {
        "schema": "hepta.hia.vm-integer-divrem-observations.v1", "lane": lane,
        "status": "OBSERVED_COMPLETE_DOMAIN", "planned": 2500, "completed": count,
        "case_inputs": pin(inputs_raw), "source_pins": {k: pin(v) for k, v in captured.items()},
        "streams": {name: pin((output / name).read_bytes()) for name in
                    ("planned.json", "observations.jsonl", "raw-tracebacks.jsonl")},
        "delivery": counts, "manifest_sha256": manifest_sha256,
        "runtime": {"version": sys.version, "executable": sys.executable},
        "raw_traceback_equivalence_claimed": False, "whole_vm_native": False,
    }
    (output / "report.json").write_bytes(canonical(report))
    return report


def generic(output, lane, manifest=None, manifest_sha256=None):
    import unittest
    from tests import test_hia_program as original_tests
    captured = source_capture()
    output = Path(output)
    output.mkdir(mode=0o700)
    original = original_tests.execute_program
    executor = None
    if lane == "native":
        from hepta.hia_vm_integer_divrem_runtime import NativeDivRemExecutor
        executor = NativeDivRemExecutor(manifest, manifest_sha256)
        original_tests.execute_program = executor
    elif lane != "original":
        raise ValueError("unknown generic lane")
    suite = unittest.defaultTestLoader.loadTestsFromModule(original_tests)
    def flatten(item):
        for test in item:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            else:
                yield test.id()
    planned = list(flatten(suite))
    if len(planned) != 21:
        raise AssertionError("original whole generic VM module is not 21 methods")
    started, stopped = [], []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
    try:
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2,
                                        resultclass=Result).run(suite)
    finally:
        original_tests.execute_program = original
    stable(captured)
    ok = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
          and not result.unexpectedSuccesses and planned == started == stopped)
    delivery = None if executor is None else {
        "native_returns": executor.binding.native_returns,
        "acknowledgements": executor.binding.acknowledgements}
    if executor is not None and (delivery["native_returns"] < 1
                                or delivery["native_returns"] != delivery["acknowledgements"]):
        raise AssertionError("selected full generic module never confirmed native div/rem")
    report = {"schema": "hepta.hia.vm-integer-divrem-generic21.v1",
              "status": "PASS_COMPLETE_ORIGINAL_METHODS" if ok else "HOLD",
              "lane": lane, "planned": planned, "started": started, "stopped": stopped,
              "testsRun": result.testsRun, "failures": len(result.failures),
              "errors": len(result.errors), "skips": len(result.skipped),
              "expectedFailures": len(result.expectedFailures), "delivery": delivery,
              "source_pins": {k: pin(v) for k, v in captured.items()},
              "default_public_entry_modified": False, "whole_vm_native": False}
    (output / "report.json").write_bytes(canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("finite", "generic"), required=True)
    parser.add_argument("--lane", choices=("original", "native"), required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    report = (finite if args.mode == "finite" else generic)(
        args.output, args.lane, args.manifest, args.manifest_sha256)
    print(json.dumps({"status": report["status"]}))
    if report["status"] == "HOLD":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
