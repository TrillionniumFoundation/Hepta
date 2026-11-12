"""Generate and execute a separate, real HIA image for finite mechanism probes.

All control/literals are emitted by that compiled image. No runtime table is
patched or host interpreted. The original policy file provides the independent
CPython oracle. Generation and compilation are development-only observations.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import traceback
import weakref


def digest(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def ambient():
    error = sys.exception()
    return None if error is None else [type(error).__name__, list(error.args)]


class ProbeError(Exception):
    pass


class Truth:
    def __init__(self, trace, truth, fail):
        self.trace, self.truth, self.fail = trace, truth, fail

    def __bool__(self):
        self.trace.append(["truth", self.truth, ambient()])
        if self.fail:
            raise ProbeError("truth")
        return self.truth

    def __del__(self):
        self.trace.append(["left-del", ambient()])


class BoolContext:
    def __init__(self, truth, failure):
        self.trace, self.weak = [], {}
        self.truth, self.failure = truth, failure

    @property
    def left(self):
        self.trace.append(["left-get", ambient()])
        value = Truth(self.trace, self.truth, self.failure == "truth")
        self.weak["left"] = weakref.ref(value)
        return value

    def right(self):
        self.trace.append(["right", self.weak["left"]() is None, ambient()])
        if self.failure == "right":
            raise ProbeError("right")
        return 37


class Argument:
    def __init__(self, trace, index):
        self.trace, self.index = trace, index

    def __del__(self):
        self.trace.append(["argument-del", self.index, ambient()])


class Callable:
    def __init__(self, trace, weak, fail, clear):
        self.trace, self.weak, self.fail, self.clear = trace, weak, fail, clear

    def __call__(self, first=None, second=None, third=None, fourth=None, *, text_alignment=None):
        self.trace.append(["call", [None if item is None else item.index
                                    for item in (first, second, third, fourth, text_alignment)],
                           first is not None and first is second, ambient()])
        if self.clear:
            first = second = third = fourth = text_alignment = None
            self.trace.append(["after-parameter-clear", {
                name: ref() is not None for name, ref in self.weak.items()
                if name != "callee"}, ambient()])
        if self.fail:
            raise ProbeError("call")
        return 41

    def __del__(self):
        self.trace.append(["callee-del", ambient()])


class CallContext:
    def __init__(self, arity, fail, clear, alias=False):
        self.trace, self.weak = [], {}
        self.arity, self.fail, self.clear = arity, fail, clear
        self.shared = None
        if alias:
            self.shared = Argument(self.trace, 99)
            self.weak["shared"] = weakref.ref(self.shared)

    def factory(self):
        self.trace.append(["factory", ambient()])
        value = Callable(self.trace, self.weak, self.fail, self.clear)
        self.weak["callee"] = weakref.ref(value)
        return value

    def argument(self, index):
        self.trace.append(["argument", index, ambient()])
        value = Argument(self.trace, index)
        self.weak[str(index)] = weakref.ref(value)
        return value


def capture(operation, context):
    try:
        return True, operation(context)
    except BaseException as error:
        return False, error


def observe(operation, context):
    result = capture(operation, context)
    if result[0]:
        value = result[1]
        if type(value) is Truth:
            outcome = {"returned": "same-left", "identity": context.weak["left"]() is value}
        else:
            outcome = {"returned": type(value).__name__, "value": value}
        value = None
    else:
        outcome = {"error": type(result[1]).__name__, "args": list(result[1].args)}
    held = list(context.trace)
    alive_held = {name: ref() is not None for name, ref in context.weak.items()}
    result = None
    # Deliberately no gc.collect, traceback surgery, or error traceback detach.
    released = list(context.trace)
    alive_released = {name: ref() is not None for name, ref in context.weak.items()}
    if isinstance(context, CallContext):
        context.shared = None
    return {"outcome": outcome, "held": held, "alive_held": alive_held,
            "released": released, "alive_released": alive_released,
            "final": list(context.trace),
            "final_alive": {name: ref() is not None for name, ref in context.weak.items()}}


def with_ambient(operation, context, outer):
    if outer:
        try:
            raise LookupError("ambient")
        except LookupError:
            return observe(operation, context)
    return observe(operation, context)


def compare_case(owner, reference, mode, make_context, label, outer):
    original = with_ambient(reference, make_context(), outer)
    actual = with_ambient(lambda context: owner.run(mode, context), make_context(), outer)
    return {"case": label, "outer": outer, "mode": mode,
            "original": original, "native": actual, "equal": original == actual}


def run_cases(owner, oracle):
    cases = []
    for mode, name in enumerate(("validate_plan", "register_assignment_witness", "code_options", "preservation_checks"), 1):
        for truth in (False, True):
            for failure in (None, "truth", "right"):
                for outer in (False, True):
                    cases.append(compare_case(owner, getattr(oracle, name), mode,
                        lambda truth=truth, failure=failure: BoolContext(truth, failure),
                        f"{name}/truth={truth}/failure={failure}", outer))
    for mode, name, arities in ((5, "_require", range(5)), (6, "_permutation", (0, 1, 3)), (7, "_terminal_arguments", (2,))):
        for arity in arities:
            for fail in (False, True):
                for clear in (False, True):
                    for outer in (False, True):
                        cases.append(compare_case(owner, getattr(oracle, name), mode,
                            lambda arity=arity, fail=fail, clear=clear, mode=mode:
                                CallContext(arity, fail, clear, alias=mode == 7),
                            f"{name}/arity={arity}/fail={fail}/clear={clear}", outer))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--require-match", action="store_true")
    args = parser.parse_args()
    source, compiler, output = args.source.resolve(), args.compiler.resolve(), args.output.resolve()
    output.mkdir(mode=0o700)
    sys.path.insert(0, str(source))
    os.chdir(source)
    policy_path = Path(__file__).with_name("mechanism_policy.py")
    pins = [Path(__file__), policy_path, compiler] + [source / path for path in (
        "tools/hia_machine_plan_control.py", "tools/generate_hia_machine_plan_control.py",
        "hepta/hia_machine_plan_control_native.py", "tools/generate_hia_selfhost.py",
        "hepta/hia_exception_delivery.py", "tools/hia_exception_delivery.py",
        "tools/qualify_hia_selfhost.py", "tools/hia_selfhost_native_observer.py")]
    if args.image is not None:
        pins.append(args.image.resolve())
    before = {str(path): digest(path) for path in pins}
    report = {"scope": "SHARED_CONTROL_MECHANISM_EXPLICIT_DEVELOPMENT_ONLY",
              "public_Core_or_plan_qualification": False, "current_cold": False,
              "python": sys.version, "runtime": sys.implementation.name,
              "source": str(source), "inputs_before": before}
    start = time.monotonic()
    try:
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_machine_plan_control_native import NativeMachinePlanControl
        from tools import generate_hia_machine_plan_control as generator
        from tools.hia_machine_plan_control import compile_policy, OPS
        from tools.qualify_hia_selfhost import compile_stage
        policy = compile_policy(policy_path.read_text())
        calls = []
        for function in policy.functions:
            for instruction in function.instructions:
                if instruction["kind"] == "effect" and instruction["opcode"] == OPS["CALL"]:
                    arguments = instruction["arguments"]
                    slots = [value.slot for value in arguments]
                    valid = (len(slots) == len(set(slots))
                             and all(value.temporary and value.slot in function.temporary_slots
                                     and value.slot not in function.cell_slots for value in arguments)
                             and instruction["consume"] == arguments)
                    calls.append({"function": function.name, "pc": instruction["pc"],
                                  "slots": slots, "raw": instruction["raw"], "valid": valid})
        assert calls and all(row["valid"] for row in calls)
        report["call_operand_contract"] = calls
        if args.image is None:
            previous = generator.program
            generator.program = lambda: policy
            try:
                document = generator.document()
                raw = render_assembly(document).encode("utf-8")
            finally:
                generator.program = previous
            hia = output / "mechanism.hiaasm"
            hia.write_bytes(raw)
            report["hia"] = {"path": str(hia), **digest(hia)}
            image, receipt = compile_stage(output, "mechanism", compiler, raw)
            report["compile_receipt"] = receipt
        else:
            image = args.image.resolve()
        report["image"] = {"path": str(image), **digest(image)}
        owner = NativeMachinePlanControl(image.read_bytes(), report["image"]["sha256"])
        spec = importlib.util.spec_from_file_location("shared_mechanism_original", policy_path)
        oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle)
        report["cases"] = run_cases(owner, oracle)
        report["entries"] = owner.entries
        report["matched"] = sum(case["equal"] for case in report["cases"])
        report["total"] = len(report["cases"])
        report["status"] = "PASS" if report["matched"] == report["total"] else "ORIGINAL_EQUIVALENCE_FAIL"
    except BaseException:
        report.update(status="HARNESS_OR_EXECUTION_ERROR", exception=traceback.format_exc())
    finally:
        report["inputs_after"] = {str(path): digest(path) for path in pins}
        report["inputs_unchanged"] = before == report["inputs_after"]
        if not report["inputs_unchanged"]:
            report["status"] = "INPUT_CHANGED"
        report["seconds"] = time.monotonic() - start
        (output / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: report.get(key) for key in (
            "status", "matched", "total", "entries", "inputs_unchanged", "seconds", "exception")}, indent=2))
    return 0 if report["status"] == "PASS" or (report["status"] == "ORIGINAL_EQUIVALENCE_FAIL" and not args.require_match) else 1


if __name__ == "__main__":
    raise SystemExit(main())
