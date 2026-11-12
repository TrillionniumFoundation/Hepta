"""Retain independent native observations for explicit v3 machine plans.

This engineering fixture is not a real-task Agent/NDU benefit experiment. Every
planned arm, rejected plan, child failure and measured phase is retained. Native
execution occurs in a disposable child, after generated objects have been linked.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_machine_plan import MACHINE_V3, register_assignment_witness
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_native import _implementation_hash, compile_program_machine, emit_program_machine


def _parameters(pairs):
    return [{"name": name, "type": typ} for name, typ in pairs]


def _op(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": _parameters(out), "attrs": attrs}


def _const(name, typ, value):
    return _op("const", out=[(name, typ)], value=value)


def _ret(*values):
    return {"op": "ret", "values": list(values)}


def _jump(target, *args):
    return {"op": "jump", "target": target, "args": list(args)}


def _branch(condition, yes, yesargs, no, noargs):
    return {"op": "branch", "cond": condition,
            "then": {"target": yes, "args": yesargs}, "else": {"target": no, "args": noargs}}


def _block(name, params, ops, term):
    return {"id": name, "params": _parameters(params), "ops": ops, "term": term}


def _function(name, params, results, blocks, effects=()):
    return {"name": name, "params": _parameters(params), "returns": results,
            "effects": list(effects), "entry": "entry", "blocks": blocks}


def fixture():
    """Fixed source, fixed Agent-authored placements, no allocation/search pass."""
    unary = [("x", "u64")]
    functions = [
        _function("plus7", unary, ["u64"], [_block("entry", unary, [
            _const("seven", "u64", 7), _op("int.add.wrap", ["x", "seven"], [("answer", "u64")]),
        ], _ret("answer"))]),
        _function("across_calls", unary, ["u64"], [_block("entry", unary, [
            _op("call", ["x"], [("first", "u64")], function="plus7"),
            _op("call", ["first"], [("second", "u64")], function="plus7"),
            _op("int.add.wrap", ["x", "second"], [("answer", "u64")]),
        ], _ret("answer"))]),
        _function("reuse", unary, ["u64"], [_block("entry", unary, [
            _const("seven", "u64", 7), _op("int.add.wrap", ["x", "seven"], [("first", "u64")]),
            _const("eleven", "u64", 11), _op("int.add.wrap", ["first", "eleven"], [("answer", "u64")]),
        ], _ret("answer"))]),
    ]
    params = [("condition", "bool"), ("yes", "u64"), ("no", "u64")]
    functions.append(_function("choose", params, ["u64"], [_block("entry", params, [
        _op("select", ["condition", "yes", "no"], [("answer", "u64")]),
    ], _ret("answer"))]))
    params = [("a", "u64"), ("b", "u64"), ("n", "u64")]
    functions.append(_function("swap_loop", params, ["u64"], [
        _block("entry", params, [], _jump("loop", "a", "b", "n")),
        _block("loop", [("x", "u64"), ("y", "u64"), ("left", "u64")], [
            _const("zero", "u64", 0), _op("compare.ne", ["left", "zero"], [("more", "bool")]),
        ], _branch("more", "body", ["x", "y", "left"], "done", ["x", "y"])),
        _block("body", [("bx", "u64"), ("by", "u64"), ("count", "u64")], [
            _const("one", "u64", 1), _op("int.sub.wrap", ["count", "one"], [("next", "u64")]),
        ], _jump("loop", "by", "bx", "next")),
        _block("done", [("dx", "u64"), ("dy", "u64")], [
            _const("factor", "u64", 1000), _op("int.mul.wrap", ["dx", "factor"], [("high", "u64")]),
            _op("int.add.wrap", ["high", "dy"], [("answer", "u64")]),
        ], _ret("answer")),
    ]))
    functions.append(_function("memory_calls", unary, ["u64"], [_block("entry", unary, [
        _const("size", "usize", 32), _op("buffer.new", ["size"], [("data", "buffer")]),
        _op("borrow.mut", ["data"], [("view", "mutbuf")]), _const("byte", "u8", 165),
        _op("buffer.fill", ["view", "byte"]), _const("index", "usize", 7),
        _op("buffer.load", ["view", "index"], [("read", "u8")]), _op("loan.end", ["view"]),
        _op("owner.drop", ["data"]), _op("int.cast", ["read"], [("wide", "u64")], mode="wrap"),
        _op("int.add.wrap", ["x", "wide"], [("answer", "u64")]),
    ], _ret("answer"))], ["alloc", "read", "write", "trap"]))
    pair = [("a", "u64"), ("b", "u64")]
    functions.append(_function("pair", pair, ["u64", "u64"], [_block("entry", pair, [], _ret("b", "a"))]))
    functions.append(_function("pair_caller", pair, ["u64"], [_block("entry", pair, [
        _op("call", ["a", "b"], [("left", "u64"), ("right", "u64")], function="pair"),
        _op("int.sub.wrap", ["left", "right"], [("answer", "u64")]),
    ], _ret("answer"))]))
    params = [("n", "u64")]
    functions.append(_function("recursive_sum", params, ["u64"], [
        _block("entry", params, [_const("zero", "u64", 0),
            _op("compare.eq", ["n", "zero"], [("empty", "bool")])],
            _branch("empty", "done", [], "again", ["n"])),
        _block("done", [], [_const("nothing", "u64", 0)], _ret("nothing")),
        _block("again", [("m", "u64")], [_const("one", "u64", 1),
            _op("int.sub.wrap", ["m", "one"], [("next", "u64")]),
            _op("call", ["next"], [("subtotal", "u64")], function="recursive_sum"),
            _op("int.add.wrap", ["m", "subtotal"], [("answer", "u64")])], _ret("answer")),
    ]))
    placements = {
        "plus7": {"x": "r12", "seven": "r13", "answer": "r14"},
        "across_calls": {"x": "rbx", "first": "r13", "second": "r14", "answer": "r15"},
        "reuse": {"x": "r12", "seven": "r13", "first": "r14", "eleven": "r12", "answer": "r13"},
        "choose": {"condition": "rbx", "yes": "r12", "no": "r13", "answer": "r14"},
        "swap_loop": {"a": "r12", "b": "r13", "n": "r14",
            "x": "r12", "y": "r13", "left": "r14", "zero": "rbx", "more": "r15",
            "bx": "r12", "by": "r13", "count": "r14", "one": "rbx", "next": "r15",
            "dx": "r12", "dy": "r13", "factor": "rbx", "high": "r14", "answer": "r15"},
        "memory_calls": {"x": "r12", "size": "r13", "byte": "r13", "index": "r13",
                         "read": "r14", "wide": "r15", "answer": "rbx"},
        "pair": {"a": "r12", "b": "r13"},
        "pair_caller": {"a": "r12", "b": "r13", "left": "r14", "right": "r15", "answer": "rbx"},
        "recursive_sum": {"n": "r12", "zero": "r13", "empty": "r14", "nothing": "r12",
            "m": "r12", "one": "r13", "next": "r14", "subtotal": "r15", "answer": "rbx"},
    }
    return {"schema": "hepta.hia.program.v2", "module": "machine_register_observation", "functions": functions}, placements


def explicit_plan(program, assignments=None, *, select="branch", layout=False, compact=False):
    functions = program.as_dict()["functions"]
    return {"schema": MACHINE_V3, "core_sha256": program.sha256,
            "block_order": ({fn["name"]: [b["id"] for b in reversed(fn["blocks"])] for fn in functions}
                            if layout else {}),
            "function_order": [fn["name"] for fn in (reversed(functions) if layout else functions)],
            "scratch_registers": {"r10": "r11", "r11": "r10"} if compact else {"r10": "r10", "r11": "r11"},
            "instruction_selection": {"move_immediate": "mov32_if_exact" if compact else "movabs",
                                      "alu_immediate": "imm8_if_exact" if compact else "imm32", "scalar_select": select},
            "function_alignment": 64 if layout else 1, "value_registers": deepcopy(assignments or {})}


def workload(program):
    values = [*range(64), (1 << 32) - 1, 1 << 32, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
    cases = []
    for name in ("plus7", "across_calls", "reuse", "memory_calls"):
        cases.extend({"function": name, "args": [value]} for value in values)
    for condition in (False, True):
        for value in values:
            cases.append({"function": "choose", "args": [condition, value, (1 << 64) - 1 - value]})
    for n in range(9):
        for a, b in ((1, 2), (0, (1 << 64) - 1), (1 << 63, (1 << 32) - 1)):
            cases.append({"function": "swap_loop", "args": [a, b, n]})
    for a, b in ((0, 0), (1, 2), ((1 << 64) - 1, 1), (1 << 63, (1 << 32) - 1)):
        cases.append({"function": "pair_caller", "args": [a, b]})
    cases.extend({"function": "recursive_sum", "args": [n]} for n in range(17))
    for case in cases:
        case["expected"] = execute_program(program, case["function"], case["args"])["result"]
    return cases


def native_worker(request, result):
    """Disposable timing/correctness observer, not a second code generator."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    request = json.loads(Path(request).read_text())
    records, libraries, functions = {}, {}, {}
    types = {"u64": ctypes.c_uint64, "bool": ctypes.c_bool}
    for name, path in request["artifacts"].items():
        started = time.monotonic_ns()
        library = libraries[name] = ctypes.CDLL(path)
        funcs = functions[name] = {}
        for symbol, signature in request["signatures"].items():
            fn = getattr(library, symbol)
            fn.argtypes = [types[typ] for typ in signature["args"]]
            fn.restype = types[signature["result"]]
            funcs[symbol] = fn
        observations = []
        for case in request["cases"]:
            actual = funcs[case["function"]](*case["args"])
            observations.append({**case, "actual": actual, "ok": actual == case["expected"]})
        records[name] = {"cases": observations, "load_and_correctness_wall_ns": time.monotonic_ns() - started,
                         "timing_samples_ns": [], "timing_checksums": []}
    names = list(functions)
    for pair in range(7):
        for name in (names if pair % 2 == 0 else list(reversed(names))):
            funcs, total = functions[name], 0
            start = time.monotonic_ns()
            for value in range(2048):
                total += funcs["across_calls"](value) + funcs["choose"](value % 2 == 0, value, 2048 - value)
            records[name]["timing_samples_ns"].append(time.monotonic_ns() - start)
            records[name]["timing_checksums"].append(total)
    expected_checksum = sum(2 * v + 14 + (v if v % 2 == 0 else 2048 - v) for v in range(2048))
    for record in records.values():
        record.update(correct_cases=sum(row["ok"] for row in record["cases"]),
                      expected_cases=len(request["cases"]), timed_native_calls=7 * 4096,
                      expected_timing_checksum=expected_checksum,
                      median_python_to_native_batch_ns=statistics.median(record["timing_samples_ns"]))
        record["ok"] = (record["correct_cases"] == record["expected_cases"]
                        and all(value == expected_checksum for value in record["timing_checksums"]))
    Path(result).write_text(json.dumps({"ok": all(row["ok"] for row in records.values()), "arms": records},
                                      sort_keys=True, indent=2) + "\n")
    return 0 if all(row["ok"] for row in records.values()) else 1


def _usage():
    own, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"self_cpu_ns": round((own.ru_utime + own.ru_stime) * 1e9),
            "child_cpu_ns": round((children.ru_utime + children.ru_stime) * 1e9),
            "self_process_highwater_kib": own.ru_maxrss, "children_highwater_kib": children.ru_maxrss}


def _observer_identity():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        "tools/qualify_hia_machine_registers.py", "hepta/hia_program_runtime.py", "hepta/hia_bounded_memory.py")}


def qualify(destination):
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    start, source, observers = time.monotonic_ns(), _implementation_hash(), _observer_identity()
    report = {"schema": "hepta.hia.machine-register-observation.v1", "ok": False,
              "fixture_kind": "synthetic_scalars_calls_loops_resources", "backend_sha256": source,
              "observer_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
              "observer_and_reference_files": observers,
              "host": {"platform": platform.platform(), "python": sys.version},
              "attempts": [], "arms": {}, "shared_phases": {},
              "external_agent_model_cost": None, "discovery_cost": None, "failed_agent_search_cost": None,
              "full_search_cost_complete": False, "real_task_strategy_benefit_proved": False,
              "universal_backend_refinement_proved": False,
              "notes": ["Register assignments are fixed fixture inputs; the backend does no allocation or profitability search.",
                        "All arm attempts, expected rejections, child failures and measured phase costs are retained.",
                        "Observed child CPU includes linking and the bounded native observation; it is not energy measurement.",
                        "Timings include Python/ctypes dispatch. Whole shared image, object, text and frame sizes remain separate.",
                        "Model/discovery/failed Agent-search costs remain unknown; finite correctness does not prove net benefit."]}

    def checkpoint():
        report["observed_campaign_wall_ns"] = time.monotonic_ns() - start
        (destination / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")

    def phase(record, label, callback):
        row = record[label] = {"status": "started"}
        beginning, usage = time.monotonic_ns(), _usage()
        checkpoint()
        try:
            value = callback()
            row["status"] = "completed"
            return value
        except Exception as exc:
            row.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)},
                       traceback=traceback.format_exc())
            raise
        finally:
            after = _usage()
            row["wall_ns"] = time.monotonic_ns() - beginning
            row["self_cpu_ns"] = after["self_cpu_ns"] - usage["self_cpu_ns"]
            row["child_cpu_ns"] = after["child_cpu_ns"] - usage["child_cpu_ns"]
            row["highwater_after"] = {key: value for key, value in after.items() if "highwater" in key}
            checkpoint()

    checkpoint()
    try:
        document, assignments = fixture()
        program = phase(report["shared_phases"], "verify_core", lambda: verify_program(document))
        report["core_sha256"] = program.sha256
        (destination / "input.core.json").write_bytes(program.canonical_bytes)
        cases = phase(report["shared_phases"], "independent_vm_reference", lambda: workload(program))
        variants = {"canonical": None, "value_registers": explicit_plan(program, assignments),
                    "scalar_select": explicit_plan(program, select="cmov_scalar"),
                    "layout": explicit_plan(program, layout=True),
                    "combined": explicit_plan(program, assignments, select="cmov_scalar", layout=True, compact=True)}
        invalid = {
            "reject_liveness": explicit_plan(program, {"plus7": {"x": "r12", "seven": "r12"}}),
            "reject_resource": explicit_plan(program, {"memory_calls": {"data": "r12"}}),
            "reject_abi_register": explicit_plan(program, {"plus7": {"x": "rax"}}),
        }
        report["planned_attempts"] = list(variants) + list(invalid)
        artifacts = {}
        for name, plan in {**variants, **invalid}.items():
            attempt = {"name": name, "expected": "rejected" if name in invalid else "native_emitted",
                       "status": "started", "phases": {}, "commands": [], "plan": plan}
            report["attempts"].append(attempt)
            checkpoint()
            try:
                image = phase(attempt["phases"], "emit", lambda: emit_program_machine(program, machine_plan=plan))
                if name in invalid:
                    raise AssertionError("invalid plan was accepted")
                (destination / (name + ".o")).write_bytes(image.object_bytes)
                output = destination / (name + ".so")
                build = phase(attempt["phases"], "rederive_link_publish", lambda: compile_program_machine(
                    image, program=program, output=output, linker="ld", machine_plan=plan, command_log=attempt["commands"]))
                attempt.update(status="native_emitted", build=build)
                report["arms"][name] = {"plan": plan, "machine_text_bytes": len(image.text_bytes),
                    "object_bytes": len(image.object_bytes), "whole_shared_bytes": output.stat().st_size,
                    "function_frames": dict(image.function_frames), "native_build": build,
                    "register_witness": register_assignment_witness(program, {} if plan is None else plan["value_registers"])}
                artifacts[name] = str(output)
            except Exception as exc:
                expected = name in invalid and isinstance(exc, ValueError) and str(exc).startswith("E_HIA_MACHINE_PLAN:")
                attempt.update(status="rejected" if expected else "failed",
                               error={"type": type(exc).__name__, "message": str(exc)})
            finally:
                attempt["observed_wall_ns"] = sum(row.get("wall_ns", 0) for row in attempt["phases"].values())
                checkpoint()
        signatures = {fn["name"]: {"args": [p["type"] for p in fn["params"]], "result": fn["returns"][0]}
                      for fn in program.as_dict()["functions"] if fn["name"] != "pair"}
        request, observed = destination / "native-request.json", destination / "native-observation.json"
        request.write_text(json.dumps({"artifacts": artifacts, "cases": cases, "signatures": signatures}, sort_keys=True) + "\n")

        def observe():
            argv = [sys.executable, str(Path(__file__).resolve()), "--worker", str(request), str(observed)]
            report["native_process"] = {"argv": argv, "status": "started", "returncode": None}
            checkpoint()
            try:
                child = subprocess.run(argv, capture_output=True, timeout=60)
            except subprocess.TimeoutExpired as exc:
                (destination / "native.stdout").write_bytes(exc.stdout or b"")
                (destination / "native.stderr").write_bytes(exc.stderr or b"")
                report["native_process"].update(status="timed_out", stdout_bytes=len(exc.stdout or b""),
                                                stderr_bytes=len(exc.stderr or b""))
                raise
            (destination / "native.stdout").write_bytes(child.stdout)
            (destination / "native.stderr").write_bytes(child.stderr)
            report["native_process"].update(status="completed", returncode=child.returncode,
                                            stdout_bytes=len(child.stdout), stderr_bytes=len(child.stderr))
            if child.returncode:
                raise AssertionError("native observation child failed: " + str(child.returncode))
            observation = json.loads(observed.read_text())
            if not observation["ok"] or set(observation["arms"]) != set(variants):
                raise AssertionError("native observation is incomplete or refuted")
            return observation

        observation = phase(report["shared_phases"], "bounded_native_campaign", observe)
        for name, row in observation["arms"].items():
            report["arms"][name]["native_observation"] = row
        report["source_unchanged"] = source == _implementation_hash() and observers == _observer_identity()
        report["inventory_complete"] = [row["name"] for row in report["attempts"]] == report["planned_attempts"]
        report["ok"] = (report["source_unchanged"] and report["inventory_complete"]
                        and all(row["status"] == row["expected"] for row in report["attempts"]))
    except Exception as exc:
        report["campaign_error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        report["source_unchanged"] = source == _implementation_hash() and observers == _observer_identity()
        report["inventory_complete"] = ("planned_attempts" in report
            and [row["name"] for row in report["attempts"]] == report["planned_attempts"])
        report["resource_usage_after"] = _usage()
        checkpoint()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out")
    parser.add_argument("--worker", nargs=2, metavar=("REQUEST", "RESULT"))
    args = parser.parse_args()
    if args.worker is not None:
        return native_worker(*args.worker)
    if not args.out:
        parser.error("--out is required")
    report = qualify(args.out)
    print(json.dumps({"ok": report["ok"], "output": str(Path(args.out) / "result.json"),
                      "attempts": [{"name": row["name"], "status": row["status"]} for row in report["attempts"]],
                      "arms": {name: {key: row[key] for key in ("machine_text_bytes", "object_bytes", "whole_shared_bytes")}
                               for name, row in report["arms"].items()}}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
