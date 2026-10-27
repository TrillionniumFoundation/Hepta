#!/usr/bin/env python3
"""Finite standalone-core resource combinations, with explicit proof limits.

The handcrafted program combines two fallible owners in a multi-return record,
ownership handoff, a mutable parent/shared child loan stored across CFG edges,
an internal borrowed call, and successful/error cleanup. A real existing C++
migration output is also lowered and interpreted when its required adapter is
available. Missing capabilities fail the qualification; no Rust fallback.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import SCHEMA, HIAProgramRejected, verify_program
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)

REPORT_SCHEMA = "hepta.hia.resource-qualification.v1"
SOURCE_FIXTURE = "examples/cpp/owned_migration/expected.hepta"
TEST_MODULES = ("tests.test_hia_program", "tests.test_hia_program_tools",
                "tests.test_hia_program_llvm")
INPUT_FILES = ("hepta/hia_program.py", "hepta/hia_program_runtime.py",
               "hepta/hia_program_source.py", "hepta/hia_program_llvm.py",
               "hepta/hia_program_tools.py", "hepta/core.py",
               "tests/test_hia_program.py", "tests/test_hia_program_tools.py",
               "tests/test_hia_program_llvm.py",
               "tools/qualify_hia_program_resources.py", SOURCE_FIXTURE)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _param(name, typ):
    return {"name": name, "type": typ}


def _op(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [_param(*o) for o in out], "attrs": attrs}


def _const(name, typ, value):
    return _op("const", out=[(name, typ)], value=value)


def _ret(*names):
    return {"op": "ret", "values": list(names)}


def _jump(target, *names):
    return {"op": "jump", "target": target, "args": list(names)}


def _branch(cond, yes, no):
    return {"op": "branch", "cond": cond,
            "then": {"target": yes[0], "args": list(yes[1:])},
            "else": {"target": no[0], "args": list(no[1:])}}


def _block(name, params, ops, term):
    return {"id": name, "params": [_param(*p) for p in params], "ops": ops, "term": term}


def _fn(name, params, returns, effects, blocks):
    return {"name": name, "params": [_param(*p) for p in params], "returns": returns,
            "effects": effects, "entry": blocks[0]["id"], "blocks": blocks}


def build_resource_program():
    """Return a fresh standalone document; no source/checker receipt is used."""
    pair = _fn("make_pair", [("n", "usize")], ["buffer", "bool", "buffer", "bool"], ["alloc"], [
        _block("entry", [("n", "usize")], [
            _const("one", "usize", 1),
            _op("buffer.try_new", ["one"], [("first", "buffer"), ("first_ok", "bool")]),
            _op("buffer.try_new", ["n"], [("second", "buffer"), ("second_ok", "bool")]),
        ], _ret("first", "first_ok", "second", "second_ok")),
    ])
    handoff = _fn("handoff", [("owner", "buffer")], ["buffer"], [], [
        _block("entry", [("owner", "buffer")], [
            _op("owner.move", ["owner"], [("returned", "buffer")]),
        ], _ret("returned")),
    ])
    peek = _fn("peek", [("view", "readbuf")], ["u8"], ["read", "trap"], [
        _block("entry", [("view", "readbuf")], [
            _const("zero", "usize", 0),
            _op("buffer.load", ["view", "zero"], [("value", "u8")]),
        ], _ret("value")),
    ])
    pipeline = _fn("pipeline", [("n", "usize"), ("seed", "u8"), ("stop", "bool")],
                   ["u64"], ["alloc", "read", "write", "trap"], [
        _block("entry", [("n", "usize"), ("seed", "u8"), ("stop", "bool")], [
            _op("call", ["n"], [("a", "buffer"), ("a_ok", "bool"), ("z", "buffer"), ("z_ok", "bool")],
                function="make_pair"),
            _op("bool.and", ["a_ok", "z_ok"], [("both", "bool")]),
        ], _branch("both", ("borrow", "a", "z", "seed", "stop"), ("failed", "a", "z"))),
        _block("borrow", [("ba", "buffer"), ("bz", "buffer"), ("bs", "u8"), ("stop1", "bool")], [
            _op("call", ["ba"], [("transferred", "buffer")], function="handoff"),
            _op("borrow.mut", ["transferred"], [("parent", "mutbuf")]),
            _const("index", "usize", 0),
            _op("buffer.store", ["parent", "index", "bs"]),
            _op("borrow.read", ["parent"], [("child", "readbuf")]),
        ], _jump("stored", "transferred", "bz", "parent", "child", "stop1")),
        _block("stored", [("sa", "buffer"), ("sz", "buffer"), ("sp", "mutbuf"), ("sc", "readbuf"), ("stop2", "bool")], [],
               _branch("stop2", ("error", "sa", "sz", "sp", "sc"), ("normal", "sa", "sz", "sp", "sc"))),
        _block("normal", [("na", "buffer"), ("nz", "buffer"), ("np", "mutbuf"), ("nc", "readbuf")], [
            _op("call", ["nc"], [("byte", "u8")], function="peek"),
            _op("loan.end", ["nc"]), _op("loan.end", ["np"]),
            _op("buffer.len", ["nz"], [("length", "usize")]),
            _op("int.cast", ["byte"], [("wide_byte", "u64")], mode="checked"),
            _op("int.cast", ["length"], [("wide_length", "u64")], mode="checked"),
            _op("int.add.checked", ["wide_byte", "wide_length"], [("result", "u64")]),
            _op("owner.drop", ["na"]), _op("owner.drop", ["nz"]),
        ], _ret("result")),
        _block("error", [("ea", "buffer"), ("ez", "buffer"), ("ep", "mutbuf"), ("ec", "readbuf")], [
            _op("loan.end", ["ec"]), _op("loan.end", ["ep"]),
            _op("owner.drop", ["ea"]), _op("owner.drop", ["ez"]), _const("error_code", "u64", 77),
        ], _ret("error_code")),
        _block("failed", [("fa", "buffer"), ("fz", "buffer")], [
            _op("owner.drop", ["fa"]), _op("owner.drop", ["fz"]), _const("failure_code", "u64", 99),
        ], _ret("failure_code")),
    ])
    return {"schema": SCHEMA, "module": "resource_combinations", "functions": [pair, handoff, peek, pipeline]}


def _case(program, function, args, expected, fail_at=None):
    result = execute_program(program, function, args, allocation_fail_at=fail_at)
    resources = result["resources"]
    ok = (result["result"] == expected and resources["live_owners"] == 0
          and resources["live_local_loans"] == 0 and resources["live_bytes"] == 0
          and resources["allocations"] == resources["frees"])
    return {"arguments": args, "allocation_fail_at": fail_at, "expected": expected,
            "ok": ok, "execution": result}


def _reject_case(label, document, expected_code=None):
    try:
        verify_program(document)
    except HIAProgramRejected as error:
        return {"case": label, "rejected": True, "code": error.code,
                "ok": expected_code is None or error.code == expected_code}
    return {"case": label, "rejected": False, "ok": False}


def negative_cases():
    base = build_resource_program()
    out = []
    def change(label, mutate, expected=None):
        document = copy.deepcopy(base)
        mutate(document)
        out.append(_reject_case(label, document, expected))
    # Typed edges cannot substitute another equally typed owner for a loan's
    # actual parent; the edge's incoming permission graph must also agree.
    def inconsistent_predecessor(document):
        pipeline = document["functions"][3]
        pipeline["blocks"][2]["term"]["else"]["target"] = "fork"
        pipeline["blocks"].append(_block("fork", [
            ("fork_a", "buffer"), ("fork_z", "buffer"), ("fork_p", "mutbuf"), ("fork_c", "readbuf")],
            [_const("fork_condition", "bool", True)],
            _branch("fork_condition", ("error", "fork_z", "fork_a", "fork_p", "fork_c"),
                    ("normal", "fork_a", "fork_z", "fork_p", "fork_c"))))
    change("swap_owner_provenance_on_one_join_edge", inconsistent_predecessor, "E_HIA_LOAN")
    change("drop_owner_while_child_stored",
           lambda d: d["functions"][3]["blocks"][2]["ops"].append(_op("owner.drop", ["sa"])), "E_HIA_LOAN")
    change("duplicate_owner_return",
           lambda d: d["functions"][0]["blocks"][0]["term"].update(values=["first", "first_ok", "first", "second_ok"]),
           "E_HIA_RESOURCE")
    change("error_path_forgets_second_owner",
           lambda d: d["functions"][3]["blocks"][4]["ops"].pop(3), "E_HIA_RESOURCE")
    change("callee_ends_callers_loan",
           lambda d: d["functions"][2]["blocks"][0]["ops"].insert(0, _op("loan.end", ["view"])), "E_HIA_LOAN")
    change("write_through_shared_child",
           lambda d: d["functions"][3]["blocks"][1]["ops"].append(_op("buffer.store", ["child", "index", "bs"])),
           "E_HIA_TYPE")
    change("suspended_mut_parent_access",
           lambda d: d["functions"][3]["blocks"][1]["ops"].append(_op("buffer.store", ["parent", "index", "bs"])),
           "E_HIA_LOAN")
    change("missing_call_effect",
           lambda d: d["functions"][3].update(effects=["alloc", "read", "trap"]), "E_HIA_EFFECT")
    for opcode in ("task.spawn", "task.cancel", "foreign.call"):
        change("unsupported_" + opcode,
               lambda d, op=opcode: d["functions"][3]["blocks"][0]["ops"].insert(0, _op(op)), "E_HIA_OPCODE")
    return out


def qualify():
    began = time.time()
    record = {"schema": REPORT_SCHEMA, "scope": "finite_standalone_resource_combinations",
              "status": "running", "inputs": {
                  name: _sha((ROOT / name).read_bytes()) for name in INPUT_FILES if (ROOT / name).is_file()},
              "environment": {"python": sys.version, "platform": platform.platform(), "word_bits": 64},
              "claims": {"whole_language_soundness_proved": False,
                         "backend_refinement_proved": False,
                         "generic_or_escaping_lifetimes_qualified": False,
                         "standalone_tasks_or_cancellation_supported": False,
                         "arbitrary_cpp_translation_qualified": False,
                         "foreign_abi_or_device_execution_qualified": False}}
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                  capture_output=True, text=True, timeout=10)
        record["repository_head"] = revision.stdout.strip() if revision.returncode == 0 else None
        verified = verify_program(build_resource_program())
        record["program"] = verified.as_dict()
        record["static"] = {"verification": verified.report(), "negative_controls": negative_cases(),
                            "mechanism": "closed SSA plus edge-normalized owner/loan/parent identity"}
        cases = []
        for n, seed, stop in [(0, 0, False), (0, 255, False), (1, 19, False),
                              (17, 255, False), (17, 19, True)]:
            for fail_at in (None, 1, 2):
                failed = fail_at == 1 or fail_at == 2 and n != 0
                expected = 99 if failed else 77 if stop else n + seed
                cases.append(_case(verified, "pipeline", [n, seed, stop], expected, fail_at))
        cases.append(_case(verified, "pipeline", [(1 << 64) - 1, 3, False], 99))
        record["runtime"] = {"cases": cases,
            "coverage": ["two-owner multi-return record and success tags", "owner transfer through call",
                         "mutable-parent/shared-child reborrow", "local stored view crossing CFG blocks",
                         "borrowed call without escape", "normal/error/allocator-failure cleanup"],
            "abort_cleanup_promised": False}
        from hepta.hia_program_source import lower_source
        source_path = ROOT / SOURCE_FIXTURE
        source_program = lower_source(source_path.read_text(), path=str(source_path))
        source_cases = [
            _case(source_program, "run_owned", [4, 5, 0, False, False], 194),
            _case(source_program, "run_owned", [4, 5, 1, False, False], 14),
            _case(source_program, "run_owned", [4, 5, 9, False, False], 2003),
            _case(source_program, "run_owned", [4, 5, 0, True, False], 1002),
            _case(source_program, "run_owned", [4, 5, 0, False, True], 2002),
            _case(source_program, "run_owned", [4, 5, 0, False, False], 1001, 1),
        ]
        record["concrete_record_result_migration"] = {
            "source": SOURCE_FIXTURE, "source_sha256": _sha(source_path.read_bytes()),
            "program_sha256": source_program.sha256, "cases": source_cases,
            "scope": "concrete OwnedBytes record and Result lowered to explicit components; returned-view helper is inlined"}
        argv = [sys.executable, "-m", "unittest", *TEST_MODULES]
        tests = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=180)
        record["tests"] = {"command": argv, "returncode": tests.returncode,
                           "stdout": tests.stdout, "stderr": tests.stderr,
                           "stdout_sha256": _sha(tests.stdout.encode()), "stderr_sha256": _sha(tests.stderr.encode())}
        record["external"] = {
            "trusted_components": ["Python checker/interpreter implementation", "host allocator",
                                   "Clang/LLVM and host platform for the separately executed native tests"],
            "not_inferred": ["machine-checked safety theorem", "FFI contract correctness",
                             "thread or task cancellation safety", "hardware/MMIO semantics"],
            "notes": "Passing finite checks is evidence for this profile, not a replacement for external obligations."}
        record["ok"] = (all(x["ok"] for x in record["static"]["negative_controls"])
                        and all(x["ok"] for x in cases + source_cases) and tests.returncode == 0)
        record["status"] = "qualified" if record["ok"] else "failed"
    except Exception as error:
        record.update(ok=False, status="failed", error={"type": type(error).__name__, "message": str(error)})
        if isinstance(error, (HIAProgramTrap, HIAProgramBudgetExceeded)):
            record["stopped_execution"] = error.report
    record["elapsed_seconds"] = time.time() - began
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = qualify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ok": record["ok"], "status": record["status"], "output": str(args.output),
                      "runtime_cases": len(record.get("runtime", {}).get("cases", [])),
                      "negative_controls": len(record.get("static", {}).get("negative_controls", []))}))
    return 0 if record["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
