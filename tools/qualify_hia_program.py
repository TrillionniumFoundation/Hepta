"""Fail-closed actual-native qualification of standalone HIA Core v1.

The frozen corpus exercises typed block arguments, loops, calls, byte ownership,
loans, failures and the scalar C ABI. It makes finite execution claims only.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm

def param(name, typ):
    return {"name": name, "type": typ}


def operation(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [param(name, typ) for name, typ in out], "attrs": attrs}


def constant(name, typ, value):
    return operation("const", out=[(name, typ)], value=value)


def block(name, params, ops, term):
    return {"id": name, "params": [param(n, t) for n, t in params], "ops": ops, "term": term}


def function(name, params, returns, effects, blocks):
    return {"name": name, "params": [param(n, t) for n, t in params], "returns": returns,
            "effects": effects, "entry": "entry", "blocks": blocks}


def ret(*values):
    return {"op": "ret", "values": list(values)}


def jump(target, *args):
    return {"op": "jump", "target": target, "args": list(args)}


def branch(cond, yes, yesargs, no, noargs):
    return {"op": "branch", "cond": cond, "then": {"target": yes, "args": yesargs},
            "else": {"target": no, "args": noargs}}


def qualification_program():
    """Integer CFG and resources in one standalone executable representation."""
    funcs = [function("sum_to", [("n", "u32")], ["u32"], ["trap"], [
        block("entry", [("n", "u32")], [constant("zero", "u32", 0)], jump("loop", "n", "zero", "zero")),
        block("loop", [("ln", "u32"), ("li", "u32"), ("ls", "u32")], [
            operation("compare.lt", ["li", "ln"], [("more", "bool")]),
        ], branch("more", "body", ["ln", "li", "ls"], "done", ["ls"])),
        block("body", [("bn", "u32"), ("bi", "u32"), ("bs", "u32")], [
            constant("one", "u32", 1),
            operation("int.add.checked", ["bs", "bi"], [("next_sum", "u32")]),
            operation("int.add.checked", ["bi", "one"], [("next_i", "u32")]),
        ], jump("loop", "bn", "next_i", "next_sum")),
        block("done", [("answer", "u32")], [], ret("answer")),
    ])]
    funcs.append(function("invoke_sum", [("argument", "u32")], ["u32"], ["trap"], [
        block("entry", [("argument", "u32")], [
            operation("call", ["argument"], [("sum", "u32")], function="sum_to"),
            constant("two", "u32", 2),
            operation("int.mul.wrap", ["sum", "two"], [("doubled", "u32")]),
        ], ret("doubled")),
    ]))
    funcs.append(function("transfer", [("incoming", "buffer")], ["buffer"], [], [
        block("entry", [("incoming", "buffer")], [
            operation("owner.move", ["incoming"], [("moved", "buffer")]),
        ], ret("moved")),
    ]))
    funcs.append(function("lifecycle", [("n", "usize"), ("value", "u8")], ["u64"], ["alloc", "read", "write", "trap"], [
        block("entry", [("n", "usize"), ("value", "u8")], [
            constant("three", "usize", 3),
            constant("index", "usize", 0),
            operation("buffer.new", ["three"], [("allocated", "buffer")]),
            operation("call", ["allocated"], [("first", "buffer")], function="transfer"),
            operation("borrow.mut", ["first"], [("write_loan", "mutbuf")]),
            operation("buffer.store", ["write_loan", "index", "value"]),
            operation("loan.end", ["write_loan"]),
            operation("buffer.try_new", ["n"], [("second", "buffer"), ("ok", "bool")]),
        ], branch("ok", "success", ["first", "second"], "failure", ["first", "second"])),
        block("success", [("a", "buffer"), ("b", "buffer")], [
            constant("at", "usize", 0),
            operation("borrow.read", ["a"], [("read_loan", "readbuf")]),
            operation("buffer.load", ["read_loan", "at"], [("byte", "u8")]),
            operation("loan.end", ["read_loan"]),
            operation("buffer.len", ["b"], [("length", "usize")]),
            operation("int.cast", ["byte"], [("wide_byte", "u64")], mode="wrap"),
            operation("int.cast", ["length"], [("wide_length", "u64")], mode="wrap"),
            operation("int.add.wrap", ["wide_byte", "wide_length"], [("result", "u64")]),
            operation("owner.drop", ["b"]),
            operation("owner.drop", ["a"]),
        ], ret("result")),
        block("failure", [("fa", "buffer"), ("fb", "buffer")], [
            operation("owner.drop", ["fb"]),
            operation("owner.drop", ["fa"]),
            constant("error", "u64", 99),
        ], ret("error")),
    ]))
    funcs.append(function("bounds_trap", [("size", "usize")], ["u8"], ["alloc", "read", "trap"], [
        block("entry", [("size", "usize")], [
            operation("buffer.new", ["size"], [("owner", "buffer")]),
            operation("borrow.read", ["owner"], [("view", "readbuf")]),
            operation("buffer.load", ["view", "size"], [("invalid", "u8")]),
            operation("loan.end", ["view"]),
            operation("owner.drop", ["owner"]),
        ], ret("invalid")),
    ]))
    funcs.append(function("overflow_trap", [("value", "u8")], ["u8"], ["trap"], [
        block("entry", [("value", "u8")], [constant("one", "u8", 1),
            operation("int.add.checked", ["value", "one"], [("result", "u8")])], ret("result")),
    ]))
    funcs.append(function("read_one", [("view", "readbuf"), ("index", "usize")], ["u8"], ["read", "trap"], [
        block("entry", [("view", "readbuf"), ("index", "usize")], [
            operation("buffer.load", ["view", "index"], [("byte", "u8")]),
        ], ret("byte")),
    ]))
    funcs.append(function("fill_sum", [("length", "usize"), ("byte", "u8")], ["u64"], ["alloc", "read", "write", "trap"], [
        block("entry", [("length", "usize"), ("byte", "u8")], [
            operation("buffer.new", ["length"], [("allocated", "buffer")]),
            constant("zero_index", "usize", 0), constant("zero_sum", "u64", 0),
        ], jump("loop", "allocated", "length", "byte", "zero_index", "zero_sum")),
        block("loop", [("owner", "buffer"), ("n", "usize"), ("value", "u8"), ("i", "usize"), ("sum", "u64")], [
            operation("compare.lt", ["i", "n"], [("again", "bool")]),
        ], branch("again", "body", ["owner", "n", "value", "i", "sum"], "done", ["owner", "sum"])),
        block("body", [("bowner", "buffer"), ("bn", "usize"), ("bvalue", "u8"), ("bi", "usize"), ("bsum", "u64")], [
            operation("borrow.mut", ["bowner"], [("writer", "mutbuf")]),
            operation("buffer.store", ["writer", "bi", "bvalue"]),
            operation("borrow.read", ["writer"], [("reader", "readbuf")]),
            operation("call", ["reader", "bi"], [("read", "u8")], function="read_one"),
            operation("loan.end", ["reader"]), operation("loan.end", ["writer"]),
            operation("int.cast", ["read"], [("wide", "u64")], mode="wrap"),
            operation("int.add.checked", ["bsum", "wide"], [("next_sum", "u64")]),
            constant("one", "usize", 1),
            operation("int.add.checked", ["bi", "one"], [("next_i", "usize")]),
        ], jump("loop", "bowner", "bn", "bvalue", "next_i", "next_sum")),
        block("done", [("final_owner", "buffer"), ("total", "u64")], [
            operation("owner.drop", ["final_owner"]),
        ], ret("total")),
    ]))
    funcs.append(function("scalar_mix", [("a", "i64"), ("b", "i64"), ("choose", "bool")], ["i64"], ["trap"], [
        block("entry", [("a", "i64"), ("b", "i64"), ("choose", "bool")], [
            operation("int.cast", ["a"], [("small", "i32")], mode="checked"),
            operation("int.cast", ["small"], [("large", "i64")], mode="checked"),
            operation("int.sub.checked", ["large", "b"], [("difference", "i64")]),
            operation("int.mul.checked", ["difference", "b"], [("product", "i64")]),
            operation("int.neg.checked", ["product"], [("negative", "i64")]),
            operation("bit.not", ["negative"], [("inverted", "i64")]),
            operation("select", ["choose", "inverted", "a"], [("selected", "i64")]),
        ], ret("selected")),
    ]))
    funcs.append(function("bool_gate", [("a", "bool"), ("b", "bool")], ["bool"], [], [
        block("entry", [("a", "bool"), ("b", "bool")], [
            operation("bool.not", ["a"], [("not_a", "bool")]),
            operation("bool.and", ["not_a", "b"], [("both", "bool")]),
            operation("bool.or", ["both", "a"], [("either", "bool")]),
        ], ret("either")),
    ]))
    funcs.append(function("pair", [("a", "u64"), ("b", "u64")], ["u64", "u64"], [], [
        block("entry", [("a", "u64"), ("b", "u64")], [], ret("b", "a")),
    ]))
    funcs.append(function("no_result", [], [], [], [block("entry", [], [], ret())]))
    funcs.append(function("tuple_call", [("a", "u64"), ("b", "u64")], ["u64"], [], [
        block("entry", [("a", "u64"), ("b", "u64")], [
            operation("call", [], [], function="no_result"),
            operation("call", ["a", "b"], [("left", "u64"), ("right", "u64")], function="pair"),
            operation("int.sub.wrap", ["left", "right"], [("answer", "u64")]),
        ], ret("answer")),
    ]))
    for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"):
        params = [("a", typ), ("b", typ)]
        for opcode in ("int.add.wrap", "int.sub.wrap", "int.mul.wrap", "int.div.checked", "int.rem.checked",
                       "int.shl.checked", "int.shr.checked", "bit.and", "bit.or", "bit.xor"):
            name = opcode.replace(".", "_") + "_" + typ
            effects = ["trap"] if opcode.endswith("checked") else []
            funcs.append(function(name, params, [typ], effects, [
                block("entry", params, [operation(opcode, ["a", "b"], [("v", typ)])], ret("v")),
            ]))
        funcs.append(function("cast_i8_" + typ, [("a", typ)], ["i8"], [], [
            block("entry", [("a", typ)], [operation("int.cast", ["a"], [("v", "i8")], mode="wrap")], ret("v")),
        ]))
    return {"schema": "hepta.hia.program.v1", "module": "standalone_native_qualification", "functions": funcs}


_CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16,
           "u16": ctypes.c_uint16, "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
           "i64": ctypes.c_int64, "u64": ctypes.c_uint64, "usize": ctypes.c_size_t,
           "isize": ctypes.c_ssize_t, "bool": ctypes.c_bool}


ALLOCATOR_DRIVER = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
void *__real_calloc(size_t,size_t);
void __real_free(void *);
static void *live_addresses[64];
static size_t allocations=0,frees=0,live=0,refusals=0;
static int inject_failure=0;
void *__wrap_calloc(size_t count,size_t size) {
  if (inject_failure && count==1 && size==12281) {refusals++;return NULL;}
  void *p=__real_calloc(count,size);
  if(p){size_t i;for(i=0;i<64;i++)if(!live_addresses[i])break;
    if(i==64)exit(89);live_addresses[i]=p;allocations++;live++;}
  return p;
}
void __wrap_free(void *p) {
  if(p){size_t i;for(i=0;i<64;i++)if(live_addresses[i]==p)break;
    if(i==64)exit(90);live_addresses[i]=NULL;frees++;live--;}
  __real_free(p);
}
extern uint64_t lifecycle(size_t,uint8_t);
int main(void) {
  if(lifecycle(5,7)!=12)return 11;
  if(lifecycle(0,11)!=11)return 12;
  inject_failure=1;
  if(lifecycle(12281,13)!=99)return 13;
  if(lifecycle(SIZE_MAX,17)!=99)return 14;
  inject_failure=0;
  if(lifecycle(2,19)!=21)return 15;
  printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
  return allocations!=7 || frees!=7 || live!=0 || refusals!=1 ? 91 : 0;
}
"""


def qualification_cases():
    cases = []
    cases += [("sum_to", [n]) for n in (0, 1, 2, 7, 31, 128, 1024)]
    cases += [("invoke_sum", [n]) for n in (0, 1, 2, 7, 31, 128)]
    cases += [("lifecycle", [n, byte]) for n in (0, 1, 255, 4096, (1 << 64) - 1) for byte in (0, 1, 7, 255)]
    cases += [("fill_sum", [n, byte]) for n in (0, 1, 7, 128) for byte in (0, 1, 7, 255)]
    cases += [("scalar_mix", [a, b, choose]) for a, b in ((-37, 5), (0, -1), (2147483647, 1), (-2147483648, 0)) for choose in (False, True)]
    cases += [("bool_gate", [a, b]) for a in (False, True) for b in (False, True)]
    cases += [("tuple_call", [a, b]) for a, b in ((0, 0), (3, 7), (7, 3), ((1 << 64) - 1, 19))]
    for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"):
        bits = int(typ[1:]); signed = typ[0] == "i"
        low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
        for action in ("add", "sub", "mul"):
            for a, b in ((low, high), (high, 1), (0, 0), (1, high)):
                cases.append(("int_" + action + "_wrap_" + typ, [a, b]))
        for action in ("div", "rem"):
            for a, b in ((low, 1), (high, high), (high, 1)):
                cases.append(("int_" + action + "_checked_" + typ, [a, b]))
        for action in ("shl", "shr"):
            for a, b in ((low, 0), (high, 1), (high, bits - 1)):
                cases.append(("int_" + action + "_checked_" + typ, [a, b]))
        for action in ("and", "or", "xor"):
            cases.append(("bit_" + action + "_" + typ, [low, high]))
        cases.append(("cast_i8_" + typ, [high]))
    return cases


_CHILD = r"""
import ctypes,json,sys
types={'i8':ctypes.c_int8,'u8':ctypes.c_uint8,'i16':ctypes.c_int16,'u16':ctypes.c_uint16,
       'i32':ctypes.c_int32,'u32':ctypes.c_uint32,'i64':ctypes.c_int64,'u64':ctypes.c_uint64,
       'usize':ctypes.c_size_t,'isize':ctypes.c_ssize_t,'bool':ctypes.c_bool}
request=json.load(open(sys.argv[2]));library=ctypes.CDLL(sys.argv[1]);answers=[]
for row in request:
    fn=getattr(library,row['function']);fn.argtypes=[types[t] for t in row['parameter_types']]
    fn.restype=types[row['return_type']]
    answers.append(fn(*row['arguments']))
print(json.dumps(answers,separators=(',',':')))
"""


def _capture(result):
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _expect(condition, message):
    if not condition:
        raise ValueError("E_HIA_QUALIFY: " + message)


def qualify(*, clang="/usr/lib/llvm-20/bin/clang"):
    program = verify_program(qualification_program())
    ir = emit_program_llvm(program)
    functions = {fn["name"]: fn for fn in program.as_dict()["functions"]}
    report = {"schema": "hepta.hia.program-native-qualification.v1", "ok": False,
              "status": "running", "program_sha256": program.sha256,
              "program": program.as_dict(), "implementation_sha256": ir.implementation_sha256,
              "llvm_ir_sha256": ir.sha256, "llvm_ir": ir.text,
              "mocked_native_executions": 0, "skipped_native_executions": 0,
              "claims": {"standalone_core_executed": True, "source_ast_required": False,
                         "rust_reference_required": False, "finite_native_corpus_passed": False,
                         "general_performance_advantage_proved": False,
                         "backend_refinement_proved": False,
                         "whole_language_soundness_proved": False}}
    try:
        with tempfile.TemporaryDirectory(prefix="hia-program-qualification-") as temporary:
            folder = Path(temporary); library = folder / "program.so"; obj = folder / "program.o"
            report["shared_build"] = compile_program_llvm(ir, program=program, output=library, clang=clang)
            report["object_build"] = compile_program_llvm(ir, program=program, output=obj, clang=clang, kind="object")
            request, references = [], []
            for name, arguments in qualification_cases():
                fn = functions[name]
                reference = execute_program(program, name, arguments)
                _expect(reference["resources"]["live_owners"] == 0 and reference["resources"]["live_local_loans"] == 0,
                        "reference returned with live resources")
                request.append({"function": name, "arguments": arguments,
                                "parameter_types": [p["type"] for p in fn["params"]],
                                "return_type": fn["returns"][0]})
                references.append(reference)
            payload = folder / "cases.json"; payload.write_text(json.dumps(request))
            observed = run_bounded([sys.executable, "-c", _CHILD, str(library), str(payload)],
                                   timeout=60, stdout_limit=1048576, stderr_limit=1048576)
            report["native_child"] = _capture(observed)
            _expect(observed.returncode == 0, "actual native matrix process did not return normally")
            answers = json.loads(observed.stdout)
            _expect(type(answers) is list and len(answers) == len(references), "native result denominator changed")
            report["cases"] = [{**row, "reference": reference, "native_result": answer,
                                "equal": type(answer) is type(reference["result"]) and answer == reference["result"]}
                               for row, reference, answer in zip(request, references, answers)]
            _expect(all(row["equal"] for row in report["cases"]), "native and independent core execution disagree")
            report["native_result_executions"] = len(answers)
            traps = [("overflow_trap", [255], "overflow"), ("bounds_trap", [1], "bounds"),
                     ("int_div_checked_i32", [7, 0], "division_by_zero"),
                     ("int_rem_checked_i64", [-(1 << 63), -1], "overflow"),
                     ("int_shl_checked_u8", [1, 8], "overflow"),
                     ("scalar_mix", [1 << 31, 0, True], "overflow")]
            report["traps"] = []
            for index, (name, arguments, code) in enumerate(traps):
                try:
                    execute_program(program, name, arguments)
                except HIAProgramTrap as error:
                    _expect(error.code == code, "reference trap kind differs")
                    reference = error.report
                else:
                    raise ValueError("E_HIA_QUALIFY: required reference trap returned")
                fn = functions[name]; case = [{"function": name, "arguments": arguments,
                                               "parameter_types": [p["type"] for p in fn["params"]],
                                               "return_type": fn["returns"][0]}]
                trap_request = folder / ("trap" + str(index) + ".json"); trap_request.write_text(json.dumps(case))
                child = run_bounded([sys.executable, "-c", _CHILD, str(library), str(trap_request)],
                                    timeout=15, stdout_limit=65536, stderr_limit=65536)
                report["traps"].append({"function": name, "arguments": arguments, "reference": reference,
                                        "native": _capture(child), "expected_native_signal": "SIGABRT"})
                _expect(child.returncode == -6, "actual native guard did not abort with SIGABRT")
            driver = folder / "allocator.c"; binary = folder / "allocator"
            driver.write_text(ALLOCATOR_DRIVER)
            linked = run_bounded([clang, "-O2", str(driver), str(obj), "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(binary)])
            report["allocator_link"] = _capture(linked)
            _expect(linked.returncode == 0, "actual allocator observer failed to link")
            allocator = run_bounded([str(binary)], timeout=30, stdout_limit=65536, stderr_limit=65536)
            report["allocator"] = {"driver_sha256": sha256(ALLOCATOR_DRIVER.encode()).hexdigest(),
                                    "artifact_sha256": sha256(binary.read_bytes()).hexdigest(),
                                    "native": _capture(allocator),
                                    "expected": {"allocations": 7, "frees": 7, "live": 0, "null_refusals": 1}}
            _expect(allocator.returncode == 0 and allocator.stdout.strip() == "7 7 0 1", "allocator failure/cleanup observation disagrees")
            report["allocator"]["reference_failure"] = execute_program(program, "lifecycle", [12281, 13], allocation_fail_at=2)
            _expect(report["allocator"]["reference_failure"]["result"] == 99,
                    "reference allocation injection did not select error cleanup")
            # A separately compiled wrong binary must retain correct results
            # while the independent address observer detects its missing frees.
            wrong_text = "\n".join(line for line in ir.text.splitlines() if "call void @free(" not in line) + "\n"
            wrong_source, wrong_object, wrong_binary = folder / "wrong.ll", folder / "wrong.o", folder / "wrong"
            wrong_source.write_text(wrong_text)
            wrong_compiled = run_bounded([clang, "-O3", "-c", "-x", "ir", str(wrong_source), "-o", str(wrong_object)])
            _expect(wrong_compiled.returncode == 0, "leak negative control did not compile")
            wrong_linked = run_bounded([clang, "-O2", str(driver), str(wrong_object), "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(wrong_binary)])
            _expect(wrong_linked.returncode == 0, "leak negative control did not link")
            wrong_result = run_bounded([str(wrong_binary)], timeout=30, stdout_limit=65536, stderr_limit=65536)
            report["leak_negative_control"] = {"qualified_hepta_artifact": False,
                                                "llvm_sha256": sha256(wrong_text.encode()).hexdigest(),
                                                "artifact_sha256": sha256(wrong_binary.read_bytes()).hexdigest(),
                                                "native": _capture(wrong_result),
                                                "compile": _capture(wrong_compiled), "link": _capture(wrong_linked)}
            _expect(wrong_result.returncode == 91 and wrong_result.stdout.strip() == "7 0 7 1",
                    "compiled leak was not caught independently of return values")
            after = emit_program_llvm(program)
            _expect(after == ir, "standalone verifier or emitter changed during qualification")
            report["implementation_after_sha256"] = after.implementation_sha256
            report["native_binaries_retained"] = False
            report["ok"] = True; report["status"] = "finite_standalone_core_native_corpus_passed"
            report["claims"]["finite_native_corpus_passed"] = True
    except Exception as error:
        report["status"] = "rejected"
        report["error"] = {"type": type(error).__name__, "message": str(error),
                           "traceback": traceback.format_exc(limit=6)}
    report["record_sha256"] = sha256(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    args = parser.parse_args(argv)
    destination = Path(args.output)
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        parser.error("output must be a new path in an existing directory")
    result = qualify(clang=args.clang)
    payload = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(payload)
    print(json.dumps({"ok": result["ok"], "status": result["status"], "output": str(destination),
                      "native_result_executions": result.get("native_result_executions", 0),
                      "record_sha256": result["record_sha256"]}, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
