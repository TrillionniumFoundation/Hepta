"""Independent finite integer boundaries for the shared opcode/native contract.

Two bounded HIA artifacts cover every signed/unsigned width and machine-word
alias. Mathematical expectations do not call a compiler arithmetic helper.
The VM exposes the first trap code; native ABI exposes SIGABRT only. These
finite observations are neither all-input refinement nor an arbitrary ABI proof.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_opcodes import opcode_spec
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_runtime import HIAProgramTrap, execute_program


TYPES = tuple(sign + str(bits) for bits in (8, 16, 32, 64) for sign in ("i", "u")) + ("isize", "usize")
CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def bounds(typ):
    bits = 64 if typ.endswith("size") else int(typ[1:])
    signed = typ.startswith("i")
    return bits, -(1 << (bits - 1)) if signed else 0, (1 << (bits - int(signed))) - 1


def mathematical_result(op, typ, arguments, destination=None):
    """Exact integer oracle, including truncation-towards-zero and width wrap."""
    bits, low, high = bounds(typ)
    a = arguments[0]
    b = arguments[1] if len(arguments) == 2 else None
    if op == "int.cast":
        bits, low, high = bounds(destination)
        value = a
    elif op.startswith("int.add."):
        value = a + b
    elif op.startswith("int.sub."):
        value = a - b
    elif op.startswith("int.mul."):
        value = a * b
    elif op in {"int.div.checked", "int.rem.checked"}:
        if b == 0:
            return "division_by_zero", None
        if low < 0 and a == low and b == -1:
            return "overflow", None
        quotient = abs(a) // abs(b)
        if (a < 0) != (b < 0):
            quotient = -quotient
        return None, quotient if op == "int.div.checked" else a - quotient * b
    elif op in {"int.shl.checked", "int.shr.checked"}:
        if not 0 <= b < bits:
            return "overflow", None
        if op == "int.shr.checked":
            return None, a // (1 << b)
        # A checked shift checks the count, not discarded high value bits.
        value = a * (1 << b)
        value %= 1 << bits
        return None, value - (1 << bits) if low < 0 and value > high else value
    else:
        raise AssertionError("unregistered test oracle operation")
    if op.endswith("checked") and not low <= value <= high:
        return "overflow", None
    if op.endswith("wrap"):
        value %= 1 << bits
        if low < 0 and value > high:
            value -= 1 << bits
    return None, value


def function(name, op, typ, destination=None):
    cast = op.startswith("int.cast.")
    instruction = "int.cast" if cast else op
    # Exercise catalog lookup, then let the complete verifier check effects,
    # argument types, SSA and CFG. Oracle expectations remain independent.
    spec = opcode_spec(instruction)
    parameters = [{"name": "a", "type": typ}]
    if not cast:
        parameters.append({"name": "b", "type": typ})
    result_type = destination if cast else typ
    mode = op.rsplit(".", 1)[-1]
    return {"name": name, "params": parameters, "returns": [result_type],
            "effects": ["trap"] if mode == "checked" else list(spec.effects),
            "entry": "entry", "blocks": [{"id": "entry", "params": parameters,
            "ops": [{"op": instruction, "args": [p["name"] for p in parameters],
                     "out": [{"name": "result", "type": result_type}],
                     "attrs": {"mode": mode} if cast else {}}],
            "term": {"op": "ret", "values": ["result"]}}]}


def corpus():
    functions, cases = [], []
    for typ in TYPES:
        bits, low, high = bounds(typ)
        for action in ("add", "sub", "mul", "div", "rem", "shl", "shr"):
            modes = ("wrap", "checked") if action in {"add", "sub", "mul"} else ("checked",)
            for mode in modes:
                op, name = "int." + action + "." + mode, action + "_" + mode + "_" + typ
                fn = function(name, op, typ)
                functions.append(fn)
                pairs = [(low, 0), (high, 1), (low, 1), (high, high)]
                if low < 0:
                    pairs += [(low, -1), (-7, 3), (7, -3), (-7, -3)]
                if action in {"shl", "shr"}:
                    pairs += [(high, bits - 1), (low, bits - 1), (1, bits)]
                    if low < 0:
                        pairs += [(-7, 1), (1, -1)]
                for arguments in dict.fromkeys(pairs):
                    error, value = mathematical_result(op, typ, arguments)
                    cases.append((name, list(arguments), error, value))
        # Sign changes, narrowing and widening all cross actual C ABI types.
        same_width_other_sign = ("u" if typ.startswith("i") else "i") + ("size" if typ.endswith("size") else str(bits))
        for destination in dict.fromkeys((same_width_other_sign, "i8", "u8", "i64", "u64")):
            for mode in ("wrap", "checked"):
                name = "cast_" + mode + "_" + typ + "_" + destination
                functions.append(function(name, "int.cast." + mode, typ, destination))
                _, after_low, after_high = bounds(destination)
                values = {low, high, 0, 1, after_low - 1, after_low, after_high, after_high + 1}
                for value in sorted(v for v in values if low <= v <= high):
                    # Cast checker semantics use the same mode suffix rule as
                    # arithmetic; destination bounds are independent here.
                    error, answer = mathematical_result("int.cast", typ, [value], destination)
                    if mode == "checked" and not after_low <= value <= after_high:
                        error, answer = "overflow", None
                    elif mode == "wrap":
                        width, lo, hi = bounds(destination)
                        answer = value % (1 << width)
                        if lo < 0 and answer > hi:
                            answer -= 1 << width
                    cases.append((name, [value], error, answer))
    return {"schema": "hepta.hia.program.v1", "module": "scalar_boundaries", "functions": functions}, cases


DOCUMENT, CASES = corpus()
FUNCTIONS = {fn["name"]: fn for fn in DOCUMENT["functions"]}


class ScalarBoundaryVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checked = {name: verify_program({**DOCUMENT, "functions": [fn]})
                       for name, fn in FUNCTIONS.items()}

    def test_all_widths_follow_independent_boundary_oracle(self):
        self.assertGreater(len(CASES), 1000)
        for name, arguments, error, expected in CASES:
            with self.subTest(function=name, arguments=arguments):
                if error is None:
                    result = execute_program(self.checked[name], name, arguments)
                    self.assertEqual(result["result"], expected)
                else:
                    with self.assertRaises(HIAProgramTrap) as caught:
                        execute_program(self.checked[name], name, arguments)
                    self.assertEqual(caught.exception.code, error)

    def test_first_trap_code_survives_later_conflicting_failure(self):
        for typ in TYPES:
            _, low, high = bounds(typ)
            for first, expected in (("division", "division_by_zero"), ("overflow", "overflow")):
                fn = function("ordered", "int.add.checked", typ)
                fn["blocks"][0]["ops"] = [
                    {"op": "int.div.checked", "args": ["a", "b"],
                     "out": [{"name": "quotient", "type": typ}], "attrs": {}},
                    {"op": "int.add.checked", "args": ["a", "a"],
                     "out": [{"name": "result", "type": typ}], "attrs": {}},
                ]
                if first == "overflow":
                    fn["blocks"][0]["ops"].reverse()
                document = {"schema": "hepta.hia.program.v1", "module": "first_trap", "functions": [fn]}
                with self.subTest(type=typ, first=first), self.assertRaises(HIAProgramTrap) as caught:
                    execute_program(document, "ordered", [high, 0])
                self.assertEqual(caught.exception.code, expected)


_WORKER = r'''
import ctypes, json, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
words = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16,
         "u16": ctypes.c_uint16, "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
         "i64": ctypes.c_int64, "u64": ctypes.c_uint64,
         "isize": ctypes.c_int64, "usize": ctypes.c_uint64}
payload = json.loads(sys.stdin.read())
library = ctypes.CDLL(sys.argv[1])
results = []
for name, arguments, parameters, returned in payload:
    entry = getattr(library, name)
    entry.argtypes = [words[typ] for typ in parameters]
    entry.restype = words[returned]
    results.append(entry(*arguments))
print(json.dumps(results))
'''


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ native toolchain required")
class ScalarBoundaryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-scalar-boundaries-")
        cls.libraries, cls.receipts = {}, []
        # Keep the existing 128-export admission limit; do not widen it for a
        # test corpus. Every independent function fits in one of two batches.
        functions = DOCUMENT["functions"]
        for index, start in enumerate(range(0, len(functions), 96)):
            batch = functions[start:start + 96]
            library = Path(cls.directory.name) / ("boundaries_" + str(index) + ".so")
            checked = verify_program({**DOCUMENT, "functions": batch})
            cls.receipts.append(compile_program_llvm(emit_program_llvm(checked), program=checked,
                                                    output=library, clang=CLANG))
            cls.libraries.update((fn["name"], library) for fn in batch)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def execute_child(self, cases):
        payload = [[name, arguments, [p["type"] for p in FUNCTIONS[name]["params"]],
                    FUNCTIONS[name]["returns"][0]] for name, arguments, *_ in cases]
        return subprocess.run([sys.executable, "-c", _WORKER, str(self.libraries[cases[0][0]])],
                              input=json.dumps(payload), capture_output=True, text=True, timeout=30)

    def test_all_normal_boundaries_reach_native_results_in_batched_children(self):
        for library in set(self.libraries.values()):
            cases = [row for row in CASES if row[2] is None and self.libraries[row[0]] == library]
            with self.subTest(library=library.name):
                result = self.execute_child(cases)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), [row[3] for row in cases])
        self.assertEqual({name for receipt in self.receipts for name in receipt["exports"]}, set(FUNCTIONS))

    def test_all_widths_abort_on_divide_overflow_shift_and_checked_cast(self):
        probes = {}
        for row in CASES:
            name, _arguments, error, _value = row
            if error is None:
                continue
            # One actual child per width and trap family; failed children never
            # suppress later probes or count SIGSEGV/SIGILL as arithmetic traps.
            family, mode, typ = name.split("_", 3)[:3]
            if family in {"div", "rem", "shl", "shr", "cast"}:
                probes.setdefault((family, typ, error), row)
        self.assertGreaterEqual(len(probes), 40)
        for identity, row in probes.items():
            with self.subTest(identity=identity, arguments=row[1]):
                result = self.execute_child([row])
                self.assertEqual(result.returncode, -signal.SIGABRT, result.stderr)


if __name__ == "__main__":
    unittest.main()
