"""Direct machine-code backend: independent VM, real ABI, traps and ownership.

No expected result is calculated by the new emitter. The fixtures are shared
with the pre-existing VM/LLVM qualification, plus tests aimed at machine ABI
and block-edge hazards. C is used only as an independent test caller/allocator
observer; HIA object generation is performed without external tools.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import ctypes
import json
from pathlib import Path
import platform
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_native import (
    build_program_machine, compile_program_machine, emit_program_machine,
)
from tools.qualify_hia_program import (
    ALLOCATOR_DRIVER, _CTYPES, block, branch, constant, function, jump,
    operation, qualification_program, ret,
)

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("cc")
LD = shutil.which("ld")
X86_LINUX = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
TYPES = ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize")
CTYPES = {**_CTYPES, "unit": None}


def scalar_document():
    """Add checks absent from the older fixture, retaining independent semantics."""
    doc = qualification_program()
    for typ in TYPES:
        params = [("a", typ), ("b", typ)]
        for action in ("add", "sub", "mul"):
            name = f"checked_{action}_{typ}"
            doc["functions"].append(function(name, params, [typ], ["trap"], [
                block("entry", params, [operation(f"int.{action}.checked", ["a", "b"], [("v", typ)])], ret("v"))]))
        for action in ("eq", "ne", "lt", "le", "gt", "ge"):
            name = f"compare_{action}_{typ}"
            doc["functions"].append(function(name, params, ["bool"], [], [
                block("entry", params, [operation(f"compare.{action}", ["a", "b"], [("v", "bool")])], ret("v"))]))
        unary = [("a", typ)]
        doc["functions"].append(function(f"neg_{typ}", unary, [typ], ["trap"], [
            block("entry", unary, [operation("int.neg.checked", ["a"], [("v", typ)])], ret("v"))]))
        for target in ("i8", "u8", "i64", "u64"):
            doc["functions"].append(function(f"cast_{typ}_to_{target}", unary, [target], ["trap"], [
                block("entry", unary, [operation("int.cast", ["a"], [("v", target)], mode="checked")], ret("v"))]))
    params = [(f"x{i}", typ) for i, typ in enumerate(("i8", "u16", "i32", "u64", "u8", "i16", "i64", "u32", "bool"))]
    ops = [constant("total0", "u64", 0)]
    for i, (_name, typ) in enumerate(params[:-1]):
        ops += [operation("int.cast", [f"x{i}"], [(f"wide{i}", "u64")], mode="wrap"),
                operation("int.add.wrap", [f"total{i}", f"wide{i}"], [(f"total{i+1}", "u64")])]
    ops += [constant("offset", "u64", 99),
            operation("int.add.wrap", ["total8", "offset"], [("adjusted", "u64")]),
            operation("select", ["x8", "adjusted", "total8"], [("answer", "u64")])]
    doc["functions"].append(function("nine_arguments", params, ["u64"], [], [block("entry", params, ops, ret("answer"))]))
    doc["functions"].append(function("call_nine", params, ["u64"], [], [block("entry", params, [
        operation("call", [p[0] for p in params], [("answer", "u64")], function="nine_arguments"),
    ], ret("answer"))]))
    params = [("a", "u64"), ("b", "u64"), ("n", "u64")]
    doc["functions"].append(function("edge_swap", params, ["u64"], [], [
        block("entry", params, [], jump("loop", "a", "b", "n")),
        block("loop", [("x", "u64"), ("y", "u64"), ("left", "u64")], [
            constant("zero", "u64", 0), operation("compare.ne", ["left", "zero"], [("more", "bool")]),
        ], branch("more", "body", ["x", "y", "left"], "done", ["x", "y"])),
        block("body", [("bx", "u64"), ("by", "u64"), ("count", "u64")], [
            constant("one", "u64", 1), operation("int.sub.wrap", ["count", "one"], [("next", "u64")]),
        ], jump("loop", "by", "bx", "next")),
        block("done", [("dx", "u64"), ("dy", "u64")], [
            constant("factor", "u64", 1000), operation("int.mul.wrap", ["dx", "factor"], [("hi", "u64")]),
            operation("int.add.wrap", ["hi", "dy"], [("answer", "u64")]),
        ], ret("answer")),
    ]))
    doc["functions"].append(function("explicit_trap", [], [], ["trap"], [block("entry", [], [], {"op":"trap", "code":"user"})]))
    return doc


def minimal_document():
    params = [("x", "u64")]
    return {"schema": "hepta.hia.program.v1", "module": "direct_smoke", "functions": [
        function("answer", params, ["u64"], [], [block("entry", params, [
            constant("delta", "u64", 7), operation("int.add.wrap", ["x", "delta"], [("result", "u64")]),
        ], ret("result"))])
    ]}


class DirectObjectTests(unittest.TestCase):
    def test_object_generation_is_deterministic_and_bound_to_exact_core(self):
        program = verify_program(minimal_document())
        first = emit_program_machine(program)
        second = emit_program_machine(verify_program(program.canonical_bytes))
        self.assertEqual(first.object_bytes, second.object_bytes)
        self.assertEqual(first.text_bytes, second.text_bytes)
        self.assertEqual(first.sha256, sha256(first.object_bytes).hexdigest())
        self.assertEqual(first.core_sha256, program.sha256)
        self.assertTrue(first.object_bytes.startswith(b"\x7fELF\x02\x01"))
        self.assertEqual(first.exports, ("answer",))

    def test_object_build_in_fresh_process_prohibits_llvm_import_and_process_launch(self):
        script = r'''
import builtins,json,pathlib,subprocess,sys
original_import=builtins.__import__
def guarded(name,*a,**kw):
    if "llvm" in name.lower(): raise AssertionError("LLVM import: "+name)
    return original_import(name,*a,**kw)
builtins.__import__=guarded
def forbidden(*a,**kw): raise AssertionError("external process launched")
subprocess.Popen=forbidden
from hepta.hia_program_native import build_program_machine
receipt=build_program_machine(json.loads(sys.argv[1]),sys.argv[2],kind="object",linker="/missing/linker")
assert receipt["ok"] is True
assert pathlib.Path(sys.argv[2]).read_bytes().startswith(b"\x7fELF")
from hepta.hia_core_api import build_core
core_output=sys.argv[2]+".core.o"
receipt=build_core(json.loads(sys.argv[1]),core_output,backend="native",kind="object",linker="/missing/linker")
assert receipt["ok"] is True
assert pathlib.Path(core_output).read_bytes().startswith(b"\x7fELF")
from tools.hia_core_reference import main
source=pathlib.Path(sys.argv[2]+".json"); source.write_text(sys.argv[1])
assert main(["build",str(source),"--backend","native","--kind","object",
             "--linker","/missing/linker","-o",sys.argv[2]+".cli.o"]) == 0
assert not any("llvm" in name for name in sys.modules)
print("direct object, common Core API and CLI: no LLVM, no process")
'''
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, "-c", script, json.dumps(minimal_document()), str(Path(temporary) / "program.o")],
                                    cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no process", result.stdout)

    def test_forged_verified_core_is_reverified_before_emission(self):
        program = verify_program(minimal_document())
        with self.assertRaises(ValueError):
            emit_program_machine(replace(program, canonical_bytes=b"{}"))
        malformed = program.as_dict()
        malformed["functions"][0]["blocks"][0]["ops"][1]["args"] = ["missing", "delta"]
        with self.assertRaises(ValueError):
            build_program_machine(malformed, "/must-not-be-published.o", kind="object")

    def test_artifact_mutation_rejected_even_with_recomputed_object_digest(self):
        program = verify_program(minimal_document())
        image = emit_program_machine(program)
        changed = image.object_bytes[:-1] + bytes([image.object_bytes[-1] ^ 1])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bad.o"
            with self.assertRaises(ValueError):
                compile_program_machine(replace(image, object_bytes=changed, sha256=sha256(changed).hexdigest()),
                                        program=program, output=output, kind="object")
            self.assertFalse(output.exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "existing.o"
            output.write_bytes(b"caller-owned")
            with self.assertRaises((ValueError, OSError)):
                build_program_machine(minimal_document(), output, kind="object")
            self.assertEqual(output.read_bytes(), b"caller-owned")

    def test_foreign_target_is_explicitly_rejected(self):
        for target in ("aarch64-unknown-linux-gnu", "riscv64-unknown-linux-gnu", "x86_64-pc-windows-msvc"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                emit_program_machine(verify_program(minimal_document()), target=target)

    def test_cli_native_object_and_explicit_target_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "core.json"; source.write_text(json.dumps(minimal_document()))
            output = root / "cli.o"
            result = subprocess.run([sys.executable, "-m", "tools.hia_core_reference", "build", str(source), "--backend", "native", "--kind", "object",
                                     "--linker", "/missing/linker", "-o", str(output)], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(result.stdout)["ok"])
            self.assertTrue(output.read_bytes().startswith(b"\x7fELF"))
            result = subprocess.run([sys.executable, "-m", "tools.hia_core_reference", "build", str(source), "--backend", "native", "--kind", "object",
                                     "--target", "aarch64-unknown-linux-gnu", "-o", str(root / "foreign.o")], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("direct machine backend", result.stdout + result.stderr)
            self.assertFalse((root / "foreign.o").exists())


    def test_route_inventory_names_explicit_direct_machine_selection(self):
        from hepta.hia_routes import route_inventory
        backends = {entry["backend"]: entry for entry in route_inventory()["backends"]}
        entry = backends["direct-machine"]
        self.assertTrue(entry["same_standalone_core"])
        self.assertEqual(entry["entry"], "hepta.hia_program_native.build_program_machine")
        self.assertIn("--backend native", entry["selection"])
        self.assertFalse(entry["llvm_ir_used"])
        self.assertFalse(entry["assembler_used"])
        self.assertFalse(entry["fallback_used"])
        self.assertIn("direct-llvm", backends)

    def test_all_versioned_agent_core_examples_are_emitted_without_llvm(self):
        paths = sorted((ROOT / "examples/hia_program").glob("*.hia"))
        self.assertGreaterEqual(len(paths), 10)
        for path in paths:
            with self.subTest(path=path.name):
                program = verify_program(path.read_bytes())
                image = emit_program_machine(program)
                self.assertTrue(image.object_bytes.startswith(b"\x7fELF"))
                self.assertEqual(image.core_sha256, program.sha256)


@unittest.skipUnless(X86_LINUX and LD, "GNU linker and Linux x86-64 execution required")
class DirectSystemLinkerTests(unittest.TestCase):
    def test_system_linker_alone_produces_callable_shared_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ld.so"
            commands = []
            receipt = build_program_machine(qualification_program(), output, linker=LD, command_log=commands)
            self.assertEqual(receipt["toolchain"]["mode"], "gnu-ld")
            self.assertEqual(len(commands), 2)
            for command in commands:
                self.assertEqual(Path(command["argv"][0]), Path(LD).resolve())
                self.assertEqual(command["returncode"], 0)
            link = commands[-1]["argv"]
            self.assertIn("-shared", link)
            self.assertTrue(any(arg.endswith(".o") for arg in link))
            self.assertFalse(any(arg.endswith((".c", ".s", ".S", ".ll", ".bc")) for arg in link))
            library = ctypes.CDLL(str(output))
            library.fill_sum.argtypes = [ctypes.c_uint64, ctypes.c_uint8]
            library.fill_sum.restype = ctypes.c_uint64
            self.assertEqual(library.fill_sum(17, 250), 4250)

    def test_cli_native_shared_library_is_callable_with_ld(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.json"
            output = root / "cli.so"
            source.write_text(json.dumps(minimal_document()))
            result = subprocess.run([sys.executable, "-m", "tools.hia_core_reference", "build", str(source),
                                     "--backend", "native", "--linker", LD, "-o", str(output)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads(result.stdout)
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["toolchain"]["mode"], "gnu-ld")
            library = ctypes.CDLL(str(output))
            library.answer.argtypes = [ctypes.c_uint64]
            library.answer.restype = ctypes.c_uint64
            self.assertEqual(library.answer(35), 42)


@unittest.skipUnless(X86_LINUX and CC, "real Linux x86-64 linker and execution required")
class DirectExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-direct-tests-")
        cls.root = Path(cls.temporary.name)
        cls.document = scalar_document()
        cls.program = verify_program(cls.document)
        cls.functions = {f["name"]: f for f in cls.program.as_dict()["functions"]}
        eligible = [name for name, spec in cls.functions.items()
                    if all(type(p["type"]) is str and p["type"] in CTYPES and p["type"] != "unit"
                           for p in spec["params"])
                    and len(spec["returns"]) <= 1
                    and all(type(t) is str and t in CTYPES for t in spec["returns"])]
        cls.libraries = {}
        cls.paths = {}
        cls.receipts = []
        # The published machine profile bounds one object's scalar exports at
        # 128; independent batches keep all helper definitions for internal calls.
        for offset in range(0, len(eligible), 128):
            document = {**cls.document, "exports": eligible[offset:offset + 128]}
            path = cls.root / f"scalar_{offset // 128}.so"
            receipt = build_program_machine(document, path, linker=CC)
            library = ctypes.CDLL(str(path))
            cls.receipts.append(receipt)
            for name in document["exports"]:
                cls.libraries[name] = library
                cls.paths[name] = path
        cls.receipt = cls.receipts[0]
        cls.oracle_programs = {}
        for name in eligible:
            needed = {name}
            pending = [name]
            while pending:
                current = pending.pop()
                for block_spec in cls.functions[current]["blocks"]:
                    for op in block_spec["ops"]:
                        target = op["attrs"].get("function") if op["op"] == "call" else None
                        if target is not None and target not in needed:
                            needed.add(target)
                            pending.append(target)
            # VM rechecks its immutable input on every invocation. Prune only
            # unreachable definitions to keep thousands of crosschecks quick.
            cls.oracle_programs[name] = verify_program({
                **cls.document, "exports": [name],
                "functions": [spec for fn, spec in cls.functions.items() if fn in needed],
            })

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def call(self, name, args, library=None, functions=None):
        function_spec = (functions or self.functions)[name]
        entry = getattr(library or self.libraries[name], name)
        entry.argtypes = [CTYPES[p["type"]] for p in function_spec["params"]]
        entry.restype = CTYPES[function_spec["returns"][0]] if function_spec["returns"] else None
        return entry(*args)

    def assert_vm(self, name, args, library=None, program=None):
        program = program or self.oracle_programs[name]
        functions = {f["name"]: f for f in program.as_dict()["functions"]}
        reference = execute_program(program, name, args)
        self.assertEqual(self.call(name, args, library, functions), reference["result"], (name, args))
        self.assertEqual(reference["resources"]["live_owners"], 0)
        self.assertEqual(reference["resources"]["live_local_loans"], 0)

    def build_fixture(self, document, basename):
        program = verify_program(document)
        path = self.root / (basename + ".so")
        build_program_machine(program, path, linker=CC)
        return program, ctypes.CDLL(str(path)), path

    def test_real_loops_calls_multiple_returns_and_parallel_block_moves(self):
        for n in (0, 1, 2, 7, 31, 128, 1024):
            self.assert_vm("sum_to", [n]); self.assert_vm("invoke_sum", [n])
        for n in (0, 1, 2, 3, 8, 99):
            self.assert_vm("edge_swap", [12, 93, n])
        for a, b in ((0, 0), (7, 3), (3, 7), ((1 << 64) - 1, 19)):
            self.assert_vm("tuple_call", [a, b])
        self.assertIsNone(self.call("no_result", []))
        self.assertNotIn("transfer", self.receipt["exports"])
        self.assertNotIn("pair", self.receipt["exports"])

    def test_scalar_c_abi_register_and_stack_arguments(self):
        cases = [(-128, 65535, -2147483648, (1 << 64) - 1, 255, -32768, -(1 << 63), 0xFFFFFFFF, True),
                 (127, 0, 2147483647, 9, 0, 32767, (1 << 63) - 1, 0, False),
                 (-7, 3, -8, 13, 29, -4, -27, 22, True)]
        for args in cases:
            for name in ("nine_arguments", "call_nine"):
                self.assert_vm(name, list(args))

    def test_all_integer_widths_wrapping_bits_shifts_and_signed_division(self):
        rng = random.Random(0x484941)
        for typ in TYPES[:8]:
            bits = int(typ[1:]); signed = typ.startswith("i")
            lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            values = [(lo, hi), (hi, lo), (0, 1), (hi, 1), (lo, 1)] + [(rng.randint(lo, hi), rng.randint(lo, hi)) for _ in range(12)]
            for a, b in values:
                for op in ("add", "sub", "mul"):
                    self.assert_vm(f"int_{op}_wrap_{typ}", [a, b])
                for op in ("and", "or", "xor"):
                    self.assert_vm(f"bit_{op}_{typ}", [a, b])
                self.assert_vm(f"cast_i8_{typ}", [a])
                if b and not (signed and a == lo and b == -1):
                    self.assert_vm(f"int_div_checked_{typ}", [a, b]); self.assert_vm(f"int_rem_checked_{typ}", [a, b])
                for count in (0, 1, bits - 1):
                    self.assert_vm(f"int_shl_checked_{typ}", [a, count]); self.assert_vm(f"int_shr_checked_{typ}", [a, count])

    def test_checked_arithmetic_comparisons_casts_and_unary(self):
        rng = random.Random(0x434F5245)
        for typ in TYPES:
            bits = 64 if typ.endswith("size") else int(typ[1:]); signed = typ.startswith("i")
            lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            values = [(lo, hi), (hi, lo), (0, 1), (hi, 0), (lo, 0), (hi, 1)] + [(rng.randint(lo, hi), rng.randint(lo, hi)) for _ in range(8)]
            for a, b in values:
                for action, answer in (("add", a+b), ("sub", a-b), ("mul", a*b)):
                    if lo <= answer <= hi:
                        self.assert_vm(f"checked_{action}_{typ}", [a, b])
                for action in ("eq", "ne", "lt", "le", "gt", "ge"):
                    self.assert_vm(f"compare_{action}_{typ}", [a, b])
            for value in (0, 1, -1 if signed else 0, hi, lo):
                if lo <= -value <= hi:
                    self.assert_vm(f"neg_{typ}", [value])
                for target in ("i8", "u8", "i64", "u64"):
                    width = int(target[1:]); minimum, maximum = (-(1 << (width-1)), (1 << (width-1))-1) if target[0]=="i" else (0, (1 << width)-1)
                    if minimum <= value <= maximum:
                        self.assert_vm(f"cast_{typ}_to_{target}", [value])
        for a in (False, True):
            for b in (False, True): self.assert_vm("bool_gate", [a, b])
        for a,b in ((-37,5),(0,-1),(2147483647,1),(-2147483648,0)):
            for choose in (False,True): self.assert_vm("scalar_mix", [a,b,choose])

    def test_owned_memory_zero_initialization_and_ordinary_error_cleanup(self):
        for n in (0, 1, 7, 255, 4096):
            for byte in (0, 7, 255):
                self.assert_vm("lifecycle", [n, byte])
                self.assert_vm("fill_sum", [n, byte])
        self.assert_vm("lifecycle", [(1 << 64) - 1, 17])

    def test_checked_failures_abort_in_isolated_native_processes(self):
        cases = [("explicit_trap", [], "user"), ("overflow_trap", [255], "overflow"), ("bounds_trap", [1], "bounds")]
        for typ in TYPES[:8]:
            bits = int(typ[1:]); signed = typ.startswith("i")
            lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            cases += [(f"checked_add_{typ}", [hi, 1], "overflow"), (f"checked_sub_{typ}", [lo, 1], "overflow"),
                      (f"checked_mul_{typ}", [hi, 2], "overflow"), (f"int_div_checked_{typ}", [1, 0], "division_by_zero"),
                      (f"int_shl_checked_{typ}", [1, bits], "overflow")]
            if signed:
                cases += [(f"neg_{typ}", [lo], "overflow"), (f"int_div_checked_{typ}", [lo, -1], "overflow"),
                          (f"int_rem_checked_{typ}", [lo, -1], "overflow"), (f"cast_{typ}_to_u64", [-1], "overflow")]
            else:
                cases.append((f"neg_{typ}", [1], "overflow"))
        cases += [("cast_u64_to_i64", [1 << 63], "overflow"), ("cast_i64_to_i8", [128], "overflow"),
                  ("cast_u64_to_u8", [256], "overflow")]
        script = '''import ctypes,json,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
lib=ctypes.CDLL(sys.argv[1]); f=getattr(lib,sys.argv[2]); types=json.loads(sys.argv[3]);
f.argtypes=[getattr(ctypes,t) for t in types]; f.restype=None; f(*json.loads(sys.argv[4]))
'''
        for name, arguments, code in cases:
            with self.subTest(name=name, arguments=arguments):
                with self.assertRaises(HIAProgramTrap) as trapped:
                    execute_program(self.oracle_programs[name], name, arguments)
                self.assertEqual(trapped.exception.code, code)
                types = [CTYPES[p["type"]].__name__ for p in self.functions[name]["params"]]
                result = subprocess.run([sys.executable,"-c",script,str(self.paths[name]),name,json.dumps(types),json.dumps(arguments)],
                                        capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,-signal.SIGABRT,result.stdout+result.stderr)

    def test_allocator_observer_checks_actual_frees_and_failed_allocation(self):
        obj=self.root/"allocator.o"; source=self.root/"allocator.c"; binary=self.root/"allocator"
        build_program_machine(qualification_program(),obj,kind="object")
        source.write_text(ALLOCATOR_DRIVER)
        linked=subprocess.run([CC,"-O2",str(source),str(obj),"-Wl,--wrap=calloc","-Wl,--wrap=free","-o",str(binary)],capture_output=True,text=True,timeout=20)
        self.assertEqual(linked.returncode,0,linked.stdout+linked.stderr)
        run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(run.stdout.strip(),"7 7 0 1")

    def test_bulk_operations_v2_through_v6_match_vm(self):
        from tests.test_hia_bulk_memory import bulk_program
        from tests.test_hia_overlap_move import move_program, empty_program
        from tests.test_hia_swap_v4 import swap_program
        from tests.test_hia_offset_copy_v5 import copy_program
        from tests.test_hia_range_fill_v6 import fill_program
        fixtures = [
            (bulk_program(), "v2", "bulk", [[n,count,byte] for n,count in ((1,0),(1,1),(17,0),(17,12),(17,17)) for byte in (0,7,255)]),
            (move_program(),"v3","move_bytes",[[5,dst,src,count,probe] for dst,src,count in ((1,0,4),(0,1,4),(0,0,5),(5,5,0)) for probe in range(5)]),
            (empty_program(),"v3empty","empty",[[0],[7]]),
            (swap_program(),"v4","swap_bytes",[[5,left,right,probe] for left,right in ((0,4),(4,0),(2,2),(1,3)) for probe in range(5)]),
            (copy_program(),"v5","copy_offset",[[5,dst,src,count,probe] for dst,src,count in ((0,0,5),(1,2,2),(2,1,2),(5,5,0)) for probe in range(5)]),
            (fill_program(),"v6","fill_range",[[5,offset,count,byte,probe] for offset,count in ((0,5),(1,3),(5,0),(0,0)) for byte in (0,255) for probe in range(5)]),
            (fill_program(read=False),"v6empty","fill_range",[[0,0,0,255,0]]),
        ]
        for document,basename,name,cases in fixtures:
            program,library,_=self.build_fixture(document,basename)
            for arguments in cases:
                with self.subTest(fixture=basename,arguments=arguments): self.assert_vm(name,arguments,library,program)

    def test_recursive_chain_and_composite_v7_have_real_dynamic_execution(self):
        for basename in ("core_v7","composite_v2"):
            document=(ROOT/"examples/hia_recursive_chain"/(basename+".json")).read_bytes()
            program,library,_=self.build_fixture(document,basename)
            names={fn["name"]:fn for fn in program.as_dict()["functions"]}
            for name in ("chain_checksum","chain_cancel","chain_head_update","chain_stored_loan","chain_recover","chain_empty_payloads"):
                if name not in names: continue
                for n in (0,1,2,17,129):
                    with self.subTest(program=basename,name=name,n=n): self.assert_vm(name,[n],library,program)
            if "chain_task" in names:
                for n in (0,1,17):
                    for mode in (0,1,2): self.assert_vm("chain_task",[n,mode],library,program)
            if "chain_empty_pop" in names: self.assert_vm("chain_empty_pop",[],library,program)

    def test_v8_parameter_loans_calls_cfg_recursion_and_aliases(self):
        from tests.test_hia_returned_loans import document, loan_program, multiple_shared, swapped_mutable, fallible_return_program
        programs=[loan_program(mode,form) for mode in ("read","mut") for form in ("forward","child","cfg","recursive")]
        combined=document(*(fn for item in programs for fn in item["functions"]))
        combined["exports"]=[item["exports"][0] for item in programs]
        program,library,_=self.build_fixture(combined,"v8loans")
        for name in combined["exports"]:
            for length in (1,3,17):
                for byte in (0,17,250,255): self.assert_vm(name,[length,byte],library,program)
        for form in ("forward","children","mixed"):
            program,library,_=self.build_fixture(multiple_shared(form),"v8shared_"+form)
            for byte in (0,37,128,255): self.assert_vm("shared",[byte],library,program)
        program,library,_=self.build_fixture(swapped_mutable(),"v8swapped")
        self.assert_vm("swapped",[],library,program)
        program,library,_=self.build_fixture(fallible_return_program(),"v8fallible")
        self.assert_vm("fallible_entry",[],library,program)

    def test_v8_chain_head_returned_loans_and_pop(self):
        from tests.test_hia_returned_chain_loans import chain_program
        for mode in ("read","mut"):
            for form in ("forward","child"):
                document=chain_program(mode,form); program,library,_=self.build_fixture(document,"v8chain_"+mode+"_"+form)
                for byte in (0,37,250,255): self.assert_vm(document["exports"][0],[byte],library,program)



if __name__ == "__main__":
    unittest.main()
