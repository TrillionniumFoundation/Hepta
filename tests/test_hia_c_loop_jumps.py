"""Actual captured C/C++ loop jumps reach Core and direct native HIA.

The C++ scope is concrete noexcept scalar bodies, not unrestricted C++.
Differentials retain original defined inputs and do not claim equivalence for
arbitrary programs. Unsupported jumps and unsafe deferred reads still reject.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project, verify_capture
from hepta.c_translation import CTranslator
from hepta.cpp_project_migrate import lower_cpp_project
from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_c_project_views, lower_source


SOURCE = r"""
unsigned while_jumps(unsigned count, unsigned seed) {
    unsigned i = 0, total = seed;
    while (i < count) {
        i++;
        if (i == 2u) continue;
        if (i == 5u) break;
        unsigned item = i * 3u;
        total += item;
    }
    return total + i * 100u;
}
unsigned for_jumps(unsigned count, unsigned seed) {
    unsigned total = seed, ticks = 0;
    for (unsigned i = 0; i < count; i++, ticks++) {
        if (i == 2u) continue;
        if (i == 5u) break;
        unsigned item = i + 1u;
        total += item;
    }
    return total + ticks * 100u;
}
unsigned do_jumps(unsigned count, unsigned seed) {
    unsigned i = 0, total = seed;
    do {
        i++;
        if (i == 5u) break;
        if (i == 2u) continue;
        unsigned item = i * 3u;
        total += item;
    } while (i < count);
    return total + i * 100u;
}
unsigned while_break_trap(unsigned count, unsigned seed) {
    unsigned divisor = 1;
    while (count / divisor > 0u) { divisor = 0; break; }
    return seed + divisor;
}
unsigned do_break_trap(unsigned count, unsigned seed) {
    unsigned divisor = 0;
    do { seed += 7u; break; } while (count / divisor > 0u);
    return seed;
}
unsigned for_break_trap(unsigned count, unsigned seed) {
    unsigned i = 0, divisor = 0;
    for (i = 0; i < count; i = i + 8u / divisor) {
        if (seed != 0u) { i = 1; break; }
        divisor = 1;
        if (i >= 4u) break;
    }
    return i;
}
unsigned nested_jumps(unsigned count, unsigned seed) {
    if (count > 16u) return seed;
    unsigned total = seed;
    for (unsigned outer = 0; outer < count; outer++) {
        unsigned inner = 0;
        while (inner < 4u) {
            inner++;
            if (inner == 2u) continue;
            if (inner == 3u) break;
            total += outer + inner;
        }
        total += 7u;
    }
    return total;
}
unsigned tail_scopes(unsigned count, unsigned seed) {
    if (count > 16u) return seed;
    unsigned total = seed;
    for (unsigned i = 0; i < count; i++) {
        {
            if ((i & 1u) != 0u) continue;
            unsigned item = seed + i;
            total += item;
        }
        unsigned item = i + 10u;
        total += item;
    }
    return total;
}
"""
NAMES = ("while_jumps", "for_jumps", "do_jumps", "while_break_trap",
         "do_break_trap", "for_break_trap", "nested_jumps", "tail_scopes")


def expected(name, count, seed):
    modulus = 1 << 32
    if name in {"while_jumps", "do_jumps"}:
        i, total = 0, seed
        while i < count or name == "do_jumps" and i == 0:
            i += 1
            if i == 5:
                break
            if i == 2:
                continue
            total += i * 3
        return (total + i * 100) % modulus
    if name == "for_jumps":
        ticks, total = 0, seed
        for i in range(min(count, 6)):
            if i == 5:
                break
            if i != 2:
                total += i + 1
            ticks += 1
        return (total + ticks * 100) % modulus
    if name == "while_break_trap":
        return (seed + (count == 0)) % modulus
    if name == "do_break_trap":
        return (seed + 7) % modulus
    if name == "for_break_trap":
        return 0 if count == 0 else 1 if seed else 8
    if name == "nested_jumps":
        return (seed + sum(i + 8 for i in range(count))) % modulus if count <= 16 else seed
    if name == "tail_scopes":
        return (seed + sum(seed + 2 * i + 10 for i in range(0, count, 2))) % modulus if count <= 16 else seed
    raise AssertionError(name)


class HIACLoopJumpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-c-loop-jumps-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.clangxx = os.environ.get("CLANGXX") or shutil.which("clang++")
        self.assertTrue(self.clang and self.clangxx, "Actual Clang/Clang++ required")

    def database(self, source, name="input", *, cpp=False):
        directory = self.work / name
        directory.mkdir()
        filename = "input.cpp" if cpp else "input.c"
        (directory / filename).write_text(source)
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([{
            "directory": str(directory), "file": filename,
            "arguments": ["clang++" if cpp else "clang", "-std=c++20" if cpp else "-std=c11",
                          "-O2", "-c", filename],
        }]))
        return directory, database

    def command(self, argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_c_and_concrete_cpp_vm_and_direct_llvm_match_originals(self):
        directory, database = self.database(SOURCE)
        cpp_source = 'extern "C" {\n' + SOURCE.replace(
            "unsigned count, unsigned seed) {", "unsigned count, unsigned seed) noexcept {") + '\n}\n'
        cpp_directory, cpp_database = self.database(cpp_source, "cpp", cpp=True)
        capture = capture_project(database, clang=self.clang)
        translator = CTranslator(capture)
        translator.retained_asts = {}
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback forbidden")):
            source, _, _ = translator.emit()
            core = lower_source(source)
            build_program_native(core, directory / "hia.so", clang=self.clang)
            cpp = lower_cpp_project(cpp_database, clangxx=self.clangxx)
            build_program_native(cpp["program"], cpp_directory / "hia.so", clang=self.clang)
        # Captured AST text remains original evidence, never replaced by a
        # synthetic tree with the jumps already removed.
        original_ast = "\n".join(translator.retained_asts.values())
        self.assertIn('"kind": "BreakStmt"', original_ast)
        self.assertIn('"kind": "ContinueStmt"', original_ast)
        self.assertNotIn('"name": "migration_loop_', original_ast)
        verify_capture(capture)
        self.assertFalse(cpp["claims"]["arbitrary_cpp_stl_raii_exceptions_supported"])
        for compiler, standard, root, filename in (
            (self.clang, "c11", directory, "input.c"),
            (self.clangxx, "c++20", cpp_directory, "input.cpp"),
        ):
            self.command([compiler, "-std=" + standard, "-O2", "-fPIC", "-shared",
                          str(root / filename), "-o", str(root / "reference.so")])
        libraries = [ctypes.CDLL(str(root / name)) for root, name in (
            (directory, "reference.so"), (cpp_directory, "reference.so"),
            (directory, "hia.so"), (cpp_directory, "hia.so"))]
        rng = random.Random(20261030)
        cases = [(count, seed) for count in (0, 1, 2, 3, 4, 5, 6, 9, 16, 0xffffffff)
                 for seed in (0, 1, 11, 0xffffffff)]
        cases += [(rng.randrange(0, 25), rng.getrandbits(32)) for _ in range(32)]
        for name in NAMES:
            natives = [getattr(library, ("c_" if index == 2 else "") + name)
                       for index, library in enumerate(libraries)]
            for native in natives:
                native.argtypes, native.restype = [ctypes.c_uint32, ctypes.c_uint32], ctypes.c_uint32
            for count, seed in cases:
                with self.subTest(function=name, count=count, seed=seed):
                    oracle = expected(name, count, seed)
                    self.assertEqual(execute_program(core, "c_" + name, [count, seed])["result"], oracle)
                    self.assertEqual(execute_program(cpp["program"], name, [count, seed])["result"], oracle)
                    self.assertEqual([native(count, seed) for native in natives], [oracle] * 4)

    def test_deferred_assignments_merge_actual_jump_exits(self):
        sources = [
            ("int value;do{if(seed){value=7;break;}value=3;}while(0);return value;", [(0, 3), (1, 7)]),
            ("int value;do{value=seed;continue;}while(0);return value;", [(0, 0), (7, 7)]),
            ("int value;do{while(count){break;}value=seed;}while(0);return value;", [(0, 0), (7, 7)]),
            ("int value;do{if(seed){return 9;}value=4;break;}while(count);return value;", [(0, 4), (1, 9)]),
        ]
        for index, (body, cases) in enumerate(sources):
            _, database = self.database("int probe(int count,int seed){" + body + "}", "deferred-" + str(index))
            capture = capture_project(database, clang=self.clang)
            source, _, functions = CTranslator(capture).emit()
            self.assertTrue(functions[0]["definite_assignment"]["checked"])
            core = lower_source(source)
            for seed, oracle in cases:
                self.assertEqual(execute_program(core, "c_probe", [1, seed])["result"], oracle)

    def test_break_continue_do_not_admit_uninitialized_reads(self):
        bodies = [
            "int value;do{if(seed)break;value=3;}while(0);return value;",
            "int value;do{if(seed)continue;value=3;}while(0);return value;",
            "int value;do{continue;value=3;}while(value);return 0;",
            "int value;for(int i=0;i<count;i+=value){if(seed)continue;value=1;}return 0;",
            "int value;do{while(count){value=7;break;}}while(0);return value;",
            "int value;while(count){value=7;break;}return value;",
            "int value;do{break;value=7;}while(0);return value;",
        ]
        for index, body in enumerate(bodies):
            with self.subTest(index=index):
                _, database = self.database("int probe(int count,int seed){" + body + "}", "uninitialized-" + str(index))
                with self.assertRaises(MigrationRejected) as caught:
                    CTranslator(capture_project(database, clang=self.clang)).emit()
                self.assertEqual(caught.exception.code, "E_C_UNINITIALIZED")

    def test_switch_goto_and_mutating_conditions_remain_rejected(self):
        bodies = [
            ("while(count){switch(seed){case 0:break;default:return 3;}count--;}return seed;", "E_C_STATEMENT"),
            ("while(count){if(seed)goto done;break;}done:return seed;", "E_C_STATEMENT"),
            ("while(count--){if(seed)break;continue;}return seed;", "E_C_UNARY"),
            ("do{if(seed)continue;break;}while(count--);return seed;", "E_C_UNARY"),
        ]
        for index, (body, code) in enumerate(bodies):
            with self.subTest(index=index):
                _, database = self.database("int probe(int count,int seed){" + body + "}", "unsupported-" + str(index))
                with self.assertRaises(MigrationRejected) as caught:
                    CTranslator(capture_project(database, clang=self.clang)).emit()
                self.assertEqual(caught.exception.code, code)

    def test_wide_jump_sequence_rejects_bounded_expansion(self):
        source = ("unsigned probe(unsigned seed){unsigned total=0;"
                  "for(unsigned i=0;i<2u;i++){" + "if(seed)continue;" * 80
                  + "total+=i;}return total;}")
        _, database = self.database(source, "wide")
        with self.assertRaises(MigrationRejected) as caught:
            CTranslator(capture_project(database, clang=self.clang)).emit()
        self.assertEqual(caught.exception.code, "E_C_CONTROL_LIMIT")

    def test_upstream_ring_maintenance_loop_jumps_reach_native_hia(self):
        from tools.qualify_hia_legacy_queue import ENTRY, SOURCES, compile_database, populate_project
        from tools.qualify_hia_filecheck import update
        project = self.work / "project"
        contracts = populate_project(project)
        ring = project / "ring/ringbuffer.c"
        before = ring.read_text()
        old = """  for(i = 0; i < size; i++) {
    ring_buffer_queue(buffer, data[i]);
  }"""
        new = """  i = 0;
  while (i < size) {
    ring_buffer_queue(buffer, data[i]);
    i++;
    if (i == size) break;
    continue;
  }"""
        self.assertEqual(before.count(old), 1)
        ring.write_text(before.replace(old, new))
        database = compile_database(project, self.work / "capture")
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback forbidden")):
            migrated = lower_c_project_views(database, contracts=contracts, clang=self.clang,
                client_source=(project / "client.hepta").read_text(), retain_asts=True)
            core = migrated["program"]
            build_program_native(core, self.work / "hia.so", clang=self.clang)
        self.command([self.clang, "-std=c11", "-DNDEBUG", "-funsigned-char", "-fno-builtin",
                      "-O2", "-fPIC", "-shared", "-I" + str(project / "compare/platform"),
                      *(str(project / name) for name in SOURCES), str(project / "client.c"),
                      "-o", str(self.work / "reference.so")])
        natives = [getattr(ctypes.CDLL(str(self.work / name)), ENTRY)
                   for name in ("reference.so", "hia.so")]
        for native in natives:
            native.argtypes = [ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32]
            native.restype = ctypes.c_uint64
        for count in range(12):
            args = [count, 0xfedcba9876543210, 0xffffffff, 0xedb88320]
            oracle = 1 << 32 if count > 8 else update(args[2], args[1].to_bytes(8, "little")[:count], args[3])
            observation = execute_program(core, ENTRY, args)
            self.assertEqual(observation["result"], oracle)
            self.assertEqual([native(*args) for native in natives], [oracle] * 2)
            self.assertEqual(observation["resources"]["live_owners"], 0)
            self.assertEqual(observation["resources"]["loans_started"], observation["resources"]["loans_ended"])
        self.assertEqual(len(migrated["raw_asts"]), 4)


if __name__ == "__main__":
    unittest.main()
