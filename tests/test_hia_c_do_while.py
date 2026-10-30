"""Captured C post-test loops reach independent Core and actual native code.

The C++ arm compiles the C-compatible reference; it is not C++ translation.
Native observations are finite differentials, not a refinement proof.
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
from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_c_project_views, lower_source


SOURCE = r"""
int once(int count, int seed) {
    int total = seed; int i = 0;
    do { total = total + 3; i = i + 1; } while (i < count);
    return total;
}
int postcondition(int count, int seed) {
    int divisor = 0; int iterations = 0;
    do { divisor = 1; iterations = iterations + 1; }
    while (9 / divisor < iterations);
    return iterations + seed;
}
int nested(int count, int seed) {
    int total = seed; int outer = 0;
    do {
        int inner = 0; int step = outer + 1;
        do { total = total + step; inner = inner + 1; } while (inner < 2);
        outer = outer + 1;
    } while (outer < count);
    return total;
}
int early(int count, int seed) {
    int i = 0;
    do { if (seed == 0) { return 33; } i = i + 1; }
    while (count / i > 1);
    return i;
}
int shadowed(int count, int seed) {
    int total = seed; int i = 0;
    do { int seed = i + 1; total = total + seed; i = i + 1; }
    while (i < count);
    return total;
}
int deferred(int count, int seed) {
    int value; int i = 0;
    do { value = seed + i; i = i + 1; } while (i < count);
    return value;
}
int branch_deferred(int count, int seed) {
    int value;
    do { if (seed < 0) { return -4; } else { value = seed; } } while (0);
    return value;
}
int unbraced(int count, int seed) {
    int i = 0;
    do i++; while (i < count);
    return i + seed;
}
"""


def expected(name, count, seed):
    iterations = max(1, count)
    if name == "once":
        return seed + 3 * iterations
    if name == "postcondition":
        return 1 + seed
    if name == "nested":
        return seed + iterations * (iterations + 1)
    if name == "early":
        return 33 if seed == 0 else max(1, count // 2 + 1)
    if name == "shadowed":
        return seed + iterations * (iterations + 1) // 2
    if name == "deferred":
        return seed + iterations - 1
    if name == "branch_deferred":
        return -4 if seed < 0 else seed
    if name == "unbraced":
        return iterations + seed
    raise AssertionError(name)


class HIACDoWhileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-c-do-while-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.clangxx = os.environ.get("CLANGXX") or shutil.which("clang++")
        self.assertTrue(self.clang and self.clangxx,
                        "Actual Clang/Clang++ required; missing tools do not qualify this gate")

    def database(self, source, name="input"):
        directory = self.work / name
        directory.mkdir()
        (directory / "input.c").write_text(source)
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([{
            "directory": str(directory), "file": "input.c",
            "arguments": [self.clang, "-std=c11", "-O2", "-c", "input.c"],
        }]))
        return directory, database

    def command(self, argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_c_cpp_vm_and_direct_llvm_match_original_post_test_semantics(self):
        directory, database = self.database(SOURCE)
        capture = capture_project(database, clang=self.clang)
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback forbidden")):
            source, _unused_bridge, functions = CTranslator(capture).emit()
            core = lower_source(source)
            build_program_native(core, directory / "hia.so", clang=self.clang)
        verify_capture(capture)
        (directory / "reference.cc").write_text('extern "C" {\n' + SOURCE + '\n}\n')
        for compiler, standard, source_name, output in (
            (self.clang, "c11", "input.c", "c.so"),
            (self.clangxx, "c++20", "reference.cc", "cpp.so"),
        ):
            self.command([compiler, "-std=" + standard, "-O2", "-fPIC", "-shared",
                          str(directory / source_name), "-o", str(directory / output)])
        libraries = [ctypes.CDLL(str(directory / name)) for name in ("c.so", "cpp.so", "hia.so")]
        rng = random.Random(20261030)
        cases = [(count, seed) for count in (-5, -1, 0, 1, 2, 3, 9, 16)
                 for seed in (-7, 0, 11)]
        cases += [(rng.randrange(-5, 25), rng.randrange(-40, 41)) for _ in range(24)]
        names = ("once", "postcondition", "nested", "early", "shadowed", "deferred",
                 "branch_deferred", "unbraced")
        for name in names:
            natives = [getattr(library, ("c_" if index == 2 else "") + name)
                       for index, library in enumerate(libraries)]
            for native in natives:
                native.argtypes, native.restype = [ctypes.c_int32, ctypes.c_int32], ctypes.c_int32
            for count, seed in cases:
                with self.subTest(function=name, count=count, seed=seed):
                    oracle = expected(name, count, seed)
                    self.assertEqual(execute_program(core, "c_" + name, [count, seed])["result"], oracle)
                    self.assertEqual([native(count, seed) for native in natives], [oracle] * 3)
        deferred = {function["name"]: function["definite_assignment"] for function in functions}
        self.assertTrue(deferred["deferred"]["checked"])
        self.assertTrue(deferred["branch_deferred"]["checked"])

    def test_upstream_ring_maintenance_variant_reaches_native_hia(self):
        # The frozen upstream file stays unchanged. This authored maintenance
        # variant changes its queue loop in a separate captured project.
        from tools.qualify_hia_legacy_queue import ENTRY, SOURCES, compile_database, populate_project
        from tools.qualify_hia_filecheck import update
        project = self.work / "project"
        contracts = populate_project(project)
        ring = project / "ring/ringbuffer.c"
        before = ring.read_text()
        old = """  for(i = 0; i < size; i++) {
    ring_buffer_queue(buffer, data[i]);
  }"""
        new = """  if (size == 0) return;
  i = 0;
  do {
    ring_buffer_queue(buffer, data[i]);
    i++;
  } while (i < size);"""
        self.assertEqual(before.count(old), 1)
        ring.write_text(before.replace(old, new))
        database = compile_database(project, self.work / "capture")
        zero_client = """
        export "C" fn queue_zero() -> usize effects {alloc, block, panic, write} {
            let mut storage = buffer(16); let input = buffer(0);
            let mut ring = C_ring_buffer_t {
                f_buffer_mask: 0, f_tail_index: 0, f_head_index: 0,
            };
            c_ring_buffer_init(mut ring, mut storage, 0, 16);
            c_ring_buffer_queue_arr(mut ring, mut storage, read input, 0, 0);
            let count = c_ring_buffer_num_items(read ring, read storage);
            drop(move input); drop(move storage); return count;
        }
        """
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback forbidden")):
            migrated = lower_c_project_views(database, contracts=contracts, clang=self.clang,
                client_source=(project / "client.hepta").read_text() + zero_client, retain_asts=True)
            core = migrated["program"]
            build_program_native(core, self.work / "hia.so", clang=self.clang)
        with (project / "client.c").open("a") as client:
            client.write("""
            size_t queue_zero(void) {
                char storage[16] = {0}; ring_buffer_t ring;
                ring_buffer_init(&ring, storage, 16);
                ring_buffer_queue_arr(&ring, NULL, 0);
                return ring_buffer_num_items(&ring);
            }
            """)
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
            observed = execute_program(core, ENTRY, args)
            self.assertEqual(observed["result"], oracle)
            self.assertEqual([native(*args) for native in natives], [oracle, oracle])
            self.assertEqual(observed["resources"]["live_owners"], 0)
            self.assertEqual(observed["resources"]["loans_started"], observed["resources"]["loans_ended"])
        zero = execute_program(core, "queue_zero", [])
        self.assertEqual(zero["result"], 0)
        self.assertEqual(zero["resources"]["live_owners"], 0)
        for name in ("reference.so", "hia.so"):
            native = ctypes.CDLL(str(self.work / name)).queue_zero
            native.argtypes, native.restype = [], ctypes.c_size_t
            self.assertEqual(native(), 0)
        self.assertFalse(migrated["claims"]["rust_backend_required"])
        self.assertEqual(len(migrated["raw_asts"]), 4)

    def test_uninitialized_paths_and_unmodeled_jumps_reject(self):
        cases = [
            ("int value;int i=0;do{if(seed)value=4;i++;}while(i<count);return value;", "E_C_UNINITIALIZED"),
            ("int value;do{value=value+1;}while(0);return value;", "E_C_UNINITIALIZED"),
            ("int value;do{seed=1;}while(value<count);value=seed;return value;", "E_C_UNINITIALIZED"),
            ("int value;do{if(seed)break;value=4;}while(0);return value;", "E_C_UNINITIALIZED"),
            ("int value;do{if(seed)continue;value=4;}while(0);return value;", "E_C_UNINITIALIZED"),
            ("int i=0;do{goto end;}while(i<count);end:return i;", "E_C_STATEMENT"),
            ("int i=0;do{i++;}while(seed--);return i;", "E_C_UNARY"),
        ]
        for index, (body, code) in enumerate(cases):
            with self.subTest(index=index):
                _, database = self.database("int probe(int count,int seed){" + body + "}", "negative-" + str(index))
                capture = capture_project(database, clang=self.clang)
                with self.assertRaises(MigrationRejected) as caught:
                    CTranslator(capture).emit()
                self.assertEqual(caught.exception.code, code)

    def test_mutating_postcondition_is_not_silently_admitted(self):
        source = """
        unsigned int step(unsigned char *data, unsigned long count) {
            data[0] = data[0] + 1; return data[0];
        }
        unsigned int probe(unsigned char *data, unsigned long count) {
            unsigned int i = 0;
            do { i = i + 1; } while (step(data, count));
            return i;
        }
        """
        contracts = {"schema": "hepta.c-contracts.v1", "functions": {
            name: {"slices": {"data": {"length": "count", "access": "mut"}}}
            for name in ("step", "probe")}}
        _, database = self.database(source)
        capture = capture_project(database, clang=self.clang)
        with self.assertRaises(MigrationRejected) as caught:
            CTranslator(capture, contracts).emit()
        self.assertEqual(caught.exception.code, "E_C_EVALUATION_ORDER")


if __name__ == "__main__":
    unittest.main()

