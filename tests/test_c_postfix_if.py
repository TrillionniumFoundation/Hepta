"""Finite full-condition sequencing, original musl input and native safety gates."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project, verify_capture
from hepta.c_translation import CTranslator
from hepta.hia_program import execute_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_source import lower_c_project_views, lower_source
from hepta.hia_program_llvm import build_program_native
from tools.qualify_hia_musl_strncmp import (CLIENT, ENTRY, FLAGS, FIXTURE,
    byte_compare, cases, expected_resources, prepare_project, verify_upstream)


SOURCE = r"""
unsigned postdec(unsigned n) {
    unsigned branch = 0;
    if (n--) branch = 100;
    return n ^ branch;
}
unsigned negated(unsigned n) {
    if (!((n)--)) return n;
    return n ^ 101u;
}
unsigned postinc(unsigned n) {
    if (n++) return n ^ 85u;
    return n ^ 170u;
}
unsigned nested(unsigned n) {
    if (n--) { if (n--) return n; return 7u; }
    return n;
}
unsigned local(unsigned n) {
    unsigned value = n;
    if (!!(value--)) return value ^ 99u;
    return value;
}
unsigned short_circuit_after_update(unsigned n) {
    unsigned zero = 0;
    if (n--) { if (zero && (7u / zero)) return 99u; return n; }
    return n;
}
int signed_dec(int n) { if (n--) return n; return 9; }
int signed_inc(int n) { if (n++) return n; return 9; }
"""


def expected(name, n):
    after = (n + (1 if name == "postinc" else -1)) & 0xffffffff
    if name == "postdec":
        return after ^ (100 if n else 0)
    if name == "negated":
        return after if n == 0 else after ^ 101
    if name == "postinc":
        return after ^ (85 if n else 170)
    if name == "nested":
        return after if n == 0 else 7 if after == 0 else (after - 1) & 0xffffffff
    if name == "local":
        return after ^ (99 if n else 0)
    if name == "short_circuit_after_update":
        return after
    if name == "signed_dec":
        return n - 1 if n else 9
    if name == "signed_inc":
        return n + 1 if n else 9
    raise AssertionError(name)


class CPostfixIfTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-c-postfix-if-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.assertTrue(self.clang, "actual Clang required")

    def database(self, source, name):
        root = self.work / name
        root.mkdir()
        (root / "input.c").write_text(source)
        database = root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(root), "file": "input.c",
            "arguments": ["clang", "-std=c11", "-O2", "-fPIC", "-c", "input.c"]}]))
        return root, database

    def translated(self, source, name):
        root, database = self.database(source, name)
        capture = capture_project(database, clang=self.clang)
        translator = CTranslator(capture)
        translator.retained_asts = {}
        emitted, _, _ = translator.emit()
        verify_capture(capture)
        return root, lower_source(emitted), translator.retained_asts

    def command(self, argv, cwd=None):
        result = subprocess.run(list(map(str, argv)), cwd=cwd, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_old_condition_and_new_branch_value_match_native_c(self):
        root, core, asts = self.translated(SOURCE, "scalar")
        self.assertIn('"isPostfix": true', asts[0])
        self.assertNotIn("migration_if_old_", asts[0])
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback forbidden")):
            receipt = build_program_native(core, root / "hia.so", clang=self.clang)
        self.assertTrue(receipt["ok"])
        self.command([self.clang, "-std=c11", "-O2", "-fPIC", "-shared", root / "input.c", "-o", root / "original.so"])
        original, hia = (ctypes.CDLL(str(root / name)) for name in ("original.so", "hia.so"))
        for name in ("postdec", "negated", "postinc", "nested", "local", "short_circuit_after_update"):
            before, after = getattr(original, name), getattr(hia, "c_" + name)
            before.argtypes = after.argtypes = [ctypes.c_uint32]
            before.restype = after.restype = ctypes.c_uint32
            for value in (0, 1, 2, 3, 127, 255, 65535, (1 << 31), 0xfffffffe, 0xffffffff):
                oracle = expected(name, value)
                self.assertEqual((before(value), after(value), execute_program(core, "c_" + name, [value])["result"]),
                                 (oracle, oracle, oracle), (name, value))
        for name in ("signed_dec", "signed_inc"):
            before, after = getattr(original, name), getattr(hia, "c_" + name)
            before.argtypes = after.argtypes = [ctypes.c_int32]
            before.restype = after.restype = ctypes.c_int32
            for value in (-2147483647, -7, -1, 0, 1, 7, 2147483646):
                oracle = expected(name, value)
                self.assertEqual((before(value), after(value), execute_program(core, "c_" + name, [value])["result"]),
                                 (oracle, oracle, oracle))

    def test_signed_overflow_traps_in_hia_without_executing_undefined_original(self):
        root, core, _ = self.translated("int down(int n){if(n--)return n;return 9;}\nint up(int n){if(n++)return n;return 9;}", "overflow")
        build_program_native(core, root / "hia.so", clang=self.clang)
        script = """import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
fn=getattr(ctypes.CDLL(sys.argv[1]),sys.argv[2]);fn.argtypes=[ctypes.c_int32];fn.restype=ctypes.c_int32
fn(int(sys.argv[3]))
"""
        for name, value in (("c_down", -(1 << 31)), ("c_up", (1 << 31) - 1)):
            with self.assertRaises(HIAProgramTrap):
                execute_program(core, name, [value])
            native = subprocess.run([sys.executable, "-I", "-c", script, str(root / "hia.so"), name, str(value)], capture_output=True, timeout=10)
            self.assertEqual(native.returncode, -6, native.stderr)

    def test_effectful_short_circuit_loop_and_arithmetic_contexts_still_reject(self):
        bodies = ["if(0u && n--)return 1u;", "if(1u || n--)return 1u;",
                  "if(n-- + 1u)return 1u;", "if(++n)return 1u;",
                  "while(n--){}", "do{}while(n--);", "if((n--,n))return 1u;"]
        for index, body in enumerate(bodies):
            with self.subTest(body=body):
                _, database = self.database("unsigned probe(unsigned n){" + body + "return n;}", "context-" + str(index))
                with self.assertRaises(MigrationRejected) as caught:
                    CTranslator(capture_project(database, clang=self.clang)).emit()
                self.assertEqual(caught.exception.code, "E_C_UNARY")

    def test_nonlocal_pointer_record_boolean_and_float_lvalues_reject(self):
        samples = [
            ("unsigned probe(unsigned *p,unsigned n){if((*p)--)return 1;return 0;}", {"schema":"hepta.c-contracts.v1","functions":{"probe":{"slices":{"p":{"length":"n","access":"mut"}}}}}),
            ("unsigned probe(unsigned *p,unsigned n){if(p[0]--)return 1;return 0;}", {"schema":"hepta.c-contracts.v1","functions":{"probe":{"slices":{"p":{"length":"n","access":"mut"}}}}}),
            ("struct State{unsigned value;};unsigned probe(struct State s){if(s.value--)return 1;return 0;}", None),
            ("unsigned probe(_Bool n){if(n--)return 1;return 0;}", None),
            ("unsigned probe(float n){if(n--)return 1;return 0;}", None),
        ]
        for index, (source, contracts) in enumerate(samples):
            with self.subTest(index=index):
                _, database = self.database(source, "lvalue-" + str(index))
                with self.assertRaises(MigrationRejected) as caught:
                    CTranslator(capture_project(database, clang=self.clang), contracts).emit()
                self.assertEqual(caught.exception.code, "E_C_IF_POSTFIX")

    def test_small_signed_narrowing_and_uninitialized_local_remain_rejected(self):
        samples = [("int probe(signed char n){if(n--)return 1;return 0;}", "E_C_SIGNED_CONVERSION"),
                   ("int probe(short n){if(n++)return 1;return 0;}", "E_C_SIGNED_CONVERSION"),
                   ("unsigned probe(unsigned n){unsigned value;if(value--)return n;return 0;}", "E_C_UNINITIALIZED")]
        for index, (source, code) in enumerate(samples):
            _, database = self.database(source, "reject-" + str(index))
            with self.assertRaises(MigrationRejected) as caught:
                CTranslator(capture_project(database, clang=self.clang)).emit()
            self.assertEqual(caught.exception.code, code)

    def test_unmodified_musl_body_executes_with_owned_storage_and_refusal_cleanup(self):
        verify_upstream()
        project = self.work / "musl"
        database, contracts = prepare_project(project)
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback forbidden")):
            migrated = lower_c_project_views(database, contracts=contracts, clang=self.clang,
                client_source=(project / "client.hepta").read_text(), retain_asts=True)
            core = migrated["program"]
            build_program_native(core, self.work / "hia.o", kind="object", clang=self.clang)
        self.assertEqual((project / "strncmp.c").read_bytes(), (FIXTURE / "strncmp.c").read_bytes())
        self.assertEqual(len(migrated["functions"]), 1)
        self.assertTrue(migrated["declaration_inventory_complete"])
        self.assertNotIn("c_strncmp", core.as_dict()["exports"])
        self.assertIn('"isPostfix": true', migrated["raw_asts"][0])
        self.command([self.clang, "-std=c11", "-O2", "-fno-builtin", project / "observer.c", self.work / "hia.o",
                      "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", self.work / "native"])
        selected = [cases()[0], cases()[48], cases()[49], cases()[-2], cases()[-1],
                    {"arguments":[8,0x00ff010203040506,0x00ff010203040507], "expected":-1},
                    {"arguments":[8,0xff00010203040506,0x0100010203040506], "expected":0}]
        for case in selected:
            for refusal in (0, 1, 2):
                expected_row = expected_resources(case, refusal)
                native = json.loads(self.command([self.work / "native", *case["arguments"], refusal]).stdout)
                vm = execute_program(core, ENTRY, case["arguments"], allocation_fail_at=refusal or None)
                self.assertEqual(native, expected_row)
                self.assertEqual(vm["result"], expected_row["result"])
                self.assertEqual(vm["resources"]["live_owners"], 0)
                self.assertEqual(vm["resources"]["loans_started"], vm["resources"]["loans_ended"])

    def test_signed_char_configuration_does_not_gain_unqualified_slice_reinterpretation(self):
        database, contracts = prepare_project(self.work / "signed-char", signed_char=True)
        with self.assertRaises(MigrationRejected) as caught:
            lower_c_project_views(database, contracts=contracts, clang=self.clang)
        self.assertEqual(caught.exception.code, "E_C_POINTER_CAST")

    def test_upstream_identity_and_independent_oracle_boundary_controls(self):
        project = self.work / "tamper"
        shutil.copytree(FIXTURE, project)
        with (project / "strncmp.c").open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaises(ValueError):
            verify_upstream(project)
        self.assertEqual(byte_compare(b"\x00\xff", b"\x00\x01", 2), 0)
        self.assertEqual(byte_compare(b"\x80", b"\x7f", 1), 1)
        self.assertEqual(byte_compare(b"\xff", b"\x00", 0), 0)
        self.assertEqual(len(cases()), 386)


if __name__ == "__main__":
    unittest.main()
