"""Post-test captured C loops execute before testing, without new resource rules."""
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

from hepta.c_migrate import migrate_c_project
from hepta.c_project import verify_capture
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)
from hepta.hia_program_source import lower_c_project_views, lower_source
from tools.qualify_hia_filecheck import update
from tools.qualify_hia_legacy_queue import ENTRY, compile_database
from tools.qualify_hia_c_posttest import prepare_project


class CapturedDoWhileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-c-post-test-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.rustc = os.environ.get("RUSTC") or shutil.which("rustc")
        self.assertTrue(self.clang and self.rustc, "Actual Clang and Rust are required")
        self.sequence = 0

    def capture(self, source, *, contracts=None, native=False):
        self.sequence += 1
        work = self.work / str(self.sequence)
        work.mkdir()
        (work / "input.c").write_text(source, encoding="utf-8")
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": "input.c",
            "arguments": ["clang", "-std=c11", "-O2", "-c", "input.c"]}]))
        report = migrate_c_project(database, work / "translated", contracts=contracts,
            clang=self.clang, rustc=self.rustc, verify_native=native)
        return report, work, database

    def core(self, work, client=None):
        source = (work / "translated/source.hepta").read_text()
        client = client or ('export "C" fn probe(a:u32,n:u32)->u32 effects {panic,write}'
                            '{return c_probe(a,n);}')
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("No Rust fallback")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("No Rust fallback")):
            return lower_source(source + client)

    def differential(self, source, cases):
        report, work, _ = self.capture(source, native=True)
        self.assertTrue(report["ok"], report)
        verify_capture(report["build"])
        core = self.core(work)
        target = work / "hia.so"
        build_program_native(core, target, clang=self.clang)
        reference = work / "original.so"
        subprocess.run(["gcc", "-std=c11", "-O2", "-fPIC", "-shared",
                        str(work / "input.c"), "-o", str(reference)],
                       check=True, capture_output=True, timeout=30)
        libraries = [ctypes.CDLL(str(path)) for path in
                     (reference, work / "translated/libtranslated.so", target)]
        for library in libraries:
            library.probe.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            library.probe.restype = ctypes.c_uint32
        for a, n, expected in cases:
            with self.subTest(a=a, n=n):
                row = execute_program(core, "probe", [a, n], max_heap_bytes=0)
                self.assertEqual(row["result"], expected)
                self.assertEqual(row["resources"]["allocations"], 0)
                self.assertEqual([int(lib.probe(a, n)) for lib in libraries], [expected] * 3)
        return report, core

    def test_initial_false_condition_still_executes_one_body(self):
        source = ('unsigned probe(unsigned a,unsigned n){unsigned x=a;unsigned i=0;'
                  'do{x=x*3u+1u;i++;}while(i<n);return x;}')
        cases = []
        for a in (0, 1, 0x80000000, 0xffffffff):
            for n in (0, 1, 2, 7):
                result = a
                for _ in range(max(n, 1)):
                    result = (result * 3 + 1) & 0xffffffff
                cases.append((a, n, result))
        self.differential(source, cases)

    def test_body_assignment_is_available_to_first_condition_and_exit(self):
        source = ('unsigned probe(unsigned a,unsigned n){unsigned x;unsigned i=0;'
                  'do{if(a){x=a+i;}else{x=7u+i;}i++;}while(x<n && i<4u);return x;}')
        cases = [(0, 0, 7), (1, 0, 1), (0, 10, 10), (5, 8, 8), (0xffffffff, 0, 0xffffffff)]
        report, _ = self.differential(source, cases)
        self.assertEqual(report["functions"][0]["definite_assignment"]["deferred_scalar_initializers"], 1)

    def test_missing_first_iteration_assignment_and_initial_read_reject(self):
        sources = [
            'unsigned probe(unsigned a,unsigned n){unsigned x;do{if(a)x=7;}while(x<n);return x;}',
            'unsigned probe(unsigned a,unsigned n){unsigned x;do{x=x+1;}while(x<n);return x;}',
            'unsigned probe(unsigned a,unsigned n){unsigned x;do{while(a){x=7;a=0;}}while(n);return x;}',
            'unsigned probe(unsigned a,unsigned n){unsigned x;while(n){do{x=a;}while(0);n=0;}return x;}',
        ]
        for source in sources:
            with self.subTest(source=source):
                report, work, _ = self.capture(source)
                self.assertFalse(report["ok"], report)
                self.assertIn("E_C_UNINITIALIZED", [row["code"] for row in report["diagnostics"]])
                self.assertFalse((work / "translated").exists())

    def test_nested_scopes_and_jump_control_preserve_defined_values(self):
        bodies = (
            ("unsigned x=a;a=x+1;", (1, 3)),
            ("{unsigned a=1;a++;}", (0, 2)),
            ("do{a++;}while(a<n);", (3, 3)),
            ("for(unsigned x=0;x<n;x++){a++;}", (3, 5)),
            ("if(a)break;a++;", (1, 2)),
            ("if(a)continue;a++;", (1, 2)),
            ("if(a)return a;a++;", (1, 2)),
        )
        for body, expected in bodies:
            with self.subTest(body=body):
                source = f'unsigned probe(unsigned a,unsigned n){{do{{{body}}}while(0);return a;}}'
                report, work, _ = self.capture(source)
                self.assertTrue(report["ok"], report)
                core = self.core(work)
                for a, value in zip((0, 2), expected):
                    self.assertEqual(execute_program(core, "probe", [a, 3])["result"], value)

    def test_goto_and_switch_remain_refused(self):
        for body in ("goto end;", "switch(a){case 0:a++;}"):
            with self.subTest(body=body):
                source = f'unsigned probe(unsigned a,unsigned n){{do{{{body}}}while(a<n);end:return a;}}'
                report, work, _ = self.capture(source)
                self.assertFalse(report["ok"], report)
                self.assertIn("E_C_STATEMENT", {row["code"] for row in report["diagnostics"]}, report)
                self.assertFalse((work / "translated").exists())

    def test_mutating_condition_remains_refused(self):
        for source, code in (
            ('unsigned probe(unsigned a,unsigned n){do{a++;}while(n--);return a;}', "E_C_UNARY"),
        ):
            report, work, _ = self.capture(source)
            self.assertFalse(report["ok"], report)
            self.assertIn(code, [row["code"] for row in report["diagnostics"]])
            self.assertFalse((work / "translated").exists())

    def test_unbraced_body_uses_the_same_posttest_semantics(self):
        self.differential('unsigned probe(unsigned a,unsigned n){do a++;while(a<n);return a;}',
                          [(0, 0, 1), (0, 3, 3), (7, 3, 8)])

    def test_side_effectful_condition_call_is_not_silently_admitted(self):
        source = ('unsigned mutate(unsigned *data,unsigned n){data[0]=data[0]+1u;return data[0];}'
                  'unsigned probe(unsigned *data,unsigned n){do{data[0]=1u;}while(mutate(data,n));return data[0];}')
        contract = {"schema": "hepta.c-contracts.v1", "functions": {
            name: {"slices": {"data": {"access": "mut", "length": "n"}}}
            for name in ("mutate", "probe")}}
        report, work, _ = self.capture(source, contracts=contract)
        self.assertFalse(report["ok"], report)
        self.assertIn("E_C_EVALUATION_ORDER", [row["code"] for row in report["diagnostics"]])
        self.assertFalse((work / "translated").exists())

    def test_first_body_trap_is_not_hidden_by_false_condition(self):
        report, work, _ = self.capture(
            'unsigned probe(unsigned a,unsigned n){unsigned x=0;do{x=24u/a;}while(n);return x;}')
        self.assertTrue(report["ok"], report)
        core = self.core(work)
        self.assertEqual(execute_program(core, "probe", [4, 0])["result"], 6)
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(core, "probe", [0, 0])
        self.assertEqual(caught.exception.report["resources"]["live_owners"], 0)
        target = work / "trap.so"
        build_program_native(core, target, clang=self.clang)
        script = ('import ctypes,resource,sys;resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
                  'lib=ctypes.CDLL(sys.argv[1]);lib.probe.argtypes=[ctypes.c_uint32,ctypes.c_uint32];'
                  'lib.probe.restype=ctypes.c_uint32;lib.probe(0,0)')
        result = subprocess.run([sys.executable, "-c", script, str(target)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, -6, result.stderr)
        # The zero divisor is outside defined C behavior and is not run in C.

    def test_budget_stop_retains_actual_live_caller_resource_ledger(self):
        report, work, _ = self.capture(
            'unsigned probe(unsigned a,unsigned n){do{a++;}while(n!=0u);return a;}')
        self.assertTrue(report["ok"], report)
        core = self.core(work, 'export "C" fn probe(a:u32,n:u32)->u32 '
            'effects{alloc,block,panic,write}{let owner=buffer(8);'
            'let value=c_probe(a,n);drop(move owner);return value;}')
        returned = execute_program(core, "probe", [2, 0])
        self.assertEqual(returned["result"], 3)
        self.assertEqual(returned["resources"]["live_owners"], 0)
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(core, "probe", [2, 1], max_steps=160)
        self.assertEqual(caught.exception.code, "steps")
        ledger = caught.exception.report["resources"]
        self.assertEqual((ledger["allocations"], ledger["frees"], ledger["live_owners"], ledger["live_bytes"]),
                         (1, 0, 1, 8))

    def test_cursor_post_test_never_skips_invalid_empty_range(self):
        source = ('unsigned consume(const unsigned char *data,unsigned long n){'
                  'const unsigned char *cursor=data;unsigned long i=0;unsigned sum=0;'
                  'do{sum=sum+*cursor;cursor++;i++;}while(i<n);return sum;}')
        contracts = {"schema": "hepta.c-record-views.v1", "records": {}, "functions": {
            "consume": {"records": {}, "slices": {"data": {"access": "read", "length": "n"}}}}}
        report, _, database = self.capture(source, contracts=contracts)
        self.assertTrue(report["ok"], report)
        client = ('export "C" fn cursor_case(n:usize)->u32 effects{alloc,block,panic,write}{'
                  'let mut data=buffer(n);let mut i:usize=0;while i<n{data[i]=7;i=i+1;}'
                  'let result=c_consume(read data,0,n as u64);drop(move data);return result;}')
        migrated = lower_c_project_views(database, contracts=contracts, clang=self.clang,
                                         client_source=client)
        for count in (1, 2, 7):
            row = execute_program(migrated["program"], "cursor_case", [count])
            self.assertEqual(row["result"], count * 7)
            self.assertEqual(row["resources"]["live_owners"], 0)
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(migrated["program"], "cursor_case", [0])
        ledger = caught.exception.report["resources"]
        self.assertEqual((ledger["live_owners"], ledger["frees"]), (1, 0))


class CapturedDoWhileApplicationTests(unittest.TestCase):
    def test_existing_upstream_queue_and_compare_application_post_test_maintenance(self):
        clang = os.environ.get("CLANG") or shutil.which("clang")
        self.assertTrue(clang, "Actual Clang is required")
        with tempfile.TemporaryDirectory(prefix="hia-post-test-app-") as temporary:
            work = Path(temporary)
            project = work / "project"
            contracts, edit = prepare_project(project)
            # This TU is already authored integration code. Locked Ring-Buffer
            # and musl implementation files remain byte-for-byte unchanged.
            self.assertNotEqual(edit["before_sha256"], edit["after_sha256"])
            self.assertFalse(edit["upstream"])
            database = compile_database(project, work / "capture")
            with patch("hepta.backend.emit_rust", side_effect=AssertionError("No Rust fallback")), \
                 patch("hepta.backend.compile_rust", side_effect=AssertionError("No Rust fallback")):
                migrated = lower_c_project_views(database, contracts=contracts, clang=clang,
                    client_source=(project / "client.hepta").read_text(), retain_asts=True)
            self.assertEqual(migrated["translated_function_bodies"], 12)
            self.assertEqual(migrated["authored_client_function_bodies"], 1)
            self.assertTrue(migrated["declaration_inventory_complete"])
            self.assertFalse(migrated["claims"]["rust_backend_required"])
            self.assertFalse(migrated["claims"]["foreign_pointer_abi_admitted"])
            verify_capture(migrated["capture"])
            core = migrated["program"]
            native = work / "hia.so"
            build_program_native(core, native, clang=clang)
            original = work / "original.so"
            subprocess.run(["gcc", "-std=c11", "-O2", "-DNDEBUG", "-funsigned-char",
                "-fno-builtin", "-fPIC", "-shared", "-Icompare/platform",
                "ring/ringbuffer.c", "compare/memcmp.c", "compare/bcmp.c", "checksum.c", "client.c",
                "-o", str(original)], cwd=project, check=True, capture_output=True, timeout=40)
            libraries = [ctypes.CDLL(str(value)) for value in (original, native)]
            functions = []
            for library in libraries:
                fn = getattr(library, ENTRY)
                fn.argtypes = [ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32]
                fn.restype = ctypes.c_uint64
                functions.append(fn)
            for polynomial in (0xedb88320, 0x82f63b78):
                for count in (0, 1, 2, 7, 8, 9):
                    args = [count, 0xfedcba9876543210, 0xffffffff, polynomial]
                    expected = (1 << 32 if count > 8 else
                                update(args[2], args[1].to_bytes(8, "little")[:count], polynomial))
                    row = execute_program(core, ENTRY, args)
                    self.assertEqual(row["result"], expected)
                    self.assertEqual([int(fn(*args)) for fn in functions], [expected, expected])
                    ledger = row["resources"]
                    self.assertEqual(ledger["live_owners"], 0)
                    self.assertEqual(ledger["loans_started"], ledger["loans_ended"])
            for fail_at in (1, 2, 3):
                row = execute_program(core, ENTRY, [8, 123, 1, 0xedb88320], allocation_fail_at=fail_at)
                self.assertEqual(row["result"], 2 << 32)
                ledger = row["resources"]
                self.assertEqual((ledger["allocations"], ledger["frees"], ledger["live_owners"]),
                                 (fail_at - 1, fail_at - 1, 0))


if __name__ == "__main__":
    unittest.main()
