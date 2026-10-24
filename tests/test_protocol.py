"""Independent transaction, native-validation, and public-ABI regression tests.

The native cases invoke the real pinned rustc.  They assert externally observable
properties (unchanged bytes on rejection, changed program behavior, C layout),
not merely correspondence between two pieces of compiler implementation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import compile_rust, emit_header, sha256
from hepta.parser import parse
from hepta.pipeline import analyze, interface_hash
from hepta.protocol import apply_patch


ROOT = Path(__file__).resolve().parents[1]
RUSTC = ROOT.parent / "toolchains" / "rust-1.90.0" / "bin" / "rustc"
NATIVE_AVAILABLE = RUSTC.is_file() and os.access(RUSTC, os.X_OK)
BASE = "fn value() -> i64 effects {} { return 7; }\n"
ALIAS_HELPER = """fn pair(a: mut [u8], b: mut [u8]) -> Unit effects {panic, write} {
    a[0] = 1;
    b[0] = 2;
}
"""
ALIAS_BODY = "{ let mut x: [u8; 2] = [0, 0]; pair(mut x, mut x); }"


def request_for(source: str, symbol: str = "value", body: str = "{ return 8; }") -> dict:
    return {"schema": "hepta.patch.v1", "expected_source_sha256": sha256(source.encode("utf-8")),
            "expected_interface_sha256": interface_hash(parse(source)), "symbol": symbol,
            "replacement_body": body}


def codes(report: dict) -> set[str]:
    return {d["code"] for d in report.get("diagnostics", [])}


class TemporarySource(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hepta-protocol-test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.file = self.directory / "program.hepta"

    def write(self, source: str = BASE) -> dict:
        self.file.write_bytes(source.encode("utf-8"))
        return request_for(source)

    def apply(self, request: dict, *, commit: bool = False) -> dict:
        return apply_patch(self.file, request, apply=commit, rustc=str(RUSTC))

    def assert_no_write(self, before: bytes, report: dict):
        self.assertFalse(report["ok"], report)
        self.assertFalse(report["applied"], report)
        self.assertEqual(self.file.read_bytes(), before)


class TransactionPreconditions(TemporarySource):
    def test_stale_source_is_rejected_before_any_compiler_runs(self):
        request = self.write()
        changed = BASE.replace("return 7", "return 91")
        self.file.write_text(changed)
        with patch("hepta.protocol.analyze", side_effect=AssertionError("stale source reached validation")):
            report = self.apply(request, commit=True)
        self.assert_no_write(changed.encode(), report)
        self.assertIn("E_STALE_SOURCE", codes(report))

    def test_stale_contract_hash_is_rejected_even_with_current_source_hash(self):
        request = self.write()
        changed = BASE.replace("effects {}", "effects {panic}")
        self.file.write_text(changed)
        request["expected_source_sha256"] = sha256(changed.encode())
        with patch("hepta.protocol.analyze", side_effect=AssertionError("stale contract reached validation")):
            report = self.apply(request, commit=True)
        self.assert_no_write(changed.encode(), report)
        self.assertIn("E_STALE_INTERFACE", codes(report))

    def test_wrong_resource_contract_hash_is_not_accepted(self):
        source = "fn value() -> i64 effects {} resources { heap_allocations = 0; } { return 7; }"
        self.write(source)
        request = request_for(source)
        request["expected_interface_sha256"] = interface_hash(parse(BASE))
        report = self.apply(request, commit=True)
        self.assert_no_write(source.encode(), report)
        self.assertIn("E_STALE_INTERFACE", codes(report))

    def test_request_schema_does_not_accept_extra_fields_or_wrong_types(self):
        valid = self.write()
        examples = [None, [], "request", {}, dict(valid, schema="hepta.patch.v2"),
                    dict(valid, force="true"), dict(valid, symbol=5),
                    dict(valid, replacement_body=["{ return 8; }"])]
        for request in examples:
            with self.subTest(request=request):
                report = self.apply(request, commit=True)
                self.assert_no_write(BASE.encode(), report)
                self.assertIn("E_PATCH_SCHEMA", codes(report))

    def test_missing_external_and_ambiguous_symbols_are_rejected(self):
        sources = [BASE, 'extern "C" fn value() -> i64 effects {ffi};', BASE + BASE]
        for source in sources:
            with self.subTest(source=source):
                self.write(source)
                request = request_for(source)
                if source == BASE:
                    request["symbol"] = "missing"
                report = self.apply(request, commit=True)
                self.assert_no_write(source.encode(), report)
                self.assertIn("E_PATCH_SYMBOL", codes(report))


@unittest.skipUnless(NATIVE_AVAILABLE, "real pinned rustc required for native acceptance")
class NativeTransactions(TemporarySource):
    def test_dry_run_binds_evidence_to_candidate_and_preserves_original(self):
        request = self.write()
        report = self.apply(request)
        expected = BASE.replace("{ return 7; }", request["replacement_body"])
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["applied"])
        self.assertEqual(self.file.read_bytes(), BASE.encode())
        self.assertEqual(report["before_sha256"], sha256(BASE.encode()))
        self.assertEqual(report["after_sha256"], sha256(expected.encode()))
        self.assertEqual(report["validation"]["source_sha256"], report["after_sha256"])
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "rustc_checked")
        self.assertNotEqual(report["before_sha256"], report["after_sha256"])
        self.assertFalse(report["functional_equivalence_proved"])
        self.assertEqual(report["concurrency"], "cooperative_writers_only")
        self.assertFalse(report["external_effects_rolled_back"])

    def test_commit_preserves_unicode_crlf_siblings_and_permissions(self):
        source = "/* π 汉字 😀 */\r\n" + BASE.replace("\n", "\r\n") + "fn sibling() -> i64 effects {} { return 93; }\r\n"
        self.write(source)
        os.chmod(self.file, 0o640)
        request = request_for(source, body="{ /* π: } fn injected */ return 8; }")
        expected = source.replace("{ return 7; }", request["replacement_body"], 1)
        report = self.apply(request, commit=True)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["applied"])
        self.assertEqual(self.file.read_bytes(), expected.encode("utf-8"))
        self.assertEqual(report["after_sha256"], sha256(self.file.read_bytes()))
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.file.with_name(self.file.name + ".hepta-lock").exists())

    def test_replaying_applied_request_is_stale(self):
        request = self.write()
        first = self.apply(request, commit=True)
        self.assertTrue(first["ok"], first)
        current = self.file.read_bytes()
        second = self.apply(request, commit=True)
        self.assert_no_write(current, second)
        self.assertIn("E_STALE_SOURCE", codes(second))

    def test_declaration_injection_is_rejected(self):
        request = self.write()
        request["replacement_body"] = "{ return 8; } fn injected() -> i64 effects {} { return 99; }"
        report = self.apply(request, commit=True)
        self.assert_no_write(BASE.encode(), report)
        self.assertIn("E_CONTRACT_CHANGE", codes(report))

    def test_body_must_be_exactly_one_block_even_when_extra_text_is_a_comment(self):
        request = self.write()
        for body in (" { return 8; }", "{ return 8; } // trailing", "{ return 8; } /* comment */"):
            with self.subTest(body=body):
                request["replacement_body"] = body
                report = self.apply(request, commit=True)
                self.assert_no_write(BASE.encode(), report)
                self.assertIn("E_PATCH_SCOPE", codes(report))

    def test_new_effects_cannot_cross_frozen_contract(self):
        self.write()
        bodies = ["{ let b = buffer(1); release(move b); return 8; }",
                  "{ unsafe {} return 8; }",
                  "{ print_i64(8); return 8; }"]
        for body in bodies:
            with self.subTest(body=body):
                report = self.apply(request_for(BASE, body=body), commit=True)
                self.assert_no_write(BASE.encode(), report)
                self.assertIn("E_EFFECT", codes(report))

    def test_native_borrow_failure_cannot_be_replaced_by_frontend_success(self):
        source = ALIAS_HELPER + "fn value() -> Unit effects {panic, write} {}\n"
        self.write(source)
        request = request_for(source, body=ALIAS_BODY)
        report = self.apply(request, commit=True)
        self.assert_no_write(source.encode(), report)
        self.assertIn("E0499", codes(report))
        self.assertEqual(report["validation"]["checks"]["types_effects_resources"],
                         "passed_in_supported_subset")
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "rejected")

    def test_candidate_is_checked_even_if_old_body_was_valid(self):
        request = self.write()
        request["replacement_body"] = "{ return true; }"
        report = self.apply(request, commit=True)
        self.assert_no_write(BASE.encode(), report)

    def test_repair_can_fix_invalid_old_body_without_claiming_old_validation(self):
        source = BASE.replace("return 7", "return true")
        self.write(source)
        request = request_for(source, body="{ return 8; }")
        report = self.apply(request, commit=True)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["validation"]["source_sha256"], sha256(self.file.read_bytes()))
        self.assertNotEqual(report["validation"]["source_sha256"], sha256(source.encode()))

    def test_entire_candidate_unit_is_checked_including_untouched_functions(self):
        source = BASE + "fn other() -> i64 effects {} { return true; }"
        self.write(source)
        report = self.apply(request_for(source), commit=True)
        self.assert_no_write(source.encode(), report)

    def test_source_changed_during_validation_is_not_overwritten(self):
        request = self.write()
        concurrent = BASE.replace("return 7", "return 90")
        real_analyze = analyze

        def concurrent_editor(*args, **kwargs):
            result = real_analyze(*args, **kwargs)
            self.file.write_text(concurrent)
            return result

        with patch("hepta.protocol.analyze", side_effect=concurrent_editor):
            report = self.apply(request, commit=True)
        self.assert_no_write(concurrent.encode(), report)
        self.assertIn("E_STALE_SOURCE", codes(report))

    def test_existing_cooperative_lock_is_respected_and_not_removed(self):
        request = self.write()
        lock = self.file.with_name(self.file.name + ".hepta-lock")
        lock.write_text("other owner")
        report = self.apply(request, commit=True)
        self.assert_no_write(BASE.encode(), report)
        self.assertIn("E_PATCH_BUSY", codes(report))
        self.assertEqual(lock.read_text(), "other owner")

    def test_source_changed_while_staging_is_detected_at_final_recheck(self):
        request = self.write()
        concurrent = BASE.replace("return 7", "return 98")
        real_chmod = os.chmod

        def concurrent_editor(path, mode):
            self.file.write_text(concurrent)
            return real_chmod(path, mode)

        with patch("hepta.protocol.os.chmod", side_effect=concurrent_editor):
            report = self.apply(request, commit=True)
        self.assert_no_write(concurrent.encode(), report)
        self.assertIn("E_STALE_SOURCE", codes(report))
        self.assertEqual(list(self.directory.glob(".hepta-patch-*")), [])

    def test_same_interface_can_change_behavior_without_equivalence_claim(self):
        source = BASE + "fn main() -> Unit effects {io, alloc, block, panic} { print_i64(value()); }\n"
        self.write(source)

        def run_program(text: str, name: str) -> str:
            result = analyze(text, rustc=str(RUSTC), crate_type="bin")
            self.assertTrue(result.report["ok"], result.report)
            build = compile_rust(result.rust, rustc=str(RUSTC), crate_type="bin",
                                 output=self.directory / name)
            self.assertTrue(build["ok"], build)
            process = subprocess.run([build["artifact"]], capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            return process.stdout

        before = run_program(source, "before")
        report = self.apply(request_for(source, body="{ return 0; }"), commit=True)
        self.assertTrue(report["ok"], report)
        after = run_program(self.file.read_text(), "after")
        self.assertEqual((before, after), ("7\n", "0\n"))
        self.assertFalse(report["functional_equivalence_proved"])
        self.assertEqual(report["scope"], "single_compilation_unit_body_only")


class ValidationLabels(TemporarySource):
    def test_frontend_only_is_explicit_and_does_not_claim_borrow_validation(self):
        source = ALIAS_HELPER + "fn value() -> Unit effects {panic, write} " + ALIAS_BODY
        report = analyze(source, native=False).report
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "frontend_only")
        self.assertEqual(report["checks"]["rust_borrows_types"], "not_run")
        self.assertNotIn("backend", report)
        self.assertFalse(report["claims"]["whole_language_soundness_proved"])

    @unittest.skipUnless(Path("/bin/true").exists(), "requires Unix true binary")
    def test_success_exit_code_without_real_toolchain_is_not_native_evidence(self):
        report = analyze(BASE, rustc="/bin/true").report
        self.assertFalse(report["ok"], report)
        self.assertTrue(any(code.startswith("E_TOOLCHAIN") for code in codes(report)), report)

    def test_explicit_missing_toolchain_does_not_silently_fallback(self):
        report = analyze(BASE, rustc=str(self.directory / "missing-rustc")).report
        self.assertFalse(report["ok"], report)
        self.assertIn("E_TOOLCHAIN", codes(report))

    @unittest.skipUnless(NATIVE_AVAILABLE and sys.platform.startswith("linux"), "Unix real toolchain required")
    def test_real_version_output_but_missing_metadata_is_rejected(self):
        # This intentionally incomplete wrapper delegates -vV to real rustc but
        # does no compilation.  A zero exit code alone must not mint evidence.
        fake = self.directory / "no-output-rustc"
        fake.write_text("#!" + sys.executable + "\nimport subprocess, sys\n"
                        "if sys.argv[1:] == ['-vV']:\n"
                        "    raise SystemExit(subprocess.call([" + repr(str(RUSTC)) + ", '-vV']))\n"
                        "raise SystemExit(0)\n")
        fake.chmod(0o700)
        report = analyze(BASE, rustc=str(fake)).report
        self.assertFalse(report["ok"], report)
        self.assertNotEqual(report["checks"]["rust_borrows_types"], "rustc_checked")

    def test_c_reserved_identifiers_are_rejected_before_generating_broken_header(self):
        sources = [
            "repr(C) struct Bad { int: i32 }",
            "repr(C) struct Bad { switch: i32 }",
            'export "C" fn auto() -> i32 effects {} { return 0; }',
            'extern "C" fn consume(int: i32) -> Unit effects {ffi};',
            "repr(C) struct Bad { class: i32 }",
            'export "C" fn size_t() -> i32 effects {} { return 0; }',
            'export "C" fn int32_t() -> i32 effects {} { return 0; }',
            'repr(C) struct Thing { x:i32 } export "C" fn hepta_Thing() -> i32 effects {} { return 0; }',
        ]
        for source in sources:
            with self.subTest(source=source):
                report = analyze(source, native=False).report
                self.assertFalse(report["ok"], report)
                self.assertIn("E_C_IDENTIFIER", codes(report))

    @unittest.skipUnless(NATIVE_AVAILABLE, "real rustc required for CLI label check")
    def test_cli_frontend_only_reports_same_boundary(self):
        self.write(ALIAS_HELPER + "fn value() -> Unit effects {panic, write} " + ALIAS_BODY)
        process = subprocess.run([sys.executable, "-m", "hepta", "check", str(self.file),
                                  "--frontend-only", "--json"], cwd=ROOT,
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["status"], "frontend_only")
        self.assertEqual(report["checks"]["rust_borrows_types"], "not_run")


@unittest.skipUnless(NATIVE_AVAILABLE and sys.platform.startswith("linux") and shutil.which("gcc"),
                     "real rustc and C compiler required for layout observation")
class CHeaderLayout(TemporarySource):
    def test_rust_keyword_member_mangling_preserves_c_names_and_layout(self):
        source = '''module keywords;
repr(C) struct Record { match: u8, type: u64, loop: u16 }
export "C" fn roundtrip(value: Record) -> Record effects {} { return value; }
'''
        result = analyze(source, rustc=str(RUSTC), crate_type="staticlib")
        self.assertTrue(result.report["ok"], result.report)
        header = emit_header(result.program)
        (self.directory / "abi.h").write_text(header)
        # These are independent observations of actual Rust layout, appended by
        # the test harness only; there is no Hepta source escape for doing this.
        probes = '\n#[no_mangle] pub extern "C" fn probe_size() -> usize { core::mem::size_of::<H_Record>() }\n'
        probes += '#[no_mangle] pub extern "C" fn probe_align() -> usize { core::mem::align_of::<H_Record>() }\n'
        for name in ("match", "type", "loop"):
            probes += f'#[no_mangle] pub extern "C" fn probe_{name}() -> usize {{ core::mem::offset_of!(H_Record, h_{name}) }}\n'
        build = compile_rust(result.rust + probes, rustc=str(RUSTC), crate_type="staticlib",
                             output=self.directory / "abi.a")
        self.assertTrue(build["ok"], build)
        harness = self.directory / "main.c"
        harness.write_text('''#include "abi.h"
extern size_t probe_size(void);
extern size_t probe_align(void);
extern size_t probe_match(void);
extern size_t probe_type(void);
extern size_t probe_loop(void);
int main(void) {
    if (probe_size() != sizeof(hepta_Record)) return 1;
    if (probe_align() != _Alignof(hepta_Record)) return 2;
    if (probe_match() != offsetof(hepta_Record, match)) return 3;
    if (probe_type() != offsetof(hepta_Record, type)) return 4;
    if (probe_loop() != offsetof(hepta_Record, loop)) return 5;
    for (uint64_t i = 0; i < 100; ++i) {
        hepta_Record in = {.match = (uint8_t)i, .type = i * UINT64_C(194819274919), .loop = (uint16_t)(65535 - i)};
        hepta_Record out = roundtrip(in);
        if (in.match != out.match || in.type != out.type || in.loop != out.loop) return 6;
    }
    return 0;
}
''')
        binary = self.directory / "abi-test"
        compilation = subprocess.run([shutil.which("gcc"), "-std=c11", "-pedantic-errors", "-Wall",
                                      "-Wextra", "-Werror", str(harness), build["artifact"],
                                      "-ldl", "-lpthread", "-lm", "-lrt", "-lutil", "-o", str(binary)],
                                     capture_output=True, text=True, timeout=30)
        self.assertEqual(compilation.returncode, 0, compilation.stderr)
        execution = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(execution.returncode, 0, execution.stderr)


if __name__ == "__main__":
    unittest.main()
