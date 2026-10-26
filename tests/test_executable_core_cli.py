"""Public core commands must preserve source identity and actual guard results."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from hepta.cli import main


SOURCE = '''module core_cli;
export "C" fn add(a:u32, b:u32)->u32 effects {} {return wrapping_add(a,b);}
export "C" fn checked(a:u8)->u8 effects {panic} {return a+1;}
'''


class ExecutableCoreCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-core-cli-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input.hepta"
        self.source.write_text(SOURCE, encoding="utf-8")
        self.core = self.root / "core.json"

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(list(map(str, args)))
        return code, json.loads(output.getvalue())

    def test_export_verify_and_interpret_exact_operations(self):
        code, exported = self.command("executable-core", self.source, "-o", self.core)
        self.assertEqual(code, 0, exported)
        self.assertEqual(exported["status"], "exported_not_native_qualified")
        self.assertFalse(exported["claims"]["native_execution_qualified"])
        code, verified = self.command("verify-executable-core", self.source, self.core)
        self.assertEqual(code, 0, verified)
        self.assertEqual(verified["core_sha256"], exported["core_sha256"])
        code, executed = self.command("run-executable-core", self.source, "--core", self.core,
                                     "--function", "add", "--arguments", "[4294967295,2]")
        self.assertEqual(code, 0, executed)
        self.assertEqual(executed["result"], 1)

    def test_guard_trap_is_a_failed_command_and_not_a_returned_value(self):
        code, result = self.command("run-executable-core", self.source,
                                    "--function", "checked", "--arguments", "[255]")
        self.assertEqual(code, 1, result)
        self.assertEqual(result["status"], "trapped")
        self.assertIsNone(result["result"])

    def test_existing_output_and_source_are_not_overwritten(self):
        self.core.write_text("retained original")
        code, report = self.command("executable-core", self.source, "-o", self.core)
        self.assertNotEqual(code, 0, report)
        self.assertEqual(self.core.read_text(), "retained original")
        code, report = self.command("executable-core", self.source, "-o", self.source)
        self.assertNotEqual(code, 0, report)
        self.assertEqual(self.source.read_text(), SOURCE)

    def test_stale_source_and_changed_core_are_rejected(self):
        self.assertEqual(self.command("executable-core", self.source, "-o", self.core)[0], 0)
        self.source.write_text(SOURCE.replace("wrapping_add(a,b)", "wrapping_sub(a,b)"))
        self.assertNotEqual(self.command("verify-executable-core", self.source, self.core)[0], 0)
        self.source.write_text(SOURCE)
        document = json.loads(self.core.read_text())
        document["functions"][0]["declared_effects"] = ["alloc"]
        self.core.write_text(json.dumps(document))
        self.assertNotEqual(self.command("verify-executable-core", self.source, self.core)[0], 0)

    def test_non_scalar_arguments_and_nonpositive_budget_reject(self):
        for options in (("--arguments", '[{"pointer":3}]'),
                        ("--arguments", "[1,2]", "--max-steps", "0")):
            with self.subTest(options=options):
                code, report = self.command("run-executable-core", self.source,
                                            "--function", "add", *options)
                self.assertNotEqual(code, 0, report)

    def test_reference_only_bool_bitwise_operation_is_rejected_at_admission(self):
        for operation in ("&", "|", "^"):
            with self.subTest(operation=operation):
                self.source.write_text('fn bits(a:bool,b:bool)->bool effects {} {return a '
                    + operation + ' b;} export "C" fn f(a:u8,b:u8)->u8 effects {} '
                    '{if bits(a==1,b==1){return 1;}return 0;}')
                code, report = self.command("executable-core", self.source)
                self.assertNotEqual(code, 0, report)
                self.assertIn("E_CORE_BACKEND_PROFILE", report["diagnostics"][0]["message"])

    def test_effectful_index_is_rejected_before_core_publication(self):
        self.source.write_text('fn index()->usize effects {alloc,block,panic} '
            '{let tmp=buffer(1);drop(move tmp);return 0;} '
            'export "C" fn f()->u8 effects {alloc,block,panic} '
            '{let data=buffer(1);let answer=data[index()];drop(move data);return answer;}')
        code, report = self.command("executable-core", self.source, "-o", self.core)
        self.assertNotEqual(code, 0, report)
        self.assertFalse(self.core.exists())
        self.assertIn("E_CORE_BACKEND_PROFILE", report["diagnostics"][0]["message"])

    def test_pure_borrow_in_index_is_rejected_before_rust_only_alias_gate(self):
        for index in ("index(mut data)", "len(data)-1"):
            with self.subTest(index=index):
                self.source.write_text('fn index(value:mut Buffer<u8>)->usize effects {} {return 0;} '
                    'export "C" fn f()->u8 effects {alloc,block,panic} '
                    '{let mut data=buffer(1);let answer=data[' + index + '];drop(move data);return answer;}')
                code, report = self.command("executable-core", self.source)
                self.assertNotEqual(code, 0, report)
                self.assertIn("E_CORE_INDEX_BORROW", report["diagnostics"][0]["message"])
        self.source.write_text('fn index(value:mut Buffer<u8>)->usize effects {} {return 0;} '
            'export "C" fn f()->u8 effects {alloc,block,panic} '
            '{let mut data=buffer(1);let offset=index(mut data);let answer=data[offset];drop(move data);return answer;}')
        code, report = self.command("run-executable-core", self.source, "--function", "f")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["result"], 0)

    def test_slice_reborrow_in_index_is_also_rejected(self):
        self.source.write_text('fn index(value:mut [u8])->usize effects {} {return 0;} '
            'fn get(value:mut [u8])->u8 effects {panic} {return value[index(mut value)];} '
            'export "C" fn f()->u8 effects {alloc,block,panic} '
            '{let mut data=buffer(1);let answer=get(mut data);drop(move data);return answer;}')
        code, report = self.command("executable-core", self.source)
        self.assertNotEqual(code, 0, report)
        self.assertIn("E_CORE_INDEX_BORROW", report["diagnostics"][0]["message"])


if __name__ == "__main__":
    unittest.main()
