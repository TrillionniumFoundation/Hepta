"""Actual Core owner VM/LLVM child differential without a source frontend.

The C library is explicitly a foreign subprocess transport control. Core native
compilation is tested independently by the preserved actual LLVM comparison.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_native_differential import (HIADifferentialRejected,
    compare_verified_hia_program, qualify_executable_hia_program)
from tests.test_hia_program import b,c,f,i,ret
CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def checked_core():
    # Direct typed Core: allocate/drop one owner, then return scalar 7.
    # No high-level AST or source-to-Core bridge participates.
    return verify_program({"schema":"hepta.hia.program.v6", "module":"core_owner_differential", "functions":[
        f("drop_case", [], ["i32"], ["alloc","trap"], [b("start", [], [
            c("size","usize",4), i("buffer.new", ["size"], [("owner","buffer")]),
            i("owner.drop",["owner"]),c("answer","i32",7)], ret("answer"))])]})

class ExistingV6CoreDifferentialTests(unittest.TestCase):

    def test_actual_owned_core_verification_and_vm_observe_drop(self):
        core = checked_core()
        result = execute_program(core, 'drop_case', [])
        self.assertEqual(result['result'], 7)
        self.assertEqual(result['resources']['allocations'], 1)
        self.assertEqual(result['resources']['frees'], 1)
        self.assertEqual(result['resources']['live_owners'], 0)

    @unittest.skipUnless(shutil.which('clang'), 'Clang needed for subprocess transport')
    def test_real_clang_transport_with_existing_verified_owner_vm(self):
        core = checked_core()
        with tempfile.TemporaryDirectory(prefix='hia-v6-transport-') as temp:
            source, library = (Path(temp) / 'bridge.c', Path(temp) / 'bridge.so')
            source.write_text('#include <stdint.h>\nint32_t drop_case(void) { return 7; }\n')
            subprocess.run(['clang', '-shared', '-fPIC', str(source), '-o', str(library)], check=True, timeout=30)
            report = compare_verified_hia_program(core, library, {'drop_case': [[]]})
            self.assertEqual(report['cases_executed'], 1)
            self.assertTrue(report['claims']['executable_hia_program_reverified'])
            self.assertFalse(report['claims']['native_compiled_from_program_verified'])
            self.assertFalse(report['claims']['checked_hepta_source_replayed'])

    def test_wrong_hia_argument_count_refused_before_native_load(self):
        core = checked_core()
        for vectors in ([[99]], [[1, 2]], [[], [5]]):
            with self.subTest(args=vectors):
                with patch('hepta.hia_native_differential._observe_native') as runner:
                    with self.assertRaisesRegex(HIADifferentialRejected, 'ABI argument arity'):
                        compare_verified_hia_program(core, 'not_a_library.so', {'drop_case': vectors})
                    runner.assert_not_called()

    def test_missing_native_export_cannot_count_as_full_qualification(self):
        core = checked_core()
        with patch('hepta.hia_native_differential._observe_native') as runner:
            with self.assertRaisesRegex(HIADifferentialRejected, 'export inventory'):
                compare_verified_hia_program(core, 'absent.so', {'wrong_export': [[]]})
            runner.assert_not_called()

    def test_core_abi_arity_rejects_before_native_child(self):
        from hepta.hia_native_differential import _require_exact_argument_arities
        core = checked_core()
        _require_exact_argument_arities({'drop_case': [[]]}, (('drop_case', 0),))
        for arguments in ([3], [3, 4], [True]):
            with self.subTest(arguments=arguments):
                with patch('hepta.hia_native_differential._observe_native') as child:
                    with self.assertRaisesRegex(HIADifferentialRejected, 'arity'):
                        compare_verified_hia_program(core, 'not-a-real-binary.so', {'drop_case': [arguments]})
                    child.assert_not_called()
        for signatures in ((('drop_case', True),), (('drop_case', 1.0),), (('drop_case', -1),), (('drop_case', 0), ('drop_case', 0))):
            with self.subTest(signatures=signatures):
                with self.assertRaisesRegex(HIADifferentialRejected, 'signature'):
                    _require_exact_argument_arities({'drop_case': [[]]}, signatures)

    @unittest.skipUnless(shutil.which(CLANG), 'pinned Clang20 required')
    def test_actual_executable_hia_llvm_matches_owner_vm(self):
        core = checked_core()
        report = qualify_executable_hia_program(core, {'drop_case': [[]]}, clang=CLANG)
        self.assertTrue(report['claims']['native_compiled_from_program_verified'])
        self.assertFalse(report['claims']['checked_hepta_source_replayed'])
        self.assertEqual(report['cases_executed'], 1)

if __name__ == "__main__":
    unittest.main()
