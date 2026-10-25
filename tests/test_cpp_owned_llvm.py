"""Actual C++ -> migrated Hepta -> independent LLVM with retained native evidence."""
import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.qualify_cpp_owned_llvm import qualify_cpp_owned_llvm, validate_report

NATIVE = all(shutil.which(x) for x in ('clang', 'clang++', 'gcc', os.environ.get('RUSTC', 'rustc')))


@unittest.skipUnless(NATIVE, 'Clang 20, GCC and pinned Rust are required')
class CppOwnedLLVMTests(unittest.TestCase):
    def test_real_translator_output_executes_complete_shared_lifecycle_suite(self):
        with tempfile.TemporaryDirectory(prefix='hepta-cpp-owned-llvm-') as directory:
            report = qualify_cpp_owned_llvm(Path(directory) / 'run')
            self.assertTrue(report['ok'], report['diagnostics'])
            validate_report(report)
            self.assertEqual(report['observed'], {'ok': True, 'cases': 475,
                'observations_fnv64': '76b9c7dcdcefd304', 'allocations': 359,
                'frees': 359, 'refusals': 98, 'live': 0})
            self.assertEqual(report['foreign_cpp_link_inputs'], [])
            mutations = {
                'skip_source_replay': lambda r: r['build']['claims'].update(actual_source_replayed=False),
                'hidden_cpp_link': lambda r: r['foreign_cpp_link_inputs'].append('original.cpp'),
                'changed_command': lambda r: r['link_process'].update(argv=['/bin/true']),
                'changed_executable': lambda r: r['execution_process'].update(argv=['/bin/true']),
                'stale_input': lambda r: r.update(compiler_sha256='0' * 64),
                'changed_ir': lambda r: r['build']['source_binding'].update(llvm_ir_sha256='0' * 64),
                'changed_result': lambda r: r['observed'].update(refusals=0),
                'bool_zero': lambda r: r['observed'].update(live=False),
                'bool_process': lambda r: r['execution_process'].update(exit_code=False),
                'claim_fallback': lambda r: r['build']['claims'].update(fallback_used=True),
                'unknown_claim': lambda r: r.update(all_blockers_closed=True),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    candidate = copy.deepcopy(report)
                    mutate(candidate)
                    with self.assertRaises(ValueError):
                        validate_report(candidate)
            binary = Path(report['llvm_object']['path'])
            saved = binary.read_bytes()
            binary.write_bytes(saved + b'tamper')
            try:
                with self.assertRaisesRegex(ValueError, 'Retained native artifact'):
                    validate_report(report)
            finally:
                binary.write_bytes(saved)
            validate_report(report)

    def test_work_directory_and_dangling_link_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'new LLVM migration'):
                qualify_cpp_owned_llvm(root)
            link = root / 'link'
            link.symlink_to(root / 'absent', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'new LLVM migration'):
                qualify_cpp_owned_llvm(link)
            self.assertFalse((root / 'absent').exists())


if __name__ == '__main__':
    unittest.main()
