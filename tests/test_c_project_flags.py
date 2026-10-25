"""Compile options that affect preprocessing must survive project capture."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_backend import emit_c
from hepta.c_migrate import migrate_c_project
from hepta.c_project import _flags
from hepta.checker import check
from hepta.parser import parse


class ProjectFrontendFlagTests(unittest.TestCase):
    def migrate(self, root, source, options):
        (root / 'input.c').write_text(source)
        database = root / 'compile_commands.json'
        database.write_text(json.dumps([{
            'directory': str(root), 'file': 'input.c',
            'arguments': ['clang', '-std=c11', *options, '-c', 'input.c', '-o', 'input.o'],
        }]))
        report = migrate_c_project(database, root / 'out', clang=shutil.which('clang'))
        return report, root / 'out/source.hepta'

    def test_semantic_options_keep_original_order(self):
        options = ['-O2', '-DVALUE=1', '-O0', '-fpic', '-UOLD', '-fPIC', '-Os', '-Oz']
        forwarded, omitted = _flags(
            ['clang', '-std=c11', *options, '-g', '-Wall', '-c', 'input.c', '-o', 'input.o'],
            Path('/tmp/input.c'), Path('/tmp'))
        self.assertEqual(forwarded, ['-std=c11', *options])
        self.assertEqual([item['argument'] for item in omitted], ['-g', '-Wall', '-c', '-o'])

    def test_optimization_branch_and_order_match_native_original(self):
        source = '#ifdef __OPTIMIZE__\nint probe(void){return 2;}\n#else\nint probe(void){return 1;}\n#endif\n'
        for options, expected in [([], 1), (['-O0'], 1), (['-O1'], 2), (['-O2'], 2),
                                  (['-O3'], 2), (['-O2', '-O0'], 1), (['-O0', '-O2'], 2)]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                report, output = self.migrate(root, source, options)
                self.assertTrue(report['ok'], report)
                program = parse(output.read_text())
                generated = emit_c(program, check(program), crate_type='obj')
                observed = []
                for name, text, flags in [
                    ('original', source + 'int main(void){return probe();}', options),
                    ('generated', generated + '\nint main(void){return __hepta_cb_fn_c_probe();}', []),
                ]:
                    path, binary = root / (name + '.c'), root / name
                    path.write_text(text)
                    subprocess.run([shutil.which('clang'), '-std=c11', *flags, str(path), '-o', str(binary)],
                                   check=True, capture_output=True, timeout=30)
                    observed.append(subprocess.run([str(binary)], timeout=10).returncode)
                self.assertEqual(observed, [expected, expected])

    def test_size_optimization_macro_preserved(self):
        source = '#ifdef __OPTIMIZE_SIZE__\nint probe(void){return 3;}\n#else\nint probe(void){return 1;}\n#endif\n'
        for options, expected in [(['-Os'], 3), (['-Oz'], 3), (['-Os', '-O2'], 1)]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as td:
                report, output = self.migrate(Path(td), source, options)
                self.assertTrue(report['ok'], report)
                self.assertIn(f'return ({expected} as i32);', output.read_text())

    def test_pic_macro_and_order_preserved(self):
        source = 'int probe(void){return __PIC__;}\n'
        for options, expected in [(['-fpic'], 1), (['-fPIC'], 2),
                                  (['-fPIC', '-fpic'], 1), (['-fpic', '-fPIC'], 2)]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as td:
                report, output = self.migrate(Path(td), source, options)
                self.assertTrue(report['ok'], report)
                self.assertIn(f'return ({expected} as i32);', output.read_text())

    def test_optimized_only_unsupported_global_rejects_without_bundle(self):
        source = '#ifdef __OPTIMIZE__\nint hidden_global;\n#endif\nint probe(void){return 1;}\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report, _ = self.migrate(root, source, ['-O2'])
            self.assertFalse(report['ok'], report)
            self.assertIn('E_C_TOPLEVEL', [d['code'] for d in report['diagnostics']])
            self.assertTrue(any(d['name'] == 'hidden_global' and d['status'] == 'rejected'
                                for d in report['declarations']))
            self.assertFalse((root / 'out').exists())

    def test_optimized_header_dependency_and_capture_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'optimized.h').write_text('#define VALUE 7\n')
            (root / 'plain.h').write_text('#define VALUE 1\n')
            source = '#ifdef __OPTIMIZE__\n#include "optimized.h"\n#else\n#include "plain.h"\n#endif\nint probe(void){return VALUE;}\n'
            report, output = self.migrate(root, source, ['-O2'])
            self.assertTrue(report['ok'], report)
            config = report['build']['configurations'][0]
            self.assertEqual(config['frontend_arguments'], ['-std=c11', '-O2'])
            self.assertIn(str(root / 'optimized.h'), config['local_dependencies'])
            self.assertNotIn(str(root / 'plain.h'), config['all_dependencies'])
            self.assertIn('return (7 as i32);', output.read_text())
