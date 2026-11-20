"""Complete new Source3/Native5; no replacement of any retained qualification."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import tempfile
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExecReleaseSourceTests(unittest.TestCase):
    def test_00_generated_policy_packer_and_actual_fixed_buffer_layout(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_artifact_publication import document
        from tools import generate_hia_exec_release as g
        observed = []
        for name, body in (('exec_release_policy', g.policy_source()),
                           ('exec_release_packer', g.packer_source())):
            path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
            text = path.read_text()
            self.assertEqual(text, render_assembly(document(body, name)))
            checked = assemble_program(text).as_dict()
            self.assertEqual(checked['schema'], 'hepta.hia.program.v8')
            self.assertEqual(checked['functions'][0]['name'], 'f0')
            observed.append({'name': name, 'bytes': len(text.encode()),
                'sha256': sha256(text.encode()).hexdigest(),
                'functions': len(checked['functions']),
                'max_function_parameters': max(len(fn['params']) for fn in checked['functions']),
                'max_block_parameters': max(len(block['params'])
                    for fn in checked['functions'] for block in fn['blocks'])})
        self.assertEqual(g.SOURCE_BYTES, g.WIRE_LIMIT + 4096)
        self.assertEqual(g.OUTPUT_OFFSET, g.SOURCE_BYTES)
        self.assertEqual(g.POLICY_OFFSET, g.OUTPUT_OFFSET + g.OUTPUT_BYTES)
        self.assertEqual(g.FRONTEND_OFFSET, g.POLICY_OFFSET + g.POLICY_BYTES)
        self.assertEqual(g.SHA_WORK_OFFSET, g.FRONTEND_OFFSET + g.FRONTEND_BYTES)
        self.assertEqual(g.MAPPING_BYTES, g.SHA_WORK_OFFSET + g.SHA_WORK_BYTES)
        self.assertEqual(g.SOURCE_BYTES % 4096, 0)
        self.assertEqual(g.PACKAGE % 4096, 0)
        self.assertEqual(g.PACKAGE_CAPACITY % 4096, 0)
        regions = ((0, 4096), (g.ASSEMBLY, g.LIMIT), (g.CODE, g.LIMIT),
            (g.SHA_INPUT, 65537), (g.SHA_OUTPUT, 32), (g.PACKAGE, g.PACKAGE_CAPACITY))
        for (a, n), (b, m) in zip(regions, regions[1:]):
            self.assertLessEqual(a + n, b)
        self.assertLessEqual(g.PACKAGE + g.PACKAGE_CAPACITY, g.OUTPUT_BYTES)
        self.graph_observations = observed

    def test_01_all_declared_policy_vm_arguments_receipts_and_early_error_paths(self):
        from tests.hia_exec_release_controls import protocol_witnesses
        rows = protocol_witnesses()
        self.assertEqual([row['id'] for row in rows], [
            'initial', 'arguments-after-signal', 'argc', 'mode-length', 'hash-length',
            'uppercase-hex', 'ABI-refusal', 'foreign-sequence', 'signal-error',
            'mmap-error-before-mapping', 'early-diagnostic-return'])

    def test_02_complete_packer_byte_oracle_and_explicit_authority_refusals(self):
        from tests.hia_exec_release_controls import complete_vm_packer
        from tools.build_hia_exec_release import build, _admission
        from tools.read_hia_exec_release import exact
        row = complete_vm_packer()
        self.assertGreater(row['complete_output_bytes'], 176)
        self.assertFalse(exact(True, 1))
        self.assertFalse(exact({'x': False}, {'x': 0}))
        self.assertFalse(exact([1, 2], [2, 1]))
        with tempfile.TemporaryDirectory(prefix='hia-exec-release-refusal-') as temporary:
            directory = Path(temporary)
            compiler, cold = directory / 'compiler', directory / 'cold.json'
            compiler.write_bytes(b'not executed')
            cold.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(directory / 'no-output', compiler, cold)
            self.assertFalse((directory / 'no-output').exists())
            with self.assertRaisesRegex(ValueError, 'disjoint'):
                _admission(b'x', b'{}', development=True, expected_compiler_sha256='0' * 64)
            with self.assertRaisesRegex(ValueError, 'byte pin'):
                _admission(b'x', None, development=True, expected_compiler_sha256='0' * 64)
            with self.assertRaisesRegex(ValueError, 'exact|explicit'):
                _admission(b'x', None, development=1, expected_compiler_sha256=None)


class ExecReleaseNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
            raise RuntimeError('this explicitly bounded native component requires Linux x86-64')
        if not os.environ.get('HEPTA_HIA_EXEC_RELEASE_COMPILER'):
            raise RuntimeError('explicit current compiler is required; no historical/default compiler selection')
        cls.compiler = Path(os.environ['HEPTA_HIA_EXEC_RELEASE_COMPILER']).resolve()
        cls.cold = os.environ.get('HEPTA_HIA_EXEC_RELEASE_COLD_REPORT')
        cls.dev = os.environ.get('HEPTA_HIA_EXEC_RELEASE_DEVELOPMENT') == '1'
        if cls.dev == bool(cls.cold):
            raise RuntimeError('choose exactly matching cold or explicit DEV, without fallback')
        cls.expected_compiler = os.environ.get('HEPTA_HIA_EXEC_RELEASE_COMPILER_SHA256')
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_EXEC_RELEASE_EVIDENCE')
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-exec-release-native-')
            cls.folder = Path(cls.temporary.name) / 'observation'
        else:
            cls.folder = Path(evidence).resolve()
        cls.attempted = False
        cls.record = None
        cls.readback = None
        cls.failure = None

    @classmethod
    def _ensure(cls):
        if cls.attempted:
            return
        cls.attempted = True
        try:
            from tools.qualify_hia_exec_release import qualify
            from tools.hia_selfhost_process_owner import run_owned
            import sys
            cls.record = qualify(cls.folder, cls.compiler,
                None if cls.cold is None else Path(cls.cold).resolve(),
                development=cls.dev, expected_compiler_sha256=cls.expected_compiler)
            report = cls.folder / 'report.json'
            raw = report.read_bytes()
            reader = ROOT / 'tools/read_hia_exec_release.py'
            reader_raw = reader.read_bytes()
            output = cls.folder / 'independent-readback'
            command = [sys.executable, '-I', '-S', '-B', str(reader), '--repo', str(ROOT),
                '--report', str(report), '--report-sha256', sha256(raw).hexdigest(),
                '--report-bytes', str(len(raw)), '--output', str(output)]
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(cls.folder), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
            if os.environ.get('LD_LIBRARY_PATH'):
                env['LD_LIBRARY_PATH'] = os.environ['LD_LIBRARY_PATH']
            cls.reader_owner = run_owned(command, cwd=str(cls.folder), env=env,
                stdout_path=cls.folder / 'reader.stdout.raw', stderr_path=cls.folder / 'reader.stderr.raw',
                receipt_path=cls.folder / 'reader.owner.json', qualification_seconds=120, cleanup_seconds=3)
            cls.readback = json.loads((output / 'READBACK.json').read_bytes())
            if report.read_bytes() != raw or reader.read_bytes() != reader_raw:
                raise AssertionError('producer/independent reader changed during actual readback')
        except Exception:
            cls.failure = traceback.format_exc()

    def group(self, group, expected_commands):
        type(self)._ensure()
        self.assertIsNone(self.failure, self.failure)
        self.assertIsNotNone(self.record)
        self.assertIsNotNone(self.readback)
        self.assertEqual(self.reader_owner['returncode'], 0, self.reader_owner)
        self.assertTrue(self.reader_owner['cleanup']['complete'])
        self.assertTrue(self.reader_owner['cleanup']['observed_echild'])
        self.assertEqual(self.readback['evidence_integrity'], 'PASS', self.readback)
        self.assertEqual(self.readback['groups'][group]['status'], 'PASS')
        self.assertEqual(self.readback['groups'][group]['commands'], expected_commands)
        self.assertFalse(self.readback['whole_native_delivery_qualified'])
        self.assertEqual(self.readback['development_only'], self.dev)

    def test_00_original_twice_before_native_package_install_verify_and_ET_EXEC(self):
        self.group('source-to-installed-exec', 18)
        self.assertEqual(self.readback['observed']['original_complete_records'], 2)
        self.assertEqual(self.readback['observed']['actual_owned_commands'], 44)

    def test_01_all_source_identity_syntax_profile_and_capacity_refusals(self):
        self.group('refusals', 11)

    def test_02_actual_kernel_input_output_and_mapping_errors_are_HIA_classified(self):
        self.group('kernel-errors', 3)

    def test_03_original_installer_no_replace_and_real_read_only_corruption_refusal(self):
        self.group('no-replace-and-corruption', 4)

    def test_04_copied_builder_installer_and_twelve_actual_installed_program_executions(self):
        self.group('copied-native-runtime', 6)
        self.assertEqual(self.readback['observed']['native_installed_program_executions'], 12)


if __name__ == '__main__':
    unittest.main()
