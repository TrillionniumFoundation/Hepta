"""SHA builder admission and publication with recording-only compiler stages.

These controls call the real builder and shared cold-admission code. Small
temporary source/compiler files are custody fixtures, never executable images;
the stage receipts explicitly deny native execution. SHA algorithm correctness
and actual native execution remain the responsibility of the existing suites.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import build_hia_json_preflight as shared
from tools import build_hia_sha256 as builder
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE


ROOT = Path(__file__).resolve().parents[1]
CHECKS = {
    'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero',
    'no_ancestor_git_identity', 'no_bytecode_cache_created',
    'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
    'source_export_hashes_preserved',
}
CANDIDATES = ('sha256', 'sha256_stream')


class Sha256BuilderSourceBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-sha-builder-custody-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source_names = tuple('examples/hia_bootstrap/' + name + '.hepta'
                                  for name in CANDIDATES)
        self.bound_names = (*self.source_names, 'related-source.py', CONTRACT_PATH)
        self.originals = {}
        for name in self.bound_names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = (name + ': custody fixture; never executed\n').encode()
            path.write_bytes(raw)
            self.originals[path] = raw
        self.compiler = self.root / 'compiler.bin'
        self.originals[self.compiler] = b'recording compiler fixture; never executed'
        self.compiler.write_bytes(self.originals[self.compiler])
        self.cold = self.root / 'cold.json'
        self.expected = self.sources()
        self.report = {
            'schema': 'hepta.hia.selfhost-cold-replay.v1', 'profile': PROFILE,
            'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
            'checks': dict.fromkeys(CHECKS, True),
            'generation_sha256': [sha256(self.compiler.read_bytes()).hexdigest()] * 3,
            'source_manifest': self.expected,
        }
        self.calls = []
        self.mutation = None
        self.latest_image = None
        for target, attribute, kwargs in (
                (builder, 'ROOT', {'new': self.root}),
                (shared, 'ROOT', {'new': self.root})):
            context = patch.object(target, attribute, **kwargs)
            context.start()
            self.addCleanup(context.stop)
        context = patch('tools.hia_selfhost_contract.validate_contract', side_effect=self.contract)
        context.start()
        self.addCleanup(context.stop)
        context = patch('tools.qualify_hia_selfhost.compile_stage', side_effect=self.compile)
        context.start()
        self.addCleanup(context.stop)

    def sources(self):
        return {name: sha256((self.root / name).read_bytes()).hexdigest()
                for name in self.bound_names}

    def contract(self):
        return {'source_identity': {'files': {
            name: value for name, value in self.sources().items() if name != CONTRACT_PATH}}}

    def compile(self, output, label, compiler, source):
        self.calls.append((label, compiler.read_bytes(), source))
        image = output / (label + '.fixture.bin')
        raw = b'not an executable; SHA builder custody fixture: ' + label.encode()
        image.write_bytes(raw)
        self.latest_image = image
        if self.mutation:
            self.mutation()
        return image, {'custody_stub': True, 'native_execution': False,
                       'produced_sha256': sha256(raw).hexdigest(), 'produced_bytes': len(raw)}

    def reset_inputs(self):
        for path, raw in self.originals.items():
            path.write_bytes(raw)
        self.cold.write_text(json.dumps(self.report))
        self.calls.clear()
        self.mutation = None

    def test_invalid_cold_never_creates_output_or_touches_existing_files(self):
        mutations = (
            ('wrong-profile', lambda r: r.update(profile='wrong-profile')),
            ('missing-profile', lambda r: r.pop('profile')),
            ('missing-map', lambda r: r.pop('source_manifest')),
            ('empty-map', lambda r: r.update(source_manifest={})),
            ('missing-source', lambda r: r['source_manifest'].pop(self.source_names[0])),
            ('changed-source', lambda r: r['source_manifest'].update({self.source_names[1]: '0' * 64})),
            ('related-source', lambda r: r['source_manifest'].update({'related-source.py': '1' * 64})),
            ('contract', lambda r: r['source_manifest'].update({CONTRACT_PATH: '2' * 64})),
            ('extra-source', lambda r: r['source_manifest'].update({'extra-source.py': '3' * 64})),
            ('false-returncode', lambda r: r.update(returncode=False)),
            ('float-returncode', lambda r: r.update(returncode=0.0)),
            ('nonzero-returncode', lambda r: r.update(returncode=1)),
            ('wrong-compiler', lambda r: r.update(generation_sha256=['4' * 64] * 3)),
            ('short-generations', lambda r: r['generation_sha256'].pop()),
            ('false-check', lambda r: r['checks'].update(nested_full_qualification_pass=False)),
            ('integer-check', lambda r: r['checks'].update(nested_full_qualification_pass=1)),
            ('missing-check', lambda r: r['checks'].pop('owned_process_tree_cleanup_confirmed')),
            ('extra-check', lambda r: r['checks'].update(unregistered=True)),
        )
        existing = self.root / 'existing-output'
        existing.mkdir(mode=0o750)
        sentinel = existing / 'original.bin'
        sentinel.write_bytes(b'previous output\x00must remain unchanged')
        sentinel.chmod(0o440)
        before = existing.stat()
        for candidate in CANDIDATES:
            for label, mutate in mutations:
                report = deepcopy(self.report)
                mutate(report)
                self.cold.write_text(json.dumps(report))
                absent = self.root / (candidate + '-' + label)
                for output in (absent, existing):
                    with self.subTest(candidate=candidate, case=label, existing=output == existing):
                        with self.assertRaises(ValueError):
                            builder.build(output, self.compiler, self.cold, candidate=candidate)
                        self.assertFalse(absent.exists())
                        self.assertEqual(list(existing.iterdir()), [sentinel])
                        self.assertEqual(sentinel.read_bytes(), b'previous output\x00must remain unchanged')
                        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o440)
                        after = existing.stat()
                        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                                         (before.st_ino, before.st_mode, before.st_mtime_ns))
        self.assertEqual(self.calls, [])

    def test_admitted_map_must_include_selected_source_and_its_actual_bytes(self):
        real_admit = builder.admit_cold_build
        for candidate in CANDIDATES:
            selected = 'examples/hia_bootstrap/' + candidate + '.hepta'
            for mode in ('missing-selected', 'changed-after-admission'):
                self.reset_inputs()
                output = self.root / (candidate + '-' + mode)
                if mode == 'missing-selected':
                    self.bound_names = tuple(name for name in self.bound_names if name != selected)
                    altered = deepcopy(self.report)
                    altered['source_manifest'] = self.sources()
                    self.cold.write_text(json.dumps(altered))
                    context = patch.object(builder, 'admit_cold_build', wraps=real_admit)
                else:
                    def admit_and_change(compiler, cold, selected=selected):
                        admitted = real_admit(compiler, cold)
                        path = self.root / selected
                        path.write_bytes(path.read_bytes() + b'changed after admission')
                        return admitted
                    context = patch.object(builder, 'admit_cold_build', side_effect=admit_and_change)
                with self.subTest(candidate=candidate, mode=mode), context:
                    with self.assertRaisesRegex(ValueError, 'source differs from admitted cold source'):
                        builder.build(output, self.compiler, self.cold, candidate=candidate)
                    self.assertFalse(output.exists())
                    self.assertEqual(self.calls, [])
                self.bound_names = (*self.source_names, 'related-source.py', CONTRACT_PATH)

    def test_valid_full_binding_is_recorded_with_explicit_recording_stage_scope(self):
        for candidate in CANDIDATES:
            self.reset_inputs()
            output = self.root / ('valid-' + candidate)
            manifest_path = builder.build(output, self.compiler, self.cold, candidate=candidate)
            manifest = json.loads(manifest_path.read_bytes())
            report = json.loads((output / 'build.json').read_bytes())
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0], (candidate, self.compiler.read_bytes(),
                (self.root / ('examples/hia_bootstrap/' + candidate + '.hepta')).read_bytes()))
            self.assertEqual(report['profile'], PROFILE)
            self.assertEqual(report['source_manifest'], self.expected)
            self.assertEqual(report['cold_report_sha256'], sha256(self.cold.read_bytes()).hexdigest())
            self.assertEqual(report['manifest'], manifest)
            self.assertEqual(manifest['image_sha256'], sha256(self.latest_image.read_bytes()).hexdigest())
            self.assertEqual(manifest['schema'], 'hepta.hia.' + candidate.replace('_', '-') + '-native.v1')
            self.assertTrue(report['native_compile_receipt']['custody_stub'])
            self.assertFalse(report['native_compile_receipt']['native_execution'])
            for claim in ('production_activated', 'all_input_equivalence_proved', 'whole_stack_rewritten_in_hia'):
                self.assertFalse(report[claim])

    def test_source_contract_cold_and_compiler_changes_prevent_publication(self):
        for candidate in CANDIDATES:
            for index, target in enumerate([*(self.root / name for name in self.bound_names),
                                            self.cold, self.compiler]):
                self.reset_inputs()
                self.mutation = lambda target=target: target.write_bytes(target.read_bytes() + b'changed')
                output = self.root / (candidate + '-changed-' + str(index))
                with self.subTest(candidate=candidate, target=target.name):
                    with self.assertRaisesRegex(ValueError, 'build inputs changed'):
                        builder.build(output, self.compiler, self.cold, candidate=candidate)
                    self.assertEqual(len(self.calls), 1)
                    self.assertFalse((output / 'manifest.json').exists())
                    self.assertFalse((output / 'build.json').exists())

    def test_changed_image_during_source_readback_prevents_publication(self):
        real_sources = builder.current_sources
        for candidate in CANDIDATES:
            self.reset_inputs()
            output = self.root / (candidate + '-changed-image')
            def sources_and_change_image():
                values = real_sources()
                self.latest_image.write_bytes(b'replaced image, never executed')
                return values
            with self.subTest(candidate=candidate), patch.object(
                    builder, 'current_sources', side_effect=sources_and_change_image):
                with self.assertRaisesRegex(ValueError, 'build inputs changed'):
                    builder.build(output, self.compiler, self.cold, candidate=candidate)
                self.assertFalse((output / 'manifest.json').exists())
                self.assertFalse((output / 'build.json').exists())

    def test_direct_script_reaches_cold_admission_without_checkout_on_pythonpath(self):
        # The actual child imports the checkout from the script's own root.
        # Deliberately invalid cold input must fail at admission before source
        # validation, output creation or any native compiler invocation.
        for candidate in CANDIDATES:
            self.reset_inputs()
            report = deepcopy(self.report)
            report.update(profile='wrong-profile', source_manifest={})
            self.cold.write_text(json.dumps(report))
            output = self.root / (candidate + '-script-output')
            environment = {key: value for key, value in os.environ.items() if not key.startswith('PYTHON')}
            result = subprocess.run([sys.executable, '-B', '-E', '-s',
                str(ROOT / 'tools/build_hia_sha256.py'), '--candidate', candidate,
                '--compiler', str(self.compiler), '--cold-report', str(self.cold), '--output', str(output)],
                cwd=self.root, env=environment, capture_output=True, timeout=30)
            with self.subTest(candidate=candidate):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'a completed matching native cold qualification is required', result.stderr)
                self.assertNotIn(b'ModuleNotFoundError', result.stderr)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
