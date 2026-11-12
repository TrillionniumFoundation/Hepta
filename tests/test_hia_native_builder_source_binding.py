"""Custody controls for the shared native builder; no synthetic native PASS.

The compiler stage is a recording stub. These tests establish which evidence
is admitted before compilation/publication, not correctness of a native image.
Actual image execution remains in each candidate's native qualification suite.
"""
from copy import deepcopy
from hashlib import sha256
import importlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools import build_hia_json_preflight as builder
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE


CHECKS = {
    'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero',
    'no_ancestor_git_identity', 'no_bytecode_cache_created',
    'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
    'source_export_hashes_preserved',
}


class NativeBuilderSourceBindingTests(unittest.TestCase):
    APPLICATION_BUILDERS = (
        ('build_hia_agent_stdio', 'build_frontend'),
        ('build_hia_core_json_cli', 'build_frontend'),
        ('build_hia_elf_linker', 'build_application'),
        ('build_hia_agent_snapshot_json', 'build_kernel'),
        ('build_hia_core_workspace_json_cli', 'build_kernel'),
        ('build_hia_core_workspace_facts', 'build_kernel'),
        ('build_hia_core_workspace_cli', 'build_kernel'),
        ('build_hia_core_admission_cli', 'build_kernel'),
        ('build_hia_core_workspace_pipeline', 'build_candidate'),
    )
    SOURCE_STEMS = (
        'json_preflight', 'agent_stdio_dispatch', 'agent_stdio_packer',
        'core_json_frontend', 'core_json_cli_packer', 'elf_static_linker',
        'native_filter_packer', 'agent_snapshot_json', 'agent_snapshot_json_packer',
        'core_workspace_json', 'core_workspace_json_packer', 'core_workspace_facts',
        'core_workspace_facts_packer', 'core_workspace_materialize',
        'core_workspace_cli_packer', 'core_admission', 'core_admission_cli_packer',
        'core_workspace_pipeline_packer', 'selfhost',
    )

    def setUp(self):
        # Import before patching shared dependencies, so no application retains
        # a mocked imported alias after this test's cleanup restores globals.
        self.applications = tuple((importlib.import_module('tools.' + name), native_stage)
                                  for name, native_stage in self.APPLICATION_BUILDERS)
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-builder-custody-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source_name = 'examples/hia_bootstrap/json_preflight.hepta'
        self.source = self.root / self.source_name
        self.source.parent.mkdir(parents=True)
        self.source_names = tuple('examples/hia_bootstrap/' + name + '.hepta'
                                  for name in self.SOURCE_STEMS)
        for name in self.source_names:
            (self.root / name).write_bytes((name + ': custody fixture, never compiled as HIA\n').encode())
        self.related = self.root / 'related-source.py'
        self.related.write_bytes(b'original source bytes\n')
        self.contract_path = self.root / CONTRACT_PATH
        self.contract_path.parent.mkdir(parents=True)
        self.contract_path.write_bytes(b'fixture contract identity\n')
        self.compiler = self.root / 'compiler.bin'
        self.compiler.write_bytes(b'fixture compiler identity, never executed')
        self.cold_path = self.root / 'cold.json'
        self.expected = self.sources()
        self.report = {
            'schema': 'hepta.hia.selfhost-cold-replay.v1', 'profile': PROFILE,
            'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
            'checks': {name: True for name in CHECKS},
            'generation_sha256': [sha256(self.compiler.read_bytes()).hexdigest()] * 3,
            'source_manifest': self.expected,
        }
        self.calls = []
        self.mutation = None
        self.addCleanup(patch.stopall)
        patch.object(builder, 'ROOT', self.root).start()
        patch('tools.hia_selfhost_contract.validate_contract', side_effect=self.contract).start()
        patch('tools.qualify_hia_selfhost.compile_stage', side_effect=self.compile).start()

    def sources(self):
        return {name: sha256((self.root / name).read_bytes()).hexdigest()
                for name in (*self.source_names, 'related-source.py', CONTRACT_PATH)}

    def contract(self):
        files = self.sources()
        del files[CONTRACT_PATH]
        return {'source_identity': {'files': files}}

    def compile(self, output, protocol, compiler, source):
        self.calls.append((protocol, compiler.read_bytes(), source))
        image = output / 'fixture.bin'
        image.write_bytes(b'not an executable; custody test only')
        if self.mutation:
            self.mutation()
        return image, {'custody_stub': True, 'native_execution': False}

    def write_report(self, value):
        self.cold_path.write_text(json.dumps(value))

    def application_builders(self):
        result = []
        for module, native_stage in self.applications:
            original_root = module.ROOT
            for field in ('SOURCE', 'PACKER', 'PACKER_SOURCE', 'DISPATCH'):
                if hasattr(module, field):
                    path = getattr(module, field)
                    patch.object(module, field, self.root / path.relative_to(original_root)).start()
            patch.object(module, 'ROOT', self.root).start()
            if hasattr(module, 'validate_contract'):
                patch.object(module, 'validate_contract', side_effect=self.contract).start()
            result.append((module, native_stage))
        return result

    def test_same_compiler_does_not_authorize_stale_or_incomplete_sources(self):
        mutations = (
            lambda r: r.update(profile='stale-profile'),
            lambda r: r.pop('source_manifest'),
            lambda r: r['source_manifest'].pop(self.source_name),
            lambda r: r['source_manifest'].update({self.source_name: '0' * 64}),
            lambda r: r['source_manifest'].update({'related-source.py': '1' * 64}),
            lambda r: r['source_manifest'].update({CONTRACT_PATH: '2' * 64}),
            lambda r: r['source_manifest'].update({'unaccounted-source': '3' * 64}),
            lambda r: r.update(returncode=False),
            lambda r: r.update(returncode=0.0),
        )
        for index, mutation in enumerate(mutations):
            report = deepcopy(self.report)
            mutation(report)
            self.write_report(report)
            output = self.root / ('refused-' + str(index))
            with self.subTest(index=index), self.assertRaises(ValueError):
                builder.build(output, self.compiler, self.cold_path)
            self.assertFalse(output.exists())
        self.assertEqual(self.calls, [])

    def test_valid_binding_is_recorded_without_claiming_native_correctness(self):
        self.write_report(self.report)
        output = self.root / 'accepted-custody'
        manifest = builder.build(output, self.compiler, self.cold_path)
        self.assertTrue(manifest.is_file())
        self.assertEqual(len(self.calls), 1)
        receipt = json.loads((output / 'build.json').read_bytes())
        self.assertEqual(receipt['profile'], PROFILE)
        self.assertEqual(receipt['source_manifest'], self.expected)
        self.assertFalse(receipt['production_activated'])
        self.assertFalse(receipt['whole_stack_rewritten_in_hia'])
        self.assertTrue(receipt['native_compile_receipt']['custody_stub'])

    def test_source_contract_cold_or_compiler_change_prevents_manifest_publication(self):
        targets = (self.source, self.related, self.contract_path, self.cold_path, self.compiler)
        originals = {path: path.read_bytes() for path in targets if path != self.cold_path}
        for index, target in enumerate(targets):
            for path, raw in originals.items():
                path.write_bytes(raw)
            self.write_report(self.report)
            self.mutation = lambda target=target: target.write_bytes(target.read_bytes() + b' changed')
            output = self.root / ('changed-' + str(index))
            with self.subTest(target=target.name), self.assertRaises(ValueError):
                builder.build(output, self.compiler, self.cold_path)
            self.assertFalse((output / 'manifest.json').exists())
            self.assertFalse((output / 'build.json').exists())

    def test_application_cold_refusals_neither_create_parents_nor_touch_existing_output(self):
        mutations = (
            lambda r: r.clear(),
            lambda r: r.update(profile='stale-profile'),
            lambda r: r.update(status='COLD_SELFHOST_REPLAY_FAIL'),
            lambda r: r.update(returncode=False),
            lambda r: r.update(returncode=0.0),
            lambda r: r.update(generation_sha256=['0' * 64] * 3),
            lambda r: r['checks'].update(nested_full_qualification_pass=False),
            lambda r: r['checks'].pop('owned_process_tree_cleanup_confirmed'),
            lambda r: r.pop('source_manifest'),
            lambda r: r['source_manifest'].update({'related-source.py': '1' * 64}),
        )
        existing = self.root / 'existing-output'
        existing.mkdir(mode=0o750)
        sentinel = existing / 'original.bin'
        sentinel.write_bytes(b'previous build\x00must remain byte-identical')
        sentinel.chmod(0o440)
        original = sentinel.read_bytes()
        before = existing.stat()
        for module, _ in self.application_builders():
            for index, mutation in enumerate(mutations):
                report = deepcopy(self.report)
                mutation(report)
                self.write_report(report)
                absent = self.root / (module.__name__ + '-' + str(index))
                for output in (absent, existing):
                    with self.subTest(builder=module.__name__, mutation=index, existing=output == existing):
                        with self.assertRaises(ValueError):
                            module.build(output, self.compiler, self.cold_path)
                        self.assertFalse(absent.exists())
                        self.assertEqual(list(existing.iterdir()), [sentinel])
                        self.assertEqual(sentinel.read_bytes(), original)
                        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o440)
                        after = existing.stat()
                        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                                         (before.st_ino, before.st_mode, before.st_mtime_ns))
        self.assertEqual(self.calls, [])

    def test_current_binding_reaches_each_application_native_build_stage(self):
        class NativeStageReached(Exception):
            pass
        self.write_report(self.report)
        for module, native_stage in self.application_builders():
            output = self.root / module.__name__
            with self.subTest(builder=module.__name__), patch.object(
                    module, native_stage, side_effect=NativeStageReached) as stage:
                with self.assertRaises(NativeStageReached):
                    module.build(output, self.compiler, self.cold_path)
                self.assertEqual(stage.call_count, 1)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                self.assertEqual(list(output.iterdir()), [])
        # This observes real application admission and filesystem boundaries,
        # not compilation, an executable image, or a native qualification pass.
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
