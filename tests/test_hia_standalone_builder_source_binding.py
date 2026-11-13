"""Standalone builder custody; recording stages are not native qualification.

These controls exercise the real build admission and publication boundaries with
small, isolated file fixtures. The compiler/packer stages never execute code;
the separate native suites retain responsibility for actual HIA execution.
"""
from copy import deepcopy
import ctypes
from hashlib import sha256
import importlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools import build_hia_json_preflight as shared
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE


CHECKS = {
    'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero',
    'no_ancestor_git_identity', 'no_bytecode_cache_created',
    'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
    'source_export_hashes_preserved',
}


class StandaloneBuilderSourceBindingTests(unittest.TestCase):
    BUILDERS = (
        ('sha256', 'build_hia_sha256', {'candidate': 'sha256'}, 'sha256'),
        ('sha256-stream', 'build_hia_sha256', {'candidate': 'sha256_stream'}, 'sha256_stream'),
        ('agent-identity', 'build_hia_agent_identity', {}, 'agent_identity'),
        ('agent-binary64', 'build_hia_agent_binary64', {}, 'agent_binary64'),
        ('agent-data-json', 'build_hia_agent_data_json', {}, 'agent_data_json'),
        ('agent-binary64-format', 'build_hia_agent_binary64_format', {}, 'agent_binary64_format'),
        ('artifact-publication', 'build_hia_artifact_publication', {}, 'artifact_publication_policy'),
    )
    APPLICATION_BUILDERS = (
        ('build_hia_agent_slice', 'native_filter_packer', 'hia-agent-slice'),
        ('build_hia_agent_stdio', 'agent_stdio_packer', 'hia-native'),
        ('build_hia_core_json_cli', 'core_json_cli_packer', 'hia-core-json'),
        ('build_hia_elf_linker', 'native_filter_packer', 'hia-elf-link'),
        ('build_hia_agent_snapshot_json', 'agent_snapshot_json_packer', 'hia-snapshot-json'),
        ('build_hia_core_workspace_json_cli', 'core_workspace_json_packer', 'hia-workspace-json'),
        ('build_hia_core_workspace_facts', 'core_workspace_facts_packer', 'hia-workspace-json'),
        ('build_hia_core_workspace_cli', 'core_workspace_cli_packer', 'hia-workspace-elf'),
        ('build_hia_core_admission_cli', 'core_admission_cli_packer', 'hia-verify-core'),
        ('build_hia_core_workspace_pipeline', 'core_workspace_pipeline_packer', 'hia-workspace-compile'),
        ('build_hia_core_patch_cli', 'core_patch_cli_packer', 'hia-patch-core'),
        ('build_hia_core_patch_result_cli', 'core_patch_result_cli_packer', 'hia-patch-result'),
        ('build_hia_release_install', 'release_install_packer', 'hia-release'),
        ('build_hia_release_selection', 'release_selection_packer', 'hia-select'),
    )

    def setUp(self):
        # Import before changing dependencies, so imported aliases never retain
        # mocks after cleanup restores the modules.
        self.builders = tuple((label, importlib.import_module('tools.' + module),
                               options, 'examples/hia_bootstrap/' + source + '.hepta')
                              for label, module, options, source in self.BUILDERS)
        self.publication = self.builders[-1][1]
        self.applications = tuple((importlib.import_module('tools.' + module),
                                   'examples/hia_bootstrap/' + source + '.hepta', target)
                                  for module, source, target in self.APPLICATION_BUILDERS)
        self.source_builder = importlib.import_module('tools.build_hia_source_build')
        self.invoked_packers = tuple(
            (module, target, 'filter-build.json' if target == 'hia-agent-slice' else 'build.json')
            for module, _, target in self.applications
            if not hasattr(module, 'NativeHiaJsonImage')) + (
                (self.publication, 'hia-artifact', 'build.json'),
                (self.source_builder, 'hia-source-build', 'build.json'),
            )
        admission_wrapper = importlib.import_module('tools.build_hia_core_admission')
        temporary = tempfile.TemporaryDirectory(prefix='hia-standalone-custody-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        sources = ({row[3] for row in self.builders} | set(self.publication.SOURCES)
                   | {'related-source.py', CONTRACT_PATH})
        all_modules = ({row[1] for row in self.builders} | {row[0] for row in self.applications}
                       | {admission_wrapper, self.source_builder})
        for module in all_modules:
            sources.update(getattr(module, 'SOURCES', ()))
            for field in ('SOURCE', 'PACKER', 'PACKER_SOURCE', 'DISPATCH', 'ADMISSION'):
                value = getattr(module, field, None)
                if isinstance(value, Path):
                    sources.add(value.relative_to(module.ROOT).as_posix())
        sources.update('examples/hia_bootstrap/' + name + '.hepta' for name in
                       ('agent_slice', 'core_json_frontend', 'agent_snapshot_json',
                        'core_workspace_json', 'elf_static_linker', 'native_filter_packer'))
        self.source_names = tuple(sorted(sources))
        for name in self.source_names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + ': custody fixture, never executed\n').encode())
        self.compiler = self.root / 'compiler.bin'
        self.compiler.write_bytes(b'compiler custody fixture, never executed')
        self.cold = self.root / 'cold.json'
        self.omitted_source = None
        self.expected = self.sources()
        self.report = {
            'schema': 'hepta.hia.selfhost-cold-replay.v1', 'profile': PROFILE,
            'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
            'checks': dict.fromkeys(CHECKS, True),
            'generation_sha256': [sha256(self.compiler.read_bytes()).hexdigest()] * 3,
            'source_manifest': self.expected,
            'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
        }
        self.calls = []
        self.mutation = None
        self.pack_mutation = None
        self.pack_receipt_mutation = None
        self.pack_output_mutation = None
        self.inspection_mutation = None
        self.latest_image = None
        self.addCleanup(patch.stopall)
        patch.object(shared, 'ROOT', self.root).start()
        patch('tools.hia_selfhost_contract.validate_contract', side_effect=self.contract).start()
        patch('tools.qualify_hia_selfhost.compile_stage', side_effect=self.compile).start()
        patch('tools.qualify_hia_selfhost.invoke', side_effect=self.pack).start()
        patch('tools.qualify_hia_selfhost_cli.inspect_executable', side_effect=self.inspect).start()
        for module in all_modules:
            for field in ('SOURCE', 'PACKER', 'PACKER_SOURCE', 'DISPATCH', 'ADMISSION'):
                value = getattr(module, field, None)
                if isinstance(value, Path):
                    patch.object(module, field, self.root / value.relative_to(module.ROOT)).start()
            patch.object(module, 'ROOT', self.root).start()
            if hasattr(module, 'validate_contract'):
                patch.object(module, 'validate_contract', side_effect=self.contract).start()
            if hasattr(module, 'compile_stage'):
                patch.object(module, 'compile_stage', side_effect=self.compile).start()
            if hasattr(module, 'invoke'):
                patch.object(module, 'invoke', side_effect=self.pack).start()
            if hasattr(module, 'inspect_executable'):
                patch.object(module, 'inspect_executable', side_effect=self.inspect).start()
            if hasattr(module, 'NativeHiaJsonImage'):
                patch.object(module, 'NativeHiaJsonImage', side_effect=self.native_packer).start()

    def sources(self):
        return {name: sha256((self.root / name).read_bytes()).hexdigest()
                for name in self.source_names if name != self.omitted_source}

    def contract(self):
        files = self.sources()
        del files[CONTRACT_PATH]
        return {'source_identity': {'files': files}}

    def compile(self, output, label, compiler, source):
        self.calls.append((label, compiler.read_bytes(), source))
        image = output / (label + '.fixture.bin')
        raw = b'not an executable; custody fixture: ' + label.encode()
        image.write_bytes(raw)
        self.latest_image = image
        if self.mutation:
            self.mutation()
        return image, {'custody_stub': True, 'native_execution': False,
                       'produced_sha256': sha256(raw).hexdigest(), 'produced_bytes': len(raw),
                       'status': 'returned', 'abi_status': 0, 'core_u32': len(raw),
                       'artifact_sha256': sha256(compiler.read_bytes()).hexdigest(),
                       'image_sha256': sha256(compiler.read_bytes()).hexdigest(),
                       'input_sha256': sha256(source).hexdigest(),
                       'source_sha256': sha256(source).hexdigest(), 'input_bytes': len(source),
                       'source_unchanged': True, 'forbidden_compiler_modules_loaded': []}

    def pack(self, *args):
        # Bind the actual fixture image and input at the recording boundary.
        # This nonexecuting stub never constitutes native qualification.
        raw = b'not an ELF executable; custody fixture only'
        receipt = {'status': 'returned', 'custody_stub': True,
                   'native_execution': False, 'core_u32': len(raw),
                   'result_u64': len(raw), 'format': 'flat-x86-64',
                   'return_encoding': 'zero-extended-u32',
                   'output_sha256': sha256(raw).hexdigest(),
                   'forbidden_compiler_modules_loaded': []}
        if len(args) >= 4:
            _, _, image, source = args[:4]
            receipt.update(abi_status=0,
                           artifact_sha256=sha256(image.read_bytes()).hexdigest(),
                           image_sha256=sha256(image.read_bytes()).hexdigest(),
                           input_sha256=sha256(source).hexdigest(), input_bytes=len(source),
                           source_sha256=sha256(source).hexdigest(),
                           source_unchanged=True)
        if self.pack_mutation:
            self.pack_mutation()
        if self.pack_receipt_mutation:
            self.pack_receipt_mutation(receipt)
        if self.pack_output_mutation:
            raw = self.pack_output_mutation(raw)
        return receipt, raw

    def inspect(self, raw):
        if self.inspection_mutation:
            self.inspection_mutation()
        return {'custody_stub': True, 'native_execution': False}

    def native_packer(self, *args):
        owner = self

        class Packer:
            def _entry(self, source, source_size, output, capacity, scratch, scratch_size):
                report, raw = owner.pack()
                assert len(raw) <= capacity
                ctypes.memmove(output, raw, len(raw))
                return report['core_u32']

        return Packer()

    def write_report(self, value=None):
        self.cold.write_text(json.dumps(self.report if value is None else value))

    def test_invalid_cold_is_refused_before_creating_or_touching_output(self):
        mutations = (
            ('empty', lambda r: r.clear()),
            ('profile', lambda r: r.update(profile='other-source-profile')),
            ('missing-profile', lambda r: r.pop('profile')),
            ('status', lambda r: r.update(status='COLD_SELFHOST_REPLAY_FAIL')),
            ('false-returncode', lambda r: r.update(returncode=False)),
            ('float-returncode', lambda r: r.update(returncode=0.0)),
            ('nonzero-returncode', lambda r: r.update(returncode=1)),
            ('compiler', lambda r: r.update(generation_sha256=['0' * 64] * 3)),
            ('check', lambda r: r['checks'].update(nested_full_qualification_pass=False)),
            ('integer-check', lambda r: r['checks'].update(nested_full_qualification_pass=1)),
            ('missing-check', lambda r: r['checks'].pop('owned_process_tree_cleanup_confirmed')),
            ('extra-check', lambda r: r['checks'].update(unaccounted_check=True)),
            ('missing-map', lambda r: r.pop('source_manifest')),
            ('related-source', lambda r: r['source_manifest'].update({'related-source.py': '1' * 64})),
            ('contract', lambda r: r['source_manifest'].update({CONTRACT_PATH: '2' * 64})),
            ('extra-source', lambda r: r['source_manifest'].update({'unaccounted-source.py': '3' * 64})),
        )
        existing = self.root / 'existing-output'
        existing.mkdir(mode=0o750)
        sentinel = existing / 'original.bin'
        sentinel.write_bytes(b'original output\x00must remain untouched')
        sentinel.chmod(0o440)
        before = existing.stat()
        original = sentinel.read_bytes()
        for label, module, options, source_name in self.builders:
            extra = (('selected-source', lambda r, name=source_name:
                      r['source_manifest'].update({name: '4' * 64})),)
            for name, mutation in (*mutations, *extra):
                report = deepcopy(self.report)
                mutation(report)
                self.write_report(report)
                absent = self.root / (label + '-' + name)
                for output in (absent, existing):
                    with self.subTest(builder=label, mutation=name, existing=output == existing):
                        with self.assertRaises(ValueError):
                            module.build(output, self.compiler, self.cold, **options)
                        self.assertFalse(absent.exists())
                        self.assertEqual(list(existing.iterdir()), [sentinel])
                        self.assertEqual(sentinel.read_bytes(), original)
                        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o440)
                        after = existing.stat()
                        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                                         (before.st_ino, before.st_mode, before.st_mtime_ns))
        self.assertEqual(self.calls, [])

    def test_current_cold_records_complete_identity_without_native_pass_claim(self):
        self.write_report()
        for label, module, options, _ in self.builders:
            with self.subTest(builder=label):
                output = self.root / ('accepted-' + label)
                result = module.build(output, self.compiler, self.cold, **options)
                self.assertTrue(result.is_file())
                receipt = json.loads((output / 'build.json').read_bytes())
                self.assertEqual(receipt['source_manifest'], self.expected)
                self.assertEqual(receipt['cold_report_sha256'], sha256(self.cold.read_bytes()).hexdigest())
                if module is self.publication:
                    self.assertTrue(all(r['custody_stub'] for r in receipt['compile_receipts'].values()))
                    self.assertFalse(receipt['whole_native_delivery_qualified'])
                else:
                    self.assertTrue(receipt['native_compile_receipt']['custody_stub'])
                    self.assertFalse(receipt.get('whole_native_delivery_qualified',
                                                receipt.get('whole_stack_rewritten_in_hia')))
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(len(self.calls), 9)

    def test_changed_inputs_or_related_source_prevent_publication(self):
        original = {self.root / name: (self.root / name).read_bytes() for name in self.source_names}
        original[self.compiler] = self.compiler.read_bytes()
        for label, module, options, source_name in self.builders:
            targets = (self.root / source_name, self.root / 'related-source.py',
                       self.root / CONTRACT_PATH, self.compiler, self.cold)
            for index, target in enumerate(targets):
                with self.subTest(builder=label, changed=target.name):
                    for path, raw in original.items():
                        path.write_bytes(raw)
                    self.write_report()
                    self.mutation = lambda target=target: target.write_bytes(target.read_bytes() + b' changed')
                    output = self.root / (label + '-changed-' + str(index))
                    with self.assertRaises(ValueError):
                        module.build(output, self.compiler, self.cold, **options)
                    self.assertFalse((output / 'manifest.json').exists())
                    self.assertFalse((output / 'build.json').exists())
                    self.assertFalse((output / 'hia-artifact').exists())

    def test_selected_source_must_belong_to_admitted_full_contract(self):
        for label, module, options, source_name in self.builders:
            with self.subTest(builder=label):
                self.omitted_source = source_name
                report = deepcopy(self.report)
                del report['source_manifest'][source_name]
                self.write_report(report)
                output = self.root / (label + '-missing-member')
                with self.assertRaises(ValueError):
                    module.build(output, self.compiler, self.cold, **options)
                self.assertFalse(output.exists())
        self.assertEqual(self.calls, [])

    def test_numeric_builders_retain_their_cold_deadline_checks(self):
        for label, module, options, _ in self.builders[3:6]:
            for field, value in (('qualification_wall_limit_seconds', 181),
                                 ('cleanup_wall_limit_seconds', 4)):
                with self.subTest(builder=label, field=field):
                    report = deepcopy(self.report)
                    report[field] = value
                    self.write_report(report)
                    output = self.root / (label + '-' + field)
                    with self.assertRaises(ValueError):
                        module.build(output, self.compiler, self.cold, **options)
                    self.assertFalse(output.exists())
        self.assertEqual(self.calls, [])

    def test_publisher_rechecks_auxiliary_sources_and_compiled_components(self):
        self.write_report()
        auxiliary = self.root / self.publication.SOURCES[-1]
        original = auxiliary.read_bytes()
        for index, which in enumerate(('auxiliary', 'compiled-policy')):
            with self.subTest(changed=which):
                auxiliary.write_bytes(original)
                output = self.root / ('publication-changed-' + str(index))
                target = auxiliary if which == 'auxiliary' else output / 'policy.fixture.bin'
                self.pack_mutation = lambda target=target: target.write_bytes(target.read_bytes() + b' changed')
                with self.assertRaises(ValueError):
                    self.publication.build(output, self.compiler, self.cold)
                self.assertFalse((output / 'hia-artifact').exists())
                self.assertFalse((output / 'build.json').exists())

    def test_outer_builders_recheck_packer_images_before_executable_publication(self):
        self.write_report()
        self.inspection_mutation = lambda: self.latest_image.write_bytes(
            self.latest_image.read_bytes() + b' changed after pack execution')
        for module, _, target in self.applications:
            with self.subTest(builder=module.__name__):
                output = self.root / (module.__name__ + '-changed-packer')
                with self.assertRaises(ValueError):
                    module.build(output, self.compiler, self.cold)
                self.assertFalse((output / target).exists())

    def test_outer_builders_recheck_complete_source_after_pack_execution(self):
        related = self.root / 'related-source.py'
        original = related.read_bytes()
        self.inspection_mutation = lambda: related.write_bytes(original + b' changed after pack execution')
        for module, _, target in self.applications:
            with self.subTest(builder=module.__name__):
                related.write_bytes(original)
                self.write_report()
                output = self.root / (module.__name__ + '-changed-related')
                with self.assertRaises(ValueError):
                    module.build(output, self.compiler, self.cold)
                self.assertFalse((output / target).exists())

    def test_outer_builders_refuse_unaccounted_packer_before_output_creation(self):
        for module, source, _ in self.applications:
            with self.subTest(builder=module.__name__):
                self.omitted_source = source
                report = deepcopy(self.report)
                del report['source_manifest'][source]
                self.write_report(report)
                output = self.root / (module.__name__ + '-missing-packer')
                with self.assertRaises(ValueError):
                    module.build(output, self.compiler, self.cold)
                self.assertFalse(output.exists())

    def test_outer_builders_recheck_consumed_nested_manifests(self):
        self.write_report()
        for module, _, target in self.applications[:10]:
            with self.subTest(builder=module.__name__):
                output = self.root / (module.__name__ + '-changed-manifest')

                def change_manifest():
                    manifests = sorted(output.rglob('manifest.json'))
                    self.assertTrue(manifests)
                    manifest = manifests[0]
                    manifest.write_bytes(manifest.read_bytes() + b' changed after pack execution')

                self.inspection_mutation = change_manifest
                with self.assertRaises(ValueError):
                    module.build(output, self.compiler, self.cold)
                self.assertFalse((output / target).exists())

    def test_outer_builders_current_inputs_reach_final_publication(self):
        self.write_report()
        for module, _, target in self.applications:
            with self.subTest(builder=module.__name__):
                output = self.root / (module.__name__ + '-current-inputs')
                module.build(output, self.compiler, self.cold)
                self.assertTrue((output / target).is_file())
                receipt_name = 'filter-build.json' if module.__name__.endswith('agent_slice') else 'build.json'
                receipt = json.loads((output / receipt_name).read_bytes())
                self.assertFalse(receipt.get('whole_native_delivery_qualified',
                                            receipt.get('native_only_delivery_qualified',
                                                        receipt.get('whole_stack_rewritten_in_hia', False))))

    def test_native_packers_refuse_failed_or_unbound_native_receipts(self):
        self.write_report()
        changes = [
            ('actual-nonzero-ABI-return', lambda r: r.update(
                abi_status=1, result_u64=(1 << 32) | r['core_u32'])),
            ('missing-ABI', lambda r: r.pop('abi_status')),
            ('missing-input-identity', lambda r: r.pop('input_sha256')),
        ]
        for field, value in (
                ('status', 'child_failed'), ('abi_status', False), ('abi_status', 0.0),
                ('result_u64', True), ('result_u64', -1),
                ('result_u64', 0x100000000), ('core_u32', True),
                ('core_u32', 0), ('core_u32', (1 << 20) + 1),
                ('format', 'seed-shared'), ('return_encoding', 'packed-ABI-status-and-u32'),
                ('artifact_sha256', '0' * 64), ('image_sha256', '0' * 64),
                ('input_sha256', '0' * 64), ('source_sha256', '0' * 64),
                ('input_bytes', False), ('input_bytes', 0),
                ('source_unchanged', 1), ('source_unchanged', False),
                ('output_sha256', '0' * 64), ('forbidden_compiler_modules_loaded', None),
                ('forbidden_compiler_modules_loaded', ['hepta.hia_program_native'])):
            changes.append((field + '-' + str(len(changes)),
                            lambda r, k=field, v=value: r.update({k: v})))
        for module, target, receipt_name in self.invoked_packers:
            for label, mutation in changes:
                with self.subTest(builder=module.__name__, receipt=label):
                    self.pack_receipt_mutation = mutation
                    output = self.root / (module.__name__ + '-bad-pack-' + label)
                    with self.assertRaises(ValueError):
                        module.build(output, self.compiler, self.cold)
                    self.assertFalse((output / target).exists())
                    self.assertFalse((output / receipt_name).exists())

    def test_native_packers_bind_complete_captured_output_bytes(self):
        self.write_report()
        changes = (
            ('changed', lambda raw: b'X' + raw[1:]),
            ('truncated', lambda raw: raw[:-1]),
            ('extended', lambda raw: raw + b'X'),
            ('mutable', bytearray),
        )
        for module, target, receipt_name in self.invoked_packers:
            for label, mutation in changes:
                with self.subTest(builder=module.__name__, output=label):
                    self.pack_output_mutation = mutation
                    output = self.root / (module.__name__ + '-pack-output-' + label)
                    with self.assertRaises(ValueError):
                        module.build(output, self.compiler, self.cold)
                    self.assertFalse((output / target).exists())
                    self.assertFalse((output / receipt_name).exists())

    def test_outer_builders_refuse_stale_captured_source_before_creating_output(self):
        self.write_report()
        ordinary_read = Path.read_bytes
        for module, source, _ in self.applications:
            with self.subTest(builder=module.__name__):
                selected = self.root / source
                captured = False

                def read(path):
                    nonlocal captured
                    raw = ordinary_read(path)
                    if path == selected and not captured:
                        # Model an old source snapshot captured just before
                        # admission observes the current contract-bound file.
                        captured = True
                        return raw + b' stale captured source'
                    return raw

                output = self.root / (module.__name__ + '-stale-captured-source')
                with patch.object(Path, 'read_bytes', read), self.assertRaises(ValueError):
                    module.build(output, self.compiler, self.cold)
                self.assertTrue(captured)
                self.assertFalse(output.exists())

    def test_shared_kernel_rechecks_image_after_complete_source_readback(self):
        self.write_report()
        reads = 0

        def source_readback():
            nonlocal reads
            reads += 1
            result = self.sources()
            if reads == 2:
                self.latest_image.write_bytes(self.latest_image.read_bytes() + b' changed during source readback')
            return result

        output = self.root / 'shared-kernel-image-change'
        with patch.object(shared, 'current_sources', side_effect=source_readback):
            with self.assertRaises(ValueError):
                shared.build(output, self.compiler, self.cold, candidate='agent-slice')
        self.assertEqual(reads, 2)
        self.assertFalse((output / 'manifest.json').exists())
        self.assertFalse((output / 'build.json').exists())


if __name__ == '__main__':
    unittest.main()
