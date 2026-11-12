"""Cold/source/receipt and selection controls with explicit transport doubles.

These controls never label their simulated compiler or cold report as an actual
native run. The separate NativeTests build and execute the real HIA component.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import build_hia_service_context as builder
from hepta import hia_service_context_native as native

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def controlled_build():
    with tempfile.TemporaryDirectory(prefix='hia-context-build-control-') as folder:
        root = Path(folder)
        for name in builder.DEVELOPMENT_INPUT_NAMES:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('controlled input: ' + name).encode())
        compiler, cold = root / 'compiler', root / 'cold.json'
        compiler.write_bytes(b'controlled compiler, not executable')
        cold.write_text(json.dumps({'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3}))
        sources = {name: sha256((root / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES}
        output = root / 'output'
        calls = []
        def compile_stage(out, label, consumed_compiler, source):
            calls.append((out, label, consumed_compiler, source))
            image = out / (label + '.image.bin'); image.write_bytes(b'x')
            c, s, i = (sha256(raw).hexdigest() for raw in (compiler.read_bytes(), source, b'x'))
            receipt = {'status': 'returned', 'format': 'flat-x86-64',
                'return_encoding': 'zero-extended-u32', 'artifact_sha256': c, 'image_sha256': c,
                'input_sha256': s, 'source_sha256': s, 'produced_sha256': i,
                'input_bytes': len(source), 'produced_bytes': 1, 'result_u64': 1, 'core_u32': 1,
                'abi_status': 0, 'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'case': label, 'produced_image': str(image)}
            (out / (label + '.receipt.json')).write_text(json.dumps(receipt))
            return image, receipt
        with patch.object(builder, 'ROOT', root), patch.object(builder, 'admit_cold_build', return_value=sources), patch.object(builder, 'current_sources', return_value=sources):
            yield SimpleNamespace(root=root, compiler=compiler, cold=cold, sources=sources,
                                  output=output, calls=calls, compile_stage=compile_stage)


class ServiceContextAdapterTests(unittest.TestCase):
    def test_held_service_selection_does_not_change_default_core_checker_scope(self):
        from hepta import hia_checker_identity as checker
        self.assertEqual(set(checker.HELD_NATIVE_OWNERS), {native.SELECTOR, 'HEPTA_HIA_SERVICE_EMISSION_MANIFEST', 'HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST', 'HEPTA_HIA_PROOF_CONTRACT_MANIFEST'})
        self.assertFalse(set(checker.NATIVE_OWNERS) & set(checker.HELD_NATIVE_OWNERS))
        env = {key: '' for key in checker.NATIVE_OWNERS}
        env[native.SELECTOR] = '/not-a-default-core-selection'
        with patch.dict(os.environ, env), patch.object(native, 'installed_context',
                side_effect=AssertionError('default Core checker reselected a service owner')):
            expected = {key: None for key in sorted(checker.NATIVE_OWNERS)}
            self.assertEqual(checker.checker_native_selection(), expected)
            self.assertEqual(checker.checker_native_selection(held_owners=()), expected)

    def test_serialized_or_duplicate_scope_cannot_select_a_held_executable(self):
        from hepta import hia_checker_identity as checker
        env = {key: '' for key in checker.NATIVE_OWNERS}
        with patch.dict(os.environ, env):
            for supplied in ([], {}, ({'selector': native.SELECTOR},),
                    (SimpleNamespace(selector=native.SELECTOR),)):
                with self.subTest(supplied=type(supplied).__name__):
                    with self.assertRaises(ValueError):
                        checker.checker_native_selection(held_owners=supplied)

    def test_invalid_real_cold_gate_refuses_before_output_or_compiler(self):
        with tempfile.TemporaryDirectory(prefix='hia-context-no-cold-') as folder:
            root = Path(folder); compiler = root / 'compiler'; cold = root / 'cold'
            compiler.write_bytes(b'not qualified'); cold.write_text('{}')
            with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaises(ValueError): builder.build(root / 'output', compiler, cold)
            self.assertFalse((root / 'output').exists())

    def test_component_and_full_source_readback_precede_output(self):
        for missing in builder.REQUIRED_SOURCE_NAMES:
            with self.subTest(missing=missing), controlled_build() as case:
                case.sources.pop(missing)
                with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                    with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)
                self.assertFalse(case.output.exists())
        with controlled_build() as case, patch.object(builder, 'current_sources', return_value={}):
            with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)
            self.assertFalse(case.output.exists())

    def test_original_cold_limits_are_exact_integers(self):
        for key, value in (('qualification_wall_limit_seconds', 180.0),
                           ('qualification_wall_limit_seconds', 181),
                           ('cleanup_wall_limit_seconds', 3.0),
                           ('cleanup_wall_limit_seconds', True),
                           ('cleanup_wall_limit_seconds', 4)):
            with self.subTest(key=key, value=value), controlled_build() as case:
                cold = json.loads(case.cold.read_bytes()); cold[key] = value
                case.cold.write_text(json.dumps(cold))
                with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)
                self.assertFalse(case.output.exists())

    def test_exact_compile_and_disk_receipt_fields_are_both_required(self):
        changes = (('abi_status', False), ('result_u64', True), ('core_u32', 1.0),
                   ('produced_bytes', True), ('input_bytes', True),
                   ('return_encoding', 'packed-seed-u64'), ('source_unchanged', 1),
                   ('forbidden_compiler_modules_loaded', {}),
                   ('produced_sha256', '0' * 64), ('case', 'another-invocation'))
        for disk_only in (False, True):
            for key, value in changes:
                with self.subTest(disk_only=disk_only, key=key), controlled_build() as case:
                    def changed(*args):
                        image, receipt = case.compile_stage(*args)
                        disk = dict(receipt); disk[key] = value
                        (case.output / 'service-context.receipt.json').write_text(json.dumps(disk))
                        return image, receipt if disk_only else disk
                    with patch.object(builder, 'compile_stage', side_effect=changed):
                        with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)
                    self.assertFalse((case.output / 'manifest.json').exists())

    def test_duplicate_receipt_or_foreign_output_path_cannot_publish(self):
        for mode in ('duplicate', 'foreign-path'):
            with self.subTest(mode=mode), controlled_build() as case:
                def changed(*args):
                    image, receipt = case.compile_stage(*args)
                    if mode == 'duplicate':
                        raw = json.dumps(receipt)
                        (case.output / 'service-context.receipt.json').write_text(raw[:-1] + ', "abi_status":0}')
                    else:
                        image = case.root / 'elsewhere.image.bin'; image.write_bytes(b'x')
                    return image, receipt
                with patch.object(builder, 'compile_stage', side_effect=changed):
                    with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)
                self.assertFalse((case.output / 'manifest.json').exists())

    def test_all_consumed_inputs_rechecked_after_compile(self):
        for name in ('compiler', 'cold', *builder.REQUIRED_SOURCE_NAMES):
            with self.subTest(name=name), controlled_build() as case:
                def changed(*args):
                    value = case.compile_stage(*args)
                    path = case.compiler if name == 'compiler' else case.cold if name == 'cold' else case.root / name
                    path.write_bytes(path.read_bytes() + b'changed')
                    return value
                with patch.object(builder, 'compile_stage', side_effect=changed):
                    with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)
                self.assertFalse((case.output / 'manifest.json').exists())

    def test_published_receipt_image_manifest_and_report_are_read_back(self):
        original = builder._publish
        for phase, target in (('manifest.json', 'service-context.image.bin'),
                              ('manifest.json', 'service-context.receipt.json'),
                              ('manifest.json', 'manifest.json'), ('build.json', 'build.json')):
            with self.subTest(phase=phase, target=target), controlled_build() as case:
                def changed(path, raw):
                    original(path, raw)
                    if path.name == phase:
                        changed_path = case.output / target
                        changed_path.write_bytes(changed_path.read_bytes() + b'changed')
                with patch.object(builder, 'compile_stage', side_effect=case.compile_stage), patch.object(builder, '_publish', side_effect=changed):
                    with self.assertRaises(ValueError): builder.build(case.output, case.compiler, case.cold)

    def test_development_and_controlled_cold_reports_have_separate_scope(self):
        for development in (False, True):
            with self.subTest(development=development), controlled_build() as case:
                with patch.object(builder, 'compile_stage', side_effect=case.compile_stage):
                    path = (builder.build_development(case.output, case.compiler) if development else
                            builder.build(case.output, case.compiler, case.cold))
                self.assertEqual(len(case.calls), 1)
                report_path = case.output / ('development-build.json' if development else 'build.json')
                report = json.loads(report_path.read_bytes())
                self.assertIs(report['whole_stack_rewritten_in_hia'], False)
                self.assertIs(report['production_activated'], False)
                self.assertEqual(report['original_compiler_child_timeout_seconds'], 20)
                self.assertEqual(report['manifest'], json.loads(path.read_bytes()))
                self.assertEqual(report['scope'], 'EXPLICIT_COMPILER_DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD')
                self.assertEqual(report['cold_report_sha256'], None if development else sha256(case.cold.read_bytes()).hexdigest())

    @contextmanager
    def selection(self):
        with tempfile.TemporaryDirectory(prefix='hia-context-selection-') as folder:
            root = Path(folder); source = root / 'source.hiaasm'; image = root / 'context.bin'; manifest = root / 'manifest.json'
            source.write_bytes(b'controlled HIA source'); image.write_bytes(b'controlled image, not executable')
            value = {'schema': native.SCHEMA, 'source_sha256': sha256(source.read_bytes()).hexdigest(),
                     'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                     'compiler_sha256': 'c' * 64}
            manifest.write_text(json.dumps(value)); calls = []
            class FakeImage:
                def __init__(self, raw, expected):
                    calls.append(raw); self.image_sha256 = expected
            native._mapped_context.cache_clear()
            with patch.object(native, 'SOURCE', source), patch.object(native, 'NativeContextImage', FakeImage), patch('hepta.hia_native_helpers.pinned_image', return_value=None):
                try:
                    yield SimpleNamespace(root=root, source=source, image=image, manifest=manifest, value=value, calls=calls)
                finally:
                    native._mapped_context.cache_clear()

    def test_warm_selection_reads_actual_source_and_image_again(self):
        for target in ('source', 'image', 'manifest'):
            with self.subTest(target=target), self.selection() as case:
                first = native.installed_context(case.manifest)
                self.assertIs(native.installed_context(case.manifest), first)
                self.assertEqual(len(case.calls), 1)
                path = getattr(case, target); raw = path.read_bytes(); path.write_bytes(raw + b'changed')
                with self.assertRaises((ValueError, OSError)): native.installed_context(case.manifest)
                self.assertEqual(len(case.calls), 1)

    def test_malformed_selection_and_active_bundle_refuse_before_mapping(self):
        for key, value in (('image_path', '../outside.bin'), ('image_path', '/tmp/outside.bin'),
                           ('image_path', ''), ('image_sha256', True), ('source_sha256', '0' * 64),
                           ('schema', 'hepta.hia.service-context-native.v2')):
            with self.subTest(key=key, value=value), self.selection() as case:
                changed = dict(case.value); changed[key] = value
                case.manifest.write_text(json.dumps(changed))
                with self.assertRaises(ValueError): native.installed_context(case.manifest)
                self.assertEqual(case.calls, [])
        with self.selection() as case:
            raw = json.dumps(case.value); case.manifest.write_text(raw[:-1] + ',"schema":' + json.dumps(native.SCHEMA) + '}')
            with self.assertRaises(ValueError): native.installed_context(case.manifest)
            self.assertEqual(case.calls, [])
        with patch('hepta.hia_native_helpers.pinned_image', side_effect=ValueError('active bundle refuses')), patch.object(native, '_regular_bytes', side_effect=AssertionError('unselected filesystem read')):
            with self.assertRaisesRegex(ValueError, 'active bundle'): native.installed_context('/unread-manifest')

    def test_post_mapping_source_image_and_manifest_drift_refuse(self):
        for target in ('source', 'image', 'manifest'):
            with self.subTest(target=target), self.selection() as case:
                def changed(raw, expected):
                    path = getattr(case, target); path.write_bytes(path.read_bytes() + b'changed')
                    return SimpleNamespace(image_sha256=expected)
                with patch.object(native, '_mapped_context', side_effect=changed):
                    with self.assertRaises(ValueError): native.installed_context(case.manifest)

    def test_fifo_source_refuses_in_a_bounded_real_child(self):
        with tempfile.TemporaryDirectory(prefix='hia-context-fifo-') as folder:
            fifo = Path(folder) / 'fifo'; os.mkfifo(fifo)
            program = "import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from hepta.hia_service_context_native import _regular_bytes\ntry:_regular_bytes(Path(sys.argv[2]),16384)\nexcept ValueError:pass\nelse:raise AssertionError('FIFO admitted')\n"
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(ROOT), str(fifo)], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fixture_selection_refuses_ambiguity_and_invalid_cold_before_output(self):
        from tests.test_hia_service_context_native import ServiceContextNativeTests
        with tempfile.TemporaryDirectory(prefix='hia-context-fixture-control-') as folder:
            root = Path(folder); evidence = root / 'not-created'
            report = root / 'invalid-cold.json'; report.write_text('{}')
            names = ('HEPTA_HIA_SERVICE_CONTEXT_COLD_REPORT', 'HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_COMPILER',
                     'HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_MANIFEST')
            for i, first in enumerate(names):
                for second in names[i + 1:]:
                    env = {name: '' for name in names}
                    env.update({first: '/unread-first', second: '/unread-second',
                                'HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE': str(evidence)})
                    with self.subTest(first=first, second=second), patch.dict(os.environ, env):
                        with self.assertRaisesRegex(ValueError, 'one explicit'): ServiceContextNativeTests.setUpClass.__func__(SimpleNamespace(__name__='InvalidContextFixture'))
                    self.assertFalse(evidence.exists())
            env = {name: '' for name in names}; env.update({names[0]: str(report), 'HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE': str(evidence)})
            with patch.dict(os.environ, env):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'): ServiceContextNativeTests.setUpClass.__func__(SimpleNamespace(__name__='InvalidContextFixture'))
            self.assertFalse(evidence.exists())
