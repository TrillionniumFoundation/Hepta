"""Source and synthetic admission controls for the explicit integer companion.

No method in this module compiles or maps native code, runs Core116, builds an
installed distribution or supplies a cold qualification. The original ten
integer Core-VM methods execute separately with their original IDs.
"""
from __future__ import annotations

import ast
from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_core_integer_selection as selection

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_core_integer'


def methods(path):
    result = {}
    for cls in ast.parse(Path(path).read_bytes()).body:
        if isinstance(cls, ast.ClassDef):
            for node in cls.body:
                if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                    result[cls.name + '.' + node.name] = node
    return result


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


def manifest(inputs, compiler='a' * 64, image=b'synthetic non-executable image'):
    hashes = {name: sha256(body).hexdigest() for name, body in inputs.items()}
    return {
        'schema': selection.SCHEMA,
        'source_sha256': hashes[selection.HIA_SOURCE],
        'abi_sha256': hashes[selection.ABI_SOURCE],
        'bridge_sha256': hashes[selection.BRIDGE_SOURCE],
        'selection_sha256': hashes[selection.SELECTION_SOURCE],
        'image_path': 'core-integer.image.bin',
        'image_sha256': sha256(image).hexdigest(),
        'compiler_sha256': compiler,
    }


class IntegerIntegrationSourceTests(unittest.TestCase):
    def test_exact_completed_kernel_bridge_and_original_Core39_are_preserved(self):
        baseline = json.loads((FIXTURE / 'BASELINE.json').read_bytes())
        for name, key in ((selection.HIA_SOURCE, 'kernel_pin'),
                          (selection.BRIDGE_SOURCE, 'bridge_pin')):
            body = (ROOT / name).read_bytes()
            self.assertEqual((len(body), sha256(body).hexdigest()),
                             (baseline[key]['bytes'], baseline[key]['sha256']))
        original = json.loads((FIXTURE / 'integer_abi_before_integration.json').read_bytes())
        current = selection.checked_abi((ROOT / selection.ABI_SOURCE).read_bytes())
        current['status'] = original['status']
        self.assertEqual(current, original)
        self.assertEqual((FIXTURE / 'integration/hepta/hia_core_lowering_native.py').read_bytes(),
                         (ROOT / 'hepta/hia_core_lowering_native.py').read_bytes())
        self.assertEqual((FIXTURE / 'inputs/hepta/hia_core_integer_abi.json').read_bytes(),
                         (ROOT / selection.ABI_SOURCE).read_bytes())
        rows = json.loads((ROOT / 'tests/fixtures/hia_core_compare_core39.json').read_bytes())['files']
        self.assertEqual(len(rows), 40)
        for row in rows:
            body = (ROOT / row['path']).read_bytes()
            self.assertEqual((len(body), sha256(body).hexdigest()), (row['size'], row['sha256']))

    def test_original_ten_method_bodies_and_complete_116_population_are_preserved(self):
        old = methods(FIXTURE / 'integer_source_before_portability.py.txt')
        current = methods(ROOT / 'tests/test_hia_core_integer_source.py')
        self.assertEqual(set(old), set(current))
        self.assertEqual(len(old), 10)
        for name in old:
            self.assertEqual(ast.dump(old[name]), ast.dump(current[name]), name)
        population = json.loads((FIXTURE / 'reference/ORIGINAL-POPULATION.json').read_bytes())
        self.assertEqual([len(population['original_methods'][key])
                          for key in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS')], [15, 51, 50])
        self.assertEqual((population['total'], population['original_gates']), (116, 32))

    def test_portable_evidence_is_fresh_and_explicit_evidence_remains_create_only(self):
        path = ROOT / 'tests/test_hia_core_integer_source.py'
        environment = {key: value for key, value in os.environ.items() if key not in (
            'HEPTA_INTEGER_DRAFT_ROOT', 'HEPTA_INTEGER_SOURCE_EVIDENCE')}
        spec = importlib.util.spec_from_file_location('integer_portable_source_control', path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, environment, clear=True):
            spec.loader.exec_module(module)
        self.assertEqual(module.ROOT, FIXTURE)
        self.assertIsNone(module.EVIDENCE)
        cls = module.ExactIntegerSourceTests
        directories = []
        with patch.object(module.author, 'source', return_value='def control():\n    pass\n'), \
             patch.object(module.author, 'document', return_value={'synthetic': True}), \
             patch.object(module, 'render_assembly', return_value='synthetic source fixture\n'), \
             patch.object(module, 'verify_program', return_value=object()):
            for _ in range(2):
                cls.setUpClass()
                directories.append(cls.evidence_directory)
                self.addCleanup(shutil.rmtree, cls.evidence_directory.parent)
                cls.tearDownClass()
                self.assertTrue((cls.evidence_directory / 'VM-CASES.json').is_file())
            self.assertNotEqual(*directories)
            with tempfile.TemporaryDirectory(prefix='integer-explicit-source-') as temporary:
                explicit = Path(temporary) / 'evidence'
                module._EXPLICIT_EVIDENCE, module.EVIDENCE = str(explicit), explicit
                cls.setUpClass()
                cls.tearDownClass()
                with self.assertRaises(FileExistsError):
                    cls.setUpClass()

    def test_generator_body_and_original62_order_are_preserved(self):
        from tools import hia_compiler_owner_gates as gates
        old = ast.parse((FIXTURE / 'integer_generator_before_standard_entry.py.txt').read_bytes())
        new = ast.parse((ROOT / 'tools/generate_hia_core_integer.py').read_bytes())
        keep = lambda tree: ast.Module(body=[node for node in tree.body if not (
            isinstance(node, ast.FunctionDef) and node.name == 'main')], type_ignores=[])
        self.assertEqual(ast.dump(keep(old)), ast.dump(keep(new)))
        baseline = json.loads((FIXTURE / 'BASELINE.json').read_bytes())
        expected = baseline['generator_prefix'] + ['core_integer']
        self.assertEqual(len(expected), 63)
        self.assertEqual(list(gates.SOURCE_GENERATORS), expected)
        workflow = (ROOT / '.github/workflows/hia-core.yml').read_text()
        actual = re.search(r'for component in ([^;]+); do', workflow).group(1).split()
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), len(set(actual)))
        for name in ('tests.test_hia_core_integer_source.ExactIntegerSourceTests',
                     'tests.test_hia_core_integer_integration.IntegerIntegrationSourceTests'):
            self.assertEqual(workflow.count(repr(name)), 1)

    def test_standard_generator_output_and_explicit_create_only_are_distinct(self):
        from tools import generate_hia_core_integer as author
        with tempfile.TemporaryDirectory(prefix='integer-generator-arguments-') as temporary:
            folder = Path(temporary)
            (folder / 'examples/hia_bootstrap').mkdir(parents=True)
            canonical = folder / 'examples/hia_bootstrap/core_integer.hiaasm'
            supplied = folder / 'explicit.hiaasm'
            with patch.object(author, '__file__', str(folder / 'tools/generate_hia_core_integer.py')), \
                 patch.object(author, 'document', return_value={'synthetic': True}), \
                 patch.object(author, 'render_assembly', return_value='synthetic non-native fixture\n'), \
                 redirect_stdout(io.StringIO()):
                with patch.object(sys, 'argv', ['generator']):
                    author.main()
                    first = canonical.read_bytes()
                    author.main()
                    self.assertEqual(canonical.read_bytes(), first)
                with patch.object(sys, 'argv', ['generator', '--output', str(supplied)]):
                    author.main()
                    self.assertEqual(supplied.read_bytes(), first)
                    with self.assertRaises(FileExistsError):
                        author.main()

    def test_all_original_resources_remain_and_integer_assets_are_packaged(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from tests import test_hia_agent_installed_resources as installed
        baseline = json.loads((FIXTURE / 'BASELINE.json').read_bytes())
        added = [selection.ABI_SOURCE, selection.HIA_SOURCE]
        self.assertEqual(list(NATIVE_SOURCE_FILES), baseline['native_resources'] + added)
        self.assertEqual(len(NATIVE_SOURCE_FILES), len(set(NATIVE_SOURCE_FILES)))
        self.assertEqual(len(NATIVE_SOURCE_FILES), 96)
        self.assertEqual((ROOT / 'MANIFEST.in').read_text().splitlines(),
                         baseline['original_manifest_lines'] + ['include ' + name for name in added])
        self.assertEqual(installed.BUNDLED_SOURCE_BINDINGS['core_integer'],
                         ('hepta.hia_core_integer_selection', 'control'))
        self.assertIn(selection.ABI_SOURCE, installed.NATIVE_METADATA_RESOURCE_FILES)
        self.assertEqual(selection.SOURCES['control'], ROOT / selection.HIA_SOURCE)

    def test_abi_rejects_missing_extra_wrong_scalar_nested_boolean_and_duplicate_fields(self):
        body = (ROOT / selection.ABI_SOURCE).read_bytes()
        value = selection.checked_abi(body)
        cases = []
        for key in value:
            missing = deepcopy(value); del missing[key]; cases.append(missing)
        cases.extend([{**value, 'extra': 0}, {**value, 'input_bytes': 256.0},
                      {**value, 'ordinary_Core_images_unchanged': 1},
                      {**value, 'integer_value_policy_cap': 8388608},
                      {**value, 'exact_types': ['int', 'bool']}])
        for key in ('operations', 'entry_statuses'):
            changed = deepcopy(value)
            changed[key][next(iter(changed[key]))] = True
            cases.append(changed)
        changed = deepcopy(value); changed['READ_ACK_input_header'][2] = 1; cases.append(changed)
        for changed in cases:
            with self.subTest(keys=tuple(changed)), self.assertRaises((ValueError, TypeError)):
                selection.checked_abi(raw(changed))
        with self.assertRaises(ValueError):
            selection.checked_abi(b'{"schema":"first",' + body.lstrip()[1:])

    def test_manifest_binds_every_source_compiler_image_path_and_exact_digest(self):
        inputs = selection.current_inputs()
        hashes = {name: sha256(body).hexdigest() for name, body in inputs.items()}
        value = manifest(inputs)
        self.assertEqual(selection._manifest(raw(value), hashes, 'a' * 64), value)
        cases = []
        for key in value:
            missing = dict(value); del missing[key]; cases.append(missing)
        for key in selection.MANIFEST_KEYS - {'schema', 'image_path', 'image_sha256'}:
            cases.append({**value, key: 'b' * 64})
        cases.extend([{**value, 'schema': 'other'}, {**value, 'image_path': '../core-integer.image.bin'},
                      {**value, 'image_sha256': 'G' * 64}, {**value, 'compiler_sha256': True},
                      {**value, 'extra': 1}])
        for changed in cases:
            with self.subTest(keys=tuple(changed)), self.assertRaises(ValueError):
                selection._manifest(raw(changed), hashes, 'a' * 64)
        with self.assertRaises(ValueError):
            selection._manifest(b'{"schema":"first",' + raw(value)[1:], hashes, 'a' * 64)

    def test_missing_selector_is_optional_but_empty_explicit_selection_is_an_error(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(selection, 'installed_integer') as admitted:
            self.assertIsNone(selection.selected_integer('a' * 64))
            admitted.assert_not_called()
        marker = object()
        with patch.dict(os.environ, {selection.SELECTOR: '/explicit/manifest.json'}, clear=True), \
             patch.object(selection, 'installed_integer', return_value=marker) as admitted:
            self.assertIs(selection.selected_integer('a' * 64), marker)
            admitted.assert_called_once_with('/explicit/manifest.json', 'a' * 64)
        with patch.dict(os.environ, {selection.SELECTOR: ''}, clear=True):
            with self.assertRaises((ValueError, OSError)):
                selection.selected_integer('a' * 64)

    def test_source_revalidation_precedes_cached_image_admission(self):
        inputs = selection.current_inputs()
        value = manifest(inputs)
        marker = object()
        with tempfile.TemporaryDirectory(prefix='integer-manifest-source-') as temporary:
            path = Path(temporary) / 'manifest.json'
            path.write_bytes(raw(value))
            with patch.object(selection, '_load', return_value=marker) as loaded:
                self.assertIs(selection.installed_integer(path, 'a' * 64), marker)
                self.assertIs(selection.installed_integer(path, 'a' * 64), marker)
                self.assertEqual(loaded.call_count, 2)
                for name in inputs:
                    changed = dict(inputs); changed[name] += b'\n'
                    with self.subTest(source=name), patch.object(selection, 'current_inputs', return_value=changed):
                        with self.assertRaises(ValueError):
                            selection.installed_integer(path, 'a' * 64)
                self.assertEqual(loaded.call_count, 2)
                for compiler in ('b' * 64, True, '', 'G' * 64):
                    with self.assertRaises(ValueError):
                        selection.installed_integer(path, compiler)
                path.write_bytes(b' ' * 4097)
                with self.assertRaises(ValueError):
                    selection.installed_integer(path, 'a' * 64)
                self.assertEqual(loaded.call_count, 2)

    def test_synthetic_cached_mapping_is_bound_and_identity_detects_source_or_image_changes(self):
        inputs = selection.current_inputs()
        image_bytes = b'synthetic non-executable image'
        value = manifest(inputs, image=image_bytes)
        mappings = []
        class SyntheticImage:
            def __init__(self, body, digest):
                if body != image_bytes or sha256(body).hexdigest() != digest:
                    raise ValueError('synthetic bytes differ')
                self.image_sha256 = digest
                mappings.append(self)
            def _bind_manifest_source(self, digest):
                self.admitted_source_sha256 = digest
        selection._load.cache_clear()
        self.addCleanup(selection._load.cache_clear)
        with tempfile.TemporaryDirectory(prefix='integer-synthetic-mapping-') as temporary:
            folder = Path(temporary)
            path = folder / 'manifest.json'; path.write_bytes(raw(value))
            (folder / value['image_path']).write_bytes(image_bytes)
            with patch.object(selection, 'NativeHiaJsonImage', SyntheticImage):
                first = selection.installed_integer(path, 'a' * 64)
                self.assertIs(selection.installed_integer(path, 'a' * 64), first)
                self.assertEqual(len(mappings), 1)
                identity = selection.implementation_identity(first)
                self.assertIn(value['image_sha256'].encode(), identity)
                for name in inputs:
                    changed = dict(inputs); changed[name] += b'\n'
                    with self.subTest(source=name), patch.object(selection, 'current_inputs', return_value=changed):
                        with self.assertRaises(ValueError):
                            selection.implementation_identity(first)
                for field in ('image_sha256', 'admitted_source_sha256'):
                    with patch.object(first.image, field, 'b' * 64):
                        with self.assertRaises(ValueError):
                            selection.implementation_identity(first)
                self.assertEqual(selection.implementation_identity(first), identity)

    def test_Core_owner_cache_distinguishes_all_three_admitted_companions(self):
        from hepta import hia_core_lowering_selection as core
        from hepta import hia_core_unpack_selection as unpack
        from hepta import hia_core_compare_selection as compare
        abi_raw = (ROOT / core.ABI_SOURCE).read_bytes()
        abi = core.checked_abi(abi_raw)
        names = ('core_lowering_pool', *abi['units'])
        bundle = {'schema': core.SCHEMA, 'abi_sha256': sha256(abi_raw).hexdigest(),
                  'compiler_sha256': 'a' * 64,
                  'unit_manifests': {name: name + '/manifest.json' for name in names}}
        loaded = SimpleNamespace(images=tuple(object() for _ in names), abi=abi)
        integer_values = [object(), object()]
        unpack_value, compare_value, namespace = object(), object(), {}
        made = []
        def construct(images, pool, admitted_abi, admitted_namespace, **companions):
            self.assertEqual((images, pool, admitted_abi, admitted_namespace),
                             (loaded.images[1:], loaded.images[0], abi, namespace))
            owner = SimpleNamespace(**companions); made.append(owner); return owner
        with tempfile.TemporaryDirectory(prefix='integer-Core-cache-') as temporary:
            folder = Path(temporary); path = folder / 'manifest.json'; path.write_bytes(raw(bundle))
            for name in names:
                (folder / name).mkdir(); (folder / name / 'manifest.json').write_bytes(b'{}')
            with patch.object(core, '_OWNER_CACHE', []), patch.object(core, '_load_bundle', return_value=loaded), \
                 patch.object(core, 'NativeCoreLowering', side_effect=construct), \
                 patch.object(unpack, 'selected_unpack', return_value=unpack_value), \
                 patch.object(compare, 'selected_compare', return_value=compare_value), \
                 patch.object(selection, 'selected_integer', return_value=integer_values[0]) as selected:
                first = core.installed_core_lowering(path, namespace)
                self.assertIs(core.installed_core_lowering(path, namespace), first)
                selected.return_value = integer_values[1]
                second = core.installed_core_lowering(path, namespace)
                self.assertIsNot(first, second)
                self.assertEqual(len(made), 2)
                self.assertIs(first.integer, integer_values[0])
                self.assertIs(second.integer, integer_values[1])
                self.assertIs(second.unpack, unpack_value)
                self.assertIs(second.numeric_compare, compare_value)
                self.assertEqual(selected.call_args.args, ('a' * 64,))

    def test_Core_scope_keeps_captured_owner_until_exit(self):
        from hepta import hia_core_lowering_selection as core
        first, second = object(), object()
        token = core._OWNER.set(core._UNSELECTED)
        self.addCleanup(core._OWNER.reset, token)
        with patch.dict(os.environ, {core.SELECTOR: '/synthetic/first'}, clear=True), \
             patch.object(core, 'installed_core_lowering', side_effect=[first, second]) as admitted:
            with core.native_core_lowering_scope({}):
                self.assertIs(core.active_core_lowering(), first)
                os.environ[core.SELECTOR] = '/synthetic/second'
                self.assertIs(core.selected_core_lowering({}), first)
                with core.native_core_lowering_scope({}):
                    self.assertIs(core.active_core_lowering(), first)
                self.assertEqual(admitted.call_count, 1)
            self.assertIsNone(core.active_core_lowering())
            self.assertIs(core.selected_core_lowering({}), second)
            self.assertEqual(admitted.call_count, 2)

    def test_Core_implementation_identity_includes_the_integer_companion(self):
        from hepta import hia_core_lowering_selection as core
        abi_raw = (ROOT / core.ABI_SOURCE).read_bytes()
        abi = core.checked_abi(abi_raw)
        names = ('core_lowering_pool', *abi['units'])
        sources = tuple((name, sha256((ROOT / ('examples/hia_bootstrap/' + name + '.hiaasm')).read_bytes()).hexdigest())
                        for name in names)
        images = tuple(SimpleNamespace(image_sha256='a' * 64) for _ in names)
        loaded = SimpleNamespace(abi_sha256=sha256(abi_raw).hexdigest(), source_hashes=sources,
                                 bundle_sha256='b' * 64, names=names, images=images)
        owner = SimpleNamespace(_admitted_bundle=loaded, unpack=None, numeric_compare=None, integer=None)
        with patch.object(core, 'selected_core_lowering', return_value=owner):
            before = core.native_implementation_identity({})
            owner.integer = object()
            with patch.object(selection, 'implementation_identity', return_value=b'bound-integer-identity') as identity:
                after = core.native_implementation_identity({})
                identity.assert_called_once_with(owner.integer)
            self.assertEqual(after, before + b'\0native-core-integer\0bound-integer-identity')

    def test_strict_builder_refuses_unqualified_cold_before_output_or_compile(self):
        from tools import build_hia_core_integer as builder
        from tools import qualify_hia_selfhost as compiler
        with tempfile.TemporaryDirectory(prefix='integer-builder-admission-') as temporary:
            folder = Path(temporary)
            image = folder / 'compiler.bin'; image.write_bytes(b'non-executable source control')
            cold = folder / 'cold.json'; cold.write_bytes(b'{}')
            output = folder / 'output'
            with patch.object(compiler, 'compile_stage', side_effect=AssertionError('source control invoked compiler')) as compile_image:
                with self.assertRaises(ValueError):
                    builder.build(output, image, cold)
                compile_image.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
