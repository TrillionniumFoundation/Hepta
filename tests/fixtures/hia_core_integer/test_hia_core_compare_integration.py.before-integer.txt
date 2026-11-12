"""Source and synthetic controls for optional numeric qualification wiring.

These tests never compile or execute a native image, run the original116,
build a wheel, or grant a matching-cold gate. The separate original eleven
Core-VM methods retain their own IDs and algorithm expectations.
"""
from __future__ import annotations

import ast
from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
import importlib.util
import io
import json
import operator
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import hia_core_companion_arguments as arguments
from tools import hia_core_compare_qualification as reader

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'tests/fixtures/hia_core_compare_integration_baseline.json'


def assignment(path, name):
    tree = ast.parse(Path(path).read_bytes())
    node = next(node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
    return ast.literal_eval(node.value)


def functions(tree):
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def methods(path):
    result = {}
    for cls in ast.parse(Path(path).read_bytes()).body:
        if isinstance(cls, ast.ClassDef):
            for node in cls.body:
                if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                    result[cls.name + '.' + node.name] = node
    return result


class NumericComparisonIntegrationSourceTests(unittest.TestCase):
    def test_resource_inventory_preserves_original92_and_Core39(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from tests import test_hia_agent_installed_resources as installed
        from hepta import hia_core_compare_selection as selection
        baseline = json.loads(BASELINE.read_bytes())
        added = [selection.ABI_SOURCE, selection.HIA_SOURCE]
        self.assertEqual(len(NATIVE_SOURCE_FILES), 94)
        self.assertEqual(len(set(NATIVE_SOURCE_FILES)), 94)
        self.assertEqual([name for name in NATIVE_SOURCE_FILES if name not in added], baseline['native_resources'])
        lines = (ROOT / 'MANIFEST.in').read_text().splitlines()
        self.assertEqual([line for line in lines if line not in ['include ' + name for name in added]],
                         baseline['manifest_lines'])
        self.assertTrue(all(lines.count('include ' + name) == 1 for name in added))
        self.assertEqual(installed.BUNDLED_SOURCE_BINDINGS['core_compare'],
                         ('hepta.hia_core_compare_selection', 'control'))
        self.assertIn(selection.ABI_SOURCE, installed.NATIVE_METADATA_RESOURCE_FILES)
        self.assertEqual(selection.SOURCES['control'].read_bytes(), (ROOT / selection.HIA_SOURCE).read_bytes())
        frozen = json.loads((ROOT / 'tests/fixtures/hia_core_compare_core39.json').read_bytes())['files']
        self.assertEqual({row['path'] for row in frozen}, set(installed.CORE_LOWERING_RESOURCE_FILES))
        self.assertEqual(len(frozen), 40)
        for pin in frozen:
            name = pin['path']
            raw = (ROOT / name).read_bytes()
            self.assertEqual((len(raw), sha256(raw).hexdigest()), (pin['size'], pin['sha256']), name)

    def test_generator_appends_after_original61_and_keeps_explicit_create_only(self):
        from tools import generate_hia_core_compare as author
        from tools import hia_compiler_owner_gates as gates
        baseline = json.loads(BASELINE.read_bytes())
        self.assertEqual(list(gates.SOURCE_GENERATORS), baseline['generator_prefix'] + ['core_compare'])
        workflow = (ROOT / '.github/workflows/hia-core.yml').read_text()
        actual = re.search(r'for component in ([^;]+); do', workflow).group(1).split()
        self.assertEqual(actual, list(gates.SOURCE_GENERATORS))
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(workflow.count("python-version: '3.14.4'"), 2)
        old = ast.parse((ROOT / 'tests/fixtures/hia_core_compare_generator_before_standard_entry.py.txt').read_bytes())
        new = ast.parse((ROOT / 'tools/generate_hia_core_compare.py').read_bytes())
        self.assertEqual(ast.dump(ast.Module(body=[n for n in old.body if not (isinstance(n, ast.FunctionDef) and n.name == 'main')], type_ignores=[])),
                         ast.dump(ast.Module(body=[n for n in new.body if not (isinstance(n, ast.FunctionDef) and n.name == 'main')], type_ignores=[])))
        with tempfile.TemporaryDirectory(prefix='numeric-generator-arguments-') as temporary:
            folder = Path(temporary)
            (folder / 'examples/hia_bootstrap').mkdir(parents=True)
            canonical = folder / 'examples/hia_bootstrap/core_compare.hiaasm'
            supplied = folder / 'explicit.hiaasm'
            with patch.object(author, '__file__', str(folder / 'tools/generate_hia_core_compare.py')), \
                 patch.object(author, 'document', return_value={'synthetic': True}), \
                 patch.object(author, 'render_assembly', return_value='source-only synthetic\n'), \
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

    def test_portable_fixture_keeps_all_eleven_original_method_bodies(self):
        current = ROOT / 'tests/test_hia_core_compare_source.py'
        old = ROOT / 'tests/fixtures/hia_core_compare_source_before_portability.py.txt'
        before, after = methods(old), methods(current)
        self.assertEqual(set(before), set(after))
        self.assertEqual(len(before), 11)
        for name in before:
            self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
        baseline = json.loads(BASELINE.read_bytes())
        ids = ['tests.test_hia_core_compare_source.' + name for name in sorted(after)]
        self.assertEqual(ids, baseline['numeric_source11'])
        environment = {key: value for key, value in os.environ.items() if key not in (
            'HEPTA_COMPARE_BASE_ROOT', 'HEPTA_COMPARE_CONTROL_EVIDENCE')}
        spec = importlib.util.spec_from_file_location('numeric_portable_source_only', current)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, environment, clear=True):
            spec.loader.exec_module(module)
        self.assertEqual(module.BASE, ROOT)
        self.assertIsNone(module.EVIDENCE)
        cls = module.ExactNumericComparisonSourceTests
        directories = []
        with patch.object(module.author, 'source', return_value='def control():\n    pass\n'), \
             patch.object(module.author, 'document', return_value={'synthetic': True}), \
             patch.object(module, 'render_assembly', return_value='synthetic fixture\n'), \
             patch.object(module, 'verify_program', return_value=object()):
            for _ in range(2):
                cls.setUpClass()
                directories.append(cls.evidence_directory)
                self.addCleanup(shutil.rmtree, cls.evidence_directory.parent)
                cls.tearDownClass()
                self.assertTrue((cls.evidence_directory / 'actual-VM-cases.json').is_file())
            self.assertNotEqual(*directories)
            with tempfile.TemporaryDirectory(prefix='numeric-explicit-fixture-') as temporary:
                explicit = Path(temporary) / 'evidence'
                module._EXPLICIT_EVIDENCE, module.EVIDENCE = str(explicit), explicit
                cls.setUpClass()
                cls.tearDownClass()
                with self.assertRaises(FileExistsError):
                    cls.setUpClass()

    def test_named_dual_companions_preserve_legacy_forms_and_refuse_ambiguity(self):
        self.assertEqual(arguments.installed_companion_arguments(), [])
        self.assertEqual(arguments.installed_companion_arguments('/unpack/manifest.json'), ['/unpack/manifest.json'])
        self.assertIsNone(arguments.parse_installed_companions([])['unpack_manifest'])
        self.assertEqual(arguments.parse_installed_companions(['/unpack/manifest.json'])['unpack_manifest'],
                         '/unpack/manifest.json')
        encoded = arguments.installed_companion_arguments('/unpack/manifest.json', '/numeric/manifest.json')
        self.assertEqual(encoded[0], '--companions-json')
        value = arguments.parse_installed_companions(encoded)
        self.assertEqual(value['unpack_manifest'], '/unpack/manifest.json')
        self.assertEqual(value['numeric_compare_manifest'], '/numeric/manifest.json')
        invalid = [['/unpack', '/numeric'], ['--companions-json'], ['--other', encoded[1]],
            ['--companions-json', encoded[1], 'extra']]
        for changed in ({**value, 'schema': 'old'}, {**value, 'extra': True},
                        {key: item for key, item in value.items() if key != 'unpack_manifest'},
                        {**value, 'unpack_manifest': None}, {**value, 'numeric_compare_manifest': False},
                        {**value, 'numeric_compare_manifest': 'relative'}):
            invalid.append(['--companions-json', json.dumps(changed)])
        invalid.append(['--companions-json', encoded[1][:-1] + ',"unpack_manifest":"/duplicate"}'])
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                arguments.parse_installed_companions(argv)
        with self.assertRaises(ValueError):
            arguments.installed_companion_arguments(None, '/numeric/manifest.json')

    def test_installed_child_keeps_two_UNPACK_blocks_and_other_fourteen_methods(self):
        new_path = ROOT / 'tests/test_hia_core_lowering_native.py'
        old_path = ROOT / 'tests/fixtures/hia_core_lowering_before_dual_companions.py.txt'
        before, after = methods(old_path), methods(new_path)
        self.assertEqual(set(before), set(after))
        self.assertEqual(len(before), 15)
        changed = 'CoreLoweringNativeTests.test_actual_installed_wheel_uses_complete_bundle_without_authoring'
        for name in before.keys() - {changed}:
            self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
        old_child = ast.parse(assignment(old_path, 'INSTALLED_CHILD'))
        new_child = ast.parse(assignment(new_path, 'INSTALLED_CHILD'))
        original_blocks = [node for node in old_child.body if isinstance(node, ast.If)
                           and ast.unparse(node.test) == 'len(sys.argv) == 5']
        selected_blocks = [node for node in new_child.body if isinstance(node, ast.If)
                           and ast.unparse(node.test) == "companions['unpack_manifest'] is not None"]
        self.assertEqual(len(original_blocks), 2)
        self.assertEqual(len(selected_blocks), 2)
        rewritten = ast.parse(ast.unparse(original_blocks[0]).replace('sys.argv[4]', "companions['unpack_manifest']")).body[0]
        self.assertEqual(ast.dump(ast.Module(body=rewritten.body, type_ignores=[])),
                         ast.dump(ast.Module(body=selected_blocks[0].body, type_ignores=[])))
        self.assertEqual(ast.dump(ast.Module(body=original_blocks[1].body, type_ignores=[])),
                         ast.dump(ast.Module(body=selected_blocks[1].body, type_ignores=[])))
        helper = functions(ast.parse((ROOT / 'tools/hia_core_companion_arguments.py').read_bytes()))
        self.assertEqual(ast.dump(functions(new_child)['parse_installed_companions']),
                         ast.dump(helper['parse_installed_companions']))
        child_source = assignment(new_path, 'INSTALLED_CHILD')
        self.assertNotIn('if len(sys.argv)==5:', child_source)
        self.assertIn("'numeric_compare_observations':numeric_compare_observations", child_source)
        self.assertIn("'unpack_observations':unpack_observations", child_source)

    def test_complete_compile_original_reader_rejects_changed_bytes_and_limits(self):
        from hepta import hia_core_compare_selection as selection
        source = (ROOT / selection.HIA_SOURCE).read_bytes()
        compiler = b'synthetic source-only compiler identity; never executed'
        image = b'synthetic source-only image identity; never mapped'
        with tempfile.TemporaryDirectory(prefix='numeric-compile-reader-') as temporary:
            folder = Path(temporary)
            compiler_path = folder / 'compiler.bin'
            compiler_path.write_bytes(compiler)
            output = image + bytes(1048576 - len(image))
            source_hash, image_hash, compiler_hash = (sha256(raw).hexdigest() for raw in (source, image, compiler))
            manifest = {'source_sha256': source_hash, 'image_sha256': image_hash}
            context = {'compiler_sha256': compiler_hash, 'identities': [{}, {}, {'path': str(compiler_path)}],
                'source_manifest': {'tools/hia_selfhost_child.py': sha256((ROOT / 'tools/hia_selfhost_child.py').read_bytes()).hexdigest()}}
            image_path = folder / 'core-compare.image.bin'
            image_path.write_bytes(image)
            receipt = {'status': 'returned', 'abi_status': 0, 'case': 'core-compare', 'format': 'flat-x86-64',
                'source_sha256': source_hash, 'input_sha256': source_hash, 'input_bytes': len(source),
                'image_sha256': compiler_hash, 'artifact_sha256': compiler_hash,
                'produced_sha256': image_hash, 'produced_image': str(image_path),
                'produced_bytes': len(image), 'core_u32': len(image), 'output_sha256': sha256(output).hexdigest(),
                'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'runner_sha256': context['source_manifest']['tools/hia_selfhost_child.py'], 'wall_elapsed_ns': 1,
                'limits': {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                    'output_capacity': 1048576, 'stack_bytes': 8388608, 'workspace_bytes': 1048576}}
            added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
                     'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
            request = {'format': 'flat-x86-64', 'image': str(compiler_path), 'image_sha256': compiler_hash,
                'source': str(folder / 'core-compare.input.bin'), 'source_sha256': source_hash,
                'capacity': 1048576, 'workspace_size': 1048576, 'workspace_fill': 0,
                'output': str(folder / 'core-compare.output.bin')}
            originals = {'.receipt.json': json.dumps(receipt).encode(),
                '.stdout.log': json.dumps({key: item for key, item in receipt.items() if key not in added}).encode(),
                '.stderr.log': b'', '.request.json': json.dumps(request).encode(),
                '.input.bin': source, '.output.bin': output}
            for suffix, raw in originals.items():
                (folder / ('core-compare' + suffix)).write_bytes(raw)
            observed = reader.compile_originals(folder, manifest, receipt, context)
            self.assertEqual(len(observed), 6)
            for suffix in ('.request.json', '.input.bin', '.output.bin', '.receipt.json', '.stdout.log'):
                path = folder / ('core-compare' + suffix)
                saved = path.read_bytes()
                path.write_bytes(saved[:-1] if suffix == '.output.bin' else b'changed')
                with self.subTest(suffix=suffix), self.assertRaises((ValueError, KeyError, json.JSONDecodeError)):
                    reader.compile_originals(folder, manifest, receipt, context)
                path.write_bytes(saved)
            for context_field in ('compiler_sha256',):
                changed = {**context, context_field: '0' * 64}
                with self.assertRaises(ValueError):
                    reader.compile_originals(folder, manifest, receipt, changed)
            widened = deepcopy(receipt)
            widened['limits']['cpu_seconds'] = 11
            (folder / 'core-compare.receipt.json').write_text(json.dumps(widened))
            (folder / 'core-compare.stdout.log').write_text(json.dumps({key: item for key, item in widened.items() if key not in added}))
            with self.assertRaises(ValueError):
                reader.compile_originals(folder, manifest, widened, context)

    def test_actual_return_reader_rejects_attempt_only_duplicate_and_boolean_rows(self):
        baseline = json.loads(BASELINE.read_bytes())
        groups = {test: label for label, ids in baseline['original116'].items() for test in ids}
        image = 'a' * 64
        effects = [dict(group=label, test=next(test for test, group in groups.items() if group == label),
                        operation=3, image_sha256=image, count=1)
                   for label in ('component', 'original-machine', 'original-core')]
        value = {'native_step_semantics': reader.STEP_MEANING, 'fixture_step_rows_are_not_test_pass': True,
            'retained_builtin_target_entries': [], 'outer_opcode13_attempts': effects,
            'outer_opcode13_eligible': effects, 'outer_opcode13_normal_returns': effects,
            'outer_opcode13_exceptions': [], 'independent_Core_VM_effects_not_native_proof': [],
            'eligible_normal_returns': effects, 'eligible_exceptions': [],
            'eligible_exception_terminal_returns': [],
            'actual_numeric_step_returns': [dict(row, status=0) for row in effects]}
        self.assertTrue(reader.validate_returns(value, groups, image))
        changed_values = []
        changed = deepcopy(value); changed['actual_numeric_step_returns'] = []; changed_values.append(changed)
        changed = deepcopy(value); changed['actual_numeric_step_returns'].append(deepcopy(changed['actual_numeric_step_returns'][0])); changed_values.append(changed)
        changed = deepcopy(value); changed['outer_opcode13_eligible'] = []; changed_values.append(changed)
        changed = deepcopy(value); changed['retained_builtin_target_entries'] = [['observed']]; changed_values.append(changed)
        for field in ('status', 'count', 'operation'):
            changed = deepcopy(value); changed['actual_numeric_step_returns'][0][field] = True; changed_values.append(changed)
        changed = deepcopy(value); changed['actual_numeric_step_returns'][0]['image_sha256'] = 'b' * 64; changed_values.append(changed)
        changed = deepcopy(value); changed['outer_opcode13_attempts'].append(deepcopy(effects[0])); changed_values.append(changed)
        for index, changed in enumerate(changed_values):
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.validate_returns(changed, groups, image)

    def test_observer_preserves_binding_get_order_errors_and_forbids_old_builtin(self):
        from hepta import hia_core_lowering_native as outer
        from tools.qualify_hia_core_compare_callers import NumericCallObservation
        events = []
        image = SimpleNamespace(image_sha256='a' * 64)
        class SyntheticSession:
            def __init__(self, operation):
                self.image, self.operation = image, operation
            def step(self, packet):
                events.append(('synthetic-return', 0))
                return 0
        primitive = SimpleNamespace(NumericCompareSession=SyntheticSession)
        class Companion:
            _admitted_compare = object()
            def __init__(self):
                self.image = image
                self.call_retained = False
            def compare(self, operation, left, right):
                if self.call_retained:
                    return operator.lt(left, right)
                SyntheticSession(operation).step(b'not a native packet')
                return True
        companion = Companion()
        session = object.__new__(outer.LoweringSession)
        session.owner = SimpleNamespace(numeric_compare=companion)
        session.pending = False
        class Registry(dict):
            def __getitem__(self, key):
                events.append(('target', key))
                return super().__getitem__(key)
        registry = Registry(outer._COMPARE)
        def get(handle):
            events.append(('get', handle))
            if handle == 1:
                registry[3] = lambda left, right: (_ for _ in ()).throw(AssertionError('rebound target used'))
            return {1: 2, 2: 3}[handle]
        session.value = get
        name = 'tests.synthetic.CoreLoweringSourceTests.test_case'
        observation = NumericCallObservation(outer, primitive, {name: 'component'})
        observation.current_test[:] = [name, 'component']
        with patch.object(outer, '_COMPARE', registry), observation.observe():
            self.assertEqual(session._primitive(13, (3, 1, 2), ()), (0, (True,)))
            self.assertEqual(events, [('target', 3), ('get', 1), ('get', 2), ('synthetic-return', 0)])
            self.assertEqual(sum(observation.returns.values()), 1)
            events.clear(); registry[3] = operator.lt
            failure = KeyboardInterrupt('original operand exception')
            def failing(handle):
                events.append(('get', handle))
                raise failure
            session.value = failing
            with self.assertRaises(KeyboardInterrupt) as caught:
                session._primitive(13, (3, 1, 2), ())
            self.assertIs(caught.exception, failure)
            self.assertEqual(events, [('target', 3), ('get', 1)])
            events.clear(); registry[3] = operator.lt; session.value = lambda handle: (2, 3)[handle - 1]
            companion.call_retained = True
            with self.assertRaisesRegex(AssertionError, 'retained builtin'):
                session._primitive(13, (3, 1, 2), ())
            self.assertEqual(len(observation.retained), 1)
            class Foreign(int):
                def __lt__(self, other):
                    return 'foreign result remains uncoerced'
            session.value = lambda handle: (Foreign(2), 3)[handle - 1]
            self.assertEqual(session._primitive(13, (3, 1, 2), ()), (0, ('foreign result remains uncoerced',)))
        self.assertIsNone(sys.getprofile())

    def test_original32_full18_full116_and_owned_environment_remain_required(self):
        from tools import hia_core_unpack_gates as unpack
        from tools import hia_compiler_owner_gates as core
        from tools import hia_selfhost_contract as contract
        baseline = json.loads(BASELINE.read_bytes())
        self.assertEqual(list(unpack.SUCCESSOR_GATES), baseline['original32'])
        self.assertEqual(len(core.SUCCESSOR_GATES), 30)
        self.assertEqual(len(unpack.SUCCESSOR_GATES), 32)
        self.assertTrue(unpack.require_successor_gates(dict.fromkeys(unpack.SUCCESSOR_GATES, True)))
        for missing in unpack.SUCCESSOR_GATES:
            value = dict.fromkeys(unpack.SUCCESSOR_GATES, True); value.pop(missing)
            with self.assertRaises(ValueError):
                unpack.require_successor_gates(value)
        caller = ROOT / 'tools/qualify_hia_core_lowering_callers.py'
        actual = {'component': assignment(caller, 'COMPONENT_IDS'),
                  'original-machine': assignment(caller, 'ORIGINAL_IDS'),
                  'original-core': assignment(caller, 'CORE_IDS')}
        self.assertEqual(actual, baseline['original116'])
        self.assertEqual([len(actual[name]) for name in ('component', 'original-machine', 'original-core')], [15, 51, 50])
        self.assertEqual(unpack.FINITE_IDS['shim'], baseline['original18']['shim'])
        self.assertEqual(unpack.FINITE_IDS['finite-native'], baseline['original18']['finite-native'])
        self.assertEqual(unpack.expected_component_ids(), baseline['original18']['ordinary'])
        for name, digest in unpack.FINITE_PINS.items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        wrapper = ast.parse((ROOT / 'tools/qualify_hia_core_compare_callers.py').read_bytes())
        main = functions(wrapper)['main']
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == 'unpack.main']
        self.assertEqual(len(calls), 1)
        unchanged = ast.parse((ROOT / 'tools/qualify_hia_core_unpack_callers.py').read_bytes())
        original_calls = [node for node in ast.walk(functions(unchanged)['main']) if isinstance(node, ast.Call)
                          and ast.unparse(node.func) == 'original.main']
        self.assertEqual(len(original_calls), 1)
        adapter = (ROOT / 'tools/qualify_hia_core_unpack_ci.py').read_text()
        self.assertIn('qualification_seconds=180, cleanup_seconds=3', adapter)
        self.assertIn("name.endswith(('_MANIFEST', '_BUNDLE'))", adapter)
        self.assertNotIn('HEPTA_HIA_CORE_COMPARE_MANIFEST', adapter)
        declared = set(contract.SOURCE_FILES)
        for name in ('tools/hia_core_companion_arguments.py', 'tools/hia_core_compare_qualification.py',
                     'tools/qualify_hia_core_compare_callers.py', 'tests/test_hia_core_compare_source.py',
                     'tests/test_hia_core_compare_integration.py', 'hepta/hia_core_compare_abi.json',
                     'examples/hia_bootstrap/core_compare.hiaasm'):
            self.assertIn(name, declared)
        ledger = json.loads((ROOT / 'docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json').read_bytes())
        self.assertEqual(ledger['complete_component_methods'], 18)
        self.assertEqual(ledger['complete_original_callers'], 116)
        self.assertEqual(ledger['limits']['phase_qualification_seconds'], 180)
        self.assertEqual(ledger['limits']['phase_cleanup_seconds'], 3)


if __name__ == '__main__':
    unittest.main()
