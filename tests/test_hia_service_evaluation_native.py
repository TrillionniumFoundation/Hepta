"""Nine exact evaluation bodies, native permissions and foreign ownership."""
from __future__ import annotations
import ast
from contextlib import ExitStack
import ctypes
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_agent_service as api
from hepta import hia_service_evaluation_native as native
from hepta import hia_machine_plan_control_native as transport
from tests import hia_service_evaluation_fixtures as fixtures

ROOT = Path(__file__).resolve().parents[1]


class ServiceEvaluationSourceTests(unittest.TestCase):
    def test_literal_ports_borrow_only_original_noncell_named_operands(self):
        from tools.generate_hia_service_evaluation import program
        from tools.hia_machine_plan_control import OPS
        policy = program()
        counts = {'item': 0, 'named_item': 0, 'named_attr': 0, 'compare': 0, 'dict': 0}
        for function in policy.functions:
            for row in function.instructions:
                if row['kind'] != 'effect':
                    continue
                op, raw, args = row['opcode'], row['raw'], row['arguments']
                if op == OPS['ITEM'] and raw:
                    self.assertIn(len(raw), (1, 3))
                    self.assertEqual(len(args), 1)
                    self.assertIn(type(policy.literals[raw[0]]), (str, int, bool, type(None)))
                    counts['item'] += 1
                if ((op == OPS['ITEM'] or op == OPS['ATTR']) and len(raw) == 3):
                    self.assertEqual(len(args), 1)
                    slot = args[0].slot
                    self.assertNotIn(slot, function.temporary_slots)
                    self.assertNotIn(slot, function.cell_slots)
                    self.assertEqual(function.read_kinds[slot], (policy.literals[raw[1]], 0))
                    self.assertEqual(raw[2], 0)
                    self.assertEqual(row['consume'], [])
                    counts['named_item' if op == OPS['ITEM'] else 'named_attr'] += 1
                if op == OPS['COMPARE'] and len(raw) == 2:
                    self.assertEqual(len(args), 1)
                    self.assertIn(type(policy.literals[raw[1]]), (str, int, bool, type(None)))
                    counts['compare'] += 1
                if op == OPS['PACK'] and len(raw) > 1:
                    self.assertEqual(raw[0], 4)
                    self.assertTrue(all(type(policy.literals[index]) is str for index in raw[1:]))
                    self.assertEqual(args, [])
                    self.assertEqual(len(row['vector']), len(raw) - 1)
                    counts['dict'] += 1
        self.assertTrue(all(value > 0 for value in counts.values()), counts)

    def test_import_template_generation_rejects_unreviewed_or_ambiguous_ports(self):
        from tools.generate_hia_native_build_foreign import IMPORT_SUPPORT
        from tools.generate_hia_service_evaluation_foreign import (
            LEGACY_IMPORT_FROM, MOVED_IMPORT_FROM, reviewed_import_support)
        self.assertEqual(sha256(LEGACY_IMPORT_FROM.encode()).hexdigest(),
                         '932b0793594c138d9f83eb87a91dad666e23028212a68c5ed819037639af7289')
        self.assertEqual(sha256(MOVED_IMPORT_FROM.encode()).hexdigest(),
                         '2df0e57cd9a985e7236f40f0768aa9ceb91dcc54ec9384bc012b8c6e2e0065fd')
        normalized = reviewed_import_support(IMPORT_SUPPORT)
        self.assertIn(MOVED_IMPORT_FROM, normalized)
        self.assertEqual(reviewed_import_support(normalized), normalized)
        self.assertEqual(reviewed_import_support(LEGACY_IMPORT_FROM), MOVED_IMPORT_FROM)
        for invalid in (MOVED_IMPORT_FROM.replace('co_stacksize=2', 'co_stacksize=3'),
                        MOVED_IMPORT_FROM + LEGACY_IMPORT_FROM, ''):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    reviewed_import_support(invalid)

    def test_definition_time_helper_anchors_and_unreviewed_cleanup_regions(self):
        from hepta import hia_agent_store
        from tools.hia_service_evaluation_control import compile_policy
        self.assertIs(api._NATIVE_EVALUATION_PUBLIC_ENTRIES[0],
                      hia_agent_store._NATIVE_EVALUATION_CONNECTION_ARGUMENTS)
        self.assertIs(api._NATIVE_EVALUATION_PUBLIC_ENTRIES[1], api._value_observation)
        self.assertIs(hia_agent_store._NATIVE_EVALUATION_CONNECTION_ARGUMENTS,
                      hia_agent_store._connection_arguments)
        source = (ROOT/'tools/hia_service_evaluation_policy.py').read_text()
        tree = ast.parse(source)
        self.assertEqual(sum(isinstance(node, ast.For) for node in ast.walk(tree)), 6)
        self.assertEqual(sum(isinstance(node, ast.Break) for node in ast.walk(tree)), 5)
        self.assertEqual(sum(isinstance(node, ast.Continue) for node in ast.walk(tree)), 2)
        self.assertFalse(any(isinstance(node, (ast.With, ast.Try, ast.TryStar))
                             for node in ast.walk(tree)))
        shapes = ('for item in items:\n    with manager:\n        break',
                  'for item in items:\n    with manager:\n        continue',
                  'for item in items:\n    try:\n        break\n    finally:\n        cleanup()',
                  'for item in items:\n    try:\n        continue\n    finally:\n        cleanup()',
                  'for item in items:\n    try:\n        invoke()\n    except Exception:\n        break')
        for shape in shapes:
            with self.subTest(shape=shape):
                with self.assertRaisesRegex(ValueError, 'no reviewed context or exception region'):
                    compile_policy(source+'\n'+shape+'\n')

    def test_original_nine_bodies_are_preserved_without_policy_changes(self):
        retained = json.loads(fixtures.ORIGINAL.read_bytes())
        self.assertEqual(sha256(fixtures.ORIGINAL.read_bytes()).hexdigest(), fixtures.ORIGINAL_SHA)
        service = next(node for node in ast.parse((ROOT/'hepta/hia_agent_service.py').read_bytes()).body
                       if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
        author = ast.parse((ROOT/'tools/hia_service_evaluation_policy.py').read_bytes())
        cls = next(node for node in author.body if isinstance(node, ast.ClassDef))
        for name, row in retained['methods'].items():
            expected = ast.parse(row['source']).body[0]
            original = next(node for node in service.body if isinstance(node, ast.FunctionDef) and node.name == name+'_reference')
            original.name = name
            emitted = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(ast.dump(original), ast.dump(expected))
            self.assertEqual(ast.dump(emitted), ast.dump(expected))
        for name, row in retained['helpers'].items():
            actual = next(node for node in author.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(ast.dump(actual), ast.dump(ast.parse(row['source']).body[0]))
        self.assertEqual(tuple(native.ARITIES), tuple(retained['methods'])+tuple(retained['helpers']))

    def test_complete_real_hia_and_foreign_bytes_regenerate_under_original_limits(self):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_program import verify_core
        from tools.generate_hia_service_evaluation import document, program
        from tools.generate_hia_service_evaluation_foreign import source
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        doc = document()
        verify_core(doc)
        self.assertEqual(render_assembly(doc).encode(), native.SOURCE.read_bytes())
        self.assertEqual(source().encode(), (ROOT/'hepta/hia_service_evaluation_foreign.py').read_bytes())
        self.assertLessEqual(len(doc['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in doc['functions'] for block in fn['blocks']), 16)
        policy = program()
        self.assertEqual(tuple(fn.name for fn in policy.functions[:9]), tuple(native.ARITIES))
        self.assertTrue(any(fn.kind == 'lambda' for fn in policy.functions))
        self.assertTrue(any(fn.kind == 'generator' for fn in policy.functions))
        self.assertTrue(any(fn.name.split(':')[1:2] == ['function'] for fn in policy.functions))

    def test_runtime_contains_only_fixed_ports_and_registered_held_identity(self):
        for path in ('hepta/hia_service_evaluation_native.py', 'hepta/hia_service_evaluation_foreign.py'):
            tree = ast.parse((ROOT/path).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith(('tools', 'tests')))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ('exec', 'eval', 'compile'))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {name+'_reference' for name in fixtures.METHODS})
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS, NATIVE_OWNERS, MECHANISM_SOURCE_FILES
        expected = ('hia_service_evaluation_native', 'NativeEvaluationImage')
        self.assertEqual(HELPERS[native.SELECTOR], expected)
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR], expected)
        self.assertNotIn(native.SELECTOR, NATIVE_OWNERS)
        self.assertTrue({'hia_service_evaluation_native.py', 'hia_service_evaluation_foreign.py'} <= set(MECHANISM_SOURCE_FILES))

    def test_binary64_literal_identity_and_sign_bits_are_distinct(self):
        from tools.generate_hia_service_evaluation import program, table
        p = program()
        positive, negative = p.literal(0.0), p.literal(-0.0)
        self.assertNotEqual(positive, negative)
        self.assertEqual(p.literal(0.0), positive)
        self.assertEqual(p.literal(-0.0), negative)
        raw = table(p)
        offsets = struct.unpack_from('<Q', raw, 48)[0]
        for index, expected in ((positive, b'\0'*8), (negative, b'\0'*7+b'\x80')):
            at = struct.unpack_from('<I', raw, offsets+4*index)[0]
            self.assertEqual(struct.unpack_from('<BQ', raw, at), (6, 8))
            self.assertEqual(raw[at+9:at+17], expected)

    def test_original_deadline_and_publication_order_remain_in_exact_author(self):
        source = json.loads(fixtures.ORIGINAL.read_bytes())
        body = source['methods']['_hia_evaluate']['source']
        self.assertLess(body.index('context_deadline = int(context_row["created_ns"])'), body.index('def remaining_total_ms'))
        self.assertLess(body.index('budget_claim ='), body.index('budget_claim.complete()'))
        self.assertLess(body.index('budget_claim.complete()'), body.index('measurements = self.store.json'))
        self.assertLess(body.index('measurements = self.store.json'), body.index('ledger = self.store.json'))
        self.assertLess(body.index('ledger = self.store.json'), body.index('receipt = self.store.json'))
        costs = source['methods']['_cost_ledger']['source']
        self.assertLess(costs.index('LIMIT 10001'), costs.index('len(rows) > 10000'))
        self.assertLess(costs.index('len(rows) > 10000'), costs.index('rows[:10000]'))

    def test_invalid_selected_manifest_refuses_before_store_or_catalog(self):
        with tempfile.TemporaryDirectory(prefix='hia-evaluation-invalid-') as directory:
            state = Path(directory)/'never'
            env = {key: '' for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')}
            env[native.SELECTOR] = str(Path(directory)/'missing')
            with patch.dict(os.environ, env), patch.object(api, 'catalog', side_effect=AssertionError('catalog entered')):
                with self.assertRaises(OSError):
                    api.HIAAgentService(state)
            self.assertFalse(state.exists())


class ServiceEvaluationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import build_hia_service_evaluation as builder
        cold = os.environ.get('HEPTA_HIA_SERVICE_EVALUATION_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_SERVICE_EVALUATION_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_SERVICE_EVALUATION_DEVELOPMENT_MANIFEST')
        if sum(bool(value) for value in (cold, compiler_choice, manifest_choice)) != 1:
            raise ValueError('service evaluation requires one explicit cold, development compiler, or development manifest selection')
        cls.inputs = {}
        if cold:
            cold = Path(cold).resolve(); cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes, object_pairs_hook=builder._pairs)
            try:
                nested = Path(report['nested_report']); nested_bytes = nested.read_bytes()
                compiler = Path(json.loads(nested_bytes)['generations'][-1]['produced_image']).resolve()
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('service-evaluation cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = builder.admit_cold_build(compiler_bytes, cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int or report['qualification_wall_limit_seconds'] != 180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int or report['cleanup_wall_limit_seconds'] != 3
                    or any(sources.get(name) != sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('service-evaluation fixture requires complete original-limit current cold source')
            cls.inputs.update({str(cold): sha256(cold_bytes).hexdigest(), str(nested): sha256(nested_bytes).hexdigest(),
                               str(compiler): sha256(compiler_bytes).hexdigest()})
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_SERVICE_EVALUATION_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-evaluation-native-')
            cls.folder = Path(cls.temporary.name)
        if cold:
            cls.manifest_path = builder.build(cls.folder / 'current-cold-build', compiler, cold)
            mode = 'MATCHING_CURRENT_SOURCE_COLD'
        elif compiler_choice:
            compiler = Path(compiler_choice).resolve()
            cls.manifest_path = builder.build_development(cls.folder / 'development-build', compiler)
            cls.inputs[str(compiler)] = sha256(compiler.read_bytes()).hexdigest()
            mode = 'EXPLICIT_COMPILER_DEVELOPMENT'
        else:
            cls.manifest_path = Path(manifest_choice).resolve(); mode = 'EXPLICIT_MANIFEST_DEVELOPMENT'
        raw = cls.manifest_path.read_bytes()
        record = json.loads(raw, object_pairs_hook=builder._pairs)
        cls.image = native.installed_evaluation(cls.manifest_path)
        cls.inputs.update({str(cls.manifest_path): sha256(raw).hexdigest(),
                           str(cls.manifest_path.parent / record['image_path']): record['image_sha256']})
        cls.inputs.update({str(ROOT / name): sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES})
        cls.entries = {}; cls.original_entry = cls.image._entry
        def counted(source, size, output, capacity, work, extent):
            result = cls.original_entry(source, size, output, capacity, work, extent)
            if size == len(cls.image.table) and extent == cls.image.workspace_bytes:
                mode = str(struct.unpack_from('<Q', ctypes.string_at(work, extent), 152)[0])
                cls.entries[mode] = cls.entries.get(mode, 0) + 1
            return result
        cls.image._entry = counted
        (cls.folder / 'fixture.json').write_text(json.dumps({'mode': mode, 'inputs': cls.inputs,
            'manifest_path': str(cls.manifest_path), 'current_source_cold': bool(cold),
            'whole_stack_native': False, 'python': sys.version}, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        cls.image._entry = cls.original_entry
        after = {name: sha256(Path(name).read_bytes()).hexdigest() for name in cls.inputs}
        (cls.folder / 'actual-entries.json').write_text(json.dumps(cls.entries, indent=2) + '\n')
        (cls.folder / 'input-after.json').write_text(json.dumps(after, indent=2) + '\n')
        if after != cls.inputs:
            raise AssertionError('held evaluation inputs changed')
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def record(self, name, value):
        (self.folder / (name + '.json')).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

    def test_actual_literal_ports_preserve_original_foreign_calls(self):
        seen = set()
        original = self.image._entry
        def observe(source, size, output, capacity, work, extent):
            result = original(source, size, output, capacity, work, extent)
            if size == len(self.image.table) and result == 1:
                words = struct.unpack('<10Q', ctypes.string_at(output, 80))
                op, nr = words[4], words[7]
                if (op in (3, 4) and nr == 3 or op == 4 and nr == 1
                        or op == 6 and nr == 2 or op == 10 and nr > 1):
                    seen.add((op, nr))
            return result
        rows = []
        with patch.object(self.image, '_entry', observe):
            for case in ('native-ok', 'eval-ok', 'claim-error', 'publish-error'):
                expected = fixtures.fixture_call(case)
                actual = fixtures.fixture_call(case, self.image)
                rows.append({'case': case, 'reference': expected, 'native': actual})
                self.record('literal-port-foreign-observations', rows)
                self.assertEqual(actual, expected)
        self.assertIn((3, 3), seen)
        self.assertIn((4, 3), seen)
        self.assertIn((6, 2), seen)
        self.assertTrue(any(op == 10 and nr > 1 for op, nr in seen))
        self.record('literal-port-actual-shapes', sorted(seen))

    def test_literal_item_comparison_and_dictionary_error_lifetimes(self):
        rows = []
        def observe(selected, failure, outer):
            events, owners = [], []
            def handled():
                return None if sys.exception() is None else type(sys.exception()).__name__
            class Truth:
                def __bool__(self):
                    events.append(['truth', handled()])
                    if failure == 'truth':
                        raise LookupError('truth')
                    return True
                def __del__(self):
                    events.append(['truth-del', handled()])
            class Status:
                def __eq__(self, other):
                    events.append(['compare', other, handled()])
                    if failure == 'compare':
                        raise LookupError('compare')
                    return Truth()
                def __del__(self):
                    events.append(['status-del', handled()])
            class Observation:
                def __init__(self):
                    owners.append(weakref.ref(self))
                def __getitem__(self, key):
                    events.append(['item', key, handled()])
                    if failure == 'item-' + key:
                        raise LookupError('item-' + key)
                    return Status() if key == 'status' else [7]
                def __contains__(self, key):
                    events.append(['contains', key, handled()])
                    if failure == 'contains':
                        raise LookupError('contains')
                    return True
                def __del__(self):
                    events.append(['observation-del', handled()])
            def invoke():
                if selected:
                    frame = self.image.prepare('_value_observation', (Observation(),))
                    return self.image.finish(frame)
                return fixtures.REFERENCE['_value_observation'](Observation())
            def capture():
                try:
                    return invoke(), None
                except BaseException as error:
                    return None, error
            def run():
                value, error = capture()
                before = {'value': value,
                          'error': None if error is None else [type(error).__name__, list(error.args)],
                          'alive': owners[0]() is not None, 'events': list(events)}
                value = error = None
                return before, {'alive': owners[0]() is not None, 'events': list(events)}
            if outer:
                try:
                    raise ValueError('outer')
                except ValueError:
                    return run()
            return run()
        for failure in (None, 'item-status', 'compare', 'truth', 'item-values', 'contains', 'item-buffers'):
            for outer in (False, True):
                expected, actual = observe(False, failure, outer), observe(True, failure, outer)
                rows.append({'failure': failure, 'outer': outer, 'reference': expected, 'native': actual})
                self.record('literal-port-held-error-lifetimes', rows)
                with self.subTest(failure=failure, outer=outer):
                    self.assertEqual(actual, expected)
                    self.assertFalse(actual[1]['alive'])

    def test_original_import_errors_release_module_while_traceback_is_held(self):
        output = self.folder/'original-import-retirement-18'
        command = [sys.executable, '-I', '-B',
                   str(ROOT/'tests/hia_service_evaluation_import_retirement_probe.py'),
                   '--source', str(ROOT), '--manifest', str(self.manifest_path),
                   '--output', str(output)]
        child = subprocess.run(command, capture_output=True, timeout=60)
        (self.folder/'original-import-retirement-18.stdout').write_bytes(child.stdout)
        (self.folder/'original-import-retirement-18.stderr').write_bytes(child.stderr)
        report = json.loads((output/'REPORT.json').read_bytes())
        self.record('original-import-retirement-18-terminal', {'returncode':child.returncode,
            'command':command,'report_sha256':sha256((output/'REPORT.json').read_bytes()).hexdigest()})
        self.assertEqual(child.returncode, 0, child.stderr.decode())
        self.assertEqual(report['cases'], 18)
        self.assertEqual(report['equal'], 18)
        self.assertEqual(report['status'], 'PASS')
        self.assertTrue(report['inputs_unchanged'])
        self.assertFalse(report['garbage_collection_used'])
        self.assertTrue(all(row['actual_entries'] > 0 for row in report['observations']))
        for row in report['observations']:
            with self.subTest(family=row['family'], module=row['module'], missing=row['missing'], outer=row['outer']):
                self.assertEqual(row['native'], row['reference'])
                self.assertEqual(row['reference']['while_error_held']['alive'], [False])
                self.assertEqual(row['native']['while_error_held']['alive'], [False])
                if row['missing'] is not None:
                    self.assertEqual(row['reference']['result']['type'], 'ImportError')

    def test_original_pre_and_post_admission_helper_binding_matrix(self):
        output = self.folder/'helper-binding-original-24'
        command = [sys.executable, '-I', '-B', str(ROOT/'tests/hia_service_evaluation_binding_probe.py'),
                   '--source', str(ROOT), '--manifest', str(self.manifest_path), '--output', str(output)]
        child = subprocess.run(command, capture_output=True, timeout=60)
        (self.folder/'helper-binding-original-24.stdout').write_bytes(child.stdout)
        (self.folder/'helper-binding-original-24.stderr').write_bytes(child.stderr)
        report = json.loads((output/'REPORT.json').read_bytes())
        self.record('helper-binding-original-24-terminal', {'returncode':child.returncode,
            'command':command,'report_sha256':sha256((output/'REPORT.json').read_bytes()).hexdigest()})
        self.assertEqual(child.returncode, 0, child.stderr.decode())
        self.assertEqual(report['case_count'], 24)
        self.assertEqual(report['equal_count'], 24)
        self.assertEqual(report['status'], 'PASS')
        self.assertIsNone(report['exception'])
        self.assertTrue(report['input_bytes_unchanged'])
        self.assertTrue(all(row['equal'] and row['native_observed'] for row in report['cases']))

    def test_store_definition_anchor_predates_service_import(self):
        rows = []
        for kind in ('original', 'function', 'none', 'object', 'absent', 'object_metadata_error'):
            observed = []
            for selected in (False, True):
                output = self.folder/('store-before-import-'+kind+'-'+str(selected)+'.json')
                command = [sys.executable, '-I', '-B', str(ROOT/'tests/hia_service_evaluation_import_probe.py'),
                           '--source', str(ROOT), '--manifest', str(self.manifest_path),
                           '--kind', kind, '--selected', str(int(selected)), '--output', str(output)]
                child = subprocess.run(command, capture_output=True, timeout=60)
                output.with_suffix('.stdout').write_bytes(child.stdout)
                output.with_suffix('.stderr').write_bytes(child.stderr)
                self.assertEqual(child.returncode, 0, child.stderr.decode())
                report = json.loads(output.read_bytes())
                self.assertTrue(report['inputs_unchanged'])
                observed.append(report)
            reference, actual = observed
            row = {'kind':kind,'reference':reference,'native':actual}
            rows.append(row)
            with self.subTest(kind=kind):
                self.assertEqual(actual['observation'], reference['observation'])
                if kind != 'absent':
                    self.assertGreater(actual['actual_native_entries'], 0)
                    self.assertTrue(actual['original_definition_anchor'])
                else:
                    self.assertEqual(actual['actual_native_entries'], 0)
                    self.assertEqual(actual['observation']['import_error']['type'], 'ImportError')
        self.record('store-before-service-import-12', rows)

    def test_original_loop_break_continue_and_held_iterator_lifetimes(self):
        rows = []
        for case in ('normal', 'incomplete', 'native-budget', 'next-error'):
            for outer in (False, True):
                expected = fixtures.loop_lifetime_observation(case, outer)
                before = self.image.entries
                actual = fixtures.loop_lifetime_observation(case, outer, self.image)
                row = {'case':case,'outer':outer,'reference':expected,'native':actual,
                       'actual_entries':self.image.entries-before}
                rows.append(row)
                with self.subTest(case=case, outer=outer):
                    self.assertGreater(row['actual_entries'], 0)
                    self.assertEqual(actual, expected)
                    self.assertEqual(expected['after_release']['alive'], [False])
                    self.assertEqual(len(expected['after_release']['drops']), 1)
                    if case == 'next-error':
                        self.assertEqual(expected['before_release']['alive'], [True])
                        self.assertTrue(expected['error']['original_failure'])
        self.record('original-loop-lifetimes-8', rows)


    def test_complete_nine_entry_provider_corpus_and_error_publication_order(self):
        rows = []
        for case in fixtures.CASES:
            expected = fixtures.fixture_call(case)
            before = self.image.entries
            actual = fixtures.fixture_call(case, self.image)
            rows.append({'case': case, 'reference': expected, 'native': actual,
                         'actual_entries': self.image.entries-before})
            with self.subTest(case=case):
                self.assertGreater(rows[-1]['actual_entries'], 0)
                self.assertEqual(actual, expected)
                if case == 'claim-error':
                    self.assertFalse(actual['claim_complete'])
                    self.assertEqual(actual['publications'], [])
                if case == 'publish-error':
                    self.assertTrue(actual['claim_complete'])
                    self.assertEqual(actual['publications'], [])
        for connection in (None, object()):
            self.assertEqual(self.image.run('_connection_arguments', connection),
                             fixtures.REFERENCE['_connection_arguments'](connection))
        for observation in ({'status': 'returned', 'values': [3]},
                            {'status': 'trapped', 'buffers': []}):
            self.assertEqual(self.image.run('_value_observation', observation),
                             fixtures.REFERENCE['_value_observation'](observation))
        self.assertEqual(len(rows), 24)
        self.assertTrue({str(mode) for mode in range(1,10)} <= set(self.entries))
        self.record('nine-entry-provider-24', rows)

    def test_helpers_selected_by_hia_never_execute_the_retained_body(self):
        original = {name: fixtures.REFERENCE[name].__code__ for name in ('_connection_arguments', '_value_observation')}
        def forbidden(value):
            raise AssertionError('retained helper entered')
        saved = {name: getattr(api, name).__code__ for name in original}
        try:
            for name in original:
                getattr(api, name).__code__ = forbidden.__code__
            actual = fixtures.fixture_call('eval-ok', self.image)
            self.assertIsNone(actual['error'])
            self.assertEqual([row[0] for row in actual['publications']],
                             ['measurements', 'cost-ledger', 'evaluation-receipt'])
        finally:
            for name, code in saved.items():
                getattr(api, name).__code__ = code

    def test_binary64_from_actual_emitted_table_has_one_object_per_index(self):
        rows = []
        for index in range(self.image._literal_count):
            at = struct.unpack_from('<I', self.image.table, self.image._literal_offsets+4*index)[0]
            kind, size = struct.unpack_from('<BQ', self.image.table, at)
            if kind == 6:
                self.assertEqual(size, 8)
                value = self.image.literal(index)
                self.assertIs(type(value), float)
                self.assertIs(self.image.literal(index), value)
                self.assertEqual(struct.pack('<d', value), self.image.table[at+9:at+17])
                rows.append({'index': index, 'bits': struct.pack('<d', value).hex()})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['bits'], '0000000000000000')
        self.record('binary64-emitted-literals', rows)

    def test_exact_issued_frame_identity_and_lost_ack_never_replay_effect(self):
        class Observation(dict):
            calls = 0
            def __getitem__(self, name):
                self.calls += 1
                return super().__getitem__(name)
        value = Observation(status='returned', values=[3])
        frame = self.image.prepare('_value_observation', (value,))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        with self.assertRaises(RuntimeError):
            frame.service(replace(issued))
        self.assertEqual(value.calls, 0)
        while struct.unpack_from('<Q', frame.pending.raw, 32)[0] != 4:
            frame.service(frame.pending)
            self.assertEqual(frame.step(), 1)
        issued = frame.pending
        frame.service(issued)
        self.assertEqual(value.calls, 1)
        real = frame._invoke
        def lost(command, *args, **kwargs):
            returned = real(command, *args, **kwargs)
            if command == 1:
                raise KeyboardInterrupt('lost ACK after real HIA return')
            return returned
        frame._invoke = lost
        with self.assertRaises(KeyboardInterrupt):
            frame.step()
        before = self.image.entries
        for call in (frame.step, frame.drive, frame.take, lambda: frame.service(issued)):
            with self.assertRaises(RuntimeError):
                call()
        self.assertEqual(self.image.entries, before)
        self.assertEqual(value.calls, 1)
        self.assertTrue(frame._uncertain)
        self.record('real-lost-ack', {'actual_entries': before, 'getitem_calls': value.calls,
                                   'uncertain': frame._uncertain, 'replay_calls': 4})

    def test_helper_lifetimes_outer_exception_and_held_original_error(self):
        rows = []
        def observe(selected, fail, outer):
            events, weak = [], []
            class Observation:
                def __init__(self):
                    weak.append(weakref.ref(self))
                def __getitem__(self, name):
                    events.append(['get', name, type(sys.exception()).__name__ if sys.exception() else None])
                    if fail:
                        raise LookupError('original observation')
                    return 'returned' if name == 'status' else [3]
                def __contains__(self, name):
                    return False
                def __del__(self):
                    events.append(['del', type(sys.exception()).__name__ if sys.exception() else None])
            def invoke():
                if not selected:
                    return fixtures.REFERENCE['_value_observation'](Observation())
                frame = self.image.prepare('_value_observation', (Observation(),))
                return self.image.finish(frame)
            def capture():
                try:
                    return invoke(), None
                except BaseException as error:
                    return None, error
            def run():
                value, error = capture()
                held = {'value': value, 'error': None if error is None else [type(error).__name__, list(error.args)],
                        'alive': weak[0]() is not None, 'events': list(events)}
                value = error = None
                return held, {'alive': weak[0]() is not None, 'events': list(events)}
            if outer:
                try:
                    raise ValueError('outer')
                except ValueError:
                    result = run()
            else:
                result = run()
            return result
        for fail in (False, True):
            for outer in (False, True):
                expected, actual = observe(False, fail, outer), observe(True, fail, outer)
                rows.append({'fail': fail, 'outer': outer, 'reference': expected, 'native': actual})
                self.assertEqual(actual, expected)
                self.assertFalse(actual[1]['alive'])
        self.record('helper-held-error-lifetimes', rows)

    def test_foreign_namespace_rebinding_is_observed_at_original_point(self):
        original = self.image.namespace['_value_observation']
        events = []
        def foreign(value):
            events.append(value['status'])
            return {'status': value['status'], 'values': value.get('values', [])}
        with patch.object(api, '_value_observation', foreign):
            actual = fixtures.fixture_call('eval-ok', self.image)
        self.assertIs(self.image.namespace['_value_observation'], original)
        self.assertIsNone(actual['error'])
        self.assertGreater(len(events), 0)
        self.record('explicit-global-rebinding', {'calls': events, 'result': actual})

    def test_independent_vm_complete_error_retirement_frames_all_modes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(native.SOURCE.read_bytes())
        function = checked.as_dict()['functions'][0]
        rows = []
        for mode in range(1, self.image.function_count+1):
            state = bytearray(self.image.workspace_bytes)
            output = bytearray(b'\xb7'*2048)
            nonce, count = 7000+mode, 0
            def call(command, flag=0, error=0, op=0):
                nonlocal count
                sequence = int.from_bytes(state[144:152], 'little')
                struct.pack_into('<6Q', state, 0, command, nonce, sequence,
                    mode if command == 0 else op if command == 2 else flag, error, self.image.runtime_profile)
                raw = self.image.table
                src = ctypes.create_string_buffer(raw+b'\xa5'*16, len(raw)+16)
                out = ctypes.create_string_buffer(bytes(output)+b'\xb7'*16, len(output)+16)
                work = ctypes.create_string_buffer(bytes(state)+b'\xc9'*16, len(state)+16)
                actual = self.image._entry(src,len(raw),out,len(output),work,len(state))
                owners = [_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(state))]
                expected = _Machine(checked,10000000,16<<20,None,128).invoke(function,
                    [_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                self.assertEqual(actual,expected)
                self.assertEqual(out.raw[:len(output)],bytes(owners[1].data))
                self.assertEqual(work.raw[:len(state)],bytes(owners[2].data))
                self.assertEqual(src.raw,raw+b'\xa5'*16)
                self.assertEqual(out.raw[len(output):],b'\xb7'*16)
                self.assertEqual(work.raw[len(state):],b'\xc9'*16)
                output[:],state[:]=owners[1].data,owners[2].data
                count+=1
                return actual
            self.assertEqual(call(0),1)
            self.assertEqual(call(2,op=int.from_bytes(output[32:40],'little')),4)
            status=call(1,error=1)
            while status==1:
                self.assertIn(int.from_bytes(output[32:40],'little'),(2,16,21,28))
                self.assertEqual(call(2,op=int.from_bytes(output[32:40],'little')),4)
                status=call(1)
                self.assertLess(count,4096)
            self.assertEqual(status,3)
            status=call(4)
            while status==1:
                self.assertIn(int.from_bytes(output[32:40],'little'),(16,28))
                self.assertEqual(call(2,op=int.from_bytes(output[32:40],'little')),4)
                status=call(1)
                self.assertLess(count,4096)
            self.assertEqual(status,5)
            rows.append({'mode':mode,'frames':count,'output_sha256':sha256(output).hexdigest(),
                         'workspace_sha256':sha256(state).hexdigest(),'full_buffers_equal':True})
        self.record('vm-native-all-modes-error-retirement',rows)

    def test_actual_capture_identity_drift_refuses_new_selection_but_preserves_held(self):
        from hepta.hia_checker_identity import checker_native_selection
        held=native.installed_evaluation(self.manifest_path,capture_identity=True)
        a=checker_native_selection(held_owners=(held,))
        raw=self.manifest_path.read_bytes()
        try:
            self.manifest_path.write_bytes(raw+b'changed')
            with self.assertRaises((ValueError,json.JSONDecodeError)):
                native.installed_evaluation(self.manifest_path)
            self.assertEqual(checker_native_selection(held_owners=(held,)),a)
            with self.assertRaises(ValueError):
                checker_native_selection(held_owners=(a[native.SELECTOR],))
            with self.assertRaises(ValueError):
                checker_native_selection(held_owners=(held,held))
        finally:
            self.manifest_path.write_bytes(raw)
        self.assertEqual(self.image.run('_connection_arguments',None),{})
        self.record('actual-held-identity',a)
