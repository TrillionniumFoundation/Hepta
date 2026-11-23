"""Independent original transactions, selected public control, and custody.

The 521 finite original cases are an independently frozen input, not candidate
expectations. SQL/locks and Python's generator ABI remain hosted protocols.
The original 112/61/130 caller scopes run separately from this component.
"""
from __future__ import annotations

import ast
import base64
from collections import Counter
from contextlib import ExitStack, closing
import csv
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import zipfile

from hepta import hia_agent_store as api
from hepta import hia_store_transaction_native as native
from hepta import hia_native_delivery as delivery
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests import hia_store_transaction_oracle as oracle
from tests.hia_store_transaction_scenarios import cases
from tools import generate_hia_store_transaction as generator

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = 'tests/fixtures/hia_store_transaction_original_c019/'
ORIGINAL_FILES = {
    'tests/hia_store_transaction_oracle.py': 'afa2a0cfc72ef5d4e30f56ed44d5febdf726f570f73cf28448d2f074e47017ce',
    'tests/hia_store_transaction_scenarios.py': 'e853b839210c150c2e42712fe73e46dbb0c99b6859e0a1705e7b102223837ed7',
    ORIGINAL + 'transaction.c019.py.txt': '23d89d8ae63bf196203cbd53a5cc8970083470a77fdd16625eb96d618e0a5587',
    ORIGINAL + 'source-identity.json': '19ed5a96773d51eeb96f3db2fce6c1cd17003a0c05eb78e14590033bc229fc5b',
    ORIGINAL + 'cases.json': '494474bdff4c988e1124a8398c3254089da7aedfad46d725f47c67d069de1672',
    ORIGINAL + 'freeze.json': '99d0ec1470b452c1add79c71c4aae752ddb97e22ac4eaa2ceb574fd32cd78e98',
}
CASE_COUNT = 521
COLD = 'HEPTA_HIA_STORE_TRANSACTION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_STORE_TRANSACTION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STORE_TRANSACTION_EVIDENCE'
SOURCE_EVIDENCE = 'HEPTA_HIA_STORE_TRANSACTION_SOURCE_EVIDENCE'
VM_CASES = (
    'normal-with', 'exit-policy-ValueError-token_true',
    'temporary-release-failure-BEGIN-outerTrue',
    'temporary-release-failure-exit-truth-outerTrue',
    'GeneratorExit-throw-token_false-outerTrue',
    'GeneratorExit-throw-token_true-outerTrue',
)
ERROR_TYPES = (ValueError, MemoryError, RuntimeError, KeyboardInterrupt, SystemExit)


def encoded(value):
    return oracle.canonical(value)


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def original_inputs():
    for name, digest in ORIGINAL_FILES.items():
        if sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('independent transaction original differs: ' + name)
    values = cases()
    if len(values) != CASE_COUNT or len({case['id'] for case in values}) != CASE_COUNT:
        raise AssertionError('independent transaction case inventory differs')
    return values


def public_observation(case):
    """Bind fake dynamic globals to the real public module only for this case."""
    missing = object()
    previous = vars(api).get('BaseException', missing)

    def public_factory(store, namespace):
        if 'BaseException' in namespace:
            api.BaseException = namespace['BaseException']
        else:
            vars(api).pop('BaseException', None)
        # The independent oracle's explicit matcher mutations now reach the
        # actual public function globals, with no change to original inputs.
        store.fixture.namespace = vars(api)
        return api.AgentStore.transaction(store)

    try:
        return oracle.observe(case, factory=public_factory)
    finally:
        if previous is missing:
            vars(api).pop('BaseException', None)
        else:
            api.BaseException = previous


def poison(stack):
    def forbidden(*arguments, **keywords):
        raise AssertionError('selected transaction entered its retained Python original')
    forbidden.__wrapped__ = forbidden
    stack.enter_context(patch.object(api, '_STORE_TRANSACTION_REFERENCE', forbidden))
    stack.enter_context(patch.object(api.AgentStore, '_transaction_reference', forbidden))


def vm_call(program, raw, output, state):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(value)) for index, value in enumerate((raw, output, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
                          [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw:
        raise AssertionError('independent VM changed immutable input')
    return code, bytes(owners[1].data), bytes(owners[2].data)


def vm_image(program):
    image = object.__new__(native.NativeStoreTransaction)
    image.image_sha256, image.entry_count = 'independent-vm-no-executable-mapping', 0

    def entry(source, size, output, capacity, state, extent):
        image.entry_count += 1
        code, result, retained = vm_call(program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, result, capacity)
        ctypes.memmove(state, retained, extent)
        return code

    image._entry = entry
    return image


def bundle(path, helpers):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    path.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
        'helpers': [{'selector': selector, 'manifest_path': str(manifest),
                     'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}
                    for selector, manifest in helpers]}) + b'\n')
    return sha256(path.read_bytes()).hexdigest()


class ControlLock:
    def __init__(self, events):
        self.events, self.held = events, False

    def __enter__(self):
        self.events.append('enter')
        self.held = True

    def __exit__(self, kind, error, traceback):
        self.events.append('exit')
        self.held = False
        return False


class ControlDB:
    def __init__(self, events):
        self.events = events

    def execute(self, sql):
        self.events.append(sql)


class ControlStore:
    def __init__(self):
        self.events = []
        self.lock, self.db = ControlLock(self.events), ControlDB(self.events)


class StoreTransactionSourceTests(unittest.TestCase):
    def test_frozen_original_actual_public_binding_and_generated_source(self):
        original_inputs()
        source = ast.parse((ROOT / 'hepta/hia_agent_store.py').read_bytes())
        cls = next(node for node in source.body if isinstance(node, ast.ClassDef)
                   and node.name == 'AgentStore')
        retained = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'transaction')
        original = ast.parse(textwrap.dedent((ROOT / ORIGINAL / 'transaction.c019.py.txt').read_text())).body[0]
        self.assertEqual(ast.dump(retained, include_attributes=False), ast.dump(original, include_attributes=False))
        self.assertIs(api.AgentStore.transaction, api._store_transaction_dispatch)
        self.assertIsNot(api.AgentStore.transaction, api._STORE_TRANSACTION_REFERENCE)
        self.assertIs(api.AgentStore._transaction_reference, api._STORE_TRANSACTION_REFERENCE)
        bindings = [node for node in source.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Attribute) and target.attr == 'transaction'
                            and isinstance(target.value, ast.Name) and target.value.id == 'AgentStore'
                            for target in node.targets)]
        self.assertEqual(len(bindings), 1)
        self.assertEqual(ast.dump(bindings[0].value), ast.dump(ast.Name(id='_store_transaction_dispatch', ctx=ast.Load())))
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        doc = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in doc['functions'] for block in fn['blocks']), 16)
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        for fn in doc['functions']:
            definitions = {value['name'] for value in fn['params']}
            for block in fn['blocks']:
                definitions.update(value['name'] for value in block['params'])
                definitions.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(definitions), 2048)
        from tools.qualify_hia_store_transaction import admit_separate_inventory
        inventory = admit_separate_inventory()
        from tools.run_hia_unittest_gate import load_declared_suite
        suite, planned = load_declared_suite(inventory['modules_in_requested_order'])
        self.assertEqual(list(planned), inventory['ordered_ids'])
        self.assertEqual(suite.countTestCases(), 61)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_store_transaction_native', 'NativeStoreTransaction'))

    def test_independent_VM_original_exception_cleanup_and_GeneratorExit(self):
        values = {case['id']: case for case in original_inputs()}
        expected = {name: oracle.observe(values[name]) for name in VM_CASES}
        program = assemble_program(native.SOURCE.read_bytes())
        with patch.object(native.NativeStoreTransaction, '__init__',
                          side_effect=AssertionError('native mapping before independent VM')):
            image = vm_image(program)
            for name in VM_CASES:
                with self.subTest(case=name):
                    actual = oracle.observe(values[name], factory=lambda store, namespace:
                        native.store_transaction_context(image, store, namespace=namespace))
                    self.assertEqual(encoded(actual), encoded(expected[name]))
            self.assertGreater(image.entry_count, 0)

    def test_complete_unselected_public_originals_and_lazy_empty_refusal(self):
        values = original_inputs()
        expected = [oracle.observe(case) for case in values]
        observations = []
        with patch.dict(os.environ, clean_environment(), clear=True), \
             patch.object(native, 'installed_store_transaction',
                          side_effect=AssertionError('unselected optional native admission')):
            for case, original in zip(values, expected):
                with self.subTest(case=case['id']):
                    actual = public_observation(case)
                    observations.append({'case': case['id'], 'expected': original, 'actual': actual})
                    self.assertEqual(encoded(actual), encoded(original))
        evidence = os.environ.get(SOURCE_EVIDENCE)
        if evidence is not None:
            if not evidence:
                raise ValueError('transaction source evidence path must not be empty')
            directory = Path(evidence).absolute()
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            (directory / 'public-unselected-521.json').write_bytes(encoded(observations) + b'\n')
            (directory / 'originals-521.json').write_bytes(encoded(expected) + b'\n')
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {native.SELECTOR: ''}))
            poison(stack)
            store = ControlStore()
            cm = api.AgentStore.transaction(store)
            self.assertEqual(store.events, [])
            with self.assertRaises(ValueError):
                cm.__enter__()
            self.assertEqual(store.events, [])
        from tools.build_hia_store_transaction import build
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compiler, cold = directory / 'compiler', directory / 'cold'
            compiler.write_bytes(b'invalid')
            cold.write_text('{}')
            with patch('tools.build_hia_store_transaction.compile_stage',
                       side_effect=AssertionError('compilation before current-cold admission')):
                with self.assertRaises(ValueError):
                    build(directory / 'built', compiler, cold)
            self.assertFalse((directory / 'built').exists())


class StoreTransactionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_transaction import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-transaction-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.cold = compiler, cold
        cls.compiler_raw, cls.sources = compiler.read_bytes(), current_sources()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_store_transaction(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = after == cls.sources and cls.compiler.read_bytes() == cls.compiler_raw
        record = {'schema': 'hepta.hia.transaction-component-custody.v1',
            'source_manifest_before': cls.sources, 'source_manifest_after': after,
            'source_and_compiler_unchanged': stable, 'manifest': str(cls.manifest),
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(), 'matching_cold_report': cls.cold,
            'python_version': sys.version, 'runtime_context_lookup_order': list(native._runtime_context_lookup_order()),
            'original_cases': CASE_COUNT, 'test_result_owned_by_outer_runner': True,
            'actual_advance_uses_new_current_process_thread_record': True,
            'suspended_resource_scope_does_not_infer_native_ancestry': True,
            'all_input_equivalence_proved': False, 'all_python_versions_tested': False,
            'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('transaction source or compiler changed during component observations')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.selection = patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})
        self.selection.start()
        self.addCleanup(self.selection.stop)

    def write(self, name, value):
        (self.case / name).write_bytes(encoded(value) + b'\n')

    def test_complete_521_frozen_originals_through_selected_public_binding(self):
        from tests.hia_store_transaction_history import HISTORIES, KNOWN_H0_ORIGINALS
        import signal
        identities = [case['id'] for case in original_inputs()]
        pin = sha256(self.manifest.read_bytes()).hexdigest()
        rows, events, frames = [], Counter(), {}
        for history in HISTORIES:
            with self.subTest(history=history):
                destination = self.case / history
                command = [sys.executable, '-B', '-m', 'tests.hia_store_transaction_history',
                    '--history', history, '--manifest', str(self.manifest),
                    '--expected-manifest-sha256', pin, '--compiler', str(self.compiler),
                    '--output', str(destination)]
                self.write(history + '-command.json', {'command': command, 'timeout_seconds': 120,
                    'same_one_parent_build': True, 'new_interpreter_process': True})
                with subprocess.Popen(command, cwd=ROOT, env=clean_environment(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        stdout, stderr = child.communicate()
                        (self.case / (history + '-stdout.log')).write_bytes(stdout)
                        (self.case / (history + '-stderr.log')).write_bytes(stderr)
                        raise
                (self.case / (history + '-stdout.log')).write_bytes(stdout)
                (self.case / (history + '-stderr.log')).write_bytes(stderr)
                report_path = destination / 'report.json'
                report = json.loads(report_path.read_bytes())
                rows.append({'history': history, 'returncode': child.returncode,
                    'report': str(report_path), 'report_sha256': sha256(report_path.read_bytes()).hexdigest(),
                    'status': report['status'], 'original_count': report['original_count'],
                    'actual_count': report['actual_count'], 'actual_frames': report['actual_frames'],
                    'events': report['actual_native_entry_events'], 'process': report['process'],
                    'originals_sha256': report['originals_sha256'], 'actuals_sha256': report['actuals_sha256']})
                events.update(report['actual_native_entry_events'])
                frames[history] = report['actual_frames']
                self.assertEqual(child.returncode, 0, stdout + stderr)
                self.assertEqual(report['status'], 'PASS', report.get('exception'))
                self.assertEqual(report['case_order'], identities)
                self.assertEqual(report['original_count'], CASE_COUNT)
                self.assertEqual(report['actual_count'], CASE_COUNT)
                self.assertEqual(report['source_before'], self.sources)
                self.assertEqual(report['source_after'], self.sources)
                self.assertEqual(report['manifest_sha256'], pin)
                self.assertTrue(report['source_image_manifest_build_and_compiler_unchanged'])
                self.assertTrue(report['expected_written_before_native_mapping'])
                self.assertTrue(report['expected_file_unchanged_after_candidate'])
                self.assertTrue(report['both_retained_aliases_poisoned'])
                self.assertTrue(report['history_equal'])
                self.assertTrue(report['held_cleanup_equal'])
                self.assertEqual(report['differences'], [])
                self.assertFalse(any(report['guards'].values()))
                expected_raw = (destination / 'originals-521.json').read_bytes()
                actual_raw = (destination / 'actuals-521.json').read_bytes()
                self.assertEqual(sha256(expected_raw).hexdigest(), report['originals_sha256'])
                self.assertEqual(sha256(actual_raw).hexdigest(), report['actuals_sha256'])
                self.assertEqual(actual_raw, expected_raw)
                self.assertEqual([row['id'] for row in json.loads(expected_raw)], identities)
                complete = json.loads((destination / 'complete-observations.json').read_bytes())
                self.assertEqual([row['case'] for row in complete], identities)
                self.assertEqual([row['expected'] for row in complete], json.loads(expected_raw))
                self.assertEqual([row['actual'] for row in complete], json.loads(actual_raw))
                self.assertTrue(all(row['equal'] for row in complete))
                if history == 'H0' and sys.version in KNOWN_H0_ORIGINALS:
                    self.assertEqual(report['originals_sha256'], KNOWN_H0_ORIGINALS[sys.version])
                    self.assertTrue(report['known_exact_runtime_H0_anchor_checked'])
                self.assertGreater(report['actual_frames'], 0)
                counts = report['actual_native_entry_events']
                self.assertTrue(all(counts.get(str(event), 0) > 0 for event in range(6)))
                self.assertEqual(counts['1'], counts['2'] + counts['3'])
        self.write('isolated-histories.json', rows)
        self.write('native-counts.json', {'events': dict(events), 'actual_frames_by_history': frames,
            'observer_process': os.getpid(), 'count_scope': 'two dedicated history child processes',
            'parent_process_entries_not_included': True, 'fork_grandchild_entries_not_invented': True,
            'unique_frozen_cases': CASE_COUNT, 'declared_histories': list(HISTORIES),
            'same_complete_521_cases_in_each_history': True,
            'all_521_include_actual_thread_Context_fork_gi_running_and_cleanup_observations': True})
        self.assertEqual([row['history'] for row in rows], list(HISTORIES))

    def test_actual_public_SQL_pinned_bundle_restoration_and_source_drift(self):
        from hepta.hia_native_helpers import native_helpers_scope
        path = self.case / 'bundle.json'
        bundle_sha = bundle(path, [(native.SELECTOR, self.manifest)])
        env = clean_environment()
        statements = []
        counts = Counter()
        original_entry = native.NativeStoreTransaction.__init__

        def observed_image(image, *arguments, **keywords):
            original_entry(image, *arguments, **keywords)
            entry = image._entry
            def observed(*args):
                counts['entries'] += 1
                return entry(*args)
            image._entry = observed

        with patch.dict(os.environ, env, clear=True), patch.object(native.NativeStoreTransaction, '__init__', observed_image):
            before = dict(os.environ)
            with native_helpers_scope(str(path), bundle_sha), ExitStack() as stack:
                poison(stack)
                store = api.AgentStore(self.case / 'state')
                try:
                    store.db.set_trace_callback(statements.append)
                    store.db.execute('CREATE TABLE transaction_probe(value INTEGER)')
                    with store.transaction():
                        store.db.execute('INSERT INTO transaction_probe VALUES (1)')
                    error = ValueError('ordinary foreign body error')
                    try:
                        with store.transaction():
                            store.db.execute('INSERT INTO transaction_probe VALUES (2)')
                            raise error
                    except ValueError as caught:
                        self.assertIs(caught, error)
                    self.assertEqual([row[0] for row in store.db.execute('SELECT value FROM transaction_probe')], [1])
                    store.db.execute('BEGIN IMMEDIATE')
                    with self.assertRaises(sqlite3.OperationalError):
                        with store.transaction():
                            self.fail('failed nested BEGIN entered its body')
                    self.assertTrue(store.db.in_transaction)
                    store.db.execute('ROLLBACK')
                finally:
                    store.close()
            self.assertEqual(dict(os.environ), before)
        self.assertGreater(counts['entries'], 0)
        self.assertEqual(statements.count('COMMIT'), 1)
        self.assertEqual(statements.count('ROLLBACK'), 2)  # body + explicit outer owner cleanup
        self.write('public-SQL.json', {'statements': statements, 'counts': dict(counts),
            'bundle_sha256': bundle_sha, 'scope_restored': True, 'retained_body_poisoned': True,
            'nested_BEGIN_did_not_rollback_the_existing_transaction': True})

        # Tamper only copies, and prove rejection before any transaction effect.
        copied = self.case / 'tampered';copied.mkdir()
        value = json.loads(self.manifest.read_bytes())
        shutil.copyfile(self.manifest.parent / value['image_path'], copied / value['image_path'])
        bad = copied / 'manifest.json';bad.write_bytes(self.manifest.read_bytes())
        bad_bundle = copied / 'bundle.json'
        pin = bundle(bad_bundle, [(native.SELECTOR, bad)])
        untouched = ControlStore()
        value['source_sha256'] = '0' * 64
        bad.write_bytes(encoded(value))
        # Standalone selection reaches the actual loader. A live pinned scope
        # deliberately returns its already admitted immutable image instead.
        with patch.dict(os.environ, {**env, native.SELECTOR: str(bad)}, clear=True), ExitStack() as stack:
            poison(stack)
            with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                api.AgentStore.transaction(untouched).__enter__()
        self.assertEqual(untouched.events, [])
        # Full pinned-bundle attestation is an explicit worker operation. The
        # original scope's finally restores selection; it is not an automatic
        # terminal attestation. Compiler metadata has no standalone executable
        # source/image check, so observe it at that actual bundle boundary.
        from hepta.hia_native_helpers import native_helpers_identity
        bad.write_bytes(self.manifest.read_bytes())
        value = json.loads(bad.read_bytes())
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                with native_helpers_scope(str(bad_bundle), pin):
                    value['compiler_sha256'] = '0' * 64
                    bad.write_bytes(encoded(value))
                    native_helpers_identity()
        self.assertEqual(untouched.events, [])
        self.write('manifest-drift.json', {
            'source_drift_refused_by_actual_owner_loader_before_effect': True,
            'source_drift_selection': 'explicit_public_selector_without_pinned_scope',
            'source_drift_retained_body_poisoned': True,
            'compiler_metadata_drift_refused_by_explicit_bundle_attestation': True,
            'original_scope_finally_automatically_attests_terminal': False,
            'probe_effects': untouched.events})
        with patch.object(native, 'SOURCE', copied / 'wrong.hepta'):
            native.SOURCE.write_bytes(b'wrong source')
            with self.assertRaises(ValueError):
                native.installed_store_transaction(str(self.manifest))

    def test_safe_initial_preparation_and_confirmed_foreign_errors_preserve_identity(self):
        rows = []
        for kind in ERROR_TYPES:
            store = ControlStore()
            error = kind('safe initial request preparation')
            frame = native.StoreTransactionFrame(self.image, store)
            before = set(native._FRAME_CUSTODY)
            with patch.object(native.struct, 'pack', side_effect=error), \
                 patch.object(self.image, '_entry', side_effect=AssertionError('safe refusal entered native')):
                try:
                    frame.start()
                except BaseException as caught:
                    self.assertIs(caught, error)
                    frame.failed(caught)
                else:
                    self.fail('controlled preparation did not fail')
                finally:
                    frame.finish_advance()
            self.assertNotIn(id(frame), native._FRAME_CUSTODY)
            self.assertFalse(frame.native_failed)
            self.assertEqual(store.events, [])
            delivery.check_resource_retirement(store)
            self.assertEqual(set(native._FRAME_CUSTODY), before - {id(frame)})
            rows.append({'error': kind.__name__, 'same_error': True, 'entries': 0,
                         'effects': [], 'unused_custody_released': True})
        store = ControlStore()
        ordinary = MemoryError('after confirmed completion')
        complete = native.StoreTransactionFrame._completed
        def after_confirmed(frame):
            complete(frame)
            raise ordinary
        with patch.object(native.StoreTransactionFrame, '_completed', after_confirmed):
            try:
                with api.AgentStore.transaction(store):
                    pass
            except MemoryError as caught:
                self.assertIs(caught, ordinary)
            else:
                self.fail('confirmed-terminal foreign exception was hidden')
        delivery.check_resource_retirement(store)
        self.assertEqual(store.events, ['enter', 'BEGIN IMMEDIATE', 'COMMIT', 'exit'])
        self.write('safe-preparation-and-confirmed.json', rows)

    def test_actual_handoff_and_foreign_ACK_loss_retain_without_cleanup_or_replay(self):
        rows = []
        for kind in ERROR_TYPES:
            store = ControlStore()
            frame = native.StoreTransactionFrame(self.image, store)
            error, entry = kind('lost native initialization acknowledgement'), self.image._entry
            calls = []
            def lost(*arguments):
                calls.append(1)
                entry(*arguments)
                raise error
            with patch.object(self.image, '_entry', lost):
                try:
                    frame.start()
                except BaseException as caught:
                    if kind in (ValueError, MemoryError):
                        self.assertIsInstance(caught, native.StoreTransactionUnknown)
                        self.assertIs(caught.__cause__, error)
                    else:
                        self.assertIs(caught, error)
                    frame.failed(caught)
                else:
                    self.fail('lost acknowledgement returned')
                finally:
                    frame.finish_advance()
            self.assertEqual(calls, [1])
            self.assertTrue(frame.native_failed)
            self.assertIn(id(frame), native._FRAME_CUSTODY)
            self.assertEqual(store.events, [])
            with self.assertRaises(delivery.NativeDeliveryUnknown):
                delivery.check_resource_retirement(store)
            with self.assertRaises(native.StoreTransactionUnknown):
                frame.start()
            rows.append({'error': kind.__name__, 'actual_entries': 1,
                         'retained': True, 'automatic_cleanup_or_replay': False})

        store, error = ControlStore(), MemoryError('BEGIN result could not be delivered')
        frame = native.StoreTransactionFrame(self.image, store)
        pack = native.struct.pack
        def lost_pack(format, *words):
            if format == '<10Q' and words[1] == native.SUCCEEDED and words[3] == native.PORT['begin']:
                raise error
            return pack(format, *words)
        with patch.object(native.struct, 'pack', lost_pack):
            try:
                frame.start()
            except MemoryError as caught:
                self.assertIs(caught, error)
                frame.failed(caught)
            else:
                self.fail('BEGIN observation was accepted without a packet')
            finally:
                frame.finish_advance()
        self.assertEqual(store.events, ['enter', 'BEGIN IMMEDIATE'])
        self.assertTrue(frame.native_failed)
        self.assertIn(id(frame), native._FRAME_CUSTODY)
        with self.assertRaises(delivery.NativeDeliveryUnknown):
            delivery.check_resource_retirement(store)
        self.write('native-and-foreign-ACK-loss.json', {'native_losses': rows,
            'foreign_ACK_error_preserved': True, 'foreign_ACK_events': store.events,
            'unconfirmed_resources_retained_not_claimed_cleaned': True})

    def test_body_resume_allocation_loss_uses_pre_BEGIN_reservation(self):
        store = ControlStore()
        cm = api.AgentStore.transaction(store)
        cm.__enter__()
        error = MemoryError('new resume record allocation failed')
        with patch.object(native, 'DeliveryRecord', side_effect=error):
            try:
                cm.__exit__(None, None, None)
            except MemoryError as caught:
                self.assertIs(caught, error)
            else:
                self.fail('body result delivery was silently discarded')
        self.assertEqual(store.events, ['enter', 'BEGIN IMMEDIATE'])
        retained = [record for record in delivery._RESOURCE_OBSERVATIONS.values()
                    if record.resource is store]
        self.assertEqual(len(retained), 1)
        self.assertIs(retained[0].error, error)
        self.assertIs(retained[0].loss, retained[0])
        with self.assertRaises(delivery.NativeDeliveryUnknown):
            delivery.check_resource_retirement(store)
        self.write('body-observation.json', {'events': store.events,
            'pre_BEGIN_token_retained': True, 'same_MemoryError': True,
            'COMMIT_ROLLBACK_unlock_not_attempted': True})

    def test_actual_cross_owner_swallowed_replaced_and_suppressed_loss_blocks_commit_and_close(self):
        from tools.build_hia_store_artifact_profile import build
        from hepta.hia_store_artifact_profile_native import SELECTOR as child_selector
        child_manifest = build(self.case / 'child-built', self.compiler, self.cold,
                               development=self.cold is None)
        path = self.case / 'bundle.json'
        pin = bundle(path, [(native.SELECTOR, self.manifest), (child_selector, child_manifest)])
        script = r'''import ctypes,json,os,select,signal,struct,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hepta import hia_agent_store as api
from hepta import hia_store_transaction_native as transaction
from hepta import hia_store_artifact_profile_native as child
from hepta import hia_native_delivery as delivery
from hepta.hia_native_helpers import native_helpers_scope
mode,bundle,pin,root=sys.argv[2:]
events=[];counts={'transaction':0,'child':0};close_calls=[]
def forbidden(*a,**k):raise AssertionError('retained transaction executed')
forbidden.__wrapped__=forbidden
api._STORE_TRANSACTION_REFERENCE=forbidden;api.AgentStore._transaction_reference=forbidden
api._STORE_ARTIFACT_PROFILE_REFERENCES['_ref']=forbidden
original_tx=transaction.NativeStoreTransaction.__init__
def tx_init(image,*a,**k):
    original_tx(image,*a,**k);entry=image._entry
    def call(*a):counts['transaction']+=1;return entry(*a)
    image._entry=call
transaction.NativeStoreTransaction.__init__=tx_init
original_child=child.NativeStoreArtifactProfile.__init__
def child_init(image,*a,**k):
    original_child(image,*a,**k);entry=image._entry
    def call(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent);counts['child']+=1
        if packet[1]==2 and packet[3]==child.PORT['ref_get']:
            raise ValueError('actual child result acknowledgement lost')
        return result
    image._entry=call
child.NativeStoreArtifactProfile.__init__=child_init
class Suppress:
    def __enter__(self):pass
    def __exit__(self,*args):return True
with native_helpers_scope(bundle,pin):
    store=api.AgentStore(Path(root));store.db.set_trace_callback(events.append)
    store.db.execute('CREATE TABLE cross_owner_probe(value INTEGER)')
    caught=None
    try:
        with store.transaction():
            store.db.execute('INSERT INTO cross_owner_probe VALUES (1)')
            if mode=='with-suppress':
                with Suppress():api.AgentStore._ref({'id':'x','sha256':'y','uri':'z'})
            else:
                try:api.AgentStore._ref({'id':'x','sha256':'y','uri':'z'})
                except child.StoreArtifactProfileUnknown:
                    if mode=='replace':raise ValueError('foreign replacement after actual loss')
    except BaseException as error:caught=type(error).__name__
    assert caught=='StoreTransactionUnknown',(caught,events)
    assert events.count('BEGIN IMMEDIATE')==1 and 'COMMIT' not in events and 'ROLLBACK' not in events,events
    assert counts['transaction']>0 and counts['child']>0,counts
    def no_close(self):close_calls.append(1);raise AssertionError('unknown resource retired')
    api._NATIVE_STORE_CLOSE_REFERENCE=no_close
    try:store.close()
    except delivery.NativeDeliveryUnknown:pass
    else:raise AssertionError('unknown Store close was accepted')
    assert not close_calls
    frames=[frame for frame in transaction._FRAME_CUSTODY.values() if frame.store is store]
    assert len(frames)==1 and frames[0].fenced
    assert any(frame.store is None for frame in child._FRAME_CUSTODY.values())
    fork_record=None
    if mode=='swallow':
        read,write=os.pipe();pid=os.fork()
        if pid==0:
            os.close(read)
            try:
                rejected=False
                try:delivery.check_resource_retirement(store)
                except delivery.NativeDeliveryUnknown:rejected=True
                fresh=delivery.DeliveryRecord(object())
                healthy=fresh.current() and fresh.loss is None and fresh.parent is None
                fresh.retire()
                os.write(write,json.dumps({'exact_inherited_unknown_rejected':rejected,
                    'no_inherited_native_ancestry':healthy}).encode())
                os._exit(0)
            except BaseException:os._exit(72)
        os.close(write)
        try:
            ready,_,_=select.select([read],[],[],10)
            if not ready:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);raise AssertionError('fork observation exceeded 10 seconds')
            fork_record=json.loads(os.read(read,65536))
            _,status=os.waitpid(pid,0)
            assert os.waitstatus_to_exitcode(status)==0 and all(fork_record.values()),fork_record
        finally:os.close(read)
    print(json.dumps({'mode':mode,'events':events,'counts':counts,'caught':caught,
        'retained_transaction_frames':len(frames),'close_calls':close_calls,'fork':fork_record,
        'unknown_resources_only_retained_until_process_exit':True},sort_keys=True))
'''
        rows = []
        for mode in ('swallow', 'replace', 'with-suppress'):
            result = subprocess.run([sys.executable, '-B', '-I', '-c', script, str(ROOT), mode,
                str(path), pin, str(self.case / mode)], cwd=self.case, env=clean_environment(),
                capture_output=True, timeout=30)
            (self.case / (mode + '.stdout')).write_bytes(result.stdout)
            (self.case / (mode + '.stderr')).write_bytes(result.stderr)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows.append(json.loads(result.stdout))
        self.write('cross-owner-observations.json', rows)

    def test_native_packet_and_full_buffer_differential_rejects_replay_and_drift(self):
        program = assemble_program(native.SOURCE.read_bytes())
        initial = struct.pack('<10Q', native.REQUEST_MAGIC, 0, 0, 0, 0, 1, 11, 17, 0, 0)
        records = []

        def compare(label, raw, state=bytes(native.STATE_BYTES), capacity=native.OUTPUT_BYTES):
            output_raw = b'\xa5' * capacity
            expected = vm_call(program, raw, output_raw, state)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            output = ctypes.create_string_buffer(output_raw + b'\xa7' * 16, capacity + 16)
            workspace = ctypes.create_string_buffer(state + b'\xb7' * 16, len(state) + 16)
            code = self.image._entry(source, len(raw), output, capacity, workspace, len(state))
            actual = code, output.raw[:capacity], workspace.raw[:len(state)]
            self.assertEqual(source.raw, raw + b'\xc9' * 16)
            self.assertEqual(output.raw[capacity:], b'\xa7' * 16)
            self.assertEqual(workspace.raw[len(state):], b'\xb7' * 16)
            self.assertEqual(actual, expected, label)
            records.append({'case': label, 'code': code, 'request': raw.hex(),
                'output': actual[1].hex(), 'state': actual[2].hex(),
                'complete_buffers_equal_to_independent_VM': True})
            return actual

        for label, raw, state, capacity in (
                ('request-short', initial[:-1], bytes(128), 96),
                ('request-long', initial + b'\0', bytes(128), 96),
                ('output-short', initial, bytes(128), 95),
                ('state-short', initial, bytes(127), 96),
                ('state-long', initial, bytes(129), 96),
                ('nonzero-initial-state', initial, b'\1' + bytes(127), 96)):
            self.assertEqual(compare(label, raw, state, capacity)[0], 0xfffffffd)
        for label, index, value in (('bad-magic', 0, 0), ('reserved-first', 8, 1),
                                    ('reserved-last', 9, 1), ('bad-mode', 5, 2)):
            packet = list(struct.unpack('<10Q', initial));packet[index] = value
            self.assertEqual(compare(label, struct.pack('<10Q', *packet))[0], 0xfffffffd)
        packet = list(struct.unpack('<10Q', initial));packet[6:8] = [0, 0]
        self.assertEqual(compare('zero-identity', struct.pack('<10Q', *packet))[0], 0xfffffffd)
        first = compare('initialize', initial)
        self.assertEqual(struct.unpack('<12Q', first[1])[1], 0)
        issue = struct.unpack('<16Q', first[2])
        ack = struct.pack('<10Q', native.REQUEST_MAGIC, native.SUCCEEDED,
                          issue[4], issue[3], 0, 1, 11, 17, 0, 0)
        refused = compare('unclaimed-ACK', ack, first[2])
        self.assertEqual(struct.unpack('<12Q', refused[1])[1], 1)
        claim = struct.pack('<10Q', native.REQUEST_MAGIC, native.CLAIM,
                            issue[4], issue[3], 0, 1, 11, 17, 0, 0)
        claimed = compare('claim', claim, first[2])
        duplicate = compare('duplicate-claim', claim, claimed[2])
        self.assertEqual(struct.unpack('<12Q', duplicate[1])[1], 1)
        broken = bytearray(first[2]);broken[80] ^= 1
        self.assertEqual(compare('state-checksum-drift', claim, bytes(broken))[0], 0xfffffffd)
        store = ControlStore()
        frame = native.StoreTransactionFrame(self.image, store)
        try:
            self.assertEqual(frame.start(), native.BODY_WAIT)
            frame.suspend()
            suspended = frame.buffer.raw[:native.STATE_BYTES]
            receipt = frame.receipt
            packet = struct.pack('<10Q', native.REQUEST_MAGIC, native.BODY_RETURNED,
                receipt.sequence, receipt.port, 0, 1, *frame.identity, 0, 0)
            advanced = compare('actual-confirmed-body-resume', packet, suspended)
            replay = compare('body-resume-replay', packet, advanced[2])
            self.assertEqual(struct.unpack('<12Q', replay[1])[1], 1)
            frame.resume(native.BODY_RETURNED);frame.drive()
        finally:
            frame.finish_advance()
        self.assertEqual(store.events, ['enter', 'BEGIN IMMEDIATE', 'COMMIT', 'exit'])
        self.write('full-packets-and-buffers.json', records)

    def test_actual_installed_wheel_worker_and_durable_COMMIT_acknowledgement_loss(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_native_helpers import native_helpers_scope
        staging = self.case / 'source';staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name;target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment()
        environment['PYTHONDONTWRITEBYTECODE'] = '1'

        def run(label, arguments, *, body=None, expected_code=0):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=self.case,
                env=environment, input=body, capture_output=True, timeout=60)
            (self.case / (label + '.stdout')).write_bytes(result.stdout)
            (self.case / (label + '.stderr')).write_bytes(result.stderr)
            self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
            return result

        from tests.hia_distribution_fixture import installed_wheel_path, ordinary_wheel
        run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                      '--wheel-dir', self.case / 'wheels', ordinary_wheel(staging)])
        wheel, = (self.case / 'wheels').glob('*.whl')
        installed = self.case / 'installed'
        run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                        '--target', installed, wheel])
        files = {}
        with zipfile.ZipFile(wheel) as archive:
            record_name, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
            for name, digest, size in csv.reader(io.StringIO(archive.read(record_name).decode())):
                raw = archive.read(name)
                if digest:
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode())
                    self.assertEqual(size, str(len(raw)))
                if name != record_name:
                    self.assertEqual(installed_wheel_path(installed, name).read_bytes(), raw, name)
                    files[name] = sha256(raw).hexdigest()
        resource = installed / 'hepta/_data/examples/hia_bootstrap/store_transaction.hepta'
        self.assertEqual(resource.read_bytes(), native.SOURCE.read_bytes())
        installed_record = {row[0]: row[1:] for row in csv.reader(io.StringIO((installed / record_name).read_text()))}
        for name in ('hepta/hia_agent_store.py', 'hepta/hia_native_delivery.py',
                     'hepta/hia_store_transaction_native.py', 'hepta/hia_store_transaction_protocol.py',
                     str(resource.relative_to(installed))):
            raw = installed_wheel_path(installed, name).read_bytes()
            digest = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
            self.assertEqual(installed_record[name], [digest, str(len(raw))])
        path = self.case / 'bundle.json'
        pin = bundle(path, [(native.SELECTOR, self.manifest)])
        script = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_store as store
from hepta import hia_store_transaction_native as native
from hepta import hia_agent_service as service
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{},'request':{},'close_calls':0};active=False
def forbidden(*a,**k):raise AssertionError('installed retained transaction executed')
forbidden.__wrapped__=forbidden
store._STORE_TRANSACTION_REFERENCE=forbidden;store.AgentStore._transaction_reference=forbidden
original_call=service.HIAAgentService._reference_call
def request_call(self,*a,**k):
    global active
    active=True
    try:return original_call(self,*a,**k)
    finally:active=False
service.HIAAgentService._reference_call=request_call
close=store._NATIVE_STORE_CLOSE_REFERENCE
def close_observed(self):counts['close_calls']+=1;return close(self)
store._NATIVE_STORE_CLOSE_REFERENCE=close_observed
initialize=native.NativeStoreTransaction.__init__
def image_init(image,*a,**k):
    initialize(image,*a,**k);entry=image._entry
    def observed(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert packet[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        bucket=counts['request' if active else 'startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1
        if active and mode=='lost_commit' and packet[1]==2 and packet[3]==native.PORT['commit']:
            raise ValueError('actual durable COMMIT acknowledgement lost')
        return result
    image._entry=observed
native.NativeStoreTransaction.__init__=image_init
try:status=main(sys.argv[1:])
finally:
    counts['unknown_frames']=len(native._FRAME_CUSTODY)
    print('TRANSACTION_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''

        def read_counts(result):
            prefix = b'TRANSACTION_COUNTS='
            values = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
            self.assertEqual(len(values), 1, result.stderr)
            return json.loads(values[0])

        def prepare():
            case = AgentToolCase('runTest')
            with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(path), pin):
                case.setUp()
            arguments = case.session.arguments(context=False, artifact_profile=case.session.profiles['artifact'],
                source={'kind': 'utf8', 'text': 'native transaction installed worker — 雪'})
            request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_artifact',
                'arguments': arguments, 'profile_sha256': 'a' * 64,
                'catalog_sha256': case.service.catalog_sha256}
            request['request_sha256'] = api.digest(request)
            case.service.close()
            return case, request

        def state(case, request):
            key = api.digest({'tool': request['tool'], 'key': request['arguments']['request_key']})
            with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
                db.row_factory = sqlite3.Row
                row = db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
                return {'request': None if row is None else dict(row),
                    'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                    'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

        def worker(label, case, request, mode='normal', code=0):
            return run(label, ['-I', '-c', script, installed, mode,
                '--state-root', case.state_root, '--artifact-root', case.files_root,
                '--request-json-stdin', '--native-helpers-manifest', path,
                '--expected-native-helpers-sha256', pin], body=encoded(request), expected_code=code)

        observations = {}
        case, request = prepare()
        try:
            before = state(case, request)
            first = worker('first', case, request)
            report, counts = json.loads(first.stdout), read_counts(first)
            after = state(case, request)
            replay = worker('replay', case, request)
            replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
            self.assertEqual(report['response']['status'], 'completed', report)
            self.assertEqual(report['native_helpers_sha256'], pin)
            self.assertEqual(replay_report['response'], report['response'])
            self.assertEqual(state(case, request), after)
            self.assertEqual(after['artifacts'], before['artifacts'] + 1)
            self.assertEqual(after['request']['state'], 'completed')
            self.assertGreater(sum(counts['request'].values()), 0)
            self.assertGreater(sum(replay_counts['request'].values()), 0)
            self.assertEqual(counts['unknown_frames'], 0)
            self.assertEqual(replay_counts['unknown_frames'], 0)
            self.assertEqual(counts['close_calls'], 1)
            reference = report['response']['result']['artifact']
            payload = (case.state_root / 'artifacts' / reference['sha256']).read_bytes()
            self.assertEqual(payload, request['arguments']['source']['text'].encode())
            observations['success'] = {'report': report, 'counts': counts, 'before': before, 'after': after}
            observations['replay'] = {'report': replay_report, 'counts': replay_counts,
                'native_transaction_still_checks_original_replay': True, 'state_unchanged': True}
        finally:
            case.tearDown()
        case, request = prepare()
        try:
            before = state(case, request)
            from tests.hia_slot_worker_terminal import worker_profile
            lost_ack_exit = worker_profile((installed / 'hepta/hia_agent_worker.py').read_bytes())['lost_ack_exit']
            lost = worker('lost-commit', case, request, 'lost_commit', lost_ack_exit)
            counts = read_counts(lost)
            after = state(case, request)
            self.assertEqual(lost.stdout, b'')
            self.assertGreater(counts['unknown_frames'], 0)
            self.assertEqual(counts['close_calls'], 0)
            self.assertEqual(after['request']['state'], 'running')
            self.assertIsNone(after['request']['response'])
            self.assertEqual(after['artifacts'], before['artifacts'])
            self.assertEqual(after['costs'], before['costs'])
            replay = worker('unknown-replay', case, request)
            replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
            replay_state = state(case, request)
            self.assertEqual(replay_report['response']['status'], 'rejected', replay_report)
            self.assertEqual(replay_report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(replay_state['request'], after['request'])
            self.assertEqual(replay_state['artifacts'], after['artifacts'])
            # Original running-intent refusal is an ordinary rejected attempt;
            # its audit cost is recorded, unlike an early cached response.
            self.assertEqual(replay_state['costs'], after['costs'] + 1)
            observations['lost_commit'] = {'worker_exit': lost.returncode, 'counts': counts,
                'before': before, 'after': after, 'close_refused_before_original_close': True}
            observations['unknown_replay'] = {'report': replay_report, 'counts': replay_counts,
                'after': replay_state, 'original_running_request_not_replayed': True}
        finally:
            case.tearDown()
        self.write('installation.json', {'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'installed': str(installed), 'wheel_files_checked_against_installed': files,
            'installed_RECORD_sha256': sha256((installed / record_name).read_bytes()).hexdigest(),
            'bundle_sha256': pin, 'observations': observations,
            'scope': 'actual installed original worker hia_artifact and exact replay; transaction selected',
            'whole_native_stack_qualified': False})
