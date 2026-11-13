"""Candidate counts in actual HIA, the original WAL and ordinary tool calls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_candidate_budget_native import (AttemptState, NativeCandidateBudgetImage,
    NativeCandidateBudgetStore, REQUEST_MAGIC, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE,
    STATE_BYTES, OUTPUT_BYTES)
from hepta.hia_agent_store import AgentStore, AgentRejected

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = b'ctx-' + b'1' * 32


def packet(event, sequence=0, a=0, b=0, c=0, payload=b'', identity=(11, 17), connection=(31, 37)):
    return struct.pack('<12Q', REQUEST_MAGIC, event, sequence, a, b, c,
                       *identity, *connection, len(payload), 0) + payload


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.checked = assemble_program(SOURCE.read_bytes())
        self.entry = next(x for x in self.checked.as_dict()['functions'] if x['name'] == 'f0')
        self.state = bytearray(STATE_BYTES)

    def call(self, raw):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(OUTPUT_BYTES)), _Owner(-3, self.state)]
        machine = _Machine(self.checked, 4000000, 16 << 20, None, 128)
        count = machine.invoke(self.entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        return count, bytes(owners[1].data[:min(count, OUTPUT_BYTES)]), bytes(self.state)


class Machine:
    def __init__(self, image):
        self.image = image
        self.state = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memset(ctypes.addressof(self.state) + STATE_BYTES, 0xb7, 16)

    def call(self, raw):
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
        ctypes.memset(ctypes.addressof(output) + OUTPUT_BYTES, 0xa5, 16)
        count = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.state, STATE_BYTES)
        if source.raw != raw or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16 or self.state.raw[STATE_BYTES:] != b'\xb7' * 16:
            raise AssertionError('native boundary changed an input or canary')
        return count, output.raw[:min(count, OUTPUT_BYTES)], self.state.raw[:STATE_BYTES]


def witnesses(engine):
    raw = [packet(0, a=4096, payload=CONTEXT), packet(1, 1, a=1),
           packet(2, 2, a=1, c=4095, payload=CONTEXT), packet(3, 3, a=1),
           packet(2, 4, a=1, c=4096, payload=CONTEXT), packet(4, 5, a=1)]
    rows = []
    for sequence, (wire, action, phase) in enumerate(zip(raw, (1, 2, 3, 2, 4, 0), (1, 2, 3, 4, 5, 6)), 1):
        result = engine.call(wire)
        header = struct.unpack('<10Q', result[1][:80])
        if (result[0] != 80 + len(CONTEXT) or header[:6] != (RESULT_MAGIC, 0, action, sequence, phase, 4096)
                or result[1][80:] != CONTEXT):
            raise AssertionError(header)
        if sequence >= 3 and header[6:8] != (4095, 4096):
            raise AssertionError(header)
        rows.append((wire, result))
    return rows


class CandidateBudgetSourceTests(unittest.TestCase):
    def test_exact_source_and_independent_vm_entire_transition(self):
        from tools.generate_hia_candidate_budget import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(witnesses(VM())), 6)

    def test_independent_vm_refuses_capacity_wrong_row_and_repeated_token(self):
        for wrong_row in [packet(2, 2, a=1, c=1, payload=CONTEXT),
                          packet(2, 2, a=1, c=0, payload=b'ctx-other')]:
            vm = VM()
            vm.call(packet(0, a=1, payload=CONTEXT))
            vm.call(packet(1, 1, a=1))
            result = vm.call(wrong_row)
            self.assertIn(struct.unpack('<10Q', result[1][:80])[1], (2, 3))
            self.assertEqual(struct.unpack('<10Q', vm.call(wrong_row)[1][:80])[1], 2)

    def test_bad_cold_refuses_before_any_output_or_compile(self):
        from tools.build_hia_candidate_budget import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler = root / 'compiler'; compiler.write_bytes(b'explicit fixture, not a compiler')
            cold = root / 'cold'; cold.write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compiler started')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(root / 'output', compiler, cold)
            self.assertFalse((root / 'output').exists())


class CandidateBudgetNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.reference = witnesses(VM())
        cold = os.environ.get('HEPTA_HIA_CANDIDATE_BUDGET_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_CANDIDATE_BUDGET_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('development compiler cannot override candidate budget cold qualification')
        cls.cold = Path(cold) if cold else None
        if cls.cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cold_bytes = cls.cold.read_bytes()
            report = json.loads(cold_bytes)
            try:
                nested = json.loads(Path(report['nested_report']).read_bytes())
                cls.compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('candidate budget cold report lacks its compiler') from error
            admit_cold_build(cls.compiler.read_bytes(), cold_bytes)
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_CANDIDATE_BUDGET_EVIDENCE')
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-candidate-budget-')
            cls.folder = Path(cls.temporary.name)
        if cls.cold:
            from tools.build_hia_candidate_budget import build
            cls.manifest = build(cls.folder / 'qualified', cls.compiler, cls.cold)
            manifest = json.loads(cls.manifest.read_bytes())
            image = cls.manifest.parent / manifest['image_path']
            receipt = json.loads((cls.manifest.parent / 'build.json').read_bytes())['native_compile_receipt']
            mode = 'MATCHING_CURRENT_SOURCE_COLD_BUILD'
        else:
            if development:
                cls.compiler = Path(development).resolve(strict=True)
                mode = 'DEVELOPMENT_REUSED_COMPILER'
            else:
                seed, _ = build_seed(cls.folder)
                source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
                first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
                cls.compiler, _ = compile_stage(cls.folder, 'B2', first, source)
                if first.read_bytes() != cls.compiler.read_bytes():
                    raise AssertionError('native compiler fixed point differs')
                mode = 'BOOTSTRAP_DEVELOPMENT_ONLY'
            image, receipt = compile_stage(cls.folder, 'candidate-budget', cls.compiler, SOURCE.read_bytes())
            manifest = {'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
        cls.image = NativeCandidateBudgetImage(image.read_bytes(), manifest['image_sha256'])
        cls.receipt = receipt
        cls.journal_manifest = None
        cls.composition_manifests = None
        (cls.folder / 'build-observation.json').write_text(json.dumps({'mode': mode,
            'matching_current_source_cold_qualified': bool(cls.cold), 'manifest': manifest,
            'compiler_receipt': receipt}, indent=2, sort_keys=True) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def directory(self):
        path = self.folder / self._testMethodName
        path.mkdir()
        return path

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def context(self, store, name='ctx-test', count=0):
        store.db.execute('INSERT INTO contexts VALUES (?,?,?,?,?)', (name, 'a' * 64, '{}', '1', count))
        return name

    def driver(self, store):
        driver = NativeCandidateBudgetStore(store, (self.image, SOURCE.read_bytes()))
        self.addCleanup(driver.close)
        return driver

    def test_actual_native_equals_full_vm_state_and_output(self):
        machine = Machine(self.image)
        for raw, expected in self.reference:
            self.assertEqual(machine.call(raw), expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_count_domain_against_independent_integer_policy_and_original_sql(self):
        store = AgentStore(self.directory() / 'state'); self.addCleanup(store.close)
        driver = self.driver(store)
        rng = random.Random(0xCAAD)
        cases = [(1, 0), (1, 1), (4096, 4095), (4096, 4096), (4096, (1 << 63) - 1)]
        cases += [(rng.randint(1, 4096), rng.randint(0, 4200)) for _ in range(256)]
        for index, (maximum, count) in enumerate(cases):
            name = self.context(store, 'ctx-' + str(index), count)
            reference_name = self.context(store, 'reference-' + str(index), count)
            changed = store.db.execute('UPDATE contexts SET attempts=attempts+1 WHERE id=? AND attempts<?',
                                      (reference_name, maximum)).rowcount
            if count < maximum:
                self.assertEqual(driver.consume(name, maximum), count + 1)
                self.assertEqual(changed, 1)
            else:
                with self.assertRaises(AgentRejected) as error:
                    driver.consume(name, maximum)
                self.assertEqual(error.exception.code, 'E_HIA_BUDGET')
                self.assertEqual(changed, 0)
            actual = store.db.execute('SELECT attempts FROM contexts WHERE id=?', (name,)).fetchone()[0]
            expected = store.db.execute('SELECT attempts FROM contexts WHERE id=?', (reference_name,)).fetchone()[0]
            self.assertEqual(actual, expected)

    def test_two_connections_charge_exactly_available_attempts(self):
        store = AgentStore(self.directory() / 'state'); self.addCleanup(store.close)
        first, second = self.driver(store), self.driver(store)
        name = self.context(store)
        def consume(index):
            try:
                return (first if index % 2 else second).consume(name, 5)
            except AgentRejected as error:
                return error.code
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(consume, range(12)))
        self.assertEqual(sorted(x for x in results if type(x) is int), list(range(1, 6)))
        self.assertEqual(results.count('E_HIA_BUDGET'), 7)
        self.assertEqual(store.db.execute('SELECT attempts FROM contexts WHERE id=?', (name,)).fetchone()[0], 5)

    def test_original_wal_temp_shadow_and_foreign_transaction(self):
        store = AgentStore(self.directory() / 'state'); self.addCleanup(store.close)
        driver = self.driver(store)
        name = self.context(store)
        driver.db.execute('CREATE TEMP TABLE contexts(id TEXT,attempts INTEGER)')
        driver.db.execute('INSERT INTO temp.contexts VALUES (?,?)', (name, 77))
        self.assertEqual(driver.consume(name, 3), 1)
        self.assertEqual(driver.db.execute('SELECT attempts FROM temp.contexts').fetchone()[0], 77)
        with store.transaction():
            with self.assertRaises(AgentRejected):
                driver.consume(name, 3)
            self.assertTrue(store.db.in_transaction)
        self.assertEqual(store.db.execute('SELECT attempts FROM main.contexts WHERE id=?', (name,)).fetchone()[0], 1)

    def test_write_readback_and_commit_ack_loss_do_not_refund_or_repeat(self):
        store = AgentStore(self.directory() / 'state'); self.addCleanup(store.close)
        driver = self.driver(store)
        name = self.context(store)
        original = driver._execute
        def before_commit(sql, parameters=()):
            if sql == 'COMMIT':
                raise OSError('explicit commit-before-effect fixture')
            return original(sql, parameters)
        with patch.object(driver, '_execute', side_effect=before_commit):
            with self.assertRaises(AgentRejected) as error:
                driver.consume(name, 3)
            self.assertEqual(error.exception.code, 'E_HIA_CANDIDATE_BUDGET_UNKNOWN')
        self.assertEqual(store.db.execute('SELECT attempts FROM contexts WHERE id=?', (name,)).fetchone()[0], 0)
        def after_commit(sql, parameters=()):
            result = original(sql, parameters)
            if sql == 'COMMIT':
                raise OSError('explicit commit-after-effect fixture')
            return result
        with patch.object(driver, '_execute', side_effect=after_commit):
            with self.assertRaises(AgentRejected) as error:
                driver.consume(name, 3)
            self.assertEqual(error.exception.code, 'E_HIA_CANDIDATE_BUDGET_UNKNOWN')
        self.assertEqual(store.db.execute('SELECT attempts FROM contexts WHERE id=?', (name,)).fetchone()[0], 1)
        name2 = self.context(store, 'ctx-trigger')
        store.db.execute("CREATE TRIGGER disturb_attempt AFTER UPDATE OF attempts ON contexts WHEN NEW.id='ctx-trigger' BEGIN UPDATE contexts SET attempts=NEW.attempts+1 WHERE id=NEW.id; END")
        with self.assertRaises(AgentRejected) as error:
            driver.consume(name2, 3)
        self.assertEqual(error.exception.code, 'E_HIA_CANDIDATE_BUDGET_CONFLICT')
        self.assertEqual(store.db.execute('SELECT attempts FROM contexts WHERE id=?', (name2,)).fetchone()[0], 0)

    def journal(self):
        if self.journal_manifest is None:
            from hepta.hia_agent_journal_native import SOURCE as source, SCHEMA as schema
            from tools.qualify_hia_selfhost import compile_stage
            if self.cold:
                from tools.build_hia_json_preflight import build
                self.__class__.journal_manifest = build(self.folder / 'qualified-journal', self.compiler, self.cold, candidate='agent-journal')
            else:
                image, receipt = compile_stage(self.folder, 'agent-journal', self.compiler, source.read_bytes())
                path = self.folder / 'journal-manifest.json'
                path.write_text(json.dumps({'schema': schema, 'source_sha256': sha256(source.read_bytes()).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(self.compiler.read_bytes()).hexdigest()}) + '\n')
                self.__class__.journal_manifest = path
        return self.journal_manifest

    def state_owner_bundle(self, root):
        from hepta import hia_execution_budget_native as budget
        from hepta import hia_retirement_state_native as retirement
        from hepta.hia_agent_journal_native import SELECTOR as journal_selector
        from hepta.hia_native_helpers import ABI, SCHEMA as bundle_schema, TARGET
        from tools.qualify_hia_selfhost import compile_stage
        if self.composition_manifests is None:
            manifests = {SELECTOR: self.manifest, journal_selector: self.journal()}
            for module, candidate in ((budget, 'execution-budget'), (retirement, 'retirement-state')):
                if self.cold:
                    if candidate == 'retirement-state':
                        from tools.build_hia_retirement_state import build
                        path = build(self.folder / ('qualified-' + candidate), self.compiler, self.cold)
                    else:
                        from tools.build_hia_json_preflight import build
                        path = build(self.folder / ('qualified-' + candidate), self.compiler, self.cold,
                                     candidate=candidate)
                else:
                    image, receipt = compile_stage(self.folder, 'bundle-' + candidate,
                                                   self.compiler, module.SOURCE.read_bytes())
                    path = self.folder / ('bundle-' + candidate + '-manifest.json')
                    path.write_text(json.dumps({'schema': module.SCHEMA,
                        'source_sha256': sha256(module.SOURCE.read_bytes()).hexdigest(),
                        'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                        'compiler_sha256': sha256(self.compiler.read_bytes()).hexdigest()}, sort_keys=True) + '\n')
                    (self.folder / ('bundle-' + candidate + '-observation.json')).write_text(
                        json.dumps({'matching_current_source_cold_qualified': False,
                                    'compiler_receipt': receipt}, sort_keys=True) + '\n')
                manifests[module.SELECTOR] = path
            self.__class__.composition_manifests = manifests
        bundle = root / 'state-owners.json'
        bundle.write_text(json.dumps({'schema': bundle_schema, 'target': TARGET, 'abi': ABI,
            'helpers': [{'selector': selector, 'manifest_path': str(path),
                         'manifest_sha256': sha256(path.read_bytes()).hexdigest()}
                        for selector, path in sorted(self.composition_manifests.items())]}, sort_keys=True) + '\n')
        clean = {name: value for name, value in os.environ.items()
                 if not (name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST'))}
        return bundle, sha256(bundle.read_bytes()).hexdigest(), clean

    def forbid_hosted_state_owners(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_execution_budget as budget, hia_native_retirement as retirement
        stack = ExitStack()
        for owner, names in (
                (HIAAgentService, ('_reference_call', '_reference_consume_attempt')),
                (budget._ReferenceExecutionBudgetStore, ('__init__', 'create', 'claim', 'observe')),
                (budget._ReferenceBudgetClaim, ('__init__', 'run', 'complete')),
                (retirement._ReferencePathIdentityPin, ('__init__',)),
                (retirement._ReferenceNativeRetirement, ('__init__',)),
                (retirement, ('_reference_observe_directory', '_reference_remove_directory'))):
            for name in names:
                stack.enter_context(patch.object(owner, name,
                    side_effect=AssertionError('selected state owner entered hosted policy')))
        return stack

    def test_pinned_bundle_keeps_both_budgets_and_v2_journal_on_original_sql_and_replay(self):
        from hepta.hia_agent_contract import installation_manifest
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_execution_budget_native import BudgetState
        from hepta.hia_native_helpers import native_helpers_identity, native_helpers_scope
        from hepta.hia_agent_store import wire
        from hepta import hia_agent_runner
        from tests.test_hia_agent_native_tools import AgentToolCase
        root = self.directory()
        bundle, digest, clean = self.state_owner_bundle(root)
        before_environment = dict(os.environ)
        case = AgentToolCase('runTest')
        try:
            with patch.dict(os.environ, clean, clear=True), \
                    native_helpers_scope(str(bundle), digest), self.forbid_hosted_state_owners():
                case.setUp()
                pins = installation_manifest()
                _base, _candidate, baseline, build, receipts = case.build_pair()
                attempts = [tuple(row) for row in case.service.store.db.execute(
                    'SELECT id,attempts FROM main.contexts ORDER BY id')]
                self.assertEqual(sorted(row[1] for row in attempts), [1, 1])
                candidate_call = next(row for row in reversed(case.client.records)
                                      if row['tool'] == 'hia_candidate')
                self.assertEqual(case.service.call('hia_candidate', candidate_call['arguments']),
                                 candidate_call['response'])
                self.assertEqual([tuple(row) for row in case.service.store.db.execute(
                    'SELECT id,attempts FROM main.contexts ORDER BY id')], attempts)
                arguments = case.session.arguments(baseline_artifact=baseline['native_artifact'],
                    candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                    verification_receipts=receipts)
                context = arguments['context']['id']
                before = dict(case.service.store.db.execute(
                    'SELECT * FROM main.execution_budgets WHERE context_id=?', (context,)).fetchone())
                request_count = case.service.store.db.execute('SELECT count(*) FROM main.requests').fetchone()[0]
                self.assertEqual((before['used_native_ns'], before['owner']), ('0', None))
                actual, events = [], []
                run_native, call_budget = hia_agent_runner.run_native_batch, BudgetState.call
                def observed(*args, **kwargs):
                    result = run_native(*args, **kwargs)
                    if kwargs.get('_mode') != 'reference':
                        actual.append(result)
                    return result
                def budget_event(state, event, **kwargs):
                    result = call_budget(state, event, **kwargs)
                    events.append(event)
                    return result
                with patch.object(hia_agent_runner, 'run_native_batch', side_effect=observed), \
                        patch.object(BudgetState, 'call', budget_event):
                    first = case.service.call('hia_evaluate', arguments)
                self.assertEqual(first['status'], 'completed', first)
                self.assertTrue(actual)
                self.assertTrue(all(row['started'] and row['termination_confirmed'] for row in actual))
                self.assertIn(6, events)
                after = dict(case.service.store.db.execute(
                    'SELECT * FROM main.execution_budgets WHERE context_id=?', (context,)).fetchone())
                self.assertGreater(int(after['used_native_ns']), 0)
                self.assertIsNone(after['owner'])
                self.assertEqual(case.service.store.db.execute('SELECT count(*) FROM main.requests').fetchone()[0],
                                 request_count + 1)
                case.service.close()
                case.service = HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
                with patch.object(hia_agent_runner, 'run_native_batch', side_effect=AssertionError('replayed effect')):
                    self.assertEqual(case.service.call('hia_evaluate', arguments), first)
                    self.assertEqual(case.service.call('hia_candidate', candidate_call['arguments']),
                                     candidate_call['response'])
                self.assertEqual(dict(case.service.store.db.execute(
                    'SELECT * FROM main.execution_budgets WHERE context_id=?', (context,)).fetchone()), after)
                self.assertEqual([tuple(row) for row in case.service.store.db.execute(
                    'SELECT id,attempts FROM main.contexts ORDER BY id')], attempts)
                self.assertEqual(native_helpers_identity()['native_helpers_sha256'], digest)
                case.service.close()
            self.assertEqual(dict(os.environ), before_environment)
            script = '''import sys
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
from hepta import hia_execution_budget as reference,hia_agent_runner
def forbidden(*args,**kwargs): raise AssertionError("host policy or replayed native effect")
HIAAgentService._reference_call=forbidden
HIAAgentService._reference_consume_attempt=forbidden
reference._ReferenceExecutionBudgetStore.__init__=forbidden
reference._ReferenceBudgetClaim.__init__=forbidden
hia_agent_runner.run_native_batch=forbidden
raise SystemExit(main(sys.argv[1:]))
'''
            envelope = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_evaluate',
                        'arguments': arguments, 'profile_sha256': 'a' * 64,
                        'catalog_sha256': pins['catalog_sha256']}
            envelope['request_sha256'] = sha256(wire(envelope)).hexdigest()
            child = subprocess.run([sys.executable, '-B', '-E', '-s', '-c', script,
                '--state-root', str(case.state_root), '--request-json-stdin',
                '--native-helpers-manifest', str(bundle), '--expected-native-helpers-sha256', digest],
                input=wire(envelope), capture_output=True, cwd=ROOT, env=clean, timeout=60)
            (root / 'worker.stdout').write_bytes(child.stdout)
            (root / 'worker.stderr').write_bytes(child.stderr)
            self.assertEqual(child.returncode, 0, child.stderr.decode())
            report = json.loads(child.stdout)
            self.assertEqual(report['native_helpers_sha256'], digest)
            self.assertEqual(report['response'], first)
            with sqlite3.connect(case.state_root / 'state.sqlite3') as database:
                database.row_factory = sqlite3.Row
                self.assertEqual([tuple(row) for row in database.execute(
                    'SELECT id,attempts FROM main.contexts ORDER BY id')], attempts)
                self.assertEqual(dict(database.execute(
                    'SELECT * FROM main.execution_budgets WHERE context_id=?', (context,)).fetchone()), after)
                self.assertEqual(database.execute('SELECT count(*) FROM main.requests').fetchone()[0],
                                 request_count + 1)
            (root / 'observation.json').write_text(json.dumps({'bundle_sha256': digest,
                'attempts': attempts, 'execution_budget_before': before, 'execution_budget_after': after,
                'actual_native_children': actual, 'native_budget_events': events,
                'original_requests_after': request_count + 1,
                'matching_current_source_cold_qualified': bool(self.cold)}, sort_keys=True) + '\n')
        finally:
            if hasattr(case, 'service'):
                case.tearDown()

    def test_same_pinned_bundle_retires_actual_multiversion_after_rollback_lease_exit(self):
        from hepta.hia_native_helpers import native_helpers_identity, native_helpers_scope
        from tests.test_hia_multiversion import MultiversionNativeTests
        root = self.directory()
        bundle, digest, clean = self.state_owner_bundle(root)
        output = io.StringIO()
        before_environment = dict(os.environ)
        with patch.dict(os.environ, clean, clear=True), \
                native_helpers_scope(str(bundle), digest), self.forbid_hosted_state_owners():
            suite = unittest.TestSuite([MultiversionNativeTests(
                'test_rollback_changes_future_calls_and_retains_old_lease')])
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
            self.assertEqual(native_helpers_identity()['native_helpers_sha256'], digest)
        self.assertEqual(dict(os.environ), before_environment)
        (root / 'multiversion.log').write_text(output.getvalue())
        self.assertEqual(result.testsRun, 1, output.getvalue())
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assertFalse(result.errors or result.failures or result.skipped or
                         result.expectedFailures or result.unexpectedSuccesses, output.getvalue())
        (root / 'observation.json').write_text(json.dumps({'bundle_sha256': digest,
            'original_multiversion_tests_run': result.testsRun, 'hosted_retirement_forbidden': True,
            'matching_current_source_cold_qualified': bool(self.cold)}, sort_keys=True) + '\n')

    def ordinary_case(self, root, native_journal):
        from hepta.hia_agent_service import HIAAgentService
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program, exhaustive_u8_workload
        with ExitStack() as stack:
            stack.enter_context(self.selected())
            stack.enter_context(patch.object(HIAAgentService, '_reference_consume_attempt', side_effect=AssertionError('host attempt owner entered')))
            if native_journal:
                stack.enter_context(patch.dict(os.environ, {'HEPTA_HIA_AGENT_JOURNAL_MANIFEST': str(self.journal())}))
                stack.enter_context(patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('host journal entered')))
            service = HIAAgentService(root); stack.callback(service.close)
            session = Session(ToolClient(service.call), prefix='native-attempt')
            session.freeze(exhaustive_u8_workload(), budget={'max_candidates': 2})
            good = session.artifact(add_program())
            bad = session.artifact('invalid core document')
            first = session.arguments(change={'kind': 'import', 'format': 'core-json', 'source': good})
            result = service.call('hia_candidate', first)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(service.call('hia_candidate', first), result)
            count = lambda: service.store.db.execute('SELECT attempts FROM contexts WHERE id=?', (session.context['id'],)).fetchone()[0]
            self.assertEqual(count(), 1)
            second = session.arguments(change={'kind': 'import', 'format': 'core-json', 'source': bad})
            failed = service.call('hia_candidate', second)
            self.assertEqual(failed['status'], 'rejected', failed)
            self.assertEqual(count(), 2)
            self.assertEqual(service.call('hia_candidate', second), failed)
            denied = service.call('hia_candidate', session.arguments(change={'kind': 'import', 'format': 'core-json', 'source': good}))
            self.assertEqual(denied['error']['code'], 'E_HIA_BUDGET')
            self.assertEqual(count(), 2)
            # A selector change cannot swap a policy held by an existing service.
            with patch.dict(os.environ, {SELECTOR: '/missing/new-selection'}):
                self.assertEqual(service.call('hia_candidate', first), result)
        with self.selected():
            reopened = HIAAgentService(root)
            try:
                self.assertEqual(reopened.call('hia_candidate', first), result)
                self.assertEqual(reopened.store.db.execute('SELECT attempts FROM contexts WHERE id=?', (session.context['id'],)).fetchone()[0], 2)
            finally:
                reopened.close()

    def test_ordinary_tool_route_charges_failed_candidates_and_replays_once(self):
        self.ordinary_case(self.directory() / 'state', False)

    def test_native_journal_composition_uses_same_attempts_and_replays(self):
        self.ordinary_case(self.directory() / 'state', True)

    def test_present_missing_or_empty_selector_never_falls_back(self):
        from hepta.hia_agent_service import HIAAgentService
        root = self.directory()
        for index, selected in enumerate(('', str(root / 'missing'))):
            state = root / ('state-' + str(index))
            with patch.dict(os.environ, {SELECTOR: selected}), patch.object(
                    HIAAgentService, '_reference_consume_attempt', side_effect=AssertionError('fallback')):
                with self.assertRaises((ValueError, OSError)):
                    HIAAgentService(state)
            self.assertFalse(state.exists())

    def test_lost_commit_ack_is_bound_to_original_request_and_not_recharged(self):
        from hepta.hia_agent_service import HIAAgentService
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program, exhaustive_u8_workload
        with self.selected(), patch.object(HIAAgentService, '_reference_consume_attempt', side_effect=AssertionError('host policy')):
            service = HIAAgentService(self.directory() / 'state'); self.addCleanup(service.close)
            session = Session(ToolClient(service.call), prefix='lost-attempt-ack')
            session.freeze(exhaustive_u8_workload(), budget={'max_candidates': 2})
            source = session.artifact(add_program())
            args = session.arguments(change={'kind': 'import', 'format': 'core-json', 'source': source})
            original = service._candidate_budget._execute
            def lose_ack(sql, parameters=()):
                result = original(sql, parameters)
                if sql == 'COMMIT':
                    raise OSError('actual commit completed before lost acknowledgement')
                return result
            with patch.object(service._candidate_budget, '_execute', side_effect=lose_ack), patch.object(
                    service, '_hia_candidate', side_effect=AssertionError('candidate ran before confirmed charge')):
                response = service.call('hia_candidate', args)
            self.assertEqual(response['error']['code'], 'E_HIA_CANDIDATE_BUDGET_UNKNOWN')
            self.assertEqual(service.call('hia_candidate', args), response)
            count = service.store.db.execute('SELECT attempts FROM contexts WHERE id=?', (session.context['id'],)).fetchone()[0]
            self.assertEqual(count, 1)

    def test_actual_process_death_before_and_after_commit_keeps_request_fenced(self):
        from hepta.hia_agent_service import HIAAgentService
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program, exhaustive_u8_workload
        root = self.directory()
        child = '''
import json,os,sys
sys.path.insert(0,sys.argv[1])
from hepta.hia_agent_service import HIAAgentService
service=HIAAgentService(sys.argv[2])
original=service._candidate_budget._execute
def cut(sql,parameters=()):
    if sql=='COMMIT' and sys.argv[4]=='before': os._exit(73)
    result=original(sql,parameters)
    if sql=='COMMIT' and sys.argv[4]=='after': os._exit(73)
    return result
service._candidate_budget._execute=cut
with open(sys.argv[3]) as stream: args=json.load(stream)
service.call('hia_candidate',args)
raise SystemExit('process-cut fixture did not reach the actual commit')
'''
        for native_journal in (False, True):
            for boundary, expected in (('before', 0), ('after', 1)):
                with self.subTest(native_journal=native_journal, boundary=boundary):
                    case = root / (str(native_journal) + '-' + boundary); case.mkdir()
                    environment = {**os.environ, SELECTOR: str(self.manifest)}
                    environment.pop('HEPTA_HIA_AGENT_JOURNAL_MANIFEST', None)
                    if native_journal:
                        environment['HEPTA_HIA_AGENT_JOURNAL_MANIFEST'] = str(self.journal())
                    with patch.dict(os.environ, environment, clear=True):
                        service = HIAAgentService(case / 'state')
                        try:
                            session = Session(ToolClient(service.call), prefix='killed-attempt')
                            session.freeze(exhaustive_u8_workload(), budget={'max_candidates': 2})
                            source = session.artifact(add_program())
                            args = session.arguments(change={'kind': 'import', 'format': 'core-json', 'source': source})
                            request = case / 'request.json'; request.write_text(json.dumps(args))
                        finally:
                            service.close()
                        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                            str(ROOT), str(case / 'state'), str(request), boundary],
                            env=environment, cwd=case, capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 73, result.stderr)
                        reopened = HIAAgentService(case / 'state')
                        try:
                            with patch.object(reopened, '_hia_candidate', side_effect=AssertionError('unfinished request replayed')):
                                response = reopened.call('hia_candidate', args)
                            self.assertEqual(response['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                            actual = reopened.store.db.execute('SELECT attempts FROM contexts WHERE id=?', (session.context['id'],)).fetchone()[0]
                            self.assertEqual(actual, expected)
                            self.assertEqual(reopened.call('hia_candidate', args)['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                        finally:
                            reopened.close()

    def test_creator_state_protocol_poison_and_source_custody(self):
        state = AttemptState(self.image, (31, 37), CONTEXT.decode(), 2)
        state.call(1, a=1)
        with self.assertRaises(AgentRejected):
            state.call(1, a=1, sequence=1)
        with self.assertRaises(AgentRejected):
            state.row({'id': CONTEXT.decode(), 'attempts': 0})
        store = AgentStore(self.directory() / 'state'); self.addCleanup(store.close)
        driver = self.driver(store)
        context = self.context(store)
        driver.source_bytes += b'changed snapshot'
        with self.assertRaisesRegex(AgentRejected, 'source changed'):
            driver.consume(context, 1)
        self.assertEqual(store.db.execute('SELECT attempts FROM contexts WHERE id=?', (context,)).fetchone()[0], 0)

    def test_failed_service_construction_closes_both_actual_sqlite_connections(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_candidate_budget_native as native
        root = self.directory()
        bad_root = root / 'ordinary-file'; bad_root.write_bytes(b'not a directory')
        original = native.NativeCandidateBudgetStore
        observed = []
        def capture(*args, **kwargs):
            value = original(*args, **kwargs)
            observed.append(value)
            return value
        with self.selected(), patch.object(native, 'NativeCandidateBudgetStore', side_effect=capture):
            with self.assertRaises(AgentRejected):
                HIAAgentService(root / 'bad-artifact-root', artifact_roots=(bad_root,))
            with patch.object(HIAAgentService, '_profiles', side_effect=OSError('injected profile initialization failure')):
                with self.assertRaisesRegex(OSError, 'profile initialization failure'):
                    HIAAgentService(root / 'bad-profile')
        self.assertEqual(len(observed), 2)
        for owner in observed:
            self.assertTrue(owner.closed)
            with self.assertRaises(sqlite3.ProgrammingError):
                owner.db.execute('SELECT 1')
            with self.assertRaises(sqlite3.ProgrammingError):
                owner.store.db.execute('SELECT 1')

    def test_execution_budget_connection_admission_failure_closes_official_connection(self):
        from hepta import hia_execution_budget_native as native
        from tools.qualify_hia_selfhost import compile_stage
        case = self.directory()
        if self.cold:
            from tools.build_hia_execution_budget import build
            manifest = build(case / 'qualified-execution-budget', self.compiler, self.cold)
        else:
            image, _receipt = compile_stage(case, 'execution-budget', self.compiler, native.SOURCE.read_bytes())
            manifest = case / 'execution-manifest.json'
            manifest.write_text(json.dumps({'schema': native.SCHEMA,
                'source_sha256': sha256(native.SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(self.compiler.read_bytes()).hexdigest()}) + '\n')
        connections = []
        original_connect, original_check = sqlite3.connect, native.NativeExecutionBudgetStore.check
        def connect(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            connections.append(connection)
            return connection
        calls = 0
        def actual_wal_drift(owner):
            nonlocal calls
            calls += 1
            if calls == 2:
                wal = Path(str(owner.path) + '-wal')
                wal.rename(case / 'original-open-wal')
            return original_check(owner)
        with patch.dict(os.environ, {native.SELECTOR: str(manifest)}), patch.object(
                sqlite3, 'connect', side_effect=connect), patch.object(
                native.NativeExecutionBudgetStore, 'check', actual_wal_drift):
            with self.assertRaises(FileNotFoundError):
                AgentStore(case / 'state')
        self.assertEqual(len(connections), 2)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute('SELECT 1')

    def test_installed_sdist_wheel_ordinary_budget_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        case = self.directory()
        source = case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        built = subprocess.run([packaging, '-B', 'setup.py', 'sdist', '--dist-dir', str(case / 'sdist')],
                               cwd=source, capture_output=True, timeout=90)
        (case / 'sdist.log').write_bytes(built.stdout + built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        archive, = (case / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as tar:
            prefix = tar.getnames()[0].split('/')[0] + '/'
            for name in resources:
                self.assertEqual(tar.extractfile(prefix + name).read(), (ROOT / name).read_bytes(), name)
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(case / 'wheels'), str(archive)],
            cwd=case, capture_output=True, timeout=90)
        (case / 'wheel.log').write_bytes(built.stdout + built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = (case / 'wheels').glob('*.whl')
        installed = case / 'installed'
        result = subprocess.run([packaging, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=case, capture_output=True, timeout=90)
        (case / 'install.log').write_bytes(result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        child = '''
import importlib.abc,json,os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed candidate budget imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected
from hepta.hia_candidate_budget_native import SOURCE,SELECTOR
def forbidden(*args,**kwargs):raise AssertionError('installed candidate budget used reference policy')
HIAAgentService._reference_consume_attempt=forbidden
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
os.environ[SELECTOR]=sys.argv[2]
service=HIAAgentService(sys.argv[3])
service.store.db.execute('INSERT INTO contexts VALUES (?,?,?,?,?)',('ctx-installed','a'*64,'{}',str(time.time_ns()),4095))
context={'ref':{'id':'ctx-installed'},'budget':{'max_candidates':4096,'max_total_wall_ms':86400000}}
service._budget(context,candidate=True)
try: service._budget(context,candidate=True)
except AgentRejected as error: assert error.code=='E_HIA_BUDGET',error.code
else: raise AssertionError('maximum candidate count did not exhaust')
assert service.store.db.execute('SELECT attempts FROM contexts').fetchone()[0]==4096
assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
service.close()
service=HIAAgentService(sys.argv[3])
assert service.store.db.execute('SELECT attempts FROM contexts').fetchone()[0]==4096
service.close()
source=SOURCE.read_bytes()
for replacement in (None,b'changed installed source'):
    if replacement is None: SOURCE.unlink()
    else: SOURCE.write_bytes(replacement)
    try: HIAAgentService(sys.argv[3]+'-refused')
    except (ValueError,OSError): pass
    else: raise AssertionError('source custody used a checkout or hosted fallback')
    assert not Path(sys.argv[3]+'-refused').exists()
    SOURCE.write_bytes(source)
print(json.dumps({'attempts':4096,'authoring_imported':False,'reference_called':False,'source_controls':2}))
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child, str(installed),
            str(self.manifest), str(case / 'state')], cwd=case, env={**os.environ, 'PATH': ''},
            capture_output=True, text=True, timeout=30)
        (case / 'actual.stdout').write_text(result.stdout)
        (case / 'actual.stderr').write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['attempts'], 4096)


if __name__ == '__main__':
    unittest.main()
