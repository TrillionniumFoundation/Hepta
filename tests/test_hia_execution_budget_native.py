"""Independent HIA state observations and real SQLite budget authority."""
from __future__ import annotations

from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
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
import threading
import time
import unittest
from unittest.mock import patch

from hepta.hia_execution_budget_native import (BudgetState, NativeExecutionBudgetImage,
    REQUEST_MAGIC, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE, STATE_BYTES, OUTPUT_BYTES)

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = b'ctx-' + b'1' * 32
OWNER = b'a' * 64


def packet(event, sequence=0, values=(), *, now=0, payload=b'', identity=(11, 17), connection=(31, 37)):
    words = [REQUEST_MAGIC, event, sequence, now, *values]
    words += [0] * (12 - len(words))
    return struct.pack('<16Q', *words, *identity, *connection) + payload


def row_packet(sequence, used, owner, *, context=CONTEXT):
    if used is None:
        return packet(2, sequence, (0, 0, 0, 0, 0))
    raw_owner = b'' if owner is None else owner
    return packet(2, sequence, (1, int(owner is not None), len(context), len(used), len(raw_owner)),
                  payload=context + used + raw_owner)


def decoded(row):
    count, output, _state = row
    assert count >= 128, count
    fields = struct.unpack('<16Q', output[:128])
    assert fields[0] == RESULT_MAGIC
    at, values = 128, []
    for size in fields[8:13]:
        values.append(output[at:at + size]); at += size
    assert at == count
    return fields, values


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.checked = assemble_program(SOURCE.read_bytes())
        self.entry = next(f for f in self.checked.as_dict()['functions'] if f['name'] == 'f0')
        self.state = bytearray(STATE_BYTES)

    def call(self, raw):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        objects = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(OUTPUT_BYTES)), _Owner(-3, self.state)]
        machine = _Machine(self.checked, 100000000, 16 << 20, None, 128)
        count = machine.invoke(self.entry, [_View(objects[0], False), _View(objects[1], True),
                                           _View(objects[2], True)])[0]
        return count, bytes(objects[1].data[:count]), bytes(self.state)


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
        assert source.raw == raw
        assert output.raw[OUTPUT_BYTES:] == b'\xa5' * 16
        assert self.state.raw[STATE_BYTES:] == b'\xb7' * 16
        return count, output.raw[:count], self.state.raw[:STATE_BYTES]


def witnesses(engine):
    rows, sequence = [], 0
    def call(event, values=(), *, payload=b'', now=0, row=None):
        nonlocal sequence
        raw = (row_packet(sequence, *row) if row is not None else
               packet(event, sequence, values, payload=payload, now=now))
        result = engine.call(raw)
        fields, values = decoded(result)
        assert fields[1] == 0, fields
        sequence = fields[3]
        rows.append((raw, result))
        return fields, values
    h, v = call(0, (1, 5, 1000000, len(CONTEXT), len(OWNER)), payload=CONTEXT + OWNER)
    assert h[2] == 1
    h, v = call(1, (1,)); assert h[2] == 2
    h, v = call(2, row=(b'999999', None)); assert (h[2], h[4]) == (4, 5)
    h, v = call(3, (1,)); assert h[2] == 2
    h, v = call(2, row=(b'999999', OWNER)); assert h[2] == 6
    h, v = call(4, (1,)); assert (h[2], h[5]) == (0, 7)
    h, v = call(5, (10,), now=2000000); assert (h[2], h[4]) == (7, 4)
    h, v = call(6, (1, 7), payload=b'1234567'); assert v[4] == b'1234567'
    h, v = call(5, (1,), now=3000000); assert (h[2], h[4]) == (7, 1)
    h, v = call(6, (1, 7), payload=b'7654321'); assert v[4] == b'8888888'
    h, v = call(10); assert h[2] == 1 and v[3] == b'9888887'
    call(1, (1,))
    h, v = call(2, row=(b'999999', OWNER)); assert h[2] == 5
    call(3, (1,))
    h, v = call(2, row=(b'9888887', None)); assert h[2] == 6
    h, v = call(4, (1,)); assert (h[2], h[5]) == (0, 8)
    return rows


class ExecutionBudgetSourceTests(unittest.TestCase):
    def test_fixture_cold_admission_precedes_evidence_seed_and_compilation(self):
        class ColdFixture(ExecutionBudgetNativeTests):
            pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / 'cold.json'
            report.write_text('{}')
            evidence = root / 'must-not-exist'
            selected = {'HEPTA_HIA_EXECUTION_BUDGET_COLD_REPORT': str(report),
                        'HEPTA_HIA_EXECUTION_BUDGET_EVIDENCE': str(evidence)}
            with patch.dict(os.environ, selected), patch.dict(os.environ, {
                    'HEPTA_HIA_EXECUTION_BUDGET_DEVELOPMENT_COMPILER': ''}), patch(
                    'tools.qualify_hia_selfhost.build_seed', side_effect=AssertionError('seed entered')), patch(
                    'tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compile entered')):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'):
                    ColdFixture.setUpClass()
            self.assertFalse(evidence.exists())
            with patch.dict(os.environ, selected | {
                    'HEPTA_HIA_EXECUTION_BUDGET_DEVELOPMENT_COMPILER': '/unread-development-compiler'}), patch.object(
                    Path, 'read_bytes', side_effect=AssertionError('artifact read')):
                with self.assertRaisesRegex(ValueError, 'development compiler cannot be combined'):
                    ColdFixture.setUpClass()
            self.assertFalse(evidence.exists())

    def test_generated_source_and_independent_vm_full_claim_run_completion(self):
        from tools.generate_hia_execution_budget import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(witnesses(VM())), 16)

    def test_bad_cold_builder_refuses_before_output_or_native_compilation(self):
        from tools.build_hia_execution_budget import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not qualified')
            (root / 'cold').write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('native compile entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(root / 'output', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'output').exists())


class ExecutionBudgetNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage, build_seed
        cold = os.environ.get('HEPTA_HIA_EXECUTION_BUDGET_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_EXECUTION_BUDGET_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('development compiler cannot be combined with an execution budget cold report')
        cls.cold_report = Path(cold) if cold else None
        cls.journal_manifest = None
        if cold:
            from tools.build_hia_execution_budget import admit_cold_build
            cold = Path(cold)
            cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes)
            try:
                nested = json.loads(Path(report['nested_report']).read_bytes())
                compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('execution budget cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            admit_cold_build(compiler_bytes, cold_bytes)
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_EXECUTION_BUDGET_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-execution-budget-')
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_execution_budget import build
            cls.manifest = build(cls.folder / 'qualified-execution-budget', compiler, cold)
            manifest = json.loads(cls.manifest.read_bytes())
            image = cls.manifest.parent / manifest['image_path']
            cls.image = NativeExecutionBudgetImage(image.read_bytes(), manifest['image_sha256'])
            if cold.read_bytes() != cold_bytes or compiler.read_bytes() != compiler_bytes:
                raise AssertionError('qualified execution budget fixture inputs changed')
            cls.compiler = compiler
            (cls.folder / 'qualified-build.json').write_text(json.dumps({
                'mode': 'MATCHING_CURRENT_SOURCE_COLD_BUILD',
                'manifest_path': str(cls.manifest),
                'cold_report_sha256': sha256(cold_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest(),
                'matching_current_source_cold_qualified': True,
            }, indent=2) + '\n')
            return
        if development:
            compiler = Path(development)
            mode = 'DEVELOPMENT_REUSED_COMPILER'
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            mode = 'DEVELOPMENT_B0_B1_B2'
        cls.compiler = compiler
        image, receipt = compile_stage(cls.folder, 'execution-budget', compiler, SOURCE.read_bytes())
        cls.image = NativeExecutionBudgetImage(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        manifest = {'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': cls.image.image_sha256,
            'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
        (cls.folder / 'development-build.json').write_text(json.dumps({'mode': mode,
            'manifest': manifest, 'compile_receipt': receipt,
            'matching_current_source_cold_qualified': False}, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None: cls.temporary.cleanup()

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def selected_journal_v2(self):
        """Compose the current journal image without substituting the v67 owner."""
        cls = type(self)
        if cls.journal_manifest is None:
            if cls.cold_report is not None:
                from tools.build_hia_json_preflight import build
                cls.journal_manifest = build(cls.folder / 'qualified-agent-journal',
                    cls.compiler, cls.cold_report, candidate='agent-journal')
            else:
                from tools.qualify_hia_selfhost import compile_stage
                from hepta.hia_agent_journal_native import SOURCE as journal_source, SCHEMA as journal_schema
                image, receipt = compile_stage(cls.folder, 'agent-journal-v2', cls.compiler,
                                               journal_source.read_bytes())
                manifest = {'schema': journal_schema,
                    'source_sha256': sha256(journal_source.read_bytes()).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}
                cls.journal_manifest = cls.folder / 'agent-journal-v2-manifest.json'
                cls.journal_manifest.write_text(json.dumps(manifest, indent=2) + '\n')
                (cls.folder / 'agent-journal-v2-development-build.json').write_text(json.dumps({
                    'mode': 'DEVELOPMENT_REUSED_COMPILER', 'manifest': manifest,
                    'compile_receipt': receipt, 'matching_current_source_cold_qualified': False},
                    indent=2) + '\n')
        from hepta.hia_agent_journal_native import SELECTOR as journal_selector
        from hepta.hia_agent_service import HIAAgentService
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {journal_selector: str(cls.journal_manifest)}))
        stack.enter_context(patch.object(HIAAgentService, '_reference_call',
                                        side_effect=AssertionError('hosted journal policy called')))
        return stack

    def test_machine_matches_every_independent_vm_state_byte(self):
        machine = Machine(self.image)
        for raw, expected in witnesses(VM()):
            self.assertEqual(machine.call(raw), expected)

    def test_actual_original_sqlite_rows_claim_cost_complete_and_observe(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            try:
                budget = store.execution_budgets
                self.assertIsNot(budget.db, store.db)
                budget.create(CONTEXT.decode())
                original = tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone())
                self.assertEqual(original, (CONTEXT.decode(), '0', None))
                claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                self.assertEqual(budget.observe(CONTEXT.decode())['owner'], OWNER.decode())
                recorded = []
                def finished(*args, **kwargs):
                    recorded.append(kwargs['timeout_ms'])
                    return {'termination_confirmed': True, 'wall_ns': '18446744073709551616'}
                claim.run(finished, now=500000, total_ms=1000)
                self.assertEqual(recorded, [1000])
                self.assertEqual(claim.native_ns, '18446744073709551616')
                claim.complete()
                row = tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone())
                self.assertEqual(row, (CONTEXT.decode(), '18446744073709551616', None))
                observed = budget.observe(CONTEXT.decode())
                self.assertEqual(observed['used_native_ns'], row[1])
                self.assertIsNone(observed['owner'])
                self.assertFalse(observed['execution_authority_granted'])
                captured = claim.snapshot()
                self.assertNotIn('owner', captured)
                self.assertNotIn('used_native_ns', captured)
                self.assertEqual(captured['captured_used_native_ns'], '0')
                self.assertEqual(captured['proposed_used_native_ns'], row[1])
                self.assertEqual(captured['claim_owner'], OWNER.decode())
            finally:
                store.close()

    def test_default_reference_original_budget_ordering(self):
        from hepta.hia_agent_store import AgentStore
        reference_environment = {key: value for key, value in os.environ.items() if key != SELECTOR}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, reference_environment, clear=True):
            store = AgentStore(directory)
            try:
                budget = store.execution_budgets; budget.create(CONTEXT.decode())
                claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                claim.run(lambda **kw: {'wall_ns': '19', 'termination_confirmed': True}, now=0, total_ms=1000)
                claim.complete()
                self.assertEqual(tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone()),
                                 (CONTEXT.decode(), '19', None))
            finally: store.close()

    def test_actual_claim_precommit_failure_rolls_back_and_lost_commit_ack_stays_owned(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        for after in (False, True):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                budget = store.execution_budgets
                try:
                    budget.create(CONTEXT.decode())
                    execute, events = budget._execute, []
                    original = OSError('actual claim COMMIT acknowledgement fault')
                    def interrupt(sql, parameters=()):
                        if sql == 'COMMIT':
                            events.append('commit')
                            if after: execute(sql, parameters)
                            raise original
                        events.append(sql.split()[0])
                        return execute(sql, parameters)
                    with patch.object(budget, '_execute', side_effect=interrupt):
                        with self.assertRaises(OSError) as caught:
                            budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    self.assertIs(caught.exception, original)
                    self.assertEqual(events.count('commit'), 1)
                    self.assertEqual(events.count('ROLLBACK'), int(not after))
                    self.assertFalse(budget.db.in_transaction)
                    row = budget.observe(CONTEXT.decode())
                    self.assertEqual(row['used_native_ns'], '0')
                    self.assertEqual(row['owner'], OWNER.decode() if after else None)
                    if after:
                        with self.assertRaises(AgentRejected) as rejected:
                            budget.claim(CONTEXT.decode(), 'b' * 64, 1000, 0)
                        self.assertEqual(rejected.exception.code, 'E_HIA_BUDGET_BUSY')
                    else:
                        claim = budget.claim(CONTEXT.decode(), 'b' * 64, 1000, 0)
                        claim.complete()
                finally: store.close()

    def test_actual_completion_lost_ack_is_never_replayed_from_equal_cost(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        for cost in ('0', '19'):
            with self.subTest(cost=cost), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                budget = store.execution_budgets
                try:
                    budget.create(CONTEXT.decode())
                    claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    claim.run(lambda **kw: {'wall_ns': cost, 'termination_confirmed': True}, now=0, total_ms=1000)
                    execute = budget._execute
                    def lost(sql, parameters=()):
                        cursor = execute(sql, parameters)
                        if sql == 'COMMIT': raise KeyboardInterrupt('lost successful completion acknowledgement')
                        return cursor
                    with patch.object(budget, '_execute', side_effect=lost):
                        with self.assertRaises(KeyboardInterrupt): claim.complete()
                    self.assertEqual(budget.observe(CONTEXT.decode())['used_native_ns'], cost)
                    self.assertIsNone(budget.observe(CONTEXT.decode())['owner'])
                    with patch.object(budget, '_execute', side_effect=AssertionError('fenced claim executed SQL')):
                        with self.assertRaises(AgentRejected): claim.complete()
                        runner = unittest.mock.Mock()
                        with self.assertRaises(AgentRejected): claim.run(runner, now=0, total_ms=1000)
                        runner.assert_not_called()
                    # A later distinct request can complete with identical
                    # cost; that does not resolve the old claim's lost reply.
                    later = budget.claim(CONTEXT.decode(), 'b' * 64, 1000, 0)
                    later.complete()
                    self.assertEqual(budget.observe(CONTEXT.decode())['used_native_ns'], cost)
                    self.assertFalse(budget.observe(CONTEXT.decode())['historical_completion_receipt'])
                    with self.assertRaises(AgentRejected): claim.complete()
                finally: store.close()

    def test_actual_uncertain_or_interrupted_run_never_clears_or_retries_owner(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        for kind in ('false', 'integer-one', 'interrupted'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                try:
                    budget = store.execution_budgets; budget.create(CONTEXT.decode())
                    claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    calls = []
                    def runner(**kwargs):
                        calls.append(kwargs['timeout_ms'])
                        if kind == 'interrupted': raise KeyboardInterrupt('unconfirmed foreign outcome')
                        return {'wall_ns': '17', 'termination_confirmed': False if kind == 'false' else 1}
                    with self.assertRaises(KeyboardInterrupt if kind == 'interrupted' else AgentRejected):
                        claim.run(runner, now=0, total_ms=1000)
                    self.assertEqual(calls, [1000])
                    self.assertEqual(budget.observe(CONTEXT.decode())['owner'], OWNER.decode())
                    self.assertEqual(budget.observe(CONTEXT.decode())['used_native_ns'], '0')
                    with self.assertRaises(AgentRejected): claim.complete()
                    with self.assertRaises(AgentRejected): claim.run(runner, now=0, total_ms=1000)
                    self.assertEqual(calls, [1000])
                    with self.assertRaises(AgentRejected) as busy:
                        budget.claim(CONTEXT.decode(), 'b' * 64, 1000, 0)
                    self.assertEqual(busy.exception.code, 'E_HIA_BUDGET_BUSY')
                finally: store.close()

    def test_actual_owner_and_original_cost_cas_refuse_concurrent_change(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        for field in ('owner', 'used_native_ns'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                try:
                    budget = store.execution_budgets; budget.create(CONTEXT.decode())
                    claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    claim.run(lambda **kw: {'wall_ns': '5', 'termination_confirmed': True}, now=0, total_ms=1000)
                    value = 'b' * 64 if field == 'owner' else '99'
                    store.db.execute('UPDATE execution_budgets SET ' + field + '=? WHERE context_id=?',
                                     (value, CONTEXT.decode()))
                    before = tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone())
                    with self.assertRaises(AgentRejected) as failed: claim.complete()
                    self.assertEqual(failed.exception.code, 'E_HIA_BUDGET_CONFLICT')
                    self.assertEqual(tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone()), before)
                    self.assertFalse(budget.db.in_transaction)
                finally: store.close()

    def test_actual_rowcount_and_readback_faults_cannot_commit_a_claim(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        for kind in ('rowcount-zero', 'readback-wrong-owner'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                budget = store.execution_budgets
                try:
                    budget.create(CONTEXT.decode())
                    execute, reads = budget._execute, []
                    def changed(sql, parameters=()):
                        cursor = execute(sql, parameters)
                        if sql.startswith('UPDATE') and kind == 'rowcount-zero':
                            class WrongCount:
                                rowcount = 0
                            return WrongCount()
                        if sql.startswith('SELECT'):
                            reads.append(sql)
                            if kind == 'readback-wrong-owner' and len(reads) == 2:
                                row = dict(cursor.fetchone()); row['owner'] = 'b' * 64
                                class WrongReadback:
                                    def fetchone(self): return row
                                return WrongReadback()
                        return cursor
                    with patch.object(budget, '_execute', side_effect=changed):
                        with self.assertRaises(AgentRejected):
                            budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    self.assertEqual(tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone()),
                                     (CONTEXT.decode(), '0', None))
                    self.assertFalse(budget.db.in_transaction)
                finally: store.close()

    def test_actual_dedicated_transaction_cannot_capture_ordinary_writer(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            budget = store.execution_budgets
            held, release, attempted = threading.Event(), threading.Event(), threading.Event()
            try:
                budget.create(CONTEXT.decode())
                execute = budget._execute
                def pause(sql, parameters=()):
                    cursor = execute(sql, parameters)
                    if sql.startswith('UPDATE main.execution_budgets SET owner=?'):
                        held.set()
                        if not release.wait(5): raise TimeoutError('ordinary-writer control was not released')
                    return cursor
                def ordinary():
                    attempted.set()
                    store.db.execute('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
                                     (None, 'ordinary-writer', 'test', '7', 'completed', '{}'))
                with ThreadPoolExecutor(2) as pool, patch.object(budget, '_execute', side_effect=pause):
                    first = pool.submit(budget.claim, CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    self.assertTrue(held.wait(5))
                    second = pool.submit(ordinary)
                    self.assertTrue(attempted.wait(5))
                    try:
                        with self.assertRaises(FutureTimeout):
                            second.result(timeout=0.1)
                        with sqlite3.connect(store.database) as observer:
                            self.assertEqual(observer.execute('SELECT count(*) FROM costs').fetchone()[0], 0)
                            self.assertIsNone(observer.execute('SELECT owner FROM execution_budgets').fetchone()[0])
                    finally:
                        release.set()
                    claim = first.result(timeout=5)
                    second.result(timeout=5)
                self.assertEqual(store.db.execute('SELECT count(*) FROM costs').fetchone()[0], 1)
                self.assertEqual(budget.observe(CONTEXT.decode())['owner'], OWNER.decode())
                claim.complete()
                self.assertEqual(store.db.execute('SELECT count(*) FROM costs').fetchone()[0], 1)
            finally:
                release.set(); store.close()

    def test_actual_existing_transaction_is_not_borrowed_or_rolled_back(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            try:
                budget = store.execution_budgets; budget.create(CONTEXT.decode())
                with store.transaction():
                    store.db.execute('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
                                     (None, 'caller-owned', 'test', '11', 'completed', '{}'))
                    with self.assertRaises(AgentRejected) as failure:
                        budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    self.assertEqual(failure.exception.code, 'E_HIA_BUDGET_NATIVE_CUSTODY')
                    self.assertTrue(store.db.in_transaction)
                    self.assertFalse(budget.db.in_transaction)
                self.assertEqual(store.db.execute('SELECT count(*) FROM costs').fetchone()[0], 1)
                self.assertIsNone(budget.observe(CONTEXT.decode())['owner'])
            finally: store.close()

    def test_actual_process_crash_preserves_sqlite_pre_and_post_commit_boundaries(self):
        from hepta.hia_agent_store import AgentStore
        program = '''import json, os, sys
from hepta.hia_agent_store import AgentStore
store = AgentStore(sys.argv[1])
budget = store.execution_budgets
boundary = sys.argv[2]
context = 'ctx-' + '1' * 32
owner = 'a' * 64
execute = budget._execute
commits = 0
target = 1 if boundary.startswith('claim') else 2
def crash(sql, parameters=()):
    global commits
    if sql == 'COMMIT':
        commits += 1
        if commits == target:
            if boundary.endswith('after'):
                execute(sql, parameters)
            print(json.dumps({'boundary': boundary, 'commit_number': commits,
                              'in_transaction': budget.db.in_transaction}), flush=True)
            os._exit(73)
    return execute(sql, parameters)
budget._execute = crash
claim = budget.claim(context, owner, 1000, 0)
# A fixed terminated observation isolates durability from runner scheduling.
# Actual child execution and outcome loss are checked separately end-to-end.
claim.run(lambda **kw: {'wall_ns': '7', 'termination_confirmed': True}, now=0, total_ms=1000)
claim.complete()
raise AssertionError('the selected crash boundary was never reached')
'''
        for boundary in ('claim-before', 'claim-after', 'completion-before', 'completion-after'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                try:
                    store.execution_budgets.create(CONTEXT.decode())
                    child = subprocess.run([sys.executable, '-c', program, directory, boundary], cwd=ROOT,
                        env={**os.environ, SELECTOR: str(self.manifest)}, capture_output=True, text=True, timeout=30)
                    (self.folder / ('crash-' + boundary + '.stdout')).write_text(child.stdout)
                    (self.folder / ('crash-' + boundary + '.stderr')).write_text(child.stderr)
                    self.assertEqual(child.returncode, 73, child.stderr)
                    observed = json.loads(child.stdout)
                    self.assertEqual(observed['in_transaction'], boundary.endswith('before'))
                    used = '7' if boundary == 'completion-after' else '0'
                    owner = None if boundary in ('claim-before', 'completion-after') else OWNER.decode()
                    expected = (CONTEXT.decode(), used, owner)
                    self.assertEqual(tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone()), expected)
                finally: store.close()
                restarted = AgentStore(directory)
                try:
                    self.assertEqual(tuple(restarted.db.execute('SELECT * FROM execution_budgets').fetchone()), expected)
                    report = restarted.execution_budgets.observe(CONTEXT.decode())
                    self.assertEqual(report['used_native_ns'], used)
                    self.assertEqual(report['owner'], owner)
                    self.assertFalse(report['historical_completion_receipt'])
                finally: restarted.close()

    def test_actual_database_and_wal_replacement_refuse_without_new_store_or_effect(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        from hepta.hia_execution_budget_native import NativeExecutionBudgetStore
        for changed in ('database-missing', 'database-replaced', 'database-symlink', 'wal', 'shm'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                budget = store.execution_budgets
                budget.create(CONTEXT.decode())
                target = (store.database if changed.startswith('database') else
                          Path(str(store.database) + ('-wal' if changed == 'wal' else '-shm')))
                saved = target.with_name(target.name + '.held-original')
                target.rename(saved)
                marker = b'foreign replacement bytes must remain unchanged'
                if changed == 'database-symlink':
                    target.symlink_to(saved)
                elif changed != 'database-missing':
                    target.write_bytes(marker); target.chmod(0o600)
                try:
                    with patch.object(budget, '_execute', side_effect=AssertionError('identity drift reached SQL')):
                        with self.assertRaises((AgentRejected, OSError)):
                            budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                    with patch('hepta.hia_execution_budget_native.sqlite3.connect',
                               side_effect=AssertionError('mismatched official journal reached connect')):
                        with self.assertRaises((AgentRejected, OSError)):
                            NativeExecutionBudgetStore(store, self.image)
                    if changed == 'database-missing':
                        self.assertFalse(target.exists())
                    elif changed != 'database-symlink':
                        self.assertEqual(target.read_bytes(), marker)
                finally:
                    target.unlink(missing_ok=True); saved.rename(target)
                    store.close()

    def test_stored_noncanonical_cost_and_decimal_overflow_preserve_original_rows(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        invalid = ('-1', '+1', '00', '1.0', ' 1', '1\n', '١', '9' * 4301)
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            budget = store.execution_budgets
            try:
                budget.create(CONTEXT.decode())
                for cost in invalid:
                    with self.subTest(cost=cost[:30]):
                        store.db.execute('UPDATE execution_budgets SET used_native_ns=?', (cost,))
                        before = tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone())
                        with self.assertRaises(AgentRejected): budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                        self.assertEqual(tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone()), before)
                largest = '9' * 4300
                store.db.execute('UPDATE execution_budgets SET used_native_ns=?', (largest,))
                claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                seen = []
                def recorded(**kwargs):
                    seen.append(kwargs['timeout_ms'])
                    return {'termination_confirmed': True, 'wall_ns': '1'}
                claim.run(recorded, now=0, total_ms=1000)
                self.assertEqual(seen, [0])
                with self.assertRaises(AgentRejected) as overflow: claim.complete()
                self.assertEqual(overflow.exception.code, 'E_HIA_BUDGET_EXHAUSTED')
                self.assertEqual(tuple(store.db.execute('SELECT * FROM execution_budgets').fetchone()),
                                 (CONTEXT.decode(), largest, OWNER.decode()))
            finally: store.close()

    def test_actual_competing_native_claims_have_one_durable_owner(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        with tempfile.TemporaryDirectory() as directory, self.selected():
            first, second = AgentStore(directory), AgentStore(directory)
            try:
                first.execution_budgets.create(CONTEXT.decode())
                barrier = threading.Barrier(2)
                def compete(store, owner):
                    barrier.wait(timeout=5)
                    try:
                        return store.execution_budgets.claim(CONTEXT.decode(), owner, 1000, 0)
                    except AgentRejected as error:
                        return error
                with ThreadPoolExecutor(2) as pool:
                    futures = [pool.submit(compete, store, owner) for store, owner in
                               ((first, 'a' * 64), (second, 'b' * 64))]
                    results = [future.result(timeout=10) for future in futures]
                failures = [result for result in results if isinstance(result, AgentRejected)]
                winners = [result for result in results if not isinstance(result, AgentRejected)]
                self.assertEqual(len(failures), 1); self.assertEqual(len(winners), 1)
                self.assertEqual(failures[0].code, 'E_HIA_BUDGET_BUSY')
                owner = winners[0].snapshot()['claim_owner']
                self.assertEqual(first.execution_budgets.observe(CONTEXT.decode())['owner'], owner)
                winners[0].complete()
                self.assertIsNone(second.execution_budgets.observe(CONTEXT.decode())['owner'])
            finally:
                first.close(); second.close()

    def test_native_wrong_instance_replay_and_corruption_never_write_sql(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            try:
                budget = store.execution_budgets
                a_context, b_context = CONTEXT.decode(), 'ctx-' + '2' * 32
                budget.create(a_context); budget.create(b_context)
                first = budget.claim(a_context, 'a' * 64, 1000, 0)
                second = budget.claim(b_context, 'b' * 64, 1000, 0)
                token = first.state.call(5, values=(1000,), now=0).token
                with self.assertRaises(AgentRejected):
                    second.state.call(6, token=token, values=(1, 1), payload=b'1')
                first.state.call(6, token=token, values=(1, 2), payload=b'17')
                with self.assertRaises(AgentRejected):
                    first.state.call(6, token=token, values=(1, 2), payload=b'17')
                self.assertEqual(first.native_ns, '17')
                for claim in (first, second):
                    with patch.object(budget, '_execute', side_effect=AssertionError('fenced state executed SQL')):
                        with self.assertRaises(AgentRejected): claim.complete()
                self.assertEqual(budget.observe(a_context)['owner'], 'a' * 64)
                self.assertEqual(budget.observe(b_context)['owner'], 'b' * 64)
                c_context = 'ctx-' + '3' * 32
                budget.create(c_context)
                damaged = budget.claim(c_context, 'c' * 64, 1000, 0)
                damaged.state.buffer[512] = b'X'
                with patch.object(budget, '_execute', side_effect=AssertionError('damaged state executed SQL')):
                    with self.assertRaises(AgentRejected): damaged.complete()
                self.assertEqual(budget.observe(c_context)['owner'], 'c' * 64)
            finally: store.close()

    def test_actual_temp_shadow_cannot_replace_main_journal_claim_authority(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        from hepta import hia_execution_budget as reference
        with tempfile.TemporaryDirectory() as directory, self.selected(), \
             patch.object(reference._ReferenceExecutionBudgetStore, '__init__',
                          side_effect=AssertionError('old execution budget policy')):
            first, second = AgentStore(directory), AgentStore(directory)
            try:
                budget = first.execution_budgets
                budget.db.execute('CREATE TEMP TABLE execution_budgets '
                    '(context_id TEXT PRIMARY KEY,used_native_ns TEXT NOT NULL,owner TEXT)')
                budget.db.execute('INSERT INTO temp.execution_budgets VALUES (?,?,NULL)',
                                  (CONTEXT.decode(), '0'))
                shadow = tuple(budget.db.execute('SELECT * FROM temp.execution_budgets').fetchone())
                # Even a present TEMP row cannot substitute for main creation,
                # claim admission, readback, observation or completion.
                budget.create(CONTEXT.decode())
                claim = budget.claim(CONTEXT.decode(), OWNER.decode(), 1000, 0)
                durable = tuple(first.db.execute('SELECT * FROM main.execution_budgets').fetchone())
                self.assertEqual(durable, (CONTEXT.decode(), '0', OWNER.decode()))
                self.assertEqual(budget.observe(CONTEXT.decode())['owner'], OWNER.decode())
                with self.assertRaises(AgentRejected) as busy:
                    second.execution_budgets.claim(CONTEXT.decode(), 'b' * 64, 1000, 0)
                self.assertEqual(busy.exception.code, 'E_HIA_BUDGET_BUSY')
                calls = []
                def terminated(**kwargs):
                    calls.append(kwargs['timeout_ms'])
                    return {'wall_ns': '7', 'termination_confirmed': True}
                claim.run(terminated, now=0, total_ms=1000)
                claim.complete()
                self.assertEqual(calls, [1000])
                self.assertEqual(tuple(first.db.execute('SELECT * FROM main.execution_budgets').fetchone()),
                                 (CONTEXT.decode(), '7', None))
                self.assertEqual(tuple(budget.db.execute('SELECT * FROM temp.execution_budgets').fetchone()), shadow)
                self.assertEqual(second.execution_budgets.observe(CONTEXT.decode())['used_native_ns'], '7')
            finally:
                second.close(); first.close()

    def test_selected_source_custody_refuses_before_store_creation_and_never_falls_back(self):
        from hepta.hia_agent_store import AgentStore
        from hepta import hia_execution_budget as reference
        from hepta import hia_execution_budget_native as native
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {SELECTOR: str(root / 'missing.json')}), \
                 patch.object(reference._ReferenceExecutionBudgetStore, '__init__',
                              side_effect=AssertionError('native admission used hosted fallback')):
                with self.assertRaises(FileNotFoundError): AgentStore(root / 'not-created')
            self.assertFalse((root / 'not-created').exists())
            copied = root / 'execution_budget.hepta'; copied.write_bytes(SOURCE.read_bytes())
            with self.selected(), patch.object(native, 'SOURCE', copied):
                self.assertIsNotNone(native.selected_execution_budget())
                copied.write_bytes(copied.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    AgentStore(root / 'warm-drift-refused')
            self.assertFalse((root / 'warm-drift-refused').exists())

    def test_actual_agent_native_effect_lost_outcome_keeps_request_and_budget_unknown(self):
        self._actual_agent_native_effect_lost_outcome('reference-journal')

    def test_actual_agent_journal_v2_lost_outcome_keeps_request_and_budget_unknown(self):
        with self.selected_journal_v2():
            self._actual_agent_native_effect_lost_outcome('native-journal-v2')

    def _actual_agent_native_effect_lost_outcome(self, evidence_label):
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_agent_runner
        from hepta import hia_execution_budget as reference
        for after in (False, True):
            with self.subTest(after=after), self.selected(), \
                 patch.object(reference._ReferenceExecutionBudgetStore, '__init__',
                              side_effect=AssertionError('old execution budget policy')):
                case = AgentToolCase('runTest'); case.setUp()
                try:
                    _base, _candidate, baseline, build, receipts = case.build_pair()
                    args = case.session.arguments(baseline_artifact=baseline['native_artifact'],
                        candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                        verification_receipts=receipts)
                    actual, references = [], []
                    original_call, run_native = BudgetState.call, hia_agent_runner.run_native_batch
                    def observed(*args, **kwargs):
                        outcome = run_native(*args, **kwargs)
                        (references if kwargs.get('_mode') == 'reference' else actual).append(outcome)
                        return outcome
                    def interrupt(state, event, **kwargs):
                        if event == 6:
                            if after: original_call(state, event, **kwargs)
                            raise KeyboardInterrupt('lost HIA acknowledgement after actual native child')
                        return original_call(state, event, **kwargs)
                    with patch.object(hia_agent_runner, 'run_native_batch', side_effect=observed), \
                         patch.object(BudgetState, 'call', interrupt):
                        with self.assertRaises(KeyboardInterrupt): case.service.call('hia_evaluate', args)
                    self.assertEqual(len(actual), 1)
                    self.assertEqual(len(references), 2)
                    self.assertTrue(actual[0]['started'])
                    self.assertTrue(actual[0]['termination_confirmed'])
                    self.assertEqual(actual[0]['status'], 'returned')
                    context = args['context']['id']
                    row = dict(case.service.store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?',
                                                            (context,)).fetchone())
                    self.assertIsNotNone(row['owner'])
                    self.assertEqual(row['used_native_ns'], '0')
                    case.service.close()
                    case.service = HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
                    with patch.object(hia_agent_runner, 'run_native_batch', side_effect=AssertionError('unknown request ran again')):
                        replay = case.service.call('hia_evaluate', args)
                    self.assertEqual(replay['status'], 'rejected')
                    self.assertEqual(replay['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                    self.assertEqual(dict(case.service.store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?',
                                                                       (context,)).fetchone()), row)
                    (self.folder / ('actual-child-lost-outcome-' + evidence_label + '-' + str(int(after)) + '.json')).write_text(json.dumps({
                        'actual_native_outcome': actual[0], 'reference_outcomes': references,
                        'retained_budget': row, 'replay': replay}, indent=2) + '\n')
                finally: case.tearDown()

    def test_original_actual_agent_lifecycle_and_campaign_disable_reference(self):
        self._actual_agent_lifecycle_and_campaign('original-actual-agent-suite')

    def test_actual_agent_journal_v2_lifecycle_and_campaign_disable_both_references(self):
        with self.selected_journal_v2():
            self._actual_agent_lifecycle_and_campaign('native-journal-v2-agent-suite')

    def _actual_agent_lifecycle_and_campaign(self, evidence_label):
        from hepta import hia_execution_budget as reference
        modules = ('tests.test_hia_agent_native_tools.NativeLifecycleTests',
                   'tests.test_hia_agent_native_campaign.QualificationCampaignTests')
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in modules)
        expected = suite.countTestCases()
        stream = io.StringIO()
        with self.selected(), ExitStack() as stack:
            for cls in (reference._ReferenceExecutionBudgetStore, reference._ReferenceBudgetClaim):
                stack.enter_context(patch.object(cls, '__init__', side_effect=AssertionError('old budget constructed')))
            for cls, names in ((reference._ReferenceExecutionBudgetStore, ('create', 'claim', 'observe')),
                               (reference._ReferenceBudgetClaim, ('run', 'complete'))):
                for name in names:
                    stack.enter_context(patch.object(cls, name, side_effect=AssertionError('old budget policy called')))
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        (self.folder / (evidence_label + '.log')).write_text(stream.getvalue())
        (self.folder / (evidence_label + '.json')).write_text(json.dumps({
            'modules': modules, 'expected': expected,
            'tests': result.testsRun, 'failures': len(result.failures),
            'errors': len(result.errors), 'skipped': len(result.skipped),
            'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses),
            'hosted_policy_forbidden': True, 'image_sha256': self.image.image_sha256}, indent=2) + '\n')
        self.assertGreater(expected, 0, stream.getvalue())
        self.assertEqual(result.testsRun, expected, stream.getvalue())
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual(result.skipped, [], stream.getvalue())
        self.assertEqual(result.expectedFailures, [], stream.getvalue())
        self.assertEqual(result.unexpectedSuccesses, [], stream.getvalue())

    def test_installed_wheel_same_journal_lifecycle_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        case = self.folder / 'installed-wheel-control'; case.mkdir(mode=0o700)
        source = case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = ((tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES
                     + PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES)
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        sdists, wheels, installed = case / 'sdists', case / 'wheels', case / 'installed'
        archived = subprocess.run([packaging, '-B', 'setup.py', 'sdist', '--dist-dir', str(sdists)],
            cwd=source, capture_output=True, timeout=120)
        (case / 'sdist-build.log').write_bytes(archived.stdout + archived.stderr)
        self.assertEqual(archived.returncode, 0, archived.stdout + archived.stderr)
        sdist, = sdists.glob('*.tar.gz')
        import tarfile
        with tarfile.open(sdist, 'r:gz') as archive:
            members = {name.split('/', 1)[1] for name in archive.getnames() if '/' in name}
        self.assertTrue(set(resources).issubset(members), sorted(set(resources) - members))
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(sdist)], cwd=case,
            capture_output=True, timeout=120)
        (case / 'wheel-build.log').write_bytes(built.stdout + built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([packaging, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=case, capture_output=True, timeout=120)
        (case / 'wheel-install.log').write_bytes(copied.stdout + copied.stderr)
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        program = r'''import importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed execution budget imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_store import AgentStore
from hepta import hia_execution_budget as reference
from hepta.hia_execution_budget_native import SOURCE,SELECTOR
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed execution budget used hosted policy')
reference._ReferenceExecutionBudgetStore.__init__=forbidden
reference._ReferenceBudgetClaim.__init__=forbidden
os.environ[SELECTOR]=sys.argv[2]
store=AgentStore(sys.argv[3])
context='ctx-'+'1'*32
store.execution_budgets.create(context)
claim=store.execution_budgets.claim(context,'a'*64,1000,0)
claim.run(lambda **kw:{'wall_ns':'18446744073709551616','termination_confirmed':True},now=0,total_ms=1000)
claim.complete()
row=store.execution_budgets.observe(context)
assert row['used_native_ns']=='18446744073709551616' and row['owner'] is None,row
assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
store.close()
store=AgentStore(sys.argv[3])
assert store.execution_budgets.observe(context)['used_native_ns']==row['used_native_ns']
store.close()
print(json.dumps(row,sort_keys=True))
'''
        child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(installed),
            str(self.manifest), str(case / 'state')], cwd=case, capture_output=True, text=True, timeout=30)
        (case / 'actual.stdout').write_text(child.stdout); (case / 'actual.stderr').write_text(child.stderr)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)['used_native_ns'], '18446744073709551616')


if __name__ == '__main__':
    unittest.main()
