"""Independent HIA observations and actual same-journal request ownership."""
from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import ExitStack, contextmanager
import dis
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta.hia_request_journal_native import (NativeRequestJournalImage, RequestJournalUnknown,
    RequestState, REQUEST_MAGIC, RESULT_MAGIC, CLEANUP_MAGIC, SCHEMA, SELECTOR, SOURCE, STATE_PREFIX, OUTPUT_PREFIX)

ROOT = Path(__file__).resolve().parents[1]
KEY, DIGEST, STARTED = b'a' * 64, b'd' * 64, b'17'
RESPONSE = b'{"result":{"answer":7},"status":"completed"}'
CAPACITY = 2048


@contextmanager
def interrupt_opcode(code, opname, name):
    """Inject once at an actual interpreter boundary, with a positive witness."""
    offsets = {item.offset for item in dis.get_instructions(code)
               if item.opname == opname and item.argval == name}
    assert len(offsets) == 1, (opname, name, offsets)
    observations = []
    def trace(frame, event, arg):
        if frame.f_code is code:
            frame.f_trace_opcodes = True
            if event == 'opcode' and frame.f_lasti in offsets and not observations:
                observations.append({'opcode': opname, 'name': name, 'offset': frame.f_lasti})
                raise KeyboardInterrupt('actual request journal interpreter handoff')
        return trace
    previous, frames, frame = sys.gettrace(), [], sys._getframe()
    while frame is not None:
        frames.append((frame, frame.f_trace_opcodes))
        frame.f_trace_opcodes = True
        frame = frame.f_back
    try:
        sys.settrace(trace)
        yield observations
    finally:
        sys.settrace(previous)
        for frame, flag in frames:
            frame.f_trace_opcodes = flag
        assert len(observations) == 1, 'requested interpreter interruption did not occur'


def packet(event, sequence=0, values=(), *, effect_token=0, payload=b'', identity=(11, 17), connection=(31, 37)):
    words = [REQUEST_MAGIC, event, sequence, effect_token, *values]
    words += [0] * (12 - len(words))
    return struct.pack('<16Q', *words, *identity, *connection) + payload


def initial(tool=b'hia_artifact', key=b'key'):
    return packet(0, values=(len(tool), len(STARTED), 1, len(key), 64),
                  payload=tool + DIGEST + STARTED + key + KEY)


def row(sequence, tool, state=b'running', response=None):
    raw = b'' if response is None else response
    return packet(2, sequence, (1, len(state), len(tool), len(STARTED), int(response is not None),
                  len(raw), 64, 64), payload=KEY + DIGEST + tool + state + STARTED + raw)


def header(result):
    count, output, _ = result
    assert 128 <= count <= CAPACITY + OUTPUT_PREFIX, count
    h = struct.unpack('<16Q', output[:128])
    assert h[0] == RESULT_MAGIC, h
    return h


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.program = assemble_program(SOURCE.read_bytes())
        self.entry = next(f for f in self.program.as_dict()['functions'] if f['name'] == 'f0')
        self.state = bytearray(STATE_PREFIX + CAPACITY)

    def call(self, raw):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        objects = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(OUTPUT_PREFIX + CAPACITY)),
                   _Owner(-3, self.state)]
        machine = _Machine(self.program, 100000000, 16 << 20, None, 128)
        count = machine.invoke(self.entry, [_View(objects[0], False), _View(objects[1], True),
                                           _View(objects[2], True)])[0]
        return count, bytes(objects[1].data[:count]), bytes(self.state)


class Machine:
    def __init__(self, image):
        self.image = image
        self.size = STATE_PREFIX + CAPACITY
        self.state = ctypes.create_string_buffer(self.size + 16)
        ctypes.memset(ctypes.addressof(self.state) + self.size, 0xb7, 16)

    def call(self, raw):
        source = ctypes.create_string_buffer(raw, len(raw))
        size = OUTPUT_PREFIX + CAPACITY
        output = ctypes.create_string_buffer(size + 16)
        ctypes.memset(ctypes.addressof(output) + size, 0xa5, 16)
        count = self.image._entry(source, len(raw), output, size, self.state, self.size)
        assert source.raw == raw
        assert output.raw[size:] == b'\xa5' * 16
        assert self.state.raw[self.size:] == b'\xb7' * 16
        return count, output.raw[:count], self.state.raw[:self.size]


def witnesses(engine, kind='normal'):
    tool = b'hia_adopt' if kind in ('atomic', 'rollback') else b'hia_artifact'
    observations, sequence, pending = [], 0, 0
    def send(raw, action=None, phase=None):
        nonlocal sequence, pending
        answer = engine.call(raw); h = header(answer)
        assert h[1] == 0, h
        if action is not None: assert h[2] == action, h
        if phase is not None: assert h[4] == phase, h
        sequence, pending = h[3], h[8]
        observations.append((raw, answer))
        return h
    def call(event, values=(), *, payload=b'', token=0, action=None, phase=None):
        return send(packet(event, sequence, values, payload=payload, effect_token=token), action, phase)
    send(initial(tool), 1, 1)
    call(1, (1,), action=2, phase=2)
    if kind == 'replay':
        send(row(sequence, tool, b'completed', RESPONSE), 8, 11)
        call(90, action=8, phase=11)
        call(9, (1,), token=pending, action=5, phase=5)
        call(4, (1,), action=0, phase=8)
        return observations
    call(2, (0, 0, 0, 0, 0, 0, 0, 0), action=3, phase=3)
    call(3, (1,), action=2, phase=4)
    send(row(sequence, tool), 5, 5)
    call(4, (1,), action=0, phase=6)
    if kind in ('atomic', 'rollback'):
        call(5, action=1, phase=1)
        call(1, (1,), action=2, phase=2)
        send(row(sequence, tool), 7, 7)
    else:
        call(5, action=7, phase=7)
    call(90, action=7, phase=7)
    if kind == 'rollback':
        call(7, (1,), token=pending, action=6, phase=10)
        raw = packet(91)
        answer = engine.call(raw)
        magic, status, granted, epoch = struct.unpack('<4Q', answer[1])
        assert (magic, status, granted) == (CLEANUP_MAGIC, 0, 1) and epoch > 0
        observations.append((raw, answer))
        call(8, (1,), action=0, phase=6)
    else:
        call(12, (len(RESPONSE), 1), payload=RESPONSE, token=pending, action=0, phase=12)
    call(6, (len(RESPONSE), 1), payload=RESPONSE, action=4 if kind == 'atomic' else 1)
    if kind != 'atomic':
        call(1, (1,), action=2, phase=2)
        send(row(sequence, tool), 4, 3)
    call(3, (1,), action=2, phase=4)
    send(row(sequence, tool, b'completed', RESPONSE), 5, 5)
    call(4, (1,), action=0, phase=8)
    before = observations[-1][1][2]
    call(6, (len(RESPONSE), 1), payload=RESPONSE, action=0, phase=8)
    assert observations[-1][1][2] == before
    return observations


class RequestJournalSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_vm_owned_lifecycles(self):
        from tools.generate_hia_request_journal import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        for kind in ('normal', 'atomic', 'rollback', 'replay'):
            with self.subTest(kind=kind):
                self.assertGreaterEqual(len(witnesses(VM(), kind)), 6)

    def test_bad_cold_builder_refuses_before_output_or_native_compilation(self):
        from tools.build_hia_request_journal import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not qualified')
            (root / 'cold').write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('native compile entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(root / 'output', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'output').exists())

    def test_explicit_cold_fixture_cannot_fall_back_to_a_development_seed(self):
        class ColdFixture(RequestJournalNativeTests):
            pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / 'cold.json'; report.write_text('{}')
            evidence = root / 'uncreated-evidence'
            environment = {
                'HEPTA_HIA_REQUEST_JOURNAL_COLD_REPORT': str(report),
                'HEPTA_HIA_REQUEST_JOURNAL_DEVELOPMENT_COMPILER': '',
                'HEPTA_HIA_REQUEST_JOURNAL_EVIDENCE': str(evidence),
            }
            with patch.dict(os.environ, environment), \
                    patch('tools.qualify_hia_selfhost.build_seed', side_effect=AssertionError('development seed entered')), \
                    patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('native compile entered')):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'):
                    ColdFixture.setUpClass()
            self.assertFalse(evidence.exists())
            environment['HEPTA_HIA_REQUEST_JOURNAL_DEVELOPMENT_COMPILER'] = '/unread-development-compiler'
            with patch.dict(os.environ, environment), \
                    patch.object(Path, 'read_bytes', side_effect=AssertionError('artifact read')):
                with self.assertRaisesRegex(ValueError, 'development compiler cannot be combined'):
                    ColdFixture.setUpClass()
            self.assertFalse(evidence.exists())

    def test_invalid_selected_owner_refuses_before_opening_or_creating_a_store(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'invalid.json'; manifest.write_text('{}')
            target = root / 'must-not-exist'
            with patch.dict(os.environ, {SELECTOR: str(manifest)}):
                with self.assertRaises(ValueError): AgentStore(target)
            self.assertFalse(target.exists())


class RequestJournalNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage, build_seed
        cold = os.environ.get('HEPTA_HIA_REQUEST_JOURNAL_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_REQUEST_JOURNAL_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('development compiler cannot be combined with a request journal cold report')
        if cold:
            from tools.build_hia_request_journal import admit_cold_build
            cold = Path(cold)
            cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes)
            try:
                nested = json.loads(Path(report['nested_report']).read_bytes())
                compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('request journal cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            admit_cold_build(compiler_bytes, cold_bytes)
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_REQUEST_JOURNAL_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-request-journal-')
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_request_journal import build as build_request
            from tools.build_hia_execution_budget import build as build_budget
            cls.manifest = build_request(cls.folder / 'qualified-request-journal', compiler, cold)
            cls.budget_manifest = build_budget(cls.folder / 'qualified-execution-budget', compiler, cold)
            manifest = json.loads(cls.manifest.read_bytes())
            image = cls.manifest.parent / manifest['image_path']
            cls.image = NativeRequestJournalImage(image.read_bytes(), manifest['image_sha256'])
            if cold.read_bytes() != cold_bytes or compiler.read_bytes() != compiler_bytes:
                raise AssertionError('qualified request journal fixture inputs changed')
            (cls.folder / 'qualified-build.json').write_text(json.dumps({
                'mode': 'MATCHING_CURRENT_SOURCE_COLD_BUILD',
                'manifest_path': str(cls.manifest),
                'budget_manifest_path': str(cls.budget_manifest),
                'cold_report_sha256': sha256(cold_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest(),
                'request_and_budget_use_same_admitted_cold_report': True,
                'matching_current_source_cold_qualified': True,
            }, indent=2) + '\n')
            return
        if development:
            compiler = Path(development); mode = 'DEVELOPMENT_REUSED_COMPILER'
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            mode = 'DEVELOPMENT_B0_B1_B2'
        image, receipt = compile_stage(cls.folder, 'request-journal', compiler, SOURCE.read_bytes())
        cls.image = NativeRequestJournalImage(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        manifest = {'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': cls.image.image_sha256,
            'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
        (cls.folder / 'development-build.json').write_text(json.dumps({'mode': mode,
            'manifest': manifest, 'compile_receipt': receipt,
            'matching_current_source_cold_qualified': False}, indent=2) + '\n')
        budget_source = ROOT / 'examples/hia_bootstrap/execution_budget.hiaasm'
        budget_image, budget_receipt = compile_stage(cls.folder, 'execution-budget', compiler, budget_source.read_bytes())
        cls.budget_manifest = cls.folder / 'execution-budget-manifest.json'
        cls.budget_manifest.write_text(json.dumps({'schema': 'hepta.hia.execution-budget-native.v1',
            'source_sha256': sha256(budget_source.read_bytes()).hexdigest(),
            'image_path': budget_image.name, 'image_sha256': sha256(budget_image.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}, indent=2) + '\n')
        (cls.folder / 'joint-budget-build.json').write_text(json.dumps(budget_receipt, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None: cls.temporary.cleanup()

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def test_machine_matches_all_independent_vm_lifecycle_state_bytes(self):
        for kind in ('normal', 'atomic', 'rollback', 'replay'):
            with self.subTest(kind=kind):
                machine = Machine(self.image)
                for raw, expected in witnesses(VM(), kind):
                    self.assertEqual(machine.call(raw), expected)

    def test_actual_sqlite_intent_once_only_dispatch_exact_completion_and_replay(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected, wire
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            try:
                journal, calls, validations = store.request_journal, [], []
                ticket = journal.admit('hia_artifact', DIGEST.decode(), 'same-key', lambda *args: None)
                original = dict(store.db.execute('SELECT * FROM main.requests').fetchone())
                self.assertEqual((original['state'], original['response']), ('running', None))
                response = ticket.run(lambda: calls.append('effect') or {'answer': 7},
                    lambda result: {'status': 'completed', 'result': result}, lambda error: {'status': 'rejected'})
                self.assertEqual(calls, ['effect'])
                ticket.finish(wire(response))
                completed = dict(store.db.execute('SELECT * FROM main.requests').fetchone())
                self.assertEqual(completed['response'], wire(response).decode())
                self.assertEqual(completed['started_ns'], original['started_ns'])
                again = journal.admit('hia_artifact', DIGEST.decode(), 'same-key',
                    lambda raw, connection: validations.append(raw))
                self.assertTrue(again.replayed)
                self.assertEqual(again.replay_bytes, wire(response))
                self.assertEqual(validations, [wire(response)])
                with self.assertRaises(RequestJournalUnknown): again.dispatch()
                self.assertEqual(calls, ['effect'])
                with self.assertRaises(AgentRejected) as conflict:
                    journal.admit('hia_artifact', 'e' * 64, 'same-key', lambda *args: None)
                self.assertEqual(conflict.exception.code, 'E_HIA_REQUEST_CONFLICT')
                self.assertEqual(dict(store.db.execute('SELECT * FROM main.requests').fetchone()), completed)
            finally: store.close()

    def test_actual_reentrant_completion_before_handler_return_never_commits(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            try:
                ticket = store.request_journal.admit('hia_artifact', DIGEST.decode(), 'reentry', lambda *args: None)
                calls = []
                def invoke():
                    calls.append('effect-started')
                    ticket.finish(RESPONSE)
                    return {'impossible': True}
                with self.assertRaises(RequestJournalUnknown):
                    ticket.run(invoke, lambda result: result, lambda error: {'error': str(error)})
                self.assertEqual(calls, ['effect-started'])
                self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()),
                                 ('running', None))
                with self.assertRaises(AgentRejected) as unknown:
                    store.request_journal.admit('hia_artifact', DIGEST.decode(), 'reentry', lambda *args: None)
                self.assertEqual(unknown.exception.code, 'E_HIA_REQUEST_UNKNOWN')
            finally: store.close()

    def test_original_agent_tools_and_campaign_disable_reference_with_native_budget(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_execution_budget as budget_reference
        classes = ('tests.test_hia_agent_native_tools.ArtifactContractTests',
                   'tests.test_hia_agent_native_tools.CandidateAndVerificationTests',
                   'tests.test_hia_agent_native_tools.MachinePlanTests',
                   'tests.test_hia_agent_native_tools.NativeLifecycleTests',
                   'tests.test_hia_agent_native_tools.AgentStoreDirectoryPermissionTests',
                   'tests.test_hia_agent_native_campaign.QualificationCampaignTests')
        # Development snapshots leave common source-contract regeneration to
        # integration. A matching cold gate runs that original case as well.
        excluded = (None if os.environ.get('HEPTA_HIA_REQUEST_JOURNAL_COLD_REPORT')
                    else 'test_discovery_is_readable_and_source_bound')
        cases = [case for name in classes for case in unittest.defaultTestLoader.loadTestsFromName(name)
                 if case._testMethodName != excluded]
        stream = io.StringIO()
        with self.selected(), patch.dict(os.environ, {'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': str(self.budget_manifest)}), ExitStack() as stack:
            stack.enter_context(patch.object(HIAAgentService, '_call_reference',
                side_effect=AssertionError('selected request journal used original policy')))
            for cls in (budget_reference._ReferenceExecutionBudgetStore, budget_reference._ReferenceBudgetClaim):
                stack.enter_context(patch.object(cls, '__init__', side_effect=AssertionError('old budget constructed')))
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite(cases))
        (self.folder / 'original-agent-tools-and-campaign.log').write_text(stream.getvalue())
        (self.folder / 'original-agent-tools-and-campaign.json').write_text(json.dumps({
            'classes': classes, 'excluded_integration_source_contract': excluded,
            'source_contract_checked_in_nested_suite': excluded is None,
            'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
            'skipped': len(result.skipped), 'request_reference_forbidden': True,
            'budget_reference_forbidden': True, 'image_sha256': self.image.image_sha256}, indent=2) + '\n')
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual(result.skipped, [], stream.getvalue())

    def test_actual_rollback_unknown_is_not_retried_or_converted_to_rejection(self):
        from hepta.hia_agent_store import AgentStore, wire
        for position in ('confirmed', 'before', 'after'):
            with self.subTest(position=position), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory); journal = store.request_journal
                try:
                    ticket = journal.admit('hia_adopt', DIGEST.decode(), 'rollback-control', lambda *args: None)
                    execute, attempts = journal._execute, []
                    def interrupt(sql, parameters=()):
                        if sql == 'ROLLBACK':
                            attempts.append(sql)
                            if position == 'before': raise KeyboardInterrupt('before actual rollback')
                        cursor = execute(sql, parameters)
                        if sql == 'ROLLBACK' and position == 'after':
                            raise KeyboardInterrupt('after actual rollback before acknowledgement')
                        return cursor
                    def invoke(connection):
                        connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
                                           ('rollback-control', 'context', '1', '1', 'a' * 64))
                        raise ValueError('confirmed handler rejection')
                    with patch.object(journal, '_execute', side_effect=interrupt):
                        with self.assertRaises(ValueError if position == 'confirmed' else RequestJournalUnknown):
                            ticket.atomic(invoke, lambda result: result)
                    self.assertEqual(attempts, ['ROLLBACK'])
                    self.assertIsNone(store.db.execute('SELECT * FROM main.slots').fetchone())
                    if position == 'confirmed':
                        response = wire({'status': 'rejected', 'error': 'confirmed handler rejection'})
                        ticket.finish(response)
                        self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()),
                                         ('completed', response.decode()))
                    else:
                        self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()),
                                         ('running', None))
                        with patch.object(journal, '_execute', side_effect=AssertionError('unknown rollback retried SQL')):
                            with self.assertRaises(RequestJournalUnknown): ticket.finish(RESPONSE)
                        self.assertEqual(journal.db.in_transaction, position == 'before')
                        self.assertEqual(journal.poisoned is not None, position == 'before')
                finally: store.close()

    def test_actual_atomic_slot_and_response_have_one_commit_boundary(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected, wire
        for after in (False, True):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory); journal = store.request_journal
                try:
                    ticket = journal.admit('hia_adopt', DIGEST.decode(), 'atomic-control', lambda *args: None)
                    execute, effects, retained = journal._execute, [], []
                    def lost(sql, parameters=()):
                        if sql == 'COMMIT' and not after: raise KeyboardInterrupt('before commit')
                        cursor = execute(sql, parameters)
                        if sql == 'COMMIT': raise KeyboardInterrupt('after commit')
                        return cursor
                    def invoke(connection):
                        retained.append(connection)
                        cursor = connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
                            ('atomic-control', 'context', '1', '1', 'a' * 64))
                        retained.append(cursor)
                        effects.append('slot-written')
                        return {'status': 'completed', 'result': {'generation': '1'}}
                    with patch.object(journal, '_execute', side_effect=lost):
                        with self.assertRaises(RequestJournalUnknown): ticket.atomic(invoke, lambda result: result)
                    self.assertEqual(effects, ['slot-written'])
                    row = dict(store.db.execute('SELECT * FROM main.requests').fetchone())
                    slot = store.db.execute('SELECT * FROM main.slots').fetchone()
                    self.assertEqual(row['state'], 'completed' if after else 'running')
                    self.assertEqual(slot is not None, after)
                    self.assertEqual(row['response'] is not None, after)
                    with self.assertRaises(RequestJournalUnknown):
                        retained[0].execute('UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?',
                                            ('2', '2', 'context', 'atomic-control'))
                    with self.assertRaises(RequestJournalUnknown): retained[1].fetchone()
                    if after:
                        replay = journal.admit('hia_adopt', DIGEST.decode(), 'atomic-control', lambda *args: None)
                        self.assertTrue(replay.replayed)
                        self.assertEqual(replay.replay_bytes, row['response'].encode())
                    else:
                        with self.assertRaises(AgentRejected) as unknown:
                            journal.admit('hia_adopt', DIGEST.decode(), 'atomic-control', lambda *args: None)
                        self.assertEqual(unknown.exception.code, 'E_HIA_REQUEST_UNKNOWN')
                    self.assertEqual(effects, ['slot-written'])
                finally: store.close()

    def test_actual_temporary_tables_never_replace_main_request_or_slot_rows(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected, digest
        with tempfile.TemporaryDirectory() as directory, self.selected():
            first, second = AgentStore(directory), AgentStore(directory)
            try:
                journal = first.request_journal
                key = digest({'tool': 'hia_adopt', 'key': 'temp-control'})
                journal.db.execute('CREATE TEMP TABLE requests AS SELECT * FROM main.requests')
                journal.db.execute('INSERT INTO temp.requests VALUES (?,?,?,?,?,?)',
                    (key, DIGEST.decode(), 'hia_adopt', 'completed', '{"forged":true}', '0'))
                journal.db.execute('CREATE TEMP TABLE slots AS SELECT * FROM main.slots')
                journal.db.execute('INSERT INTO temp.slots VALUES (?,?,?,?,?)',
                    ('shadow-slot', 'foreign', '99', '99', 'b' * 64))
                shadow = [tuple(row) for row in journal.db.execute('SELECT * FROM temp.requests')]
                ticket = journal.admit('hia_adopt', DIGEST.decode(), 'temp-control',
                    lambda *args: self.fail('TEMP response became replay authority'))
                with self.assertRaises(AgentRejected) as busy:
                    second.request_journal.admit('hia_adopt', DIGEST.decode(), 'temp-control', lambda *args: None)
                self.assertEqual(busy.exception.code, 'E_HIA_REQUEST_UNKNOWN')
                def invoke(connection):
                    self.assertIsNone(connection.execute('SELECT * FROM slots WHERE name=?', ('shadow-slot',)).fetchone())
                    connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
                        ('shadow-slot', 'owned', '1', '1', 'a' * 64))
                    return {'status': 'completed', 'result': 'main-only'}
                ticket.atomic(invoke, lambda result: result)
                self.assertEqual(first.db.execute('SELECT generation FROM main.slots').fetchone()[0], '1')
                self.assertEqual(journal.db.execute('SELECT generation FROM temp.slots').fetchone()[0], '99')
                self.assertEqual([tuple(row) for row in journal.db.execute('SELECT * FROM temp.requests')], shadow)
            finally: second.close(); first.close()

    def test_actual_atomic_transaction_does_not_capture_an_ordinary_writer(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory); journal = store.request_journal
            held, release, attempted = threading.Event(), threading.Event(), threading.Event()
            try:
                ticket = journal.admit('hia_adopt', DIGEST.decode(), 'ordinary-writer', lambda *args: None)
                def invoke(connection):
                    connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
                        ('ordinary-writer', 'context', '1', '1', 'a' * 64))
                    held.set()
                    if not release.wait(5): raise TimeoutError('atomic control not released')
                    return {'status': 'completed'}
                def ordinary():
                    attempted.set()
                    store.db.execute('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
                        (None, 'ordinary', 'outside', '1', 'completed', '{}'))
                with ThreadPoolExecutor(2) as pool:
                    first = pool.submit(ticket.atomic, invoke, lambda result: result)
                    self.assertTrue(held.wait(5))
                    second = pool.submit(ordinary)
                    self.assertTrue(attempted.wait(5))
                    try:
                        with self.assertRaises(FutureTimeout): second.result(timeout=0.1)
                        with sqlite3.connect(store.database) as observer:
                            self.assertEqual(observer.execute('SELECT count(*) FROM main.slots').fetchone()[0], 0)
                            self.assertEqual(observer.execute('SELECT count(*) FROM main.costs').fetchone()[0], 0)
                            self.assertEqual(observer.execute('SELECT state FROM main.requests').fetchone()[0], 'running')
                    finally: release.set()
                    first.result(timeout=5); second.result(timeout=5)
                self.assertEqual(store.db.execute('SELECT count(*) FROM main.slots').fetchone()[0], 1)
                self.assertEqual(store.db.execute('SELECT count(*) FROM main.costs').fetchone()[0], 1)
                self.assertEqual(store.db.execute('SELECT state FROM main.requests').fetchone()[0], 'completed')
            finally: release.set(); store.close()

    def test_actual_service_claim_and_completion_lost_ack_never_fabricate_a_reply(self):
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import digest
        for commit in (1, 2):
            for after in (False, True):
                with self.subTest(commit=commit, after=after), self.selected(), \
                     patch.object(HIAAgentService, '_call_reference', side_effect=AssertionError('hosted request policy')):
                    case = AgentToolCase('runTest'); case.setUp()
                    try:
                        args = case.session.arguments(context=False, artifact_profile=case.session.profiles['artifact'],
                            source={'kind': 'utf8', 'text': 'actual durable artifact before request completion'})
                        key = digest({'tool': 'hia_artifact', 'key': args['request_key']})
                        journal = case.service.store.request_journal
                        execute, commits, effects = journal._execute, [], []
                        original = case.service._hia_artifact
                        def observed(arguments):
                            result = original(arguments); effects.append(result); return result
                        def lost(sql, parameters=()):
                            selected = False
                            if sql == 'COMMIT':
                                commits.append(sql); selected = len(commits) == commit
                            if selected and not after: raise KeyboardInterrupt('before actual request COMMIT')
                            result = execute(sql, parameters)
                            if selected: raise KeyboardInterrupt('after actual request COMMIT')
                            return result
                        with patch.object(journal, '_execute', side_effect=lost), \
                             patch.object(case.service, '_hia_artifact', side_effect=observed):
                            with self.assertRaises(RequestJournalUnknown): case.service.call('hia_artifact', args)
                        row = case.service.store.db.execute('SELECT * FROM main.requests WHERE key=?', (key,)).fetchone()
                        recorded = None if row is None else dict(row)
                        self.assertEqual(len(effects), int(commit == 2))
                        self.assertEqual(row is None, commit == 1 and not after)
                        if row is not None:
                            self.assertEqual(row['state'], 'completed' if commit == 2 and after else 'running')
                            self.assertEqual(row['response'] is not None, commit == 2 and after)
                        case.service.close()
                        case.service = HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
                        replay = None
                        if row is not None:
                            with patch.object(case.service, '_hia_artifact', side_effect=AssertionError('original effect replayed')):
                                replay = case.service.call('hia_artifact', args)
                            if commit == 2 and after:
                                self.assertEqual(replay, json.loads(row['response']))
                            else:
                                self.assertEqual(replay['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                        (self.folder / ('actual-service-commit-' + str(commit) + '-' + str(int(after)) + '.json')).write_text(
                            json.dumps({'commit': commit, 'after': after, 'effects': effects,
                                'durable_row': recorded, 'restarted_reply': replay}, indent=2) + '\n')
                    finally: case.tearDown()

    def test_actual_adopt_and_rollback_use_only_explicit_connection_and_exact_commit(self):
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import digest
        for tool in ('hia_adopt', 'hia_rollback'):
            for after in (False, True):
                with self.subTest(tool=tool, after=after), self.selected(), \
                     patch.dict(os.environ, {'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': str(self.budget_manifest)}), \
                     patch.object(HIAAgentService, '_call_reference', side_effect=AssertionError('hosted request policy')):
                    case = AgentToolCase('runTest'); case.setUp()
                    try:
                        _base, _candidate, baseline, build, receipts = case.build_pair()
                        evaluation = case.session.evaluate(baseline, build, receipts=receipts)
                        args = case.session.arguments(target_slot='actual-atomic',
                            expected_current={'generation': '0', 'epoch': '0'},
                            candidate_artifact=build['native_artifact'],
                            evaluation_receipt=evaluation['evaluation_receipt'], verification_receipts=receipts)
                        if tool == 'hia_rollback':
                            adopted = case.client.result('hia_adopt', args)
                            args = case.session.arguments(target_slot='actual-atomic',
                                expected_current=adopted['current'], retained_generation=adopted['previous']['generation'],
                                reason='actual request-journal commit boundary')
                        before = case.service.inspect_slot('actual-atomic')
                        key = digest({'tool': tool, 'key': args['request_key']})
                        journal, official = case.service.store.request_journal, case.service.store.db
                        execute, commits, capabilities, leaked, effects = journal._execute, [], [], [], []
                        original = getattr(case.service, '_' + tool)
                        def deny(*observation):
                            leaked.append(observation)
                            return sqlite3.SQLITE_DENY
                        def observed(arguments, *, _connection):
                            capabilities.append(_connection)
                            official.set_authorizer(deny)
                            try:
                                with self.assertRaises(sqlite3.DatabaseError): official.execute('SELECT 42')
                                self.assertTrue(leaked); leaked.clear()
                                result = original(arguments, _connection=_connection)
                                effects.append(result)
                                return result
                            finally: official.set_authorizer(None)
                        def lost(sql, parameters=()):
                            selected = False
                            if sql == 'COMMIT':
                                commits.append(sql); selected = len(commits) == 2
                            if selected and not after: raise KeyboardInterrupt('before atomic COMMIT')
                            result = execute(sql, parameters)
                            if selected: raise KeyboardInterrupt('after atomic COMMIT')
                            return result
                        with patch.object(case.service, '_' + tool, side_effect=observed), \
                             patch.object(journal, '_execute', side_effect=lost):
                            with self.assertRaises(RequestJournalUnknown): case.service.call(tool, args)
                        self.assertEqual(leaked, [], 'atomic helper reached the official connection')
                        self.assertEqual(len(effects), 1)
                        row = dict(official.execute('SELECT * FROM main.requests WHERE key=?', (key,)).fetchone())
                        current = case.service.inspect_slot('actual-atomic')
                        self.assertEqual(row['state'], 'completed' if after else 'running')
                        self.assertEqual(row['response'] is not None, after)
                        if after:
                            self.assertEqual(current['current'], json.loads(row['response'])['result']['current'])
                            self.assertNotEqual(current['current'], before['current'])
                        else:
                            self.assertEqual(current, before)
                        with self.assertRaises(RequestJournalUnknown):
                            capabilities[0].execute('SELECT * FROM slots WHERE name=?', ('actual-atomic',))
                        with patch.object(case.service, '_' + tool, side_effect=AssertionError('atomic effect replayed')):
                            replay = case.service.call(tool, args)
                        if after:
                            self.assertEqual(replay, json.loads(row['response']))
                        else:
                            self.assertEqual(replay['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                        (self.folder / (tool + '-commit-' + str(int(after)) + '.json')).write_text(json.dumps({
                            'tool': tool, 'after': after, 'before_slot': before, 'after_slot': current,
                            'durable_row': row, 'observed_handler_results': effects, 'reply': replay,
                            'official_connection_denied_during_handler': True}, indent=2) + '\n')
                    finally: case.tearDown()

    def test_native_rollback_claim_survives_lost_guard_and_diagnostic_publication(self):
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_request_journal_native import NativeRequestJournalStore
        for boundary in ('guard', 'diagnostic'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory); journal = store.request_journal
                try:
                    ticket = journal.admit('hia_adopt', DIGEST.decode(), 'native-cleanup-claim', lambda *args: None)
                    execute, attempts = journal._execute, []
                    def failure(sql, parameters=()):
                        if sql == 'ROLLBACK':
                            attempts.append(sql)
                            raise KeyboardInterrupt('unconfirmed rollback transport')
                        return execute(sql, parameters)
                    def invoke(connection):
                        connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
                            ('native-cleanup-claim', 'context', '1', '1', 'a' * 64))
                        raise ValueError('known handler rejection')
                    code = (RequestState.claim_rollback if boundary == 'guard'
                            else NativeRequestJournalStore._cleanup).__code__
                    opcode, name = ('STORE_FAST', 'count') if boundary == 'guard' else ('STORE_ATTR', 'poisoned')
                    with patch.object(journal, '_execute', side_effect=failure), \
                            interrupt_opcode(code, opcode, name) as observations:
                        with self.assertRaises(RequestJournalUnknown):
                            ticket.atomic(invoke, lambda value: value)
                    self.assertEqual(len(attempts), int(boundary == 'diagnostic'))
                    self.assertTrue(journal.db.in_transaction)
                    self.assertIs(journal._transaction_owner, ticket.state)
                    self.assertIsNotNone(journal.poisoned)
                    words = struct.unpack('<32Q', ctypes.string_at(ticket.state.buffer, 256))
                    self.assertGreater(words[25], 0); self.assertEqual(words[19], words[25])
                    self.assertFalse(ticket.state.claim_rollback())
                    self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()),
                                     ('running', None))
                    self.assertIsNone(store.db.execute('SELECT * FROM main.slots').fetchone())
                    (self.folder / ('native-cleanup-' + boundary + '.json')).write_text(json.dumps({
                        'boundary': observations, 'rollback_attempts': len(attempts),
                        'native_epoch': words[25], 'native_consumed_epoch': words[19],
                        'open_transaction_owner_retained': True,
                        'native_image_sha256': self.image.image_sha256}, indent=2) + '\n')
                finally: store.close()

    def test_confirmed_atomic_abort_and_failed_completion_have_distinct_cleanup_epochs(self):
        from hepta.hia_agent_store import AgentStore
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory); journal = store.request_journal
            try:
                ticket = journal.admit('hia_adopt', DIGEST.decode(), 'fresh-cleanup-epoch', lambda *args: None)
                execute, epochs = journal._execute, []
                def observed(sql, parameters=()):
                    if sql == 'ROLLBACK':
                        words = struct.unpack('<32Q', ctypes.string_at(ticket.state.buffer, 256))
                        self.assertEqual(words[19], words[25]); epochs.append(words[25])
                    if sql.startswith('UPDATE main.requests'):
                        raise KeyboardInterrupt('completion UPDATE was not confirmed')
                    return execute(sql, parameters)
                def invoke(connection):
                    connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
                        ('fresh-cleanup-epoch', 'context', '1', '1', 'a' * 64))
                    raise ValueError('known atomic rejection')
                with patch.object(journal, '_execute', side_effect=observed):
                    with self.assertRaises(ValueError): ticket.atomic(invoke, lambda value: value)
                    with self.assertRaises(RequestJournalUnknown): ticket.finish(b'{"status":"rejected"}')
                self.assertEqual(len(epochs), 2); self.assertGreater(epochs[1], epochs[0])
                self.assertFalse(journal.db.in_transaction)
                self.assertEqual(tuple(store.db.execute('SELECT state,response FROM main.requests').fetchone()),
                                 ('running', None))
                self.assertIsNone(store.db.execute('SELECT * FROM main.slots').fetchone())
            finally: store.close()

    def test_actual_process_exit_commit_boundaries_preserve_same_journal_on_restart(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected, wire
        program = r'''import os,sys
sys.path.insert(0,sys.argv[1])
from hepta.hia_agent_store import AgentStore,wire
from hepta.hia_request_journal_native import SELECTOR
os.environ[SELECTOR]=sys.argv[2]
store=AgentStore(sys.argv[3]); journal=store.request_journal
tool,selected,after=sys.argv[4],int(sys.argv[5]),int(sys.argv[6])
execute=journal._execute; commits=0
def crash(sql,parameters=()):
    global commits
    if sql=='COMMIT': commits+=1
    match=sql=='COMMIT' and commits==selected
    if match and not after: os._exit(73)
    result=execute(sql,parameters)
    if match: os._exit(73)
    return result
journal._execute=crash
ticket=journal.admit(tool,'d'*64,'physical-exit',lambda *args:None)
response={'status':'completed','result':{'durable':True}}
if tool=='hia_adopt':
    def invoke(connection):
        connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',
            ('physical-exit','context','1','1','a'*64))
        return response
    ticket.atomic(invoke,lambda value:value)
else:
    ticket.run(lambda:response,lambda value:value,lambda error:None)
    ticket.finish(wire(response))
raise AssertionError('process exit was not reached')
'''
        expected = wire({'status': 'completed', 'result': {'durable': True}})
        for tool in ('hia_artifact', 'hia_adopt'):
            for commit in (1, 2):
                for after in (False, True):
                    with self.subTest(tool=tool, commit=commit, after=after), self.selected():
                        folder = self.folder / ('process-exit-' + tool + '-' + str(commit) + '-' + str(int(after)))
                        folder.mkdir(mode=0o700)
                        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program,
                            str(ROOT), str(self.manifest), str(folder / 'state'), tool, str(commit), str(int(after))],
                            cwd=folder, capture_output=True, timeout=15)
                        (folder / 'stdout').write_bytes(result.stdout); (folder / 'stderr').write_bytes(result.stderr)
                        self.assertEqual(result.returncode, 73, result.stderr)
                        store = AgentStore(folder / 'state')
                        try:
                            rows = [dict(row) for row in store.db.execute('SELECT * FROM main.requests')]
                            slots = [dict(row) for row in store.db.execute('SELECT * FROM main.slots')]
                            exists, completed = commit != 1 or after, commit == 2 and after
                            self.assertEqual(len(rows), int(exists))
                            self.assertEqual(len(slots), int(completed and tool == 'hia_adopt'))
                            if completed:
                                ticket = store.request_journal.admit(tool, DIGEST.decode(), 'physical-exit', lambda *args: None)
                                self.assertEqual(ticket.replay_bytes, expected)
                                with self.assertRaises(RequestJournalUnknown): ticket.dispatch()
                            elif exists:
                                self.assertEqual((rows[0]['state'], rows[0]['response']), ('running', None))
                                with self.assertRaises(AgentRejected) as unknown:
                                    store.request_journal.admit(tool, DIGEST.decode(), 'physical-exit', lambda *args: None)
                                self.assertEqual(unknown.exception.code, 'E_HIA_REQUEST_UNKNOWN')
                            (folder / 'restart.json').write_text(json.dumps({
                                'exit_status': result.returncode, 'tool': tool, 'commit': commit,
                                'after': after, 'durable_rows': rows, 'durable_slots': slots,
                                'native_image_sha256': self.image.image_sha256}, indent=2) + '\n')
                        finally: store.close()

    def test_replay_validation_readonly_revocation_and_unknown_commit_preserve_exact_row(self):
        from hepta.hia_agent_store import AgentStore
        for mode in ('write', 'known-rejection', 'commit-before', 'commit-after', 'confirmed'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory); journal = store.request_journal
                try:
                    ticket = journal.admit('hia_artifact', DIGEST.decode(), 'replay-capability', lambda *args: None)
                    ticket.run(lambda: {'exact': 7}, lambda result: result, lambda error: None)
                    ticket.finish(b'{"exact":7}')
                    original = tuple(store.db.execute('SELECT * FROM main.requests').fetchone())
                    retained, returned, execute = [], [], journal._execute
                    def validate(raw, connection):
                        self.assertEqual(raw, b'{"exact":7}')
                        retained.extend((connection, connection.execute('SELECT * FROM slots WHERE name=?', ('missing',))))
                        if mode == 'write':
                            connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)', ('forbidden', 'ctx', '1', '1', 'a'*64))
                        if mode == 'known-rejection': raise ValueError('proof no longer accepted')
                    def lost(sql, parameters=()):
                        if sql == 'COMMIT' and mode == 'commit-before': raise KeyboardInterrupt('before replay COMMIT')
                        result = execute(sql, parameters)
                        if sql == 'COMMIT' and mode == 'commit-after': raise KeyboardInterrupt('after replay COMMIT')
                        return result
                    with patch.object(journal, '_execute', side_effect=lost):
                        if mode == 'confirmed':
                            returned.append(journal.admit('hia_artifact', DIGEST.decode(), 'replay-capability', validate))
                            self.assertEqual(returned[0].replay_bytes, b'{"exact":7}')
                        else:
                            expected_error = ValueError if mode == 'known-rejection' else RequestJournalUnknown
                            with self.assertRaises(expected_error):
                                returned.append(journal.admit('hia_artifact', DIGEST.decode(), 'replay-capability', validate))
                            self.assertEqual(returned, [])
                    self.assertEqual(tuple(store.db.execute('SELECT * FROM main.requests').fetchone()), original)
                    self.assertIsNone(store.db.execute('SELECT * FROM main.slots').fetchone())
                    with self.assertRaises(RequestJournalUnknown):
                        retained[0].execute('SELECT * FROM slots WHERE name=?', ('missing',))
                    with self.assertRaises(RequestJournalUnknown): retained[1].fetchall()
                    replay = journal.admit('hia_artifact', DIGEST.decode(), 'replay-capability', lambda *args: None)
                    self.assertEqual(replay.replay_bytes, b'{"exact":7}')
                finally: store.close()

    def test_actual_concurrent_claim_has_one_owner_and_exact_response_cannot_change(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected, wire
        with tempfile.TemporaryDirectory() as directory, self.selected():
            stores = [AgentStore(directory), AgentStore(directory)]
            start = threading.Barrier(3)
            try:
                def claim(store):
                    start.wait(timeout=5)
                    try: return store.request_journal.admit('hia_artifact', DIGEST.decode(), 'concurrent', lambda *args: None)
                    except AgentRejected as error: return error
                with ThreadPoolExecutor(2) as pool:
                    pending = [pool.submit(claim, store) for store in stores]
                    start.wait(timeout=5)
                    answers = [future.result(timeout=15) for future in pending]
                winners = [answer for answer in answers if not isinstance(answer, AgentRejected)]
                refusals = [answer for answer in answers if isinstance(answer, AgentRejected)]
                self.assertEqual(len(winners), 1); self.assertEqual(len(refusals), 1)
                self.assertEqual(refusals[0].code, 'E_HIA_REQUEST_UNKNOWN')
                effects = []
                response = winners[0].run(lambda: effects.append('once') or {'answer': 7}, lambda value: value, lambda error: None)
                response['answer'] = 8
                with patch.object(winners[0].store, '_execute', side_effect=AssertionError('changed response reached SQL')):
                    with self.assertRaises(RequestJournalUnknown): winners[0].finish(wire(response))
                self.assertEqual(effects, ['once'])
                self.assertEqual(tuple(stores[0].db.execute('SELECT state,response FROM main.requests').fetchone()),
                                 ('running', None))
            finally:
                for store in stores: store.close()

    def test_native_key_boundaries_and_cross_owner_tokens_never_grant_sql(self):
        from hepta.hia_agent_store import AgentStore, AgentRejected
        keys = (None, False, '', '\0', 'a' * 192, 'a' * 193, '\U0001f680' * 192, '\U0001f680' * 193)
        for key in keys:
            with self.subTest(key_type=type(key).__name__, length=len(key) if type(key) is str else None):
                state = RequestState(self.image, (31, 37), 'hia_artifact', DIGEST.decode(), key,
                                     started='17', response_capacity=CAPACITY)
                self.assertEqual(state.receipt.keyed, type(key) is str and 1 <= len(key) <= 192)
        for invalid in ('foreign-token', 'corrupt-retained-bytes'):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory)
                try:
                    journal = store.request_journal
                    first = journal.admit('hia_artifact', DIGEST.decode(), 'first', lambda *args: None)
                    second = journal.admit('hia_artifact', DIGEST.decode(), 'second', lambda *args: None)
                    if invalid == 'foreign-token':
                        with self.assertRaises(AgentRejected): first.state.call(5, token=second.state.receipt.token)
                    else:
                        first.state.buffer[320] = b'e'
                    with patch.object(journal, '_execute', side_effect=AssertionError('invalid native owner reached SQL')):
                        with self.assertRaises(RequestJournalUnknown): first.dispatch()
                    self.assertEqual([tuple(row) for row in store.db.execute('SELECT state,response FROM main.requests')],
                                     [('running', None), ('running', None)])
                finally: store.close()

    def test_main_and_wal_identity_changes_refuse_before_request_sql(self):
        from hepta.hia_agent_store import AgentStore
        for suffix in ('', '-wal', '-shm'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory, self.selected():
                store = AgentStore(directory); journal = store.request_journal
                original = Path(str(store.database) + suffix)
                retained = Path(str(original) + '.retained-original')
                try:
                    original.rename(retained)
                    original.write_bytes(b'replaced official identity'); original.chmod(0o600)
                    with patch.object(journal, '_execute', side_effect=AssertionError('changed journal reached SQL')):
                        with self.assertRaises(RequestJournalUnknown):
                            journal.admit('hia_artifact', DIGEST.decode(), 'identity-change', lambda *args: None)
                    self.assertEqual(original.read_bytes(), b'replaced official identity')
                finally:
                    original.unlink(); retained.rename(original); store.close()

    def test_installed_wheel_real_service_and_atomic_journal_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        case = self.folder / 'installed-wheel-control'; case.mkdir(mode=0o700)
        source = case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], cwd=case,
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
            raise AssertionError('installed request journal imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire
from hepta import hia_execution_budget as reference
from hepta.hia_request_journal_native import SOURCE,SELECTOR,RequestJournalUnknown
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed request journal used reference policy or repeated effect')
HIAAgentService._call_reference=forbidden
reference._ReferenceExecutionBudgetStore.__init__=forbidden
reference._ReferenceBudgetClaim.__init__=forbidden
os.environ[SELECTOR]=sys.argv[2]
os.environ['HEPTA_HIA_EXECUTION_BUDGET_MANIFEST']=sys.argv[3]
service=HIAAgentService(sys.argv[4])
args={'catalog_sha256':service.catalog_sha256,'request_key':'installed-artifact',
    'artifact_profile':service.profiles['artifact'],'source':{'kind':'utf8','text':'installed native request owner'}}
response=service.call('hia_artifact',args)
assert response['status']=='completed',response
data,_=service.store.get(response['result']['artifact'])
assert data==b'installed native request owner',data
service._hia_artifact=forbidden
assert service.call('hia_artifact',args)==response
ticket=service.store.request_journal.admit('hia_adopt','d'*64,'installed-atomic',lambda *args:None)
retained=[]
def invoke(connection):
    retained.append(connection)
    connection.execute('INSERT INTO slots VALUES (?,?,?,?,?)',('installed-slot','context','1','1','a'*64))
    return {'status':'completed','result':{'generation':'1'}}
atomic=ticket.atomic(invoke,lambda value:value)
assert service.store.db.execute('SELECT generation FROM main.slots').fetchone()[0]=='1'
try:retained[0].execute('SELECT * FROM slots WHERE name=?',('installed-slot',))
except RequestJournalUnknown:pass
else:raise AssertionError('installed effect connection was not revoked')
service.close()
service=HIAAgentService(sys.argv[4]);service._hia_artifact=forbidden
assert service.call('hia_artifact',args)==response
replay=service.store.request_journal.admit('hia_adopt','d'*64,'installed-atomic',lambda *args:None)
assert replay.replay_bytes==wire(atomic)
assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
service.close()
print(json.dumps({'artifact_response':response,'atomic_response':atomic,'installed_source':str(SOURCE),
    'same_original_journal_restarted':True,'authoring_imported':False,'reference_called':False},sort_keys=True))
'''
        child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(installed),
            str(self.manifest), str(self.budget_manifest), str(case / 'state')],
            cwd=case, capture_output=True, text=True, timeout=30)
        (case / 'actual.stdout').write_text(child.stdout); (case / 'actual.stderr').write_text(child.stderr)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertTrue(json.loads(child.stdout)['same_original_journal_restarted'])


if __name__ == '__main__':
    unittest.main()
