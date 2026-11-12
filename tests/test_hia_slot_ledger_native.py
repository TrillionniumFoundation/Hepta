"""Independent VM/actual native checks for streamed slot ledger decisions."""
from __future__ import annotations
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_slot_ledger_native import (NativeSlotLedger, SlotLedgerReceipt,
    REQUEST_MAGIC, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE, STATE_BYTES, MAX_U64,
    request_packet)

ROOT = Path(__file__).resolve().parents[1]
TOKEN = (11, 17, 31, 37)
ARTIFACT = b'{"id":"artifact-a","sha256":"abc","uri":"hepta:artifact-a"}'
FIELDS = (b'Slease-a', b'Sslot-a', b'S9', ARTIFACT)


@lru_cache(maxsize=1)
def checked():
    from hepta.hia_agent_assembly import assemble_program
    program = assemble_program(SOURCE.read_bytes())
    entry = next(f for f in program.as_dict()['functions'] if f['name'] == 'f0')
    return program, entry


class VM:
    def __init__(self):
        self.program, self.entry = checked()
        self.reset()

    def reset(self):
        self.state = bytearray(STATE_BYTES)

    def corrupt(self, index):
        self.state[index] ^= 1

    def call(self, raw, capacity=None):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        capacity = max(256, len(raw) + 128) if capacity is None else capacity
        owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'\xa5' * capacity)),
                  _Owner(-3, self.state)]
        machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
        count = machine.invoke(self.entry, [_View(owners[0], False), _View(owners[1], True),
                                           _View(owners[2], True)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('VM input changed')
        return count, bytes(owners[1].data[:min(count, capacity)]), bytes(self.state)


class Machine:
    def __init__(self, image):
        self.image = image
        self.reset()

    def reset(self):
        self.state = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memset(ctypes.addressof(self.state) + STATE_BYTES, 0xb7, 16)

    def corrupt(self, index):
        value = self.state[index]
        self.state[index] = bytes((value[0] ^ 1,))

    def call(self, raw, capacity=None):
        capacity = max(256, len(raw) + 128) if capacity is None else capacity
        source = ctypes.create_string_buffer(raw, len(raw)) if raw else ctypes.create_string_buffer(1)
        output = ctypes.create_string_buffer(capacity + 16)
        ctypes.memset(ctypes.addressof(output), 0xa5, capacity)
        ctypes.memset(ctypes.addressof(output) + capacity, 0xc9, 16)
        count = self.image._entry(source, len(raw), output, capacity, self.state, STATE_BYTES)
        if ((raw and source.raw != raw) or output.raw[capacity:] != b'\xc9' * 16
                or self.state.raw[STATE_BYTES:] != b'\xb7' * 16):
            raise AssertionError('native byte boundary changed an input/canary')
        return count, output.raw[:min(count, capacity)], self.state.raw[:STATE_BYTES]


def decode(result):
    count, raw, _state = result
    if count < 64 or count != len(raw):
        raise AssertionError(('unexpected result extent', count, len(raw)))
    header = struct.unpack('<8Q', raw[:64])
    if header[0] != RESULT_MAGIC:
        raise AssertionError('unexpected result magic')
    lengths = struct.unpack_from('<' + str(header[3]) + 'Q', raw, 64)
    at, fields = 64 + len(lengths) * 8, []
    for length in lengths:
        fields.append(raw[at:at + length]); at += length
    if at != count or sum(lengths) != header[6]:
        raise AssertionError('result payload extent')
    return header, tuple(fields)


def witnesses(engine):
    rows = []
    def call(op, fields=(), *, status=0, action=0, values=(0, 0), returned=(), **kwargs):
        raw = request_packet(op, fields, **kwargs)
        result = engine.call(raw)
        h, got = decode(result)
        if (h[1], h[2], h[4:6], got, h[7]) != (status, action, values, returned, op):
            raise AssertionError((op, h, got, status, action, values, returned))
        rows.append((raw, result))
    call(2)
    snapshot = (b'S9', b'S3', b'Sctx', ARTIFACT)
    call(2, snapshot, flags=1, a=7, action=1, values=(7, 0), returned=snapshot)
    call(3, (b'S9', b'S3', b'S9', b'S3'), flags=1)
    call(3, (b'S9', b'S3', b'S8', b'S3'), flags=1, status=3)
    call(3, (b'S9', b'S3', b'S9', b'S3'), flags=0, status=3)
    for op, status in ((4, 4), (5, 5), (11, 13)):
        call(op, (b'Ssame', b'Ssame'))
        call(op, (b'Ssame', b'Schanged'), status=status)
    call(6, flags=1)
    call(6, status=8)
    call(6, a=1, status=9)
    call(10, flags=1)
    call(10, status=10)
    call(12, flags=0, action=1)
    call(12, flags=1, action=2)
    for active, status in ((b'I1', 0), (b'I0', 11), (b'I2', 11), (b'I-1', 11), (b'X', 11)):
        call(16, (*FIELDS, FIELDS[1], FIELDS[2], active), flags=1, status=status,
             action=1 if status == 0 else 0, returned=FIELDS if status == 0 else ())
    call(16, (*FIELDS, b'Sother', FIELDS[2], b'I1'), flags=1, status=11)
    call(16, (*FIELDS, FIELDS[1], FIELDS[2], b'I1'), flags=0, status=11)
    call(13, (*FIELDS, FIELDS[1], FIELDS[2], ARTIFACT), flags=1, a=1, b=1,
         action=1, returned=FIELDS)
    call(14, (*FIELDS, FIELDS[1], FIELDS[2], ARTIFACT), flags=1, a=1, b=1,
         action=2, returned=FIELDS)
    call(13, (*FIELDS, FIELDS[1], FIELDS[2], ARTIFACT.replace(b'hepta:', b'forged:')),
         flags=1, a=1, b=1, status=11)
    call(13, (*FIELDS, FIELDS[1], FIELDS[2], b''), flags=1, a=1, b=0, status=11)
    call(15, FIELDS, flags=1, action=3, returned=FIELDS)
    call(15, FIELDS, flags=0, status=8)
    for value in (b'0', b'9', b'10', b'9223372036854775808', b'18446744073709551615'):
        call(1, (value,), flags=1, values=(int(value), 0))
    for value in (b'', b'00', b'-1', b'+1', b' 1', b'1 ', b'18446744073709551616', b'\xff'):
        call(1, (value,), flags=1, status=2, values=(1, 0))
    call(1, (b'3', b'bad'), flags=1, status=2, values=(2, 0))
    engine.reset()
    call(7, (b'9',), flags=1, token=TOKEN)
    for value in (b'0', b'9', b'2', b'18446744073709551614'):
        call(8, (value,), token=TOKEN)
    call(9, token=TOKEN, values=(MAX_U64, 10),
         returned=(b'18446744073709551615', b'10'))
    call(9, token=TOKEN, status=12)
    engine.reset()
    call(7, (b'10', b'0'), flags=2, token=TOKEN)
    call(9, token=TOKEN, values=(0, 11), returned=(b'0', b'11'))
    engine.reset()
    call(7, (b'0',), flags=1, token=TOKEN)
    call(8, (b'18446744073709551615',), token=TOKEN)
    call(9, token=TOKEN, status=6)
    engine.reset()
    call(7, (b'18446744073709551615',), flags=1, token=TOKEN)
    call(8, (b'0',), token=TOKEN)
    call(9, token=TOKEN, status=6)
    engine.reset()
    call(7, (b'18446744073709551615', b'0'), flags=2, token=TOKEN)
    call(9, token=TOKEN, status=7)
    engine.reset()
    call(7, (b'0',), flags=1, token=TOKEN)
    call(8, (b'8',), token=(11, 17, 31, 38), status=12)
    call(8, (b'8',), token=TOKEN)
    engine.corrupt(64)
    call(9, token=TOKEN, status=12)
    return rows


def malformed(engine):
    rows = []
    raw = request_packet(2)
    for value, capacity, expected in ((b'', 256, 4294967293),
                                      (raw, 63, 4294967293),
                                      (request_packet(2, (b'S1', b'S2', b'Sctx', ARTIFACT), flags=1),
                                       95, 4294967294)):
        engine.reset()
        result = engine.call(value, capacity)
        if result[0] != expected or result[1] != b'\xa5' * capacity:
            raise AssertionError(('partial output publication', result))
        rows.append((value, capacity, result))
    cases = []
    words = list(struct.unpack('<16Q', raw))
    for index, value in ((0, 0), (1, 99), (2, 8), (6, 1), (8, 1), (12, 1), (15, 1)):
        changed = words.copy(); changed[index] = value
        cases.append(struct.pack('<16Q', *changed))
    wrapped = list(struct.unpack('<16Q', request_packet(3, (b'', b'', b'', b''), flags=1)[:128]))
    cases.append(struct.pack('<16Q', *wrapped) + struct.pack('<4Q', MAX_U64, 1, 0, 0))
    cases.extend((request_packet(3, (b'a', b'b', b'a', b'b'), flags=1)[:-1],
                  request_packet(2) + b'extra'))
    for value in cases:
        engine.reset()
        result = engine.call(value)
        if value[:8] == b'\x00' * 8:
            if result[0] != 4294967293: raise AssertionError(result)
        elif decode(result)[0][1] != 12:
            raise AssertionError(result)
        rows.append((value, None, result))
    return rows


def evaluation_witnesses(engine):
    """Independent Python value semantics versus actual HIA byte decisions."""
    from hepta.hia_agent_store import wire
    values = (None, False, True, 0, -0.0, 0.0, 1, -2, 10 ** 100,
              1e-300, -1e-300, "", "false", "雪", [], [False], {}, {"x": 0})
    rows = []
    def check(opcode, fields, expected):
        raw = request_packet(opcode, fields)
        result = engine.call(raw)
        header, returned = decode(result)
        if (header[1], header[2], header[4:6], returned, header[7]) != (
                expected, 0, (0, 0), (), opcode):
            raise AssertionError((opcode, fields, expected, header, returned))
        rows.append((raw, result))
    for value in values:
        check(17, (wire(value),), 0 if bool(value) else 14)
        check(19, (wire(value),), 15 if bool(value) else 0)
    for outcome in ("improved", "unchanged", "incorrect", "IMPROVED", "", None, 0, True, [], {}):
        for allow in (False, True, 0, "", [], [False], {"x": 0}):
            try:
                eligible = outcome in ({"improved", "unchanged"} if allow else {"improved"})
                expected = 0 if eligible else 14
            except TypeError:
                expected = 16 if type(outcome) is list else 17
            check(18, (wire(outcome), wire(allow)), expected)
    for raw in (b'', b'undefined', b'01', b'-', b'1.', b'1e', b'1e+', b'"', b'['):
        check(17, (raw,), 12)
    return rows


class SlotLedgerSourceTests(unittest.TestCase):
    def test_exact_generated_source_and_independent_vm_decisions(self):
        from tools.generate_hia_slot_ledger import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        rows = witnesses(VM())
        self.assertGreater(len(rows), 60)

    def test_independent_vm_refuses_wrapped_lengths_and_partial_publication(self):
        self.assertGreater(len(malformed(VM())), 10)

    def test_independent_vm_admits_evaluation_values_and_outcomes(self):
        self.assertGreater(len(evaluation_witnesses(VM())), 100)

    def test_evaluation_adapter_preserves_reference_errors_and_short_circuit(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_slot_ledger_native import NativeSlotLedgerStore
        class VMImage:
            def transition(self, raw, state=None):
                result = VM().call(raw)
                header, fields = decode(result)
                return SlotLedgerReceipt(header[1], header[2], header[4:6], fields, result[1])
        driver = NativeSlotLedgerStore(None, VMImage())
        def observed(function, *args):
            try:
                function(*args)
                return ('accepted',)
            except Exception as error:
                return (type(error).__name__, str(error), getattr(error, 'code', None),
                        getattr(error, 'phase', None), getattr(error, 'retry_action', None))
        evaluation = dict(report_complete=True, planned_workload_complete=True,
                          termination_confirmed=True, outcome='improved')
        cases = [(evaluation, {'allow_unchanged': True}),
                 ({}, {}), ({'report_complete': False}, {}),
                 ({'report_complete': True}, {}),
                 ({'report_complete': True, 'planned_workload_complete': []}, {}),
                 ({'report_complete': True, 'planned_workload_complete': True}, {}),
                 (evaluation | {'termination_confirmed': 0}, {}),
                 (evaluation | {'outcome': []}, {}),
                 (evaluation | {'outcome': []}, {'allow_unchanged': False}),
                 (evaluation | {'outcome': {}}, {'allow_unchanged': True}),
                 (evaluation | {'outcome': 'unchanged'}, {'allow_unchanged': False}),
                 (evaluation | {'outcome': 'unchanged'}, {'allow_unchanged': [False]}),
                 (evaluation | {'outcome': 'incorrect'}, {'allow_unchanged': True})]
        reference = lambda value, objective: HIAAgentService._reference_adoption_evaluation(None, value, objective)
        for value, objective in cases:
            with self.subTest(value=value, objective=objective):
                self.assertEqual(observed(driver.admit_evaluation, value, objective),
                                 observed(reference, value, objective))
        reference_net = lambda objective: HIAAgentService._reference_adoption_net_benefit(None, objective)
        for objective in ({}, {'require_net_benefit': False}, {'require_net_benefit': True},
                          {'require_net_benefit': 0}, {'require_net_benefit': {}}):
            self.assertEqual(observed(driver.admit_net_benefit, objective), observed(reference_net, objective))

    def test_unhashable_outcome_uses_interpreter_error_after_native_refusal(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_slot_ledger_native as native
        class VMImage:
            def __init__(self):
                self.operations = []
            def transition(self, raw, state=None):
                result = VM().call(raw)
                header, fields = decode(result)
                self.operations.append((struct.unpack_from('<Q', raw, 8)[0], header[1]))
                return SlotLedgerReceipt(header[1], header[2], header[4:6], fields, result[1])
        complete = dict(report_complete=True, planned_workload_complete=True,
                        termination_confirmed=True)
        for outcome, status in (([], 16), ([0], 16), ({}, 17), ({'value': 0}, 17)):
            for allow in (False, True):
                with self.subTest(outcome=outcome, allow=allow):
                    evaluation = complete | {'outcome': outcome}
                    objective = {'allow_unchanged': allow}
                    with self.assertRaises(TypeError) as expected:
                        HIAAgentService._reference_adoption_evaluation(None, evaluation, objective)
                    image = VMImage()
                    # Interpreter-raised errors do not consult this module name.
                    # A hand-written TypeError constructor must fail this control.
                    with patch.object(native, 'TypeError',
                            side_effect=AssertionError('manual outcome TypeError'), create=True):
                        with self.assertRaises(TypeError) as actual:
                            native.NativeSlotLedgerStore(None, image).admit_evaluation(evaluation, objective)
                    self.assertEqual((type(actual.exception), actual.exception.args, str(actual.exception)),
                                     (type(expected.exception), expected.exception.args, str(expected.exception)))
                    self.assertEqual(image.operations, [(17, 0), (17, 0), (17, 0), (18, status)])

    def test_outcome_diagnostic_cannot_override_native_decisions(self):
        from hepta.hia_agent_store import AgentRejected
        from hepta.hia_slot_ledger_native import NativeSlotLedgerStore
        class VerdictImage:
            def __init__(self, status):
                self.status = status
            def transition(self, raw, state=None):
                opcode = struct.unpack_from('<Q', raw, 8)[0]
                return SlotLedgerReceipt(self.status if opcode == 18 else 0, 0, (0, 0), (), b'')
        complete = dict(report_complete=True, planned_workload_complete=True,
                        termination_confirmed=True)
        objective = {'allow_unchanged': False}
        # Adapter-only controls: a selected verdict owns the decision. These
        # synthetic receipts are not executable-image qualification evidence.
        for outcome in ([], {}):
            evaluation = complete | {'outcome': outcome}
            self.assertIsNone(NativeSlotLedgerStore(None, VerdictImage(0)).admit_evaluation(evaluation, objective))
            with self.assertRaises(AgentRejected) as refused:
                NativeSlotLedgerStore(None, VerdictImage(14)).admit_evaluation(evaluation, objective)
            self.assertEqual(refused.exception.code, 'E_HIA_EVALUATION_REQUIRED')
        for status in (16, 17):
            with self.assertRaises(AgentRejected) as invalid:
                NativeSlotLedgerStore(None, VerdictImage(status)).admit_evaluation(
                    complete | {'outcome': 'improved'}, objective)
            self.assertEqual((invalid.exception.code, invalid.exception.retry_action),
                             ('E_HIA_SLOT_NATIVE_CUSTODY', 'stop'))

    def test_bad_cold_builder_refuses_before_output_or_compilation(self):
        from tools.build_hia_slot_ledger import build
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            compiler = folder / 'compiler'; compiler.write_bytes(b'not a qualified compiler')
            cold = folder / 'cold.json'; cold.write_text('{}')
            with patch('tools.qualify_hia_selfhost.compile_stage',
                       side_effect=AssertionError('native compile entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(folder / 'must-not-exist', compiler, cold)
            self.assertFalse((folder / 'must-not-exist').exists())

    def test_fixture_requires_explicit_cold_or_development_and_admits_before_output(self):
        class Fixture(SlotLedgerNativeTests):
            pass
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            evidence = folder / 'evidence'
            cold = folder / 'cold.json'; cold.write_text('{}')
            env = {'HEPTA_HIA_SLOT_LEDGER_EVIDENCE': str(evidence)}
            with patch.dict(os.environ, env, clear=True), patch(
                    'tools.qualify_hia_selfhost.compile_stage',
                    side_effect=AssertionError('native compile entered')), patch(
                    'tools.qualify_hia_selfhost.build_seed',
                    side_effect=AssertionError('implicit seed entered')):
                with self.assertRaisesRegex(ValueError, 'requires an explicit'):
                    Fixture.setUpClass()
            with patch.dict(os.environ, env | {'HEPTA_HIA_SLOT_LEDGER_COLD_REPORT': str(cold)}, clear=True):
                with self.assertRaisesRegex(ValueError, 'cold report lacks a compiler'):
                    Fixture.setUpClass()
            with patch.dict(os.environ, env | {'HEPTA_HIA_SLOT_LEDGER_COLD_REPORT': str(cold),
                    'HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER': '/unread'}, clear=True), patch.object(
                    Path, 'read_bytes', side_effect=AssertionError('artifact read before mode refusal')):
                with self.assertRaisesRegex(ValueError, 'cannot be combined'):
                    Fixture.setUpClass()
            self.assertFalse(evidence.exists())

    def test_selected_empty_or_missing_image_refuses_before_state_effect(self):
        from hepta.hia_agent_service import HIAAgentService
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            for selected in ('', str(folder / 'missing')):
                state = folder / ('state-empty' if not selected else 'state-missing')
                with self.subTest(selected=selected), patch.dict(os.environ, {SELECTOR: selected}, clear=True), patch(
                        'hepta.hia_agent_service.AgentStore', side_effect=AssertionError('state opened')):
                    with self.assertRaises((ValueError, OSError)):
                        HIAAgentService(state)
                self.assertFalse(state.exists())


    def test_actual_sqlite_blob_and_short_circuit_via_independent_hia_vm(self):
        import sqlite3
        from hepta.hia_agent_store import AgentStore, AgentRejected, wire
        from hepta.hia_slot_ledger_native import NativeSlotLedgerStore
        class VMImage:
            def __init__(self):
                self.operations = []
            def transition(self, raw, state=None):
                if state is not None:
                    raise AssertionError('this lease control is stateless')
                self.operations.append(struct.unpack_from('<Q', raw, 8)[0])
                result = VM().call(raw)
                header, fields = decode(result)
                return SlotLedgerReceipt(header[1], header[2], header[4:6], fields, result[1])
        artifact = {'id': 'artifact-a', 'sha256': 'a' * 64, 'uri': 'hepta:artifact-a'}
        lease = {'id': 'lease-source-blob', 'slot': 'slot-source-blob',
                 'generation': '7', 'artifact': artifact}
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            store = AgentStore(Path(temporary) / 'state')
            self.addCleanup(store.close)
            image = VMImage()
            driver = NativeSlotLedgerStore(store, image)
            canonical = wire(artifact)
            store.db.execute('INSERT INTO leases VALUES (?,?,?,?,1)',
                (lease['id'], lease['slot'], lease['generation'], sqlite3.Binary(canonical)))
            self.assertEqual(store.db.execute('SELECT typeof(artifact) FROM leases').fetchone()[0], 'blob')
            result = driver.lease(lease)
            self.assertEqual(result, lease)
            self.assertIsNot(result['artifact'], artifact)
            self.assertEqual(image.operations, [16, 13])
            for stored in (sqlite3.Binary(b'not-json'), sqlite3.Binary(bytes((255,))), 'not-json', 1.5):
                store.db.execute('UPDATE leases SET artifact=?,active=1', (stored,))
                for change in ({'id': 'unknown'}, {'slot': 'other'}, {'generation': 7}):
                    with self.subTest(stored=repr(stored), change=change):
                        with self.assertRaises(AgentRejected) as rejected:
                            driver.lease(lease | change)
                        self.assertEqual(rejected.exception.code, 'E_HIA_LEASE')
                store.db.execute('UPDATE leases SET active=0')
                with self.assertRaises(AgentRejected) as rejected:
                    driver.release(lease)
                self.assertEqual(rejected.exception.code, 'E_HIA_LEASE')
            store.db.execute('UPDATE leases SET artifact=?,active=1', (sqlite3.Binary(canonical),))
            for claimed in (artifact | {'extra': 1}, {'id': artifact['id']},
                            artifact | {'sha256': None}, b'not-a-descriptor'):
                with self.subTest(claimed=repr(claimed)), self.assertRaises(AgentRejected) as rejected:
                    driver.lease(lease | {'artifact': claimed})
                self.assertEqual(rejected.exception.code, 'E_HIA_LEASE')
            fault = ValueError('explicit selected renderer custody fault')
            class FailingRenderer:
                def render(self, number):
                    raise fault
            with patch.dict(os.environ, {'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST': 'selected-renderer'}), patch(
                    'hepta.hia_agent_binary64_format_native.installed_agent_binary64_format',
                    return_value=FailingRenderer()):
                before = len(image.operations)
                statements = []
                store.db.set_trace_callback(statements.append)
                try:
                    with self.assertRaises(ValueError) as rejected:
                        with store.transaction():
                            driver.release(lease | {'artifact': artifact | {'extra': 1.25}})
                finally:
                    store.db.set_trace_callback(None)
                self.assertIs(rejected.exception, fault)
                self.assertEqual(image.operations[before:], [16])
                self.assertIn('ROLLBACK', statements)
                self.assertNotIn('COMMIT', statements)
                self.assertFalse(any(statement.lstrip().upper().startswith(('UPDATE ', 'INSERT ', 'DELETE '))
                                     for statement in statements))
            self.assertEqual(store.db.execute('SELECT active FROM leases').fetchone()[0], 1)


class SlotLedgerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage
        cold = os.environ.get('HEPTA_HIA_SLOT_LEDGER_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('slot ledger development compiler cannot be combined with a cold report')
        if not cold and not development:
            raise ValueError('slot ledger fixture requires an explicit matching cold report or development compiler')
        cls.cold = Path(cold) if cold else None
        cls.temporary = None
        if cls.cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cold_bytes = cls.cold.read_bytes()
            report = json.loads(cold_bytes)
            try:
                nested_bytes = Path(report['nested_report']).read_bytes()
                nested = json.loads(nested_bytes)
                cls.compiler = Path(nested['generations'][-1]['produced_image'])
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('slot ledger cold report lacks a compiler') from error
            compiler_bytes = cls.compiler.read_bytes()
            admitted = admit_cold_build(compiler_bytes, cold_bytes)
        else:
            cls.compiler = Path(development).resolve(strict=True)
            compiler_bytes = cls.compiler.read_bytes()
        source_bytes = SOURCE.read_bytes()
        evidence = os.environ.get('HEPTA_HIA_SLOT_LEDGER_EVIDENCE')
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-slot-ledger-')
            cls.folder = Path(cls.temporary.name)
        if cls.cold:
            from tools.build_hia_slot_ledger import build
            cls.manifest = build(cls.folder / 'qualified', cls.compiler, cls.cold)
            record = json.loads(cls.manifest.read_bytes())
            image_path = cls.manifest.parent / record['image_path']
            receipt = json.loads((cls.manifest.parent / 'build.json').read_bytes())['native_compile_receipt']
            mode = 'MATCHING_CURRENT_SOURCE_COLD_BUILD'
            if (cls.cold.read_bytes() != cold_bytes
                    or Path(report['nested_report']).read_bytes() != nested_bytes
                    or admit_cold_build(compiler_bytes, cold_bytes) != admitted):
                raise AssertionError('slot ledger fixture cold evidence changed')
        else:
            image_path, receipt = compile_stage(cls.folder, 'slot-ledger-development',
                                               cls.compiler, source_bytes)
            raw_image = image_path.read_bytes()
            record = {'schema': SCHEMA, 'source_sha256': sha256(source_bytes).hexdigest(),
                'image_path': image_path.name, 'image_sha256': sha256(raw_image).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
            mode = 'EXPLICIT_DEVELOPMENT_COMPILER_NOT_COLD_QUALIFIED'
        image_bytes = image_path.read_bytes()
        cls.image = NativeSlotLedger(image_bytes, record['image_sha256'])
        if SOURCE.read_bytes() != source_bytes or cls.compiler.read_bytes() != compiler_bytes:
            raise AssertionError('slot ledger fixture source/compiler changed')
        (cls.folder / 'fixture.json').write_text(json.dumps({'mode': mode,
            'manifest': record, 'native_compile_receipt': receipt,
            'cold_report': str(cls.cold) if cls.cold else None,
            'matching_current_source_cold_qualified': bool(cls.cold)}, indent=2, sort_keys=True) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def test_actual_machine_matches_every_independent_vm_result_and_state_byte(self):
        reference, actual = witnesses(VM()), witnesses(Machine(self.image))
        self.assertEqual(actual, reference)
        (self.folder / 'native-vm-witnesses.json').write_text(json.dumps([
            {'request_hex': request.hex(), 'return': result[0],
             'output_hex': result[1].hex(), 'state_hex': result[2].hex()}
            for request, result in actual], indent=2, sort_keys=True) + '\n')

    def test_actual_machine_refuses_wrapped_lengths_without_partial_output(self):
        self.assertEqual(malformed(Machine(self.image)), malformed(VM()))

    def test_actual_evaluation_policy_matches_independent_value_semantics(self):
        reference = evaluation_witnesses(VM())
        actual = evaluation_witnesses(Machine(self.image))
        self.assertEqual(actual, reference)
        (self.folder / 'native-evaluation-witnesses.json').write_text(json.dumps([
            {'request_hex': request.hex(), 'return': result[0],
             'output_hex': result[1].hex(), 'state_hex': result[2].hex()}
            for request, result in actual], indent=2, sort_keys=True) + '\n')

    def test_actual_image_receipts_bind_frozen_state_and_full_descriptors(self):
        state = ctypes.create_string_buffer(STATE_BYTES)
        self.assertIsInstance(self.image.transition(request_packet(7, (b'8',), flags=1, token=TOKEN), state),
                              SlotLedgerReceipt)
        self.image.transition(request_packet(8, (b'0',), token=TOKEN), state)
        self.image.transition(request_packet(8, (b'9223372036854775808',), token=TOKEN), state)
        receipt = self.image.transition(request_packet(9, token=TOKEN), state)
        self.assertEqual(receipt.values, (9223372036854775809, 9))
        self.assertEqual(receipt.fields, (b'9223372036854775809', b'9'))
        self.assertEqual(struct.unpack('<16Q', bytes(state))[3], 9)
        self.assertEqual(struct.unpack('<16Q', bytes(state))[6], 9223372036854775809)
        self.assertEqual(self.image.transition(request_packet(9, token=TOKEN), state).status, 12)
        good = self.image.transition(request_packet(13,
            (*FIELDS, FIELDS[1], FIELDS[2], ARTIFACT), flags=1, a=1, b=1))
        self.assertEqual(good.fields, FIELDS)
        for old, new in ((b'artifact-a', b'artifact-b'), (b'abc', b'abd'), (b'hepta:', b'else:')):
            bad = ARTIFACT.replace(old, new)
            result = self.image.transition(request_packet(13,
                (*FIELDS, FIELDS[1], FIELDS[2], bad), flags=1, a=1, b=1))
            self.assertEqual(result.status, 11)

    def test_actual_fold_has_no_history_count_limit_and_uses_numeric_u64_order(self):
        state = ctypes.create_string_buffer(STATE_BYTES)
        self.image.transition(request_packet(7, (b'0',), flags=1, token=TOKEN), state)
        for value in range(4097):
            result = self.image.transition(request_packet(8, (str(value).encode(),), token=TOKEN), state)
            self.assertEqual(result.status, 0)
        self.image.transition(request_packet(8, (b'18446744073709551614',), token=TOKEN), state)
        result = self.image.transition(request_packet(9, token=TOKEN), state)
        self.assertEqual(result.values, (MAX_U64, 1))
        self.assertEqual(result.fields, (b'18446744073709551615', b'1'))


if __name__ == '__main__':
    unittest.main()
