"""Actual HIA effect claims, CPython sort observations and lifetime controls.

The retained writer is independent. Explicit fixture mode is inherited from the
original ELF module; no cold report is inferred from a development image.
"""
from __future__ import annotations
from hashlib import sha256
import ctypes
import gc
import json
import random
import struct
import sys
import unittest
from unittest.mock import patch
from hepta import hia_machine_elf_native as bridge
from tests.test_hia_machine_elf_native import (
    ROOT, _Fixture, _ORACLE, _outcome, _encoded, _write_json, pending_lookup)

def run_foreign(values, writer, *, flip=False, stop=None, truth_error=False, ambient=False):
    events = []
    counter = [0]
    rows = []

    class ForeignComparisonError(Exception):
        pass

    class Truth:

        def __bool__(self):
            return 1

        def __del__(self):
            events.append(('release_truth', None if sys.exception() is None else type(sys.exception()).__name__))

    class Number(int):

        def __eq__(self, other):
            events.append(('eq', int(self), int(other)))
            return int(self) == int(other)

        def __lt__(self, other):
            events.append(('lt', int(self), int(other)))
            counter[0] += 1
            if stop == counter[0]:
                raise ForeignComparisonError('comparison stopped', stop)
            if truth_error:
                return Truth()
            return bool(int(self) < int(other)) ^ bool(flip and counter[0] % 7 == 0)

        def __gt__(self, other):
            events.append(('gt', int(self), int(other)))
            return int(self) > int(other)

    class Offset:

        def __init__(self, row, n):
            self.row = row
            self.n = n
            self.count = 0

        def __hash__(self):
            return hash('offset')

        def __eq__(self, other):
            if type(other) is str and other == 'offset':
                self.count += 1
                if self.count >= 3:
                    self.row[self] = Number(self.n)
                return True
            return False
    for i, n in enumerate(values):
        row = {'name': 'function_' + str(i), 'size': 1, 'global': True}
        row[Offset(row, n)] = n
        rows.append(row)

    def call():
        try:
            raw = writer(b'\xc3' * max(1, max(values, default=0) + 1), rows, [])
            result = ('bytes', len(raw), sha256(raw).hexdigest())
        except BaseException as error:
            result = ('exception', type(error).__qualname__, error.args)
        return result
    if ambient:
        try:
            raise LookupError('ambient')
        except LookupError:
            result = call()
            at_return = list(events)
    else:
        result = call()
        at_return = list(events)
    gc.collect()
    return {'result': result, 'events': at_return, 'events_after_gc': list(events)}


class MachineElfProtocolTests(_Fixture, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.records = {}

    @classmethod
    def tearDownClass(cls):
        _write_json(cls.folder / 'protocol-observations.json', cls.records)

    def test_partial_constructor_closes_first_actual_mapping(self):
        original, opened = bridge._private_buffer, []
        marker = MemoryError('second buffer allocation')
        def partial(size):
            if opened:
                raise marker
            pair = original(size)
            opened.append(pair[0])
            return pair
        with patch.object(bridge, '_private_buffer', partial):
            with self.assertRaises(MemoryError) as caught:
                bridge.ElfSession(self.native, b'\xc3', [], [], 16)
        self.assertIs(caught.exception, marker)
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].closed)
        self.records['partial_mapping'] = {'same_exception': True, 'first_mapping_closed': True}

    def test_explicit_close_retires_only_still_open_actual_mappings(self):
        rows = []
        for after_effect in (False, True):
            session = bridge.ElfSession(self.native, b'\xc3', [], [], 16)
            work, output = session.work_map, session.out_map
            class CloseProbe:
                def __init__(self):
                    self.calls, self.fail = 0, True
                @property
                def closed(self):
                    return work.closed
                def close(self):
                    self.calls += 1
                    if self.fail:
                        if after_effect:
                            work.close()
                        raise BufferError('known mapping close interruption')
                    work.close()
            probe = CloseProbe()
            session.work_map = probe
            try:
                with self.assertRaises(BufferError):
                    session.close()
                self.assertTrue(output.closed)
                self.assertEqual(work.closed, after_effect)
                self.assertEqual(len(session._cleanup_failures), 1)
                probe.fail = False
                session.close()
                self.assertTrue(work.closed and output.closed)
                self.assertEqual(probe.calls, 1 if after_effect else 2)
                self.assertEqual(session._cleanup_failures, ())
                rows.append({'after_effect': after_effect, 'close_calls': probe.calls,
                             'both_closed': True})
            finally:
                session.close()
        self.records['explicit_mapping_close'] = rows

    def test_foreign_error_outcome_is_native_terminal_before_delivery(self):
        session, ledger, control = pending_lookup(self.native)
        marker = StopIteration('actual callback outcome')
        control['exception'] = marker
        entry, results = self.native._entry, []
        def observe(*args):
            result = entry(*args)
            results.append(result)
            return result
        try:
            with patch.object(self.native, '_entry', observe):
                with self.assertRaises(StopIteration) as caught:
                    session.observe()
            self.assertIs(caught.exception, marker)
            self.assertEqual(results, [5, 6])
            self.assertEqual(session.word(bridge.PENDING), 0)
            self.assertEqual(session.word(bridge.DEAD), 1)
            after = list(ledger)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, after)
            self.records['native_error_outcome'] = {'results': results, 'pending': 0, 'dead': 1}
        finally:
            session.close()

    def test_unknown_error_outcome_retains_original_without_retry(self):
        rows = []
        for after_entry in (False, True):
            session, ledger, control = pending_lookup(self.native)
            marker = ValueError('foreign error retained')
            interrupted = KeyboardInterrupt('error ACK handoff')
            control['exception'] = marker
            actual, results = self.native._entry, []
            def lose(*args):
                if args[1] == 0:
                    if after_entry:
                        results.append(actual(*args))
                    raise interrupted
                result = actual(*args)
                results.append(result)
                return result
            try:
                with patch.object(self.native, '_entry', lose):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        session.observe()
                self.assertIs(caught.exception, interrupted)
                self.assertIs(session._unconfirmed_error, marker)
                self.assertEqual(results, [5, 6] if after_entry else [5])
                self.assertEqual(session.word(bridge.PENDING), 0 if after_entry else 2)
                self.assertEqual(session.word(bridge.DEAD), int(after_entry))
                before = list(ledger)
                with self.assertRaises(RuntimeError):
                    session.observe()
                with self.assertRaises(RuntimeError):
                    session.step()
                self.assertEqual(ledger, before)
                session.close(release=False)
                self.assertIs(session._unconfirmed_error, marker)
                rows.append({'after_entry': after_entry, 'results': results, 'retained_same_error': True})
            finally:
                session.close()
        self.records['unknown_error_outcome'] = rows

    def test_transport_packing_failure_cannot_acknowledge_callback_error(self):
        session, ledger, _ = pending_lookup(self.native)
        marker = KeyboardInterrupt('after callback before packed outcome')
        actual, results = self.native._entry, []
        def entry(*args):
            result = actual(*args)
            results.append(result)
            return result
        try:
            before = list(ledger)
            with patch.object(self.native, '_entry', entry), patch.object(session, 'answer', side_effect=marker):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    session.observe()
            self.assertIs(caught.exception, marker)
            self.assertNotEqual(ledger, before)
            self.assertEqual(results, [5])
            self.assertEqual(session.word(bridge.PENDING), 2)
            self.assertEqual(session.word(bridge.FOREIGN_ERROR), 0)
            self.assertIsNone(session._unconfirmed_error)
            after = list(ledger)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, after)
            self.records['packing_unknown'] = {'results': results, 'pending': 2, 'foreign_error': 0}
        finally:
            session.close()

    def test_changed_issued_field_cannot_authorize_another_lookup(self):
        session, ledger, _ = pending_lookup(self.native)
        try:
            original = struct.unpack_from('<5Q', session.work, bridge.REQUEST)
            before = list(ledger)
            session.put(bridge.REQUEST + 16, 2)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, before)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, before)
            self.records['changed_request'] = {'original': original, 'new_effects': 0}
        finally:
            session.close()

    def test_consumed_temporary_set_releases_before_next_field_lookup(self):
        def run(writer):
            events, row = [], {}
            class Key:
                def __hash__(self):
                    return hash('name')
                def __eq__(self, other):
                    if type(other) is str and other == 'name':
                        events.append('equality-clears-row')
                        row.clear()
                        return True
                    return False
                def __del__(self):
                    events.append('temporary-release-restores-row')
                    row.update(name='entry', offset=0, size=1, **{'global': True})
            row[Key()] = 'entry'
            row.update(offset=0, size=1, **{'global': True})
            result = writer(b'\xc3', [row], [])
            return result, events, row
        original, actual = run(_ORACLE), run(self.native.write)
        self.assertEqual(actual, original)
        self.assertEqual(actual[1], ['equality-clears-row', 'temporary-release-restores-row'])
        self.records['temporary_set'] = {'output_sha256': sha256(actual[0]).hexdigest(), 'events': actual[1]}

    def test_direct_comparison_truth_release_precedes_caller_catch(self):
        def run(writer, ambient):
            events, relocations, observed = [], [], {}
            class Truth:
                def __bool__(self):
                    return 1
                def __del__(self):
                    events.append(('released', None if sys.exception() is None else type(sys.exception()).__name__))
            class Number(int):
                def __lt__(self, other):
                    events.append(('lt', int(self), int(other)))
                    return Truth()
            class Key:
                def __init__(self, row, number):
                    self.row, self.number, self.calls = row, number, 0
                def __hash__(self):
                    return hash('offset')
                def __eq__(self, other):
                    if type(other) is str and other == 'offset':
                        self.calls += 1
                        if self.calls >= 3:
                            self.row[self] = Number(self.number)
                        return True
                    return False
            for number in (6, 1):
                row = {'symbol': 'puts', 'type': 4, 'addend': -4}
                row[Key(row, number)] = number
                relocations.append(row)
            code = b'\xe8\0\0\0\0\xe8\0\0\0\0\xc3'
            def call():
                try:
                    writer(code, [{'name': 'entry', 'offset': 0, 'size': len(code), 'global': True}], relocations)
                except BaseException as error:
                    observed['result'] = (type(error).__qualname__, error.args)
                    observed['at_catch'] = list(events)
            if ambient:
                try:
                    raise LookupError('ambient')
                except LookupError:
                    call()
                    observed['after_call'] = list(events)
            else:
                call()
                observed['after_call'] = list(events)
            gc.collect()
            observed['after_gc'] = list(events)
            return observed
        results = []
        for ambient in (False, True):
            original, actual = run(_ORACLE, ambient), run(self.native.write, ambient)
            self.assertEqual(actual, original)
            self.assertEqual(actual['at_catch'][-1], ('released', 'LookupError' if ambient else None))
            results.append({'ambient': ambient, 'original': original, 'native': actual})
        self.records['direct_comparison_lifetime'] = results


    def test_original_55(self):
        cases = json.loads((ROOT / 'tests/hia_machine_elf_cases.json').read_bytes())['cases']
        rows = []
        for row in cases:
            expected = _outcome(_ORACLE, row['arguments'])
            actual = _outcome(self.native.write, row['arguments'])
            rows.append({'id': row['id'], 'original': _encoded(expected), 'native': _encoded(actual), 'equal': expected == actual})
            with self.subTest(case=row['id']):
                self.assertEqual(expected, actual)
        self.records['original55'] = rows
        self.assertEqual(len(rows), 55)

    def test_complete_foreign_comparison_sequences(self):
        rng = random.Random(8263941)
        vectors = []
        for n in (1, 2, 3, 7, 31, 32, 33, 63, 64, 65, 97, 127, 128, 129, 257, 513):
            values = list(range(n))
            rng.shuffle(values)
            vectors.append(('random-' + str(n), values))
        vectors += [('reverse-129', list(range(128, -1, -1))), ('ascending-129', list(range(129))), ('equal-runs', [i // 3 for i in range(129)]), ('reversed-equal-runs', [i // 3 for i in range(128, -1, -1)]), ('gallop-long-runs', list(range(64, 192)) + list(range(64)) + list(range(192, 256))), ('gallop-interleaved-runs', list(range(0, 256, 2)) + list(range(1, 256, 2)))]
        rows = []
        for name, values in vectors:
            original = run_foreign(values, _ORACLE)
            actual = run_foreign(values, self.native.write)
            rows.append({'name': name, 'values': values, 'original': original, 'native': actual, 'equal': original == actual})
            with self.subTest(case=name):
                self.assertEqual(original, actual)
        self.records['sort_vectors'] = rows

    def test_inconsistent_and_raising_comparisons(self):
        rng = random.Random(872)
        values = list(range(129))
        rng.shuffle(values)
        rows = []
        for name, options in [('inconsistent', {'flip': True}), ('first-error', {'stop': 1}), ('insertion-error', {'stop': 12}), ('merge-error', {'stop': 500})]:
            original = run_foreign(values, _ORACLE, **options)
            actual = run_foreign(values, self.native.write, **options)
            rows.append({'name': name, 'original': original, 'native': actual, 'equal': original == actual})
            with self.subTest(case=name):
                self.assertEqual(original, actual)
        self.records['sort_exceptions'] = rows

    def test_business_payload_and_exception_emitter_domains_do_not_collide(self):
        from hepta.hia_exception_delivery import ExceptionDelivery, EMIT_REQUEST, CODE_BYTES, CODE_SHA256
        entries = []
        for n in (1, 8, 63, 64, 65, 128):
            for prefix in (b'\xc3', b'HIACTP01', EMIT_REQUEST):
                code = (prefix + b'\x90' * n)[:n]
                rows = [{'name': 'entry', 'offset': 0, 'size': len(code), 'global': True}]
                expected = _ORACLE(code, rows, [])
                actual = self.native.write(code, rows, [])
                self.assertEqual(actual, expected)
                entries.append({'bytes': n, 'prefix': prefix.hex(), 'sha256': sha256(actual).hexdigest()})
        delivery = ExceptionDelivery.from_hia(self.native)
        try:
            marker = ValueError('actual emitted mechanism')
            with self.assertRaises(ValueError) as caught:
                delivery.deliver(marker)
            self.assertIs(caught.exception, marker)
        finally:
            delivery.close()
        self.records['disjoint_payload_domains'] = {'cases': entries, 'emitter_bytes': CODE_BYTES, 'emitter_sha256': CODE_SHA256}

    def test_lost_preclaim_return_permanently_revokes(self):
        session, ledger, _ = pending_lookup(self.native)
        old = list(ledger)
        actual = self.native._entry
        codes = []

        class Interrupted(BaseException):
            pass
        marker = Interrupted('after native claim')

        def lose(*args):
            codes.append(actual(*args))
            raise marker
        try:
            with patch.object(self.native, '_entry', lose):
                with self.assertRaises(Interrupted) as caught:
                    session.observe()
            self.assertIs(caught.exception, marker)
            self.assertEqual(codes, [5])
            self.assertEqual(session.word(bridge.PENDING), 2)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, old)
            self.assertIsNone(session._issued)
            self.records['lost_preclaim'] = {'codes': codes, 'pending': session.word(bridge.PENDING), 'new_effects': len(ledger) - len(old)}
        finally:
            session.close()

    def test_foreign_claim_nonce_and_repeat_are_native_refusals(self):
        a, ledger, _ = pending_lookup(self.native)
        b, _, _ = pending_lookup(self.native)
        try:
            self.assertNotEqual(a.nonce, b.nonce)
            wire = bytearray(a._issued)
            struct.pack_into('<Q', wire, 8, b.nonce)
            source = ctypes.create_string_buffer(bytes(wire), len(wire))
            before = list(ledger)
            code = self.native._entry(source, len(wire), a.output, len(a.output), a.work, len(a.work))
            self.assertEqual(code, bridge.ABI)
            self.assertEqual(a.word(bridge.DEAD), 1)
            with self.assertRaises(RuntimeError):
                a.observe()
            self.assertEqual(ledger, before)
            b.observe()
            with self.assertRaises(RuntimeError):
                b.observe()
            self.records['nonce'] = {'different': True, 'code': code, 'a_dead': a.word(bridge.DEAD)}
        finally:
            a.close()
            b.close()

    def test_full_vm_and_native_protocol_buffers(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program((ROOT / 'examples/hia_bootstrap/machine_elf.hepta').read_bytes())
        state = bytes(4096)
        output = b'\xa7' * 96
        rows = []

        def compare(wire, old_w, old_o):
            s = ctypes.create_string_buffer(wire, max(1, len(wire)))
            w = ctypes.create_string_buffer(old_w, len(old_w))
            o = ctypes.create_string_buffer(old_o, len(old_o))
            code = self.native._entry(s, len(wire), o, len(old_o), w, len(old_w))
            roots = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(old_o)), _Owner(-3, bytearray(old_w))]
            machine = _Machine(checked, 2000000, 0, None, 256)
            actual = machine.invoke(machine.functions['f0'], [_View(r, i != 0) for i, r in enumerate(roots)])
            self.assertEqual(actual, [code])
            self.assertEqual(bytes(roots[0].data), wire)
            self.assertEqual(bytes(roots[1].data), o.raw)
            self.assertEqual(bytes(roots[2].data), w.raw)
            rows.append({'wire_hex': wire.hex(), 'status': code, 'workspace_sha256': sha256(w.raw).hexdigest(), 'output_sha256': sha256(o.raw).hexdigest(), 'vm_steps': machine.steps})
            return (code, w.raw, o.raw)
        code, state, output = compare(struct.pack('<3Q', bridge.INIT_MAGIC, 9331, 312), state, output)
        self.assertEqual(code, 1)
        request = struct.unpack_from('<5Q', state, bridge.REQUEST)
        sequence = struct.unpack_from('<Q', state, bridge.SEQUENCE)[0]
        claim = struct.pack('<9Q', bridge.CLAIM_MAGIC, 9331, sequence, *request, 0)
        compare(struct.pack('<9Q', bridge.CLAIM_MAGIC, 9332, sequence, *request, 0), state, output)
        code, claimed, out = compare(claim, state, output)
        self.assertEqual(code, 5)
        compare(claim, claimed, out)
        acknowledged = bytearray(claimed)
        struct.pack_into('<Q', acknowledged, bridge.ACK, sequence)
        struct.pack_into('<7Q', acknowledged, bridge.FACT, 1, 16, 0, 0, 1, 0, 0)
        code, _, _ = compare(b'', bytes(acknowledged), out)
        self.assertEqual(code, 1)
        exhausted = bytearray(claimed)
        struct.pack_into('<Q', exhausted, bridge.SEQUENCE, bridge.WORD_MASK)
        struct.pack_into('<Q', exhausted, bridge.ACK, bridge.WORD_MASK)
        struct.pack_into('<Q', exhausted, bridge.PENDING, 0)
        struct.pack_into('<Q', exhausted, bridge.PHASE, 1)
        code, _, _ = compare(b'', bytes(exhausted), out)
        self.assertEqual(code, bridge.ABI)
        self.records['vm_protocol'] = rows

    def test_comparison_result_release_with_original_ambient_exception(self):
        rows = []
        for ambient in (False, True):
            original = run_foreign([2, 0, 1], _ORACLE, truth_error=True, ambient=ambient)
            actual = run_foreign([2, 0, 1], self.native.write, truth_error=True, ambient=ambient)
            rows.append({'ambient': ambient, 'original': original, 'native': actual, 'equal': original == actual})
            with self.subTest(ambient=ambient):
                self.assertEqual(original, actual)
        self.records['comparison_truth_release'] = rows
