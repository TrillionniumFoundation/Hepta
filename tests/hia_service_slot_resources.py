"""Actual Store A / receipt Store B, selected Slot SQL, and handler ACK controls.

Every case is a fresh process. Unknown resources stay retained until process exit;
there is no test-side loss assignment, forced retirement, retry, or fake SQL.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
import json
import os
from pathlib import Path
import struct
import sys
import types
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from tests.hia_service_slot_controls import encoded, put, digest

CASES = tuple(mode + '.' + kind for mode in ('rollback', 'adopt') for kind in (
    'result-ack-loss', 'release-ack-loss', 'finalize-ack-loss',
    'first-preparation-refusal', 'late-preparation-refusal',
    'confirmed-provider-error', 'same-frame-reentry', 'child-sql-ack-loss',
    'finalize-preparation-refusal', 'confirmed-retirement-error'))

def rows(store):
    return {name: [dict(row) for row in store.db.execute(sql)] for name, sql in (
        ('slots', 'SELECT * FROM slots ORDER BY name'),
        ('versions', 'SELECT * FROM versions ORDER BY slot,generation'),
        ('artifacts', 'SELECT * FROM artifacts ORDER BY id'))}

def chain_has(error, target):
    visited = set(); pending = [error]
    while pending:
        value = pending.pop()
        if value is target: return True
        if value is None or id(value) in visited: continue
        visited.add(id(value)); pending.extend((value.__cause__, value.__context__))
    return False

def run(name, manifests, bundle_path, pin, output):
    from hepta import hia_agent_service as api
    from hepta import hia_agent_store as store_api
    from hepta import hia_service_slot_native as native
    from hepta import hia_slot_operations_native as slot_native
    from hepta import hia_native_delivery as delivery
    from hepta.hia_native_helpers import native_helpers_scope
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.build_hia_json_preflight import current_sources
    if name not in CASES: raise ValueError('unknown fixed resource control')
    output = Path(output); output.mkdir(mode=0o700, parents=True, exist_ok=False)
    mode, kind = name.split('.', 1)
    before_sources = current_sources()
    manifest_pins = {k: digest(v) for k, v in manifests.items()}
    case = AgentToolCase('runTest')
    original_close = store_api._NATIVE_STORE_CLOSE_REFERENCE
    close_calls, sql, entries, child_entries, reentries = [], [], [], [], []
    fault = MemoryError('declared preparation refusal') if ('preparation' in kind or 'retirement' in kind) else ValueError('declared actual acknowledgement loss')
    original_error = ValueError('ordinary confirmed provider outcome')
    result = caught = None
    a = b = frame = None
    fired = False
    ledger_completed = False
    receipt_completed = False
    first_sql_seen = False

    def close_observer(store):
        close_calls.append('A' if store is a else 'B' if store is b else 'other')
        return original_close(store)

    with native_helpers_scope(str(bundle_path), pin):
        case.setUp()
        a = case.service.store
        b = store_api.AgentStore(case.root / 'receipt-store-B')
        base, revised, baseline, built, receipts = case.build_pair()
        evaluation = case.session.evaluate(baseline, built, receipts=receipts)
        adopt = case.session.arguments(target_slot='resource-slot',
            expected_current={'generation': '0', 'epoch': '0'},
            candidate_artifact=built['native_artifact'],
            evaluation_receipt=evaluation['evaluation_receipt'], verification_receipts=receipts)
        if mode == 'rollback':
            adopted = case.client.result('hia_adopt', adopt)
            arguments = case.session.arguments(target_slot='resource-slot',
                expected_current=adopted['current'],
                retained_generation=adopted['previous']['generation'], reason='actual resource control')
        else:
            arguments = adopt
        service = case.service
        actual_ledger = service._slot_ledger
        if actual_ledger is None:
            raise AssertionError('same-attempt real Slot ledger was not selected')

        class LedgerSwitch:
            def __getattr__(self, key): return getattr(actual_ledger, key)
            def adopt(self, *args, **kwargs):
                value = actual_ledger.adopt(*args, **kwargs)
                return self.done(value)
            def rollback(self, *args, **kwargs):
                value = actual_ledger.rollback(*args, **kwargs)
                return self.done(value)
            def done(self, value):
                nonlocal ledger_completed
                ledger_completed = True
                if kind == 'same-frame-reentry':
                    active = delivery.current_record()
                    assert active is frame._delivery
                    try: frame.finish()
                    except native.ServiceSlotUnknown as error:
                        reentries.append({'class': type(error).__name__,
                            'active_record_not_retired': not active.retired,
                            'current': active.current(), 'loss_absent': active.loss is None})
                    else: raise AssertionError('same Frame recursively entered')
                    assert reentries[-1] == {'class': 'ServiceSlotUnknown',
                        'active_record_not_retired': True, 'current': True, 'loss_absent': True}
                service.store = b
                return value

        service._slot_ledger = LedgerSwitch()
        before_a, before_b = rows(a), rows(b)
        def trace_a(statement):
            nonlocal first_sql_seen
            sql.append({'store': 'A', 'statement': statement})
            first_sql_seen = True
        def trace_b(statement): sql.append({'store': 'B', 'statement': statement})
        a.db.set_trace_callback(trace_a); b.db.set_trace_callback(trace_b)
        image = native.installed_service_slot(str(manifests['service']))
        child = slot_native.installed_slot_operations(str(manifests['operations']))
        actual_entry, actual_child_entry = image._entry, child._entry
        allocate = native.ctypes.create_string_buffer
        b_json = b.json
        retire = delivery._WeakResourceObservation.retire

        def receipt(*args, **kwargs):
            nonlocal receipt_completed
            value = b_json(*args, **kwargs)
            receipt_completed = True
            if kind == 'confirmed-provider-error': raise original_error
            return value

        def native_entry(source, size, out, capacity, state, extent):
            nonlocal fired
            request = struct.unpack('<10Q', ctypes.string_at(source, size))
            code = actual_entry(source, size, out, capacity, state, extent)
            entries.append({'event': request[1], 'port': request[3], 'code': code,
                            'ledger_completed': ledger_completed,
                            'receipt_completed': receipt_completed})
            target = {'result-ack-loss': mode + '_result', 'release-ack-loss': mode + '_release_locals'}.get(kind)
            trigger = (target is not None and request[1] == native.SUCCEEDED
                       and request[3] == native.PORT[target])
            trigger = trigger or (kind == 'finalize-ack-loss' and request[1] == native.FINALIZE)
            if trigger and not fired:
                assert ledger_completed and receipt_completed
                fired = True
                raise fault
            return code

        def slot_entry(source, size, out, capacity, state, extent):
            nonlocal fired
            request = struct.unpack_from('<6Q', ctypes.string_at(source, size))
            code = actual_child_entry(source, size, out, capacity, state, extent)
            child_entries.append({'event': request[1], 'port': request[3], 'mode': request[5],
                                  'code': code, 'actual_sql_seen': first_sql_seen})
            if kind == 'child-sql-ack-loss' and first_sql_seen and request[1] == slot_native.SUCCEEDED and not fired:
                fired = True
                raise fault
            return code

        def allocate_observed(*args, **kwargs):
            nonlocal fired
            if not fired and ((kind == 'first-preparation-refusal' and frame is not None)
                    or (kind == 'late-preparation-refusal' and receipt_completed)
                    or (kind == 'finalize-preparation-refusal' and frame is not None
                        and frame.receipt.phase in (native.READY_RETURN, native.READY_PROPAGATE)
                        and frame._whole is not None and not frame._whole.active)):
                fired = True
                raise fault
            return allocate(*args, **kwargs)

        def retire_observed(observation):
            nonlocal fired
            if (kind == 'confirmed-retirement-error' and not fired and frame is not None
                    and frame._whole is not None and frame._whole.pending_resources.completed):
                fired = True
                raise fault
            return retire(observation)

        def forbidden(*args, **kwargs):
            raise AssertionError('selected service Slot entered a retained method')

        old_rollback, old_adopt = api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE
        store_api._NATIVE_STORE_CLOSE_REFERENCE = close_observer
        api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE = api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = forbidden
        b.json = receipt
        delivery._WeakResourceObservation.retire = retire_observed
        image._entry, child._entry = native_entry, slot_entry
        try:
            frame = native.ServiceSlotFrame(image, native.ROLLBACK if mode == 'rollback' else native.ADOPT,
                                            service, arguments)
            native.ctypes.create_string_buffer = allocate_observed
            try: result = frame.finish()
            except BaseException as error: caught = error
        finally:
            native.ctypes.create_string_buffer = allocate
            image._entry, child._entry = actual_entry, actual_child_entry
            api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = old_rollback, old_adopt
            b.json = b_json
            delivery._WeakResourceObservation.retire = retire
            a.db.set_trace_callback(None); b.db.set_trace_callback(None)

        unknown = kind not in ('first-preparation-refusal', 'confirmed-provider-error', 'same-frame-reentry', 'confirmed-retirement-error')
        if kind == 'same-frame-reentry':
            assert result is not None and caught is None and len(reentries) == 1
            assert frame.finished and frame._delivery.terminal
        elif kind == 'confirmed-provider-error':
            assert caught is original_error and result is None
            assert frame.receipt.phase == native.PROPAGATE and frame._delivery.terminal
            assert any(e['event'] == native.RAISED for e in entries)
            assert any(e['event'] == native.FINALIZE for e in entries)
        else:
            assert fired and caught is not None and chain_has(caught, fault)
        if kind == 'confirmed-retirement-error':
            assert caught is fault and frame._delivery.loss is None
            assert sum(e['event'] == native.FINALIZE for e in entries) == 1
            assert frame._whole.pending_resources.completed
            assert not delivery._RESOURCE_OBSERVATIONS
        if kind == 'first-preparation-refusal':
            assert caught is fault and sql == [] and not ledger_completed and not receipt_completed
            assert frame._delivery.loss is None
            assert not any(e['event'] in (native.RAISED, native.FINALIZE) for e in entries)
        after_a, after_b = rows(a), rows(b)
        if kind in ('result-ack-loss', 'release-ack-loss', 'finalize-ack-loss', 'late-preparation-refusal',
                    'finalize-preparation-refusal', 'confirmed-retirement-error'):
            assert ledger_completed and receipt_completed
            assert after_a['slots'] != before_a['slots']
            assert len(after_b['artifacts']) == len(before_b['artifacts']) + 1
        if kind != 'first-preparation-refusal':
            assert child_entries, 'actual Slot control image was not entered'
        if ledger_completed:
            assert any(e['mode'] == (11 if mode == 'rollback' else 10) for e in child_entries)
        if kind == 'child-sql-ack-loss':
            assert child_entries[-1]['actual_sql_seen'] and not ledger_completed and not receipt_completed
            assert not any(e['event'] == native.RAISED for e in entries)
        retained_before_close = delivery.custody_snapshot()
        close_refusals = {}
        for label, resource in (('A', a), ('B', b)):
            expect_refusal = unknown and (label == 'A' or receipt_completed)
            try: resource.close()
            except delivery.NativeDeliveryUnknown as error:
                assert expect_refusal, (label, kind)
                close_refusals[label] = type(error).__name__
                assert label not in close_calls
            else:
                assert not expect_refusal, (label, kind)
                assert close_calls.count(label) == 1
        if unknown:
            assert frame._delivery.loss is not None and not frame._delivery.retired
            assert any(item['lost'] for item in retained_before_close)
            assert len(delivery._RESOURCE_OBSERVATIONS) > 0
        else:
            assert not delivery.custody_snapshot()
        after_sources = current_sources()
        assert after_sources == before_sources
        assert manifest_pins == {k: digest(v) for k, v in manifests.items()}
        report = {'schema': 'hepta.hia.service-slot-resource-control.v1', 'status': 'PASS',
            'case': name, 'mode': mode, 'runtime': sys.version,
            'actual_same_attempt_manifests': {k: str(v) for k, v in manifests.items()},
            'manifest_pins': manifest_pins, 'bundle_sha256': pin,
            'source_before': before_sources, 'source_after': after_sources,
            'before_A': before_a, 'after_A': after_a, 'before_B': before_b, 'after_B': after_b,
            'SQL': sql, 'handler_entries': entries, 'child_entries': child_entries,
            'ledger_completed': ledger_completed, 'receipt_completed': receipt_completed,
            'original_error_identity': caught is original_error,
            'fault_identity_in_chain': caught is not None and chain_has(caught, fault),
            'same_frame_reentry': reentries, 'custody_before_close': retained_before_close,
            'close_body_calls': close_calls, 'close_refusals': close_refusals,
            'unknown_custody_intentionally_retained': unknown,
            'per_port_ACK_implies_whole_method_ACK': False,
            'loss_fields_or_parent_check_modified': False,
            'direct_handler_without_outer_transaction': True}
        put(output / 'report.json', report)
        store_api._NATIVE_STORE_CLOSE_REFERENCE = original_close
        # Unknown cases deliberately do not call tearDown or clear custody.
        # The supervisor reaps this fresh process; no cleanup success is claimed.
        if not unknown:
            case.service.store = a
            case.temporary.cleanup()
        return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--authority', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    authority = json.loads(args.authority.read_bytes())
    result = run(args.case, {k: Path(v) for k, v in authority['manifests'].items()},
                 Path(authority['bundle']), authority['bundle_sha256'], args.output)
    print(encoded({'status': result['status'], 'case': args.case}).decode(), end='')

if __name__ == '__main__': main()
