"""Actual child/Store resource controls for the four-method lease owner.

These controls use SQLite and the admitted Store/TX images. They never write
delivery flags, invent a loss record, normalize an exception, or retry SQL.
Opaque unregistered providers are explicitly outside these resource claims.
"""
from __future__ import annotations
import ctypes
import json
import os
from pathlib import Path
import struct

from tests.hia_service_lease_controls import PlainService, PlainLedger, LEASE_VALUE, raw_frame

RESOURCE_IDS = (
    'actual-child-confirmed-parent-ACK-lost',
    'actual-child-loss-swallowed',
    'actual-child-loss-replaced',
    'ordinary-provider-error-confirmed',
    'normal-final-ACK-resource-retired',
    'late-FINALIZE-ACK-lost',
    'actual-B-used-A-unassociated',
    'same-resource-loss-new-Context',
    'different-healthy-resource',
    'with-transaction-body-loss-no-COMMIT',
    'with-transaction-cleanup-known-error',
    'healthy-release-before-next-invocation',
)


def _capture(call):
    try:
        return {'kind': 'return', 'value': call()}, None
    except BaseException as error:
        return {'kind': 'raised', 'type': type(error).__name__, 'message': str(error)}, error


def run_resources(manifests, root, group):
    from hepta import hia_service_lease_native as lease_native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta.hia_native_delivery import NativeDeliveryUnknown
    from hepta import hia_native_delivery as delivery
    from hepta.hia_agent_store import AgentStore
    import contextvars
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    old_environment = dict(os.environ)
    os.environ['HEPTA_HIA_SERVICE_LEASE_MANIFEST'] = str(manifests['lease'])
    os.environ['HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST'] = str(manifests['store'])
    os.environ['HEPTA_HIA_STORE_TRANSACTION_MANIFEST'] = str(manifests['transaction'])
    image = lease_native.installed_service_lease(str(manifests['lease']))
    store_image = store_native.installed_store_artifact_profile(str(manifests['store']))
    owner_entry, child_entry = image._entry, store_image._entry
    rows, owned = [], []
    if group not in RESOURCE_IDS:
        raise ValueError('undeclared complete resource control')
    cases = (group,)
    try:
        for index, case in enumerate(cases):
            a, b = AgentStore(root / (str(index) + '-A')), AgentStore(root / (str(index) + '-B'))
            owned.extend((a, b))
            sql_a, sql_b = [], []
            a.db.set_trace_callback(sql_a.append)
            b.db.set_trace_callback(sql_b.append)
            child_calls, owner_calls, provider_calls = [], [], []
            swallowed, replacement = [], RuntimeError('replacement after actual child loss')
            requested = MemoryError('ordinary provider failure after confirmed child')
            class Ledger(PlainLedger):
                def lease(self, value):
                    provider_calls.append('lease')
                    try:
                        b.put(b'controlled resource bytes', 'program', {})
                    except store_native.StoreArtifactProfileUnknown as error:
                        swallowed.append(type(error).__name__)
                        if case == 'actual-child-loss-replaced':
                            raise replacement
                        if case != 'actual-child-loss-swallowed':
                            raise
                    if case == 'ordinary-provider-error-confirmed' or case == 'with-transaction-cleanup-known-error':
                        raise requested
                    return dict(value)
                def acquire(self, target, snapshot, native):
                    provider_calls.append('acquire')
                    return self.lease(LEASE_VALUE)
            service = PlainService()
            service.store = a
            service._slot_ledger = Ledger(service.events)
            def child_hook(source, size, output, capacity, state, extent):
                code = child_entry(source, size, output, capacity, state, extent)
                words = struct.unpack('<' + str(size // 8) + 'Q', ctypes.string_at(source, size))
                child_calls.append({'event': words[1], 'mode': words[5], 'code': code})
                if (case in ('actual-child-loss-swallowed', 'actual-child-loss-replaced',
                             'with-transaction-body-loss-no-COMMIT')
                        and words[1] == 2 and words[5] == 1
                        and any('INSERT' in statement.upper() for statement in sql_b)):
                    raise ValueError('controlled actual child ACK loss')
                return code
            def owner_hook(source, size, output, capacity, state, extent):
                code = owner_entry(source, size, output, capacity, state, extent)
                words = struct.unpack('<10Q', ctypes.string_at(source, size))
                owner_calls.append({'event': words[1], 'port': words[3], 'code': code})
                if (case in ('actual-child-confirmed-parent-ACK-lost', 'actual-B-used-A-unassociated',
                             'same-resource-loss-new-Context', 'different-healthy-resource')
                        and words[1] == lease_native.SUCCEEDED
                        and words[3] == lease_native.PORT['lease_ledger']):
                    raise ValueError('controlled parent ACK loss after confirmed child')
                if case == 'late-FINALIZE-ACK-lost' and words[1] == lease_native.FINALIZE:
                    raise ValueError('controlled actual FINALIZE ACK loss')
                return code
            store_image._entry, image._entry = child_hook, owner_hook
            mode = 1 if case.startswith('with-transaction') else 2
            frame = raw_frame(image, mode, service)
            outcome, error = _capture(frame.finish)
            store_image._entry, image._entry = child_hook, owner_entry
            rows.append({'case': case, 'outcome': outcome, 'child_entries': list(child_calls),
                         'owner_entries': list(owner_calls), 'provider_calls': list(provider_calls),
                         'sql_A': list(sql_a), 'sql_B': list(sql_b), 'validated': False})

            inserts = [statement for statement in sql_b if 'INSERT' in statement.upper()]
            if not inserts or not child_calls or not provider_calls:
                raise AssertionError('resource control did not reach actual Store/native/SQLite effects')
            expected_loss = case not in ('ordinary-provider-error-confirmed', 'normal-final-ACK-resource-retired',
                'with-transaction-cleanup-known-error', 'healthy-release-before-next-invocation')
            if expected_loss:
                if case == 'actual-child-loss-replaced':
                    if error is not replacement:
                        raise AssertionError('recorded loss normalized the replacement RuntimeError')
                elif case == 'with-transaction-body-loss-no-COMMIT':
                    if not isinstance(error, store_native.StoreArtifactProfileUnknown):
                        raise AssertionError(('original child unknown object was replaced', outcome))
                elif error is None or not isinstance(error, (lease_native.ServiceLeaseUnknown, NativeDeliveryUnknown)):
                    raise AssertionError(('actual unknown outcome was not classified', outcome))
                rows[-1]['parent_record_lost'] = frame._delivery.loss is not None
                rows[-1]['replacement_identity_preserved'] = error is replacement
                if frame._delivery.loss is None or not frame.native_failed:
                    raise AssertionError('real native loss was not retained by the parent')
                close_b, close_error = _capture(b.close)
                if not isinstance(close_error, NativeDeliveryUnknown):
                    raise AssertionError(('actual resource retirement was not fenced', close_b))
                if case in ('actual-child-loss-swallowed', 'actual-child-loss-replaced'):
                    if swallowed != ['StoreArtifactProfileUnknown']:
                        raise AssertionError('provider did not catch the actual child classification')
                if case == 'actual-B-used-A-unassociated':
                    a.close(); owned.remove(a)
                if case == 'same-resource-loss-new-Context':
                    before_entries, before_sql = len(child_calls), tuple(sql_b)
                    retry, retry_error = _capture(lambda: contextvars.Context().run(
                        b.put, b'not a retry', 'program', {}))
                    if (not isinstance(retry_error, (NativeDeliveryUnknown, store_native.StoreArtifactProfileUnknown))
                            or len(child_calls) != before_entries or tuple(sql_b) != before_sql):
                        raise AssertionError('same unknown resource entered a fresh Context SQL/native path')
                if case == 'different-healthy-resource':
                    c = AgentStore(root / 'healthy-C')
                    try:
                        contextvars.Context().run(c.put, b'healthy', 'program', {})
                    finally:
                        c.close()
                if case == 'with-transaction-body-loss-no-COMMIT':
                    if not any('BEGIN' in statement.upper() for statement in sql_a):
                        raise AssertionError('original transaction was not entered')
                    if any('COMMIT' in statement.upper() for statement in sql_a):
                        raise AssertionError('unknown body outcome committed')
            else:
                if case in ('ordinary-provider-error-confirmed', 'with-transaction-cleanup-known-error'):
                    if error is not requested:
                        raise AssertionError(('confirmed ordinary error changed identity', outcome))
                elif error is not None or not frame.finished:
                    raise AssertionError(('healthy completion failed', outcome))
                if frame._delivery.loss is not None:
                    raise AssertionError('ordinary confirmed outcome was incorrectly marked lost')
                if case == 'with-transaction-cleanup-known-error':
                    if not any('ROLLBACK' in statement.upper() for statement in sql_a):
                        raise AssertionError('original known-error transaction cleanup did not run')
                    if any('COMMIT' in statement.upper() for statement in sql_a):
                        raise AssertionError('ordinary error committed')
                if case == 'healthy-release-before-next-invocation':
                    second = raw_frame(image, 2, service)
                    if second.finish() != LEASE_VALUE:
                        raise AssertionError('healthy prior ACK poisoned a fresh invocation')
                if delivery._RESOURCE_OBSERVATIONS:
                    raise AssertionError('healthy final ACK retained resource observations')
                b.close(); owned.remove(b)
            rows[-1]['validated'] = True
        return rows
    finally:
        (root.parent / 'raw-control.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')
        store_image._entry, image._entry = child_entry, owner_entry
        for store in owned:
            try:
                store.close()
            except NativeDeliveryUnknown:
                # This process remains the explicit custodian until its owned
                # exit; no private close bypass or replay releases an unknown DB.
                pass
        os.environ.clear(); os.environ.update(old_environment)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-list', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--case', choices=RESOURCE_IDS, required=True)
    args = parser.parse_args()
    value = json.loads(args.manifest_list.read_bytes())
    rows = run_resources(value, args.root / 'state', args.case)
    args.root.mkdir(parents=True, exist_ok=True)
    (args.root / 'report.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
