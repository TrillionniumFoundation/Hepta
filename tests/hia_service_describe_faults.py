"""Fresh-process foreign-effect, ABI and explicit-resource controls for describe.

The effects here are labelled test providers. Complete original-handler
equivalence belongs to the separate finite oracle. No custody registry is
cleared to turn an unknown delivery into a healthy observation.
"""
from __future__ import annotations

import argparse
import builtins
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta import hia_native_delivery as delivery
from hepta import hia_service_describe_native as native
from hepta.hia_service_describe_protocol import REFUSED


BOOL_PORTS = frozenset({'has_cursor', 'has_backend_profile', 'backend_differs'})
EXPECTED_PORTS = (
    'import_catalog', 'has_cursor', 'reject_cursor', 'has_backend_profile',
    'backend_differs', 'reject_profile', 'language_schema', 'language',
    'profile_pair', 'section', 'resources', 'result', 'release_locals',
)
ERROR_TYPES = (RuntimeError, ValueError, MemoryError, KeyboardInterrupt, SystemExit)
ABI_MUTATIONS = (
    'short_return', 'output_magic', 'output_status', 'output_nonce',
    'output_sequence', 'output_phase', 'output_reserved7', 'output_reserved10',
    'output_reserved11', 'state_checksum', 'state_nonce', 'state_reserved9',
    'state_reserved15', 'state_mode', 'mutated_input', 'input_guard',
    'output_guard', 'state_guard',
)


class _Resource:
    pass


class _Providers:
    def __init__(self, *, error_port=None, error=None, resource_port=None,
                 resource=None, check_prior_ack=False):
        self.error_port, self.error = error_port, error
        self.resource_port, self.resource = resource_port, resource
        self.check_prior_ack = check_prior_ack
        self.visits = []
        self.events = []

    def effect(self, frame, port):
        if (frame.receipt.phase != native.CLAIMED
                or frame.receipt.port != port):
            raise AssertionError('test provider entered without its exact claim')
        name = native.PORTS[port - 1]
        self.visits.append(name)
        self.events.append(['provider_enter', name])
        if self.resource_port == name:
            with delivery.resource_scope(self.resource):
                self.events.append(['actual_resource_scope_body', name])
                return self._body(frame, name)
        return self._body(frame, name)

    def _body(self, frame, name):
        if self.check_prior_ack and name == 'section':
            delivery.check_resource_retirement(self.resource)
            self.events.append(['prior_resource_ACK_retired_before_next_provider', name])
        if name == self.error_port:
            self.events.append(['provider_raise', name, type(self.error).__name__])
            raise self.error
        if name in BOOL_PORTS:
            # Both rejection providers return normally. This visits every
            # original port and checks their required fallthrough paths.
            return 1
        if name == 'result':
            frame.result = {'fixture_returned': True}
        elif name == 'release_locals':
            frame.data.clear()
        return 0


class _ProbeFrame(native.ServiceDescribeFrame):
    def __init__(self, image, providers):
        self.providers = providers
        super().__init__(image, object(), {}, namespace={
            '__builtins__': vars(builtins), '__package__': 'hepta'})

    def effect(self, port):
        return self.providers.effect(self, port)


def _buffers(source, output, state):
    return {
        'request_and_guard_hex': ctypes.string_at(source, native.REQUEST_BYTES + 16).hex(),
        'output_and_guard_hex': ctypes.string_at(output, native.OUTPUT_BYTES + 16).hex(),
        'state_and_guard_hex': ctypes.string_at(state, native.STATE_BYTES + 16).hex(),
    }


def _write_word(pointer, index, value):
    ctypes.memmove(ctypes.addressof(pointer) + index * 8,
                   struct.pack('<Q', value & ((1 << 64) - 1)), 8)


def _mutate(name, source, output, state, code):
    if name == 'short_return':
        return native.OUTPUT_BYTES - 1
    output_words = list(struct.unpack('<12Q', ctypes.string_at(output, native.OUTPUT_BYTES)))
    state_words = list(struct.unpack('<16Q', ctypes.string_at(state, native.STATE_BYTES)))
    if name.startswith('output_') and name != 'output_guard':
        indices = {'output_magic': 0, 'output_status': 1, 'output_nonce': 8,
                   'output_sequence': 3, 'output_phase': 4, 'output_reserved7': 7,
                   'output_reserved10': 10, 'output_reserved11': 11}
        index = indices[name]
        value = (REFUSED if name == 'output_phase' else output_words[index] ^ 1)
        _write_word(output, index, value)
    elif name.startswith('state_') and name != 'state_guard':
        indices = {'state_checksum': 10, 'state_nonce': 6, 'state_reserved9': 9,
                   'state_reserved15': 15, 'state_mode': 2}
        index = indices[name]
        state_words[index] ^= 1
        if index != 10:
            # Keep a valid checksum for the independent nonce/reserved/mode
            # checks; a checksum failure must not be their only rejection.
            state_words[10] = native._checksum(state_words)
        ctypes.memmove(state, struct.pack('<16Q', *state_words), native.STATE_BYTES)
    elif name == 'mutated_input':
        words = list(struct.unpack('<10Q', ctypes.string_at(source, native.REQUEST_BYTES)))
        _write_word(source, 0, words[0] ^ 1)
    else:
        pointer, length = {'input_guard': (source, native.REQUEST_BYTES),
                           'output_guard': (output, native.OUTPUT_BYTES),
                           'state_guard': (state, native.STATE_BYTES)}[name]
        ctypes.memmove(ctypes.addressof(pointer) + length, b'\x01', 1)
    return code


def _error_record(error):
    if error is None:
        return None
    return {'type': type(error).__name__, 'args_repr': repr(error.args),
            'context_type': type(error.__context__).__name__ if error.__context__ is not None else None,
            'cause_type': type(error.__cause__).__name__ if error.__cause__ is not None else None,
            'suppress_context': error.__suppress_context__}


def _resource_observation(resource):
    try:
        delivery.check_resource_retirement(resource)
    except delivery.NativeDeliveryUnknown as error:
        allowed, error_record = False, _error_record(error)
    else:
        allowed, error_record = True, None
    rows = [observation for observation in delivery._RESOURCE_OBSERVATIONS.values()
            if observation.resource is resource]
    return {'retirement_allowed': allowed, 'retirement_error': error_record,
            'actual_retained_occurrences': len(rows),
            'pending_occurrences': sum(bool(row.pending) for row in rows),
            'lost_occurrences': sum(row.loss is not None for row in rows)}


def _run_one(image, providers, *, mutation=None, target_event=native.SUCCEEDED,
             target_port='import_catalog', lose_ack=False, retry=False):
    entry = image._entry
    trace = []
    injected = []
    actual, returned, frame = None, None, None
    outer = LookupError('describe fault-control caller context')
    before_custody = delivery.custody_snapshot()

    def observed(source, size, output, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, native.REQUEST_BYTES))
        row = {'event': packet[1], 'port': packet[3], 'before_native': _buffers(source, output, state)}
        trace.append(row)
        code = entry(source, size, output, capacity, state, extent)
        row['native_return'] = code
        row['after_native'] = _buffers(source, output, state)
        matches = (packet[1] == target_event and packet[3] == (
            0 if target_event == native.INITIALIZE else native.PORT[target_port]))
        if matches and not injected and (mutation is not None or lose_ack):
            if lose_ack:
                injected.append([packet[1], packet[3]])
                row['fault'] = 'actual_native_return_then_lost_ACK'
                raise ValueError('actual native describe acknowledgement is unavailable')
            code = _mutate(mutation, source, output, state, code)
            injected.append([packet[1], packet[3]])
            row['fault'] = mutation
        row['adapter_return'] = code
        row['after_fault'] = _buffers(source, output, state)
        return code

    image._entry = observed
    try:
        try:
            raise outer
        except LookupError:
            try:
                frame = _ProbeFrame(image, providers)
                returned = frame.finish()
            except BaseException as error:
                actual = error
        retry_record = None
        if retry and frame is not None:
            visits_before, entries_before = len(providers.visits), len(trace)
            try:
                frame.finish()
            except BaseException as error:
                retry_error = _error_record(error)
            else:
                retry_error = None
            retry_record = {'error': retry_error,
                            'additional_effects': len(providers.visits) - visits_before,
                            'additional_native_entries': len(trace) - entries_before}
    finally:
        image._entry = entry
    record = {
        'visits': providers.visits, 'provider_events': providers.events,
        'returned': returned, 'error': _error_record(actual),
        'original_exception_preserved': actual is providers.error if providers.error is not None else None,
        'original_active_context_preserved': actual.__context__ is outer if actual is not None else None,
        'injected': injected, 'retry': retry_record, 'trace': trace,
        'custody_before': list(before_custody), 'custody_after': list(delivery.custody_snapshot()),
        'frame': None if frame is None else {
            'finished': frame.finished, 'fenced': frame.fenced,
            'native_failed': frame.native_failed, 'local_slots': list(frame.data),
            'loss_recorded': frame._delivery.loss is not None,
            'retired': frame._delivery.retired,
        },
    }
    if providers.resource is not None:
        record['resource'] = _resource_observation(providers.resource)
    return record


def _healthy_retired(record):
    frame = record['frame']
    return (frame is not None and frame['retired'] and not frame['fenced']
            and not frame['native_failed'] and not frame['loss_recorded']
            and record['custody_after'] == record['custody_before'])


def _unknown_without_retry(record, expected_visits):
    frame = record['frame']
    before, after = record['custody_before'], record['custody_after']
    new_custody = after[len(before):]
    return (record['error'] is not None
            and record['error']['type'] == 'ServiceDescribeUnknown'
            and record['visits'] == expected_visits and len(record['injected']) == 1
            and (frame is None or not frame['retired'] and frame['fenced']
                 and frame['native_failed'] and frame['loss_recorded'])
            and after[:len(before)] == before and bool(new_custody)
            and all(row['lost'] and not row['retired'] for row in new_custody)
            and (record['retry'] is None or record['retry']['error'] is not None
                 and record['retry']['additional_effects'] == 0
                 and record['retry']['additional_native_entries'] == 0))


def run_controls(image, output):
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if tuple(native.PORTS) != EXPECTED_PORTS:
        raise ValueError('the frozen thirteen describe effect identities changed')
    rows = []

    def retain(name, record, passed):
        record['passed'] = bool(passed)
        record['control'] = name
        raw = (json.dumps(record, indent=2, sort_keys=True) + '\n').encode()
        filename = name + '.json'
        (output / filename).write_bytes(raw)
        rows.append({'control': name, 'passed': bool(passed), 'raw_file': filename,
                     'raw_bytes': len(raw), 'raw_sha256': sha256(raw).hexdigest(),
                     'native_entries': len(record['trace'])})

    healthy = _run_one(image, _Providers())
    retain('all-13-returning-providers', healthy,
           healthy['error'] is None and healthy['visits'] == list(native.PORTS)
           and healthy['returned'] == {'fixture_returned': True}
           and healthy['frame']['finished'] and _healthy_retired(healthy))

    for index, port in enumerate(native.PORTS):
        for kind in ERROR_TYPES:
            error = kind('describe provider ' + port)
            row = _run_one(image, _Providers(error_port=port, error=error))
            last = row['trace'][-1]
            passed = (row['original_exception_preserved'] and row['original_active_context_preserved']
                      and row['visits'] == list(native.PORTS[:index + 1])
                      and last['event'] == native.RAISED and last['port'] == native.PORT[port]
                      and row['frame']['finished'] and _healthy_retired(row)
                      and bool(row['frame']['local_slots']))
            retain('provider-' + port + '-' + kind.__name__, row, passed)

        for event in (native.SUCCEEDED, native.RAISED):
            error = RuntimeError('provider before lost raised ACK') if event == native.RAISED else None
            providers = _Providers(error_port=port if error is not None else None, error=error)
            row = _run_one(image, providers, target_event=event, target_port=port,
                           lose_ack=True, retry=True)
            retain('lost-ACK-' + port + '-' + str(event), row,
                   _unknown_without_retry(row, list(native.PORTS[:index + 1])))

    for event in (native.INITIALIZE, native.CLAIM, native.SUCCEEDED, native.RAISED):
        for mutation in ABI_MUTATIONS:
            error = RuntimeError('provider before malformed raised ACK') if event == native.RAISED else None
            providers = _Providers(error_port='import_catalog' if error is not None else None, error=error)
            row = _run_one(image, providers, mutation=mutation, target_event=event, retry=True)
            expected = [] if event in (native.INITIALIZE, native.CLAIM) else ['import_catalog']
            retain('ABI-' + str(event) + '-' + mutation, row,
                   _unknown_without_retry(row, expected))

    for mode in ('confirmed-before-next-error', 'lost-success-ACK',
                 'confirmed-provider-error', 'lost-raised-ACK',
                 'unscoped-lookalike', 'exception-class-without-loss'):
        resource = _Resource()
        delivery.bind_resource_lifetime(resource)
        scoped = mode not in ('unscoped-lookalike', 'exception-class-without-loss')
        error_port, error = None, None
        if mode == 'confirmed-before-next-error':
            error_port, error = 'section', RuntimeError('later provider failed after completed resource ACK')
        elif mode in ('confirmed-provider-error', 'lost-raised-ACK'):
            error_port, error = 'profile_pair', RuntimeError('actual resource provider raised')
        elif mode == 'exception-class-without-loss':
            error_port, error = 'profile_pair', delivery.NativeDeliveryUnknown('ordinary provider exception only')
        providers = _Providers(error_port=error_port, error=error,
                               resource_port='profile_pair' if scoped else None,
                               resource=resource,
                               check_prior_ack=mode == 'confirmed-before-next-error')
        lost = mode in ('lost-success-ACK', 'lost-raised-ACK', 'unscoped-lookalike')
        event = native.RAISED if mode == 'lost-raised-ACK' else native.SUCCEEDED
        row = _run_one(image, providers, target_event=event, target_port='profile_pair',
                       lose_ack=lost, retry=lost)
        held = mode in ('lost-success-ACK', 'lost-raised-ACK')
        passed = row['resource']['retirement_allowed'] is (not held)
        if held:
            passed = (passed and row['resource']['actual_retained_occurrences'] > 0
                      and row['resource']['pending_occurrences'] > 0
                      and row['resource']['lost_occurrences'] > 0)
        else:
            passed = passed and all(row['resource'][field] == 0 for field in (
                'actual_retained_occurrences', 'pending_occurrences', 'lost_occurrences'))
        if lost:
            passed = passed and _unknown_without_retry(row, list(native.PORTS[:native.PORT['profile_pair']]))
        else:
            passed = passed and row['original_exception_preserved'] and _healthy_retired(row)
        if mode == 'confirmed-before-next-error':
            passed = passed and ['prior_resource_ACK_retired_before_next_provider', 'section'] in row['provider_events']
        retain('resource-' + mode, row, passed)

    report = {
        'schema': 'hepta.hia.service-describe-fault-controls.v1',
        'status': 'PASS' if len(rows) == 170 and all(row['passed'] for row in rows) else 'FAIL',
        'controls': rows, 'control_count': len(rows),
        'expected_control_count': 170,
        'actual_native_entries': sum(row['native_entries'] for row in rows),
        'image_sha256': image.image_sha256,
        'source_sha256': image.admitted_source_sha256,
        'complete_request_output_state_and_guards_retained': True,
        'custody_registry_reset': False,
        'resource_scope': 'explicit test resources; not a real Store or SQLite replacement',
        'foreign_provider_scope': '13 actual claimed adapter ports; separate original-handler oracle required',
        'unknown_observations_retained_until_child_exit': True,
        'whole_native_delivery_qualified': False,
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image = native.installed_service_describe(str(args.manifest))
    report = run_controls(image, args.output)
    print(json.dumps({key: report[key] for key in ('status', 'control_count', 'actual_native_entries')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
