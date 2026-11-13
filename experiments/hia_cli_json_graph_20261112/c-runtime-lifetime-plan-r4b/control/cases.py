"""Finite actual C/runtime/lifetime observations in two disposable children.

The code never invokes a retained JSON encoder. Two toy generators provide
real frames and a same-process CPython cleanup oracle. Raw-leaf-only cases
and deliberate quarantine/trace-overflow controls remain separately labelled.
No finite trace capacity is imposed on the public JSON value domain.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import traceback
import weakref

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import require, read_file, pin, save, create
from original_current_compiler import json_original
from case_contract import (RUNTIME_IDS, LIFETIME_IDS, RAW_LEAF_ONLY_IDS,
                           NORMAL_EFFECTS, YIELD_EFFECTS,
                           ERROR_TWO_STACK_EFFECTS, UNEXECUTED_SCOPES,
                           EXPECTED_HIA_RETURNS, EXPECTED_C_PUMP_CALLS)

# Real raw references on a protocol refusal are retained to process exit.
# No Python destructor guesses a frame/slot cleanup plan after quarantine.
QUARANTINE = []
KEEP = []


class MarkerError(Exception):
    pass


class Token:
    def __init__(self, label, observations):
        self.label = label
        self.observations = observations

    def __del__(self):
        handled = sys.exception()
        self.observations.append((self.label, id(handled) if handled is not None else 0))


def empty_generator(first, second):
    if False:
        yield None


def stacked_generator(first, second, factory):
    (factory('operand0'), factory('operand1'), (yield None))


def handled_generator(factory, handled):
    try:
        raise handled
    except MarkerError:
        (factory('handled_operand'), (yield None))


def yield_generator(value):
    yield value


def expected_error(function, kind):
    try:
        function()
    except kind as error:
        return {'type': type(error).__name__, 'message': str(error)}
    raise AssertionError('the fixed negative control unexpectedly returned')


def address(function):
    value = ctypes.cast(function, ctypes.c_void_p).value
    require(type(value) is int and value > 0, 'actual C function address is absent')
    return value


def bind_entry(leaves, name):
    return ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)(
        address(getattr(leaves.library, name)))


def call_table(entry, words):
    values = (ctypes.c_uint64 * len(words))(*words)
    before = tuple(values)
    result = entry(values, len(values))
    require(tuple(values) == before, 'immutable runtime table was modified')
    return result


def run_runtime(policy, dso_path, dso_sha, output, report):
    from hepta.hia_cli_json_sort_native import CpythonJsonLeaves, REFUSAL
    from hepta.hia_cli_json_runtime312 import admit_runtime
    from hepta.hia_cli_json_runtime312_control import admit_runtime_control

    leaves = None
    base_words = control_words = None
    base_record = control_record = None
    for case_id in RUNTIME_IDS:
        start = time.monotonic_ns()
        row = {'id': case_id, 'status': 'HOLD', 'hia_entry_calls': 0}
        report['loaded_ids'].append(case_id)
        try:
            runtime = policy['python']
            if case_id == RUNTIME_IDS[0]:
                leaves = CpythonJsonLeaves(dso_path, sha256_pin=dso_sha)
                require(leaves.profile == 31214 and leaves.layout_record[1] == 192
                        and leaves.layout_record[4] == sys.hexversion,
                        'actual compiled leaf layout does not match this interpreter')
                row.update(layout=list(leaves.layout_record), dso=leaves.input_pin)
            elif case_id == RUNTIME_IDS[1]:
                base_record = leaves.bind_runtime_312(runtime['path'],
                    sha256_pin=runtime['sha256'], bytes_pin=runtime['bytes'])
                base_words, fresh = admit_runtime(runtime['path'],
                    sha256_pin=runtime['sha256'], bytes_pin=runtime['bytes'])
                require(fresh == base_record and len(base_words) == 12
                        and len(base_record['symbols']) == 11,
                        'the full original private-symbol binding differs')
                row['binding'] = base_record
            elif case_id == RUNTIME_IDS[2]:
                control_words, control_record = admit_runtime_control(runtime['path'],
                    sha256_pin=runtime['sha256'], bytes_pin=runtime['bytes'])
                require(len(control_words) == 6 and len(control_record['symbols']) == 5
                        and tuple(control_record['base_words']) == base_words
                        and control_record['base_binding'] == base_record,
                        'additional runtime table is not bound to the original table')
                require(call_table(bind_entry(leaves, 'hia_cli_json_bind_runtime_312_control'),
                                   control_words) == 0, 'actual additional C binder refused')
                row['binding'] = control_record
            elif case_id == RUNTIME_IDS[3]:
                row['refusal'] = expected_error(lambda: admit_runtime(runtime['path'],
                    sha256_pin='0' * 64, bytes_pin=runtime['bytes']), ValueError)
            elif case_id == RUNTIME_IDS[4]:
                row['refusal'] = expected_error(lambda: admit_runtime_control(runtime['path'],
                    sha256_pin=runtime['sha256'], bytes_pin=runtime['bytes'] - 1), ValueError)
            elif case_id == RUNTIME_IDS[5]:
                results = [call_table(bind_entry(leaves, 'hia_cli_json_bind_runtime_312'), base_words),
                           call_table(bind_entry(leaves, 'hia_cli_json_bind_runtime_312_control'),
                                      control_words)]
                require(results == [0, 0], 'identical already-admitted tables did not rebind')
                row['returns'] = results
            elif case_id == RUNTIME_IDS[6]:
                changed = list(base_words)
                changed[2] += 1
                result = call_table(bind_entry(leaves, 'hia_cli_json_bind_runtime_312'), changed)
                require(result == REFUSAL, 'changed admitted base table was accepted')
                row['return'] = result
            elif case_id == RUNTIME_IDS[7]:
                changed = list(control_words)
                changed[2] += 1
                result = call_table(bind_entry(leaves, 'hia_cli_json_bind_runtime_312_control'), changed)
                require(result == REFUSAL, 'changed admitted additional table was accepted')
                row['return'] = result
            row['status'] = 'PASS'
            report['executed_ids'].append(case_id)
        except BaseException:
            row['error'] = traceback.format_exc()
            raise
        finally:
            row['elapsed_ns'] = time.monotonic_ns() - start
            report['outcomes'].append(row)
            save(output / (case_id + '.json'), row)


def frame_info(raw, generator):
    # Integer metadata only: accessing gi_frame would materialize a real frame
    # owner and alter the very local-reference disposal being measured.
    frame = raw.call(95, (id(generator),))
    values = tuple(frame[9:17])
    require(values[0] == id(generator.gi_code), 'actual generator code differs')
    require(values[4] >= values[2], 'actual frame top is below its locals')
    return values


def native_session(image, raw, generator, mode, *, records=128, handled=False):
    from hepta.hia_cli_json_py312_pump_native import BatchedPy312LifetimeSession
    info = frame_info(raw, generator)
    instruction = info[5]
    require(instruction < (1 << 63), 'the finite fixture has no entered code position')
    result = BatchedPy312LifetimeSession(image, raw, generator_pointer=id(generator),
        code_pointer=info[0], parent_pointer=0, instruction=instruction, mode=mode,
        traceback_handled=handled, trace_records=records)
    KEEP.append((result, raw, generator, image))
    return result


def parse_trace(session, *, complete=True):
    raw = session.trace_bytes()
    require(len(raw) % 256 == 0, 'partial fixed trace record')
    rows = [struct.unpack_from('<32Q', raw, index) for index in range(0, len(raw), 256)]
    request = tuple(session.request)
    require(len(rows) == request[27] and request[27] + request[28] == request[22] + request[24],
            'full actual trace/counter extent differs')
    if complete:
        require(request[28] == 0, 'a finite incomplete trace cannot qualify as complete')
        native = [row for row in rows if row[0] == 1]
        leaves = [row for row in rows if row[0] == 2]
        require(len(native) == request[21] == request[22]
                and len(leaves) == request[23] == request[24]
                and len(native) == len(leaves) + 1,
                'each real HIA/leaf return must be present exactly once')
        require([row[3] for row in leaves] == list(range(1, len(leaves) + 1))
                and all(row[1] == 0 and row[10] == 2 for row in leaves)
                and all(row[1] == 2 for row in native[:-1])
                and native[-1][1] == request[20], 'actual HIA permission/leaf marker sequence differs')
        for index, row in enumerate(rows):
            require(row[0] == (1 if index % 2 == 0 else 2), 'trace return alternation differs')
            require(row[29:] == (0, 0, 0), 'trace reserved words differ')
    return raw, rows


def record_session(row, session, output, suffix, *, effects=None, complete=True):
    raw, rows = parse_trace(session, complete=complete)
    trace_pin = create(output / (row['id'] + '.' + suffix + '.trace.bin'), raw)
    request_pin = create(output / (row['id'] + '.' + suffix + '.request.bin'),
                         ctypes.string_at(ctypes.addressof(session.request), ctypes.sizeof(session.request)))
    state_pin = create(output / (row['id'] + '.' + suffix + '.state.bin'), session.state.raw)
    actual_effects = [record[4] for record in rows if record[0] == 2]
    if effects is not None:
        require(complete and actual_effects == list(effects), 'the actual HIA-selected effect order differs')
    row.setdefault('runs', []).append({'receipt': session.batched_receipt,
        'request': request_pin, 'state': state_pin, 'trace': trace_pin,
        'observed_effects': actual_effects, 'complete_trace_required': complete})
    row['hia_entry_calls'] += int(session.request[22])
    row['c_pump_calls'] += 1


def assert_no_replay(session):
    before = tuple(session.request)
    refusal = expected_error(session.run_raw, RuntimeError)
    require(tuple(session.request) == before, 'Python duplicate attempted another C/native call')
    direct = session.pump_entry(session.request, 64)
    require(direct == 0xfffffffd and tuple(session.request) == before,
            'already-used C request was replayed or changed')
    return {'python_refusal': refusal, 'c_direct_refusal': direct,
            'native_before': before[22], 'native_after': int(session.request[22])}


def normal_fixture(raw_factory, image, observations, ambient, row, output):
    oracle_events = []
    oracle = empty_generator(Token('first', oracle_events), Token('second', oracle_events))
    require(next(oracle, None) is None, 'normal CPython fixture did not exhaust')
    require(oracle_events == [('first', ambient), ('second', ambient)],
            'the actual CPython forward-locals oracle differs')
    raw = raw_factory()
    generator = empty_generator(Token('first', observations), Token('second', observations))
    raw.call(79, (id(None),))
    session = native_session(image, raw, generator, 0)
    require(session.run_raw() == 0, 'actual HIA normal terminal differs')
    require(observations == oracle_events and generator.gi_frame is None,
            'normal local cleanup or actual frame closure differs')
    record_session(row, session, output, 'normal', effects=NORMAL_EFFECTS)
    row.update(oracle_events=oracle_events, actual_events=observations)
    return session


def run_lifetime(policy, dso_path, dso_sha, image_path, image_sha, output, report):
    from hepta.hia_cli_json_sort_native import CpythonJsonLeaves
    from hepta.hia_cli_json_raw_native import RawTransactions
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    leaves = CpythonJsonLeaves(dso_path, sha256_pin=dso_sha)
    runtime = policy['python']
    runtime_record = leaves.bind_runtime_312(runtime['path'],
        sha256_pin=runtime['sha256'], bytes_pin=runtime['bytes'])
    report['runtime_binding'] = runtime_record
    image_raw, image_pin = read_file(image_path, 1 << 20)
    require(image_pin['sha256'] == image_sha, 'actual lifetime image bytes differ')
    image = NativeHiaJsonImage(image_raw, image_sha)
    image._bind_manifest_source(policy['lifetime_source']['sha256'])
    require(image.admitted_source_sha256 == policy['lifetime_source']['sha256'],
            'actual lifetime image source binding differs')
    report['image'] = image_pin
    factory = lambda: RawTransactions(leaves)
    KEEP.extend((leaves, image))

    for case_id in LIFETIME_IDS:
        start = time.monotonic_ns()
        row = {'id': case_id, 'status': 'HOLD', 'hia_entry_calls': 0, 'c_pump_calls': 0,
               'raw_leaf_only': case_id in RAW_LEAF_ONLY_IDS}
        report['loaded_ids'].append(case_id)
        try:
            if case_id == LIFETIME_IDS[0]:
                normal_fixture(factory, image, [], 0, row, output)
            elif case_id == LIFETIME_IDS[1]:
                ambient = MarkerError('ambient-normal')
                try:
                    raise ambient
                except MarkerError:
                    normal_fixture(factory, image, [], id(ambient), row, output)
                    require(sys.exception() is ambient, 'the caller handled exception changed')
            elif case_id == LIFETIME_IDS[2]:
                events = []
                generator = stacked_generator(Token('local0', events), Token('local1', events),
                    lambda label: Token(label, events))
                require(next(generator) is None, 'two-operand fixture did not yield')
                raw = factory()
                info = frame_info(raw, generator)
                require(info[4] - info[2] == 2, 'the real suspended frame does not own two operands')
                failure = MarkerError('original-business-error')
                # A borrowed, still unraised exception is acquired directly by
                # the C owner. No synthetic raise establishes its traceback.
                raw.capture_external(failure)
                raw.install_external_after_except()
                session = native_session(image, raw, generator, 1)
                require(session.run_raw() == 1 and session.error_address == id(failure),
                        'HIA lost the actual business exception')
                require(events == [('operand1', 0), ('operand0', 0)],
                        'actual operand cleanup was not reverse, or traceback locals were lost')
                require(failure.__traceback__ is not None
                        and failure.__traceback__.tb_frame.f_code is stacked_generator.__code__
                        and generator.gi_frame is None, 'actual traceback/frame transfer differs')
                record_session(row, session, output, 'error', effects=ERROR_TWO_STACK_EFFECTS)
                before_raise = list(events)
                try:
                    raw.raise_pending()
                except MarkerError as caught:
                    require(caught is failure, 'actual C exception propagation replaced identity')
                else:
                    raise AssertionError('the original pending exception did not propagate')
                require(raw.refresh()[8] == 0, 'original error owner did not transfer')
                failure.__traceback__ = None
                require(events == before_raise + [('local0', 0), ('local1', 0)],
                        'traceback-held local release order differs')
                row.update(actual_events=events, original_error_identity_preserved=True,
                           complete_throw_body_equivalence_claimed=False)
            elif case_id == LIFETIME_IDS[3]:
                events = []
                handled = MarkerError('generator-handled')
                generator = handled_generator(lambda label: Token(label, events), handled)
                require(next(generator) is None, 'handled-context fixture did not yield')
                raw = factory()
                info = frame_info(raw, generator)
                require(info[4] > info[2], 'handled-context fixture has no live operand')
                raw.call(100, (id(generator),), generator_pointer=id(generator), instruction=info[5])
                raw.call(6, generator_pointer=id(generator), instruction=info[5])
                require(events == [('handled_operand', id(handled))] and sys.exception() is None,
                        'the named release leaf lost generator handled state or leaked it to the caller')
                # This is a mechanical named-leaf control. Complete remaining
                # raw storage disposal is explicit; no retained body resumes.
                while frame_info(raw, generator)[4] > info[2]:
                    raw.call(100, (id(generator),))
                    if raw.refresh()[5]:
                        raw.call(6)
                raw.call(96, (id(generator), 0))
                raw.call(106, (id(generator),))
                require(generator.gi_frame is None, 'raw finite frame cleanup did not close')
                handled.__traceback__ = None
                row.update(actual_events=events, raw_returns=raw.actual_leaf_returns,
                           generator_leaf_returns=raw.actual_generator_leaf_returns)
            elif case_id == LIFETIME_IDS[4]:
                events = []
                value = Token('yielded', events)
                pointer = id(value)
                reference = weakref.ref(value)
                generator = yield_generator(value)
                raw = factory()
                raw.call(79, (pointer,))
                del value
                session = native_session(image, raw, generator, 2)
                require(session.run_raw() == 3 and session.result_address == pointer
                        and reference() is not None and not events,
                        'actual yield did not preserve the owned result')
                record_session(row, session, output, 'yield', effects=YIELD_EFFECTS)
                raw.call(6)
                require(reference() is not None and not events, 'yield cleanup stole the frame local')
                raw.call(79, (id(None),))
                terminal = native_session(image, raw, generator, 0)
                require(terminal.run_raw() == 0 and reference() is None
                        and events == [('yielded', 0)], 'actual yield/terminal ownership differs')
                record_session(row, terminal, output, 'terminal', effects=NORMAL_EFFECTS)
                row['actual_events'] = events
            elif case_id == LIFETIME_IDS[5]:
                session = normal_fixture(factory, image, [], 0, row, output)
                row['repeat'] = assert_no_replay(session)
                row['c_pump_calls'] += 1
            elif case_id == LIFETIME_IDS[6]:
                events = []
                raw = factory()
                generator = empty_generator(Token('first', events), Token('second', events))
                raw.call(79, (id(None),))
                session = native_session(image, raw, generator, 0, records=1)
                require(session.run_raw() == 0 and generator.gi_frame is None
                        and events == [('first', 0), ('second', 0)]
                        and session.request[27] == 1 and session.request[28] > 0,
                        'full trace buffer stopped the actual lifetime plan or hid omissions')
                row['complete_trace_refusal'] = expected_error(lambda: parse_trace(session), ValueError)
                record_session(row, session, output, 'negative-incomplete', complete=False)
                row.update(negative_observer_control=True, full_trace_qualified=False,
                           actual_events=events)
            elif case_id == LIFETIME_IDS[7]:
                events = []
                first, second = Token('first', events), Token('second', events)
                references = (weakref.ref(first), weakref.ref(second))
                generator = empty_generator(first, second)
                del first, second
                raw = factory()
                raw.call(79, (id(None),))
                session = native_session(image, raw, generator, 0)
                session.state[8] = b'\x01'
                row['refusal'] = expected_error(session.run_raw, RuntimeError)
                require(session.quarantined and raw.protocol_failed
                        and session.request[21] == session.request[22] == 0
                        and session.request[23] == session.request[24] == 0
                        and all(reference() is not None for reference in references) and not events,
                        'dirty workspace made an entry call or lost a quarantined owner')
                QUARANTINE.append((session, raw, generator, image, references))
                row.update(request=list(session.request), retained_to_process_exit=True,
                           hia_entry_calls=0, c_pump_calls=1, negative_preentry_control=True)
                create(output / (case_id + '.request.bin'), bytes(session.request))
                create(output / (case_id + '.state.bin'), session.state.raw)
            elif case_id == LIFETIME_IDS[8]:
                events = []
                raw = factory()
                generator = empty_generator(Token('first', events), Token('second', events))
                raw.call(79, (id(None),))
                session = native_session(image, raw, generator, 0)
                original_refresh = raw.refresh
                bookkeeping = MarkerError('after-C-return-bookkeeping')
                def refuse_refresh():
                    raise bookkeeping
                raw.refresh = refuse_refresh
                try:
                    session.run_raw()
                except MarkerError as observed:
                    require(observed is bookkeeping, 'bookkeeping error identity changed')
                else:
                    raise AssertionError('the actual Python post-return failure did not occur')
                finally:
                    raw.refresh = original_refresh
                require(session.quarantined and session.failure is bookkeeping
                        and session.pump_returned and session.request[3] == 2
                        and session.request[22] == 6 and session.request[24] == 5
                        and generator.gi_frame is None and events == [('first', 0), ('second', 0)],
                        'bookkeeping failure was mistaken for a C failure or replayed cleanup')
                record_session(row, session, output, 'returned-before-bookkeeping', effects=NORMAL_EFFECTS)
                row['repeat'] = assert_no_replay(session)
                row['c_pump_calls'] += 1
                QUARANTINE.append((session, raw, generator, image, bookkeeping))
                row.update(negative_postreturn_control=True, retained_to_process_exit=True,
                           actual_events=events)
            elif case_id == LIFETIME_IDS[9]:
                events = []
                raw = factory()
                generator = empty_generator(Token('first', events), Token('second', events))
                returned = Token('return-value', events)
                reference = weakref.ref(returned)
                pointer = id(returned)
                raw.call(79, (pointer,))
                del returned
                raw.call(96, (id(generator), 0))
                require(reference() is not None and raw.refresh()[5] == pointer
                        and events == [('first', 0), ('second', 0)],
                        'frame clear released the separately owned return value')
                raw.call(6)
                raw.call(106, (id(generator),))
                require(reference() is None and generator.gi_frame is None
                        and events == [('first', 0), ('second', 0), ('return-value', 0)],
                        'return value was not disposed strictly after frame locals')
                row.update(actual_events=events, raw_returns=raw.actual_leaf_returns)
            position = LIFETIME_IDS.index(case_id)
            require(type(row['hia_entry_calls']) is int
                    and row['hia_entry_calls'] == EXPECTED_HIA_RETURNS[position]
                    and row['c_pump_calls'] == EXPECTED_C_PUMP_CALLS[position],
                    'the finite real-entry denominator differs from the HIA source plan')
            row['status'] = 'PASS'
            report['executed_ids'].append(case_id)
        except BaseException:
            row['error'] = traceback.format_exc()
            raise
        finally:
            row['elapsed_ns'] = time.monotonic_ns() - start
            report['outcomes'].append(row)
            save(output / (case_id + '.json'), row)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--kind', choices=('runtime', 'lifetime'), required=True)
    parser.add_argument('--dso', type=Path, required=True)
    parser.add_argument('--dso-sha256', required=True)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--image-sha256')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw, policy_pin = read_file(args.policy, 2 << 20)
    require(policy_pin['sha256'] == args.policy_sha256, 'fixed finite policy differs')
    policy = json_original(raw)
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and list(sys.version_info[:3]) == [3, 12, 14]
            and str(Path(sys.executable).resolve()) == policy['python']['path']
            and os.environ.get('PATH') == '', 'isolated exact runtime/empty PATH required')
    sys.path.insert(0, str(ROOT / 'source'))
    require(args.output.is_dir() and not any(args.output.iterdir()), 'fresh finite output required')
    expected = RUNTIME_IDS if args.kind == 'runtime' else LIFETIME_IDS
    require(policy[args.kind + '_ids'] == list(expected), 'fixed finite denominator differs')
    report = {'schema': 'hia.cli-json.C-runtime-lifetime-finite.v1', 'kind': args.kind,
        'status': 'HOLD', 'expected_ids': list(expected), 'loaded_ids': [], 'executed_ids': [],
        'outcomes': [], 'errors': [], 'original17_executed': False, 'original46_executed': False,
        'body_driver_qualified': False, 'unexecuted_scopes': list(UNEXECUTED_SCOPES),
        'policy_sha256': args.policy_sha256, 'dso_sha256': args.dso_sha256,
        'image_sha256': args.image_sha256, 'declared_child_seconds': 5,
        'clock_started_ns': time.monotonic_ns()}
    try:
        dso_before = pin(args.dso, 1 << 20)
        require(dso_before['sha256'] == args.dso_sha256, 'actual DSO pin differs')
        if args.kind == 'runtime':
            require(args.image is None and args.image_sha256 is None, 'runtime case must not receive HIA image')
            run_runtime(policy, args.dso, args.dso_sha256, args.output, report)
        else:
            require(args.image is not None and type(args.image_sha256) is str,
                    'actual lifetime image required')
            run_lifetime(policy, args.dso, args.dso_sha256, args.image, args.image_sha256,
                         args.output, report)
        require(report['loaded_ids'] == report['executed_ids'] == list(expected)
                and len(report['outcomes']) == len(expected)
                and all(row['status'] == 'PASS' for row in report['outcomes']),
                'finite case body missing or failed')
        require(pin(args.dso, 1 << 20) == dso_before, 'actual DSO changed')
        report['status'] = 'FINITE_' + args.kind.upper() + '_PASS'
    except BaseException:
        report['errors'].append(traceback.format_exc())
    finally:
        report['elapsed_ns'] = time.monotonic_ns() - report['clock_started_ns']
        report['hia_entry_calls'] = sum(row['hia_entry_calls'] for row in report['outcomes'])
        report['c_pump_calls'] = sum(row.get('c_pump_calls', 0) for row in report['outcomes'])
        report['quarantined_owners_retained_to_process_exit'] = len(QUARANTINE)
        save(args.output / 'REPORT.json', report)
    print(json.dumps({'kind': args.kind, 'status': report['status'],
                      'executed_ids': report['executed_ids'], 'elapsed_ns': report['elapsed_ns']}))
    return 0 if report['status'].endswith('_PASS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
