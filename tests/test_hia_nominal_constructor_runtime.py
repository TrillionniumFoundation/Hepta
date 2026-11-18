"""Compare the installed constructor with the existing bound callback route."""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from hepta.hia_composite_functions_errors import ERRORS as FUNCTION_ERRORS
from hepta.hia_composite_constructor_errors import ERRORS as CONSTRUCTOR_ERRORS
from hepta.hia_composite_constructor_native import NativeConstructorInvocation
from hepta.hia_composite_function_tokens import ObjectTokenDecoder, detached_packet_index
from hepta.hia_composite_types_native import ERRORS as TYPE_ERRORS, NativeCompositeTypes
from hepta.hia_instruction_policy_native import transport
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_composite import _Elaborator
from tests.test_hia_partial_record import roundtrip_program
from tests.test_hia_composite_returned_loans import pair_program, task_program as loan_task
from tests.test_hia_program_composite import task_program


FRAME = struct.Struct('<8s7Q')


def image(folder, role, cls=NativeHiaJsonImage):
    body = (folder / (role + '.image.bin')).read_bytes()
    return cls(body, sha256(body).hexdigest())


def reference(folder, document, legacy):
    images = {name: image(folder, name) for name in ('owner', 'render')}
    types = image(folder, 'types', NativeCompositeTypes)
    commands, terminal = [], None
    original = NativeConstructorInvocation._stream

    def observe(invocation, action, request):
        nonlocal terminal
        value = original(invocation, action, request)
        if action:
            commands.append(action)
        else:
            terminal = value
        return value

    owner = SimpleNamespace()
    with (patch('hepta.hia_composite_types_native.selected_composite_types', types.session),
          patch.object(NativeConstructorInvocation, '_stream', observe)):
        try:
            NativeConstructorInvocation(images, owner, document, legacy=legacy).initialize()
            code, message = None, None
        except HIAProgramRejected as exc:
            code, message = exc.code, str(exc)
        finally:
            if getattr(owner, 'native_types', None):
                owner.native_types.close()
    return commands, terminal, code, message


def cases():
    for profile in (1, 2, 3):
        doc = task_program()
        doc['schema'] = 'hepta.hia.composite.v' + str(profile)
        yield 'task-v' + str(profile), doc, False, (0, 0)
    yield 'legacy-v1', task_program(), True, (0, 0)
    yield 'returned-loan-v4', pair_program(), False, (0, 0)
    yield 'loan-and-task-v4', loan_task(), False, (0, 0)
    many = {'schema': 'hepta.hia.composite.v1', 'module': 'many',
            'types': [], 'functions': [
                {'name': f'f{i}', 'params': [{'name': f'p{j}', 'type': 'u8'} for j in range(6)],
                 'returns': [], 'effects': [], 'entry': 'b', 'blocks': []}
                for i in range(256)]}
    yield 'multi-chunk', many, False, (0, 0)
    wrong_origin = pair_program()
    wrong_origin['functions'][0]['return_loans'][0]['param'] = 'missing'
    yield 'delegated-refusal', wrong_origin, False, (999, 39)
    wrong_module = pair_program()
    wrong_module['module'] = '00'
    yield 'early-owner-refusal', wrong_module, False, (4, 0)
    wrong_effect = task_program()
    wrong_effect['functions'][0]['effects'].append('unknown')
    yield 'late-owner-refusal', wrong_effect, False, (14, 0)


def check(executable, oracle):
    def run(raw, *, digits=4300, legacy=False, count=None, flags=0, trailer=b'', handoff=False):
        length = len(raw) if count is None else count
        magic = b'HIACBX01' if handoff else b'HIACSX01'
        request = FRAME.pack(magic, digits, int(legacy), length, flags, 0, 0, 0)
        result = subprocess.run([executable], input=request + raw + trailer, capture_output=True,
                                env={'PATH': ''}, timeout=20, check=False)
        assert not result.stderr
        return result.returncode, result.stdout

    requests, documents, kinds, seeds, admitted = 0, 0, set(), 0, 0
    for name, document, legacy, status in cases():
        commands, expected, old_code, old_message = reference(oracle, document, legacy)
        assert expected is not None, (name, old_message)
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        code, data = run(raw, legacy=legacy)
        assert code == (65 if status[0] else 0), (name, code)
        assert FRAME.unpack_from(data) == (
            b'HIACSF01', *status, expected[0], expected[1], len(commands), len(raw), 1)
        diagnostic = TYPE_ERRORS[status[1]] if status[1] else CONSTRUCTOR_ERRORS.get(status[0])
        assert (diagnostic[0] if diagnostic else None) == old_code
        if diagnostic is not None:
            assert diagnostic[1] in old_message

        # Decoding is performed only by this independent test observer;
        # the actual installed process never imports a host object decoder.
        _, index = detached_packet_index(transport([document, legacy]))
        decoder = ObjectTokenDecoder(index)
        sequence, cursor = 0, 64
        while not decoder.complete:
            magic, action, seq, final, a, b, request, size = FRAME.unpack_from(data, cursor)
            assert (magic, action, seq, a, b, request) == (b'HIACTK01', 0, sequence, 0, 0, len(commands))
            assert final in (0, 1)
            cursor += FRAME.size
            assert size <= len(data) - cursor
            decoder.feed(data[cursor:cursor + size], final=bool(final))
            sequence += 1
            cursor += size
        assert cursor == len(data) and decoder.root == expected, name
        if name == 'multi-chunk':
            assert sequence > 1
        for role in (1, 2):
            seed_code, seed_data = run(raw, legacy=legacy, flags=role, handoff=True)
            if status[0]:
                assert (seed_code, seed_data) == (code, data)
                continue
            registry = [row[:3] for row in expected[4]]
            if role == 1:
                payload = transport([document, registry, expected[5], 0, 0, legacy, 0])
            else:
                payload = transport([document, registry, 0, 0, [], []])
            assert seed_code == 0
            assert FRAME.unpack_from(seed_data) == (
                b'HIACIP01', role, len(payload), expected[1], len(commands), 0, 0, 0)
            assert seed_data[64:] == payload
            seeds += 1
        first_code, first_data = run(raw, legacy=legacy, flags=3, handoff=True)
        if status[0]:
            assert (first_code, first_data) == (code, data)
        elif name == 'multi-chunk':
            assert (first_code, first_data) == (65, FRAME.pack(b'HIAFAF01', 1, 1, 0, 0, 0, 0, 0))
        else:
            serial, slots, count = {'returned-loan-v4': (8, 18, 6),
                                    'loan-and-task-v4': (9, 37, 19)}.get(name, (2, 38, 29))
            first = FRAME.pack(b'HIAFAF01', 10, 0, 100, serial, slots, count, 0)
            assert (first_code, first_data) == (0, first)
            admitted += count
        requests += len(commands)
        kinds.update(commands)
        documents += 1

    assert kinds == {1, 2, 3, 4, 5}
    malformed = [(b'{"x":0,"x":0}', 0xfffffffc), (b'{}\xff', 0xffffffff), (b'[] ', 0xfffffffd)]
    for raw, expected in malformed:
        digits = 639 if expected == 0xfffffffd else 4300
        assert run(raw, digits=digits) == (65, struct.pack('<8sQ', b'HIANJE01', expected))
    assert run(b'', count=(8 << 20) + 1) == (65, struct.pack('<8sQ', b'HIANJE01', 0xfffffffb))
    assert run(b'', count=1) == (64, b'')
    assert run(b'{}', flags=1) == (64, b'')
    assert run(b'{}', trailer=b' ') == (64, b'')
    assert run(b'{}', handoff=True, flags=0) == (64, b'')
    assert run(b'{}', handoff=True, flags=6) == (64, b'')
    bad_param = task_program()
    bad_param['functions'][0]['blocks'][0]['params'][0]['type'] = 'Missing'
    bad_raw = json.dumps(bad_param, separators=(',', ':')).encode()
    assert run(bad_raw, flags=3, handoff=True) == (
        65, FRAME.pack(b'HIAFAF01', 1, 999, 2, 0, 0, 1, 18))
    print(f'{documents} exact constructor completions and failure prefixes; '
          f'{requests} dependent requests across all five kinds; nine raw framing controls; '
          f'{seeds} exact function or outer seed packets; '
          f'{admitted} automatic first-function parameter requests and two refusal stages')
    check_bodies(run)
    check_modules(run)


def check_bodies(run):
    def first(document, *, legacy=False):
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        return run(raw, legacy=legacy, flags=4, handoff=True)

    with_helpers = task_program()
    with_helpers['functions'] = with_helpers['functions'][2:] + with_helpers['functions'][:2]
    samples = [(name, doc, legacy) for name, doc, legacy, status in cases()
               if not status[0] and name != 'multi-chunk']
    samples += [('partial-record', roundtrip_program(), False),
                ('five-task-helpers', with_helpers, False)]
    requests, helper_count = 0, 0
    for name, document, legacy in samples:
        owner = _Elaborator(deepcopy(document), legacy=legacy)
        expected = owner.function(owner.document['functions'][0])
        code, result = first(document, legacy=legacy)
        assert code == 0, (name, code)
        magic, action, error, phase, serial, slots, request, delegate = FRAME.unpack_from(result)
        assert (magic, action, error, phase, serial, slots, delegate) == (
            b'HIAFBL01', 2, 0, 2000, owner.serial, owner.value_slots, 0)
        payload, packet = transport(expected), FRAME.unpack_from(result, 64)
        assert packet == (b'HIAFPP01', 0, request, len(payload), serial, slots, 0, 0)
        assert result[128:128 + len(payload)] == payload, name
        cursor, handles, helpers = 128 + len(payload), [], []
        for helper in owner.helpers:
            marker, status, final, name_id, size, sequence, r0, r1 = FRAME.unpack_from(result, cursor)
            assert (marker, status, r0, r1) == (b'HIAFHR01', 0, 0, 0)
            assert name_id <= final <= serial and 0 < sequence < request
            start = cursor + 64
            end = start + size
            assert end <= len(result)
            value = json.loads(result[start:end])
            assert value == {'helper': helper}
            assert helper['name'] == 'h2internal_' + str(name_id)
            cursor = end
            handles.append(sequence)
            helpers.append(name_id)
        assert cursor == len(result) and handles == sorted(set(handles)), name
        assert helpers == sorted(set(helpers)), name
        if name == 'five-task-helpers':
            assert len(helpers) == 5
        requests += request
        helper_count += len(helpers)

    # An error after helper lowering must not publish any generated helper.
    broken = deepcopy(with_helpers)
    for block in broken['functions'][0]['blocks']:
        if any(ins['op'] == 'task.close' for ins in block['ops']):
            block['ops'].append({'op': 'call', 'args': [], 'out': [],
                                          'attrs': {'function': 'missing_function'}})
            break
    else:
        raise AssertionError('missing task.close fixture')
    owner = _Elaborator(deepcopy(broken))
    try:
        owner.function(owner.document['functions'][0])
    except HIAProgramRejected as exc:
        code, result = first(broken)
        assert code == 65 and len(result) == 64
        magic, action, error, phase, serial, slots, request, delegate = FRAME.unpack(result)
        assert (magic, action, delegate) == (b'HIAFBL01', 1, 0)
        assert request > 0 and phase < 2000
        assert (serial, slots) == (owner.serial, owner.value_slots)
        assert FUNCTION_ERRORS[error][0] == exc.code
        assert FUNCTION_ERRORS[error][1] in str(exc)
    else:
        raise AssertionError('hosted function did not reject the missing callee')
    assert owner.helpers, 'missing callee must be reached after real helper generation'

    wrong = task_program()
    wrong['functions'][0]['blocks'][0]['params'][0]['type'] = 'Missing'
    assert first(wrong) == (65, FRAME.pack(b'HIAFBL01', 1, 999, 2, 0, 0, 1, 18))
    print(f'{len(samples)} exact lowered Core function packets, {requests} automatic dependent requests, '
          f'{helper_count} generated helper functions, and two refusal stages with no partial output')


def check_modules(run):
    def module(raw, *, legacy=False):
        return run(raw, legacy=legacy, flags=5, handoff=True)

    root = Path(__file__).resolve().parents[1]
    checked = [(name, doc, legacy) for name, doc, legacy, status in cases()
               if not status[0] and name != 'multi-chunk']
    examples = (
        'examples/hia_program/cooperative_task.hepta',
        'examples/hia_program/generic_owned_enum.hepta',
        'examples/hia_program/partial_record.hepta',
        'examples/hia_program/stored_loan_record.hepta',
        'examples/hia_recursive_chain/composite_v2.hepta',
    )
    samples = [
        (name, json.dumps(doc, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode(), legacy)
        for name, doc, legacy in checked]
    samples += [(path, (root / path).read_bytes(), False) for path in examples]
    ordinary_count, helper_count = 0, 0
    for name, raw, legacy in samples:
        document = json.loads(raw)
        owner = _Elaborator(document, legacy=legacy)
        expected = owner.lower()
        payload = transport(expected)
        # The oracle still runs ordinary primitive verification; elaboration
        # alone neither grants execution authority nor mutates the source.
        verify_core(expected)
        code, result = module(raw, legacy=legacy)
        count, helpers = len(document['functions']), len(owner.helpers)
        assert code == 0, (name, code)
        assert FRAME.unpack_from(result) == (b'HIAOMF01', 2, 0, 2000, count, 0, count, helpers), name
        assert FRAME.unpack_from(result, 64) == (
            b'HIAOTP01', count, len(payload), count, helpers, owner.serial, 0, 0), name
        assert result[128:] == payload, name
        ordinary_count += count
        helper_count += helpers

    # A later function may reject after prior functions are already retained;
    # the outer status contains its delegate, not a partial Core program.
    broken = task_program()
    broken['functions'][-1]['blocks'] = []
    raw = json.dumps(broken, separators=(',', ':')).encode()
    code, result = module(raw)
    assert code == 65 and len(result) == 128
    assert FRAME.unpack_from(result) == (b'HIAOMF01', 1, 999, 2000, 3, 0, 2, 0)
    magic, action, error, phase, _serial, _slots, request, delegate = FRAME.unpack_from(result, 64)
    assert (magic, action, error, phase, delegate) == (b'HIAFBL01', 1, 1, 0, 0)
    assert request > 0

    for name, document, legacy, status in cases():
        if status[0]:
            raw = json.dumps(document, separators=(',', ':')).encode()
            assert module(raw, legacy=legacy) == run(raw, legacy=legacy), name
    print(f'{len(samples)} exact complete nominal modules ({len(examples)} repository sources), '
          f'{ordinary_count} ordinary functions, {helper_count} helpers, '
          'and four failure prefixes without partial Core')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--oracle-images', type=Path, required=True)
    args = parser.parse_args()
    check(args.executable, args.oracle_images)
