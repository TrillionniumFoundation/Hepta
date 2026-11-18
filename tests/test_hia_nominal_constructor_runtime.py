"""Compare the installed constructor with the existing bound callback route."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from hepta.hia_composite_constructor_errors import ERRORS as CONSTRUCTOR_ERRORS
from hepta.hia_composite_constructor_native import NativeConstructorInvocation
from hepta.hia_composite_function_tokens import ObjectTokenDecoder, detached_packet_index
from hepta.hia_composite_types_native import ERRORS as TYPE_ERRORS, NativeCompositeTypes
from hepta.hia_instruction_policy_native import transport
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program import HIAProgramRejected
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
    def run(raw, *, digits=4300, legacy=False, count=None, flags=0, trailer=b''):
        length = len(raw) if count is None else count
        request = FRAME.pack(b'HIACSX01', digits, int(legacy), length, flags, 0, 0, 0)
        result = subprocess.run([executable], input=request + raw + trailer, capture_output=True,
                                env={'PATH': ''}, timeout=20, check=False)
        assert not result.stderr
        return result.returncode, result.stdout

    requests, documents, kinds = 0, 0, set()
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
    print(f'{documents} exact constructor completions and failure prefixes; '
          f'{requests} dependent requests across all five kinds; seven raw framing controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--oracle-images', type=Path, required=True)
    args = parser.parse_args()
    check(args.executable, args.oracle_images)
