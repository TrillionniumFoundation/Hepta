"""Selected HIA policy over detached, freshly verified primitive Core facts.

Encoding preserves names, types, operation names, cast mode and edge targets.
It performs no profile classification, export inference, budget sum, graph
construction or ABI sorting. Core verification and totality proofs remain in
the original caller; this component grants neither proof nor publication.
The runtime's public constructor requires an exact Boolean prove_total choice;
equivalence for arbitrary effectful Python truth-value objects is not claimed.
"""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/scalar_profile.hepta')
SCHEMA = 'hepta.hia.scalar-profile-native.v1'
SELECTOR = 'HEPTA_HIA_SCALAR_PROFILE_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIASCP01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASCR01', 'little')
STATE_BYTES = 8192
OUTPUT_BYTES = 144
REASONS = {
    1: 'native lifecycle requires the qualified primitive v1-v7 proof profile',
    2: 'finite profile requires one to sixteen functions',
    3: 'every function must be an exported scalar function',
    4: 'only effect-free scalar signatures with one scalar result are admitted',
    5: 'finite block/instruction budget exceeded',
    6: 'resource block parameters are outside the scalar profile',
    7: 'instruction may trap, allocate, call or escape the total scalar profile',
    8: 'trapping terminators are outside the total scalar profile',
    9: 'cyclic control flow is outside the total scalar profile',
}


def _word(value):
    return struct.pack('<Q', value)


def _text(value):
    raw = value.encode('utf-8')
    return _word(len(raw)) + raw


def _sequence(values):
    return _word(len(values)) + b''.join(_text(value) for value in values)


def _frame(raw):
    return _word(len(raw)) + raw


def header(program, data, *, prove_total=False, phase=0):
    """Only metadata is observed until HIA asks for the complete Core facts."""
    return (struct.pack('<7Q', REQUEST_MAGIC, int(program.structured_bytes is not None),
                        int(bool(prove_total)), int('exports' in data), len(data['functions']),
                        len(data.get('exports', ())), phase) + _text(data['schema']))


def packet(program, data, *, prove_total=False):
    """Transport original verified facts; no native-profile predicate lives here."""
    functions = []
    for function in data['functions']:
        blocks = []
        for block in function['blocks']:
            operations = []
            for operation in block['ops']:
                mode = operation['attrs'].get('mode')
                # A generic foreign string tag preserves whether this field is
                # a string. Only HIA decides whether the opcode requires wrap.
                is_text = type(mode) is str
                operations.append(_frame(_text(operation['op'])
                    + _sequence([value['type'] for value in operation['out']])
                    + _word(int(is_text)) + _text(mode if is_text else '')))
            term = block['term']
            body = (_text(block['id']) + _sequence([value['type'] for value in block['params']])
                    + _word(len(operations)) + b''.join(operations)
                    + _text(term['op']) + _text(term.get('target', ''))
                    + _text(term.get('then', {}).get('target', ''))
                    + _text(term.get('else', {}).get('target', '')))
            blocks.append(_frame(body))
        body = (_text(function['name']) + _sequence([value['type'] for value in function['params']])
                + _sequence(function['returns']) + _sequence(function['effects'])
                + _word(len(blocks)) + b''.join(blocks))
        functions.append(_frame(body))
    exports = data.get('exports', ())
    return (header(program, data, prove_total=prove_total, phase=1)
            + b''.join(_text(name) for name in exports)
            + b''.join(functions))


class NativeScalarProfile(NativeHiaJsonImage):
    def decision(self, wire):
        if type(wire) is not bytes:
            raise TypeError('scalar profile requires exact verified-fact bytes')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        initial = b'\xa5' * OUTPUT_BYTES
        output = ctypes.create_string_buffer(initial, OUTPUT_BYTES)
        state = ctypes.create_string_buffer(STATE_BYTES)
        result = self._entry(source, len(wire), output, OUTPUT_BYTES, state, STATE_BYTES)
        if (type(result) is not int or result not in (0, *REASONS, 16, 17)
                or source.raw != (wire or b'\0')):
            raise RuntimeError('invalid scalar profile ABI or changed verified facts')
        if result:
            if output.raw != initial:
                raise RuntimeError('refused scalar profile published output')
            return result, ()
        magic, count = struct.unpack_from('<2Q', output.raw)
        if magic != RESULT_MAGIC or not 1 <= count <= 16:
            raise RuntimeError('invalid scalar profile result identity')
        indices = struct.unpack_from('<' + 'Q' * count, output.raw, 16)
        if (len(set(indices)) != count or any(index >= count for index in indices)
                or output.raw[16 + count * 8:] != initial[16 + count * 8:]):
            raise RuntimeError('invalid scalar profile ABI permutation')
        return 0, indices

    def admit(self, program, data, *, prove_total=False):
        from .hia_multiversion import ScalarABI, _reject
        preliminary, _ = self.decision(header(program, data, prove_total=prove_total))
        if preliminary in REASONS:
            _reject(REASONS[preliminary])
        if preliminary != 17:
            raise RuntimeError('native scalar profile refused its metadata continuation')
        result, indices = self.decision(packet(program, data, prove_total=prove_total))
        if result in (16, 17):
            raise RuntimeError('native scalar profile refused its verified-fact transport')
        if result:
            _reject(REASONS[result])
        functions = data['functions']
        if len(indices) != len(functions):
            raise RuntimeError('native scalar profile changed the function inventory')
        # Materialization follows HIA's complete accepted order and signatures.
        return tuple(ScalarABI(functions[index]['name'],
                               tuple(value['type'] for value in functions[index]['params']),
                               functions[index]['returns'][0]) for index in indices)


def installed_scalar_profile(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeScalarProfile)


def selected_scalar_profile(program, data, *, prove_total=False):
    path = os.environ[SELECTOR]
    if not path:
        raise ValueError('scalar profile selector must not be empty')
    return installed_scalar_profile(path).admit(program, data, prove_total=prove_total)
