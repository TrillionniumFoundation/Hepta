"""Post-restart first-pass differential against the untouched whole function.

The reference runs until its actual second-pass line; no hosted source admission
algorithm is reimplemented by this test. Native service calls remain native.
"""
from copy import deepcopy
import ctypes
import inspect
import os
import struct
import sys
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_functions_native import installed_composite_functions, WORKSPACE_BYTES, OUTPUT_BYTES
from hepta.hia_composite_types_native import installed_composite_types, SESSION_BYTES
from hepta.hia_composite_functions_errors import ERRORS
from hepta.hia_composite_function_tokens import ObjectTokenDecoder, detached_packet_index
from hepta.hia_instruction_policy_native import transport
from hepta.hia_program import HIAProgramRejected
from tests.test_hia_program import b, f, i, ret
from tests.test_hia_program_composite import record
from tests.test_hia_composite_returned_loans import v4

ADMIT = int.from_bytes(b'HIAFAD01', 'little')
RESPONSE = int.from_bytes(b'HIAFRS01', 'little')
STREAM = int.from_bytes(b'HIAFNC01', 'little')


class PassTwoReached(Exception):
    pass


def reference_pass_one(owner):
    method = composite._Elaborator._reference_function
    source, first = inspect.getsourcelines(method)
    boundary = first + next(n for n, line in enumerate(source) if line == '        result = []\n')
    def trace(frame, event, arg):
        if frame.f_code is method.__code__ and event == 'line' and frame.f_lineno == boundary:
            raise PassTwoReached()
        return trace
    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        method(owner, owner.document['functions'][0])
    except PassTwoReached:
        return None
    except HIAProgramRejected as error:
        return error
    finally:
        sys.settrace(previous)
    raise AssertionError('oracle did not reach its actual second pass')


class AdmissionHarness:
    def __init__(self, owner, images):
        self.owner, self.images, self.types = owner, images, owner.native_types
        registry = [[name, [[n, self.types._ids[id(t)]] for n, t in params],
                     [self.types._ids[id(t)] for t in returns]]
                    for name, (params, returns) in owner.signatures.items()]
        wire = transport([owner.document, registry, list(owner.return_origins.items()),
                          owner.serial, owner.value_slots, False, 0])
        _, self.sources = detached_packet_index(wire)
        self.workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self.error = None
        self.invoke(wire)

    def decode(self, size):
        if size != 64: raise AssertionError(('admission ABI', size))
        frame = struct.unpack_from('<8Q', self.output)
        if frame[0] != ADMIT or frame[-1]: raise AssertionError(('frame', frame))
        self.owner.serial, self.owner.value_slots = frame[4:6]
        return frame

    def invoke(self, wire):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        size = self.images['admit']._entry(source, len(wire), self.output,
            OUTPUT_BYTES, self.workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire: raise AssertionError('source mutation')
        return self.decode(size)

    def run(self):
        while True:
            with self.types._lock:
                size = self.images['admit']._entry(self.types._state, SESSION_BYTES, self.output,
                    OUTPUT_BYTES, self.workspace, WORKSPACE_BYTES)
            frame = self.decode(size)
            action, error, request = frame[1], frame[2], frame[6]
            if action == 10: return None
            if action == 1:
                if error == 999:
                    if self.error is None: raise AssertionError('unissued service refusal')
                    return self.error
                code, message = ERRORS[error]
                return HIAProgramRejected(message, code)
            if action != 2: raise AssertionError(('transition', frame))
            decoder, sequence = ObjectTokenDecoder(self.sources), 0
            while not decoder.complete:
                size = self.images['render']._entry(self.types._state, SESSION_BYTES, self.output,
                    OUTPUT_BYTES, self.workspace, WORKSPACE_BYTES)
                if not 64 <= size <= OUTPUT_BYTES: raise AssertionError(('stream ABI', size))
                chunk = struct.unpack_from('<8Q', self.output)
                if chunk[:3] != (STREAM, 2, sequence) or chunk[6] != request or chunk[7] != size - 64:
                    raise AssertionError(('stream correlation', chunk))
                decoder.feed(ctypes.string_at(ctypes.addressof(self.output) + 64, size - 64), final=bool(chunk[3]))
                sequence += 1
            command = decoder.root
            if type(command) is not list or len(command) != 2 or command[0] != 2:
                raise AssertionError('not a typed parameter request')
            ids, status = [], 0
            try:
                values = self.types.parameters(command[1])
                ids = [self.types._ids[id(typ)] for _, typ in values]
            except HIAProgramRejected as error:
                self.error, status = error, 1
            response = struct.pack('<4Q', RESPONSE, request, status, len(ids))
            resumed = self.invoke(response + b''.join(struct.pack('<Q', ident) for ident in ids))
            if resumed[1] == 1:
                if resumed[2] != 999 or self.error is None:
                    raise AssertionError('invalid delegated refusal transition')
                return self.error


class AdmissionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.images = fixture.bundle.images
        cls.types_image = fixture.types_image

    def owner(self, document):
        with patch('hepta.hia_composite_types_native.selected_composite_types',
                   new=lambda definitions, **flags: self.types_image.session(definitions, **flags)), \
             patch('hepta.hia_composite_functions_native.selected_composite_functions', new=lambda: None), \
             patch('hepta.hia_task_helpers_native.selected_task_helpers', new=lambda: None):
            return composite._Elaborator(document)

    def compare(self, document, serial=0, slots=0):
        expected, actual = self.owner(deepcopy(document)), self.owner(deepcopy(document))
        expected.serial = actual.serial = serial
        expected.value_slots = actual.value_slots = slots
        harness = None
        try:
            left = reference_pass_one(expected)
            harness = AdmissionHarness(actual, self.images)
            right = harness.run()
            observe = lambda error: None if error is None else (error.code, str(error))
            self.assertEqual(observe(right), observe(left))
            self.assertEqual((actual.serial, actual.value_slots), (expected.serial, expected.value_slots))
            self.assertEqual(actual.types.observations, expected.types.observations)
            self.assertEqual(actual.document, document)
        finally:
            if harness is not None: harness.workspace = harness.output = None
            expected.types.close(); actual.types.close()

    def test_complete_first_pass_error_order_matrix(self):
        base = v4([], f('main', [], [], [], [b('entry', [], [], ret())]))
        cases = [('valid', base)]
        def edit(label, operation):
            document = deepcopy(base)
            operation(document['functions'][0])
            cases.append((label, document))
        for value in (None, 0, [], [{}] * 4097):
            edit('block inventory', lambda fn, value=value: fn.update(blocks=value))
        for value in (None, 0, {}, {'id': 'entry'},
                      {'id': 'entry', 'params': [], 'ops': [], 'term': ret(), 'extra': 1}):
            edit('block shape', lambda fn, value=value: fn.update(blocks=[value]))
        for name in ('', None, 'bad name', 'h2internal_reserved', '__hia_reserved'):
            edit('block name', lambda fn, name=name: fn['blocks'][0].update(id=name))
        edit('duplicate block', lambda fn: fn['blocks'].append(deepcopy(fn['blocks'][0])))
        for value in (None, 0, {}, 'ops'):
            edit('operations shape', lambda fn, value=value: fn['blocks'][0].update(ops=value))
        for value in (None, 0, {}, {'op': 'const'},
                      {'op': None, 'args': [], 'out': [], 'attrs': {}},
                      {'op': 'const', 'args': [], 'out': [], 'attrs': None},
                      {'op': 'record.unknown', 'args': [], 'out': [], 'attrs': {}},
                      {'op': 'const', 'args': None, 'out': [], 'attrs': {}},
                      {'op': 'const', 'args': ['bad name'], 'out': [], 'attrs': {}},
                      {'op': 'const', 'args': [], 'out': [{'name': 'x', 'type': 'Missing'}], 'attrs': {}}):
            edit('instruction', lambda fn, value=value: fn['blocks'][0].update(ops=[value]))
        for entry in ('', None, 'missing', 'h2internal_reserved'):
            edit('entry', lambda fn, entry=entry: fn.update(entry=entry))
        edit('delayed duplicate before later type error', lambda fn: fn['blocks'][0].update(ops=[
            i('const', [], [('same', 'u8')], value=0), i('const', [], [('same', 'u8')], value=1),
            i('const', [], [('late', 'Missing')], value=2)]))
        edit('duplicate after block', lambda fn: fn['blocks'][0].update(ops=[
            i('const', [], [('same', 'u8')], value=0), i('const', [], [('same', 'u8')], value=1)]))
        edit('entry parameter mismatch', lambda fn: fn['blocks'][0].update(params=[{'name': 'x', 'type': 'u8'}]))
        for index, (label, document) in enumerate(cases):
            with self.subTest(index=index, label=label): self.compare(document)

    def test_fresh_slot_and_zero_width_boundaries(self):
        params = [('x', 'Pair')]
        document = v4([record('Pair', [('a', 'u8'), ('b', 'u8')])],
            f('main', params, [], [], [b('entry', params, [], ret())]))
        self.compare(document, serial=8191)
        self.compare(document, slots=32767)
        params = [('x', 'Empty')]
        document = v4([record('Empty', [])], f('main', params, [], [], [b('entry', params, [], ret())]))
        self.compare(document, serial=8192, slots=32768)
        document['functions'][0]['blocks'][0]['ops'] = 0
        self.compare(document, serial=8192, slots=32768)


if __name__ == '__main__':
    unittest.main()
