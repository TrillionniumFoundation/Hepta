"""Independent VM witnesses; complete originals supply semantic expectations."""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

# Resolve the independent VM before the oracle installs isolated provider modules.
from hepta import hia_program_runtime as _runtime

CASES = (
    'inspect-summary-outer-0',
    'inspect-dependencies-outer-0',
    'inspect-view-block-outer-0',
    'candidate-import-hia-asm.v1-outer-0',
    'candidate-reference-patch-outer-0',
    'candidate-native-patch-none-result-outer-0',
)


def vm_call(program, request, output, retained):
    _Machine, _Owner, _View = _runtime._Machine, _runtime._Owner, _runtime._View
    owners = [_Owner(index + 1, bytearray(value))
              for index, value in enumerate((request, output, retained))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
        [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != request:
        raise AssertionError('VM changed the immutable request')
    return code, bytes(owners[1].data), bytes(owners[2].data)


def image_for_vm(program):
    from hepta import hia_service_inspection_native as native
    image = object.__new__(native.NativeServiceInspection)
    image.image_sha256 = 'independent-VM-without-executable-mapping'
    image.entries = 0
    def entry(source, size, output, capacity, state, extent):
        code, answer, retained = vm_call(program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, answer, capacity)
        ctypes.memmove(state, retained, extent)
        image.entries += 1
        return code
    image._entry = entry
    return image


def observe_six(image):
    from tests.hia_service_inspection_oracle import DIRECTORY, canonical, observe_case
    from hepta import hia_service_inspection_native as native
    document = json.loads((DIRECTORY / 'cases.json').read_bytes())
    cases = {case['id']: case for case in document['cases']}
    # Every expected result is observed before the first candidate invocation.
    expected = {name: observe_case(cases[name])[0] for name in CASES}
    def owner(mode, service, arguments, namespace, original_code):
        return native.ServiceInspectionFrame(image, mode, service, arguments,
            namespace=namespace, global_builtins=namespace['__builtins__'],
            local_names=original_code.co_varnames + original_code.co_cellvars).finish()
    rows = []
    for name in CASES:
        actual, raw_traceback = observe_case(cases[name], owner)
        row = {'case_id': name, 'original': expected[name], 'candidate': actual,
               'candidate_raw_traceback': raw_traceback,
               'canonical_equal': canonical(expected[name]) == canonical(actual)}
        rows.append(row)
    return rows


def protocol_witnesses(image, program):
    """Actual native and VM must agree on all request/output/state bytes."""
    from hepta import hia_service_inspection_protocol as protocol
    entries = []
    def invoke(words, state=bytes(protocol.STATE_BYTES)):
        request = struct.pack('<16Q', *words)
        answer = bytes(protocol.OUTPUT_BYTES)
        expected = vm_call(program, request, answer, state)
        source, output, retained = [ctypes.create_string_buffer(value, len(value))
                                   for value in (request, answer, state)]
        code = image._entry(source, len(request), output, len(answer), retained, len(state))
        actual = code, output.raw, retained.raw
        assert source.raw == request and actual == expected
        entries.append({'request_hex': request.hex(), 'prior_state_hex': state.hex(),
            'return': code, 'output_hex': output.raw.hex(), 'state_hex': retained.raw.hex(),
            'actual_all_buffers_equal_VM': True})
        return actual
    for mode in (protocol.INSPECT, protocol.CANDIDATE):
        initial = [protocol.REQUEST_MAGIC, 0, 0, 0, 0, mode, 17, 29, *([0] * 8)]
        code, answer, initial_state = invoke(initial)
        first = protocol.PORT['inspect_import' if mode == protocol.INSPECT else 'candidate_assemble_import']
        receipt = struct.unpack('<12Q', answer)
        assert code == protocol.OUTPUT_BYTES and receipt[1:7] == (0, first, 1, protocol.ISSUED, mode, 0)
        claim = [protocol.REQUEST_MAGIC, 1, 1, first, 0, mode, 17, 29, *([0] * 8)]
        _, answer, claimed = invoke(claim, initial_state)
        assert struct.unpack('<12Q', answer)[4] == protocol.CLAIMED
        _, answer, raised = invoke(
            [protocol.REQUEST_MAGIC, 3, 1, first, 0, mode, 17, 29, *([0] * 8)], claimed)
        assert struct.unpack('<12Q', answer)[2:7] == (0, 2, protocol.READY_PROPAGATE, mode, 1)
        _, answer, final = invoke(
            [protocol.REQUEST_MAGIC, 4, 2, 0, 0, mode, 17, 29, *([0] * 8)], raised)
        assert struct.unpack('<12Q', answer)[2:7] == (0, 3, protocol.PROPAGATE, mode, 1)
        for name, changed in (
                ('foreign_nonce', {6: 99}), ('wrong_sequence', {2: 2}),
                ('wrong_port', {3: first + 1}), ('claim_observation', {4: 1}),
                ('unclaimed_ACK', {1: 2}), ('unknown_event', {1: 99})):
            words = list(claim)
            for index, value in changed.items():
                words[index] = value
            code, answer, after = invoke(words, initial_state)
            assert code == protocol.OUTPUT_BYTES and struct.unpack('<12Q', answer)[1] == 1
            # A valid-state refusal writes the protocol's terminal refusal.
            # It does not preserve the issued state's port/phase/checksum.
            refused = list(struct.unpack('<24Q', initial_state))
            refused[3], refused[5] = 0, protocol.REFUSED
            checksum = 1469598103934665603
            for index, word in enumerate(refused):
                if index != 10:
                    checksum = (((checksum << 7) | (checksum >> 57)) & ((1 << 64) - 1)) ^ word
            refused[10] = checksum
            assert after == struct.pack('<24Q', *refused)
        damaged = bytearray(initial_state); damaged[80] ^= 1
        code, _, after = invoke(claim, bytes(damaged))
        assert code != protocol.OUTPUT_BYTES and after == bytes(damaged)
        for index, value in ((0, 0), (5, 0), (8, 1)):
            packet = list(initial); packet[index] = value
            code, _, after = invoke(packet)
            assert code != protocol.OUTPUT_BYTES and after == bytes(protocol.STATE_BYTES)
    return {'entries': entries, 'actual_entry_count': len(entries),
            'all_complete_buffers_match_VM': True, 'handwritten_business_expected': False}
