"""Actual HIA/independent-VM physical frame protocol controls.

Forced profile words test the transport ABI, not execution on another Python.
The separate original lifetime methods remain the real-interpreter oracle.
"""
import ctypes
from hashlib import sha256
import struct


def profile_matrix(test, owner, frame_class, source, mode, arguments, expected_value):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    program = assemble_program(source.read_bytes())
    function = program.as_dict()['functions'][0]
    native_entry = owner._entry
    frames, issued, rows = [], [], []

    def entry(source_buffer, source_size, output, output_size, workspace, workspace_size):
        before = [ctypes.string_at(ptr, size) for ptr, size in (
            (source_buffer, source_size), (output, output_size), (workspace, workspace_size))]
        guards = [ctypes.create_string_buffer(b'Z' * 16 + value + b'Y' * 16,
                                             len(value) + 32) for value in before]
        actual = native_entry(ctypes.addressof(guards[0]) + 16, source_size,
                              ctypes.addressof(guards[1]) + 16, output_size,
                              ctypes.addressof(guards[2]) + 16, workspace_size)
        memory = [_Owner(-1-index, bytearray(value)) for index, value in enumerate(before)]
        vm = _Machine(program, 20_000_000, 64 << 20, None, 128)
        expected = vm.invoke(function, [_View(memory[0], False),
            _View(memory[1], True), _View(memory[2], True)])[0]
        test.assertEqual(actual, expected)
        for guard, value in zip(guards, memory):
            test.assertEqual(guard.raw[:16], b'Z' * 16)
            test.assertEqual(guard.raw[-16:], b'Y' * 16)
            test.assertEqual(guard.raw[16:-16], bytes(value.data))
        test.assertEqual(guards[0].raw[16:-16], before[0])
        ctypes.memmove(output, guards[1].raw[16:-16], output_size)
        ctypes.memmove(workspace, guards[2].raw[16:-16], workspace_size)
        command, profile = struct.unpack_from('<Q', before[2])[0], struct.unpack_from('<Q', before[2], 40)[0]
        row = {'command': command, 'profile': profile, 'return': actual,
               'source_bytes': source_size, 'output_bytes': output_size,
               'workspace_bytes': workspace_size,
               'output_sha256': sha256(guards[1].raw[16:-16]).hexdigest(),
               'workspace_sha256': sha256(guards[2].raw[16:-16]).hexdigest()}
        if actual == 1:
            head = struct.unpack_from('<10Q', guards[1].raw, 16)
            if head[9] in (5, 6):
                request = {'request': head[9], 'slot': struct.unpack_from('<Q', guards[1].raw, 16+128)[0]}
                issued.append(request); row.update(request)
        frames.append(row)
        return actual

    owner._entry = entry
    try:
        _, slots, _, metadata = owner.function(mode)
        flags = owner.table[metadata:metadata+slots]
        expected_named = [i for i, flag in enumerate(flags) if not flag & 1 or flag & 2]
        test.assertGreaterEqual(len(expected_named), 3)
        for profile in (312, 313, 314):
            frame = frame_class(owner, mode, arguments)
            frame._runtime_profile = profile  # Explicit private ABI injection.
            start = len(frames)
            test.assertEqual(frame.drive(), 0)
            test.assertEqual(frame.take(), expected_value)
            births = [struct.unpack_from('<Q', frame.state, 1024 + index*8)[0]
                      for index in range(slots)]
            expected_temporaries = [index for index in sorted(range(slots),
                                      key=lambda i: births[i], reverse=True) if births[index]]
            from hepta.hia_machine_plan_control_native import _EMPTY
            live_named = [i for i in expected_named if frame.values[i] is not _EMPTY]
            empty_named = [i for i in expected_named if frame.values[i] is _EMPTY]
            test.assertGreaterEqual(len(live_named), 2)
            issued.clear()
            frame.close()
            actual_temporaries = [row['slot'] for row in issued if row['request'] == 5]
            actual_named = [row['slot'] for row in issued if row['request'] == 6]
            named = list(reversed(expected_named)) if profile == 314 else expected_named
            test.assertEqual(actual_temporaries, expected_temporaries)
            test.assertEqual(actual_named, named)
            test.assertTrue(all(row['request'] == 5 for row in issued[:len(expected_temporaries)]))
            test.assertLess(len(actual_named), slots)
            test.assertTrue(frame._retired)
            rows.append({'profile': profile, 'actual_calls': len(frames)-start,
                         'remaining_births': births, 'temporary_retirement': actual_temporaries,
                         'named_retirement': actual_named, 'live_named_before_close': live_named,
                         'empty_named_before_close': empty_named, 'total_slots': slots,
                         'omitted_proven_empty_noncell_slots': slots-len(actual_named)})
        test.assertEqual(rows[0]['named_retirement'], rows[1]['named_retirement'])
        test.assertEqual(rows[2]['named_retirement'], list(reversed(rows[0]['named_retirement'])))
        for invalid in (0, 1, 311, 315, 400, (1 << 64)-1):
            workspace = ctypes.create_string_buffer(owner.workspace_bytes)
            output = ctypes.create_string_buffer(b'Q' * 2048, 2048)
            struct.pack_into('<6Q', workspace, 0, 0, 987654321, 0, mode, 0, invalid)
            before = bytes(workspace)
            status = entry(owner._table_buffer, len(owner.table), output, len(output), workspace, len(workspace))
            test.assertEqual(status, 0xfffffffd)
            test.assertEqual(bytes(output), b'Q' * 2048)
            test.assertEqual(bytes(workspace), before)
        frame = frame_class(owner, mode, arguments)
        test.assertEqual(frame.step(), 1)
        original = bytes(frame.state)
        copied = ctypes.create_string_buffer(original, len(original))
        sequence = struct.unpack_from('<Q', original, 144)[0]
        operation = struct.unpack_from('<Q', frame.pending.raw, 32)[0]
        alternate = 314 if frame._runtime_profile != 314 else 312
        struct.pack_into('<6Q', copied, 0, 2, frame.nonce, sequence, operation, 0, alternate)
        output = ctypes.create_string_buffer(b'X' * 2048, 2048)
        before = bytes(copied)
        status = entry(owner._table_buffer, len(owner.table), output, len(output), copied, len(copied))
        test.assertEqual(status, 0xfffffffd)
        test.assertEqual(bytes(copied), before)
        test.assertEqual(bytes(output), b'X' * 2048)
        test.assertEqual(bytes(frame.state), original)
        frame.service(frame.pending)
        status = frame.step()
        while status == 1:
            frame.service(frame.pending); status = frame.step()
        test.assertEqual(status, 0)
        test.assertEqual(frame.take(), expected_value)
        frame.close()
    finally:
        owner._entry = native_entry
    return {'scope': 'THREE_EXPLICIT_PRIVATE_ABI_PROFILES_NOT_THREE_INTERPRETERS',
            'source_sha256': sha256(source.read_bytes()).hexdigest(),
            'image_sha256': owner.image_sha256, 'profiles': rows, 'frames': frames,
            'invalid_profiles': [0, 1, 311, 315, 400, (1 << 64)-1],
            'pending_profile_drift_refused_before_effect': True}
