"""Exact v8 reference and current Slot word paths under the original VM limits.

Each invocation owns fresh machine state and buffers. Only immutable verified
metadata is prepared; no execution result is reused. These source controls do
not replace original248/derived7574, Native, or actual resource qualification.
Word operations retain their specified one-tick cost. Equal interruptions for
every smaller VM step budget are deliberately not claimed.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import struct
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program_runtime import HIAProgramTrap, _Machine, _Owner, _View
from hepta.hia_program_runtime_prepared import prepare_runtime_program
from tools import generate_hia_slot_operations as generator


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / 'tests/fixtures/slot_operations_word_memory_v8.json'
AUTHORITY_PIN = {'bytes': 1854, 'sha256': '327179a0ee72a74f13bfeeea32af25c784a4ac7c55b87ce1dc5c64e6e20b9d98'}
MASK = (1 << 64) - 1
LENGTHS = (*range(10), 15, 16, 17, 23, 24, 31, 32, 96, 192)
WORD_INDICES = (0, 1, 2, 3, 11, 23, (1 << 32) + 1, 1 << 61, (1 << 61) + 1, MASK)
VALUES = (0, 0x0123456789ABCDEF, MASK)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class SlotWordMemorySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_path = ROOT / generator.SOURCE_NAME
        cls.source_before = cls.source_path.read_bytes()
        cls.authority_before = AUTHORITY.read_bytes()
        if pin(cls.authority_before) != AUTHORITY_PIN:
            raise AssertionError('fixed complete original Slot word authority changed')
        cls.authority = json.loads(cls.authority_before)
        cls.documents = (generator.document(word_memory=False), generator.document())
        raw = tuple(render_assembly(document).encode() for document in cls.documents)
        if pin(raw[0]) != {key: cls.authority['original_source'][key] for key in ('bytes', 'sha256')}:
            raise AssertionError('retained v8 generator no longer restores the full original source')
        if raw[1] != cls.source_before:
            raise AssertionError('actual current Slot source differs from its v9 authoring')
        cls.programs = tuple(prepare_runtime_program(assemble_program(value)) for value in raw)
        names = [node.name for node in ast.parse(generator.source_program(word_memory=False)).body]
        if names != cls.authority['retained_protocol']['functions']:
            raise AssertionError('complete original Slot function inventory changed')
        cls.names = {name: 'f' + str(index) for index, name in enumerate(names)}

    @classmethod
    def tearDownClass(cls):
        if cls.source_path.read_bytes() != cls.source_before or AUTHORITY.read_bytes() != cls.authority_before:
            raise AssertionError('Slot word source or immutable original authority changed during controls')

    def invoke(self, program, name, buffers, scalars=()):
        owners = [_Owner(index + 1, bytearray(raw)) for index, (raw, _) in enumerate(buffers)]
        arguments = [_View(owner, mutable) for owner, (_, mutable) in zip(owners, buffers)]
        arguments.extend(scalars)
        machine = _Machine(program, 4_000_000, 16 << 20, None, 128)
        try:
            result = machine.invoke(machine.functions[self.names[name]], arguments)
            outcome = ('returned', tuple(result))
        except HIAProgramTrap as error:
            outcome = ('trapped', type(error), error.code, str(error))
        return (outcome, tuple(bytes(owner.data) for owner in owners), machine.resources()), machine.steps

    def compare(self, name, buffers, scalars=()):
        old, old_steps = self.invoke(self.programs[0], name, buffers, scalars)
        new, new_steps = self.invoke(self.programs[1], name, buffers, scalars)
        self.assertEqual(new, old)
        return new, old_steps, new_steps

    def test_00_original_source_exact_and_only_three_guarded_helpers_change(self):
        self.assertEqual(pin(generator.PROTOCOL.encode()),
                         {key: self.authority['retained_protocol'][key] for key in ('bytes', 'sha256')})
        old, new = self.documents
        self.assertEqual(old['schema'], 'hepta.hia.program.v8')
        self.assertEqual(new['schema'], 'hepta.hia.program.v9')
        self.assertEqual(old['module'], new['module'])
        self.assertEqual(len(old['functions']), 31)
        self.assertEqual(len(new['functions']), 31)
        changed = {self.names[name] for name in ('read_word', 'get', 'set')}
        for before, after in zip(old['functions'], new['functions']):
            self.assertEqual(before['name'], after['name'])
            if before['name'] not in changed:
                self.assertEqual(before, after)
            else:
                for field in ('name', 'params', 'returns', 'effects', 'entry'):
                    self.assertEqual(before[field], after[field])
                word_ops = [op['op'] for block in after['blocks'] for op in block['ops']
                            if op['op'].startswith(('buffer.load.u64.', 'buffer.store.u64.'))]
                self.assertEqual(word_ops, ['buffer.store.u64.le'] if after['name'] == self.names['set']
                                 else ['buffer.load.u64.le'])
                # The old per-byte path remains in each helper for short tails.
                old_bytes = [op['op'] for block in before['blocks'] for op in block['ops']
                             if op['op'] in ('buffer.load', 'buffer.store')]
                new_bytes = [op['op'] for block in after['blocks'] for op in block['ops']
                             if op['op'] in ('buffer.load', 'buffer.store')]
                self.assertEqual(new_bytes, old_bytes)
        self.assertEqual(self.authority['original_vm_limits'],
                         {'max_steps': 4_000_000, 'max_heap_bytes': 16 << 20, 'max_call_depth': 128})
        self.assertEqual(self.authority['original_complete_groups'],
                         {'original248': 248, 'derived7574': 7574, 'total_seconds': 1800})
        self.assertFalse(self.authority['resource_contract']['claims_arbitrary_step_budget_equivalence'])
        for value in (None, 0, 1, 'v9', (), []):
            with self.subTest(selection=repr(value)), self.assertRaises(ValueError):
                generator.document(word_memory=value)

    def test_01_complete_words_short_tails_offsets_wrap_and_partial_store_prefixes(self):
        count = 0
        for length in LENGTHS:
            raw = bytes((index * 29 + 17) & 255 for index in range(length))
            indices = sorted({0, 1, max(0, length - 8), max(0, length - 7),
                              length, length + 1, (1 << 32) + 1, MASK})
            for name, positions in (('read_word', indices), ('get', WORD_INDICES), ('set', WORD_INDICES)):
                for index in positions:
                    for value in (VALUES if name == 'set' else (None,)):
                        with self.subTest(name=name, length=length, index=index, value=value):
                            scalars = (index, value) if name == 'set' else (index,)
                            observed, old_steps, new_steps = self.compare(name, ((raw, name != 'read_word'),), scalars)
                            offset = index if name == 'read_word' else (index * 8) & MASK
                            fits = offset <= length and length - offset >= 8
                            expected = bytearray(raw)
                            if name == 'set' and offset < length:
                                available = min(8, length - offset)
                                expected[offset:offset + available] = value.to_bytes(8, 'little')[:available]
                            self.assertEqual(observed[1], (bytes(expected),))
                            if fits:
                                result = value if name == 'set' else int.from_bytes(raw[offset:offset + 8], 'little')
                                self.assertEqual(observed[0], ('returned', (result,)))
                                self.assertLess(new_steps, old_steps)
                            else:
                                self.assertEqual(observed[0][0], 'trapped')
                                self.assertEqual(observed[0][2], 'bounds')
                            count += 1
        self.assertEqual(count, 890)

    def test_02_packets_transitions_and_refusals_keep_complete_return_buffers(self):
        def request(event=0, sequence=0, port=0, observation=0, mode=1):
            return struct.pack('<16Q', generator.REQUEST_MAGIC, event, sequence, port,
                               observation, mode, 0x0123456789ABCDEF, MASK, *([0] * 8))

        count = 0
        def entry(source, output, state):
            nonlocal count
            result = self.compare('slot_operations', ((source, False), (output, True), (state, True)))
            count += 1
            return result

        for mode in range(1, 16):
            initialized, old_steps, new_steps = entry(request(mode=mode), b'\xa5' * 96, bytes(192))
            self.assertEqual(initialized[0], ('returned', (96,)))
            self.assertLess(new_steps, old_steps)
            saved = struct.unpack('<24Q', initialized[1][2])
            claim = request(1, saved[4], saved[3], mode=mode)
            claimed, old_steps, new_steps = entry(claim, b'\xa5' * 96, initialized[1][2])
            self.assertEqual(claimed[0], ('returned', (96,)))
            self.assertLess(new_steps, old_steps)
            saved = struct.unpack('<24Q', claimed[1][2])
            for event, observation in ((2, 0), (2, 1), (2, 2), (3, 0), (3, 1), (4, 0), (5, 0)):
                entry(request(event, saved[4], saved[3], observation, mode), b'\xa5' * 96, claimed[1][2])
            if mode == 6:
                saved_state = claimed[1][2]
                saved_request = request(2, saved[4], saved[3], mode=mode)
        for offset in range(64, 128):
            source = bytearray(request())
            source[offset] = 1
            observed, _, _ = entry(bytes(source), b'\xa5' * 96, bytes(192))
            self.assertEqual(observed[0], ('returned', (0xfffffffd,)))
            self.assertEqual(observed[1][1:], (b'\xa5' * 96, bytes(192)))
        for dimension, extent in enumerate((128, 96, 192)):
            for length in (0, extent - 1, extent + 1):
                buffers = [request(), b'\xa5' * 96, bytes(192)]
                buffers[dimension] = buffers[dimension][:length].ljust(length, b'\x11')
                observed, _, _ = entry(*buffers)
                self.assertEqual(observed[0], ('returned', (0xfffffffd,)))
                self.assertEqual(observed[1], tuple(buffers))
        for offset in sorted({*range(0, 192, 8), *range(80, 88)}):
            changed = bytearray(saved_state)
            changed[offset] ^= 1
            observed, _, _ = entry(saved_request, b'\xa5' * 96, bytes(changed))
            self.assertEqual(observed[0], ('returned', (0xfffffffd,)))
            self.assertEqual(observed[1][1:], (b'\xa5' * 96, bytes(changed)))
        self.assertEqual(count, 239)


if __name__ == '__main__':
    unittest.main()
