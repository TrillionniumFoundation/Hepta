"""Actual native fixed points and independent parallel-assignment oracles.

The reference wire fixtures below are constructed directly, without the Python
authoring CFG or its register assignment. Their expected complete output comes
from Python tuple parallel assignment. Old parent and new native emitters must
preserve all buffer bytes, calls, branches, loop backedges and original traps.
No component result in this file qualifies a whole cold construction.
"""
from pathlib import Path
from hashlib import sha256
from itertools import product
from collections import Counter
import argparse
import ctypes
import json
import mmap
import os
import random
import resource
import signal
import struct
import time

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.hia_native_seed_test_support import NativeSeeds

ROOT = Path(__file__).resolve().parents[1]
GUARD = b'\x91\xd3\x4a\x68' * 4
MASK = (1 << 64) - 1


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class Wire:
    def __init__(self, registers, bounce=64):
        self.registers, self.bounce = registers, bounce
        self.commands, self.data, self.labels, self.functions = [], [], {}, []

    def label(self, name, function=False):
        assert name not in self.labels
        self.labels[name] = len(self.commands)
        if function:
            self.functions.append(name)

    def words(self, values):
        result = ('data', len(self.data))
        self.data.append(tuple(values))
        return result

    def op(self, *values):
        assert len(values) <= 8
        self.commands.append(tuple(values) + (0,) * (8 - len(values)))

    def constant(self, slot, value):
        self.op(32, slot, value)

    def edge(self, label, slots):
        # The wire's instruction-boundary scanner sees the edge-record pointer
        # before following its register-list pointer. Keep the record first.
        record = self.words([0, 0, 0])
        self.data[record[1]] = (('code', label), self.words(slots), len(slots))
        return record

    def jump(self, label, slots):
        self.op(36, self.edge(label, slots))

    def branch(self, condition, yes, no, yes_slots, no_slots):
        self.op(37, condition, self.edge(yes, yes_slots), self.edge(no, no_slots))

    def call(self, callee, slots, result):
        self.op(33, callee, self.words(slots), len(slots), self.words([result]), 1)

    def returned(self, slot):
        self.op(34, self.words([slot]), 1)

    def snapshot(self, slots, temp):
        descriptor = self.words([5, 4, 3, 0])  # original mutable byte-store ABI
        empty = self.words([])
        for index, slot in enumerate(slots):
            for byte in range(8):
                self.constant(temp, index * 8 + byte)
                self.constant(temp + 1, byte * 8)
                self.op(10, temp + 2, slot, temp + 1, 0, 64, 0, 9)
                self.op(38, descriptor, self.words([1, temp, temp + 2]), 3, empty, 0)

    def pack(self):
        start = 64 + 8 * len(self.functions)
        end_instructions = start + 64 * len(self.commands)
        offsets, end = [], end_instructions
        for values in self.data:
            offsets.append(end)
            end += 8 * len(values)
        def value(item):
            if type(item) is int:
                return item & MASK
            kind, which = item
            return offsets[which] if kind == 'data' else start + 64 * self.labels[which]
        words = [int.from_bytes(b'HIAERW02', 'little'), self.registers,
                 self.bounce, end, 1, 1, 0, 0]
        words += [start + 64 * self.labels[name] for name in self.functions]
        words += [value(x) for instruction in self.commands for x in instruction]
        words += [value(x) for data in self.data for x in data]
        words.append(8)
        raw = struct.pack('<' + 'Q' * len(words), *words)
        assert len(raw) == end + 8
        return raw


def fixture(values, mapping, mode='jump', *, condition=1, iterations=1, registers=None):
    """Independent concrete oracle over numeric slots; views retain 0,1,2."""
    count = len(values)
    temp = count + 3
    wire = Wire(max(temp + 4, registers or 0))
    wire.label('entry', function=True)
    for i, value in enumerate(values):
        wire.constant(i + 3, value)
    slots = [0, 1, 2] + [i + 3 for i in mapping]
    expected = list(values)
    if mode == 'empty':
        wire.jump('after', [])
    elif mode == 'branch':
        wire.constant(temp, condition)
        reverse = [0, 1, 2] + [i + 3 for i in reversed(range(count))]
        wire.branch(temp, 'after', 'after', slots, reverse)
        source = mapping if condition else list(reversed(range(count)))
        expected[:len(source)] = [expected[i] for i in source]
    elif mode == 'loop':
        assert count and mapping[0] == 0 and iterations > 0
        wire.constant(3, iterations)
        expected[0] = iterations
        wire.label('loop')
        wire.constant(temp, 1)
        wire.op(2, 3, 3, temp, 0, 64, 0, 9)
        wire.branch(3, 'loop', 'after', slots, slots)
        for _ in range(iterations):
            expected[0] -= 1
            expected[:len(mapping)] = [expected[i] for i in mapping]
    elif mode == 'call':
        wire.jump('before-call', slots)
        expected[:len(mapping)] = [expected[i] for i in mapping]
        wire.label('before-call')
        # Both calls use complete identity argument lists after an edge that
        # leaves holes in bounce. The second call must restage every argument.
        for _ in range(2):
            wire.call(1, list(range(count + 3)), temp)
        wire.returned(temp)
        wire.label('callee', function=True)
        wire.jump('after', slots)
        expected[:len(mapping)] = [expected[i] for i in mapping]
    else:
        assert mode == 'jump'
        wire.jump('after', slots)
        expected[:len(mapping)] = [expected[i] for i in mapping]
    wire.label('after')
    wire.snapshot(list(range(3, count + 3)), temp)
    wire.constant(temp, 0xED6E)
    wire.returned(temp)
    return wire.pack(), struct.pack('<' + 'Q' * len(expected), *expected), 0xED6E


def call(native, source, output, workspace, *, reported=None):
    raw = (source, output, workspace)
    buffers = [ctypes.create_string_buffer(GUARD + item + GUARD, len(item) + 32) for item in raw]
    arguments = []
    for index, (buffer, item) in enumerate(zip(buffers, raw)):
        arguments += [ctypes.byref(buffer, 16), len(item) if reported is None else reported[index]]
    result = native._entry(*arguments)
    assert all(buf.raw[:16] == GUARD and buf.raw[-16:] == GUARD for buf in buffers)
    assert buffers[0].raw[16:-16] == source
    return result, *(buf.raw[16:-16] for buf in buffers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    seeds = NativeSeeds(ROOT, args.bootstrap, output)
    captured = {str(p.relative_to(ROOT)): p.read_bytes()
                for p in [ROOT / 'tools/generate_hia_seed_cold_backend.py',
                          ROOT / 'tools/qualify_hia_seed_cold_backend.py',
                          *(ROOT / 'examples/hia_bootstrap' / ('seed_' + name + '_backend.hepta')
                            for name in ('bulk', 'endian', 'cold_bulk', 'cold_endian'))]}
    report = {'schema': 'hepta.hia.cold-seed-parallel-edges.v1', 'passed': False,
              'scope': 'Finite independent native compiler and ABI qualification; not whole cold.',
              'whole_cold_qualified': False, 'profiles': {},
              'source_pins': {p: pin(raw) for p, raw in captured.items()}}
    started = time.monotonic_ns()
    records = (output / 'observations.jsonl').open('x')
    def save():
        seeds.save()
        (output / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    def image(raw):
        return NativeHiaJsonImage(raw, sha256(raw).hexdigest())
    def project(raw):
        core = seeds.invoke(output / 'hia-seed-assembly', raw, '--agent-compact')
        return seeds.invoke(output / 'hia-seed-projector', b'[' + core + b',"f0",1]')
    def compile_flat(native, wire):
        got = call(native, wire, b'\xa5' * (1 << 20), b'\x6d' * (1 << 20))
        assert 0 < got[0] <= 1 << 20
        assert got[2][got[0]:] == b'\xa5' * ((1 << 20) - got[0])
        return got[2][:got[0]]
    try:
        rng = random.Random(0xED6ECA11)
        cases = []
        for count in range(5):
            values = [rng.getrandbits(64) for _ in range(count)]
            for mapping in product(range(count), repeat=count):
                cases.append(('exhaustive-' + str(count), fixture(values, mapping)))
        for count in (1, 2, 3, 7, 16, 31, 61):
            values = [rng.getrandbits(64) for _ in range(count)]
            identity = list(range(count))
            cycle = identity[1:] + identity[:1]
            fanout = [0] * count
            for mapping in (identity, cycle, fanout, identity[::-1]):
                cases.append(('boundary-jump-' + str(count), fixture(values, mapping, registers=2048)))
                cases.append(('call-' + str(count), fixture(values, mapping, 'call')))
                for truth in (0, 1):
                    cases.append(('branch-' + str(count), fixture(values, mapping, 'branch', condition=truth)))
            cases.append(('empty-edge-' + str(count), fixture(values, [], 'empty')))
            loopmap = [0] + (identity[2:] + identity[1:2] if count > 1 else [])
            cases.append(('loop-' + str(count), fixture(values, loopmap, 'loop', iterations=17)))
        for _ in range(48):
            count = rng.randrange(1, 62)
            values = [rng.getrandbits(64) for _ in range(count)]
            mapping = [rng.randrange(count) for _ in range(count)]
            cases.append(('random-fanout', fixture(values, mapping)))
        for profile in ('bulk', 'endian'):
            parent_source = captured['examples/hia_bootstrap/seed_' + profile + '_backend.hepta']
            candidate_source = captured['examples/hia_bootstrap/seed_cold_' + profile + '_backend.hepta']
            projected = project(candidate_source)
            old = seeds.compile(parent_source, 'v1')
            b1 = seeds.invoke(output / 'hia-seed-backend', projected)
            old_native, b1_native = image(old), image(b1)
            b2 = compile_flat(b1_native, projected)
            b2_native = image(b2)
            b3 = compile_flat(b2_native, projected)
            assert b1 != b2 and b2 == b3
            for label, raw in [('parent', old), ('B1', b1), ('B2', b2), ('B3', b3)]:
                (output / (profile + '-' + label + '.flat')).write_bytes(raw)
            row = {'parent': pin(old), 'B1': pin(b1), 'B2': pin(b2), 'B3': pin(b3),
                   'B1_from_original_v1': True, 'B2_equals_B3': True,
                   'original_parent_fixedpoint_gate_changed': False, 'cases': 0,
                   'groups': {}, 'rejection_controls': 0, 'trap_controls': 0}
            report['profiles'][profile] = row
            groups = Counter()
            for index, (group, (wire, expected, status)) in enumerate(cases):
                flats = [compile_flat(native, wire) for native in (old_native, b1_native, b2_native)]
                assert flats[1] == flats[2], (profile, index, 'B1/B2 emitter output')
                observations = []
                for flat in flats[:2]:
                    executable = image(flat)
                    observed = call(executable, b'input-preserved', b'\xa5' * 520, b'workspace-preserved' * 32)
                    assert observed == (status, b'input-preserved', expected + b'\xa5' * (520-len(expected)), b'workspace-preserved' * 32), (profile, index, group)
                    observations.append(observed)
                    executable._mapping.close()
                assert observations[0] == observations[1]
                records.write(json.dumps({'profile': profile, 'case': index, 'group': group,
                    'wire': pin(wire), 'expected_output': pin(expected),
                    'parent_image': pin(flats[0]), 'candidate_image': pin(flats[1]),
                    'whole_buffers_and_canaries_equal': True}, separators=(',', ':')) + '\n')
                groups[group] += 1
                row['cases'] += 1
            valid, _, _ = fixture([11, 22, 33], [1, 2, 0])
            start = struct.unpack_from('<Q', valid, 64)[0]
            edge_instruction = next(at for at in range(start, len(valid)-64, 64)
                                    if struct.unpack_from('<Q', valid, at)[0] == 36)
            edge_record = struct.unpack_from('<Q', valid, edge_instruction+8)[0]
            slots = struct.unpack_from('<Q', valid, edge_record+8)[0]
            changes = [(0, 0), (8, 2), (8, 2049), (16, 0), (16, 65),
                       (edge_instruction+8, 1), (edge_record, start+1),
                       (edge_record+8, 1), (edge_record+16, 65),
                       (slots, struct.unpack_from('<Q', valid, 8)[0])]
            refused = [valid[:79], valid[:-1], valid+b'\0']
            for offset, value in changes:
                bad = bytearray(valid)
                struct.pack_into('<Q', bad, offset, value)
                refused.append(bytes(bad))
            for index, wire in enumerate(refused):
                observed = [call(native, wire, b'\xa5'*(1<<20), b'\x6d'*(1<<20))
                            for native in (old_native, b1_native, b2_native)]
                assert observed[0] == observed[1] == observed[2]
                assert observed[0][0] in (4294967293, 4294967295)
                assert observed[0][2] == b'\xa5'*(1<<20)
                row['rejection_controls'] += 1
            wire, expected, status = fixture([11, MASK, 0x123456789ABCDEF0], [2, 1, 0])
            flats = [compile_flat(native, wire) for native in (old_native, b1_native)]
            for extent in (0, 1, 7, 8, 23):
                outcomes = []
                for flat in flats:
                    executable = image(flat)
                    shared = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED,
                                       prot=mmap.PROT_READ | mmap.PROT_WRITE)
                    initial = rng.randbytes(4096)
                    shared[:] = initial
                    buf = (ctypes.c_char * 4096).from_buffer(shared)
                    child = os.fork()
                    if child == 0:
                        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                        signal.alarm(5)
                        executable._entry(None, 0, ctypes.byref(buf, 64), extent, None, 0)
                        os._exit(111)
                    _, wait_status = os.waitpid(child, 0)
                    assert os.WIFSIGNALED(wait_status) and os.WTERMSIG(wait_status) == signal.SIGILL
                    actual = shared[:]
                    assert actual == initial[:64] + expected[:extent] + initial[64+extent:]
                    outcomes.append(actual[64:64+extent])
                    del buf
                    shared.close()
                    executable._mapping.close()
                assert outcomes[0] == outcomes[1]
                row['trap_controls'] += 1
            row['groups'] = dict(groups)
            save()
            print('COLD_SEED_PROFILE_PASS', profile, row['cases'], row['rejection_controls'], row['trap_controls'], flush=True)
            for native in (old_native, b1_native, b2_native):
                native._mapping.close()
        assert all((ROOT/path).read_bytes() == raw for path, raw in captured.items())
        records.close()
        report['observations'] = pin((output/'observations.jsonl').read_bytes())
        report['source_unchanged'] = True
        report['elapsed_ns'] = time.monotonic_ns()-started
        report['passed'] = True
        save()
        print('COLD_SEED_QUALIFICATION_PASS', json.dumps(report, sort_keys=True), flush=True)
    finally:
        if not records.closed:
            records.close()
        save()


if __name__ == '__main__':
    main()
