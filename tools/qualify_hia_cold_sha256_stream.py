"""Qualify the separate cold SHA profile against the original actual native entry.

The Python process is an external observer and standard SHA oracle. Both payload
hashes and every compared transition execute HIA machine code constructed by the
independent seed profile. This tool does not build or select a target compiler.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import time
import traceback

from hepta.hia_sha256_stream_native import NativeSha256Stream, STATE_BYTES, MAX_CHUNK, MAX_TOTAL
from tests.test_hia_sha256_native import VECTORS
from tests.test_hia_sha256_stream_transition_equivalence import (
    MAGIC, REJECTED, programs, public_witnesses, alias_witnesses,
)

GUARD = b'\x91\xd3\x4a\x68' * 4
ROOT = Path(__file__).resolve().parents[1]


def qualify(old_path: Path, new_path: Path, output: Path):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    captured = {name: (ROOT / name).read_bytes() for name in (
        'tools/generate_hia_sha256_stream.py',
        'examples/hia_bootstrap/sha256_stream.hepta',
        'tools/generate_hia_cold_sha256_stream.py',
        'examples/hia_bootstrap/cold_sha256_stream.hepta',
        'tests/fixtures/sha256_stream_a7710b5.hepta.txt',
        'tests/test_hia_sha256_stream_transition_equivalence.py',
        'tests/test_hia_sha256_stream_native.py',
    )}
    raw_images = {'old': old_path.read_bytes(), 'new': new_path.read_bytes()}
    images = {key: NativeSha256Stream(raw, sha256(raw).hexdigest())
              for key, raw in raw_images.items()}
    report = {
        'schema': 'hepta.hia.cold-sha-native-qualification.v1', 'passed': False,
        'scope': 'independent native component; not a completed cold replay',
        'full_state_bytes_per_transition': STATE_BYTES,
        'source_pins': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'images': {name: {'path': str(path), 'sha256': sha256(raw_images[name]).hexdigest(),
                         'bytes': len(raw_images[name])}
                   for name, path in (('old', old_path), ('new', new_path))},
        'groups': {}, 'benchmarks': [],
    }
    counts = Counter()
    evidence = open(output / 'transitions.jsonl', 'x', buffering=1)
    started = time.monotonic()

    def save():
        report['groups'] = dict(counts)
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')

    def native_frame(image, wire, before_output, state, reported=None):
        raws = (wire, before_output, state)
        buffers = [ctypes.create_string_buffer(GUARD + raw + GUARD, len(raw) + 32)
                   for raw in raws]
        sizes = tuple(map(len, raws)) if reported is None else reported
        args = []
        for buf, size in zip(buffers, sizes):
            args.extend((ctypes.byref(buf, 16), size))
        result = image._entry(*args)
        for buf in buffers:
            assert buf.raw[:16] == GUARD and buf.raw[-16:] == GUARD, 'canary changed'
        after = tuple(buf.raw[16:-16] for buf in buffers)
        assert after[0] == wire, 'read-only input changed'
        return result, *after

    def pair(group, name, wire, before_output, state, expected=None, rejected=False, reported=None):
        old = native_frame(images['old'], wire, before_output, state, reported)
        new = native_frame(images['new'], wire, before_output, state, reported)
        assert old == new, (group, name, 'full-buffer mismatch',
                            old[0], new[0], old[2].hex(), new[2].hex(),
                            old[3].hex(), new[3].hex())
        if expected is not None:
            assert old == expected, (group, name, 'original VM mismatch')
        if rejected:
            assert old == (REJECTED, wire, before_output, state), (group, name, 'refusal wrote')
        counts[group] += 1
        row = {'group': group, 'case': name, 'result': old[0], 'source_bytes': len(wire),
               'output_bytes': len(old[2]), 'state_bytes': len(old[3]),
               'source_sha256': sha256(wire).hexdigest(),
               'output_sha256': sha256(old[2]).hexdigest(),
               'state_sha256': sha256(old[3]).hexdigest(),
               'full_buffers_byte_equal': True, 'all_canaries_unchanged': True}
        if group == 'original-vm':
            row['output_hex'] = old[2].hex()
            row['state_hex'] = old[3].hex()
        evidence.write(json.dumps(row, separators=(',', ':')) + '\n')
        return old

    initial_state = bytes((i * 131 + 91) & 255 for i in range(STATE_BYTES + 17))
    untouched_output = b'\xa5' * 41

    def begin(group, name):
        result = pair(group, name + '-init', b'\x00', untouched_output, initial_state)
        assert result[0] == 0
        return result[2], result[3]

    def update(group, name, wire, out, state):
        result = pair(group, name, b'\x01' + wire, out, state)
        assert result[0] == 0
        return result[2], result[3]

    def finish(group, name, wire, out, state):
        result = pair(group, name, b'\x02', out, state)
        assert result[0] == 32 and result[2][:32] == sha256(wire).digest(), (group, name)
        assert result[2][32:] == out[32:]
        return result

    def wire_case(group, name, wire, chunks, *, repeat=False):
        out, state = begin(group, name)
        at = 0
        for index, size in enumerate(chunks):
            part = wire[at:at + size]
            at += len(part)
            out, state = update(group, name + '-update-' + str(index), part, out, state)
        assert at == len(wire), (name, at, len(wire))
        final = finish(group, name + '-final', wire, out, state)
        if repeat:
            pair(group, name + '-refinal-reject', b'\x02', final[2], final[3], rejected=True)
            again = finish(group, name + '-snapshot-final', wire, out, state)
            assert final == again
            appended_out, appended_state = update(group, name + '-append', b'tail', out, state)
            finish(group, name + '-appended-final', wire + b'tail', appended_out, appended_state)
        return final

    save()
    try:
        original, current = programs()
        public = public_witnesses(original, current)
        aliases = alias_witnesses(original, current)
        for row in public:
            pair('original-vm', row['name'], row['wire'], row['output'], row['state'],
                 row['expected'], row['rejected_before_writes'])
        for row in aliases:
            observations = []
            for image in images.values():
                buffers = [ctypes.create_string_buffer(GUARD + raw + GUARD, len(raw) + 32)
                           for raw in row['buffers']]
                args = []
                for index in row['aliases']:
                    args.extend((ctypes.byref(buffers[index], 16), len(row['buffers'][index])))
                result = image._entry(*args)
                after = tuple(buf.raw[16:-16] for buf in buffers)
                assert all(buf.raw[:16] == GUARD and buf.raw[-16:] == GUARD for buf in buffers)
                observations.append((result, after))
            assert observations[0] == observations[1] == row['expected'], row['name']
            counts['foreign-pointer-alias'] += 1
            evidence.write(json.dumps({
                'group': 'foreign-pointer-alias', 'case': row['name'], 'aliases': row['aliases'],
                'result': observations[0][0], 'owners_after_hex': [x.hex() for x in observations[0][1]],
                'scope': 'foreign pointer stress; not an affine Core admission claim',
                'full_buffers_byte_equal': True, 'all_canaries_unchanged': True}) + '\n')
        save()
        print('PASS original VM and aliases', dict(counts), flush=True)

        for index, (wire, expected_hex) in enumerate(VECTORS):
            for step in (1, 7, 55, 56, 63, 64, 65):
                result = wire_case('FIPS', str(index) + '-' + str(step), wire,
                                  [min(step, len(wire)-at) for at in range(0, len(wire), step)],
                                  repeat=True)
                assert result[2][:32].hex() == expected_hex
        for size in (0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256):
            wire = bytes((i * 137 + 29) & 255 for i in range(size))
            for split in range(size + 1):
                wire_case('all-padding-splits', f'{size}-{split}', wire, (split, size-split))
        wire = b'a' * 1_000_000
        result = wire_case('million-a', 'million-a', wire, [1000] * 1000)
        assert result[2][:32].hex() == 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'
        save()
        print('PASS FIPS, all original padding splits, million a', flush=True)

        rng = random.Random(0x256517)
        for trial in range(1000):
            wire = rng.randbytes(rng.randrange(2049))
            out, state = begin('random-partitions', str(trial))
            position = 0
            while position < len(wire):
                end = position + rng.randrange(1, 131)
                out, state = update('random-partitions', f'{trial}-{position}', wire[position:end], out, state)
                position = end
                if rng.randrange(16) == 0:
                    finish('random-partitions', f'{trial}-intermediate-{position}', wire[:position], out, state)
            finish('random-partitions', f'{trial}-final', wire, out, state)
        save()
        print('PASS 1000 original random partitions', flush=True)

        _, initialized = begin('raw-protocol', 'raw-init')
        for name, source, reported in (
                ('oversized-reported-input', b'\x01x', (MAX_CHUNK + 2, 41, len(initialized))),
                ('short-reported-state', b'\x00', (1, 41, STATE_BYTES - 1)),
                ('short-reported-output', b'\x02', (1, 31, len(initialized)))):
            pair('raw-protocol', name, source, untouched_output, initialized,
                 rejected=True, reported=reported)
        rng = random.Random(0x1184256)
        for trial in range(256):
            state = bytearray(initialized)
            for index in range(136):
                struct.pack_into('<Q', state, index * 8, rng.getrandbits(64))
            total = rng.randrange(MAX_TOTAL - MAX_CHUNK)
            struct.pack_into('<QQQ', state, 1088, total, total & 63, 1)
            struct.pack_into('<Q', state, 1176, MAGIC)
            wire = b'\x02' if trial & 1 else b'\x01' + rng.randbytes(rng.randrange(257))
            pair('noncanonical-full-u64', str(trial), wire, untouched_output, bytes(state))
        large = b'\x00\x80\xff.' * ((MAX_CHUNK + 192) // 4)
        wire_case('original-large-stream', '8MiB+192', large, (MAX_CHUNK, 192))
        for size in (MAX_CHUNK - 1, MAX_CHUNK, MAX_CHUNK + 1):
            wire = (bytes(range(256)) * ((size + 255) // 256))[:size]
            if size <= MAX_CHUNK:
                wire_case('native-chunk-boundary', str(size), wire, (size,))
            else:
                pair('native-chunk-boundary', str(size), b'\x01' + wire,
                     untouched_output, initialized, rejected=True)
        save()
        print('PASS full u64 states and original large/boundary refusals', flush=True)

        wires = [bytes([i]) * (i * 29) for i in range(64)]
        expected = [sha256(wire).digest() for wire in wires]
        for name, image in images.items():
            with ThreadPoolExecutor(max_workers=8) as pool:
                actual = list(pool.map(image.digest, wires))
            assert actual == expected
            counts['concurrent-private-states'] += len(wires)
            for wire, expected_hex in VECTORS:
                state = image.new(wire)
                before = state._state.raw
                assert state.hexdigest() == expected_hex and state.hexdigest() == expected_hex
                assert state._state.raw == before
                copied = state.copy()
                copied.update(b'tail')
                assert copied.digest() == sha256(wire + b'tail').digest()
                assert state._state.raw == before
                state.update(b'!')
                assert state.digest() == sha256(wire + b'!').digest()
                counts['copy-digest-reuse'] += 1
        for size in (1 << 20, 4 << 20, 8 << 20):
            wire = (bytes(range(256)) * ((size + 255) // 256))[:size]
            wanted = sha256(wire).digest()
            for name, image in images.items():
                began = time.monotonic()
                actual = image.digest(wire)
                elapsed = time.monotonic() - began
                assert actual == wanted
                report['benchmarks'].append({'image': name, 'bytes': size, 'seconds': elapsed,
                                             'MiB_per_second': size / (1 << 20) / elapsed,
                                             'sha256': actual.hex()})
        assert old_path.read_bytes() == raw_images['old'] and new_path.read_bytes() == raw_images['new']
        assert all((ROOT / name).read_bytes() == raw for name, raw in captured.items())
        evidence.close()
        report['evidence_sha256'] = sha256((output / 'transitions.jsonl').read_bytes()).hexdigest()
        report['source_and_images_unchanged'] = True
        report['passed'] = True
        save()
        print(json.dumps(report), flush=True)
    except BaseException:
        report['error'] = traceback.format_exc()
        save()
        raise
    finally:
        if not evidence.closed:
            evidence.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--old', required=True, type=Path)
    parser.add_argument('--new', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    qualify(args.old.resolve(), args.new.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
