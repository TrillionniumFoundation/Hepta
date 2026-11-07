#!/usr/bin/env python3
"""Finite supplemental runtime Base64 oracle, not a public ABI contract.

Generate C from the checked source and add compiler-private test adapters in the
same translation unit. Python ctypes calls only those temporary adapters. Public
package-consumer tests remain separate. Requires a qualified 64-bit host and cc.
The entire corpus runs independently at O0 and O3 with nonrecovering UBSan.
All input/output backing bytes are checked, including empty private views.
All random cases are deterministic; Python's strict decoder is additionally
round-tripped to reject noncanonical unused bits and excess padding.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.pipeline import analyze


class Size(ct.Structure):
    _fields_ = [('bytes', ct.c_size_t), ('ok', ct.c_bool)]


ADAPTER = r'''
/* Test-only compiler-private names: no exported Hepta/C interoperability claim. */
__hepta_cb_type_Size oracle_length(size_t n) {
    return __hepta_cb_fn_encoded_length(n);
}
__hepta_cb_type_Size oracle_decoded(uint8_t *p, size_t n, size_t a, size_t b) {
    return __hepta_cb_fn_decoded_length((__hepta_cb_slice_1){p,n},a,b);
}
__hepta_cb_type_Size oracle_transform(int decode, uint8_t *p, size_t n,
        size_t a, size_t b, uint8_t *q, size_t capacity, size_t offset) {
    if (decode) return __hepta_cb_fn_decode((__hepta_cb_slice_1){p,n},a,b,
        (__hepta_cb_slice_2){q,capacity},offset);
    return __hepta_cb_fn_encode((__hepta_cb_slice_1){p,n},a,b,
        (__hepta_cb_slice_2){q,capacity},offset);
}
'''


def canonical(data):
    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error):
        return None
    return decoded if base64.b64encode(decoded) == data else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    args = parser.parse_args()
    if not __debug__:
        raise RuntimeError('Run without Python -O: oracle assertions must remain enabled')
    assert ct.sizeof(ct.c_size_t) == 8, 'requires qualified 64-bit host'
    source = ROOT / 'stdlib/base64/src/lib.hepta'
    result = analyze(source.read_text(), str(source), backend='c', native=False)
    assert result.report['ok'], result.report
    lanes = [run_lane(args, source, result, optimization) for optimization in ('-O0', '-O3')]
    print(json.dumps({'status': 'passed', 'lanes': lanes,
                      'total_cases': sum(lane['total_cases'] for lane in lanes)}, indent=2))


def run_lane(args, source, result, optimization):
    counts = {}
    rng = random.Random(4648)
    maximum = (1 << 64) - 1
    with tempfile.TemporaryDirectory(prefix='hepta-base64-oracle-') as directory:
        c_path = Path(directory) / 'oracle.c'
        shared = Path(directory) / 'oracle.so'
        c_path.write_text(result.c + ADAPTER)
        subprocess.run([args.cc, '-std=c11', optimization, '-fPIC', '-shared',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        str(c_path), '-o', str(shared)], check=True)
        native = ct.CDLL(str(shared))
        byteptr = ct.POINTER(ct.c_uint8)
        native.oracle_length.argtypes = [ct.c_size_t]
        native.oracle_decoded.argtypes = [byteptr, ct.c_size_t, ct.c_size_t, ct.c_size_t]
        native.oracle_transform.argtypes = [ct.c_int, byteptr, ct.c_size_t,
            ct.c_size_t, ct.c_size_t, byteptr, ct.c_size_t, ct.c_size_t]
        for name in ('oracle_length', 'oracle_decoded', 'oracle_transform'):
            getattr(native, name).restype = Size

        def case(category, decode, data, start, end, capacity, offset):
            valid_range = start <= end <= len(data)
            expected = None
            if valid_range:
                expected = canonical(data[start:end]) if decode else base64.b64encode(data[start:end])
            wanted = expected is not None and offset <= capacity and len(expected) <= capacity - offset
            # Physical prefix/suffix canaries surround the advertised output slice.
            original = bytes([0xA5]) * (capacity + 16)
            output = (ct.c_uint8 * len(original)).from_buffer_copy(original)
            input_original = b'\xC3' * 8 + data + b'\x3C' * 8
            input_buf = (ct.c_uint8 * len(input_original)).from_buffer_copy(input_original)
            inptr = ct.cast(ct.byref(input_buf, 8), byteptr)
            outptr = ct.cast(ct.byref(output, 8), byteptr)
            answer = native.oracle_transform(decode, inptr, len(data), start, end, outptr, capacity, offset)
            assert bool(answer.ok) == wanted, (category, decode, data, start, end, capacity, offset)
            assert answer.bytes == (len(expected) if wanted else 0)
            changed = original
            if wanted:
                changed = original[:8+offset] + expected + original[8+offset+len(expected):]
            assert bytes(output) == changed, ('mutation', category, data, start, end, capacity, offset)
            if decode:
                size = native.oracle_decoded(inptr, len(data), start, end)
                assert bool(size.ok) == (expected is not None)
                assert size.bytes == (len(expected) if expected is not None else 0)
            assert bytes(input_buf) == input_original, ('input backing mutated', category)
            assert bytes(output) == changed, ('output backing mutated', category)
            counts[category] = counts.get(category, 0) + 1

        for decode in (False, True):
            for data, start, end, capacity, offset in (
                (b'', 0, 0, 0, 0), (b'!', 1, 1, 0, 0),
                (b'!', 1, 1, 3, 3), (b'', 0, 0, 0, 1),
                (b'', 1, 0, 0, 0), (b'', 0, 1, 0, 0),
                (b'', maximum, maximum, 0, 0),
            ):
                case('explicit_empty_and_bounds', decode, data, start, end, capacity, offset)
        for data in (b'A', b'AA', b'AAA', b'AAAAA', b'AA==\n', b' AA==', b'AA==\x00'):
            case('explicit_invalid_lengths', True, data, 0, len(data), 20, 0)

        for length in range(3):
            for value in range(256 ** length):
                raw = value.to_bytes(length, 'big')
                encoded = base64.b64encode(raw)
                case('exhaustive_0_1_2_encode', False, b'!?'+raw+b'!', 2, 2+length, len(encoded)+4, 2)
                case('exhaustive_0_1_2_decode', True, b'!?'+encoded+b'!', 2, 2+len(encoded), length+4, 2)

        # Every possible replacement byte at every position, including trailing
        # groups and padding placement, on canonical and deliberately bad seeds.
        seeds = [b'AA==', b'AAA=', b'AAAA', b'Zg==', b'Zm8=', b'Zm9v',
                 b'AAAAAA==', b'AAAAAAA=', b'AAAAAAAA', b'=AAA', b'AA=A',
                 b'AA==AAAA', b'A===', b'====']
        for seed in seeds:
            for index in range(len(seed)):
                for value in range(256):
                    data = seed[:index] + bytes([value]) + seed[index+1:]
                    case('all_byte_mutations', True, data, 0, len(data), len(data)+3, 1)

        for _ in range(4000):
            raw = rng.randbytes(rng.randrange(257))
            encoded = base64.b64encode(raw)
            for decode, data, expected_length in ((False, raw, len(encoded)), (True, encoded, len(raw))):
                padded = b'!?'+data+b'!'
                case('random_valid', decode, padded, 2, len(data)+2, expected_length+4, 2)
                if expected_length:
                    case('short_capacity', decode, padded, 2, len(data)+2, expected_length+1, 2)

        for _ in range(12000):
            decode = bool(rng.getrandbits(1))
            raw = rng.randbytes(rng.randrange(65))
            data = base64.b64encode(raw) if decode and rng.getrandbits(1) else raw
            n = len(data)
            choices = [0, n, n+1, maximum, rng.randrange(n+2)]
            start, end = rng.choice(choices), rng.choice(choices)
            capacity = rng.randrange(90)
            offset = rng.choice([0, capacity, capacity+1, maximum, rng.randrange(capacity+2)])
            case('random_ranges_and_capacity', decode, data, start, end, capacity, offset)

        # Mathematical boundary oracle without allocating huge slices.
        threshold = (maximum // 4) * 3
        lengths = list(range(1000)) + [threshold+d for d in range(-8, 9)] + [maximum-d for d in range(8)]
        lengths += [rng.getrandbits(64) for _ in range(10000)]
        for length in lengths:
            expected = ((length + 2) // 3) * 4
            answer = native.oracle_length(length)
            assert bool(answer.ok) == (expected <= maximum), length
            assert answer.bytes == (expected if expected <= maximum else 0), length
        counts['encoded_length_boundaries'] = len(lengths)
        return {'status': 'passed', 'optimization': optimization, 'scope': 'finite compiler-private C runtime oracle; not public ABI',
            'seed': 4648, 'sanitizer': 'undefined (nonrecovering)', 'counts': counts,
            'total_cases': sum(counts.values()), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'oracle_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'compiler_sha256': result.report['compiler_sha256'],
            'adapter_sha256': hashlib.sha256(ADAPTER.encode()).hexdigest(),
            'translation_unit_sha256': hashlib.sha256(c_path.read_bytes()).hexdigest(),
            'generated_c_sha256': hashlib.sha256(result.c.encode()).hexdigest(),
            'cc': subprocess.check_output([args.cc, '--version'], text=True).splitlines()[0]}


if __name__ == '__main__':
    main()
