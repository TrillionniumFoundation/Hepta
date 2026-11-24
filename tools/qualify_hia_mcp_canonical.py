"""Compare native MCP canonical bytes with an independently pinned serde oracle."""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import json
import math
import mmap
import random
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_mcp_canonical import LIMIT, SOURCE, WORKSPACE_BYTES, render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flat', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--oracle-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    oracle = args.oracle.read_bytes()
    assert sha256(oracle).hexdigest() == args.oracle_sha256
    args.output.mkdir(mode=0o700, exist_ok=False)
    source = (Path(__file__).resolve().parents[1] / SOURCE).read_bytes()
    assert source.decode() == render()
    flat = args.flat.read_bytes()
    image = mmap.mmap(-1, len(flat), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    image.write(flat)
    entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                             ctypes.c_size_t)(ctypes.addressof(ctypes.c_ubyte.from_buffer(image)))
    output = ctypes.create_string_buffer(LIMIT)
    workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
    cases = []
    values = ['null', 'true', 'false', '0', '-0', '-0.0', '0.0', '1e0', '1E+0', '1e-0',
              '1e-5', '1e-6', '1e-7', '1e15', '1e16', '1e20', '1e21',
              '18446744073709551615', '18446744073709551616',
              '9223372036854775807', '9223372036854775808',
              '-9223372036854775808', '-9223372036854775809',
              '1e400', '-1e400', '1e-400', '-1e-400', '5e-324',
              '2.2250738585072014e-308', '1.7976931348623157e308',
              '1.2345678901234567', '99999999999999999999999999999999999999999',
              '1.' + '0' * 2000 + '1', '1' + '0' * 2000 + 'e-2000',
              '{ "z":2, "a":["\\u4e2d\\ud83d\\ude00",1e-5,-0], "b":{"y":true,"x":null} }',
              '{"中":1,"é":2,"😀":3,"z":4,"a":5}',
              '{"escaped":"\\b\\f\\n\\r\\t\\u0000\\u001f\\\\\\\"/"}',
              '[]', '{}', '""']
    rng = random.Random(20261124)
    for _ in range(384):
        bits = rng.getrandbits(64)
        value = struct.unpack('<d', struct.pack('<Q', bits))[0]
        if math.isfinite(value):
            values.append(repr(value))
    for exponent in range(-7, 18):
        values.extend((f'1e{exponent}', f'-1e{exponent}', f'1.2345678901234567e{exponent}'))
    for _ in range(64):
        value = rng.randrange(-(1 << 80), 1 << 80)
        values.append(str(value))
    oracle_result = subprocess.run([str(args.oracle)], input=('\n'.join(values) + '\n').encode(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    assert oracle_result.returncode == 0 and not oracle_result.stderr
    expected = [json.loads(line) for line in oracle_result.stdout.splitlines()]
    assert len(expected) == len(values)
    (args.output / 'oracle.jsonl').write_bytes(oracle_result.stdout)
    (args.output / 'inputs.jsonl').write_text('\n'.join(values) + '\n')
    for i, (wire, answer) in enumerate(zip(values, expected, strict=True)):
        raw = wire.encode()
        buf = ctypes.create_string_buffer(raw, max(1, len(raw)))
        result = entry(buf, len(raw), output, LIMIT, workspace, WORKSPACE_BYTES)
        row = {'index': i, 'input_sha256': sha256(raw).hexdigest(), 'status': result}
        if 'error' in answer:
            assert result > LIMIT, (i, wire[:160], result)
            row['refused'] = True
        else:
            want = answer['ok'].encode()
            assert 0 < result <= LIMIT, (i, wire[:160], result, want)
            got = output.raw[:result]
            assert got == want, (i, wire[:160], got, want)
            row['output_sha256'] = sha256(got).hexdigest()
        cases.append(row)
    for name, raw in (
        ('duplicate-decoded-key', b'{"a":1,"\\u0061":2}'),
        ('invalid-utf8', b'"\xff"'), ('unpaired-surrogate', b'"\\ud800"'),
        ('bad-decimal', b'1.'), ('bad-exponent', b'1e+'), ('nan', b'NaN'),
        ('leading-zero', b'01'), ('extra-value', b'1 2'),
        ('over-input-bound', b' ' * (LIMIT + 1)),
    ):
        buf = ctypes.create_string_buffer(raw, max(1, len(raw)))
        result = entry(buf, len(raw), output, LIMIT, workspace, WORKSPACE_BYTES)
        assert result > LIMIT, (name, result)
        cases.append({'name': name, 'input_sha256': sha256(raw).hexdigest(), 'status': result, 'refused': True})
    assert args.oracle.read_bytes() == oracle and args.flat.read_bytes() == flat
    assert (Path(__file__).resolve().parents[1] / SOURCE).read_bytes() == source
    report = {'scope': 'NATIVE_MCP_CANONICAL_COMPONENT', 'passed': True, 'count': len(cases),
              'serde_json_version': '1.0.151', 'serde_float_roundtrip': True,
              'arbitrary_precision': False, 'zmij_version': '1.0.23',
              'precondition': 'HIA session has admitted duplicate-free JSON and its depth/node bounds',
              'flat_sha256': sha256(flat).hexdigest(), 'source_sha256': sha256(source).hexdigest(),
              'oracle_sha256': args.oracle_sha256, 'whole_mcp_server_qualified': False, 'cases': cases}
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases), 'flat_sha256': report['flat_sha256']}), flush=True)
    del entry
    image.close()


if __name__ == '__main__':
    main()
