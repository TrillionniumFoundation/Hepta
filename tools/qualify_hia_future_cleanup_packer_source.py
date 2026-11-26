"""Independent layout and admission checks of the new fixed nine-role packer.

Pure author execution only. No compiled HIA or executable product is admitted.
"""
from pathlib import Path
from hashlib import sha256
import importlib.util
import json
import os
import struct
import sys

HERE = Path(__file__).resolve().parents[1]
OUTPUT = Path(os.environ.get('HEPTA_FUTURE_SOURCE_QA_OUTPUT', str(HERE / 'build/future-source-qa')))
OUTPUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(HERE))
p = HERE / 'tools/generate_hia_background_optimizer_future_public_cleanup_packer.py'
spec = importlib.util.spec_from_file_location('cleanup_packer', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
env = {'readbuf': bytearray, 'mutbuf': bytearray, 'u64': int, 'u32': int,
       'length': len, 'byte': lambda b, i: b[i],
       'store': lambda b, i, x: b.__setitem__(i, x)}
exec(compile(m.source_program(), str(p) + ':SOURCE', 'exec'), env)
cases = []
def record(name, count):
    cases.append({'case': name, 'checks': count, 'passed': True})
def packet(flats, mode):
    return struct.pack('<8s11Q', b'HIABFPP3', 9, *map(len, flats), mode) + b''.join(flats)

count = 0
for lengths in ((1,) * 9, tuple(range(1, 10)), tuple(17 * i for i in range(1, 10)),
                (2, 3, 5, 7, 11, 127, 128, 129, 257)):
    flats = [bytes((i * 29 + j) & 255 for j in range(n)) for i, n in enumerate(lengths)]
    for mode in (0, 1):
        src = packet(flats, mode)
        expected = m.reference_object(flats) if mode == 0 else m.reference_flat(flats)
        for poison in (0, 0xA5, 0xFF):
            out, work = bytearray(len(expected)), bytearray([poison]) * 512
            assert env['pack'](src, out, work) == len(expected) and out == expected
            count += 1
        out = bytearray([0xA5]) * (len(expected) - 1)
        before = bytes(out)
        assert env['pack'](src, out, bytearray([0xFF]) * 512) == (1 << 32) - 2
        assert out == before
        count += 1
record('nine-distinct-offsets-and-object-flat-byte-equality-with-poisoned-workspace', count)

flats = [bytes([i + 1]) * 17 for i in range(9)]
valid = packet(flats, 1)
invalid = [valid[:n] for n in (0, 7, 8, 15, 80, 88, 95)]
for at, value in ((0, 0), (8, 8), (8, 10), (88, 2), (16, 0),
                  (80, 4194305), (72, (1 << 64) - 1)):
    b = bytearray(valid)
    struct.pack_into('<Q', b, at, value)
    invalid.append(bytes(b))
invalid += [valid + b'x', valid[:-1], valid.replace(b'HIABFPP3', b'HIABFPP2', 1)]
for src in invalid:
    out = bytearray([0xA5]) * 4096
    assert env['pack'](src, out, bytearray(512)) == (1 << 32) - 1
    assert out == bytes([0xA5]) * 4096
out = bytearray([0xA5]) * 4096
assert env['pack'](valid, out, bytearray(511)) == (1 << 32) - 2
assert out == bytes([0xA5]) * 4096
record('new-profile-domain-and-atomic-capacity-refusals', len(invalid) + 1)

report = {'schema': 'hepta.hia.future-cleanup-packer-author-probes.v1',
          'passed': True, 'checks': sum(x['checks'] for x in cases), 'cases': cases,
          'bridge_bytes': len(m.BRIDGE), 'bridge_sha256': sha256(m.BRIDGE).hexdigest(),
          'fixups': m.FIXUPS, 'roles': m.ROLES,
          'execution_kind': 'Pure author execution and independent struct layout oracle',
          'native_build_pass': False, 'whole_native_runtime_closed': False}
(OUTPUT / 'cleanup-packer-author-v1.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
