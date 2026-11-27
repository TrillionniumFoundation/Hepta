"""Execute native scheduler continuation contracts for metadata publication.

These controls execute the seed-built native images against syscall results.
They do not claim HTTP process delivery; complete stdio publication is covered
separately by real process, kernel seals and cancellation controls.
"""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
import mmap
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds

ROOT = Path(__file__).resolve().parents[1]
STATE_BYTES = 384 << 20
ROW = 36864
SESSION_OUT = 48 << 20
NEG4 = (1 << 64) - 4
MAXIMUM = (72 << 20) + 512


def qualify(bootstrap, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    seeds = HistorySeeds(ROOT, bootstrap, output/'seeds')
    rows = []
    report = {'schema': 'hepta.hia.metadata-publication-native-contract.v1',
              'passed': False, 'scope': 'native continuation syscall-plan controls',
              'real_http_delivery_claimed': False, 'whole_cold_qualified': False,
              'checks': rows, 'sources': {}}
    arena = mmap.mmap(-1, STATE_BYTES)
    state = (ctypes.c_ubyte * STATE_BYTES).from_buffer(arena)
    request = ctypes.create_string_buffer(1)
    plan = ctypes.create_string_buffer(64)

    def put(at, value):
        struct.pack_into('<Q', arena, at, value)

    def get(at):
        return struct.unpack_from('<Q', arena, at)[0]

    def reset(phase=120, size=58_719_955, metadata=1, result=0):
        arena[:40960] = bytes(40960)
        put(0, phase); put(8, result); put(1624, ROW); put(1632, 10)
        put(ROW, 123); put(ROW+8, 10); put(ROW+16, 11); put(ROW+40, metadata)
        put(9264, size); put(1640, size); put(1656, 0); put(1648, 0)

    def step(code, result=None):
        if result is not None:
            put(8, result)
        ctypes.memset(plan, 0, 64)
        status = code._entry(request, 0, plan, 64, state, STATE_BYTES)
        assert status == 1, (status, get(0))
        return tuple(struct.unpack('<8Q', plan.raw))

    def expect(code, label, wanted):
        actual = step(code)
        assert actual == wanted, (label, actual, wanted)
        rows.append({'case': label, 'plan': list(actual), 'phase': get(0), 'passed': True})

    fallback = (5, 11, 9216, 0, 0, 0, 0, 12)
    seal = (72, 10, 1033, 15, 0, 0, 0, 0)
    try:
        images = {}
        for transport, filename in [('stdio', 'mcp_service_scheduler'), ('http', 'mcp_http_scheduler')]:
            path = ROOT/'examples/hia_bootstrap'/(filename+'.hepta')
            raw = path.read_bytes()
            flat = seeds.compile(raw, 'div-word')
            (output/(filename+'.flat')).write_bytes(flat)
            images[transport] = NativeHiaJsonImage(flat, sha256(flat).hexdigest())
            report['sources'][str(path.relative_to(ROOT))] = {
                'source_sha256': sha256(raw).hexdigest(), 'source_bytes': len(raw),
                'image_sha256': sha256(flat).hexdigest(), 'image_bytes': len(flat)}
            code = images[transport]
            reset(metadata=0)
            expect(code, transport+'-ordinary-large-refuses', fallback)
            reset(size=8389120, metadata=0)
            expect(code, transport+'-ordinary-boundary-seals', seal)
            reset(size=0)
            expect(code, transport+'-empty-refuses', fallback)
            reset(result=(1 << 64)-5)
            expect(code, transport+'-stat-failure-refuses', fallback)
            reset()
            expect(code, transport+'-metadata-large-bound', seal if transport=='stdio' else fallback)
            reset(size=MAXIMUM+1)
            expect(code, transport+'-metadata-over-maximum-refuses', fallback)
            reset(phase=122, result=(1 << 64)-1)
            expect(code, transport+'-seal-failure-refuses', fallback)

        code = images['stdio']
        reset(phase=122)
        expect(code, 'stdio-sealed-large-reads-first-bounded-chunk',
               (17, 10, SESSION_OUT, 65536, 0, 0, 0, 12))
        put(8, 100)
        expect(code, 'stdio-short-read-publishes-exact-chunk',
               (1, 1, SESSION_OUT, 100, 0, 0, 0, 12))
        put(8, 40)
        expect(code, 'stdio-short-write-publishes-only-remaining',
               (1, 1, SESSION_OUT+40, 60, 0, 0, 0, 12))
        put(8, 60)
        expect(code, 'stdio-next-read-preserves-file-offset',
               (17, 10, SESSION_OUT, 65536, 100, 0, 0, 12))
        put(8, NEG4)
        expect(code, 'stdio-eintr-keeps-file-offset',
               (17, 10, SESSION_OUT, 65536, 100, 0, 0, 12))
        assert len(rows) == 19
        report.update(passed=True, passed_checks=len(rows))
        return report
    finally:
        seeds.save()
        del state
        arena.close()
        (output/'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.bootstrap.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()
