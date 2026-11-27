"""Execute native HTTP file, cache and metadata admission boundaries.

These are continuation controls using explicit syscall outcomes. Real sockets,
seals, process cancellation and original Rust error bytes are observed by the
separate public HTTP qualifier.
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
from tools.generate_hia_mcp_http_common import C
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds

ROOT = Path(__file__).resolve().parents[1]
NONE = (1 << 64)-1
NEG4 = NONE-3
NEG5 = NONE-4
STATE_BYTES = 384 << 20
SIZE = 29_353_108
MAXIMUM = (72 << 20)+512
SESSION_OUT = 48 << 20


def qualify(bootstrap, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    seeds = HistorySeeds(ROOT, bootstrap, output/'seeds')
    checks = []
    report = {'schema': 'hepta.hia.http-metadata-native-continuations.v1', 'passed': False,
              'checks': checks, 'sources': {}, 'whole_cold_qualified': False,
              'real_http_delivery_claimed': False, 'ordinary_parent_bound': 16777216,
              'ordinary_cache_bound': 16777728, 'metadata_response_bound': MAXIMUM,
              'cache_expiry_nanoseconds': 60_000_000_000}
    arena = mmap.mmap(-1, STATE_BYTES)
    state = (ctypes.c_ubyte * STATE_BYTES).from_buffer(arena)
    request = ctypes.create_string_buffer(1)
    plan = ctypes.create_string_buffer(64)
    images = {}

    def at(key):
        return C[key] if isinstance(key, str) else key

    def put(key, value):
        struct.pack_into('<Q', arena, at(key), value)

    def get(key):
        return struct.unpack_from('<Q', arena, at(key))[0]

    def reset(phase, result=0):
        arena[:65536] = bytes(65536)
        for start, size in [(C['H_RECORD'], 1024), (C['H_SESSION'], 1024),
                            (C['H_TASKS'], 8192), (C['H_IO'], 131072)]:
            arena[start:start+size] = bytes(size)
        put(0, phase)
        put(8, result)
        put('H_HTTP_CONTINUE_MODULE', C['HTTP_DELIVERY'])
        put('H_HTTP_CONTINUE_PHASE', 200)

    def step(role, *, result=None):
        if result is not None:
            put(8, result)
        ctypes.memset(plan, 0, 64)
        status = images[role]._entry(request, 0, plan, 64, state, STATE_BYTES)
        return status, tuple(struct.unpack('<8Q', plan.raw))

    def record(name, actual, expected):
        assert actual == expected, (name, actual, expected)
        checks.append({'case': name, 'passed': True, 'status': actual[0],
                       'phase': get(0), 'module': get(16), 'plan': list(actual[1])})

    def syscall(role, name, wanted, result=None):
        record(name, step(role, result=result), (1, wanted))

    def transition(role, name, module, phase, result=None):
        actual = step(role, result=result)
        record(name, actual, (6, (0,)*8))
        assert (get(16), get(0)) == (module, phase), (name, get(16), get(0))

    def file_setup(phase=110, result=0, *, mode=2, size=SIZE):
        reset(phase, result)
        for key, value in {'H_HTTP_FILE_MODE': mode, 'H_HTTP_FILE_FD': 44,
                           'H_HTTP_FILE_START': 512, 'H_HTTP_SIZE': size,
                           'H_HTTP_FILE_APPEND': 1, 'CR_REPLY_FD': 30,
                           'CR_REPLY_N': 256, 'CR_REPLY_SENT': 192,
                           'CR_VERSION': 2, 'CR_FLAGS': 256, 'CR_FD': 20}.items():
            put(key, value)

    def closed(name, phase, result):
        file_setup(phase, result)
        transition('response', name, C['HTTP_IO'], 800)
        assert (get('H_CLOSE_MODULE'), get('H_CLOSE_PHASE')) == (C['HTTP_DELIVERY'], 200)

    def delivery_setup(*, metadata=1, size=SIZE):
        reset(1, 64)
        put('H_S_CURRENT', 7)
        row = C['H_TASKS']
        for offset, value in {0: 1, 8: 9, 16: 7, 40: 44, 48: size, 72: 3, 248: metadata}.items():
            put(row+offset, value)
        header = C['SR_OUT_HEADER']
        arena[header:header+64] = struct.pack('<8Q', int.from_bytes(b'HIAHCO01', 'little'),
                                             size, 0, 9, 0, 0, 0, 0)

    def cache_setup(*, magic=b'HIAHEV02', size=SIZE, now=100, stamp=0, index=1):
        reset(210, 64)
        put('SR_CACHE_FD', 44)
        put('SR_CACHE_N', size+64)
        put('H_E_STREAM', 9)
        put('H_E_INDEX', index)
        put('H_NOW', now)
        arena[C['H_IO']:C['H_IO']+64] = struct.pack('<8Q', int.from_bytes(magic, 'little'),
                                                  9, stamp, size, 0, 0, 0, 0)

    try:
        for role in ('response', 'delivery', 'events', 'post'):
            path = ROOT/'examples/hia_bootstrap'/('mcp_http_'+role+'.hepta')
            raw = path.read_bytes()
            flat = seeds.compile(raw, 'div-word')
            (output/(role+'.flat')).write_bytes(flat)
            images[role] = NativeHiaJsonImage(flat, sha256(flat).hexdigest())
            report['sources'][str(path.relative_to(ROOT))] = {
                'source_sha256': sha256(raw).hexdigest(), 'source_bytes': len(raw),
                'image_sha256': sha256(flat).hexdigest(), 'image_bytes': len(flat)}

        reset(0)
        put('H_HTTP_SIZE', 16777729)
        record('ordinary-response-over-bound-remains-refused', step('response'), (0, (0,)*8))
        for field, value in [('H_HTTP_SIZE', MAXIMUM+129), ('H_HTTP_FILE_FD', 2),
                             ('H_HTTP_FILE_START', NONE-SIZE+1), ('H_HTTP_FILE_LEAD_N', 257),
                             ('CR_REPLY_FD', NONE), ('H_HTTP_FILE_MODE', 3)]:
            file_setup()
            put(field, value)
            transition('response', 'file-invalid-'+field, C['HTTP_IO'], 800)
            assert (get('H_CLOSE_MODULE'), get('H_CLOSE_PHASE')) == (C['HTTP_DELIVERY'], 200)

        file_setup()
        prefix = (format(SIZE, 'X')+'\r\n').encode()
        syscall('response', 'file-chunk-prefix-before-body',
                (18, 30, C['H_FILE_PREFIX'], len(prefix), 256, 0, 0, 12))
        assert arena[C['H_FILE_PREFIX']:C['H_FILE_PREFIX']+len(prefix)] == prefix
        syscall('response', 'file-prefix-short-write',
                (18, 30, C['H_FILE_PREFIX']+2, len(prefix)-2, 258, 0, 0, 12), result=2)
        syscall('response', 'file-prefix-eintr-preserves-offset',
                (18, 30, C['H_FILE_PREFIX']+2, len(prefix)-2, 258, 0, 0, 12), result=NEG4)
        syscall('response', 'file-first-read-bounded',
                (17, 44, C['H_FILE_BUFFER'], 65536, 512, 0, 0, 12), result=len(prefix)-2)
        offset = 256+len(prefix)
        syscall('response', 'file-short-read-written-exactly',
                (18, 30, C['H_FILE_BUFFER'], 100, offset, 0, 0, 12), result=100)
        syscall('response', 'file-short-body-write-preserves-offset',
                (18, 30, C['H_FILE_BUFFER']+40, 60, offset+40, 0, 0, 12), result=40)
        syscall('response', 'file-body-eintr-preserves-offset',
                (18, 30, C['H_FILE_BUFFER']+40, 60, offset+40, 0, 0, 12), result=NEG4)
        syscall('response', 'file-next-read-preserves-source-offset',
                (17, 44, C['H_FILE_BUFFER'], 65536, 612, 0, 0, 12), result=60)
        put('H_HTTP_USED', SIZE-31)
        syscall('response', 'file-final-short-read',
                (18, 30, C['H_FILE_BUFFER'], 31, offset+SIZE-31, 0, 0, 12), result=31)
        syscall('response', 'file-terminal-chunk-after-complete-body',
                (18, 30, C['H_FILE_SUFFIX'], 7, offset+SIZE, 0, 0, 12), result=31)
        assert arena[C['H_FILE_SUFFIX']:C['H_FILE_SUFFIX']+7] == b'\r\n0\r\n\r\n'
        syscall('response', 'file-complete-body-before-seal', (72, 30, 1033, 15, 0, 0, 0, 0), result=7)
        assert get('CR_REPLY_SENT') == 192
        assert get('CR_REPLY_N') == 256, 'unsealed complete length was published'
        transition('response', 'file-seal-refusal-keeps-task-cleanup', C['HTTP_IO'], 800, result=NEG5)
        assert (get('H_CLOSE_MODULE'), get('H_CLOSE_PHASE')) == (C['HTTP_DELIVERY'], 200)
        for name, phase, result in [('file-eof-refused', 114, 0), ('file-read-error-refused', 114, NEG5),
                                     ('file-overreported-read-refused', 114, 65537),
                                     ('file-memfd-failure-cleans-task', 2, NEG5),
                                     ('file-header-write-failure-cleans-task', 3, 0),
                                     ('file-response-seal-failure-cleans-task', 5, NEG5),
                                     ('file-epoll-failure-cleans-task', 6, NEG5)]:
            closed(name, phase, result)

        for metadata, size, accepted, label in (
            (0, 16777216, True, 'ordinary-parent-boundary'),
            (0, 16777217, False, 'ordinary-parent-over-bound'),
            (1, MAXIMUM, True, 'held-metadata-max'),
            (1, MAXIMUM+1, False, 'metadata-over-max'),
            (2, SIZE, False, 'invalid-metadata-admission-flag'),
        ):
            delivery_setup(metadata=metadata, size=size)
            if accepted:
                syscall('delivery', label, (319, C['H_IO'], 3, 0, 0, 0, 0, 3))
            else:
                transition('delivery', label, C['HTTP_DELIVERY'], 900)
        for field, value, label in [(C['H_TASKS']+8, 10, 'generation'),
                                     (C['H_TASKS']+16, 8, 'session'),
                                     (C['SR_OUT_HEADER']+48, 1, 'reserved')]:
            delivery_setup()
            put(field, value)
            transition('delivery', 'frame-refuses-wrong-'+label, C['HTTP_DELIVERY'], 900)
        delivery_setup()
        put(0, 100)
        syscall('delivery', 'large-parent-prefix-is-bounded', (17, 44, SESSION_OUT, 65536, 0, 0, 0, 12))
        syscall('delivery', 'large-parent-prefix-short-read', (17, 44, SESSION_OUT+17, 65536, 17, 0, 0, 12), result=17)
        syscall('delivery', 'large-parent-prefix-eintr', (17, 44, SESSION_OUT+17, 65536, 17, 0, 0, 12), result=NEG4)
        put(0, 111)
        put(8, 1)
        arena[C['H_IO']] = 0
        transition('delivery', 'large-parent-missing-final-lf-refused', C['HTTP_DELIVERY'], 900)
        put(0, 111)
        put(8, 1)
        arena[C['H_IO']] = 10
        transition('delivery', 'large-parent-complete-lf-enters-events', C['HTTP_EVENTS'], 100)
        assert get('H_D_N') == SIZE-1
        reset(5, NEG5)
        transition('delivery', 'parent-capture-seal-failure-never-delivers', C['HTTP_DELIVERY'], 900)

        for kind, role, tool, admitted in [(1, 5, 12, 1), (1, 5, 13, 1), (1, 5, 14, 1),
                                           (1, 5, 11, 0), (1, 5, 15, 0), (2, 5, 12, 0), (1, 4, 12, 0)]:
            reset(50)
            put('H_LEGACY', 1)
            put('H_S_CURRENT', 7)
            put('SR_NEXT_STREAM', 9)
            for offset, value in [(8, kind), (16, role), (56, tool)]:
                put(C['H_REQUEST_DESCRIPTOR']+offset, value)
            actual = step('post')
            assert actual[0] == 6 and get(C['H_TASKS']+248) == admitted, (kind, role, tool, actual)
            checks.append({'case': f'only-metadata-descriptor-{kind}-{role}-{tool}', 'passed': True,
                           'admitted': admitted})

        for index in (0, 1):
            cache_setup(index=index)
            transition('events', 'large-cache-file-replay-'+str(index), C['HTTP_RESPONSE'], 0)
            assert get('H_HTTP_FILE_MODE') == 2 and get('H_HTTP_FILE_FD') == 44
            assert get('H_HTTP_FILE_START') == 64 and get('H_HTTP_SIZE') == SIZE
            assert (get('H_HTTP_FILE_LEAD_N') > 0) is (index == 0)
        for label, options in [('original-cache-over-bound', {'magic': b'HIAHEV01', 'size': 16777729}),
                               ('unknown-cache-version', {'magic': b'HIAHEV03'}),
                               ('large-cache-over-bound', {'size': MAXIMUM+129})]:
            cache_setup(**options)
            transition('events', label, C['HTTP_DELIVERY'], 900)
        for offset in (32, 40, 48, 56):
            cache_setup()
            put(C['H_IO']+offset, 1)
            transition('events', 'large-cache-reserved-'+str(offset), C['HTTP_DELIVERY'], 900)
        for label, options in [('exact-sixty-second-cache-expiry', {'now': 60_000_000_000}),
                               ('future-cache-timestamp-refused', {'now': 100, 'stamp': 101}),
                               ('completed-event-index-empty', {'index': 2})]:
            cache_setup(**options)
            transition('events', label, C['HTTP_RESPONSE'], 0)
            assert get('H_HTTP_FILE_MODE') == 0 and get('H_HTTP_SIZE') == 5
        report.update(passed=True, passed_checks=len(checks))
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
    report = qualify(args.bootstrap.resolve(), args.output.resolve())
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks'])}))


if __name__ == '__main__':
    main()
