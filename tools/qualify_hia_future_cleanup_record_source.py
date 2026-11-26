"""Independent custody invariants for the cleanup-record author candidate.

This uses a bounded synthetic transport and scripted dependency completions.
It is not native execution, allocation qualification, or a concurrency gate.
"""
from pathlib import Path
import importlib.util
import json
import os
import struct
import sys

HERE = Path(__file__).resolve().parents[1]
OUTPUT = Path(os.environ.get('HEPTA_FUTURE_SOURCE_QA_OUTPUT', str(HERE / 'build/future-source-qa')))
OUTPUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(HERE))
path = HERE / 'tools/generate_hia_background_optimizer_future_public_cleanup.py'
spec = importlib.util.spec_from_file_location('record_author', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
C = module.C
NONE = (1 << 64) - 1

def put(b, at, n):
    struct.pack_into('<Q', b, at, n)

def get(b, at):
    return struct.unpack_from('<Q', b, at)[0]

env = {'readbuf': bytearray, 'mutbuf': bytearray, 'u64': int, 'u32': int,
       'length': len, 'byte': lambda b, at: b[at],
       'store': lambda b, at, n: b.__setitem__(at, n), 'word_load': get}
import re
record_source=module.SOURCE
for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
    record_source=re.sub(r'\b'+key+r'\b',str(value),record_source)
exec(compile(record_source, str(path) + ':record-SOURCE', 'exec'), env)

def packet(op, fid=(0, 0, 0), record=(0, 0, 0), kind=0, cap=(0, 0, 0), count=0):
    p = bytearray(192)
    p[:8] = b'HIABFC01'
    put(p, 8, op)
    for at, words in ((16, fid), (40, record), (72, cap)):
        for i, word in enumerate(words):
            put(p, at + 8 * i, word)
    put(p, 64, kind)
    put(p, 96, count)
    return p

def words(b, at):
    return tuple(get(b, at + i * 8) for i in range(3))

class Model:
    def __init__(self):
        self.w = bytearray(256)
        self.waddress = 0x30000
        put(self.w,208,self.waddress)
        put(self.w, 0, C['STATE'])
        put(self.w, 8, 12345)
        put(self.w, 72, 0x100)
        put(self.w, 80, 0x200)
        put(self.w, 112, 0x300)
        put(self.w, 120, 256)
        self.fid = (0x8000, 0x101, 0x202)
        factory = bytearray(512)
        put(factory, 0, C['FACTORY'])
        put(factory, 8, 12345)
        put(factory, 32, self.fid[1])
        put(factory, 40, self.fid[2])
        put(factory, 112, 1)
        put(self.w, 16, self.fid[0])
        self.memory = {self.fid[0]: factory}
        self.allocated = set()
        self.next_address = 0x100000
        self.random_count = 1
        self.provider_records = []
        self.next_records = []
        self.freed = []
        self.before_provider = None

    def span(self, selector, at, n, s, o):
        if selector in (1, 2, 3):
            buf = (None, self.w, s, o)[selector]
            assert 0 <= at <= len(buf) and n <= len(buf) - at
            return buf, at
        assert selector == 0
        for address, buf in self.memory.items():
            if address <= at <= address + len(buf) and n <= address + len(buf) - at:
                return buf, at - address
        raise AssertionError(('unowned extent', selector, at, n))

    def head(self, fid):
        return get(self.memory[fid[0]], 152) if fid[0] else get(self.w, 224)

    def chain(self, fid):
        out, at, previous = [], self.head(fid), 0
        while at:
            assert at not in out and at in self.allocated
            row = self.memory[at]
            assert get(row, 40) == previous
            out.append(at)
            previous, at = at, get(row, 48)
        return out

    def call(self, request):
        s, o = bytearray(request), bytearray(32768)
        for steps in range(100000):
            action = env['future_cleanup'](s, o, self.w)
            if action == 0:
                assert o[:8] == b'HIABFCR1'
                assert o[88:128] == bytes(40)
                return o[:128]
            if action == 10:
                continue
            if action in (2, 3):
                at, first, second = get(o, 0), get(o, 8), get(o, 16)
                old = get(self.w, at)
                assert at == 32
                if action == 3 or old == first:
                    put(self.w, at, first if action == 3 else second)
                raw = old
            elif action == 1:
                nr = get(o, 0)
                if nr == 39:
                    raw = 12345
                elif nr in (24, 202):
                    raw = 0
                elif nr == 318:
                    at, n = get(o, 16), get(o, 24)
                    assert get(o, 8) & 3 == 3 and n <= 16
                    data = struct.pack('<QQ', self.random_count, self.random_count ^ 0x987654)
                    o[at:at + n] = data[:n]
                    self.random_count += 1
                    raw = n
                else:
                    raise AssertionError(('unmodeled syscall', nr))
            elif action == 5:
                raw = self.waddress + get(o,0)
            elif action == 6:
                n = get(o, 0)
                if n > 1024 * 1024:
                    raw = 0
                else:
                    raw = self.next_address
                    self.next_address += ((n + 4095) // 4096 + 1) * 4096
                    self.memory[raw] = bytearray([0xA5]) * n
                    self.allocated.add(raw)
            elif action == 7:
                at = get(o, 0)
                assert at in self.allocated and at not in self.freed
                assert at not in self.chain(self.fid) and at not in self.chain((0, 0, 0))
                self.allocated.remove(at)
                self.freed.append(at)
                del self.memory[at]
                raw = 0
            elif action == 8:
                a, at, b, bt, n = (get(o, x) for x in (0, 8, 16, 24, 32))
                source, si = self.span(a, at, n, s, o)
                dest, di = self.span(b, bt, n, s, o)
                data = bytes(source[si:si + n])
                dest[di:di + n] = data
                raw = 0
            elif action == 9:
                assert get(self.w, 32) == 0, 'dependency call while global mutex held'
                src, sn, dst, dn = (get(o, x) for x in (16, 24, 32, 40))
                req = bytes(o[src:src + sn])
                op = get(req, 8)
                profile = req[:8]
                self.provider_records.append((profile.decode(), op, words(req, 24)))
                if self.before_provider is not None:
                    callback, self.before_provider = self.before_provider, None
                    callback()
                if self.next_records:
                    wanted, fields, corrupt = self.next_records.pop(0)
                    assert wanted == (profile.decode(), op), (wanted, profile, op)
                else:
                    fields, corrupt = None, None
                reply = bytearray(dn)
                if profile == b'HIABVQ02':
                    reply[:8] = b'HIABVR02'
                    status, known, consumed, pending = fields or (0, 1, int(op == 29), 0)
                    for off, n in ((8, status), (80, pending), (88, known), (96, consumed)):
                        put(reply, off, n)
                elif profile == b'HIABFQ04':
                    reply[:8] = b'HIABFR02'
                    if op == 20:
                        status, consumed = fields or (0, 1)
                        put(reply, 8, status)
                        put(reply, 128, consumed)
                    elif op == 21:
                        put(reply, 136, 0 if fields is None else fields[0])
                        put(reply, 144, 1)
                    else:
                        raise AssertionError(op)
                else:
                    assert profile == b'HIABFQ01' and op == 13
                    reply[:8] = b'HIABFR01'
                    put(reply, 8, 0 if fields is None else fields[0])
                if corrupt:
                    put(reply, *corrupt)
                o[dst:dst + dn] = reply
                raw = 0
            else:
                raise AssertionError(('unexpected action', action))
            put(o, C['FEEDBACK'], raw)
        raise AssertionError('policy failed to return in model')

    def reserve(self, fid=None, count=8):
        fid = self.fid if fid is None else fid
        r = self.call(packet(0, fid, count=count))
        assert get(r, 8) == 0 and get(r, 48) == 1 and get(r, 56) == 0
        assert get(r, 40) == 1 and get(r, 72) == 128 + 96 * count
        assert get(r, 80) == count
        return words(r, 16)

cases = []
def done(name, checks):
    cases.append({'case': name, 'checks': checks, 'passed': True})

count = 0
for fid_kind in ('factory', 'global'):
    m = Model()
    fid = m.fid if fid_kind == 'factory' else (0, 0, 0)
    rs = [m.reserve(fid, count=n) for n in (1, 8, 257)]
    assert m.chain(fid) == [x[0] for x in reversed(rs)]
    for idx in (1, 0, 2):
        r = m.call(packet(2, fid, rs[idx]))
        assert get(r, 8) == 0 and get(r, 56) == 1 and get(r, 48) == 1
        assert rs[idx][0] not in m.allocated
        m.chain(fid)
        bad = m.call(packet(2, fid, rs[idx]))
        assert get(bad, 8) == 1 and get(bad, 56) == 0
        count += 2
    assert not m.allocated
done('actual-registry-model-head-middle-tail-and-stale-record', count)

count = 0
for kind in (1, 2):
    m = Model(); rec = m.reserve(count=1)
    r = m.call(packet(1, m.fid, rec, kind, (0xAAA0, 11, 12)))
    assert get(r, 8) == 0 and get(r, 56) == 1
    assert m.memory[rec[0]][128:192] == bytes(64)
    r = m.call(packet(2, m.fid, rec))
    assert get(r, 8) == 0 and get(r, 40) == 0 and not m.allocated
    count += 2
done('poisoned-allocation-initialization-successful-drop-and-record-release', count)

m = Model(); rec = m.reserve(count=1); cap = (0xBBB0, 13, 14)
m.next_records = [(('HIABVQ02', 29), (11, 1, 0, 0), None)]
r = m.call(packet(1, m.fid, rec, 2, cap))
assert get(r, 8) == 9 and words(m.memory[rec[0]], 144) == cap
before = len(m.provider_records)
r = m.call(packet(1, m.fid, rec, 2, cap))
assert len(m.provider_records) == before and get(r, 56) == 1
assert get(m.call(packet(2, m.fid, rec)), 40) == 1
r = m.call(packet(3, m.fid))
assert get(r, 8) == 0 and get(r, 40) == 0 and not m.allocated
assert [x[1] for x in m.provider_records] == [29, 29]
done('known-preconsume-failure-retains-reference-and-retries-once-after-release', 6)

m = Model(); rec = m.reserve(count=1); cap = (0xCCC0, 15, 16)
m.next_records = [(('HIABVQ02', 29), (11, 1, 1, 1), None)]
r = m.call(packet(1, m.fid, rec, 2, cap))
assert words(m.memory[rec[0]], 144) == (0, 0, 0)
assert get(m.memory[rec[0]], 136) & 15 == 2
m.call(packet(2, m.fid, rec))
m.next_records = [(('HIABVQ02', 31), (11, 1, 0, 0), None)]
r = m.call(packet(3, m.fid))
assert get(r, 40) == 1 and get(m.memory[rec[0]], 136) & 15 == 2
r = m.call(packet(3, m.fid))
assert get(r, 40) == 0 and [x[1] for x in m.provider_records] == [29, 31, 31]
done('consumed-reference-never-redropped-and-failed31-preserves-mapping', 5)

count = 0
for fields, corrupt, mode in (
    ((11, 1, 1, 0), None, 4),
    ((6, 1, 0, 1), None, 4),
    ((11, 1, 0, 1), None, 4),
    ((0, 1, 1, 0), (8, 999), 3),
    ((0, 1, 1, 0), (80, 1), 3),
    ((11, 0, 0, 0), None, 3),
):
    m = Model(); rec = m.reserve(count=1); cap = (0xDDD0, 17, 18)
    m.next_records = [(('HIABVQ02', 29), fields, corrupt)]
    r = m.call(packet(1, m.fid, rec, 2, cap))
    assert get(m.memory[rec[0]], 136) & 15 == mode
    if fields[2] == 0 and fields[3] == 1:
        assert get(m.memory[rec[0]], 136) & 16
    if mode == 3 or fields[2] == 0:
        assert words(m.memory[rec[0]], 144) == cap
    else:
        assert words(m.memory[rec[0]], 144) == (0, 0, 0)
    m.call(packet(2, m.fid, rec))
    calls = len(m.provider_records)
    r = m.call(packet(3, m.fid))
    assert get(r, 40) == 1 and len(m.provider_records) == calls and rec[0] in m.allocated
    count += 4
done('quarantine-preserves-known-and-unknown-fates-without-effect-replay', count)

m = Model(); rec = m.reserve(count=1); cap = (0xEEE0, 19, 20)
m.next_records = [(('HIABFQ04', 20), (9, 1), None)]
m.call(packet(1, m.fid, rec, 1, cap)); m.call(packet(2, m.fid, rec))
m.next_records = [(('HIABFQ01', 13), (0,), None), (('HIABFQ04', 21), (1,), None)]
r = m.call(packet(3, m.fid))
assert get(r, 40) == 1 and rec[0] in m.allocated
r = m.call(packet(3, m.fid))
assert get(r, 40) == 0 and not m.allocated
assert [x[1] for x in m.provider_records] == [20, 13, 21, 13, 21]
done('cell13-success-is-not-empty-without-actual-locked-query21', 4)

m = Model(); rec = m.reserve(count=1)
def interleave():
    assert get(m.memory[rec[0]], 80) == 1
    r = m.call(packet(2, m.fid, rec))
    assert get(r, 8) == 5 and get(r, 56) == 0 and rec[0] in m.allocated
    r = m.call(packet(3, m.fid))
    assert get(r, 40) == 1 and rec[0] in m.allocated
m.before_provider = interleave
r = m.call(packet(1, m.fid, rec, 2, (0xFFF0, 21, 22)))
assert get(r, 8) == 0 and get(m.memory[rec[0]], 80) == 0
m.call(packet(2, m.fid, rec))
assert not m.allocated
done('synthetic-interleaving-claim-protects-active-record-and-storage', 5)

count = 0
for op in range(8):
    for off in range(16, 192, 8):
        p = packet(op, count=1 if op == 0 else 0)
        if op == 1:
            put(p, 64, 2); put(p, 72, 1)
        put(p, off, 1)
        o = bytearray(b'\xa5' * 32768)
        result = env['begin'](p, o, bytearray(256))
        if result == (1 << 32) - 3:
            assert o == b'\xa5' * 32768
        count += 1
m = Model()
r = m.call(packet(0, m.fid, count=(NONE - 160) // 96))
assert get(r, 8) == 4 and not m.allocated
done('strict-reserved-domain-and-full-u64-allocation-extent', count + 1)

count = 0
for field in (0, 8, 16, 24):
    m = Model(); rec = m.reserve(count=2)
    actual = m.memory[rec[0]]
    shadow = 128 + 64 * 2
    put(actual, shadow + field, 0xA11)
    saved = bytes(actual[shadow:])
    r = m.call(packet(2, m.fid, rec))
    assert get(r, 8) == 9 and get(r, 48) == 0 and get(r, 56) == 1
    assert get(actual, 112) == 1 and rec[0] in m.chain(m.fid)
    for _ in range(3):
        r = m.call(packet(3, m.fid))
        assert get(r, 8) == 9 and get(r, 48) == 0 and get(r, 40) == 1
        assert bytes(actual[shadow:]) == saved and not m.provider_records
        assert rec[0] in m.allocated
        count += 1
    count += 2
done('retained-original-caller-shadow-quarantines-without-replay-or-free', count)

report = {'schema': 'hepta.hia.future-cleanup-record-author-probes.v1',
          'passed': True, 'checks': sum(x['checks'] for x in cases), 'cases': cases,
          'execution_kind': 'Pure author evaluation with independent synthetic byte transport and scripted dependency completions',
          'native_execution_qualification_pass': False,
          'actual_concurrency_qualified': False,
          'whole_native_runtime_closed': False}
(OUTPUT / 'cleanup-record-probes-v1.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
