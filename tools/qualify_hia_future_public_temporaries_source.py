"""Independent byte-transport development probes for the new temp chain.

Runs the two pure author policies with scripted leaf completions. This is not
native execution, syscall fault injection, or actual concurrent qualification.
"""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import runpy
import struct
import sys

HERE = Path(__file__).resolve().parents[1]
OUTPUT = Path(os.environ.get('HEPTA_FUTURE_SOURCE_QA_OUTPUT', str(HERE / 'build/future-source-qa')))
OUTPUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(HERE))
with contextlib.redirect_stdout(io.StringIO()):
    record = runpy.run_path(str(HERE / 'tools/qualify_hia_future_cleanup_record_source.py'))
Model = record['Model']
put, get, words = record['put'], record['get'], record['words']
NONE = (1 << 64) - 1
p = HERE / 'tools/generate_hia_background_optimizer_future_public_owner.py'
spec = importlib.util.spec_from_file_location('temp_public_author', p)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
C = module.C
env = {'readbuf': bytearray, 'mutbuf': bytearray, 'u64': int, 'u32': int,
       'length': len, 'byte': lambda b, at: b[at],
       'store': lambda b, at, n: b.__setitem__(at, n), 'word_load': get}
exec(compile(module.full_source_program(), str(p) + ':SOURCE', 'exec'), env)


class PublicModel(Model):
    def __init__(self):
        super().__init__()
        self.waddress = 0x30000
        self.memory[self.waddress] = self.w
        put(self.w, 216, 0x400)
        put(self.memory[self.fid[0]], 48, 0x1230)
        self.private_calls = []
        self.guard_corruption = []
        self.bad_initial_future = False
        self.fail_allocation = False
        self.temp_nonce = 0
        self.after_reserve = None
        self.policy = env['future_public']
        self.policy_constants = C
        self.policy_allocation_failure = False

    def run(self, op=9, initial=None, request=None):
        s = bytearray(192)
        s[:8] = b'HIABFP01'
        put(s, 8, op)
        if op != 20:
            for at, values in ((16, self.fid), (40, (0xABC0, 22, 33))):
                for i, v in enumerate(values):
                    put(s, at + i * 8, v)
        if request is not None:
            s = bytearray(request)
        o = bytearray(65536) if initial is None else bytearray(initial)
        for _ in range(100000):
            action = self.policy(s, o, self.w)
            if action == 0:
                assert o[:8] in (b'HIABFRP1', b'HIABFRP2', b'HIAPFCR1')
                assert get(self.w, 32) == 0
                self.last_output = o
                return o[:128]
            if action == 10:
                continue
            if action in (2, 3):
                off, a, b = (get(o, x) for x in (0, 8, 16))
                assert off == 32
                old = get(self.w, off)
                if action == 3 or old == a:
                    put(self.w, off, a if action == 3 else b)
                raw = old
            elif action == 1:
                nr = get(o, 0)
                assert nr in (39, 186, 202, 24), nr
                raw = 12345 if nr == 39 else 77 if nr == 186 else 0
            elif action == 5:
                raw = self.waddress + get(o, 0)
            elif action == 4:
                raise AssertionError('frame path needs a separate modeled owner call')
            elif action == 6:
                if self.policy_allocation_failure:
                    raw = 0
                else:
                    n = get(o, 0)
                    raw = self.next_address
                    self.next_address += ((n + 4095) // 4096 + 1) * 4096
                    self.memory[raw] = bytearray([0xA5]) * n
                    self.allocated.add(raw)
            elif action == 7:
                ptr = get(o, 0)
                assert ptr in self.allocated
                self.allocated.remove(ptr)
                del self.memory[ptr]
                raw = 0
            elif action == 8:
                a, at, b, bt, n = (get(o, x) for x in (0, 8, 16, 24, 32))
                src, si = self.span(a, at, n, s, o)
                dst, di = self.span(b, bt, n, s, o)
                dst[di:di + n] = bytes(src[si:si + n])
                raw = 0
            elif action == 9:
                fn = get(o, 0)
                src, sn, dst, dn = (get(o, x) for x in (16, 24, 32, 40))
                assert get(o, 8) == 51
                req = bytes(o[src:src + sn])
                op = get(req, 8)
                self.private_calls.append((fn, req[:8].decode(), op))
                if fn == 0x400:
                    assert get(self.w, 32) == 0
                    if op == 0 and self.fail_allocation:
                        reply = bytearray(128)
                        reply[:8] = b'HIABFCR1'
                        put(reply, 8, 4)
                        put(reply, 48, 1)
                    else:
                        reply = self.call(req)
                    if op == 0 and self.after_reserve is not None:
                        callback, self.after_reserve = self.after_reserve, None
                        callback()
                    if self.guard_corruption and self.guard_corruption[0][0] == op:
                        _, at, v = self.guard_corruption.pop(0)
                        put(reply, at, v)
                else:
                    reply = self.leaf_reply(fn, req, dn)
                assert len(reply) == dn
                o[dst:dst + dn] = reply
                raw = 0
            else:
                raise AssertionError(('unexpected public action', action, get(o, self.policy_constants['PHASE'])))
            put(o, self.policy_constants['FEEDBACK'], raw)
        raise AssertionError(('public policy did not terminate', get(o, self.policy_constants['PHASE'])))

    def leaf_reply(self, fn, req, dn):
        assert fn == 0x200 and req[:8] == b'HIABFQ01'
        reply = bytearray(dn)
        reply[:8] = b'HIABFR01'
        op = get(req, 8)
        if op == 6:
            put(reply, 8, int(self.bad_initial_future))
            put(reply, 64, 0x9000)
        elif op == 2:
            self.temp_nonce += 1
            for at, v in zip((16, 24, 32), (0xB000 + 16 * self.temp_nonce, 44, 55)):
                put(reply, at, v)
        elif op == 9:
            put(reply, 48, 2)
        else:
            assert op == 13, op
        return reply


cases = []
def checked(name, count):
    cases.append({'case': name, 'checks': count, 'passed': True})

m = PublicModel()
r = m.run()
assert get(r, 8) == 0 and get(r, 96) == 2 and get(r, 120) == 0
assert not m.allocated and get(m.memory[m.fid[0]], 152) == 0
assert get(m.memory[m.fid[0]], 56) == 0
assert [x[1] for x in m.provider_records] == [20]
assert m.private_calls == [(0x200, 'HIABFQ01', 6), (0x400, 'HIABFC01', 0),
                           (0x200, 'HIABFQ01', 2), (0x200, 'HIABFQ01', 9),
                           (0x400, 'HIABFC01', 1), (0x400, 'HIABFC01', 2)]
checked('full-public-observe-acquire-adopt-release-and-original-reply', 5)

m = PublicModel(); m.bad_initial_future = True; m.fail_allocation = True
r = m.run()
assert get(r, 8) != 0 and get(r, 16) != 103 and not m.allocated
assert m.private_calls == [(0x200, 'HIABFQ01', 6)]
m = PublicModel(); m.fail_allocation = True
r = m.run()
assert get(r, 8) == 1 and get(r, 16) == 103 and not m.allocated
assert not any(op == 2 for _, profile, op in m.private_calls if profile == 'HIABFQ01')
assert get(m.memory[m.fid[0]], 56) == 0
checked('original-invalid-capability-before-reservation-and-reserve-OOM-before-retain', 5)

for fields in ((1, 0), (9, 0), (9, 1)):
    m = PublicModel()
    m.next_records = [(('HIABFQ04', 20), fields, None)]
    r = m.run()
    assert get(r, 8) == 0 and get(r, 120) == NONE
    node = m.head(m.fid)
    assert node and node in m.allocated and get(m.memory[node], 72) == 1
    assert m.last_output[C['FUTURE_TEMP']:C['FUTURE_TEMP'] + 24] == bytes(24)
    assert m.memory[node][128 + 64 * 16:] == bytes(32 * 16)
    m.run(20)
    assert not m.allocated and m.head(m.fid) == 0
    assert [x[1] for x in m.provider_records] == ([20, 13, 21] if fields[1] else [20, 20])
checked('known-preconsume-and-postconsume-failures-retained-through-real-record-graph', 18)

for off, value in ((0, 0), (8, 999), (48, 3), (56, 0), (88, 1)):
    m = PublicModel(); m.guard_corruption = [(1, off, value)]
    r = m.run()
    node = m.head(m.fid)
    assert node and node in m.allocated
    actual = m.memory[node]
    assert get(actual, 112) == 1 and get(actual, 72) == 1
    assert get(actual, 128 + 64 * 16) == 1
    assert get(r, 120) == NONE and get(m.memory[m.fid[0]], 56) == 0
    before = len(m.provider_records)
    m.run(20)
    assert node in m.allocated and len(m.provider_records) == before
checked('malformed-guard-completion-preserves-actual-caller-shadow-without-replay', 25)

for off, value in ((0, 0), (8, 999), (56, 0), (96, 1)):
    m = PublicModel(); m.guard_corruption = [(2, off, value)]
    r = m.run()
    assert not m.allocated
    factory = m.memory[m.fid[0]]
    assert get(factory, 144) == 1 and get(factory, 168) != 0
    assert get(r, 120) == NONE
    assert get(factory, 56) == 0
checked('malformed-post-release-record-never-dereferenced-after-possible-free', 16)

m = PublicModel()
def new_frame_head():
    put(m.memory[m.fid[0]], 96, 0x515151)
m.after_reserve = new_frame_head
r = m.run()
assert get(m.last_output, C['HEADER'] + 96) == 0x515151
assert get(m.memory[m.fid[0]], 96) == 0x515151
checked('live-header-refreshed-after-reservation-unlocks-registry', 2)

def inherited_state(model):
    cap = model.reserve(count=16)
    initial = bytearray(65536)
    for name, value in [('PHASE', 1400), ('EACTIVE', 1), ('ACTIVE', 1),
                        ('PID', 12345), ('TID', 77), ('F', model.fid[0]),
                        ('WPTR', model.waddress), ('GPTR', cap[0]),
                        ('ERROR', 1), ('RKIND', 107)]:
        put(initial, C[name], value)
    for at, values in ((C['GCAP'], cap), (C['FACTORY_ID'], model.fid)):
        for i, value in enumerate(values):
            put(initial, at + 8 * i, value)
    expected = []
    for i in range(6):
        value = (0x60000 + 16 * i, i + 1, i + 100)
        expected.append(value)
        for j, v in enumerate(value):
            put(initial, C['EVAL_CAP'] + 24 * i + 8 * j, v)
    put(model.memory[model.fid[0]], 56, 1)
    return initial, cap, expected

m = PublicModel(); initial, cap, expected = inherited_state(m)
r = m.run(initial=initial)
assert [x[1] for x in m.provider_records] == [29] * 6
assert [x[2] for x in m.provider_records] == expected
assert not m.allocated and get(m.memory[m.fid[0]], 56) == 0
assert get(r, 8) == 1 and get(r, 16) == 107 and get(r, 120) == 0
checked('all-six-inherited-owned-temporaries-use-actual-record-before-old-slot-clear', 4)

for corrupt in ((0, 0), (48, 3), (56, 0), (104, 1)):
    m = PublicModel(); initial, cap, expected = inherited_state(m)
    m.guard_corruption = [(1, *corrupt)]
    r = m.run(initial=initial)
    actual = m.memory[cap[0]]
    shadow = 128 + 16 * 64
    assert get(actual, 112) == 1 and get(actual, 72) == 1
    assert [x[1] for x in m.provider_records] == [29]
    assert [words(actual, shadow + 64 + i * 32 + 8) for i in range(6)] == expected
    assert m.last_output[C['EVAL_CAP']:C['EVAL_CAP'] + 144] == bytes(144)
    before = len(m.provider_records)
    m.run(20)
    assert len(m.provider_records) == before and cap[0] in m.allocated
checked('inherited-malformed-completion-preserves-cleared-and-not-yet-cleaned-refs', 20)

report = {'schema': 'hepta.hia.future-public-temp-chain-author-probes.v1',
          'passed': True, 'checks': sum(x['checks'] for x in cases), 'cases': cases,
          'execution_kind': 'Two pure author policies with independent synthetic byte transport and scripted leaf completions',
          'native_execution_qualification_pass': False, 'actual_concurrency_qualified': False,
          'whole_native_runtime_closed': False}
(OUTPUT / 'public-temp-chain-probes-v1.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
