"""Carrier ownership graph checks using independent synthetic byte transport.

The callback and value/cell leaves are scripted; no native or concurrency claim.
"""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import runpy
import struct

HERE = Path(__file__).resolve().parents[1]
OUTPUT = Path(os.environ.get('HEPTA_FUTURE_SOURCE_QA_OUTPUT', str(HERE / 'build/future-source-qa')))
OUTPUT.mkdir(parents=True, exist_ok=True)
with contextlib.redirect_stdout(io.StringIO()):
    public = runpy.run_path(str(HERE / 'tools/qualify_hia_future_public_temporaries_source.py'))
PublicModel = public['PublicModel']
put, get, words = public['put'], public['get'], public['words']
p = HERE / 'tools/generate_hia_background_optimizer_future_public_carrier.py'
spec = importlib.util.spec_from_file_location('temp_carrier_author', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
C = m.C
env = {'readbuf': bytearray, 'mutbuf': bytearray, 'u64': int, 'u32': int,
       'length': len, 'byte': lambda b, at: b[at],
       'store': lambda b, at, n: b.__setitem__(at, n), 'word_load': get}
exec(compile(m.source_program(), str(p) + ':SOURCE', 'exec'), env)


class CarrierModel(PublicModel):
    def __init__(self):
        super().__init__()
        self.policy = env['future_carrier']
        self.policy_constants = C
        put(self.w, 64, 0x600)
        put(self.w, 176, 0x800)
        put(self.memory[self.fid[0]], 56, 1)
        self.frame = 0x400000
        self.carrier = 0x500000
        frame = bytearray(128)
        for at, v in ((16, 77), (24, self.fid[0]), (88, C['FMAGIC'])):
            put(frame, at, v)
        self.memory[self.frame] = frame
        put(self.memory[self.fid[0]], 96, self.frame)
        obj = bytearray(33792)
        for at, v in ((0, C['OBJECT']), (8, 12345), (16, self.fid[0]),
                      (24, self.fid[1]), (32, self.fid[2]), (40, 0x9000),
                      (48, 0x700), (56, 0xE000), (64, 70), (72, 71),
                      (96, 1), (184, self.waddress)):
            put(obj, at, v)
        self.memory[self.carrier] = obj
        put(self.memory[self.fid[0]], 104, self.carrier)
        self.callback_kind = 0
        self.callback_cap = (0xD000, 61, 62)
        self.future_cap = (0xC000, 51, 52)
        self.retained_env = (0xE010, 81, 82)
        self.value_observation_failure = False
        self.env_invalid = False

    def request(self, op):
        p = bytearray(192)
        p[:8] = b'HIAPFC01'
        put(p, 8, op)
        if op:
            put(p, 16, self.carrier)
            if op == 1:
                put(p, 24, 0x9000)
        else:
            for at, values in ((16, self.fid), (40, (0xA000, 1, 2)),
                               (64, (0xE000, 70, 71))):
                for i, v in enumerate(values):
                    put(p, at + i * 8, v)
            put(p, 88, 0x700)
        return p

    def leaf_reply(self, fn, req, dn):
        op = get(req, 8)
        out = bytearray(dn)
        if fn == 0x200:
            out[:8] = b'HIABFR01'
            if op == 14:
                assert req[:8] == b'HIABFQ02'
                for at, v in zip((16, 24, 32), self.future_cap):
                    put(out, at, v)
            elif op == 6:
                put(out, 8, int(self.bad_initial_future))
                put(out, 64, 0x9000)
            else:
                assert op == 13, op
        elif fn == 0x100:
            out[:8] = b'HIABVR01'
            if op == 5:
                for at, v in zip((24, 32, 40), self.retained_env):
                    put(out, at, v)
            else:
                assert op == 7, op
                cap = words(req, 24)
                put(out, 8, int(self.env_invalid if cap[0] == 0xE000 else self.value_observation_failure))
                put(out, 16, 6)
        elif fn == 0x700:
            assert req[:8] == b'HIAFCBQ1'
            assert words(req, 40) == self.future_cap
            assert words(req, 64) == (0xE000, 70, 71)
            out[:8] = b'HIAFCBR1'
            put(out, 8, self.callback_kind)
            for at, v in zip((24, 32, 40), self.callback_cap):
                put(out, at, v)
        elif fn == 0x800:
            assert req[:8] == b'HIAFPL01'
            out[:8] = b'HIAFPLR1'
        else:
            assert fn == 0x600 and req[:8] == b'HIAMVFQ1' and op == 4
            out[:8] = b'HIAMVFR1'
        return out


cases = []
def record(name, count):
    cases.append({'case': name, 'checks': count, 'passed': True})

for kind in (0, 1, 2):
    model = CarrierModel(); model.callback_kind = kind
    r = model.run(request=model.request(1))
    assert not model.allocated and model.head(model.fid) == 0
    assert get(model.memory[model.carrier], 104) == 1
    assert [x[1] for x in model.provider_records] == ([20] if kind == 2 else [20, 29])
    assert words(model.memory[model.carrier], 56) == (0xE000, 70, 71)
    if kind == 2:
        assert words(model.memory[model.frame], 40) == model.callback_cap
        assert get(model.memory[model.frame], 32) == 2
    assert get(r, 8) == 0
record('callback-result-and-baseexception-transfer-keeps-borrowed-environment', 15)

for op in (0, 1):
    model = CarrierModel(); model.fail_allocation = True
    r = model.run(request=model.request(op))
    assert not model.allocated and not model.provider_records
    if op == 0:
        assert get(r, 8) == 1 and get(r, 16) == 103
    else:
        assert get(model.memory[model.frame], 80) == 103
        assert get(model.memory[model.frame], 32) == 1
    assert not any(profile == 'HIABFQ02' for _, profile, _ in model.private_calls)
record('reserve-before-first-owned-env-or-callback-future-with-original-error-carrier', 6)

model = CarrierModel(); model.fail_allocation = True; model.env_invalid = True
r = model.run(request=model.request(0))
assert get(r, 16) == 107 and model.private_calls == [(0x100, 'HIABVQ01', 7)]
record('invalid-environment-precedes-reservation-memory-error', 1)

for fail_kind in ('bad-future', 'allocation'):
    model = CarrierModel()
    model.bad_initial_future = fail_kind == 'bad-future'
    model.policy_allocation_failure = fail_kind == 'allocation'
    model.next_records = [(('HIABVQ02', 29), (11, 1, 1, 0), None)]
    r = model.run(request=model.request(0))
    assert get(r, 8) == 1
    node = model.head(model.fid)
    assert node in model.allocated and get(model.memory[node], 72) == 1
    assert model.provider_records == [('HIABVQ02', 29, model.retained_env)]
    assert get(model.memory[node], 128 + 8) & 15 == 4
    assert model.last_output[C['ENV_TEMP']:C['ENV_TEMP'] + 24] == bytes(24)
record('retained-env-after-register-failure-stays-in-independent-factory-record', 10)

model = CarrierModel(); model.value_observation_failure = True
model.next_records = [(('HIABFQ04', 20), (0, 1), None),
                      (('HIABVQ02', 29), (1, 1, 0, 0), None)]
r = model.run(request=model.request(1))
assert model.provider_records[-1] == ('HIABVQ02', 29, model.callback_cap)
assert model.head(model.fid) in model.allocated
record('failed-result-observation-does-not-prove-owned-result-consumption', 2)

for off, value in ((0, 0), (8, 999), (56, 0), (104, 1)):
    model = CarrierModel(); model.guard_corruption = [(1, off, value)]
    r = model.run(request=model.request(1))
    node = model.head(model.fid)
    actual = model.memory[node]
    assert get(actual, 112) == 1 and get(actual, 72) == 1
    shadow = 128 + 16 * 64
    assert words(actual, shadow + 8) == model.future_cap
    assert words(actual, shadow + 32 + 8) == model.callback_cap
    assert len(model.provider_records) == 1
    assert get(r, 8) == 1 and get(r, 16) == 107
record('malformed-carrier-temp-completion-retains-all-original-callsite-refs', 20)

report = {'schema': 'hepta.hia.future-carrier-temp-chain-author-probes.v1',
          'passed': True, 'checks': sum(x['checks'] for x in cases), 'cases': cases,
          'execution_kind': 'Carrier and cleanup author policies with synthetic byte transport and scripted leaves',
          'native_execution_qualification_pass': False, 'actual_concurrency_qualified': False,
          'whole_native_runtime_closed': False}
(OUTPUT / 'carrier-temp-chain-probes-v1.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
