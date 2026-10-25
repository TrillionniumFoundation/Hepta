"""Independent mathematical oracle, never copied into adapter/build capsules.

No candidate implementation or generated output is used to derive expectations.
Allocation/thread/native call instrumentation is part of the public task contract.
"""
from __future__ import annotations

import bisect
import random


def hidden_cases(task):
    rng = random.Random(2026102407)
    if task == 'api_migration':
        pairs = [(q, p) for q in (-3, 0, 1, 9, 10, 11, 100) for p in (-1, 0, 1, 99, 1001)]
        pairs += [(rng.randrange(0, 300), rng.randrange(0, 50000)) for _ in range(40)]
    elif task == 'owned_result':
        pairs = [(n, mode) for n in (0, 1, 17, 251, 257, 1021, 4093, 65519) for mode in (0, 1)]
    elif task == 'native_bridge':
        pairs = [(a, b) for a in (-4000, -1, 0, 1, 3333, 4000) for b in (-2, 0, 1, 7)]
        pairs += [(rng.randrange(-300, 300), rng.randrange(-2, 20)) for _ in range(32)]
    elif task == 'resource_cancel':
        pairs = [(n, mode) for n in (0, 1, 2, 17, 257, 1021, 4099) for mode in (0, 1)]
    elif task == 'defect_repair':
        pairs = [(n, key) for n in (-1, 0, 1, 2, 3, 7, 63, 64, 65)
                 for key in (-10, -7, -6, 0, 13, 14, 100)]
        pairs += [(rng.randrange(0, 65), rng.randrange(-10, 20)) for _ in range(80)]
    else:
        raise ValueError('unknown task')
    cases = [{'id': i, 'a': a, 'b': b, 'refuse': False} for i, (a, b) in enumerate(pairs)]
    if task == 'owned_result':
        for n in (17, 257, 1021, 65519):
            for mode in (0, 1):
                cases.append({'id': len(cases), 'a': n, 'b': mode, 'refuse': True})
    return cases


def expected(task, case):
    a, b = case['a'], case['b']
    out = {'id': case['id'], 'result': 0, 'allocations': 0, 'frees': 0,
           'refusals': 0, 'threads': 0, 'joins': 0, 'c_calls': 0, 'cpp_calls': 0}
    if task == 'api_migration':
        out['result'] = -1 if a < 0 or b < 0 else a * b * (8750 if a >= 10 else 9750) // 10000
    elif task == 'owned_result':
        if a == 0:
            out['result'] = -1
        elif case['refuse']:
            out.update(result=-3, refusals=1)
        else:
            out.update(result=-2 if b else sum((i * 7 + 3) % 251 for i in range(a)), allocations=1, frees=1)
    elif task == 'native_bridge':
        adjusted = a * 3 + b
        out.update(result=-101 if b < 0 or not -10000 <= adjusted <= 10000 else (2 * adjusted + 1) * b,
                   c_calls=1, cpp_calls=1)
    elif task == 'resource_cancel':
        if a < 2:
            out['result'] = -1
        else:
            out.update(result=sum(i % 251 for i in range(1, a)) + (1000000 if b else 0),
                       allocations=1, frees=1, threads=1, joins=1)
    elif task == 'defect_repair':
        out['result'] = -1 if not 0 <= a <= 64 else bisect.bisect_left([i // 3 - 7 for i in range(a)], b)
    else:
        raise ValueError('unknown task')
    return out


def contract_probe(task, language):
    """Compile-only API clients; they contain no hidden case values."""
    if task == 'api_migration':
        if language == 'rust':
            return '''\nfn cf_contract() { let _: Result<i64, i32> = pricing::quote(0, pricing::Price { unit_cents: 1, discount_bps: 1 }); }\n'''
        return '''\nfn cf_contract() -> i64 effects {panic} {
    match pricing::quote(0, pricing::Price {unit_cents:1, discount_bps:1}) {
        Result::Ok(value) => { return value; }, Result::Err(code) => { return -(code as i64); },
    }
}\n'''
    if task == 'owned_result':
        if language == 'rust':
            return '''\nfn cf_contract() { let x: Result<storage::Packet, i32> = storage::make(0); if let Ok(packet) = x { storage::close(packet); } }\n'''
        return '''\nfn cf_contract() -> Unit effects {alloc,block,panic,write} {
    let x: Result<storage::Packet, i32> = storage::make(0);
    match move x { Result::Ok(packet) => {storage::close(move packet);}, Result::Err(code) => {}, }
}\n'''
    return ''
