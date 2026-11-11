"""Reconstructed independent Core summary proof controls.

RECONSTRUCTED_FROM_CONTEXT after environment replacement. The old local run
has no retained terminal receipt and is not counted as passing. This version
must run fresh against the exact retained reference below. It is test-only;
no Python summary or decision is used by the production native component.
"""
from hashlib import sha256
import argparse
import json
from pathlib import Path
import random
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--base', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
sys.path.insert(0, str(args.base.resolve()))
from hepta import hia_program as reference
reference_raw = Path(reference.__file__).read_bytes()
assert sha256(reference_raw).hexdigest() == '76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92'
M, DEPTH, BYTES = reference.MAX_NODES, reference.MAX_DEPTH, reference.MAX_BYTES
assert (M, DEPTH, BYTES) == (262144, 64, 8388608)
MAX, CAP = (1 << 64) - 1, M + 1


def summary(value, limit):
    pending, nodes, arities, first = [(value, 0)], 0, 0, MAX
    root = {type(None): 0, bool: 1, int: 2, str: 4, list: 5, dict: 6}[type(value)]
    while pending:
        node, depth = pending.pop()
        nodes = min(CAP, nodes + 1)
        if depth > limit and first == MAX:
            first = arities
        if type(node) in (list, dict):
            values = node if type(node) is list else list(node.values())
            arities = min(CAP, arities + len(values))
            pending.extend((child, depth + 1) for child in reversed(values))
    assert nodes == min(CAP, 1 + arities)
    return root, nodes, first


def decision(nodes, first):
    if first != MAX and first <= M - 1:
        return 1
    return 2 if nodes > M else 0


def reference_snapshot(value):
    try:
        reference._bounded_detached_snapshot(value)
        return 0
    except reference.HIAProgramRejected as exc:
        if exc.code != 'E_HIA_LIMIT':
            raise
        if str(exc).endswith('caller-owned tree exceeds snapshot budget'):
            return 1
        if str(exc).endswith('caller-owned tree exceeds queued-node budget'):
            return 2
        raise


def composed_outer(value):
    pending, nodes, arities, first = [(value, 0, False)], 0, 0, MAX
    while pending:
        node, depth, opaque = pending.pop()
        if opaque:
            kind, n, d = summary(node, 62)
            assert kind == 6 and depth == 2
            if first == MAX and d != MAX:
                first = min(CAP, arities + d)
            nodes = min(CAP, nodes + n)
            arities = min(CAP, arities + n - 1)
            continue
        nodes = min(CAP, nodes + 1)
        if depth > DEPTH and first == MAX:
            first = arities
        if type(node) in (dict, list):
            values = node if type(node) is list else list(node.values())
            arities = min(CAP, arities + len(values))
            opaque_children = type(node) is list and depth == 1 and node is value['functions']
            pending.extend((child, depth + 1, opaque_children) for child in reversed(values))
    return nodes, first


def chain(depth, leaf=0):
    result = leaf
    for _ in range(depth):
        result = [result]
    return result


def outer(functions):
    return {'schema': 'hepta.hia.program.v8', 'module': 'm', 'exports': [], 'functions': functions}


cases = []
started = time.monotonic_ns()


def compare(label, value, compose=False):
    actual = summary(value, DEPTH)
    expected = reference_snapshot(value)
    assert decision(actual[1], actual[2]) == expected, (label, actual, expected)
    if compose:
        joined = composed_outer(value)
        assert joined == actual[1:], (label, joined, actual)
    cases.append({'case': label, 'snapshot': expected, 'nodes_cap': actual[1],
                  'first_depth_arity_prefix': actual[2], 'opaque_composition_exact': compose})


compare('scalar', 0)
for depth in (62, 63, 64, 65, 66, 80):
    compare('absolute-depth-' + str(depth), chain(depth))
    compare('function-relative-depth-' + str(depth), outer([{'x': chain(depth - 1)}]), True)
for size in (M - 2, M - 1, M, M + 1):
    compare('list-nodes-' + str(size), [None] * size)
compare('map-keys-do-not-count', {str(i): None for i in range(M - 1)})
compare('alias-is-counted-twice', [[None] * (M // 2)] * 2)
compare('depth-before-wide', [chain(65), [None] * M])
compare('wide-before-depth', [[None] * M, chain(65)])
compare('dict-order-depth-first', {'deep': chain(65), 'wide': [None] * M})
compare('dict-order-wide-first', {'wide': [None] * M, 'deep': chain(65)})
for delta in (-1, 0, 1):
    compare('opaque-queued-before-depth-' + str(delta), outer([
        {'wide': [None] * (M - 80 + delta)}, {'deep': chain(64)}]), True)
    compare('opaque-depth-before-queued-' + str(delta), outer([
        {'deep': chain(64)}, {'wide': [None] * (M - 80 + delta)}]), True)

rng = random.Random(0x434f52455f4c415445)
def random_value(depth):
    pick = rng.randrange(6 if depth else 4)
    if pick == 0: return None
    if pick == 1: return bool(rng.randrange(2))
    if pick == 2: return rng.randrange(1 << 32)
    if pick == 3: return rng.choice(('', 'a', '中', 'quote"', '\0'))
    if pick == 4: return [random_value(depth - 1) for _ in range(rng.randrange(5))]
    return {'key' + str(i): random_value(depth - 1) for i in range(rng.randrange(5))}
for i in range(400):
    values = [{'body': random_value(4)} for _ in range(rng.randrange(1, 8))]
    if i % 5 == 0:
        values.insert(rng.randrange(len(values) + 1), {'deep': chain(rng.randrange(58, 70))})
    compare('deterministic-' + str(i), outer(values), True)

byte_cases = []
for delta in (-1, 0, 1):
    value = {'x': 'a' * (BYTES - 8 + delta)}
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    assert len(raw) == BYTES + delta
    assert reference_snapshot(value) == 0
    try:
        counted = reference._structure(value)
        assert counted == len(raw) <= BYTES
        code = 0
    except reference.HIAProgramRejected as exc:
        assert exc.code == 'E_HIA_LIMIT'
        assert str(exc).endswith('program exceeds byte budget before encoding')
        code = 3
    assert code == (3 if len(raw) > BYTES else 0)
    byte_cases.append({'delta': delta, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'late_status': code})

assert Path(reference.__file__).read_bytes() == reference_raw
result = {'scope': 'FRESH_RECONSTRUCTED_PROOF_CONTROLS_NOT_NATIVE_QUALIFICATION',
          'status': 'PASS', 'cases': cases, 'byte_cases': byte_cases,
          'original_limits_unchanged': [M, DEPTH, BYTES],
          'reference_sha256': sha256(reference_raw).hexdigest(),
          'wall_elapsed_ns': time.monotonic_ns() - started,
          'old_pre_switch_run_status': 'UNKNOWN_NOT_COUNTED'}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'cases': len(cases), 'byte_cases': len(byte_cases),
                  'wall_elapsed_ns': result['wall_elapsed_ns']}), flush=True)
