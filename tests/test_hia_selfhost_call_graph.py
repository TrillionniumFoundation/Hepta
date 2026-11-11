"""Actual old/new HIA call graphs, complete state and independent decisions.

Dirty readiness words are private-helper controls. Production clears the graph.
"""
import ast
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import random
import shutil
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_selfhost import Builder, source_program

CBASE, CSTATE, SIZE = 858368, 874752, 1048576
PREVIOUS = '''def check_calls(w:mutbuf) -> u64:
    n = byte(w, 64)
    step = 0
    f = 0
    target = 0
    ready = 0
    while step < n:
        f = 0
        while f < n:
            ready = 1
            target = 0
            while target < 128:
                if byte(w, 858368 + f * 128 + target) != 0:
                    if target >= n:
                        return fail(w, 55)
                    if get(w, 874752 + target * 8) == 0:
                        ready = 0
                target = target + 1
            if ready == 1:
                put(w, 874752 + f * 8, 1)
            f = f + 1
        step = step + 1
    f = 0
    while f < n:
        if get(w, 874752 + f * 8) == 0:
            return fail(w, 56)
        f = f + 1
    return 0
'''
assert sha256(PREVIOUS.encode()).hexdigest() == 'cc639d6a1093e6dba269fe05a715a7b09c36065610f4959a49e23f7bf669d530'
ENTRY = '''def probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 17424 or length(o) != 1048576 or length(w) != 1048576:
        return 4294967294
    copy_range(w, 858368, s, 16, 17408)
    copy_range(w, 64, s, 0, 8)
    copy_range(w, 40, s, 8, 8)
    put(w, 24, 17)
    check_calls(w)
    i = 0
    while i < 1048576:
        store(o, i, byte(w, i))
        i = i + 1
    return state_get32(w, 40)
'''

class ProbeBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
            args = [self.expr(value) for value in node.args]
            assert len(args) == 5
            return self.op('buffer.copy_range', [args[0], args[2], self.cast(args[1], 'usize'),
                self.cast(args[3], 'usize'), self.cast(args[4], 'usize')])
        return super().expr(node)

def programs():
    original = {n.name: n for n in ast.parse(source_program()).body}
    sources = {}
    for variant in ('previous', 'candidate'):
        nodes = [ast.parse(ENTRY).body[0]] + [original[n] for n in
            ('check_calls', 'get', 'put', 'fail', 'state_get32', 'state_put32')]
        if variant == 'previous': nodes[1] = ast.parse(PREVIOUS).body[0]
        names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
        signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
        functions = []
        for node in nodes:
            builder = ProbeBuilder(node, names, signatures)
            builder.statements(node.body)
            functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
        doc = {'schema': 'hepta.hia.program.v8', 'module': 'call_graph_fixed_point', 'functions': functions}
        raw = render_assembly(doc).encode()
        assemble_program(raw)
        sources[variant] = raw
    return sources

def case(name, n, edges=(), *, initial=None, first_error=0):
    graph = bytearray(128 * 128)
    for owner, target in edges: graph[owner * 128 + target] = 0x80 if (owner + target) & 1 else 1
    states = [0] * 128 if initial is None else list(initial)
    assert 0 <= n <= 128 and len(states) == 128
    raw = n.to_bytes(8, 'little') + first_error.to_bytes(8, 'little') + graph
    raw += b''.join(v.to_bytes(8, 'little') for v in states)
    assert len(raw) == 17424
    return {'id': name, 'n': n, 'edges': list(edges), 'initial': states, 'first_error': first_error, 'input': bytes(raw)}

def cases():
    rows = [case('zero', 0), case('one-leaf', 1), case('one-cycle', 1, [(0, 0)])]
    for n in (2, 3, 4, 8, 16, 64, 128):
        forward = [(i, i + 1) for i in range(n - 1)]
        reverse = [(i, i - 1) for i in range(1, n)]
        rows.extend([
            case(f'{n}-no-edges', n), case(f'{n}-forward-chain', n, forward),
            case(f'{n}-reverse-chain', n, reverse),
            case(f'{n}-cycle-with-leaves', n, [(0, 1), (1, 0)]),
            case(f'{n}-last-self-cycle', n, [(n - 1, n - 1)]),
            case(f'{n}-complete-forward-DAG', n, [(a, b) for a in range(n) for b in range(a + 1, n)]),
            case(f'{n}-complete-reverse-DAG', n, [(a, b) for a in range(n) for b in range(a)]),
            case(f'{n}-private-ready-cycle', n, [(0, 1), (1, 0)], initial=[1] * 128),
            case(f'{n}-private-mixed-state', n, forward, initial=[2 if i % 3 else 0 for i in range(128)]),
        ])
        if n < 128:
            rows.extend([
                case(f'{n}-first-outside-target', n, [(0, n)]),
                case(f'{n}-last-outside-target-after-ready-prefix', n, [(n - 1, 127)], initial=[1] * 128),
                case(f'{n}-retained-first-error', n, [(n - 1, 127)], first_error=23),
            ])
    rng = random.Random(0x48494143414c4c)
    for n in (4, 16, 64, 128):
        for repeat in range(3):
            edges = [(a, b) for a in range(n) for b in range(n) if rng.randrange(32) == 0]
            rows.append(case(f'{n}-seeded-graph-{repeat}', n, edges))
    assert len(rows) == 96 and len({r['id'] for r in rows}) == 96
    return rows

def graph_decision(row):
    """Independent predecessor/out-degree elimination instead of ordered rounds."""
    n = row['n']
    if any(target >= n for owner, target in row['edges'] if owner < n):
        return row['first_error'] or 55
    ready = {i for i in range(n) if row['initial'][i] != 0}
    outgoing = [set() for _ in range(n)]
    predecessors = [set() for _ in range(n)]
    for owner, target in row['edges']:
        if owner < n:
            outgoing[owner].add(target); predecessors[target].add(owner)
    pending = [len(targets - ready) for targets in outgoing]
    queue = [i for i in range(n) if i not in ready and pending[i] == 0]
    while queue:
        node = queue.pop()
        if node in ready: continue
        ready.add(node)
        for predecessor in predecessors[node]:
            pending[predecessor] -= 1
            if predecessor not in ready and pending[predecessor] == 0: queue.append(predecessor)
    return row['first_error'] or (0 if len(ready) == n else 56)

def initial_workspace(row):
    data = bytearray(b'\xa7' * SIZE)
    data[CBASE:CSTATE + 1024] = row['input'][16:]
    data[64:72] = row['input'][:8]
    data[40:48] = row['input'][8:16]
    data[24:32] = (17).to_bytes(8, 'little')
    return data

def vm_observations(selected):
    checked = {key: assemble_program(value) for key, value in programs().items()}
    records = []
    for row in selected:
        results = []
        for variant, program in checked.items():
            root = _Owner(-1, initial_workspace(row))
            machine = _Machine(program, 1_000_000, 16 << 20, None, 256)
            entry = next(fn for fn in program.as_dict()['functions'] if fn['name'] == 'f1')
            result = machine.invoke(entry, [_View(root, True)])
            actual = bytes(root.data)
            assert result == [0]
            assert int.from_bytes(actual[40:44], 'little') == graph_decision(row), (row['id'], variant)
            results.append(actual)
        assert results[0] == results[1], row['id']
        records.append({'id': row['id'], 'decision': graph_decision(row), 'workspace_sha256': sha256(results[0]).hexdigest()})
    return records

class CallGraphSourceTests(unittest.TestCase):
    def test_complete_independent_VM_state_for_acyclic_graphs_and_zero_count(self):
        wanted = {'zero', 'one-leaf', '3-forward-chain', '3-reverse-chain'}
        records = vm_observations([row for row in cases() if row['id'] in wanted])
        self.assertEqual(len(records), 4)
        self.assertTrue(all(row['decision'] == 0 for row in records))

    def test_complete_independent_VM_state_for_cycles_late_bad_edges_and_first_error(self):
        wanted = {'one-cycle', '2-cycle-with-leaves', '2-last-outside-target-after-ready-prefix', '2-retained-first-error'}
        records = vm_observations([row for row in cases() if row['id'] in wanted])
        self.assertEqual(len(records), 4)
        self.assertEqual({row['decision'] for row in records}, {23, 55, 56})

@contextmanager
def evidence_root():
    selected = os.environ.get('HEPTA_HIA_CALL_GRAPH_EVIDENCE')
    if selected:
        root = Path(selected)
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
        yield root
    else:
        with tempfile.TemporaryDirectory(prefix='hia-call-fixed-point-') as directory:
            yield Path(directory)

@unittest.skipUnless(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64')
                    and shutil.which('ld'), 'Linux x86-64 native bootstrap required')
class CallGraphNativeTests(unittest.TestCase):
    def test_actual_old_and_new_HIA_match_every_workspace_byte_at_the_full_128_function_bound(self):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke, SOURCE
        wanted = {'zero', '3-forward-chain', 'one-cycle', '2-last-outside-target-after-ready-prefix'}
        before_seed = vm_observations([row for row in cases() if row['id'] in wanted])
        sources = programs()
        with evidence_root() as root:
            (root / 'before-seed-independent-VM.json').write_text(json.dumps(before_seed, indent=2, sort_keys=True) + '\n')
            seed, _ = build_seed(root)
            compiler, _ = compile_stage(root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
            images = {key: compile_stage(root, key, compiler, value)[0] for key, value in sources.items()}
            ledger = []
            for number, row in enumerate(cases()):
                results = []
                observations = []
                for variant, image in images.items():
                    receipt, output = invoke(root, str(number) + '-' + variant, image, row['input'],
                        capacity=SIZE, workspace_size=SIZE, workspace_fill=0xa7)
                    self.assertEqual(receipt['status'], 'returned', (row['id'], variant, receipt))
                    self.assertEqual(receipt['abi_status'], 0)
                    self.assertEqual(receipt['core_u32'], graph_decision(row), (row['id'], variant))
                    self.assertEqual(len(output), SIZE)
                    self.assertTrue(receipt['source_unchanged'])
                    self.assertEqual(receipt['limits']['cpu_seconds'], 10)
                    self.assertEqual(receipt['limits']['address_bytes'], 256 << 20)
                    before = initial_workspace(row)
                    for begin, end in ((0, 40), (48, 104), (112, CSTATE), (CSTATE + 1024, SIZE)):
                        self.assertEqual(output[begin:end], before[begin:end], (row['id'], variant, begin, end))
                    results.append(output)
                    observations.append({'variant': variant, 'result': receipt['core_u32'],
                        'workspace_sha256': sha256(output).hexdigest(), 'native_elapsed_ns': receipt['native_elapsed_ns'],
                        'wall_elapsed_ns': receipt['wall_elapsed_ns']})
                self.assertEqual(results[0], results[1], row['id'])
                ledger.append({'id': row['id'], 'functions': row['n'], 'observations': observations})
                (root / 'actual-ledger.json').write_text(json.dumps(ledger, indent=2, sort_keys=True) + '\n')
            self.case_counts = {'cases': len(ledger), 'actual_native_entries': 2 * len(ledger),
                'full_workspace_bytes_per_entry': SIZE, 'maximum_functions': 128,
                'fresh_seed_after_independent_VM': True, 'original_limits_changed': False}
            (root / 'case-counts.json').write_text(json.dumps(self.case_counts, indent=2, sort_keys=True) + '\n')

if __name__ == '__main__': unittest.main()
