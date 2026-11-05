"""Run from repository root: python -m tests.lock_diff_graph_oracle"""
import json
import random
from pathlib import Path
from tempfile import TemporaryDirectory
from hepta.packages import digest
from hepta.lock_diff import read_lock_snapshot
from hepta.ast import HeptaError

random.seed(12)
with TemporaryDirectory() as td:
    path = Path(td) / 'lock'
    count = 0
    for n in range(1, 11):
        for trial in range(100):
            names = ['.'] + [f'p{i}' for i in range(1, n)]
            edges = {p: {f'a{j}': q for j, q in enumerate(names) if random.random() < .15} for p in names}
            nodes = {p: dict(name='pkg', version='1.0.0', kind='lib', entry='src/lib.hepta', dependencies=edges[p]) for p in names}
            files = {('/' if p != '.' else '').join([p if p != '.' else '', f]): '0' * 64 for p in names for f in ['hepta.toml', 'src/lib.hepta']}
            content = dict(packages=nodes, files=files)
            snap = dict(schema='hepta.lock.v1', **content, sha256=digest(json.dumps(content, sort_keys=True, separators=(',', ':')).encode()))
            reachable = {'.'}
            while True:
                nxt = reachable | {q for p in reachable for q in edges[p].values()}
                if nxt == reachable:
                    break
                reachable = nxt
            remaining = set(names)
            while True:
                leaves = {p for p in remaining if not (set(edges[p].values()) & remaining)}
                if not leaves:
                    break
                remaining -= leaves
            expected = not remaining and reachable == set(names)
            path.write_text(json.dumps(snap))
            try:
                read_lock_snapshot(path)
                accepted = True
            except HeptaError:
                accepted = False
            assert accepted == expected, (edges, expected, accepted)
            count += 1
    print(f'{count} randomized graph fixtures matched independent reachability/cycle oracle')
