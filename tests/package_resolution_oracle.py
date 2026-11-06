"""Independent manifest-only graph review. Never compiles or executes Hepta."""
import itertools
import json
from pathlib import Path
import random
import tempfile
from hepta.ast import HeptaError
from hepta.packages import load_package

rng = random.Random(2026110501)
identities = ('p', 'q', 'r')
versions = (1, 2)

def declaration():
    name = rng.choice(identities)
    if rng.random() < .25:
        return ('fixed', name, rng.choice(versions))
    sources = tuple(rng.sample(versions, rng.randint(1, 2)))
    accepted = rng.choice(((1, 2), (1,), (2,)))
    return ('candidate', name, sources, accepted)

def graph_valid(graph, assignment):
    visited, active = set(), set()
    def visit(node):
        if node in active:
            return False
        if node in visited:
            return True
        active.add(node)
        for edge in graph[node]:
            kind, name = edge[:2]
            if kind == 'fixed':
                target = (name, edge[2])
            else:
                selected = assignment[name]
                if selected not in edge[2] or selected not in edge[3]:
                    return False
                target = (name, selected)
            if not visit(target):
                return False
        active.remove(node)
        visited.add(node)
        return True
    return visit(('app', 1))

satisfiable = 0
unsatisfiable = 0
for case in range(500):
    graph = {(name, version): [declaration() for _ in range(rng.randint(0, 2))]
             for name in identities for version in versions}
    graph[('app', 1)] = [declaration() for _ in range(rng.randint(1, 3))]
    solutions = [dict(zip(identities, assignment)) for assignment in itertools.product(versions, repeat=3)
                 if graph_valid(graph, dict(zip(identities, assignment)))]
    with tempfile.TemporaryDirectory(prefix='hepta-independent-review-') as temp:
        root = Path(temp)
        for (name, version), edges in graph.items():
            directory = root / f'{name}{version}'
            (directory / 'src').mkdir(parents=True)
            (directory / 'src/lib.hepta').write_text('')
            manifest = [f'[package]\nname = "{name}"\nversion = "{version}.0.0"\nkind = "lib"\n[dependencies]']
            for index, edge in enumerate(edges):
                if edge[0] == 'fixed':
                    spec = {'path': f'../{edge[1]}{edge[2]}'}
                else:
                    requirement = '>=1.0.0' if len(edge[3]) == 2 else f'={edge[3][0]}.0.0'
                    spec = {'package': edge[1], 'version': requirement,
                            'candidates': [f'../{edge[1]}{v}' for v in edge[2]]}
                manifest.append(f'e{index} = {{ '+', '.join(k+' = '+json.dumps(v) for k,v in spec.items())+' }')
            (directory/'hepta.toml').write_text('\n'.join(manifest))
        try:
            result = load_package(root / 'app1')
        except HeptaError as error:
            assert not solutions, (case, graph, solutions, error)
            assert error.diagnostic.code in ('E_PACKAGE_RESOLUTION', 'E_PACKAGE_CYCLE'), error
            unsatisfiable += 1
        else:
            assert solutions, (case, graph)
            selected = {}
            visited = set()
            def check(package):
                node = (package.name, int(package.version.split('.')[0]))
                if node in visited:
                    return
                visited.add(node)
                for index, edge in enumerate(graph[node]):
                    actual = package.dependencies[f'e{index}']
                    actual_version = int(actual.version.split('.')[0])
                    if edge[0] == 'fixed':
                        assert actual_version == edge[2]
                    else:
                        assert actual_version in edge[2] and actual_version in edge[3]
                        assert selected.setdefault(edge[1], actual_version) == actual_version
                    check(actual)
            check(result)
            satisfiable += 1
print(f'500 independent three-identity/two-version graphs passed: {satisfiable} satisfiable, {unsatisfiable} unsatisfiable; includes mixed fixed paths and candidate cycles.')
