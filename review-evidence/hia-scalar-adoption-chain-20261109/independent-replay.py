"""Independent retained-query replay only; no native loading or new ISA proof."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import z3

source, output = map(Path, sys.argv[1:])
stream = output.open('x')
result = {'status': 'started', 'files': 0, 'queries': [], 'fresh_native_execution': False,
          'replayer_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
          'source_report_sha256': sha256((source / 'report.json').read_bytes()).hexdigest(),
          'solver_version': z3.get_version_string()}
started = time.monotonic_ns()
try:
    assert z3.get_version_string() == '4.15.4'
    manifest = json.loads((source / 'original-files.json').read_bytes())
    assert len(manifest) == len({row['path'] for row in manifest})
    for row in manifest:
        path = (source / row['path']).resolve(strict=True)
        assert path.is_relative_to(source.resolve())
        data = path.read_bytes()
        assert len(data) == row['bytes'] and sha256(data).hexdigest() == row['sha256']
        result['files'] += 1
    report = json.loads((source / 'report.json').read_bytes())
    assert report['status'] == 'passed' and report['source']['worktree_status'] == ''
    assert report['types'] == ['u8', 'u32', 'u64', 'usize']
    for family in report['families']:
        root = source / family['type']
        spec = json.loads((root / 'specification/specification.json').read_bytes())
        assert spec == family['specification']
        assert spec['core_sha256'] == family['candidate']['sha256']
        queries = [(root / 'specification' / q['query_file'], q) for q in spec['obligations']]
        for mode in ('canonical', 'planned'):
            proof = json.loads((root / (mode + '-machine-evidence.json')).read_bytes())
            assert proof['artifact_binding']['candidate_core_sha256'] == family['candidate']['sha256']
            assert proof['validation']['complete'] and proof['validation']['ok']
            queries.extend((root / (mode + '-' + q['query_file']), q) for q in proof['validation']['obligations'])
        assert len(queries) == 13
        for path, q in queries:
            data = path.read_bytes()
            assert sha256(data).hexdigest() == q['query_sha256']
            solver = z3.Solver(ctx=z3.Context())
            solver.set(timeout=15000)
            solver.from_string(data.decode())
            actual = str(solver.check())
            result['queries'].append({'path': str(path.relative_to(source)), 'expected': q['expected'],
                                      'result': actual, 'query_sha256': q['query_sha256']})
            assert actual == q['expected']
    assert len(result['queries']) == 52
    result['status'] = 'passed'
except BaseException as exc:
    result.update(status='failed', error_type=type(exc).__name__, error=str(exc))
    raise
finally:
    result['elapsed_ns'] = str(time.monotonic_ns() - started)
    json.dump(result, stream, indent=2, sort_keys=True)
    stream.write('\n')
    stream.close()
    print(json.dumps({'status': result['status'], 'files': result['files'], 'queries': len(result['queries'])}))
