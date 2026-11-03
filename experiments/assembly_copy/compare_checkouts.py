"""Direct frozen-baseline/new normal-loader comparison in isolated processes.

Both processes read the same frozen baseline example paths. Their hepta imports
come from separate selected trees. No parser/loader implementation is copied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def capture(root, inputs):
    import dataclasses
    sys.path.insert(0, str(root.resolve()))
    from hepta import modules
    from hepta.ast import HeptaError
    paths = sorted((inputs/'examples').rglob('*.hepta'))
    if len(paths) != 80:
        raise RuntimeError('Expected exactly 80 frozen example inputs')
    results = {}; successes = failures = 0
    for path in paths:
        row = {'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        try:
            graph = modules.load_project(path)
        except HeptaError as error:
            row['diagnostic'] = error.diagnostic.to_dict(); failures += 1
        else:
            row['report'] = graph.report()
            row['program'] = dataclasses.asdict(graph.program)
            row['source_bytes'] = {name: data.hex() for name, data in graph.source_bytes.items()}
            row['unchanged'] = graph.unchanged(); successes += 1
        results[str(path.relative_to(inputs))] = row
    if (successes, failures) != (68, 12):
        raise RuntimeError(('Unexpected graph outcomes', successes, failures))
    return json.dumps(results, sort_keys=True, separators=(',', ':'),
                      default=lambda value: sorted(value))


def run(root, inputs):
    result = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                             '--capture', str(root.resolve()),
                             '--inputs', str(inputs.resolve())],
                            check=True, capture_output=True, text=True)
    return result.stdout.strip()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path); p.add_argument('--candidate', type=Path)
    p.add_argument('--capture', type=Path); p.add_argument('--inputs', type=Path)
    args = p.parse_args()
    if args.capture is not None:
        print(capture(args.capture.resolve(), args.inputs.resolve())); return
    if args.baseline is None or args.candidate is None:
        p.error('--baseline and --candidate required')
    left = run(args.baseline, args.baseline); right = run(args.candidate, args.baseline)
    before, after = json.loads(left), json.loads(right)
    differences = [name for name in sorted(before.keys() | after.keys())
                   if before.get(name) != after.get(name)]
    print(json.dumps({'matched': left == right, 'cases': len(before),
                      'graphs': 68, 'diagnostics': 12, 'different_cases': differences,
                      'baseline_sha256': hashlib.sha256(left.encode()).hexdigest(),
                      'candidate_sha256': hashlib.sha256(right.encode()).hexdigest()}, indent=2))
    if differences: raise SystemExit(1)


if __name__ == '__main__': main()
