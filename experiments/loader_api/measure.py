"""Reproduce loader-only evidence for fixed repository examples. No compiler run."""
import hashlib
import json
from pathlib import Path
from experiments.request_load.context import Context, Limits

CASES = ('examples/ssa_scalar.hepta', 'examples/results.hepta',
         'examples/borrowed_storage/main.hepta', 'examples/owned/main.hepta',
         'examples/groups/shared_budget.hepta', 'examples/packages/app')


def measure(root):
    result = {'schema': 'hepta.loader-api-workloads.v1',
              'baseline': '43ea9c8f316d38cf3aa14b883d540a7ad0c5f3c6',
              'scope': 'repository examples; load, explicit unchanged, reload; no native build',
              'limits': vars(Limits()), 'workloads': []}
    for name in CASES:
        context = Context()
        row = {'entry': name, 'stages': []}
        def record(stage):
            row['stages'].append({'stage': stage, 'bytes_read': context.reader.bytes_read,
                                  'reads': context.reader.reads, **context.counts})
        try:
            first = context.load(root / name)
            record('initial_load_including_implicit_revalidation')
            row['source_hashes'] = {str(Path(p).relative_to(root)): hashlib.sha256(b).hexdigest()
                                    for p, b in first.source_bytes.items()}
            row['unchanged'] = first.unchanged()
            record('explicit_unchanged')
            second = context.load(root / name)
            record('reload_including_implicit_revalidation')
            row['same_identity'] = first.identity == second.identity
            row['outcome'] = 'passed' if row['same_identity'] and row['unchanged'] else 'mismatch'
        except Exception as error:
            row['outcome'] = 'rejected'
            row['error_type'] = type(error).__name__
            row['error'] = str(error).replace(str(root), '<repo>')
            record('rejected')
        result['workloads'].append(row)
    return result


if __name__ == '__main__':
    print(json.dumps(measure(Path(__file__).resolve().parents[2]), indent=2, sort_keys=True))
