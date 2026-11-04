"""Compare prior experimental profile diagnostics and ledgers in isolated imports.

Both sides use the same small fixtures and each original profile's default and
one-tightened-field configurations. This is finite legacy compatibility evidence,
not new-profile qualification or hostile-input coverage.
"""
import argparse
import dataclasses
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def capture(root, fixtures):
    sys.path.insert(0, str(root.resolve()))
    names = ['owned_loader', 'graph_loader', 'owned_tokens', 'ast_structure',
             'parser_appends', 'assembly_copy', 'loader_transform', 'authority_maps',
             'shallow_authority', 'package_copy']
    results = {}
    for name in names:
        mod = importlib.import_module('experiments.' + name + '.owner')
        limits_type = mod.Limits
        variants = [('defaults', {})] + [(f.name, {f.name: 1}) for f in dataclasses.fields(limits_type)]
        for case in ['main.hepta', 'bad.hepta', 'missing.hepta']:
            for label, kwargs in variants:
                row = {}; owner = None
                try:
                    owner = mod.Owner(limits_type(**kwargs))
                    h = owner.load(fixtures / case)
                    row['ok'] = True
                    row['unchanged'] = h.unchanged()
                except BaseException as e:
                    row['exception'] = [type(e).__module__, type(e).__qualname__, str(e)]
                    if hasattr(e, 'diagnostic'): row['diagnostic'] = e.diagnostic.to_dict()
                if owner is not None:
                    c = owner.context
                    row['ledger'] = dict(counts=c.counts, closed=c.closed, reads=c.reader.reads, bytes=c.reader.bytes_read)
                    if c.closed:
                        try: owner.load(fixtures / 'main.hepta')
                        except BaseException as e: row['terminal'] = [type(e).__module__, type(e).__qualname__, str(e)]
                        else: row['terminal'] = 'REOPENED'
                results[name + '/' + case + '/' + label] = row
    return results


def run(root, fixtures):
    result = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                             '--capture', str(root.resolve()), '--fixtures', str(fixtures)],
                            check=True, capture_output=True, text=True, timeout=120)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path)
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--candidate', type=Path)
    args = parser.parse_args()
    if args.capture is not None:
        if args.fixtures is None:
            parser.error('--capture requires --fixtures')
        print(json.dumps(capture(args.capture, args.fixtures), sort_keys=True))
        return
    if args.baseline is None or args.candidate is None:
        parser.error('--baseline and --candidate are required')
    with tempfile.TemporaryDirectory() as temp:
        fixtures = Path(temp)
        (fixtures / 'main.hepta').write_text('fn main()->Unit effects {} {}\n')
        (fixtures / 'bad.hepta').write_text('fn main( {')
        left = run(args.baseline, fixtures)
        right = run(args.candidate, fixtures)
        differences = [name for name in sorted(left.keys() | right.keys())
                       if left.get(name) != right.get(name)]
        print(json.dumps({'cases': len(left), 'matched': not differences,
                          'different_cases': differences}, indent=2))
        if len(left) != 813 or differences:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
