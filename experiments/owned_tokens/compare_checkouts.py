"""Compare normal Lexer/Parser behavior from two independently materialized trees.

Run directly, not as a module: python experiments/owned_tokens/compare_checkouts.py
--baseline /path/to/baseline --candidate /path/to/candidate

Each child imports hepta only from its selected tree. No historical lexer/parser
implementation is bundled. Verify the checkout identities independently. This
finite corpus compares tokens, complete AST data and diagnostics, not all inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


SYNTHETIC = [
    '', '// trailing', '/* nested /* ok */ end */', '/* never closed', "'a",
    '0 1 0xff 0b101 0o77 1_024 1.0 0.0 1.5e-2', '0x_', '1__2', '1e9999',
    '1.foo 0..2', '"C"', '"bad\\escape"', '@',
    '// hi\r\nfn main()->Unit effects {} {}',
    'fn main()->Unit effects {} {let n:i64=1;}',
    'fn f(x:Box<Box<i64>>)->Unit effects {} {}', 'fn main(',
    'fn main()->Unit effects {} {let n=;}',
    'fn main()->Unit effects {} {let n:i64=' + '+'.join(['1'] * 150) + ';}',
]


def _capture(root):
    import dataclasses
    sys.path.insert(0, str(root))
    from hepta import lexer, parser
    from hepta.ast import HeptaError
    paths = sorted((root / 'examples').rglob('*.hepta'))
    if len(paths) != 80:
        raise RuntimeError(f'Expected 80 example inputs, found {len(paths)}')
    cases = {str(path.relative_to(root)): path.read_bytes().decode('utf-8') for path in paths}
    cases.update({f'synthetic/{i}': text for i, text in enumerate(SYNTHETIC)})
    outcomes = {}
    for path, source in cases.items():
        row = {'source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest()}
        for name, function in [('tokens', lexer.tokenize), ('ast', parser.parse)]:
            try:
                value = function(source, path)
                row[name] = {'ok': [dataclasses.asdict(t) for t in value]
                             if name == 'tokens' else dataclasses.asdict(value)}
            except HeptaError as error:
                row[name] = {'diagnostic': error.diagnostic.to_dict()}
            except Exception as error:
                row[name] = {'exception': type(error).__name__, 'message': str(error)}
        outcomes[path] = row
    return json.dumps(outcomes, sort_keys=True, separators=(',', ':'),
                      default=lambda value: sorted(value))


def _run_capture(root):
    result = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                             '--capture', str(root.resolve())],
                            check=True, capture_output=True, text=True)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--capture', type=Path, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.capture is not None:
        print(_capture(options.capture.resolve()))
        return
    if options.baseline is None or options.candidate is None:
        parser.error('--baseline and --candidate are required')
    baseline = _run_capture(options.baseline)
    candidate = _run_capture(options.candidate)
    left, right = json.loads(baseline), json.loads(candidate)
    differences = [name for name in sorted(left.keys() | right.keys())
                   if left.get(name) != right.get(name)]
    summary = {'matched': baseline == candidate, 'cases': len(left),
               'example_cases': 80, 'synthetic_cases': len(SYNTHETIC),
               'successful_lexes': sum('ok' in row['tokens'] for row in left.values()),
               'successful_parses': sum('ok' in row['ast'] for row in left.values()),
               'baseline_sha256': hashlib.sha256((baseline + '\n').encode()).hexdigest(),
               'candidate_sha256': hashlib.sha256((candidate + '\n').encode()).hexdigest(),
               'different_cases': differences}
    print(json.dumps(summary, sort_keys=True, indent=2))
    if not summary['matched']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
