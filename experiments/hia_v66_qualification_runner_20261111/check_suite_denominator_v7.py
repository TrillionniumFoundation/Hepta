"""Exercise the actual embedded v7 unittest observer with small real suites.

These are qualification-controller controls. They do not qualify HIA product
code, any fixture, a native application, or a complete retained regression.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys


CASES = {
    'normal': (
        "class Example(unittest.TestCase):\n"
        " def test_a(self): pass\n"
        " def test_b(self): pass\n",
        0, 2, 2, 0, 0, 0),
    'class_skip': (
        "class Example(unittest.TestCase):\n"
        " @classmethod\n"
        " def setUpClass(cls): raise unittest.SkipTest('actual class-level refusal')\n"
        " def test_a(self): pass\n"
        " def test_b(self): pass\n"
        " def test_c(self): pass\n",
        1, 3, 0, 1, 0, 0),
    'expected_failure': (
        "class Example(unittest.TestCase):\n"
        " @unittest.expectedFailure\n"
        " def test_a(self): self.fail('actual expected failure')\n",
        1, 1, 1, 0, 1, 0),
    'unexpected_success': (
        "class Example(unittest.TestCase):\n"
        " @unittest.expectedFailure\n"
        " def test_a(self): pass\n",
        1, 1, 1, 0, 0, 1),
    'early_stop': (
        "class Example(unittest.TestCase):\n"
        " def test_a(self): self._outcome.result.stop()\n"
        " def test_b(self): pass\n",
        1, 2, 1, 0, 0, 0),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    runner = Path(__file__).with_name('run_hia_qualification_v7.py')
    raw = runner.read_bytes()
    tree = ast.parse(raw)
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'suite')
    assignment = next(node for node in function.body
                      if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'source'
                              for target in node.targets))
    actual_source = ast.literal_eval(assignment.value)
    rows = []
    for name, (fixture, returncode, loaded, executed, skipped, expected, unexpected) in CASES.items():
        directory = args.output / name
        directory.mkdir()
        (directory / 'fixture.py').write_text('import unittest\n' + fixture)
        result_path = directory / 'result.json'
        code = ('DISCOVER=False\nNAMES=["fixture"]\nRESULT=' + repr(str(result_path.resolve()))
                + '\n' + actual_source)
        stdout = directory / 'stdout.log'
        stderr = directory / 'stderr.log'
        with stdout.open('xb') as output, stderr.open('xb') as errors:
            process = subprocess.run([sys.executable, '-B', '-c', code],
                                     cwd=directory, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                     stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                     timeout=10, check=False)
        result = json.loads(result_path.read_bytes())
        assert process.returncode == returncode, (name, process.returncode)
        assert result['expected_test_count'] == loaded
        assert len(result['loaded_test_ids']) == loaded
        assert len(result['executed_test_ids']) == result['tests_run'] == executed
        assert len(result['skipped']) == skipped
        assert len(result['expected_failures']) == expected
        assert len(result['unexpected_successes']) == unexpected
        if name == 'normal':
            assert result['loaded_test_ids'] == result['executed_test_ids']
        if name == 'early_stop':
            assert result['successful'] is True
            assert result['loaded_test_ids'] != result['executed_test_ids']
        rows.append({'case': name, 'returncode': process.returncode,
                     'loaded': loaded, 'executed': executed,
                     'skipped': skipped, 'expected_failures': expected,
                     'unexpected_successes': unexpected,
                     'raw_files': {path.name: sha256(path.read_bytes()).hexdigest()
                                   for path in sorted(directory.iterdir()) if path.is_file()}})
    assert runner.read_bytes() == raw
    receipt = {'schema': 'hia.v7-real-unittest-denominator-controls.v1',
               'status': 'CONTROLLER_CONTROLS_PASS',
               'runner_sha256': sha256(raw).hexdigest(),
               'embedded_observer_sha256': sha256(actual_source.encode()).hexdigest(),
               'cases': rows, 'product_qualification_claimed': False}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': receipt['status'], 'cases': len(rows),
                      'receipt': str(args.output / 'receipt.json')}, sort_keys=True))


if __name__ == '__main__':
    main()
