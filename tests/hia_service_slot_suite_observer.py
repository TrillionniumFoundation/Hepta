"""Observe complete new Source3 or Native8 without filtering any method."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import unittest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from tests.hia_service_slot_controls import put, encoded

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kind', choices=('source', 'native'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    path = ROOT / 'tests/test_hia_service_slot_native.py'; raw = path.read_bytes()
    tree = ast.parse(raw); cls = 'ServiceSlotSourceTests' if args.kind == 'source' else 'ServiceSlotNativeTests'
    names = [n.name for c in tree.body if isinstance(c, ast.ClassDef) and c.name == cls
             for n in c.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
    planned = ['tests.test_hia_service_slot_native.' + cls + '.' + name for name in sorted(names)]
    if len(planned) != (3 if args.kind == 'source' else 8):
        raise ValueError('full declared new method inventory differs')
    from tools.build_hia_json_preflight import current_sources
    before = current_sources()
    suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_hia_service_slot_native.' + cls)
    def flatten(value):
        for node in value:
            if isinstance(node, unittest.TestSuite): yield from flatten(node)
            else: yield node.id()
    if list(flatten(suite)) != planned: raise ValueError('real loader identities differ')
    started, stopped, events = [], [], []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id()); events.append({'event': 'start', 'id': test.id(), 'time_ns': time.time_ns()})
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id()); events.append({'event': 'stop', 'id': test.id(), 'time_ns': time.time_ns()})
            super().stopTest(test)
    begin = time.monotonic()
    with (args.output / 'tests.log').open('x') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    after = current_sources()
    anomalies = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in anomalies)
    passed = clean and result.testsRun == len(planned) and planned == started == stopped and before == after and path.read_bytes() == raw
    report = {'schema': 'hepta.hia.service-slot-observed-suite.v1',
        'status': 'PASS' if passed else 'HOLD', 'kind': args.kind, 'class': cls,
        'planned': planned, 'started': started, 'stopped': stopped, 'events': events,
        'actual_tests': result.testsRun, 'runtime': sys.version, 'argv': sys.argv,
        'wall_seconds': time.monotonic() - begin, 'source_before': before, 'source_after': after,
        'test_source_sha256': sha256(raw).hexdigest(), 'original_scope_reduced': False,
        'errors': [(t.id(), e) for t, e in result.errors],
        'failures': [(t.id(), e) for t, e in result.failures],
        'skipped': [(t.id(), e) for t, e in result.skipped],
        'expected_failures': [(t.id(), e) for t, e in result.expectedFailures],
        'unexpected_successes': [t.id() for t in result.unexpectedSuccesses]}
    put(args.output / 'report.json', report)
    print(encoded({'status': report['status'], 'tests': result.testsRun}).decode(), end='')
    return 0 if passed else 1
if __name__ == '__main__': raise SystemExit(main())
