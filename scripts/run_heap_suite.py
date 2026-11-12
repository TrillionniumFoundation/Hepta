"""Run fixed original heap gates; this is a development-only CI harness."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest

COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
SELECTED = (
    'tests.test_hia_heap_bound_native.HeapBoundSourceTests',
    'tests.test_hia_heap_bound_native.HeapBoundAdapterTests',
    'tests.test_hia_heap_live_engine_native.HeapLiveEngineSourceTests',
    'tests.test_hia_heap_live_engine_native.HeapLiveEngineNativeTests',
    'tests.test_hia_heap_graphs_native.HeapGraphNativeTests.test_existing_key_overwrite_and_copy_match_complete_vm_buffers',
    'tests.test_hia_heap_bound_native.HeapBoundNativeTests',
)


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def ids(suite):
    result = []
    for item in suite:
        result.extend(ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result


def source_map(root):
    found = {}
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if '.git' in rel.parts or '__pycache__' in rel.parts:
            continue
        if path.is_file():
            if path.is_symlink():
                raise ValueError('unexpected source symlink: ' + rel.as_posix())
            raw = path.read_bytes()
            found[rel.as_posix()] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                     'mode': format(path.stat().st_mode & 0o777, '04o')}
    return found


class ObservedResult(unittest.TextTestResult):
    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    args = parser.parse_args()
    root, folder, compiler = args.source.resolve(), args.evidence.resolve(), args.compiler.resolve()
    folder.mkdir(parents=True, exist_ok=False)
    before = source_map(root)
    compiler_bytes = compiler.read_bytes()
    assert len(compiler_bytes) == 669494 and hashlib.sha256(compiler_bytes).hexdigest() == COMPILER_SHA
    write(folder / 'SOURCE-BEFORE.json', before)
    removed = {key: os.environ.pop(key) for key in tuple(os.environ) if key.startswith('HEPTA_')}
    os.environ.update({
        'PYTHONDONTWRITEBYTECODE': '1',
        'HEPTA_HIA_HEAP_BOUND_DEVELOPMENT_COMPILER': str(compiler),
        'HEPTA_HIA_HEAP_BOUND_EVIDENCE': str(folder / 'public-evidence'),
        'HEPTA_HIA_HEAP_LIVE_ENGINE_DEVELOPMENT_COMPILER': str(compiler),
        'HEPTA_HIA_HEAP_LIVE_ENGINE_EVIDENCE': str(folder / 'live-evidence'),
        'HEPTA_HIA_HEAP_GRAPHS_DEVELOPMENT_COMPILER': str(compiler),
        'HEPTA_HIA_HEAP_GRAPHS_EVIDENCE': str(folder / 'graph-evidence'),
    })
    sys.path.insert(0, str(root))
    os.chdir(root)
    report = {'schema': 'hia.heap-optimization.development-suite.v1',
              'scope': 'RETAINED_COMPILER_DEVELOPMENT_COMPONENTS_AND_ORIGINAL_PUBLIC_GATES',
              'qualification': False, 'current_source_cold': False,
              'selected': list(SELECTED), 'expected_outer_count': 38,
              'python': sys.version, 'compiler_sha256': COMPILER_SHA,
              'removed_selector_names': sorted(removed), 'original_public_child_timeout': 150,
              'original_compile_child_timeout': 20, 'original_context_depth_transfer_limits': [1024, 64, 32768]}
    start = time.perf_counter()
    try:
        assert sys.version_info[:3] == (3, 14, 4), sys.version
        report['packages'] = {name: importlib.metadata.version(name) for name in
                              ('setuptools', 'wheel', 'jsonschema', 'z3-solver')}
        assert report['packages'] == {'setuptools': '78.1.1', 'wheel': '0.46.3',
                                      'jsonschema': '4.26.0', 'z3-solver': '4.15.4.0'}
        import z3
        assert z3.get_version_string() == '4.15.4'
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in SELECTED)
        report['loaded_test_ids'] = ids(suite)
        assert len(report['loaded_test_ids']) == 38
        assert len(set(report['loaded_test_ids'])) == 38
        class Result(ObservedResult):
            def __init__(self, *values, **kwargs):
                super().__init__(*values, **kwargs)
                self.executed = []
        with (folder / 'unittest.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_test_ids=result.executed,
                      failures=[{'id': case.id(), 'traceback': trace} for case, trace in result.failures],
                      errors=[{'id': case.id(), 'traceback': trace} for case, trace in result.errors],
                      skipped=[{'id': case.id(), 'reason': reason} for case, reason in result.skipped],
                      expected_failures=[{'id': case.id(), 'traceback': trace} for case, trace in result.expectedFailures],
                      unexpected_successes=[case.id() for case in result.unexpectedSuccesses])
        report['status'] = 'PASS' if (result.wasSuccessful() and result.testsRun == 38
            and report['loaded_test_ids'] == result.executed and not result.skipped
            and not result.expectedFailures and not result.unexpectedSuccesses) else 'FAIL'
        nested = {}
        for mode in ('reference', 'native'):
            path = folder / 'public-evidence' / 'HeapBoundNativeTests' / 'original-public' / (mode + '-RESULT.json')
            if path.exists():
                raw = path.read_bytes()
                value = json.loads(raw)
                nested[mode] = {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'status': value['status'], 'tests_run': value['tests_run'],
                    'wall_seconds': value['finished'] - value['started'],
                    'native_step_count': value['native_step_count'], 'old_policy_calls': value['old_policy_calls'],
                    **{key: value[key] for key in ('failures', 'errors', 'skips', 'expected_failures', 'unexpected_successes')}}
            else:
                nested[mode] = {'missing': True}
        report['original_public_runs'] = nested
        if report['status'] == 'PASS':
            for value in nested.values():
                assert value['status'] == 'PASS' and value['tests_run'] == 134
                assert not any(value[key] for key in ('failures', 'errors', 'skips', 'expected_failures',
                                                     'unexpected_successes', 'old_policy_calls'))
            assert nested['native']['native_step_count'] > 0
    except BaseException:
        report['status'] = 'ERROR'
        report['traceback'] = traceback.format_exc()
    finally:
        after = source_map(root)
        report['source_unchanged'] = before == after
        report['compiler_unchanged'] = compiler.read_bytes() == compiler_bytes
        report['wall_seconds'] = time.perf_counter() - start
        if not (report['source_unchanged'] and report['compiler_unchanged']):
            report['status'] = 'FAIL'
        write(folder / 'SOURCE-AFTER.json', after)
        write(folder / 'RESULT.json', report)
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
