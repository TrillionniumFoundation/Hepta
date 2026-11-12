"""Run nine frozen, native-forbidden progress controls in a private namespace."""
from pathlib import Path
import argparse
import ast
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ['tests.test_hia_core_unpack_progress.UnpackQualificationProgressTests.' + name for name in (
    'test_bounds_and_write_failures_leave_hold_originals',
    'test_complete_readback_rejects_missing_truncated_duplicated_events',
    'test_diagnostic_failure_preserves_original_exception',
    'test_fixture_failures_and_baseexceptions_are_distinct',
    'test_nested_suite_fixture_order_and_original_callbacks',
    'test_new_gate_rereads_progress_and_cannot_accept_summary_alone',
    'test_receipt_cannot_substitute_original_report_or_current_bytes',
    'test_uncovered_or_reordered_inner_suite_is_rejected',
    'test_unpack_wrapper_keeps_default_main_and_old_gate_paths')]


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest()}


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def flatten(suite):
    for value in suite:
        if isinstance(value, unittest.TestSuite):
            yield from flatten(value)
        else:
            yield value


def mechanical(validation):
    checks = {}
    source = ast.parse((ROOT / 'controls/prepare_sources.py').read_bytes())
    for node in source.body:
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name) and node.value.func.id == 'change'):
            continue
        name = ast.literal_eval(node.value.args[0])
        replacements = ast.literal_eval(node.value.args[2])
        text = (ROOT / 'inputs' / name).read_text()
        for before, after in reversed(replacements):
            assert text.count(after) == 1, name
            text = text.replace(after, before)
        checks['reverse:' + name] = text.encode() == (ROOT / 'references' / name).read_bytes()
    for name in ('tools/qualify_hia_core_lowering_callers.py', 'tools/hia_compiler_owner_gates.py'):
        checks['unchanged:' + name] = (validation / name).read_bytes() == (ROOT / 'references' / name).read_bytes()
    suites = [(ROOT / ('references/cpython-' + version + '/Lib/unittest/suite.py')).read_bytes()
              for version in ('v3.12.14', 'v3.14.4')]
    checks['official_runtime_suite_sources_equal'] = suites[0] == suites[1]
    checks['official_suite_sha256'] = all(sha256(raw).hexdigest() ==
        'ed2da92bc9f97c53403ee2d3d12cc53b16a96e85d596ebc887b5a93458f3f6bc' for raw in suites)
    core = ast.parse((ROOT / 'references/tools/qualify_hia_core_lowering_callers.py').read_bytes())
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in core.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS')}
    counts, events = [], 2
    for name in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS'):
        ids = values[name]
        classes, modules = [value.rsplit('.', 1)[0] for value in ids], [value.rsplit('.', 2)[0] for value in ids]
        class_runs = sum(index == 0 or value != classes[index - 1] for index, value in enumerate(classes))
        module_runs = sum(index == 0 or value != modules[index - 1] for index, value in enumerate(modules))
        counts.append(len(ids))
        events += 2 + 2 * len(ids) + 4 * (class_runs + module_runs)
    checks['static_original116_event_model_360_below_1024'] = counts == [15, 51, 50] and events == 360 < 1024
    assert checks and all(checks.values()), checks
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    out = args.evidence.absolute()
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    started = time.monotonic()
    paths = [path for parent in ('inputs', 'references', 'controls')
             for path in sorted((ROOT / parent).rglob('*')) if path.is_file()]
    before = [pin(path) for path in paths]
    write(out / 'source-before.json', before)
    report = {'schema': 'hepta.hia.core-unpack-progress-source-controls.v1', 'status': 'HOLD',
        'scope': 'REAL_SYNTHETIC_UNITTEST_AND_FILE_CONTROLS_NO_NATIVE',
        'runtime': sys.version, 'runtime_executable': pin(Path(sys.executable).resolve()),
        'expected_ids': EXPECTED, 'loaded_ids': [], 'executed_ids': [],
        'original18_executed': False, 'original116_executed': False,
        'native_or_compiler_or_cold_executed': False, 'forbidden_attempts': []}
    try:
        manifest = json.loads((ROOT / 'PREEXEC.json').read_bytes())
        expected_pins = {row['path']: (row['size'], row['sha256']) for row in manifest['frozen_files']}
        assert all(expected_pins[str(path.relative_to(ROOT))] == (row['size'], row['sha256'])
                   for path, row in zip(paths, before)), 'preexec source bytes differ'
        validation = out / 'validation-root'
        validation.mkdir()
        for path in sorted((ROOT / 'inputs').rglob('*')):
            if path.is_file():
                target = validation / path.relative_to(ROOT / 'inputs')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
        for name in ('tools/qualify_hia_core_lowering_callers.py', 'tools/hia_compiler_owner_gates.py',
                     'tools/hia_store_page_gates.py', 'tests/__init__.py'):
            target = validation / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / 'references' / name).read_bytes())
        report['mechanical_checks'] = mechanical(validation)
        for path in (ROOT / 'inputs').rglob('*.py'):
            ast.parse(path.read_bytes(), filename=str(path))
        sys.path.insert(0, str(validation))
        import tests.test_hia_core_unpack_progress as module
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_ids'] = loaded
        assert loaded == EXPECTED and not loader.errors, 'nine exact source control IDs differ'
        executed = []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        def forbidden(*arguments, **keywords):
            report['forbidden_attempts'].append('native-constructor-or-subprocess')
            raise AssertionError('native, compiler and product subprocess execution forbidden')
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {'HEPTA_PROGRESS_CONTROL_EVIDENCE': str(out / 'fixtures')}))
            for name in ('CDLL', 'PyDLL', 'CFUNCTYPE', 'PYFUNCTYPE'):
                stack.enter_context(patch.object(ctypes, name, forbidden))
            stack.enter_context(patch.object(subprocess, 'Popen', forbidden))
            with (out / 'unittest.log').open('x') as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report.update(executed_ids=executed, tests_run=result.testsRun, loader_errors=list(loader.errors),
                      successful=result.wasSuccessful())
        for name in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            report[name] = [(item[0].id(), item[1]) if isinstance(item, tuple) else item.id()
                            for item in getattr(result, name)]
        report['product_modules_imported'] = sorted(name for name in sys.modules if name == 'hepta' or name.startswith('hepta.'))
        assert not report['product_modules_imported'], 'synthetic control imported a product module'
        if (result.wasSuccessful() and loaded == executed == EXPECTED and result.testsRun == 9
                and not any(report[name] for name in ('loader_errors', 'errors', 'failures', 'skipped',
                    'expectedFailures', 'unexpectedSuccesses', 'forbidden_attempts'))):
            report['status'] = 'SOURCE_CONTROL_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        after = [pin(path) for path in paths]
        write(out / 'source-after.json', after)
        report['source_preserved'] = before == after
        if before != after:
            report['status'] = 'HOLD'
        report['seconds'] = time.monotonic() - started
        actual = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()
                  and not path.is_relative_to(out / 'validation-root')]
        write(out / 'actual-originals.json', actual)
        report['actual_original_count_before_report'] = len(actual)
        write(out / 'report.json', report)
        print(json.dumps({key: report.get(key) for key in ('status', 'tests_run', 'seconds', 'source_preserved', 'error')}))
    return 0 if report['status'] == 'SOURCE_CONTROL_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
