"""Execute all eight added regression methods under the retained 1800s guard."""
from pathlib import Path
from hashlib import sha256
import importlib.util
import json
import os
import sys
import time
import traceback
import unittest

ROOT = Path(os.environ['HIA_V80_DEVELOPMENT_ROOT']).resolve(strict=True)
SOURCE = ROOT / 'source'
OUT = ROOT / 'new-controls-r1'
IMAGES = ROOT / 'development-images-r2'
SELECTORS = (
    'tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_global_nameerror_preserves_name_and_active_context',
    'tests.test_hia_native_byte_abi_native.NativeByteABISourceTests.test_global_nameerror_preserves_name_and_active_context',
    'tests.test_hia_service_verification_native.ServiceVerificationSourceTests.test_global_nameerror_preserves_name_and_active_context',
    'tests.test_hia_core_lowering_native.CoreLoweringNativeTests.test_global_helpers_observe_replacement_and_deletion_before_and_after_admission',
    'tests.test_hia_native_byte_abi_native.NativeByteABINativeTests.test_imported_helpers_observe_replacement_and_deletion_before_and_after_admission',
    'tests.test_hia_native_byte_abi_native.NativeByteABINativeTests.test_import_groups_keep_fromlist_namespace_order_and_module_retirement',
    'tests.test_hia_native_byte_abi_native.NativeByteABINativeTests.test_held_importerror_releases_original_module_before_error_traceback',
    'tests.test_hia_native_build_native.NativeBuildNativeTests.test_held_importerror_releases_original_module_before_error_traceback',
)


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def child():
    sys.path.insert(0, str(SOURCE))
    helper = load_file('source_manifest', Path(__file__).with_name('source_manifest.py'))
    before = helper.manifest(SOURCE)
    write(OUT / 'SOURCE-BEFORE.json', before)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(SELECTORS)
    loaded = [test.id() for test in flatten(suite)]
    if loader.errors or loaded != list(SELECTORS) or len(loaded) != 8:
        write(OUT / 'LOADER-FAILURE.json', {'errors': loader.errors, 'loaded': loaded})
        raise ValueError('exact added test inventory differs')
    from hepta.hia_machine_plan_control_native import PlanFrame
    original = PlanFrame._invoke
    active = ['outside-test']
    returns = {}
    def invoke(self, *args, **kwargs):
        value = original(self, *args, **kwargs)
        if '_mapping' not in vars(self.image):
            raise AssertionError('an added native control used an unreviewed non-native image')
        key = self.image.image_sha256 + ':' + active[0]
        returns[key] = returns.get(key, 0) + 1
        return value
    executed = []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            active[0] = test.id()
            executed.append(test.id())
            super().startTest(test)
    report = {'schema': 'hia.global-import.added-permanent-controls.v80.r2',
              'python': sys.version, 'loaded_ids': loaded, 'whole_native': False,
              'current_source_cold': False, 'scope': 'EXPLICIT_RETAINED_COMPILER_DEVELOPMENT'}
    start = time.monotonic()
    PlanFrame._invoke = invoke
    try:
        with (OUT / 'unittest.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_ids=executed)
        for name in ('failures', 'errors', 'skipped', 'expectedFailures'):
            report[name] = [[test.id(), detail] for test, detail in getattr(result, name)]
        report['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
        report['status'] = 'PASS' if (result.testsRun == 8 and executed == loaded and
            not any(report[name] for name in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))) else 'FAIL'
    except BaseException:
        report.update(status='FAIL', exception=traceback.format_exc())
    finally:
        PlanFrame._invoke = original
        after = helper.manifest(SOURCE)
        write(OUT / 'SOURCE-AFTER.json', after)
        report.update(seconds=time.monotonic() - start, source_unchanged=before == after,
                      source_tree=helper.tree_hash(after), actual_native_returns=returns,
                      total_actual_native_returns=sum(returns.values()))
        if before != after:
            report['status'] = 'FAIL'
        write(OUT / 'REPORT.json', report)
    print(json.dumps({k: report[k] for k in ('status', 'tests_run', 'seconds', 'source_unchanged', 'total_actual_native_returns', 'current_source_cold')}, sort_keys=True))
    return int(report['status'] != 'PASS')


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        return child()
    OUT.mkdir(mode=0o700)
    workflow = Path(__file__).with_name('workflow_process.py')
    raw = workflow.read_bytes()
    if sha256(raw).hexdigest() != 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80':
        raise ValueError('original workflow process guard differs')
    supervisor = load_file('original_workflow_guard', workflow)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith('HEPTA_HIA_') and (key.endswith('_MANIFEST') or key.endswith('_COLD_REPORT') or '_DEVELOPMENT' in key):
            del env[key]
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(SOURCE),
        HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST=str(IMAGES / 'core_lowering/manifest.json'),
        HEPTA_HIA_CORE_LOWERING_FIXTURE_EVIDENCE=str(OUT / 'core'),
        HEPTA_HIA_NATIVE_BYTE_ABI_DEVELOPMENT_COMPILER=str(IMAGES / 'retained-development-compiler.bin'),
        HEPTA_HIA_NATIVE_BYTE_ABI_EVIDENCE=str(OUT / 'byte'),
        HEPTA_HIA_NATIVE_BUILD_DEVELOPMENT_COMPILER=str(IMAGES / 'retained-development-compiler.bin'),
        HEPTA_HIA_NATIVE_BUILD_EVIDENCE=str(OUT / 'build'))
    result = supervisor.run_workflow_step([sys.executable, '-B', str(Path(__file__).resolve()), '--child'],
        cwd=SOURCE, env=env, stdout_path=OUT / 'stdout', stderr_path=OUT / 'stderr',
        receipt_path=OUT / 'PROCESS.json', seconds=1800)
    print(json.dumps(result, sort_keys=True))
    return int(result.get('returncode', 1) != 0)


if __name__ == '__main__':
    sys.exit(main())
