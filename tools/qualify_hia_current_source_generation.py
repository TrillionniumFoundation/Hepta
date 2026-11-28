"""Run the complete retained 393-source-control domain from current custody.

The four product/source successors and the appended composition reader have
explicit fixed complete predecessors. Original test IDs, method bodies,
assertions, all 47 selectors and the original 900-second budget are retained.
A successful historical gate does not qualify current product execution.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

SELECTORS = (
    "tests.test_hia_cold_caller_selection_history",
    "tests.test_hia_store_source_history",
    "tests.test_hia_store_native_delivery.StoreNativeDeliverySourceTests",
    "tests.test_hia_caller_terminal_admission.CallerTerminalAdmissionSourceTests",
    "tests.test_hia_caller_terminal_readback.CallerTerminalReadbackSourceTests",
    "tests.test_hia_release_contract",
    "tests.test_hia_store_file_capture_native_readback",
    "tests.test_hia_history_fixture_custody",
    "tests.test_hia_integrated_caller_history",
    "tests.test_hia_integrated_caller_source_admission",
    "tests.test_hia_current_caller_source_history",
    "tests.test_hia_native_result_caller_history",
    "tests.test_hia_artifact_caller_source_history",
    "tests.test_hia_cost_artifact_caller_admission",
    "tests.test_hia_caller_diagnostics_admission",
    "tests.test_hia_current_terminal_admission_history",
    "tests.test_hia_service_bootstrap_caller_admission",
    "tests.test_hia_scoped_caller_source_history",
    "tests.test_hia_evaluation_window_history",
    "tests.test_hia_installed_evaluation_source_history",
    "tests.test_hia_evaluation_caller_capture_history",
    "tests.test_hia_evaluation_caller_admission",
    "tests.test_hia_current_store_source_history",
    "tests.test_hia_cold_compiler",
    "tests.test_hia_native_cold_ci",
    "tests.test_hia_component_input_custody",
    "tests.test_hia_native_cold_custody_readers",
    "tests.test_hia_cold_native_transport.ColdNativeTransportSourceTests",
    "tests.test_hia_cold_native_transport.ColdNativeTransportLibraryPathTests",
    "tests.test_hia_cold_native_transport_controls.ColdNativeTransportControlsSourceTests",
    "tests.test_hia_component_cold_readback",
    "tests.test_hia_current_component_authoring_history",
    "tests.test_hia_evaluation_cold_source_history",
    "tests.test_hia_current_store_broad_cold",
    "tests.test_hia_native_cold_caller_sources",
    "tests.test_hia_native_cold_caller_integration",
    "tests.test_hia_transport_native_cold_source_admission",
    "tests.test_hia_native_cold_caller_physical_history",
    "tests.test_hia_slot_cold_selection_history",
    "tests.test_hia_slot_integration_component_history",
    "tests.test_hia_native_cold_composition_history",
    "tests.test_hia_native_cold_original_fixture",
    "tests.test_hia_worker_install_owner_generation",
    "tests.test_hia_scoped_evaluation_cold_admission",
    "tests.test_hia_transport_history_views",
    "tests.test_hia_scoped_caller_admission_history",
    "tests.test_hia_scoped_store_diagnostic_history",
)
EXPECTED_TESTS = 393
ORIGINAL_TIMEOUT = 900


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    from tools import hia_current_source_generation as history
    if (source / history.SELF).read_bytes() != Path(history.__file__).read_bytes():
        raise ValueError('original-source supervisor loaded another current reader')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source).decode().strip()
    paths = [p.decode() for p in subprocess.check_output(
        ['git', 'ls-files', '-z'], cwd=source).split(b'\0') if p]
    # The new source files may be under review before a normal commit. They
    # are named actual inputs, and are captured like every tracked input.
    extra = (history.SELF, history.FIXTURE, 'tools/qualify_hia_current_source_generation.py',
             'tests/test_hia_current_source_generation.py')
    paths = sorted(set(paths) | set(extra))
    modules = sorted(set('/'.join(name.split('.')[:2]) + '.py' for name in SELECTORS))
    raw_modules = {n: (source / n).read_bytes() for n in modules}
    result = {'schema': 'hepta.hia.current-physical-original393-source-controls.v1',
              'source_head': head, 'scope': 'EXPLICIT_RETAINED_393_SOURCE_CONTROL_DOMAIN',
              'original_selectors': list(SELECTORS), 'expected_tests': EXPECTED_TESTS,
              'original_timeout_seconds': ORIGINAL_TIMEOUT,
              'physical_current_source_qualified': False,
              'current_product_execution_qualified': False,
              'whole_native_stack_qualified': False, 'passed': False}
    def save():
        (output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    save()
    try:
        with history.original_source_view(source, output / 'source-view', paths) as (view, review, custody):
            result['source_preparation'] = review
            for name, raw in raw_modules.items():
                if (view / name).read_bytes() != raw:
                    raise ValueError('original source test module changed during preparation: ' + name)
            result['original_test_modules'] = {n: history.pin(raw) for n, raw in raw_modules.items()}
            result['all_original_test_modules_byte_identical'] = True
            argv = [str(args.python.resolve(strict=True)), '-B',
                    'tools/run_hia_unittest_gate.py', *SELECTORS]
            result['argv'] = argv
            save()
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            started = time.monotonic()
            with (output / 'tests.stdout').open('xb') as stdout, (output / 'tests.stderr').open('xb') as stderr:
                child = subprocess.Popen(argv, cwd=view, env=env, stdout=stdout,
                                         stderr=stderr, start_new_session=True)
                result['pid'] = child.pid
                save()
                timeout = False
                try:
                    code = child.wait(timeout=ORIGINAL_TIMEOUT)
                except subprocess.TimeoutExpired:
                    timeout = True
                    os.killpg(child.pid, signal.SIGKILL)
                    code = child.wait(timeout=3)
                result.update(returncode=code, timed_out=timeout,
                              elapsed_seconds=time.monotonic()-started)
            data = (output / 'tests.stderr').read_bytes()
            match = re.search(rb'^Ran ([0-9]+) tests? in ([0-9.]+)s$', data, re.M)
            result['reported_tests'] = int(match.group(1)) if match else None
            result['reported_unittest_seconds'] = float(match.group(2)) if match else None
            result['stderr'] = history.pin(data)
            result['stdout'] = history.pin((output / 'tests.stdout').read_bytes())
            result['passed'] = (code == 0 and not timeout
                                and result['reported_tests'] == EXPECTED_TESTS
                                and re.search(rb'^OK$', data, re.M) is not None)
            history.verify_unchanged(custody)
        result['source_preparation'] = review
        save()
    except BaseException as error:
        result['error'] = repr(error)
        result['passed'] = False
        save()
        raise
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ('source_preparation', 'original_test_modules', 'original_selectors')},
                     sort_keys=True), flush=True)
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
