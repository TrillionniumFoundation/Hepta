"""Pinned upstream upgrade, independent behavior oracle and honest failure scope."""
from __future__ import annotations

import copy
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.qualify_cpp_upgrade import FIXTURES, VERSIONS, _run, cases, expected_rows, locked_libraries, qualify_cpp_upgrade, validate_report

NATIVE = shutil.which('g++') and shutil.which(os.environ.get('RUSTC', 'rustc')) and shutil.which('ldd') and shutil.which('nm')


class UpgradeInputTests(unittest.TestCase):
    def test_exact_unmodified_two_version_headers_and_independent_case_denominator(self):
        self.assertEqual(tuple(r['version'] for r in locked_libraries()), VERSIONS)
        self.assertEqual(len(cases()), 98)
        rows = expected_rows()
        self.assertEqual(len(rows), 98)
        self.assertTrue(any(r['direct_status'] == 0 for r in rows))
        self.assertTrue(any(r['direct_status'] == 3 for r in rows))

    def test_changed_upstream_header_is_rejected_even_if_declared_hash_is_rewritten(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'upstream'
            shutil.copytree(FIXTURES, target)
            header = target / VERSIONS[1] / 'json.hpp'
            header.write_bytes(header.read_bytes() + b'\n// changed\n')
            with self.assertRaisesRegex(ValueError, 'header content'):
                locked_libraries(target)
            lock = json.loads((target / 'lock.json').read_text())
            lock['versions'][1]['sha256'] = '0' * 64
            (target / 'lock.json').write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError, 'identity differs'):
                locked_libraries(target)

    def test_existing_work_directory_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / 'keep'
            marker.write_text('unchanged')
            with self.assertRaisesRegex(ValueError, 'new work directory'):
                qualify_cpp_upgrade(td)
            self.assertEqual(marker.read_text(), 'unchanged')


class UpgradeFailureCollectionTests(unittest.TestCase):
    def test_timeout_preserves_exact_partial_bytes_and_prior_completed_stage(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            receipt = {}
            first = _run([sys.executable, '-c', 'print("completed")'], owner=receipt, directory=directory, stage='first')
            with patch('tools.qualify_cpp_upgrade.subprocess.run', side_effect=subprocess.TimeoutExpired(
                    ['interrupted'], 1, output=b'partial\xff', stderr=b'error\xfe')):
                with self.assertRaises(subprocess.TimeoutExpired):
                    _run([sys.executable, '-c', 'pass'], owner=receipt, directory=directory, stage='second', timeout=1)
            self.assertEqual(len(receipt['processes']), 2)
            self.assertIs(receipt['processes'][0], first)
            self.assertEqual(first['stdout'], 'completed\n')
            failed = receipt['processes'][1]
            self.assertEqual(failed['status'], 'timeout')
            self.assertIsNone(failed['exit_code'])
            self.assertEqual(Path(failed['stdout_path']).read_bytes(), b'partial\xff')
            self.assertEqual(Path(failed['stderr_path']).read_bytes(), b'error\xfe')
            self.assertEqual(base64.b64decode(failed['stdout_bytes_base64']), b'partial\xff')

    def test_nonzero_stage_retains_actual_exit_and_both_streams(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = {}
            with self.assertRaises(RuntimeError):
                _run([sys.executable, '-c', 'import sys;print("partial");print("failed",file=sys.stderr);sys.exit(7)'],
                     owner=receipt, directory=Path(td), stage='failed')
            process = receipt['processes'][0]
            self.assertEqual((process['exit_code'], process['stdout'], process['stderr']), (7, 'partial\n', 'failed\n'))
            self.assertEqual(Path(process['stdout_path']).read_bytes(), b'partial\n')

    @unittest.skipUnless(shutil.which('g++') and shutil.which('nm') and shutil.which('ldd'), 'observed compiler/dependency tools required')
    def test_mid_version_failure_keeps_partial_row_and_continues_other_version(self):
        seen = []
        def injected(root, locked, compiler, rustc, *, receipt, native_tools):
            seen.append(locked['version'])
            receipt['status'] = 'running'
            directory = root / locked['version']
            directory.mkdir()
            _run([sys.executable, '-c', 'print("prior stage")'], owner=receipt, directory=directory, stage='prior')
            if locked['version'] == VERSIONS[0]:
                raise RuntimeError('injected middle-stage failure')
            receipt['status'] = 'passed'
        with tempfile.TemporaryDirectory() as td, patch('tools.qualify_cpp_upgrade._native_version', side_effect=injected):
            report = qualify_cpp_upgrade(Path(td) / 'attempt')
            self.assertFalse(report['ok'])
            self.assertEqual(seen, list(VERSIONS))
            self.assertEqual([row['status'] for row in report['versions']], ['failed', 'passed'])
            self.assertEqual(report['versions'][0]['processes'][0]['stdout'], 'prior stage\n')
            self.assertIn('injected middle-stage failure', report['versions'][0]['error'])
            self.assertEqual(report['negative_controls']['status'], 'not_run')


@unittest.skipUnless(NATIVE, 'native pinned Rust/C++ and observed runtime tools required')
class NativeUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hepta-upstream-upgrade-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.report = qualify_cpp_upgrade(Path(cls.temp.name) / 'run')
        if cls.report.get('ok') is not True:
            raise AssertionError(json.dumps(cls.report))

    def test_real_versions_generated_sources_C_ABI_and_behavior(self):
        validate_report(self.report)
        self.assertEqual(len(self.report['versions']), 2)
        self.assertTrue(self.report['upgrade']['generated_identity_equal'])
        self.assertTrue(self.report['upgrade']['c_export_symbols_equal'])
        self.assertEqual(self.report['upgrade']['source_files_patched'], [])
        self.assertIsNone(self.report['upgrade']['human_review_hours'])
        self.assertIsNone(self.report['upgrade']['agent_tokens'])

    def test_every_allocation_site_retained_without_crediting_abort_as_recovery(self):
        for row in self.report['versions']:
            faults = row['allocation_failures']
            self.assertEqual(len(faults), row['execution']['allocation_sites'])
            self.assertTrue(any(f['status'] == 'caught_and_recovered' for f in faults))
            # Exact released libraries allocate while destroying their values.
            # A rejecting allocator can therefore terminate their noexcept dtor.
            self.assertTrue(any(f['status'] == 'foreign_noexcept_termination' for f in faults))
            self.assertIs(row['all_allocation_failure_paths_recovered'], False)
            for fault in faults:
                if fault['status'] == 'foreign_noexcept_termination':
                    self.assertIs(fault['recovery_qualified'], False)
                    self.assertIsNone(fault['observation'])

    def test_inconsistent_or_scope_enlarged_receipts_fail_closed(self):
        mutations = {
            'one_version': lambda r: r['versions'].pop(),
            'compiler': lambda r: r.update(compiler_sha256='0' * 64),
            'oracle': lambda r: r.update(oracle_sha256='0' * 64),
            'case_denominator': lambda r: r.update(case_count_per_version=97),
            'wrong_native_case': lambda r: r['versions'][0]['execution']['cases'][0].update(hepta_value=0),
            'bool_native_case': lambda r: r['versions'][0]['execution']['cases'][0].update(live_delta=False),
            'process_bool': lambda r: r['versions'][0]['execution_process'].update(exit_code=False),
            'missing_allocation_site': lambda r: r['versions'][0]['allocation_failures'].pop(),
            'invented_recovery': lambda r: r['versions'][0].update(all_allocation_failure_paths_recovered=True),
            'invented_site_recovery': lambda r: r['versions'][0]['allocation_failures'][-1].update(recovery_qualified=True),
            'empty_generated_identities': lambda r: [v.update(generated_identity={}) for v in r['versions']],
            'empty_runtime_closure': lambda r: r['versions'][0]['runtime_dependencies'].update(files={}),
            'missing_cpp_artifact': lambda r: r['versions'][0]['artifacts'].pop('bridge/bridge.cpp'),
            'unobserved_C_symbol': lambda r: r['versions'][0]['c_symbols'].append('hepta_cpp_json_upgrade_fake'),
            'negative_control_passed': lambda r: r['negative_controls']['wrong_implementation']['execution_process'].update(exit_code=0),
            'zero_total_cost': lambda r: r['versions'][0]['cost'].update(total_seconds=0),
            'unknown_cost_to_zero': lambda r: r['upgrade'].update(agent_tokens=0),
            'bool_change_count': lambda r: r['upgrade'].update(contract_changes=False),
            'adapter_cost_omitted': lambda r: r['upgrade'].update(authored_initial_adapter_lines=0),
            'unsafe_scope_upgrade': lambda r: r['claims'].update(foreign_memory_safety_proved=True),
            'false_equals_zero_claim': lambda r: r['claims'].update(foreign_library_rewritten=0),
            'unrelated_compile_command': lambda r: r['versions'][0]['commands'][0].update(argv=['/bin/true']),
            'unrelated_execution': lambda r: r['versions'][0]['execution_process'].update(argv=['/bin/true']),
            'wrong_fault_command': lambda r: r['versions'][0]['allocation_failures'][0]['process'].update(argv=['/bin/true']),
            'wrong_rust_source': lambda r: r['versions'][0]['hepta_native'].update(rust_sha256='0' * 64),
            'wrong_native_binary': lambda r: r['versions'][0]['artifacts']['json-upgrade'].update(sha256='0' * 64),
            'missing_header_dependency': lambda r: r['versions'][0]['headers_before']['files'].pop(next(iter(r['versions'][0]['headers_before']['files']))),
            'missing_compilation_dependency': lambda r: r['versions'][0]['compile_dependencies']['bridge']['files'].pop(next(iter(r['versions'][0]['compile_dependencies']['bridge']['files']))),
            'invented_runtime_closure': lambda r: r['versions'][0]['runtime_dependencies'].update(files={'/absent/libfake.so': '0' * 64}),
            'bool_ordinary_live_delta': lambda r: r['versions'][0]['execution'].update(ordinary_live_delta=False),
            'invented_calibration': lambda r: r['versions'][0]['calibration']['observation'].update(allocation_sites=1),
            'calibration_used_other_binary': lambda r: r['versions'][0]['calibration']['process'].update(argv=['/bin/true']),
            'inflated_cost_scope': lambda r: r['upgrade'].update(cost_scope='all development effort is zero'),
            'unknown_top_level_claim': lambda r: r.update(all_allocation_failures_recovered=True),
            'invented_native_tool': lambda r: r['native_tools']['cxx'].update(sha256='0' * 64),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.report)
                mutate(candidate)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    validate_report(candidate)


if __name__ == '__main__':
    unittest.main()
