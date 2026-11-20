"""Four complete actual-native methods for the versioned Budget B resource ABI.

No old test is replaced. The existing bootstrap 17-resource gate, its blocking
B case, original candidate/execution budget modules and full callers remain
independent requirements. No absent-selector skip or administrator upgrade.
"""
from __future__ import annotations
from pathlib import Path
import os
import sys
import unittest

from tests import hia_service_bootstrap_support as support
from tests.hia_service_bootstrap_controls import (
    COLD, DEV, build_images, invocation, manifest_pins)
from tests.hia_budget_resource_retirement_controls import CASE_IDS, SELECTORS

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'HEPTA_HIA_BUDGET_RESOURCE_EVIDENCE'
_AUTHORITY = None


def authority():
    global _AUTHORITY
    if _AUTHORITY is not None:
        return _AUTHORITY
    root = invocation(EVIDENCE, 'native-budget-resource')
    before = support.source_snapshot()
    images_root = root / 'images'
    images_root.mkdir(mode=0o700)
    manifests = build_images(images_root)
    support.write_json(images_root / 'manifest-list.json',
        {name: str(Path(path).resolve()) for name, path in manifests.items()})
    construction_path = images_root / 'construction.json'
    construction_raw, construction, construction_pin = support.capture_json(construction_path)
    compiler = Path(construction['compiler_path'])
    compiler_raw = compiler.read_bytes()
    if support.bytes_pin(compiler_raw) != construction['compiler']:
        raise AssertionError('actual six-image compiler changed')
    from tools.build_hia_slot_operations import build as slot_build
    cold = os.environ.get(COLD)
    manifests['operations'] = slot_build(root / 'slot-operations-image', compiler, cold,
                                        development=cold is None)
    if compiler.read_bytes() != compiler_raw:
        raise AssertionError('seventh image did not preserve the common compiler')
    manifest_path = root / 'manifest-list.json'
    manifest_pin = support.write_json(manifest_path,
        {name: str(Path(path).resolve()) for name, path in manifests.items()})
    from hepta.hia_native_helpers import SCHEMA, ABI, TARGET
    bundle_path = root / 'bundle.json'
    bundle_pin = support.write_json(bundle_path, {
        'schema': SCHEMA, 'abi': ABI, 'target': TARGET,
        'helpers': [
            {'selector': SELECTORS[name], 'manifest_path': str(Path(path).resolve()),
             'manifest_sha256': support.file_pin(path)['sha256']}
            for name, path in manifests.items()]})
    after = support.source_snapshot()
    if not support.same(before, after):
        raise AssertionError('resource construction sources changed')
    support.exact_reread(construction_path, construction_raw)
    value = {
        'schema': 'hepta.hia.budget-resource-authority.v1',
        'scope': construction['scope'],
        'source_before': before, 'source_after': after,
        'compiler_path': str(compiler.resolve()), 'compiler': support.bytes_pin(compiler_raw),
        'cold_report_path': construction['cold_report_path'],
        'cold_report': construction['cold_report'],
        'construction_path': str(construction_path.resolve()), 'construction': construction_pin,
        'operations_build_path': str((root / 'slot-operations-image/build.json').resolve()),
        'operations_build': support.file_pin(root / 'slot-operations-image/build.json'),
        'manifest_list_path': str(manifest_path.resolve()), 'manifest_list': manifest_pin,
        'images': manifest_pins(manifests),
        'bundle_path': str(bundle_path.resolve()), 'bundle': bundle_pin,
        'whole_native_stack_qualified': False,
    }
    path = root / 'authority.json'
    pin = support.write_json(path, value)
    _AUTHORITY = root, before, path, pin
    return _AUTHORITY


class BudgetResourceRetirementNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, dev = os.environ.get(COLD), os.environ.get(DEV)
        if (cold is None) == (dev is None) or cold == '' or dev == '':
            raise ValueError('resource Native gates require one current cold/explicit DEV compiler')
        cls.root, cls.before, cls.authority_path, cls.authority_pin = authority()

    @classmethod
    def tearDownClass(cls):
        if not support.same(cls.before, support.source_snapshot()):
            raise AssertionError('complete Budget B component source changed')

    def cases(self, names):
        directory = self.root / self._testMethodName
        directory.mkdir(mode=0o700)
        rows = []
        report = {'schema': 'hepta.hia.budget-resource-method.v1',
                  **support.child_identity(), 'test_id': self.id(),
                  'planned': list(names), 'cases': rows, 'status': 'HOLD',
                  'authority': self.authority_pin, 'source_before': self.before}
        try:
            for name in names:
                with self.subTest(case=name):
                    row = {'case': name, 'started': True, 'stopped': False, 'status': 'HOLD'}
                    rows.append(row)
                    support.write_json(directory / (name + '.planned.json'), {
                        'test_id': self.id(), 'case': name, 'started': True})
                    destination = directory / name
                    command = [sys.executable, '-I', '-B',
                        str(ROOT / 'tests/hia_budget_resource_retirement_controls.py'),
                        '--authority', str(self.authority_path),
                        '--authority-sha256', self.authority_pin['sha256'],
                        '--authority-bytes', str(self.authority_pin['bytes']),
                        '--case', name, '--output', str(destination)]
                    try:
                        result, inner, raw = support.run_child(
                            directory, name, command, seconds=180, report_relative='report.json')
                        self.assertEqual(inner['argv'], command[3:])
                        self.assertEqual(inner['case'], name)
                        self.assertEqual(inner['status'], 'PASS_CONTROL_ONLY')
                        self.assertIs(inner['validated'], True)
                        self.assertEqual(result['stderr']['bytes'], 0)
                        self.assertTrue(support.same(inner['authority'], self.authority_pin))
                        self.assertTrue(support.same(inner['source_before'], self.before))
                        self.assertTrue(support.same(inner['source_after'], self.before))
                        support.exact_reread(destination / 'report.json', raw)
                        row.update(status='PASS_CONTROL_ONLY', command=result,
                                   inner_report=support.bytes_pin(raw))
                    except BaseException as error:
                        row['failure'] = {'type': type(error).__name__, 'text': str(error)}
                        raise
                    finally:
                        row['stopped'] = True
                        support.write_json(directory / (name + '.record.json'), row)
            report['source_after'] = support.source_snapshot()
            self.assertTrue(support.same(self.before, report['source_after']))
            if (len(rows) == len(names)
                    and all(row['status'] == 'PASS_CONTROL_ONLY' for row in rows)):
                report['status'] = 'PASS_METHOD_ONLY'
        finally:
            support.write_json(directory / 'method.json', report)

    def installed(self):
        directory=self.root/'installed-method'
        directory.mkdir(mode=0o700)
        report={'schema':'hepta.hia.budget-resource-installed-method.v1',
                **support.child_identity(),'test_id':self.id(),'status':'HOLD',
                'authority':self.authority_pin}
        command=[sys.executable,'-I','-B',
            str(ROOT/'tests/hia_budget_resource_retirement_installed.py'),
            '--authority',str(self.authority_path),
            '--authority-sha256',self.authority_pin['sha256'],
            '--authority-bytes',str(self.authority_pin['bytes']),
            '--output',str(directory/'installed')]
        try:
            result,inner,raw=support.run_child(directory,'installed',command,
                seconds=1800,report_relative='report.json')
            self.assertEqual(inner['status'],'PASS_INSTALLED_ONLY')
            self.assertIs(inner['actual_budget_connection_and_public_close'],True)
            self.assertTrue(support.same(inner['authority'],self.authority_pin))
            self.assertTrue(support.same(inner['source_before'],self.before))
            self.assertTrue(support.same(inner['source_after'],self.before))
            support.exact_reread(directory/'installed/report.json',raw)
            report.update(command=result,inner_report=support.bytes_pin(raw),
                          status='PASS_INSTALLED_METHOD_ONLY')
        finally:
            support.write_json(directory/'method.json',report)

    def test_01_actual_construction_ack_admission_cleanup_and_repeated_close(self):
        self.cases(CASE_IDS[:6])

    def test_02_actual_close_return_ordinary_error_and_child_loss_identity(self):
        self.cases(CASE_IDS[6:12])

    def test_03_actual_nested_series_parent_receipts_and_preparation_returns(self):
        self.cases(CASE_IDS[12:18])

    def test_04_actual_unknown_reinitialize_Context_thread_and_fork(self):
        self.cases(CASE_IDS[18:])
        self.installed()
