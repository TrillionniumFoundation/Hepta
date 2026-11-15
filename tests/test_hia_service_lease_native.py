"""Whole four-method lease controller gates, without replacing any old gate."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest

from tests.hia_service_lease_controls import (
    ROOT, COLD, DEV, EVIDENCE, SOURCE_EVIDENCE, invocation, source_paths,
    finite, build_images, product_snapshot, pin, read_json, write_json,
    run_owned, successful_exit, PlainService, LEASE_VALUE, fake_runner, fake_validator)

_AUTHORITY = None


def _child(module, arguments, directory, seconds):
    code = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
            'runpy.run_module(sys.argv.pop(1),run_name="__main__")')
    command = [sys.executable, '-I', '-B', '-c', code, str(ROOT), module, *map(str, arguments)]
    result = run_owned(command, cwd=ROOT, directory=directory, timeout_seconds=seconds)
    if not successful_exit(result):
        raise AssertionError('complete owned lease control failed: ' + module)
    return result


def _authority():
    global _AUTHORITY
    if _AUTHORITY is None:
        cold, dev = os.environ.get(COLD), os.environ.get(DEV)
        if (cold is None) == (dev is None) or cold == '' or dev == '':
            raise ValueError('one exact matching cold report or explicit DEV compiler is required')
        directory = invocation(EVIDENCE, 'native-authority')
        before = product_snapshot(ROOT, source_paths())
        manifests = build_images(directory, companions=True)
        manifest_list = directory / 'manifests.json'
        write_json(manifest_list, {name: str(path.resolve()) for name, path in manifests.items()})
        images = {}
        for name, path in manifests.items():
            value = read_json(path)
            images[name] = {'manifest': pin(path), 'image': pin(path.parent / value['image_path'])}
        _AUTHORITY = (directory, before, manifests, manifest_list, images)
        write_json(directory / 'authority.json', {
            'scope': 'MATCHING_SOURCE_COLD' if cold else 'DEVELOPMENT_ONLY',
            'source_before': before, 'manifests': images,
            'cold_report': cold, 'development_compiler': dev,
            'whole_native_qualified': False})
    return _AUTHORITY


class ServiceLeaseSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = invocation(SOURCE_EVIDENCE, 'source')
        cls.before = product_snapshot(ROOT, source_paths())

    @classmethod
    def tearDownClass(cls):
        after = product_snapshot(ROOT, cls.before)
        write_json(cls.root / 'source-custody.json', {'before': cls.before, 'after': after})
        if after != cls.before:
            raise AssertionError('Source component changed during execution')

    def test_01_complete_original_bodies_public_bindings_and_HIA_profile(self):
        from tests import hia_service_lease_original_oracle as oracle
        from hepta import hia_agent_service as api
        from hepta import hia_service_lease_native as native
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools import generate_hia_service_lease as generator
        raw = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        module, lines = ast.parse(raw), raw.splitlines(keepends=True)
        cls = next(node for node in module.body if isinstance(node, ast.ClassDef)
                   and node.name == 'HIAAgentService')
        expected_names = ('acquire_slot', '_lease', 'invoke_lease', 'release_slot')
        dispatches = ('_service_lease_acquire_dispatch', '_service_lease_lease_dispatch',
                      '_service_lease_invoke_dispatch', '_service_lease_release_dispatch')
        for name, dispatch in zip(expected_names, dispatches):
            method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(b''.join(lines[method.lineno - 1:method.end_lineno]),
                             (oracle.FIXTURE / (name + '.py.txt')).read_bytes())
            self.assertIs(getattr(api.HIAAgentService, name), getattr(api, dispatch))
        self.assertEqual(len(oracle.cases()), 258)
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_service_lease_native', 'NativeServiceLease'))
        source = native.SOURCE.read_bytes()
        self.assertEqual(source, render_assembly(generator.document()).encode())
        document = assemble_program(source).as_dict()
        self.assertLessEqual(len(source), 1 << 20)
        self.assertLessEqual(len(source.splitlines()), 16384)
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in document['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in document['functions'] for b in f['blocks']), 8192)
        for function in document['functions']:
            self.assertLessEqual(len(function['blocks']), 256)
            names = {parameter['name'] for parameter in function['params']}
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                names.update(parameter['name'] for parameter in block['params'])
                names.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(names), 2048)

    def test_02_complete_258_prior_originals_and_independent_VM(self):
        report = finite(self.root / 'complete-vm', 'vm')
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['actual_cases'], 258)
        self.assertEqual(set(report['modes']), {'1', '2', '3', '4'})

    def test_03_complete_unselected_public_originals_and_empty_selector(self):
        report = finite(self.root / 'complete-unselected', 'unselected')
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['actual_cases'], 258)
        self.assertEqual(report['entries'], 0)
        from hepta import hia_agent_service as api
        from hepta import hia_service_lease_native as native
        old = os.environ.get(native.SELECTOR)
        service = PlainService()
        try:
            os.environ[native.SELECTOR] = ''
            with self.assertRaises(ValueError):
                api.HIAAgentService.acquire_slot(service, 'slot')
            self.assertEqual(service.events, [])
        finally:
            if old is None:
                os.environ.pop(native.SELECTOR, None)
            else:
                os.environ[native.SELECTOR] = old


class _LeaseNativeAuthority(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root, cls.before, cls.manifests, cls.manifest_list, cls.images = _authority()

    @classmethod
    def tearDownClass(cls):
        after = product_snapshot(ROOT, cls.before)
        images = {name: {'manifest': pin(path), 'image': pin(path.parent / read_json(path)['image_path'])}
                  for name, path in cls.manifests.items()}
        write_json(cls.root / (cls.__name__ + '-custody.json'), {
            'before': cls.before, 'after': after, 'images_before': cls.images, 'images_after': images,
            'actual_runtime': sys.version, 'whole_native_qualified': False})
        if cls.before != after or cls.images != images:
            raise AssertionError('complete native source/image custody changed')

    def control(self, name, seconds=180):
        target = self.root / ('control-' + name)
        _child('tests.hia_service_lease_controls',
            ['--action', name, '--manifest-list', self.manifest_list, '--output', target],
            self.root / ('command-' + name), seconds)
        report = read_json(target / 'report.json')
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['action'], name)
        self.assertEqual(report['source_before'], report['source_after'])
        self.assertEqual(report['manifest_before'], report['manifest_after'])
        return report


class ServiceLeaseNativeTests(_LeaseNativeAuthority):
    def test_01_complete_258_prior_originals_and_actual_public_native(self):
        report = finite(self.root / 'complete-native', 'native', self.manifests['lease'])
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['actual_cases'], 258)
        self.assertEqual(set(report['modes']), {'1', '2', '3', '4'})

    def test_02_actual_public_binding_overrides_and_original_signature_errors(self):
        report = self.control('public')
        self.assertTrue(report['observation']['retained_poisoned'])
        self.assertTrue(report['observation']['explicit_class_call_selected'])

    def test_03_full_ABI_buffers_independent_VM_and_replay_refusal(self):
        report = self.control('transport')
        self.assertTrue(report['observation']['full_buffer_VM_native_comparisons'])
        self.assertEqual(report['observation']['provider_effects'], 0)

    def test_04_preentry_refusal_and_actual_native_return_loss(self):
        report = self.control('loss')
        self.assertEqual(len(report['observation']['controls']), 8)
        self.assertTrue(report['observation']['exception_class_was_not_loss_evidence'])

    def test_05_thread_fork_stale_reentry_and_live_creator(self):
        report = self.control('ownership')
        self.assertEqual(len(report['observation']['controls']), 5)

    def test_06_complete_original_lease_snapshot_workflow(self):
        report = self.control('workflow', 1800)
        self.assertEqual(report['observation']['run'], 1)
        self.assertFalse(report['observation']['original_fixture_or_budget_changed'])

    def test_07_exact_loader_source_and_exclusive_worker_authority(self):
        self.control('loader')
        report = self.control('pinned')
        self.assertTrue(report['observation']['exact_pinned_image'])
        self.assertEqual(len(report['observation']['controls']), 4)

    def test_08_installed_worker_and_public_consumers_with_actual_ACK_loss(self):
        target = self.root / 'installed'
        _child('tests.hia_service_lease_installed',
            ['--manifest-list', self.manifest_list, '--output', target],
            self.root / 'installed-command', 1800)
        report = read_json(target / 'report.json')
        self.assertEqual(report['status'], 'PASS')
        self.assertTrue(report['actual_worker_entry'])
        self.assertTrue(report['installed_four_public_methods_selected'])
        self.assertFalse(report['whole_native_execution_claimed'])


class ServiceLeaseResourceTests(_LeaseNativeAuthority):
    def resources(self, indexes):
        from tests.hia_service_lease_resources import RESOURCE_IDS
        for index in indexes:
            name = RESOURCE_IDS[index]
            target = self.root / 'resources' / name
            _child('tests.hia_service_lease_resources',
                ['--manifest-list', self.manifest_list, '--root', target, '--case', name],
                self.root / 'resource-commands' / name, 180)
            rows = read_json(target / 'report.json')
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['case'], name)
            self.assertIs(rows[0]['validated'], True)
            self.assertTrue(rows[0]['child_entries'])
            self.assertTrue(rows[0]['owner_entries'])
            self.assertTrue(rows[0]['sql_B'])

    def test_01_actual_child_effect_swallowed_replaced_and_parent_ACK_loss(self):
        self.resources((0, 1, 2))

    def test_02_confirmed_foreign_error_final_ACK_and_finalization_loss(self):
        self.resources((3, 4, 5))

    def test_03_actual_resource_identity_and_new_Context(self):
        self.resources((6, 7, 8))

    def test_04_transaction_cleanup_and_healthy_retirement(self):
        self.resources((9, 10, 11))


if __name__ == '__main__':
    unittest.main()
