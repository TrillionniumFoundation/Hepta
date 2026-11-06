"""Pairing/overlay refusals for actual system images; no synthetic kernel PASS."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools import qualify_hia_linux_system as system


class SystemEvidence(unittest.TestCase):
    def test_bound_file_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'first')
            bound = system.base.identity(path)
            self.assertEqual(system.checked_binding(bound), path)
            path.write_bytes(b'other')
            with self.assertRaisesRegex(ValueError, 'changed'):
                system.checked_binding(bound)

    def test_overlay_checks_before_and_after_and_preserves_unmentioned_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'old.c').write_bytes(b'old')
            (root/'keep.S').write_bytes(b'asm')
            before = system.base.inventory_tree(root)
            payload = root/'payload'; payload.write_bytes(b'new')
            manifest = {'files': [{'relative_path': 'old.c', 'before_sha256': system.base.sha(root/'old.c'),
                                    'after': system.base.identity(payload)}]}
            expected = system.overlay_expected_inventory(before, manifest)
            self.assertEqual(next(x for x in expected if x['path']=='keep.S'), next(x for x in before if x['path']=='keep.S'))
            self.assertEqual(next(x for x in expected if x['path']=='old.c')['sha256'], system.base.sha(payload))
            bad = copy.deepcopy(manifest); bad['files'][0]['before_sha256'] = '0'*64
            with self.assertRaisesRegex(ValueError, 'before-image'):
                system.overlay_expected_inventory(before, bad)
            bad = copy.deepcopy(manifest); bad['files'][0]['relative_path'] = '../outside'
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                system.overlay_expected_inventory(before, bad)

    def test_actual_hardlinked_source_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); original = root/'original'; copied=root/'copied'
            original.mkdir();copied.mkdir();(original/'code.c').write_bytes(b'code')
            os.link(original/'code.c', copied/'code.c')
            with self.assertRaisesRegex(ValueError, 'hardlinked'):
                system.require_independent_inodes(original, copied, system.base.inventory_tree(original))

    def test_qemu_option_alias_or_duplicate_cannot_change_selected_image(self):
        self.assertEqual(system.single_option(['qemu','-kernel','expected'],'-kernel'), 'expected')
        for argv in (['qemu'], ['qemu','-kernel'], ['qemu','-kernel','one','-kernel','two']):
            with self.assertRaises(ValueError):system.single_option(argv,'-kernel')

    def test_component_observation_requires_one_complete_arm_and_cpu_bound_frame(self):
        prepared={'artifact':{'core_sha256':'a'*64,'sha256':'b'*64}}
        frame={'arm':'hybrid','core_sha256':'a'*64,'object_sha256':'b'*64,
               'direct_calls':system.component_tool.CALLS,'natural_calls':system.component_tool.CALLS,
               'abi_calls':32,'popcnt':0,'failures':0,'result_digest':system.component_tool.expected_digest()}
        text='[2.4] '+system.component_tool.PREFIX+json.dumps(frame)+'\n'
        self.assertEqual(system.validate_component_observation(text,'hybrid',prepared)['status'],'PASS')
        with self.assertRaises(ValueError):system.validate_component_observation(text+text,'hybrid',prepared)
        for key,value in [('arm','control'),('object_sha256','0'*64),('popcnt',1),('failures',1),('natural_calls',0),
                          ('failures',False),('abi_calls',32.0),('natural_calls',str(system.component_tool.CALLS))]:
            changed={**frame,key:value}
            with self.assertRaises(ValueError):
                system.validate_component_observation(system.component_tool.PREFIX+json.dumps(changed),'hybrid',prepared)

    def test_partial_stock_receipt_cannot_start_paired_build(self):
        for value in ({}, {'status':'PASS','build_status':'PASS','boot_status':'NOT_RUN'},
                      {'status':'PASS','build_status':'PASS','boot_status':'PASS','image_kind':'hybrid_linux_hia_component'}):
            with self.assertRaises(ValueError):system.validate_stock(value)


    def test_stock_pass_cannot_override_observed_boot_process_group_failure(self):
        # Reuse only the explicit synthetic receipt fixture; no guest runs here.
        from tests import test_hia_linux_kernel_contract as fixtures
        fixture = fixtures.KernelContractTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        stock = fixture.baseline
        stock['compiler'] = fixture.write('tools/clang', b'SYNTHETIC COMPILER; NOT EXECUTABLE')
        stock['source_before']['wrapper'] = system.base.identity(system.base.__file__)
        stock['source_before']['guest_source'] = system.base.identity(
            system.ROOT / 'experiments/hia_linux_kernel_20261106/guest_init.c')
        self.assertEqual(system.validate_stock(stock)['status'], 'PASS')
        for failure in ({'incomplete_process_group': True},
                        {'process_group_cleanup': {'drained': False}},
                        {'interruption': {'type': 'RequestedCancellation', 'message': 'cancelled'}}):
            with self.subTest(failure=failure):
                changed = copy.deepcopy(stock)
                changed['boot']['command_receipt'].update(failure)
                with self.assertRaisesRegex(ValueError, 'stock boot command process group did not complete'):
                    system.validate_stock(changed)


if __name__=='__main__':unittest.main()
