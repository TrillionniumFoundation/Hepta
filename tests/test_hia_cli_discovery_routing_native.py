"""Optional discovery route: source admission and retained actual comparisons."""
from __future__ import annotations

import ast
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class CliDiscoveryRoutingSourceTests(unittest.TestCase):
    def test_all_original_43_test_bytes_and_ordered_ids_are_retained(self):
        from tools.hia_cli_discovery_bundle_custody import retained_inputs
        from tools.qualify_hia_cli_discovery_bundle import _flatten
        value = retained_inputs()
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(('tests.test_hia_cli_native', 'tests.test_hia_cli_continuation_native'))
        self.assertEqual(loader.errors, [])
        self.assertEqual(suite.countTestCases(), 43)
        self.assertEqual([test.id() for test in _flatten(suite)], value['original_ids'])
        for name, row in value['original_tests'].items():
            with self.subTest(path=name):
                self.assertEqual((ROOT/name).read_bytes(), row['text'].encode())

    def test_explicit_byte_projections_preserve_original_semantic_definitions(self):
        from tools.hia_cli_discovery_bundle_custody import retained_inputs, retained_module_bytes
        value = retained_inputs()
        for name, row in value['integration_projections'].items():
            with self.subTest(path=name):
                current = (ROOT/name).read_bytes()
                self.assertEqual(current, row['after']['text'].encode())
                original = retained_module_bytes(name, current)
                self.assertEqual(sha256(original).hexdigest(), row['before']['sha256'])
                before, after = ast.parse(original), ast.parse(current)
                for selected in row['unchanged_definitions']:
                    old = next(n for n in before.body if getattr(n, 'name', None) == selected)
                    new = next(n for n in after.body if getattr(n, 'name', None) == selected)
                    self.assertEqual(ast.dump(old, include_attributes=False), ast.dump(new, include_attributes=False))
                with self.assertRaises(ValueError): retained_module_bytes(name, current + b'\n')
        self.assertEqual(set(value['integration_projections']),
                         {'hepta/cli.py','hepta/hia_opcodes.py','hepta/hia_cli_native.py'})

    def test_routing_and_parser_generators_reproduce_their_exact_assets(self):
        paths = ('tools/generate_hia_cli_discovery_routing.py', 'tools/generate_hia_cli_parser_context.py')
        consumed = ('examples/hia_bootstrap/cli_discovery_routing.hepta',
                    'examples/hia_bootstrap/cli_parser_context.hepta', 'hepta/hia_cli_parser_context_data.py')
        before = {name:(ROOT/name).read_bytes() for name in consumed}
        for name in paths:
            with self.subTest(generator=name):
                result = subprocess.run([sys.executable, '-I', '-B', str(ROOT/name), '--check'],
                                        cwd=ROOT, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(before, {name:(ROOT/name).read_bytes() for name in consumed})

    def test_all_five_hia_images_keep_the_original_compiler_limits(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_cli_discovery_bundle_custody import SOURCES
        self.assertEqual(list(SOURCES), ['control','format','discovery','routing','parser_context'])
        for name in SOURCES.values():
            with self.subTest(path=name):
                raw = (ROOT/name).read_bytes(); doc = assemble_program(raw).as_dict()
                self.assertLessEqual(len(raw), 1 << 20)
                self.assertLessEqual(len(doc['functions']), 128)
                self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), 1536)
                self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), 8192)
                for fn in doc['functions']:
                    self.assertLessEqual(len(fn['blocks']), 256)
                    definitions = {item['name'] for item in fn['params']}
                    for block in fn['blocks']:
                        definitions.update(item['name'] for item in block['params'])
                        definitions.update(item['name'] for op in block['ops'] for item in op['out'])
                    self.assertLessEqual(len(definitions), 2048)

    def test_current_cold_rejects_before_any_output_or_compiler_call(self):
        from tools import build_hia_cli_discovery_bundle as builder
        from tools import qualify_hia_cli_discovery_bundle as qualifier
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cold=root/'cold.json'; cold.write_text('{}')
            compiler=root/'compiler'; compiler.write_bytes(b'unqualified')
            with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaises(ValueError): builder.build(root/'build', compiler, cold)
                with self.assertRaises(ValueError): qualifier.prepare_fixture(root/'fixture', cold)
            self.assertFalse((root/'build').exists()); self.assertFalse((root/'fixture').exists())

    def test_development_fixture_cannot_be_admitted_as_current_cold(self):
        from tools import qualify_hia_cli_discovery_bundle as qualifier
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.json'
            row={'schema':qualifier.FIXTURE_SCHEMA,'status':qualifier.FIXTURE_STATUS,'authority':{},'build':{},
                 'owner_sources':{},'matching_cold':False,'scope':'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD',
                 'ordinary_cli_activated':False,'whole_cli_native':False,'whole_native_delivery_qualified':False}
            path.write_text(json.dumps(row))
            with patch.object(qualifier,'admit_cold',side_effect=AssertionError('authority entered')):
                with self.assertRaises(ValueError):qualifier.admit_fixture(path)

    def test_result_admission_rejects_all_missing_or_exceptional_outcomes(self):
        from tools import qualify_hia_cli_discovery_bundle as qualifier
        for group, ids in qualifier.groups().items():
            expected=list(ids)
            good={'schema':'hepta.hia.cli-discovery-bundle-test-observations.v1',
                  'scope':'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY','status':'PASS','group':group,
                  'request_sha256':'a'*64,'loaded_ids':expected,'started_ids':expected,'stopped_ids':expected,
                  'loaded':len(expected),'tests_run':len(expected),'source_and_inputs_unchanged':True,
                  **{name:[] for name in qualifier.ANOMALIES}}
            if group=='original_cli':
                good['fixture_provider_calls']=[{'status':'BUILT_AND_READ_BACK'},{'status':'BUILT_AND_READ_BACK'},
                                                {'status':'REJECTED_BEFORE_BUILD'}]
            qualifier.admit_result(good,group,'a'*64)
            for key in qualifier.ANOMALIES:
                bad=copy.deepcopy(good);bad[key]=['original failure']
                with self.subTest(group=group,field=key),self.assertRaises(ValueError):qualifier.admit_result(bad,group,'a'*64)
            for key in ('loaded_ids','started_ids','stopped_ids'):
                bad=copy.deepcopy(good);bad[key]=expected[:-1]
                with self.subTest(group=group,field=key),self.assertRaises(ValueError):qualifier.admit_result(bad,group,'a'*64)
            for key in ('loaded','tests_run'):
                for value in (0,True,len(expected)-1):
                    bad=copy.deepcopy(good);bad[key]=value
                    with self.subTest(group=group,field=key,value=value),self.assertRaises(ValueError):qualifier.admit_result(bad,group,'a'*64)
            bad=copy.deepcopy(good);bad['source_and_inputs_unchanged']=False
            with self.assertRaises(ValueError):qualifier.admit_result(bad,group,'a'*64)

    def test_every_owner_input_is_in_the_actual_cold_source_closure(self):
        from tools.hia_cli_discovery_bundle_custody import OWNER_FILES, owner_sources
        from tools.hia_selfhost_contract import SOURCE_FILES, file_digests
        self.assertEqual(len(OWNER_FILES),len(set(OWNER_FILES)))
        self.assertTrue(set(owner_sources()).issubset(file_digests(ROOT)))
        for name in OWNER_FILES:
            with self.subTest(path=name):
                self.assertTrue((ROOT/name).is_file())
                if not name.startswith('hepta/'):self.assertIn(name,SOURCE_FILES)

    def test_new_native_bridge_resources_have_one_real_role_and_sdist_entry(self):
        from hepta import hia_agent_contract as contract
        from tests.test_hia_cli_discovery_json import ROLES
        manifest=(ROOT/'MANIFEST.in').read_text()
        for stem in ('cli_discovery_json','cli_discovery_routing','cli_parser_context'):
            name='examples/hia_bootstrap/'+stem+'.hepta'
            with self.subTest(resource=name):
                self.assertEqual(sum(getattr(contract,role).count(name) for role in ROLES),1)
                self.assertIn(name,contract.NATIVE_SOURCE_FILES)
                self.assertIn('include '+name,manifest)
                module=__import__('hepta.hia_'+stem+'_native',fromlist=['SOURCE'])
                self.assertEqual(module.SOURCE.read_bytes(),(ROOT/name).read_bytes())

    def test_original_limits_and_permanent_groups_are_explicit(self):
        from tools import qualify_hia_cli_discovery_bundle as qualifier
        self.assertEqual((qualifier.SECONDS,qualifier.CLEANUP_SECONDS,qualifier.CAPACITY),(180,3,1<<20))
        self.assertEqual(len(qualifier.groups()['original_cli']),43)
        self.assertEqual(len(qualifier.NATIVE_IDS),9)
        controls=(ROOT/'tools/hia_cli_discovery_routing_controls.py').read_text()
        self.assertIn('_Machine(program,10000000,8<<20,None,128)',controls)
        self.assertNotIn('gc.collect(',controls)


class CliDiscoveryRoutingNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import qualify_hia_cli_discovery_bundle as qualifier
        cold=os.environ.get(qualifier.COLD_FIXTURE);development=os.environ.get(qualifier.DEVELOPMENT)
        if (cold is None)==(development is None) or cold=='' or development=='':
            raise ValueError('exactly one nonempty explicit CLI bundle fixture required')
        if os.environ.get(qualifier.OLD_DEVELOPMENT) is not None:
            raise ValueError('old development selector cannot override bundle fixture')
        cls.cold=cold
        if cold is not None:
            value=qualifier.admit_fixture(cold);cls.manifest=Path(value['build']['manifest'])
            cls.scope='MATCHING_CURRENT_SOURCE_COLD_CLI_DISCOVERY_BUNDLE'
        else:
            cls.manifest=Path(development).resolve(strict=True)
            qualifier.inspect_build(cls.manifest.parent,None)
            cls.scope='EXPLICIT_DEVELOPMENT_ONLY'
        evidence=os.environ.get(qualifier.EVIDENCE)
        if not evidence:raise ValueError('explicit permanent CLI evidence directory required')
        cls.folder=Path(evidence).absolute()/cls.__name__;cls.folder.mkdir(mode=0o700)

    def tearDown(self):
        from tools import qualify_hia_cli_discovery_bundle as qualifier
        if self.cold is not None:qualifier.admit_fixture(self.cold)
        else:qualifier.inspect_build(self.manifest.parent,None)

    def observe(self,name,count,key='cases'):
        from tools import hia_cli_discovery_routing_controls as controls
        report=getattr(controls,name)(self.manifest,self.folder/name)
        self.assertEqual(report.get('status'),'PASS',report.get('traceback',report))
        self.assertIs(report.get('source_unchanged'),True)
        self.assertEqual(len(report[key]),count)
        return report

    def test_01_original_21_discovery_and_foreign_observations(self):
        report=self.observe('differential',21)
        self.assertGreater(report['entries']['routing'],0);self.assertGreater(report['entries']['json'],0)

    def test_02_original_12_evaluation_order_and_retirement_observations(self):
        self.observe('ordered',12)

    def test_03_original_three_admission_side_effect_controls(self):
        self.observe('admission',3)

    def test_04_original_four_foreign_error_lifetime_observations(self):
        self.observe('foreign_lifetimes',4,'lifetime')

    def test_05_original_28_parser_contexts_and_complete_graphs(self):
        report=self.observe('parser_graph',28)
        self.assertEqual(report['old_parser_bodies_native_entries'],0)

    def test_06_original_three_routing_lost_ack_and_complete_vm_frames(self):
        report=self.observe('routing_protocol',3,'protocol')
        self.assertTrue(report['vm']);self.assertTrue(all(row['equal'] for row in report['vm']))

    def test_07_original_eight_parser_protocol_lifetime_and_complete_vm_frames(self):
        report=self.observe('parser_protocol',8,'controls')
        self.assertTrue(report['vm']);self.assertEqual(len(report['vm']),len(report['frames']))
        self.assertTrue(all(row['complete_buffers_equal'] for row in report['vm']))

    def test_08_actual_routing_step_reentry_is_rejected_before_second_native_entry(self):
        from tools.hia_cli_discovery_routing_controls import inflight_route
        report=inflight_route(self.manifest,self.folder/'inflight_route')
        self.assertEqual(report.get('status'),'PASS',report.get('traceback',report))
        self.assertIs(report.get('source_unchanged'),True)
        self.assertEqual(report['attempts'],['rejected'])
        self.assertEqual(len(report['native_entries']),1)
        self.assertEqual(report['effects'],[])
        self.assertEqual(report['replay_entries'],0)

    def test_09_inplace_metadata_mutation_retains_actual_foreign_semantics(self):
        self.observe('metadata_mutations',11)


if __name__=='__main__':unittest.main()
