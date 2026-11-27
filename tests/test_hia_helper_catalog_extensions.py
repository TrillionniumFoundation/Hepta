"""Control the explicit helper extension and preserve every original HIA function."""
from copy import deepcopy
import importlib
import json
from pathlib import Path
import struct
import unittest

from hepta.hia_program_runtime import execute_program
from tools import generate_hia_source_helper_manifest as author
from tools.build_hia_worker_release import INSTALLED_HELPERS, EXTENDED_INSTALLED_HELPERS
from tools.build_hia_json_preflight import CANDIDATES, image_manifest_schema
from tools.generate_hia_helper_extension_recipe import recipe
from tools.generate_hia_worker_manifest import model, current_model
from tests.test_hia_release_stage_recipes import decode

ROOT = Path(__file__).resolve().parents[1]


class HelperExtensionSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = author.helper_program()
        cls.stage = author.stage_program()

    def test_complete_original_helper_function_bodies_are_retained(self):
        for original in author.original('helper')['functions']:
            expected = deepcopy(original)
            name = expected['name']
            if name == 'admit':
                expected['name'] = 'admit_prior'
                for block in expected['blocks']:
                    for op in block['ops']:
                        if op['op'] == 'call' and op['attrs'].get('function') == 'module_header':
                            op['attrs']['function'] = 'module_header_prior'
            elif name == 'module_header':
                expected['name'] = 'module_header_prior'
            elif name == 'protocol_name':
                expected['name'] = 'protocol_name_prior'
            elif name == 'render':
                calls = [o for b in expected['blocks'] for o in b['ops']
                         if o['op'] == 'call' and o['attrs'].get('function') == 'protocol_name']
                calls[1]['attrs']['function'] = 'schema_name'
                tail = next(o for b in expected['blocks'] for o in b['ops']
                            if o['op'] == 'call' and o['attrs'].get('function') == 'part4')
                tail['attrs']['function'] = 'schema_tail'
                tail['args'].append('v56')
            with self.subTest(function=name):
                self.assertEqual(author.function(self.helper, expected['name']), expected)

    def test_complete_original_stage_function_bodies_are_retained(self):
        names = {'f21': 'frame_kind_prior', 'f26': 'check_prior', 'f57': 'manifest_value_prior'}
        for original in author.original('stage')['functions']:
            expected = deepcopy(original)
            expected['name'] = names.get(expected['name'], expected['name'])
            with self.subTest(function=original['name']):
                self.assertEqual(author.function(self.stage, expected['name']), expected)

    def test_hia_executes_the_explicit_role_boundary_and_rejects_core_roles(self):
        for document in (self.helper, self.stage):
            for role in (*range(17), (1 << 64) - 1):
                observed = execute_program(document, 'invalid_extended_role', [role])
                with self.subTest(module=document['module'], role=role):
                    self.assertEqual(observed['status'], 'returned')
                    self.assertIs(observed['result'], role not in (9, 10, 14, 15))

    def test_output_literals_never_call_the_sha_scratch_put(self):
        names = [f'extended_name_{r}' for r, *_ in author.EXTENSIONS]
        for name in (*names, 'page_schema_name', 'version_two', 'version_three'):
            fn = author.function(self.helper, name)
            ops = [o for b in fn['blocks'] for o in b['ops']]
            self.assertTrue(any(o['op'] == 'buffer.store' for o in ops), name)
            self.assertFalse(any(o['op'] == 'call' for o in ops), name)
            self.assertFalse(any(o['op'] == 'buffer.store.u64.le' for o in ops), name)

    def test_new_dag_has_exact_roles_and_eight_publications(self):
        r = recipe()
        decode(r.binary())
        self.assertEqual(len(r.published), 8)
        self.assertEqual([args[:2] for op, _, args, _ in r.nodes if op == 10],
                         [(13, 9), (13, 10), (13, 14), (13, 15)])
        self.assertEqual([args[:3] for op, _, args, _ in r.nodes if op == 5],
                         [(4, 2, 9), (4, 2, 10), (4, 2, 14), (4, 2, 15)])
        self.assertEqual(len(INSTALLED_HELPERS), 8)

    def test_current_worker_keeps_original_thirty_seven_ordinals(self):
        original, current = model(ROOT), current_model(ROOT)
        self.assertEqual(len(original['helpers']), 37)
        self.assertEqual(current['helpers'][:37], original['helpers'])
        self.assertEqual([h['role'] for h in current['helpers'][37:]], [38, 39, 40, 41])
        self.assertEqual([h['name'] for h in current['helpers'][37:]],
                         [kind for _, kind in EXTENDED_INSTALLED_HELPERS])
        for key, value in original.items():
            if key != 'helpers':
                self.assertEqual(current[key], value)

    def test_generic_custody_uses_exact_component_schemas_and_factories(self):
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        selectors = ('HEPTA_HIA_BOUNDED_READ_MANIFEST', 'HEPTA_HIA_JSON_PRETTY_MANIFEST',
                     'HEPTA_HIA_ARTIFACT_PAGE_POLICY_MANIFEST', 'HEPTA_HIA_JSON_WIRE_MANIFEST')
        for (_, candidate), selector in zip(EXTENDED_INSTALLED_HELPERS, selectors, strict=True):
            module_name, name = HELPERS[selector]
            module = importlib.import_module('hepta.' + module_name)
            source, protocol = CANDIDATES[candidate]
            self.assertEqual(module.SCHEMA, image_manifest_schema(candidate, protocol))
            self.assertEqual(module.SOURCE.read_bytes(),
                             (ROOT / 'examples/hia_bootstrap' / (source + '.hepta')).read_bytes())
            self.assertTrue(issubclass(getattr(module, name), NativeHiaJsonImage))

    def test_generated_protocol_sources_and_current_tables_are_exact(self):
        for name, raw in author.generated_files().items():
            self.assertEqual((ROOT / name).read_bytes(), raw)
        from tools.generate_hia_current_worker_manifest import generated_files, TABLE_PATH, MODEL_PATH
        declared_raw = (ROOT / MODEL_PATH).read_bytes()
        declared = json.loads(declared_raw)
        self.assertEqual(declared['schema'], 'hepta.hia.worker-manifest-records.v2')
        native = declared['sources'].get('native_source_authority')
        authority_path = None
        authority_raw = None
        if native is not None:
            from tools.hia_native_worker_source_authority import load_native_source_authority, SCHEMA
            self.assertEqual(native['schema'], SCHEMA)
            authority_path = ROOT / 'docs/HIA_NATIVE_SOURCE_AUTHORITY.json'
            authority_raw = authority_path.read_bytes()
            self.assertEqual(list(load_native_source_authority(authority_path)), native['paths'])
        files, _ = generated_files(authority_path)
        for name, raw in files.items():
            self.assertEqual((ROOT / name).read_bytes(), raw)
        self.assertEqual(files[TABLE_PATH][:8], b'HIAWMT02')
        spec = json.loads(files[MODEL_PATH])
        self.assertEqual(spec['request'], 'HIAWMF02')
        self.assertEqual((ROOT / MODEL_PATH).read_bytes(), declared_raw)
        if authority_path is not None:
            self.assertEqual(authority_path.read_bytes(), authority_raw)


if __name__ == '__main__':
    unittest.main()
