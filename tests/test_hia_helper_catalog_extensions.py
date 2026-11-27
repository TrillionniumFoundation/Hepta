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

ROOT = Path(__file__).resolve().parents[1]


# Independent current-domain decoder; the original 1..15 decoder is unchanged.
def decode_extension(raw):
    if len(raw) < 24:
        raise ValueError('short header')
    magic, count, declared = struct.unpack_from('<8s2Q', raw)
    if magic != b'HIASTD01' or not 1 <= count <= 2048:
        raise ValueError('header')
    at, handles, nodes, publications = 24, set(), [], []
    for _ in range(count):
        if len(raw) - at < 32:
            raise ValueError('short node')
        op, identity, argc, size = struct.unpack_from('<4Q', raw, at)
        at += 32
        if not 1 <= op <= 17 or argc > 132 or argc * 8 + size > len(raw) - at:
            raise ValueError('node extent')
        args = struct.unpack_from('<' + 'Q' * argc, raw, at)
        at += argc * 8
        payload = raw[at:at + size]
        at += size
        if op in (7, 8, 9, 10):
            if identity:
                raise ValueError('effect identity')
        elif not 1 <= identity <= 2048 or identity in handles:
            raise ValueError('view identity')
        references = ()
        if op == 16 and (not 1 <= argc <= 128 or size):
            raise ValueError('concat extent')
        if op == 17 and (argc != 1 or size):
            raise ValueError('length extent')
        if op in (2, 3, 4, 9, 13, 14, 15):
            references = args[:1]
        elif op in (5, 10):
            references = args[4 if op == 5 else 2:]
        elif op == 6:
            references = (args[0], args[2])
        elif op in (7, 8):
            references = tuple(value for value in args if value or op == 8)
        if op in (16, 17):
            references = args
        if any(value not in handles for value in references):
            raise ValueError('forward or absent view')
        if identity:
            handles.add(identity)
        if op == 7:
            name = payload.decode('ascii')
            if not name or '/' in name or name in publications:
                raise ValueError('publication')
            publications.append(name)
        nodes.append((op, identity, args, payload))
    if at != len(raw) or len(publications) != declared:
        raise ValueError('exhaustion')
    return nodes, publications


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

    def test_original_stage_is_byte_exact_and_reused_extension_functions_are_whole(self):
        fixture, digest = author.FIXTURES['stage']
        self.assertEqual((ROOT / author.OUTPUTS['stage']).read_bytes(),
                         (ROOT / fixture).read_bytes())
        originals = {f['name']: f for f in author.original('stage')['functions']}
        self.assertLess(sum(len(f['blocks']) for f in self.stage['functions']), 1536)
        reused = 0
        for current in self.stage['functions']:
            name = current['name']
            if name not in originals or name in ('f21', 'f26', 'f57'):
                continue
            expected = deepcopy(originals[name])
            if name == 'f0':
                calls = [o for b in expected['blocks'] for o in b['ops']
                         if o['op'] == 'call' and o['attrs'].get('function') == 'f1']
                self.assertEqual(len(calls), 1)
                calls[0]['attrs']['function'] = 'reject_plan'
            self.assertEqual(current, expected, name)
            reused += 1
        self.assertGreater(reused, 40)
        expected = deepcopy(originals['f26'])
        expected['name'] = 'check_current'
        author.constant(expected, 'v64', 11, 13)
        author.constant(expected, 'v470', 5, 13)
        author.operation(expected, 'v497').update(
            op='call', args=['v495'], attrs={'function': 'invalid_extended_role'})
        self.assertEqual(author.function(self.stage, 'check_current'), expected)

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
        self.assertEqual(decode_extension(r.binary()), (r.nodes, r.published))
        self.assertEqual(len(r.published), 8)
        frames = [struct.unpack('<8s5Q', raw)[1:] for op, _, _, raw in r.nodes
                  if op == 12 and raw[:8] == b'HIASTF01']
        checks = [struct.unpack('<8s4Q', raw)[1:] for op, _, _, raw in r.nodes
                  if op == 12 and raw[:8] == b'HIASTC01']
        self.assertEqual(frames, [(4, 2, role, 0, 4) for role in (9, 10, 14, 15)])
        self.assertEqual(checks, [(13, role, 4, 0) for role in (9, 10, 14, 15)])
        self.assertFalse(any(op in (5, 10) for op, _, _, _ in r.nodes))
        self.assertEqual(sum(op == 6 for op, _, _, _ in r.nodes), 12)
        self.assertEqual(sum(op == 8 for op, _, _, _ in r.nodes), 6)
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
        files, _ = generated_files()
        for name, raw in files.items():
            self.assertEqual((ROOT / name).read_bytes(), raw)
        self.assertEqual(files[TABLE_PATH][:8], b'HIAWMT02')
        spec = json.loads(files[MODEL_PATH])
        self.assertEqual(spec['request'], 'HIAWMF02')


if __name__ == '__main__':
    unittest.main()
