"""Independent VM, exact whole-compiler JSON frontend and real semantic refusal."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import copy
from hashlib import sha256
import json
from pathlib import Path
import random
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_core_json_frontend_native import (NativeCoreJsonFrontend, SOURCE,
    SCHEMA, OUTPUT_LIMIT, installed_frontend)
from hepta.hia_json_decode_native import arena_sizes
from tests.test_hia_json_decode_native import vm_arena
from tools.generate_hia_core_json_frontend import document

ROOT = Path(__file__).resolve().parents[1]


def small_program():
    from tests.test_hia_program_tools import scalar_program
    value = scalar_program()
    value['schema'] = 'hepta.hia.program.v8'
    return value


def wire(value, **options):
    return json.dumps(value, ensure_ascii=False, **options).encode()


def vm_render(value):
    raw = wire(value)
    arena, keys = arena_sizes(len(raw), 128, 32)
    return vm_arena(raw, 128, 32, source_path=SOURCE,
                    sizes=(max(OUTPUT_LIMIT, keys), arena))


class CoreJsonFrontendHiaSourceTests(unittest.TestCase):
    def test_generated_HIA_source_is_exact_and_independently_accepted(self):
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']), 40)

    def test_independent_VM_representation_and_refusals_before_B0(self):
        program = small_program()
        expected = render_assembly(program).encode()
        code, output = vm_render(program)
        self.assertEqual(code, len(expected))
        self.assertEqual(output, expected)
        for value in (None, [], {}, {**program, 'exports': []},
                      {**program, 'module': 'selfhost_elf'},
                      {**program, 'module': 'selfhost_exec'},
                      {**program, 'schema': 'hepta.hia.program.v9'},
                      {**program, 'functions': False}):
            with self.subTest(value=value):
                self.assertEqual(vm_render(value)[0], 0xfffffffb)


class CoreJsonFrontendHiaNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent reference and original/modified JSON source exist BEFORE
        # any seed is built; native successors never import their translator.
        program = small_program()
        code, output = vm_render(program)
        assert output == render_assembly(program).encode() and code == len(output)
        from tools.qualify_hia_selfhost import build_seed, compile_stage, mutate_compiler
        cls.original = (ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        cls.modified = mutate_compiler(cls.original)
        cls.compiler_documents = [assemble_program(s).as_dict() for s in (cls.original, cls.modified)]
        cls.compiler_wires = [wire(p, separators=(',', ':')) for p in cls.compiler_documents]
        cls.sample = assemble_program((ROOT/'examples/hia_bootstrap/bytesum.hiaasm').read_bytes()).as_dict()
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-core-json-native-')
        cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        first, _ = compile_stage(cls.folder, 'B1', seed, cls.original, image_format='seed-shared')
        cls.compiler, _ = compile_stage(cls.folder, 'B2', first, cls.original)
        assert first.read_bytes() == cls.compiler.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'frontend', cls.compiler, SOURCE.read_bytes())
        cls.image = image.read_bytes()
        cls.native = NativeCoreJsonFrontend(cls.image, sha256(cls.image).hexdigest())
        cls.manifest = cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA,
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': sha256(cls.image).hexdigest(),
            'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_native_frontend_does_not_parse_or_encode_payload_with_python(self):
        raw = wire(small_program())
        expected = render_assembly(small_program()).encode()
        installed_frontend(str(self.manifest))
        with (patch('json.loads', side_effect=AssertionError('host payload parser')),
              patch('json.dumps', side_effect=AssertionError('host payload encoder')),
              patch.object(json.JSONDecoder, 'decode', side_effect=AssertionError('host JSON decoder'))):
            self.assertEqual(self.native.render(raw), expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_full_original_and_modified_compiler_JSON_have_exact_assembly_and_fixed_points(self):
        from tools.qualify_hia_selfhost import compile_stage
        sources = (self.original, self.modified)
        for i, (raw, expected) in enumerate(zip(self.compiler_wires, sources)):
            rendered = self.native.render(raw)
            self.assertEqual(rendered, expected)
            previous = self.compiler
            images = []
            for generation in range(3):
                previous, receipt = compile_stage(self.folder, f'JSON-{i}-G{generation}', previous, rendered)
                self.assertEqual(receipt['forbidden_compiler_modules_loaded'], [])
                images.append(previous.read_bytes())
            self.assertEqual(images[1], images[2])
            if i == 0:
                self.assertEqual(images[0], self.compiler.read_bytes())
            else:
                self.assertNotEqual(images[1], self.compiler.read_bytes())

    def test_native_program_execution_and_explicit_driver_preserve_real_resource_checks(self):
        from tools.compile_hia_core_json import compile_core
        from tools.qualify_hia_selfhost import invoke, hash_reference
        produced = compile_core(wire(self.sample), self.manifest, self.compiler, self.folder/'driver')
        for i, data in enumerate((b'', b'HIA JSON input', bytes(range(256))*4)):
            result, output = invoke(self.folder, f'JSON-program-{i}', produced, data, capacity=1, workspace_size=1)
            self.assertEqual(result['core_u32'], hash_reference(data))
            self.assertEqual(output, bytes([hash_reference(data)&255]))
            self.assertEqual(result['forbidden_compiler_modules_loaded'], [])
        receipt = json.loads((self.folder/'driver/frontend.receipt.json').read_bytes())
        self.assertFalse(receipt['Python_payload_decoder_or_Core_verifier_used'])
        bad = copy.deepcopy(self.sample)
        bad['functions'][0]['blocks'][0]['ops'][0]['args'] = ['undefined_value']
        # Representation is not a semantic admission: HIA compiler must refuse.
        rendered = self.native.render(wire(bad))
        result, _ = invoke(self.folder, 'JSON-invalid-SSA', self.compiler, rendered)
        self.assertEqual(result['core_u32'], 0xffffffff)
        self.assertTrue(result['output_unchanged'])
        with self.assertRaises(AssertionError):
            compile_core(wire(bad), self.manifest, self.compiler, self.folder/'driver-refused')
        wrong = self.folder/'wrong-compiler.bin'
        wrong.write_bytes(b'not the manifest compiler')
        with self.assertRaises(ValueError):
            compile_core(wire(self.sample), self.manifest, wrong, self.folder/'wrong-driver')

    def test_returned_loans_and_general_names_are_not_dropped_in_representation(self):
        from tools.hia_selfhost_returned_loans import cases
        from tools.hia_selfhost_names import cases as name_cases
        from tools.qualify_hia_selfhost import compile_stage, invoke
        rows = {}
        for row in cases() + name_cases():
            rows.setdefault(row['program'], row)
        for i, row in enumerate(rows.values()):
            program = assemble_program(row['source'].encode()).as_dict()
            expected = render_assembly(program).encode()
            owned = row.get('owned_elf_only', False)
            if owned:
                with self.assertRaises(ValueError):self.native.render(wire(program))
            actual = self.native.render(wire(program), output_profile='elf' if owned else 'flat')
            self.assertEqual(actual, expected, row['program'])
            image, _ = compile_stage(self.folder, f'JSON-case-{i}', self.compiler, actual)
            if owned:
                obj = self.folder/f'JSON-case-{i}.o'
                obj.write_bytes(image.read_bytes())
                image = self.folder/f'JSON-case-{i}.so'
                subprocess.run(['cc','-shared','-Wl,-z,defs','-Wl,-z,noexecstack',str(obj),'-o',str(image)],
                               check=True,capture_output=True)
            result, output = invoke(self.folder, f'JSON-execute-{i}', image,
                bytes.fromhex(row['source_hex']), image_format='linked-selfhost' if owned else 'flat-x86-64',
                capacity=len(bytes.fromhex(row['initial_hex'])), workspace_size=0,
                output_initial=bytes.fromhex(row['initial_hex']))
            self.assertEqual(result['core_u32'], row['expected_result'], row['program'])
            self.assertEqual(output, bytes.fromhex(row['expected_hex']), row['program'])

    def test_field_orders_escaped_fields_unicode_attrs_and_subtree_boundary(self):
        program = self.sample
        expected = render_assembly(program).encode()
        rng = random.Random(11033)
        def shuffled(value):
            if type(value) is dict:
                items = list(value.items()); rng.shuffle(items)
                return {key:shuffled(child) for key, child in items}
            if type(value) is list:return [shuffled(child) for child in value]
            return value
        for i in range(100):
            value = shuffled(program)
            raw = json.dumps(value, ensure_ascii=bool(i&1), indent=1 if i&2 else None).encode()
            self.assertEqual(self.native.render(raw), expected)
        escaped = wire(program).replace(b'"schema"', b'"\\u0073chema"').replace(b'"attrs"', b'"attr\\u0073"')
        self.assertEqual(self.native.render(escaped), expected)
        # The attrs fragment root has siblings in its containing instruction.
        # Neither their names nor their value subtrees may leak into the output.
        value = small_program()
        value['functions'][0]['blocks'][0]['ops'][0]['attrs'] = {'value': {'é😀':'\x00\n', 'a':[None,-0]}}
        rendered = self.native.render(wire(value)).decode()
        self.assertIn('{"value":{"a":[null,0],"é😀":"\\u0000\\n"}}', rendered)
        self.assertNotIn('"out"', rendered)
        self.assertNotIn('"args"', rendered)

    def test_closed_shapes_type_confusion_unknown_fields_and_identifier_injection_refuse(self):
        paths = [(), ('functions',0), ('functions',0,'blocks',0),
                 ('functions',0,'blocks',0,'ops',0),
                 ('functions',0,'blocks',0,'ops',0,'out',0),
                 ('functions',0,'blocks',0,'term')]
        def at(value, path):
            for item in path:value=value[item]
            return value
        for path in paths:
            for change in ('unknown', 'missing', 'null', 'bool', 'array'):
                value = small_program()
                obj = at(value, path)
                if change == 'unknown':obj['unknown'] = 0
                elif change == 'missing':del obj[next(iter(obj))]
                else:
                    replacement = {'null':None,'bool':False,'array':[]}[change]
                    if path:at(value,path[:-1])[path[-1]]=replacement
                    else:value=replacement
                with self.subTest(path=path,change=change), self.assertRaises(ValueError):
                    self.native.render(wire(value))
        for module in ('', 'a\nend\nfn injected', 'é', 'a.b', 'a'*129, 'selfhost_elf', 'selfhost_exec'):
            value = small_program(); value['module'] = module
            with self.subTest(module=module), self.assertRaises(ValueError):self.native.render(wire(value))
        for raw in (b'{"module":0,"module":1}', wire(small_program())+b'null', b'"\\ud800"'):
            with self.assertRaises(ValueError):self.native.render(raw)
        for schema in ('hepta.hia.program.v1','hepta.hia.program.v7','hepta.hia.program.v9'):
            value=small_program();value['schema']=schema
            with self.assertRaises(ValueError):self.native.render(wire(value))
        for field,value in (('exports',[]),('exports',['main']),('unknown',None)):
            program=small_program();program[field]=value
            with self.assertRaises(ValueError):self.native.render(wire(program))
        program=small_program();program['functions'][0]['params']=[{'name':'x','type':{'kind':'tuple'}}]
        with self.assertRaises(ValueError):self.native.render(wire(program))

    def test_depth_node_wire_output_limits_manifest_drift_and_private_concurrency(self):
        raw=wire(small_program())
        for options in ({'max_nodes':1},{'max_depth':0}):
            with self.assertRaises(OverflowError):self.native.render(raw,**options)
        for bad in (b' '*(8388609), 'not bytes'):
            with self.assertRaises(ValueError):self.native.render(bad)
        program=small_program()
        attrs=program['functions'][0]['blocks'][0]['ops'][0]['attrs']
        attrs['value']=''
        base=len(self.native.render(wire(program)))
        attrs['value']='x'*(OUTPUT_LIMIT-base)
        exact=self.native.render(wire(program))
        self.assertEqual(len(exact),OUTPUT_LIMIT)
        attrs['value']+='x'
        with self.assertRaises(OverflowError):self.native.render(wire(program))
        native=installed_frontend(str(self.manifest))
        with tempfile.TemporaryDirectory() as temp:
            drift=Path(temp)/'source';drift.write_bytes(SOURCE.read_bytes()+b'\n')
            with patch('hepta.hia_core_json_frontend_native.SOURCE',drift),self.assertRaises(ValueError):
                installed_frontend(str(self.manifest))
        expected=render_assembly(small_program()).encode()
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(native.render,[raw]*64)),[expected]*64)


if __name__=='__main__':unittest.main()
