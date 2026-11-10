"""Independent VM, actual native canonical-wire execution and Core integration."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_json_canonical_native import (NativeJsonCanonicalizer, SOURCE, SCHEMA,
    installed_canonicalizer, selected_canonical_wire)
from hepta.hia_json_decode_native import arena_sizes, installed_decoder
from tools.generate_hia_json_canonical import document
from tests.test_hia_json_decode_native import vm_arena

ROOT = Path(__file__).resolve().parents[1]


def sizes(wire, nodes, depth):
    arena, keys = arena_sizes(len(wire), nodes, depth)
    return max(keys, len(wire)), arena


def vm_canonical(wire, nodes=32, depth=4):
    return vm_arena(wire, nodes, depth, source_path=SOURCE, sizes=sizes(wire, nodes, depth))


def expected(wire):
    return json.dumps(json.loads(wire), sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


class JsonCanonicalHiaSourceTests(unittest.TestCase):
    def test_generated_source_exact_and_independent_core_accepts_it(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        self.assertEqual(render_assembly(document()), SOURCE.read_text())
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']), 22)

    def test_VM_canonical_wire_before_any_native_seed(self):
        for wire in (b'null', b' -0 ', b'[]', b'{}', b'[0,null]',
                     b'{"z":true,"a":false}', b'{"z":{"z":0,"a":1},"a":[]}',
                     b'"\\ud83d\\ude00\\u0000\\b\\n\\t\\f\\r\\\\\\\""'):
            with self.subTest(wire=wire):
                code, output = vm_canonical(wire)
                self.assertLess(code, 240)
                self.assertEqual(output, expected(wire))
        for wire, nodes, depth, status in (
                (b'{"a":0,"\\u0061":1}', 32, 4, 0xfffffffc),
                (b'[0]', 1, 4, 0xfffffffe), (b'[[0]]', 32, 1, 0xfffffffe),
                (b'"\\ud800"', 32, 4, 0xffffffff), (b'[0,]', 32, 4, 0xffffffff)):
            self.assertEqual(vm_canonical(wire, nodes, depth)[0], status)

    def test_explicit_selection_does_not_change_default_encoder_or_outside_profile(self):
        with patch.dict('os.environ', {'HEPTA_HIA_JSON_CANONICAL_MANIFEST': ''}):
            self.assertIsNone(selected_canonical_wire('[]', max_nodes=16, max_depth=4))
        with patch.dict('os.environ', {'HEPTA_HIA_JSON_CANONICAL_MANIFEST': '/missing/manifest'}):
            self.assertIsNone(selected_canonical_wire('[]', max_nodes=1048577, max_depth=4))
            with self.assertRaises(FileNotFoundError):
                selected_canonical_wire('[]', max_nodes=16, max_depth=4)


class JsonCanonicalHiaNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        code, output = vm_canonical(b'{"z":-0,"a":"\\u00e9"}')
        assert output == b'{"a":"\xc3\xa9","z":0}' and code == len(output)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-json-canonical-native-')
        folder = Path(cls.temporary.name)
        seed, _ = build_seed(folder)
        source = (ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(folder, 'B2', first, source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(folder, 'json-canonical', second, SOURCE.read_bytes())
        cls.image = image.read_bytes()
        cls.native = NativeJsonCanonicalizer(cls.image, sha256(cls.image).hexdigest())
        cls.manifest = folder/'canonical.json'
        def manifest(path, image, source, schema):
            path.write_text(json.dumps({'schema':schema,'source_sha256':sha256(source.read_bytes()).hexdigest(),
                'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
        manifest(cls.manifest, image, SOURCE, SCHEMA)
        decode_source=ROOT/'examples/hia_bootstrap/json_decode.hiaasm'
        decode, _ = compile_stage(folder,'json-decode',second,decode_source.read_bytes())
        cls.decode_manifest=folder/'decode.json'
        manifest(cls.decode_manifest,decode,decode_source,'hepta.hia.json-decode-native.v1')
        preflight_source=ROOT/'examples/hia_bootstrap/json_preflight.hiaasm'
        preflight, _ = compile_stage(folder,'json-preflight',second,preflight_source.read_bytes())
        cls.preflight_manifest=folder/'preflight.json'
        manifest(cls.preflight_manifest,preflight,preflight_source,'hepta.hia.json-preflight-native.v1')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def canonical(self, wire, nodes=262144, depth=128):
        return self.native.canonicalize(wire,max_nodes=nodes,max_depth=depth)

    def test_native_wire_canonicalization_has_no_host_JSON_parser_or_encoder(self):
        installed_canonicalizer(str(self.manifest))
        with (patch('json.loads',side_effect=AssertionError('host parser')),
              patch('json.dumps',side_effect=AssertionError('host encoder')),
              patch.object(json.JSONDecoder,'decode',side_effect=AssertionError('host decoder'))):
            self.assertEqual(self.canonical(b'{"z":-0,"a":"\\u00e9"}'),b'{"a":"\xc3\xa9","z":0}')
            with patch.dict('os.environ',{'HEPTA_HIA_JSON_CANONICAL_MANIFEST':str(self.manifest)}):
                self.assertEqual(selected_canonical_wire('{"z":1,"a":0}',max_nodes=8,max_depth=4),b'{"a":0,"z":1}')
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_existing_Core_input_and_immutable_snapshot_use_HIA_payload_JSON_both_directions(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_tools import scalar_program
        program=scalar_program()
        wire=json.dumps(program,ensure_ascii=False).encode()
        canonical=expected(wire)
        installed_canonicalizer(str(self.manifest))
        installed_decoder(str(self.decode_manifest))
        selected={'HEPTA_HIA_JSON_CANONICAL_MANIFEST':str(self.manifest),
                  'HEPTA_HIA_JSON_DECODE_MANIFEST':str(self.decode_manifest)}
        with patch.dict('os.environ',selected):
            with (patch('json.loads',side_effect=AssertionError('host parser')),
                  patch('json.dumps',side_effect=AssertionError('host encoder')),
                  patch.object(json.JSONDecoder,'decode',side_effect=AssertionError('host decoder'))):
                checked=verify_program(wire)
                self.assertEqual(checked.canonical_bytes,canonical)
                self.assertEqual(checked.as_dict(),program)
                self.assertEqual(verify_program(checked).canonical_bytes,canonical)
        # Structural/type/effect checking is still real, not a JSON-admission bypass.
        program['functions'][0]['blocks'][0]['term']['values']=['not_defined']
        with patch.dict('os.environ',selected), self.assertRaises(ValueError):
            verify_program(json.dumps(program).encode())

    def test_order_prefix_unicode_widths_control_escaping_and_nested_order(self):
        keys=['','a','aa','a\x00','aé','é','\ue000','\U00010000','😀','\U0010ffff','z','\x00','\x1f']
        values=[{key:[i,{k:i for k in reversed(keys[:5])}] for i,key in enumerate(reversed(keys))},
                ''.join(chr(i) for i in range(256))+'\ue000\U00010000😀\\"/']
        for value in values:
            for escaped in (False,True):
                wire=json.dumps(value,ensure_ascii=escaped).encode()
                self.assertEqual(self.canonical(wire),expected(wire))
        for wire in (b'-0',b' -0 \r\n',b'0',b'-1',b'123456789012345678901234567890'):
            self.assertEqual(self.canonical(wire),expected(wire))

    def test_two_thousand_random_trees_and_reverse_key_merge_sort(self):
        rng=random.Random(10007)
        def tree(depth=0):
            if depth<6 and rng.randrange(3):
                if rng.randrange(2):return [tree(depth+1) for _ in range(rng.randrange(4))]
                names=['a','z','é','😀','\x00','ä','aaa','']
                rng.shuffle(names)
                return {name:tree(depth+1) for name in names[:rng.randrange(4)]}
            return rng.choice([None,False,True,rng.randrange(-2**128,2**128),'xé😀\n\x00\\"'])
        for i in range(2000):
            wire=json.dumps(tree(),ensure_ascii=bool(i&1)).encode()
            self.assertEqual(self.canonical(wire),expected(wire))
        for count in (1,2,3,7,8,9,31,32,33,16384):
            wire=json.dumps({f'key{i:05d}':i for i in reversed(range(count))}).encode()
            self.assertEqual(self.canonical(wire),expected(wire))

    def test_budgets_large_wire_large_tree_and_lexical_integer_boundary(self):
        for depth in (0,1,8,64,128):
            good=b'['*depth+b'0'+b']'*depth
            self.assertEqual(self.canonical(good,depth=depth),good)
            empty=b'['*(depth+1)+b']'*(depth+1)
            self.assertEqual(self.canonical(empty,depth=depth),empty)
            with self.assertRaises(OverflowError):self.canonical(b'['*(depth+1)+b'0'+b']'*(depth+1),depth=depth)
        for count in (1,2,1024,1048576):
            good=b'0' if count==1 else b'['+b','.join([b'0']*(count-1))+b']'
            self.assertEqual(self.canonical(good,nodes=count),good)
            with self.assertRaises(OverflowError):self.canonical(b'['+b','.join([b'0']*count)+b']',nodes=count)
        wire=b'"'+b'a'*((8<<20)-2)+b'"'
        self.assertEqual(self.canonical(wire),wire)
        with self.assertRaises(ValueError):self.canonical(wire+b' ')
        # This is lexical integer canonicalization, NOT host big-int construction.
        huge=b'-'+b'9'*10000
        with patch('json.loads',side_effect=AssertionError('host integer parser')):
            self.assertEqual(self.canonical(huge),huge)
        from hepta.hia_program_tools import decode_json
        import sys
        previous=sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(4300)
            with patch.dict('os.environ',{'HEPTA_HIA_JSON_DECODE_MANIFEST':str(self.decode_manifest)}):
                # The host's explicit conversion policy still applies to this API.
                with self.assertRaises(ValueError):decode_json(huge)
        finally:
            sys.set_int_max_str_digits(previous)

    def test_invalid_input_and_two_thousand_mutation_refusals_preserve_preflight_order(self):
        from tests.test_hia_json_preflight_native import reference
        rng=random.Random(32203)
        original=b'{"a":[0,true,false,null,"\\ud83d\\ude00"],"b":{"x":"xyz"}}'
        wires=[bytes([b]) for b in range(256)]+[b'"'+bytes([b])+b'"' for b in range(256)]
        wires.extend([b'{"a":0,"\\u0061":1}',b'{"/":0,"\\/":1}',b'"\\ud800"',b'[0,]',b'01',b'1e2'])
        for _ in range(2000):
            wire=bytearray(original)
            for _ in range(rng.randrange(1,4)):wire[rng.randrange(len(wire))]=rng.randrange(256)
            wires.append(bytes(wire))
        for wire in wires:
            if reference(wire):
                with self.assertRaises(ValueError):self.canonical(wire)
            else:self.assertEqual(self.canonical(wire),expected(wire))

    def test_source_drift_after_warm_cache_duplicate_manifests_and_bad_buffers(self):
        from hepta import hia_json_decode_native as decode
        from hepta import hia_json_preflight_native as preflight
        from hepta import hia_json_canonical_native as canonical
        for module,select,manifest in ((canonical,installed_canonicalizer,self.manifest),
                (decode,installed_decoder,self.decode_manifest),
                (preflight,preflight.installed_preflight,self.preflight_manifest)):
            original=select(str(manifest))
            bad=manifest.with_name(module.__name__.split('.')[-1]+'-drift.hiaasm')
            bad.write_bytes(b'not-the-source')
            with patch.object(module,'SOURCE',bad),self.assertRaisesRegex(ValueError,'source identity'):
                select(str(manifest))
            self.assertIs(select(str(manifest)),original)
        value=json.loads(self.manifest.read_text())
        bad=self.manifest.with_name('duplicate.json')
        raw=json.dumps(value)
        bad.write_text('{"schema":"wrong",'+raw[1:])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            installed_canonicalizer(str(bad))
        with self.assertRaises(ValueError):NativeJsonCanonicalizer(self.image,'0'*64)
        raw=ctypes.create_string_buffer(256)
        for extent in (0,127):
            self.assertEqual(self.native._entry(raw,0,raw,extent,raw,128),0xfffffffd)

    def test_concurrent_private_sorting_and_output_buffers(self):
        wires=[json.dumps({'z':i,'a':[{'é':i},{'é':-i}]}).encode() for i in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.canonical,wires)),[expected(w) for w in wires])
