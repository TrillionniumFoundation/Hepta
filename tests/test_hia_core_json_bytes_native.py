"""Core public-bytes equality through real HIA canonical and nominal images."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_core_json_bytes_native import (
    BAD_ABI, BAD_BUDGET, BAD_BYTES, BAD_JSON, HEADER, MAX_BYTES, MAX_DEPTH,
    MAX_NODES, REQUEST_MAGIC, SOURCE, SCHEMA, CoreJSONBytesProtocolError,
    NativeCoreJSONBytes, canonical_buffer_sizes, installed_core_json_bytes,
)
from hepta.hia_nominal_json_native import (
    SOURCE as NOMINAL_SOURCE, SCHEMA as NOMINAL_SCHEMA,
    installed_nominal_json,
)
from hepta.hia_program import HIAProgramRejected

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_CORE_JSON_BYTES_COLD_REPORT'
EVIDENCE_DIRECTORY = 'HEPTA_HIA_CORE_JSON_BYTES_EVIDENCE'


@contextmanager
def integer_policy(limit):
    original = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(limit)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(original)


def reference(raw, *, digits=4300, wrapper=False, legacy=False):
    """Run the unchanged real public bytes boundary and host packet oracle."""
    from hepta.hia_program import _decode
    from hepta.hia_instruction_policy_native import transport
    selectors = {name: '' for name in (
        'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST', 'HEPTA_HIA_JSON_DECODE_MANIFEST',
        'HEPTA_HIA_JSON_CANONICAL_MANIFEST')}
    with patch.dict(os.environ, selectors), integer_policy(digits):
        try:
            value, canonical = _decode(raw)
        except HIAProgramRejected as exc:
            return (exc.code, str(exc)), None, None
        return None, canonical, transport([value, legacy] if wrapper else value)


def vm_canonical(raw, *, digits=4300):
    """Independent interpreter executes emitted HIA before native compilation."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    output_size, workspace_size = canonical_buffer_sizes(len(raw))
    initial = HEADER.pack(REQUEST_MAGIC, digits, 0, 0, 0, 0, 0, 0)
    body = Body(0)
    owners, views = [], []
    for size, contents in ((len(raw), raw), (output_size, b''), (workspace_size, initial)):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for offset, value in enumerate(contents):
            if value:
                body.effect('buffer.store', [view, body.const('usize', offset), body.const('u8', value)])
        owners.append(owner)
        views.append(view)
    body.effect('loan.end', [views[0]])
    views[0] = body.value('readbuf', 'borrow.read', [owners[0]])
    result = body.value('u32', 'call', views, {'function': 'f0'})
    observed = [body.value('u8', 'buffer.load', [views[1], body.const('usize', i)]) for i in range(240)]
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 core_json_bytes_reference\n'
              'fn observe() -> (u32,' + ','.join(['u8'] * 240) + ') '
              'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
              + body.text() + '  ret(' + ','.join([result, *observed]) + ')\nend\n'
              + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=6000000)
    if result['status'] != 'returned':
        raise AssertionError(result)
    code, *values = result['values']
    return code, bytes(values[:code]) if code <= 240 else None


class CoreJSONBytesSourceTests(unittest.TestCase):
    def test_source_is_reproducible_and_passes_independent_Core_verification(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_core_json_bytes import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        program = assemble_program(SOURCE.read_bytes()).as_dict()
        self.assertEqual(len(program['functions']), 25)
        for function in program['functions']:
            self.assertLessEqual(len(function['params']), 16)
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)

    def test_actual_VM_canonical_order_unicode_and_public_refusals(self):
        for raw in (b'null', b' -0 ', b'{}', b'{"z":{"z":1,"a":0},"a":"\\ud83d\\ude00"}'):
            with self.subTest(raw=raw):
                error, canonical, _ = reference(raw)
                self.assertIsNone(error)
                self.assertEqual(vm_canonical(raw), (len(canonical), canonical))
        for raw, status in ((b'"\\ud800"', BAD_JSON),
                            (b'{"a":0,"a":1}\xff', BAD_JSON),
                            (b'['*65 + b'0' + b']'*65, BAD_BUDGET)):
            with self.subTest(raw=raw):
                self.assertEqual(vm_canonical(raw)[0], status)


class CoreJSONBytesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = b'{"z":-0,"a":"\\u00e9"}'
        canonical = reference(raw)[1]
        assert vm_canonical(raw) == (len(canonical), canonical)
        selected = os.environ.get(EVIDENCE_DIRECTORY)
        cls.temporary = None
        if selected:
            cls.folder = Path(selected).resolve()
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-core-json-bytes-native-')
            cls.folder = Path(cls.temporary.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from tools.build_hia_core_json_bytes import admit_compile_receipt
        cold = os.environ.get(COLD_REPORT)
        cls.receipts = {}
        if cold:
            from tools.build_hia_core_json_bytes import build as build_front
            from tools.build_hia_nominal_json import build as build_nominal
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.front_manifest = build_front(cls.folder / 'cold-front', cls.compiler, Path(cold))
            cls.nominal_manifest = build_nominal(cls.folder / 'cold-nominal', cls.compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD'
            for label, manifest in (('front', cls.front_manifest), ('nominal', cls.nominal_manifest)):
                cls.receipts[label] = json.loads((manifest.parent / 'build.json').read_bytes())['native_compile_receipt']
        else:
            seed, _ = build_seed(cls.folder)
            selfhost = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, selfhost, image_format='seed-shared')
            cls.compiler, _ = compile_stage(cls.folder, 'B2', first, selfhost)
            assert first.read_bytes() == cls.compiler.read_bytes()
            manifests = []
            for label, source, schema in (('front', SOURCE, SCHEMA),
                                          ('nominal', NOMINAL_SOURCE, NOMINAL_SCHEMA)):
                image, receipt = compile_stage(cls.folder, label, cls.compiler, source.read_bytes())
                cls.receipts[label] = receipt
                manifest = cls.folder / (label + '-manifest.json')
                manifest.write_text(json.dumps({'schema': schema,
                    'source_sha256': sha256(source.read_bytes()).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}, sort_keys=True) + '\n')
                manifests.append(manifest)
            cls.front_manifest, cls.nominal_manifest = manifests
            cls.scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.compiler_bytes = cls.compiler.read_bytes()
        cls.snapshots = {cls.compiler: cls.compiler_bytes}
        for label, manifest, source in (
                ('front', cls.front_manifest, SOURCE),
                ('nominal', cls.nominal_manifest, NOMINAL_SOURCE)):
            metadata = json.loads(manifest.read_bytes())
            image_path = manifest.parent / metadata['image_path']
            image = image_path.read_bytes()
            source_bytes = source.read_bytes()
            admit_compile_receipt(cls.receipts[label], compiler_bytes=cls.compiler_bytes,
                                  source_bytes=source_bytes, image_bytes=image)
            for path in (manifest, image_path, source):
                cls.snapshots[path] = path.read_bytes()
        cls.front = installed_core_json_bytes(cls.front_manifest)
        cls.nominal = installed_nominal_json(cls.nominal_manifest)
        cls.observations = []
        cls.pins = {'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
                    'front_image_sha256': cls.front.image_sha256,
                    'nominal_image_sha256': cls.nominal.image_sha256,
                    'files': {str(path): sha256(raw).hexdigest() for path, raw in cls.snapshots.items()}}
        print(json.dumps({'core_json_bytes_fixture_scope': cls.scope, **cls.pins}, sort_keys=True))

    @classmethod
    def tearDownClass(cls):
        for path, raw in cls.snapshots.items():
            assert path.read_bytes() == raw, str(path)
        report = {'schema': 'hepta.hia.core-json-bytes-development-observations.v1',
                  'status': 'OBSERVATIONS_RECORDED_SEE_TEST_RUNNER_RESULT',
                  'scope': cls.scope, 'pins': cls.pins, 'native_compile_receipts': cls.receipts,
                  'observations': cls.observations, 'public_route_replaced': False,
                  'whole_stack_rewritten_in_hia': False}
        (cls.folder / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if cls.temporary:
            cls.temporary.cleanup()

    def assert_public_matches(self, raw, *, digits=4300, wrapper=False, legacy=False):
        error, canonical, packet = reference(raw, digits=digits, wrapper=wrapper, legacy=legacy)
        controls = dict(integer_digit_limit=digits, constructor_wrapper=wrapper, legacy=legacy)
        if error:
            with self.assertRaises(HIAProgramRejected) as caught:
                self.front.decode(raw, self.nominal, **controls)
            actual_error = (caught.exception.code, str(caught.exception))
            self.assertEqual(actual_error, error)
            actual = None
        else:
            actual = self.front.decode(raw, self.nominal, **controls)
            self.assertEqual(actual.canonical.canonical_bytes, canonical)
            self.assertEqual(actual.packet.wire, packet)
            self.assertEqual(actual.canonical.input_sha256, sha256(raw).hexdigest())
            self.assertEqual(actual.canonical.canonical_sha256, sha256(canonical).hexdigest())
            self.assertEqual(actual.packet.input_sha256, actual.canonical.canonical_sha256)
            self.assertEqual(actual.packet.source_nodes, actual.canonical.source_nodes)
            self.assertEqual(actual.canonical.integer_digit_limit, digits)
        self.observations.append({'input_sha256': sha256(raw).hexdigest(), 'input_bytes': len(raw),
            'digits': digits, 'wrapper': wrapper, 'legacy': legacy,
            'public_error': error, 'canonical_sha256': sha256(canonical).hexdigest() if canonical is not None else None,
            'packet_sha256': sha256(packet).hexdigest() if packet is not None else None})
        return actual

    def test_canonical_packet_matches_detached_public_order_and_not_raw_key_order(self):
        raw = b'{"z":{"z":-0,"a":1},"a":"\\u00e9","aa":[]}'
        result = self.assert_public_matches(raw)
        self.assertNotEqual(result.packet.wire, self.nominal.packet(raw))
        self.assertEqual(result.canonical.canonical_bytes, b'{"a":"\xc3\xa9","aa":[],"z":{"a":1,"z":0}}')
        wrapped = self.assert_public_matches(raw, wrapper=True, legacy=True)
        self.assertEqual(len(wrapped.packet.wire), len(result.packet.wire) + 41)
        self.assertEqual(wrapped.packet.source_nodes, result.packet.source_nodes)

    def test_full_scalar_unicode_and_control_escape_domain(self):
        values = [None, False, True, 0, -1, 2**257, -(2**257), '', [], {},
                  {'': [0, {'é😀': '\x00\\"/'}], 'second': False},
                  ''.join(chr(i) for i in range(256)) + '\ue000\U00010000😀']
        for cp in (0, 31, 32, 127, 128, 2047, 2048, 55295, 57344, 65535, 65536, 1114111):
            values.append({chr(cp): chr(cp)})
        for value in values:
            for escaped in (False, True):
                raw = json.dumps(value, ensure_ascii=escaped).encode()
                with self.subTest(value=value, escaped=escaped):
                    self.assert_public_matches(raw)

    def test_random_trees_and_reverse_key_sorting_use_both_native_images(self):
        rng = random.Random(68007420261111)
        def tree(depth=0):
            if depth < 6 and rng.randrange(3):
                if rng.randrange(2):
                    return [tree(depth + 1) for _ in range(rng.randrange(4))]
                names = ['z', 'a', 'é', '😀', '\x00', '', 'aaa', 'ä']
                rng.shuffle(names)
                return {name: tree(depth + 1) for name in names[:rng.randrange(5)]}
            return rng.choice([None, False, True, rng.randrange(-2**160, 2**160), 'é😀\x00\\"'])
        for index in range(256):
            self.assert_public_matches(json.dumps(tree(), ensure_ascii=bool(index & 1)).encode(),
                                       wrapper=bool(index & 2), legacy=bool(index & 2 and index & 4))
        for count in (1, 3, 32, 33, 16384):
            raw = json.dumps({f'k{i:05d}': i for i in reversed(range(count))}).encode()
            self.assert_public_matches(raw)

    def test_actual_public_error_code_message_and_earliest_refusal_order(self):
        invalid = [b'', b' ', b'1.5', b'1e0', b'NaN', b'Infinity', b'+1', b'01', b'-01',
                   b'[1,]', b'{"a":}', b'{}[]', b'"\\ud800"', b'"\\udc00"',
                   b'"\xed\xa0\x80"', b'"\xc0\x80"', b'"\xf4\x90\x80\x80"', b'"\xe2\x82"',
                   b'{"a":0,"\\u0061":1}', '{"é":0,"\\u00e9":1}'.encode(),
                   b'{"a":0,"a":1}\xff', b'{"a":0,"a":1}\x00',
                   b'[' + b'9'*4301 + b',',
                   b'{"n":' + b'9'*4301 + b',"a":0,"a":1}',
                   b'{"n":' + b'9'*4301 + b',"deep":' + b'['*65 + b'0' + b']'*65 + b'}',
                   b'['*65 + b'0' + b']'*65 + b'\xff',
                   b'{"bad":1.5,"deep":' + b'['*65 + b'0' + b']'*65 + b'}',
                   b'{"deep":' + b'['*65 + b'0' + b']'*65 + b',"bad":1.5}']
        for raw in invalid:
            with self.subTest(prefix=raw[:60], size=len(raw)):
                self.assert_public_matches(raw)
        self.assertEqual(reference(b'['*65+b'0'+b']'*65)[0][0], 'E_HIA_LIMIT')
        self.assertEqual(reference(b'['*65+b'0'+b']'*65+b'\xff')[0][0], 'E_HIA_FORMAT')

    def test_Core_depth_64_and_empty_container_root_depth_accounting(self):
        for depth in (0, 1, 63, 64, 65, 128):
            self.assert_public_matches(b'['*depth + b'0' + b']'*depth, wrapper=True)
        self.assert_public_matches(b'['*65 + b']'*65, wrapper=True)
        # The generic raw codec accepts this; the public Core bytes API must not.
        raw = b'['*65 + b'0' + b']'*65
        self.nominal.packet(raw)
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_LIMIT: program exceeds structural budget before JSON allocation'):
            self.front.decode(raw, self.nominal)

    def test_full_node_budget_object_keys_and_packet_output_above_eight_mib(self):
        good = b'[' + b','.join([b'0'] * (MAX_NODES - 1)) + b']'
        self.assert_public_matches(good, wrapper=True)
        bad = b'[' + b','.join([b'0'] * MAX_NODES) + b']'
        self.assert_public_matches(bad)
        self.assert_public_matches(bad + b'\xff')
        raw = b'{' + b','.join(('"key%06d":null' % i).encode() for i in reversed(range(MAX_NODES - 1))) + b'}'
        result = self.assert_public_matches(raw, wrapper=True)
        self.assertEqual(result.canonical.source_nodes, MAX_NODES)
        self.assertGreater(len(result.packet.wire), MAX_BYTES)
        self.assert_public_matches(raw[:-1] + b',"extra":null}')

    def test_full_input_byte_budget_and_refusal_before_UTF8(self):
        raw = b'"' + b'a' * (MAX_BYTES - 2) + b'"'
        self.assert_public_matches(raw)
        self.assert_public_matches(raw + b' ')
        self.assert_public_matches(raw + b'\xff')
        self.assert_public_matches(b'0' + b' ' * (MAX_BYTES - 1))

    def test_integer_policy_is_captured_once_and_negative_zero_is_canonical(self):
        for digits in (640, 4300, 0):
            for length in (639, 640, 641, 4300, 4301, 6000):
                for sign in (b'', b'-'):
                    self.assert_public_matches(sign + b'9' * length, digits=digits)
        self.assert_public_matches(b'[-0,0,-0]', digits=640, wrapper=True)
        with integer_policy(640):
            with self.assertRaises(HIAProgramRejected):
                self.front.decode(b'9'*641, self.nominal)
            self.assertEqual(self.front.decode(b'1', self.nominal).canonical.integer_digit_limit, 640)
        first = self.front.decode(b'1', self.nominal, integer_digit_limit=640)
        second = self.front.decode(b'1', self.nominal, integer_digit_limit=0)
        self.assertEqual(first.packet.wire, second.packet.wire)
        self.assertNotEqual(first.identity_sha256, second.identity_sha256)
        for digits in (True, False, -1, 1, 639, 1 << 64, 640.0):
            with self.subTest(digits=digits), self.assertRaises(ValueError):
                self.front.decode(b'1', self.nominal, integer_digit_limit=digits)

    def test_native_call_path_uses_no_host_payload_parser_graph_sorter_or_packet_walk(self):
        raw = b'{"z":[true,null,-0,"\\ud83d\\ude00"],"a":{"z":0,"a":1}}'
        _, canonical, packet = reference(raw, wrapper=True, legacy=True)
        from hepta import hia_program, hia_json_preflight, hia_json_decode_native
        from hepta import hia_instruction_policy_native, hia_composite_function_tokens
        forbidden = AssertionError('host payload semantics entered the native Core bytes API')
        with (patch('json.loads', side_effect=forbidden), patch('json.dumps', side_effect=forbidden),
              patch.object(json.JSONDecoder, 'decode', side_effect=forbidden),
              patch.object(hia_program, '_decode', side_effect=forbidden),
              patch.object(hia_program, '_structure', side_effect=forbidden),
              patch.object(hia_json_preflight, '_preflight_hia_json_reference', side_effect=forbidden),
              patch.object(hia_json_decode_native, 'materialize', side_effect=forbidden),
              patch.object(hia_instruction_policy_native, 'transport', side_effect=forbidden),
              patch.object(hia_composite_function_tokens, 'detached_packet_index', side_effect=forbidden)):
            result = self.front.decode(raw, self.nominal, constructor_wrapper=True, legacy=True)
            self.assertEqual(result.canonical.canonical_bytes, canonical)
            self.assertEqual(result.packet.wire, packet)

    def test_parallel_calls_keep_private_canonical_and_packet_buffers(self):
        inputs = [json.dumps({'z': i, 'a': ['é😀', bool(i & 1), None]}).encode() for i in range(64)]
        expected = [(reference(raw)[1], reference(raw)[2]) for raw in inputs]
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual = list(pool.map(lambda raw: self.front.decode(raw, self.nominal), inputs))
        self.assertEqual([(v.canonical.canonical_bytes, v.packet.wire) for v in actual], expected)

    def test_raw_ABI_short_buffers_fixed_policy_and_canaries(self):
        raw = b'{"z":[true,-0],"a":0}'
        out_size, work_size = canonical_buffer_sizes(len(raw))
        for changed, out_short, work_short in ((None, 0, 0), ((0, 0), 0, 0),
                ((1, 1), 0, 0), ((2, 1), 0, 0), ((7, 1), 0, 0),
                (None, 1, 0), (None, 0, 1)):
            words = [REQUEST_MAGIC, 4300, 0, 0, 0, 0, 0, 0]
            if changed:
                words[changed[0]] = changed[1]
            source = ctypes.create_string_buffer(b'\xa5'*16 + raw + b'\x5a'*16)
            output = ctypes.create_string_buffer(b'\xa5'*16 + b'\0'*out_size + b'\x5a'*16)
            workspace = ctypes.create_string_buffer(b'\xa5'*16 + b'\0'*work_size + b'\x5a'*16)
            HEADER.pack_into(workspace, 16, *words)
            result = self.front._entry(ctypes.addressof(source)+16, len(raw),
                ctypes.addressof(output)+16, out_size-out_short,
                ctypes.addressof(workspace)+16, work_size-work_short)
            self.assertEqual(source.raw[:16+len(raw)+16], b'\xa5'*16 + raw + b'\x5a'*16)
            for buffer, size in ((output, out_size), (workspace, work_size)):
                self.assertEqual(buffer.raw[:16], b'\xa5'*16)
                self.assertEqual(buffer.raw[16+size:16+size+16], b'\x5a'*16)
            if changed or out_short or work_short:
                self.assertEqual(result, BAD_ABI)
            else:
                expected = reference(raw)[1]
                self.assertEqual(result, len(expected))
                self.assertEqual(output.raw[16:16+result], expected)
        for options in ({'constructor_wrapper': 1}, {'legacy': 0}, {'legacy': True}):
            with self.subTest(options=options), self.assertRaises((TypeError, ValueError)):
                self.front.decode(b'0', self.nominal, **options)
        with self.assertRaises(TypeError):
            self.front.decode(bytearray(b'0'), self.nominal)

    def test_fixed_response_corruption_and_nonzero_upper_return_bits_fail_closed(self):
        fake = object.__new__(NativeCoreJSONBytes)
        fake.image_sha256 = self.front.image_sha256
        for mutate in ('return-high', 'bool', 'digits', 'source-length', 'nodes', 'depth', 'version'):
            def entry(source, size, output, capacity, workspace, work_size):
                result = self.front._entry(source, size, output, capacity, workspace, work_size)
                if mutate == 'return-high':
                    return result | (1 << 32)
                if mutate == 'bool':
                    return True
                offset, value = {'digits': (16, 0), 'source-length': (24, size+1),
                                 'nodes': (32, 0), 'depth': (48, 128), 'version': (56, 2)}[mutate]
                ctypes.memmove(workspace + offset, struct.pack('<Q', value), 8)
                return result
            fake._entry = entry
            with self.subTest(mutate=mutate), self.assertRaises(CoreJSONBytesProtocolError):
                fake.decode(b'0', self.nominal)


if __name__ == '__main__':
    unittest.main()
