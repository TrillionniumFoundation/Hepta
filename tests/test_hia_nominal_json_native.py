"""Full raw-domain packet equality, actual HIA VM/native, and custody controls.

The independent reference exists only in this test module. The new component
has a fixed-status API; these tests do not claim old public message/span parity.
"""
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

from hepta.hia_nominal_json_native import (
    BAD_ABI, BAD_BUDGET, BAD_BYTES, BAD_DUPLICATE, BAD_INTEGER, BAD_JSON,
    HEADER, MAX_BYTES, MAX_DEPTH, MAX_NODES, REPLY_MAGIC, REQUEST_MAGIC,
    NativeNominalJSON, NominalJSONProtocolError, NominalJSONRejected,
    SCHEMA, SOURCE, installed_nominal_json, packet_buffer_sizes,
)
from tools.build_hia_nominal_json import admit_compile_receipt

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_NOMINAL_JSON_COLD_REPORT'
EVIDENCE_DIRECTORY = 'HEPTA_HIA_NOMINAL_JSON_EVIDENCE'


@contextmanager
def integer_policy(limit):
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(limit)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


def reference(raw, *, digits=4300, wrapper=False, legacy=False):
    """The retained public raw preflight and original host transport oracle."""
    from hepta.hia_json_preflight import _preflight_hia_json_reference
    from hepta.hia_instruction_policy_native import transport
    if len(raw) > MAX_BYTES:
        return BAD_BYTES, None, None
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        return BAD_JSON, None, None
    try:
        _preflight_hia_json_reference(text, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)
    except OverflowError:
        return BAD_BUDGET, None, None
    except ValueError as exc:
        status = BAD_DUPLICATE if str(exc) == 'HIA JSON preflight: duplicate decoded object key' else BAD_JSON
        return status, None, None
    with integer_policy(digits):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            raise AssertionError('independent HIA preflight accepted invalid JSON')
        except ValueError:
            return BAD_INTEGER, None, None
        pending, count = [value], 0
        while pending:
            item = pending.pop()
            count += 1
            if type(item) is list:
                pending.extend(item)
            elif type(item) is dict:
                pending.extend(item.values())
        return 0, transport([value, legacy] if wrapper else value), count


def vm_packet(raw, *, digits=4300, wrapper=False, legacy=False):
    """Execute emitted HIA with an independent interpreter before native B0."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    output_size, workspace_size = packet_buffer_sizes(len(raw))
    initial = HEADER.pack(REQUEST_MAGIC, digits, int(wrapper), int(legacy), 0, 0, 0, 0)
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
    source = ('hia-asm.v1 hepta.hia.program.v8 nominal_packet_reference\n'
              'fn observe() -> (u32,' + ','.join(['u8'] * 240) + ') '
              'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
              + body.text() + '  ret(' + ','.join([result, *observed]) + ')\nend\n'
              + SOURCE.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=4000000)
    if result['status'] != 'returned':
        raise AssertionError(result)
    code, *values = result['values']
    return code, bytes(values[:code]) if code <= 240 else None


class NominalJSONSourceTests(unittest.TestCase):
    def test_source_is_generated_and_independently_verified(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_nominal_json import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        program = assemble_program(SOURCE.read_bytes()).as_dict()
        self.assertEqual(len(program['functions']), 22)
        for function in program['functions']:
            self.assertLessEqual(len(function['params']), 16)
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)

    def test_real_vm_scalar_unicode_object_wrapper_and_refusal_order(self):
        for raw in (b'null', b'false', b'-0', b'[]', b'{}', b'{"x":[true,-12]}',
                    b'"\\ud83d\\ude00"'):
            for wrapper in (False, True):
                with self.subTest(raw=raw, wrapper=wrapper):
                    status, expected, _ = reference(raw, wrapper=wrapper, legacy=wrapper)
                    self.assertEqual(status, 0)
                    code, actual = vm_packet(raw, wrapper=wrapper, legacy=wrapper)
                    self.assertEqual(code, len(expected))
                    self.assertEqual(actual, expected)
        for raw in (b'{"a":0,"\\u0061":1}', b'"\\ud800"', b'1.5',
                    b'{"a":0,"a":1}\xff', b'{"a":0,"a":1}\x00'):
            with self.subTest(raw=raw):
                self.assertEqual(vm_packet(raw)[0], reference(raw)[0])


class NominalJSONNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        status, expected, _ = reference(b'{"x":true}', wrapper=True)
        assert status == 0 and vm_packet(b'{"x":true}', wrapper=True) == (len(expected), expected)
        selected = os.environ.get(EVIDENCE_DIRECTORY)
        cls.temporary = None
        if selected:
            cls.folder = Path(selected).resolve()
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-nominal-json-native-')
            cls.folder = Path(cls.temporary.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cold = os.environ.get(COLD_REPORT)
        if cold:
            from tools.build_hia_nominal_json import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'cold-built', cls.compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD'
            built = json.loads((cls.manifest.parent / 'build.json').read_bytes())
            cls.receipt = built['native_compile_receipt']
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            cls.compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == cls.compiler.read_bytes()
            image, cls.receipt = compile_stage(cls.folder, 'nominal-json', cls.compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps({'schema': SCHEMA,
                'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}, sort_keys=True) + '\n')
            cls.scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        manifest = json.loads(cls.manifest.read_bytes())
        cls.image_path = cls.manifest.parent / manifest['image_path']
        cls.image = cls.image_path.read_bytes()
        cls.compiler_bytes = cls.compiler.read_bytes()
        cls.source_bytes = SOURCE.read_bytes()
        admit_compile_receipt(cls.receipt, compiler_bytes=cls.compiler_bytes,
                              source_bytes=cls.source_bytes, image_bytes=cls.image)
        cls.native = installed_nominal_json(cls.manifest)
        cls.observations = []
        cls.pins = {'source_sha256': sha256(cls.source_bytes).hexdigest(),
                    'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
                    'image_sha256': sha256(cls.image).hexdigest(),
                    'manifest_sha256': sha256(cls.manifest.read_bytes()).hexdigest(),
                    'source_files': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                        'tools/generate_hia_nominal_json.py', 'tools/build_hia_nominal_json.py',
                        'hepta/hia_nominal_json_native.py', 'tests/test_hia_nominal_json_native.py',
                        'tools/generate_hia_json_decode.py', 'tools/generate_hia_json_preflight.py',
                        'hepta/hia_json_preflight.py', 'hepta/hia_instruction_policy_native.py')}}
        print(json.dumps({'nominal_json_fixture_scope': cls.scope, **cls.pins}, sort_keys=True))

    @classmethod
    def tearDownClass(cls):
        assert SOURCE.read_bytes() == cls.source_bytes
        assert cls.compiler.read_bytes() == cls.compiler_bytes
        assert cls.image_path.read_bytes() == cls.image
        report = {'schema': 'hepta.hia.nominal-json-development-observations.v1',
                  'status': 'OBSERVATIONS_RECORDED_SEE_TEST_RUNNER_RESULT', 'scope': cls.scope,
                  'pins': cls.pins, 'native_compile_receipt': cls.receipt,
                  'observations': cls.observations, 'whole_stack_rewritten_in_hia': False}
        (cls.folder / 'observations.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        if cls.temporary:
            cls.temporary.cleanup()

    def assert_matches(self, raw, *, digits=4300, wrapper=False, legacy=False):
        status, expected, count = reference(raw, digits=digits, wrapper=wrapper, legacy=legacy)
        controls = dict(integer_digit_limit=digits, constructor_wrapper=wrapper, legacy=legacy)
        if status:
            with self.assertRaises(NominalJSONRejected) as caught:
                self.native.encode(raw, **controls)
            self.assertEqual(caught.exception.status, status)
            result_sha = None
        else:
            result = self.native.encode(raw, **controls)
            self.assertEqual(result.wire, expected)
            self.assertEqual(result.source_nodes, count)
            self.assertEqual(result.input_sha256, sha256(raw).hexdigest())
            self.assertEqual(result.packet_sha256, sha256(expected).hexdigest())
            self.assertEqual(result.integer_digit_limit, digits)
            self.assertEqual(result.constructor_wrapper, wrapper)
            self.assertEqual(result.legacy, legacy)
            result_sha = result.packet_sha256
        self.observations.append({'input_sha256': sha256(raw).hexdigest(), 'input_bytes': len(raw),
            'digits': digits, 'wrapper': wrapper, 'legacy': legacy, 'status': status,
            'packet_sha256': result_sha, 'source_nodes': count})
        return expected

    def test_full_scalar_unicode_and_container_domain(self):
        values = [None, False, True, 0, -1, 2**257, -(2**257), '', [], {},
                  {'': [0, {'é😀': '\x00\\"/'}], 'second': False}]
        for cp in (0, 31, 32, 127, 128, 2047, 2048, 55295, 57344, 65535, 65536, 1114111):
            values.extend((chr(cp), {chr(cp): chr(cp)}))
        for value in values:
            for escaped in (False, True):
                raw = json.dumps(value, ensure_ascii=escaped).encode()
                for wrapper in (False, True):
                    with self.subTest(value=value, escaped=escaped, wrapper=wrapper):
                        self.assert_matches(raw, wrapper=wrapper, legacy=wrapper)
        self.assert_matches(b' [ -0 , 0 , -123 , 123 ] \t\r\n')

    def test_two_thousand_random_trees_complete_packet_equality(self):
        rng = random.Random(742020261111)
        def tree(depth=0):
            if depth < 6 and rng.randrange(3):
                if rng.randrange(2):
                    return [tree(depth + 1) for _ in range(rng.randrange(4))]
                return {f'k{i}é😀': tree(depth + 1) for i in range(rng.randrange(4))}
            return rng.choice([None, True, False, rng.randrange(-2**160, 2**160), 'é😀\x00\\"'])
        for index in range(2000):
            raw = json.dumps(tree(), ensure_ascii=bool(index & 1)).encode()
            self.assert_matches(raw, wrapper=bool(index & 2), legacy=bool(index & 2 and index & 4))

    def test_invalid_domain_and_earliest_refusal_precedence(self):
        invalid = [b'', b' ', b'1.0', b'1e0', b'NaN', b'Infinity', b'+1', b'01', b'-01',
                   b'[1,]', b'{"a":}', b'{}[]', b'"\\ud800"', b'"\\udc00"',
                   b'"\\ud800\\ud800"', b'"\xed\xa0\x80"', b'"\xc0\x80"',
                   b'"\xf4\x90\x80\x80"', b'"\xf0\x80\x80\x80"', b'"\xe2\x82"',
                   b'{"a":0,"\\u0061":1}', '{"é":0,"\\u00e9":1}'.encode(),
                   b'{"a":0,"a":1}\xff', b'{"a":0,"a":1}\x00',
                   b'[' + b'9'*4301 + b',',
                   b'{"n":' + b'9'*4301 + b',"a":0,"a":1}',
                   b'['*129 + b'0' + b']'*129 + b'\xff']
        for raw in invalid:
            with self.subTest(prefix=raw[:80], size=len(raw)):
                self.assert_matches(raw)
        self.assertEqual(reference(b'{"a":0,"a":1}\xff')[0], BAD_JSON)
        self.assertEqual(reference(b'{"a":0,"a":1}\x00')[0], BAD_DUPLICATE)
        self.assertEqual(reference(b'{"n":' + b'9'*4301 + b',"a":0,"a":1}')[0], BAD_DUPLICATE)

    def test_integer_limits_negative_zero_and_policy_identity(self):
        for digits in (640, 4300, 0):
            for length in (639, 640, 641, 4300, 4301, 6000):
                for sign in (b'', b'-'):
                    self.assert_matches(sign + b'9' * length, digits=digits)
        self.assert_matches(b'[-0,0,-0]', digits=640, wrapper=True)
        first = self.native.encode(b'1', integer_digit_limit=640)
        second = self.native.encode(b'1', integer_digit_limit=0)
        self.assertEqual(first.wire, second.wire)
        self.assertNotEqual(first.policy_sha256, second.policy_sha256)
        self.assertNotEqual(first.identity_sha256, second.identity_sha256)
        with integer_policy(640):
            self.assertEqual(self.native.encode(b'1').integer_digit_limit, 640)
            with self.assertRaises(NominalJSONRejected) as caught:
                self.native.packet(b'9'*641)
            self.assertEqual(caught.exception.status, BAD_INTEGER)
        for digits in (True, False, -1, 1, 639, 1 << 64, 640.0):
            with self.subTest(digits=digits), self.assertRaises(ValueError):
                self.native.encode(b'1', integer_digit_limit=digits)

    def test_depth_and_constructor_wrapper_accounting(self):
        from hepta.hia_composite_function_tokens import detached_packet_index
        for depth in (0, 1, 64, 128, 129):
            raw = b'[' * depth + b'0' + b']' * depth
            self.assert_matches(raw)
            self.assert_matches(raw, wrapper=True)
        # Empty containers at depth 128 consume a value but no child at 129.
        self.assert_matches(b'['*129 + b']'*129, wrapper=True)
        raw = b'['*128 + b'0' + b']'*128
        plain = self.native.packet(raw)
        wrapped = self.native.constructor_packet(raw, legacy=True)
        value, index = detached_packet_index(plain)
        outer, wrapped_index = detached_packet_index(wrapped)
        self.assertEqual(outer, [value, True])
        self.assertEqual(len(wrapped), len(plain) + 41)
        self.assertEqual(len(wrapped_index), len(index) + 2)
        for offset in index:
            self.assertIn(offset + 24, wrapped_index)

    def test_full_node_budget_keys_and_more_than_eight_mib_output(self):
        good = b'[' + b','.join([b'0'] * (MAX_NODES - 1)) + b']'
        self.assert_matches(good, wrapper=True)
        bad = b'[' + b','.join([b'0'] * MAX_NODES) + b']'
        self.assert_matches(bad)
        self.assert_matches(bad[:-1] + b',"\xff"]')
        # Keys are not structural values; this has exactly MAX_NODES values.
        raw = b'{' + b','.join(('"key%06d":null' % i).encode() for i in range(MAX_NODES - 1)) + b'}'
        packet = self.assert_matches(raw, wrapper=True)
        self.assertGreater(len(packet), MAX_BYTES)
        self.assertLess(len(packet), 64 << 20)
        self.assert_matches(raw[:-1] + b',"extra":null}')

    def test_full_byte_budget_and_size_refusal_before_utf8(self):
        raw = b'"' + b'a' * (MAX_BYTES - 2) + b'"'
        self.assert_matches(raw)
        self.assert_matches(raw, wrapper=True, legacy=True)
        self.assert_matches(raw + b' ')
        self.assert_matches(raw + b'\xff')
        self.assert_matches(b'0' + b' ' * (MAX_BYTES - 1))

    def test_native_execution_without_python_payload_parsers_or_walkers(self):
        raw = b'{"a":[true,null,-0,"\\ud83d\\ude00"],"b":{}}'
        expected = reference(raw, wrapper=True, legacy=True)[1]
        from hepta import hia_json_preflight, hia_json_decode_native, hia_instruction_policy_native
        from hepta import hia_composite_function_tokens
        forbidden = AssertionError('Python payload semantics entered the native byte codec')
        with (patch('json.loads', side_effect=forbidden), patch('json.dumps', side_effect=forbidden),
              patch.object(json.JSONDecoder, 'decode', side_effect=forbidden),
              patch.object(hia_json_preflight, '_preflight_hia_json_reference', side_effect=forbidden),
              patch.object(hia_json_decode_native, 'materialize', side_effect=forbidden),
              patch.object(hia_instruction_policy_native, 'transport', side_effect=forbidden),
              patch.object(hia_composite_function_tokens, 'detached_packet_index', side_effect=forbidden)):
            self.assertEqual(self.native.constructor_packet(raw, legacy=True), expected)

    def test_private_buffers_and_parallel_calls(self):
        inputs = [json.dumps({'i': i, 's': 'é😀', 'v': [bool(i & 1), None]}).encode() for i in range(128)]
        expected = [reference(raw, wrapper=True)[1] for raw in inputs]
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual = list(pool.map(self.native.constructor_packet, inputs))
        self.assertEqual(actual, expected)

    def test_raw_abi_control_validation_short_buffers_and_canaries(self):
        raw = b'{"x":[true,-0]}'
        out_size, work_size = packet_buffer_sizes(len(raw))
        for changed, out_short, work_short in ((None, 0, 0), ((0, 0), 0, 0),
                ((1, 1), 0, 0), ((2, 2), 0, 0), ((3, 1), 0, 0),
                ((4, 1), 0, 0), ((7, 1), 0, 0), (None, 1, 0), (None, 0, 1)):
            words = [REQUEST_MAGIC, 4300, 0, 0, 0, 0, 0, 0]
            if changed:
                words[changed[0]] = changed[1]
            source = ctypes.create_string_buffer(b'\xa5'*16 + raw + b'\x5a'*16)
            output = ctypes.create_string_buffer(b'\xa5'*16 + b'\0'*out_size + b'\x5a'*16)
            workspace = ctypes.create_string_buffer(b'\xa5'*16 + b'\0'*work_size + b'\x5a'*16)
            HEADER.pack_into(workspace, 16, *words)
            result = self.native._entry(ctypes.addressof(source)+16, len(raw),
                ctypes.addressof(output)+16, out_size-out_short,
                ctypes.addressof(workspace)+16, work_size-work_short)
            self.assertEqual(source.raw[:16+len(raw)+16], b'\xa5'*16 + raw + b'\x5a'*16)
            self.assertEqual(output.raw[:16], b'\xa5'*16)
            self.assertEqual(output.raw[16+out_size:16+out_size+16], b'\x5a'*16)
            self.assertEqual(workspace.raw[:16], b'\xa5'*16)
            self.assertEqual(workspace.raw[16+work_size:16+work_size+16], b'\x5a'*16)
            if changed or out_short or work_short:
                self.assertEqual(result, BAD_ABI)
            else:
                expected = reference(raw)[1]
                self.assertEqual(result, len(expected))
                self.assertEqual(output.raw[16:16+result], expected)
        for options in ({'constructor_wrapper': 1}, {'legacy': 0}, {'legacy': True}):
            with self.subTest(options=options), self.assertRaises((TypeError, ValueError)):
                self.native.encode(b'0', **options)
        with self.assertRaises(TypeError):
            self.native.encode(bytearray(b'0'))

    def test_fixed_response_mutation_and_nonzero_upper_return_bits_fail_closed(self):
        fake = object.__new__(NativeNominalJSON)
        fake.image_sha256 = self.native.image_sha256
        for mutate in ('return-high', 'digits', 'wrapper', 'source-length', 'nodes', 'version'):
            def entry(source, size, output, capacity, workspace, work_size):
                result = self.native._entry(source, size, output, capacity, workspace, work_size)
                if mutate == 'return-high':
                    return result | (1 << 32)
                offset, value = {'digits': (16, 0), 'wrapper': (24, 1),
                    'source-length': (40, size+1), 'nodes': (48, 0), 'version': (56, 2)}[mutate]
                ctypes.memmove(workspace + offset, struct.pack('<Q', value), 8)
                return result
            fake._entry = entry
            with self.subTest(mutate=mutate), self.assertRaises(NominalJSONProtocolError):
                fake.packet(b'0', integer_digit_limit=4300)

    def test_loader_rebinds_actual_source_and_receipt_custody_rejects_mutations(self):
        from hepta import hia_nominal_json_native
        self.assertIs(installed_nominal_json(self.manifest), self.native)
        different = self.folder / 'changed-source.hiaasm'
        different.write_bytes(self.source_bytes + b'\n')
        with patch.object(hia_nominal_json_native, 'SOURCE', different), self.assertRaisesRegex(ValueError, 'source identity'):
            installed_nominal_json(self.manifest)
        for key, replacement in (
                ('artifact_sha256', '0'*64), ('image_sha256', '0'*64),
                ('input_sha256', '0'*64), ('source_sha256', '0'*64),
                ('produced_sha256', '0'*64), ('input_bytes', True),
                ('produced_bytes', True), ('result_u64', True), ('core_u32', True),
                ('abi_status', False), ('source_unchanged', 1),
                ('forbidden_compiler_modules_loaded', ()),
                ('forbidden_compiler_modules_loaded', ['hepta.hia_program']),
                ('return_encoding', 'packed-ABI-status-and-u32')):
            receipt = {**self.receipt, key: replacement}
            with self.subTest(key=key, replacement=replacement), self.assertRaises(ValueError):
                admit_compile_receipt(receipt, compiler_bytes=self.compiler_bytes,
                    source_bytes=self.source_bytes, image_bytes=self.image)
        # This distinguishes valid zero from bool False in a known scalar slot.
        self.assertEqual(self.receipt['abi_status'], 0)
        self.assertIs(type(self.receipt['abi_status']), int)


if __name__ == '__main__':
    unittest.main()
