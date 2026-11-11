"""Independent references and actual HIA-compiled JSON admission candidate."""
from __future__ import annotations
import ctypes
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_json_preflight import _preflight_hia_json_reference as preflight_hia_json
from hepta.hia_json_preflight_native import NativeJsonPreflight, scratch_sizes, installed_preflight, SYNTAX_REASONS
from tools.generate_hia_json_preflight import document

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/json_preflight.hiaasm'


def reference(wire, nodes=262144, depth=128):
    try:
        preflight_hia_json(wire.decode('utf-8'), max_nodes=nodes, max_depth=depth)
    except OverflowError:
        return 2
    except ValueError as exc:
        return 4 if 'duplicate' in str(exc) else 1
    return 0


def vm_reference(wire, nodes=32, depth=8, *, diagnostic=False):
    # Real owners and loans in a scalar VM wrapper, never fabricated host views.
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body = Body(0)
    keys, state_size = scratch_sizes(len(wire), nodes, depth)
    state = bytearray(state_size)
    struct.pack_into('<QQ', state, 48, nodes, depth)
    owners, views = [], []
    for size, initial in ((len(wire), wire), (keys, b''), (state_size, state)):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for index, value in enumerate(initial):
            if value:
                body.effect('buffer.store', [view, body.const('usize', index), body.const('u8', value)])
        owners.append(owner)
        views.append(view)
    body.effect('loan.end', [views[0]])
    views[0] = body.value('readbuf', 'borrow.read', [owners[0]])
    result = body.value('u32', 'call', views, {'function': 'f0'})
    reason = body.value('u64', 'call', [views[2], body.const('u64', 32)], {'function': 'f8'})
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 json_reference\n'
              'fn reference_entry() -> (u32,u64) effects(alloc,read,write,trap) entry(b0)\n'
              'block b0()\n' + body.text() + '  ret(' + result + ',' + reason + ')\nend\n'
              + SOURCE.read_text().split('\n', 1)[1])
    actual = execute_program(assemble_program(source), 'reference_entry', [], max_steps=1000000)
    if actual['status'] != 'returned':
        raise AssertionError(actual)
    return tuple(actual['values']) if diagnostic else actual['values'][0]


def outcome(call):
    try:
        call()
    except (ValueError, OverflowError) as exc:
        return type(exc), str(exc)
    return None


class JsonPreflightHiaSourceTests(unittest.TestCase):
    def test_checked_in_source_is_exact_ordinary_core_authoring(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        checked = assemble_program(SOURCE.read_bytes())
        self.assertEqual(len(checked.as_dict()['functions']), 10)

    def test_build_refuses_incomplete_or_mismatched_cold_receipts_before_output(self):
        from tools.build_hia_json_preflight import build
        with tempfile.TemporaryDirectory(prefix='hia-json-build-refusal-') as temporary:
            directory = Path(temporary)
            image = directory / 'image.bin'
            image.write_bytes(b'not-an-authorized-native-image')
            report = directory / 'cold.json'
            for value in ([], {}, {'status': 'COLD_SELFHOST_REPLAY_PASS', 'checks': {'claimed': True}},
                          {'status': 'COLD_SELFHOST_REPLAY_PASS', 'checks': []}):
                report.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    build(directory / 'never-created', image, report)
                self.assertFalse((directory / 'never-created').exists())

    def test_independent_vm_and_old_python_agree_before_any_native_seed(self):
        for wire in (b'{}', b'[0,null]', b'{"a":1,"\\u0061":2}',
                     b'"\\ud83d\\ude00"', b'"\\ud800"', b'[1,]', b'[[0]]'):
            with self.subTest(wire=wire):
                self.assertEqual(vm_reference(wire), reference(wire, 32, 8))
        self.assertEqual(vm_reference(b'[[0]]', depth=1), 2)
        self.assertEqual(vm_reference(b'[0,0]', nodes=2), 2)

    def test_vm_selects_exact_diagnostics_and_keeps_budget_order(self):
        for wire, reason in ((b'', 9), (b'"ordinary', 8), (b'"\\', 3),
                             (b'"\\u00G0"', 5), (b'"\\ud800"', 6),
                             (b'"\\udc00"', 7), (b'- 1', 10),
                             (b'[0 0]', 14), (b'{0:1}', 16),
                             (b'{"x" 0}', 17), (b'{"x":0 0}', 18),
                             (b'0 0', 12)):
            with self.subTest(wire=wire):
                self.assertEqual(vm_reference(wire, diagnostic=True), (1, reason))
                self.assertEqual(outcome(lambda: preflight_hia_json(
                    wire.decode(), max_nodes=32, max_depth=8)),
                    (ValueError, 'HIA JSON preflight: ' + SYNTAX_REASONS[reason]))
        self.assertEqual(vm_reference(b'[0,"\\x"]', nodes=2, diagnostic=True), (2, 0))
        self.assertEqual(vm_reference(b'{"x":0,"x":"\\x"}', nodes=2, diagnostic=True), (4, 0))


class JsonPreflightHiaNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Establish a fresh independent VM/Python observation BEFORE B0.
        cls.pre_seed_observation = vm_reference(b'{"x":true}', nodes=32, depth=8)
        assert cls.pre_seed_observation == reference(b'{"x":true}', 32, 8) == 0
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-json-native-')
        directory = Path(cls.temporary.name)
        seed, _ = build_seed(directory)
        compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(directory, 'B1', seed, compiler_source, image_format='seed-shared')
        second, _ = compile_stage(directory, 'B2', first, compiler_source)
        assert first.read_bytes() == second.read_bytes()
        image, cls.compile_receipt = compile_stage(directory, 'json-preflight', second, SOURCE.read_bytes())
        cls.image = image.read_bytes()
        cls.native = NativeJsonPreflight(cls.image, sha256(cls.image).hexdigest())
        cls.manifest = directory / 'installed.json'
        cls.manifest.write_text(json.dumps({'schema': 'hepta.hia.json-preflight-native.v1',
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
            'image_sha256': sha256(cls.image).hexdigest(), 'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compare(self, wire, *, nodes=262144, depth=128):
        expected = reference(wire, nodes, depth)
        result = self.native.status(wire, max_nodes=nodes, max_depth=depth)
        self.assertEqual(result, expected, (wire[:100], len(wire), nodes, depth))
        return result

    def test_native_generation_and_no_python_json_parse_during_admission(self):
        self.assertEqual(self.compile_receipt['forbidden_compiler_modules_loaded'], [])
        with patch('json.loads', side_effect=AssertionError('payload decoded')):
            self.assertEqual(self.native.status(b'{"a":[true,null]}', max_nodes=64, max_depth=8), 0)

    def test_all_utf8_widths_boundaries_escaped_spelling_and_duplicate_scopes(self):
        points = [0, 1, 8, 9, 10, 12, 13, 31, 32, 34, 47, 92, 127, 128,
                  2047, 2048, 55295, 57344, 65535, 65536, 1114111]
        for point in points:
            escaped = json.dumps(chr(point))
            literal = json.dumps(chr(point), ensure_ascii=False)
            self.compare(literal.encode())
            self.assertEqual(self.compare(('{'+escaped+':0,'+literal+':1}').encode()), 4)
            self.assertEqual(self.compare(('[{'+escaped+':0},{'+literal+':1}]').encode()), 0)
        for wire in (b'{"a":0,"\\u0061":1}', b'{"/":0,"\\/":1}',
                     b'{"a":{"a":0},"b":{"a":1}}', b'{"":0,"":1}',
                     b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\u0000"',
                     b'"\\udc00\\ud800"', b'"\\u0000"', b'"\\uG000"',
                     b'"\\ud800\\udc00"', b'"\\udbff\\udfff"'):
            self.compare(wire)

    def test_malformed_utf8_and_json_grammar(self):
        for wire in (b'', b'{', b'[', b'[1,]', b'{"k":1,}', b'[,]', b'{"k" 1}',
                     b'01', b'-01', b'-0.5', b'1e2', b'NaN', b'Infinity', b'[] []',
                     b'"\\z"', b'"unterminated', b'"\x00"', b'trueX',
                     b'"\xc0\x80"', b'"\xe0\x80\x80"', b'"\xed\xa0\x80"',
                     b'"\xf0\x80\x80\x80"', b'"\xf4\x90\x80\x80"', b'"\xf5\x80\x80\x80"'):
            self.compare(wire)
        for byte in range(256):
            self.compare(bytes([byte]))
            self.compare(b'"' + bytes([byte]) + b'"')

    def test_exact_node_and_depth_budgets_and_large_wire(self):
        for depth in (0, 1, 4, 64, 128):
            self.assertEqual(self.compare(b'[' * depth + b'0' + b']' * depth, depth=depth), 0)
            self.assertEqual(self.compare(b'[' * (depth + 1) + b'0' + b']' * (depth + 1), depth=depth), 2)
            self.assertEqual(self.compare(b'[' * (depth + 1) + b']' * (depth + 1), depth=depth), 0)
        for nodes in (1, 2, 1024, 262144, 1048576):
            self.assertEqual(self.compare(b'[' + b','.join([b'0'] * (nodes - 1)) + b']', nodes=nodes), 0)
            self.assertEqual(self.compare(b'[' + b','.join([b'0'] * nodes) + b']', nodes=nodes), 2)
        wire = b'"' + b'a' * ((8 << 20) - 2) + b'"'
        self.assertEqual(self.compare(wire), 0)
        with self.assertRaises(ValueError):
            self.native.status(wire + b' ', max_nodes=262144, max_depth=128)

    def test_dense_unique_keys_and_collision_resolution(self):
        # 16384 different keys include many equal initial table slots. Open
        # addressing must retain full decoded equality, not trust a hash.
        wire = json.dumps({f'k{i}': i for i in range(16384)}, separators=(',', ':')).encode()
        self.assertEqual(self.compare(wire), 0)
        self.assertEqual(self.compare(wire[:-1] + b',"\\u006b0":1}'), 4)

    def test_two_thousand_random_trees_and_randomized_node_depth_budgets(self):
        rng = random.Random(973417)
        def value(depth=0):
            if depth < 5 and rng.randrange(3):
                if rng.randrange(2):
                    return [value(depth + 1) for _ in range(rng.randrange(4))]
                return {f'k{i}': value(depth + 1) for i in range(rng.randrange(4))}
            return rng.choice([None, False, True, rng.randrange(-100000, 100000), 'é😀\x00}[],\\"'])
        for i in range(2000):
            wire = json.dumps(value(), ensure_ascii=bool(i & 1)).encode()
            self.compare(wire)
            self.compare(wire, nodes=rng.randrange(1, 40), depth=rng.randrange(5))

    def test_two_thousand_mutated_wires_against_independent_scanner(self):
        rng = random.Random(38471)
        valid = b'{"a":[0,true,false,null,"\\ud83d\\ude00"],"b":{"x":"xyz"}}'
        for _ in range(2000):
            wire = bytearray(valid)
            for _ in range(rng.randrange(1, 4)):
                wire[rng.randrange(len(wire))] = rng.randrange(256)
            self.compare(bytes(wire))

    def test_exact_diagnostics_and_error_order_match_the_independent_scanner(self):
        wires = ('', ' ', '[', '{', '[1,]', '{"k":1,}', '[,]', '{"k" 1}',
                 '{"k":1 2}', '[1 2]', '0 0', '01', '-01', '-0.5', '1e2',
                 'NaN', 'Infinity', '٠', '１', '\u00a00', '0\u00a0', '- 1',
                 '"unterminated', '"\\', '"\\x"', '"\\u"', '"\\u0"',
                 '"\\u00G0"', '"\\u𐐷"', '"\\u00Ω"', '"\\ud800"',
                 '"\\ud800\\u0041"', '"\\udc00"', '"\x00"',
                 '{"a":0,"\\u0061":"\\x"}', '[0,"\\x"]', '[["\\x"]]')
        rng = random.Random(69413)
        seed = '{"a":[0,true,false,null,"\\ud83d\\ude00"],"b":{"x":"Ω𐐷"}}'
        mutated = []
        alphabet = list('[]{}:,"\\-+0123efnultr x\t\r\n\x00') + ['Ω', '𐐷', '٠', '１', '\u00a0']
        for _ in range(2000):
            wire = list(seed)
            for _ in range(rng.randrange(1, 4)):
                wire[rng.randrange(len(wire))] = rng.choice(alphabet)
            mutated.append(''.join(wire))
        for wire in (*wires, *mutated):
            for nodes, depth in ((32, 8), (2, 0), (3, 1)):
                with self.subTest(wire=wire, nodes=nodes, depth=depth):
                    expected = outcome(lambda: preflight_hia_json(
                        wire, max_nodes=nodes, max_depth=depth))
                    with patch('hepta.hia_json_preflight._preflight_hia_json_reference',
                               side_effect=AssertionError('native diagnostic fell back')):
                        actual = outcome(lambda: self.native.admit(
                            wire.encode(), max_nodes=nodes, max_depth=depth))
                    self.assertEqual(actual, expected)

    def test_private_scratch_concurrent_calls_and_abi_refusals(self):
        inputs = [b'{}', b'{"a":0,"a":1}', b'[[0]]', b'"\xc0\x80"'] * 16
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual = list(pool.map(lambda x: self.native.status(x, max_nodes=64, max_depth=8), inputs))
        self.assertEqual(actual, [reference(x, 64, 8) for x in inputs])
        source, tiny = ctypes.create_string_buffer(b'{}'), ctypes.create_string_buffer(1)
        self.assertEqual(self.native._entry(source, 2, tiny, 0, tiny, 0), 3)
        state = ctypes.create_string_buffer(256)
        struct.pack_into('<QQ', state, 48, 64, 0)
        self.assertEqual(self.native._entry(source, 2, tiny, 0, state, 256), 3)
        self.assertEqual(self.native._entry(source, (8 << 20) + 1, tiny, 0, tiny, 0), 3)

    def test_existing_api_dispatch_and_unchanged_original_regressions(self):
        import os
        import subprocess
        import sys
        from hepta.hia_json_preflight import preflight_hia_json as dispatch
        with patch.dict(os.environ, {'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST': str(self.manifest)}):
            with patch('hepta.hia_json_preflight._preflight_hia_json_reference',
                       side_effect=AssertionError('native admission fell back')):
                dispatch('{"a":[true,null]}', max_nodes=64, max_depth=8)
                with self.assertRaisesRegex(ValueError, 'duplicate'):
                    dispatch('{"a":0,"\\u0061":1}', max_nodes=64, max_depth=8)
                with self.assertRaises(OverflowError):
                    dispatch('[0,0]', max_nodes=2, max_depth=8)
                for wire, reason in (('"unterminated', 'unterminated JSON string'),
                                     ('٠', 'expected JSON integer or literal')):
                    with self.assertRaises(ValueError) as caught:
                        dispatch(wire, max_nodes=8, max_depth=8)
                    self.assertEqual(str(caught.exception), 'HIA JSON preflight: ' + reason)
            # Unsupported budgets and unencodable Python strings retain the
            # reference, not a narrower claim about the existing public API.
            dispatch('0', max_nodes=1048577, max_depth=129)
            with self.assertRaises(ValueError):
                dispatch('"\ud800"', max_nodes=64, max_depth=8)
            def test_ids(suite):
                for child in suite:
                    if isinstance(child, unittest.TestSuite):
                        yield from test_ids(child)
                    else:
                        yield child.id()

            expected_ids = list(test_ids(unittest.defaultTestLoader.loadTestsFromName(
                'tests.test_hia_json_preflight')))
            self.assertGreater(len(expected_ids), 0)
            script = '''import json, unittest
suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_hia_json_preflight')
def ids(items):
    for item in items:
        if isinstance(item, unittest.TestSuite):
            yield from ids(item)
        else:
            yield item.id()
test_ids = list(ids(suite))
result = unittest.TextTestRunner(verbosity=2).run(suite)
counts = dict(tests=result.testsRun, errors=len(result.errors),
              failures=len(result.failures), skipped=len(result.skipped),
              expected_failures=len(result.expectedFailures),
              unexpected_successes=len(result.unexpectedSuccesses))
passed = (result.wasSuccessful() and 0 < counts['tests'] == len(test_ids)
          and not any(value for key, value in counts.items() if key != 'tests'))
print(json.dumps(dict(test_ids=test_ids, counts=counts, passed=passed)), flush=True)
raise SystemExit(0 if passed else 1)
'''
            child = subprocess.run([sys.executable, '-B', '-c', script], cwd=ROOT,
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            observed = json.loads(child.stdout)
            self.assertEqual(observed['test_ids'], expected_ids)
            self.assertEqual(observed['counts'], dict(tests=len(expected_ids), errors=0,
                failures=0, skipped=0, expected_failures=0, unexpected_successes=0))
            self.assertIs(observed['passed'], True)
            with patch.dict(os.environ, {'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST': str(self.manifest) + '.missing'}):
                with self.assertRaises(FileNotFoundError):
                    dispatch('0', max_nodes=8, max_depth=8)

    def test_installed_artifact_is_source_and_byte_bound(self):
        selected = installed_preflight(str(self.manifest))
        selected.admit(b'{"x":0}', max_nodes=8, max_depth=8)
        bad = json.loads(self.manifest.read_text())
        for field in ('source_sha256', 'image_sha256'):
            wrong = self.manifest.with_name('bad-' + field + '.json')
            wrong.write_text(json.dumps({**bad, field: '0' * 64}))
            with self.assertRaises(ValueError):
                installed_preflight(str(wrong))
        with self.assertRaises(ValueError):
            NativeJsonPreflight(self.image, '0' * 64)


if __name__ == '__main__':
    unittest.main()
