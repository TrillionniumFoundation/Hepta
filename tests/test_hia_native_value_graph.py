"""Representation controls for lossless native-produced logical object graphs."""
import math
import struct
import unittest
from unittest.mock import patch

from hepta.hia_instruction_policy_native import transport
from hepta.hia_native_value_graph import NativeValuePool, decode_native_graph, decode_bound_native_graph


def reference(offset):
    return struct.pack('<3Q', 8, 8, offset)


def concatenate(offsets):
    return struct.pack('<3Q', 9, 8 + 8 * len(offsets), len(offsets)) + b''.join(
        struct.pack('<Q', offset) for offset in offsets)


def external_reference(identifier):
    return struct.pack('<3Q', 10, 8, identifier)


def external_concatenate(identifiers):
    return struct.pack('<3Q', 11, 8 + 8 * len(identifiers), len(identifiers)) + b''.join(
        struct.pack('<Q', identifier) for identifier in identifiers)


class NativeValueGraphTests(unittest.TestCase):
    def test_bound_owned_graph_rejects_typed_edges_keys_and_new_cycles(self):
        raw = transport({'path': ['blocks', 0, 'params'], 'bool': True,
                         'zero': -0.0, 'nested': {'items': [1]}})
        def changes(value):
            return (
                lambda: value['path'].__setitem__(1, 1),
                lambda: value.__setitem__('bool', 1),
                lambda: value.__setitem__('zero', 0.0),
                lambda: value['nested']['items'].append(value),
                lambda: value.__setitem__('extra', None),
                lambda: value.__setitem__('path', list(value['path'])),
            )
        for index in range(6):
            value, binding = decode_bound_native_graph(raw, raw)
            binding.validate(value)
            changes(value)[index]()
            with self.subTest(index=index), self.assertRaises(ValueError):
                binding.validate(value)
        value, binding = decode_bound_native_graph(raw, raw)
        value['path'] = value.pop('path')
        with self.assertRaises(ValueError):
            binding.validate(value)

    def test_bound_source_concatenation_has_no_expanded_shadow_array(self):
        import sys
        import tracemalloc
        raw = transport(['name_' + str(i) for i in range(512)])
        encoded = concatenate([0] * 8193)
        tracemalloc.start()
        try:
            value, binding = decode_bound_native_graph(encoded, raw)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(value), 8193 * 512)
        self.assertLess(peak - sys.getsizeof(value), 2 << 20)
        binding.validate(value)
        value[8192 * 512 + 7] = object()
        with self.assertRaises(ValueError):
            binding.validate(value)
        raw = transport([{'held': [1]}])
        value, binding = decode_bound_native_graph(concatenate([0, 0]), raw)
        self.assertIs(value[0], value[1])
        value[1]['held'][0] = 2
        with self.assertRaises(ValueError):
            binding.validate(value)

    def test_bound_external_values_preserve_opaque_identity_and_tuple_spines(self):
        helper = {'blocks': [{'args': ['held'] * (8193 * 512)}]}
        pool = NativeValuePool()
        direct = pool.add(helper)
        array = pool.add((helper, helper))
        with patch('hepta.hia_native_value_graph._external_height',
                   side_effect=AssertionError('stable opaque value was traversed again')):
            value, binding = decode_bound_native_graph(external_reference(direct), transport(None), pool)
            self.assertIs(value, helper)
            binding.validate(value)
            for encoded in (external_reference(array), external_concatenate([array, array])):
                value, binding = decode_bound_native_graph(encoded, transport(None), pool)
                self.assertTrue(all(item is helper for item in value))
                binding.validate(value)
                value[0] = dict(helper)
                with self.assertRaises(ValueError):
                    binding.validate(value)

    def test_exact_types_unicode_signed_zero_and_nested_source_values(self):
        original = {'null': None, 'bool': [True, False], 'integer': [-2**63, 2**64-1],
                    'float': [-0.0, 1.25, 5e-324], 'text': 'x\x00汉\ud800',
                    'nested': {'code': [{'payload': 'trap'}, [], {}]}}
        raw = transport(original)
        for encoded in (raw, reference(0)):
            actual = decode_native_graph(encoded, raw)
            self.assertEqual(actual, original)
            self.assertIs(type(actual['bool'][0]), bool)
            self.assertEqual(math.copysign(1.0, actual['float'][0]), -1.0)
            actual['nested']['code'][0]['payload'] = 'changed'
            self.assertEqual(original['nested']['code'][0]['payload'], 'trap')
            self.assertEqual(transport(original), raw)

    def test_repeated_512_slot_aliases_are_not_limited_by_wire_output_bytes(self):
        original = [('value_' + str(i)).ljust(128, '_') for i in range(512)]
        raw = transport(original)
        encoded = concatenate([0] * 8193)
        self.assertLess(len(encoded), 1 << 17)
        expanded = decode_native_graph(encoded, raw)
        self.assertEqual(len(expanded), 8193 * 512)
        self.assertEqual(expanded[:512], original)
        self.assertEqual(expanded[-512:], original)
        self.assertEqual(expanded[512 * 4096:512 * 4097], original)
        self.assertEqual(transport(original), raw)

    def test_reference_must_name_a_complete_original_node(self):
        raw = transport(['x'])
        for offset in (1, 8, 16, 23, 25, len(raw), 2**64-1):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode_native_graph(reference(offset), raw)
        self.assertEqual(decode_native_graph(reference(24), raw), 'x')
        with self.assertRaises(ValueError):
            decode_native_graph(concatenate([24]), raw)

    def test_original_graph_cannot_reference_output_or_itself(self):
        for raw in (reference(0), concatenate([0])):
            with self.assertRaises(ValueError):
                decode_native_graph(reference(0), raw)

    def test_truncated_extents_counts_trailing_bytes_and_unknown_tags_refused(self):
        good = transport({'a': [1, 2, 3]})
        invalid = [good[:i] for i in (0, 1, 15, 16, 23, len(good)-1)]
        invalid += [good + b'\0', struct.pack('<3Q', 9, 16, 2),
                    struct.pack('<2Q', 10, 0), struct.pack('<2Q', 8, 0),
                    struct.pack('<3Q', 5, 8, 2**64-1),
                    struct.pack('<3Q', 6, 8, 1)]
        for encoded in invalid:
            with self.subTest(encoded=encoded[:24]), self.assertRaises(ValueError):
                decode_native_graph(encoded, good)

    def test_duplicate_nonstring_keys_nonfinite_and_opaque_values_refused(self):
        pair = transport('x') + transport(1)
        duplicate = struct.pack('<3Q', 6, 8+len(pair)*2, 2) + pair*2
        for encoded in (duplicate, transport({1: 'x'}), transport(float('inf')),
                        transport(float('nan')), transport(object()),
                        struct.pack('<2Q', 2, 2) + b'01'):
            with self.subTest(encoded=encoded[:24]), self.assertRaises((ValueError, TypeError)):
                decode_native_graph(encoded, transport(None))

    def test_depth_and_mutable_byte_input_refused(self):
        value = None
        for _ in range(130):
            value = [value]
        with self.assertRaises(ValueError):
            decode_native_graph(transport(value), transport(None))
        for encoded, original in ((bytearray(transport(None)), transport(None)),
                                  (transport(None), bytearray(transport(None)))):
            with self.assertRaises(ValueError):
                decode_native_graph(encoded, original)


class NativeExternalValuePoolTests(unittest.TestCase):
    def test_exact_held_identity_and_stable_outer_snapshots(self):
        function = {'name': 'complete', 'blocks': [{'ops': [{'op': 'const', 'attrs': {'value': -0.0}}]}]}
        helpers = [function]
        snapshot = tuple(helpers)
        pool = NativeValuePool()
        self.assertEqual((pool.add(function), pool.add(snapshot)), (0, 1))
        helpers.append({'name': 'later'})
        raw = transport(None)
        self.assertIs(decode_native_graph(external_reference(0), raw, external=pool), function)
        actual = decode_native_graph(external_reference(1), raw, external=pool)
        self.assertIs(type(actual), list)
        self.assertEqual(len(actual), 1)
        self.assertIs(actual[0], function)
        self.assertEqual(math.copysign(1.0, actual[0]['blocks'][0]['ops'][0]['attrs']['value']), -1.0)

    def test_external_concat_allocates_only_outer_list_and_preserves_order(self):
        first, second = {'block': 'first'}, {'block': 'second'}
        left, right = [first], (second, first)
        pool = NativeValuePool(); pool.add(left); pool.add(right); pool.add(())
        result = decode_native_graph(external_concatenate([1, 2, 0, 1]), transport(None), pool)
        self.assertEqual(result, [second, first, first, second, first])
        self.assertIsNot(result, left)
        self.assertTrue(all(value is first for value in (result[1], result[2], result[4])))
        result.append('new outer item')
        self.assertEqual((left, right), ([first], (second, first)))

    def test_pool_representation_cycles_types_nonfinite_and_depth(self):
        cycle = []; cycle.append(cycle)
        mutual = {}; other = [mutual]; mutual['back'] = other
        deep = None
        for _ in range(129): deep = [deep]
        class NotJsonList(list): pass
        invalid = (cycle, mutual, deep, object(), NotJsonList(), {'x': (1, 2)},
                   {1: 'not a JSON key'}, {'x': float('nan')}, [float('inf')])
        for value in invalid:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                NativeValuePool().add(value)
        leaf = {'name': 'held'}; shared = [leaf, leaf]
        pool = NativeValuePool(); self.assertEqual(pool.add(shared), 0)
        self.assertIs(decode_native_graph(external_reference(0), transport(None), pool), shared)

    def test_raw_pool_references_validate_ids_kinds_and_current_custody(self):
        value = {'nested': [3]}
        for pool in ([value], (value,)):
            self.assertIs(decode_native_graph(external_reference(0), transport(None), pool), value)
            with self.assertRaises(ValueError):
                decode_native_graph(external_concatenate([0]), transport(None), pool)
        for identifier in (1, 2**64-1):
            with self.assertRaises(ValueError):
                decode_native_graph(external_reference(identifier), transport(None), (value,))
        value['cycle'] = value
        with self.assertRaisesRegex(ValueError, 'cycle'):
            decode_native_graph(external_reference(0), transport(None), (value,))
        for pool in (None, {}, iter(())):
            with self.assertRaises(ValueError):
                decode_native_graph(transport(None), transport(None), pool)

    def test_external_headers_and_original_pool_references_fail_closed(self):
        invalid = (struct.pack('<2Q', 10, 0), struct.pack('<3Q', 10, 16, 0),
                   struct.pack('<3Q', 11, 16, 2), struct.pack('<3Q', 11, 8, 1),
                   struct.pack('<2Q', 12, 0), external_reference(0) + b'x')
        for encoded in invalid:
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                decode_native_graph(encoded, transport(None), ([],))
        for original in (external_reference(0), external_concatenate([0])):
            with self.assertRaises(ValueError):
                decode_native_graph(reference(0), original, ([],))

    def test_existing_aggregate_values_do_not_consume_new_expansion_quota(self):
        from unittest.mock import patch
        first, second = ['a'] * 100, ['b'] * 100
        pool = NativeValuePool(); pool.add(first); pool.add(second)
        items = external_reference(0) + external_reference(1)
        encoded = struct.pack('<3Q', 5, 8 + len(items), 2) + items
        with patch('hepta.hia_native_value_graph.MAX_EXPANDED_ELEMENTS', 32):
            actual = decode_native_graph(encoded, transport(None), pool)
            self.assertIs(actual[0], first); self.assertIs(actual[1], second)
            with self.assertRaisesRegex(ValueError, 'expanded-element'):
                decode_native_graph(external_concatenate([0, 1]), transport(None), pool)
            with self.assertRaisesRegex(ValueError, 'expanded-element'):
                decode_native_graph(external_reference(0), transport(None), (tuple(first),))

    def test_external_embedding_cannot_hide_excessive_depth(self):
        deep = None
        for _ in range(128): deep = [deep]
        pool = NativeValuePool(); pool.add(deep)
        self.assertIs(decode_native_graph(external_reference(0), transport(None), pool), deep)
        child = external_reference(0)
        encoded = struct.pack('<3Q', 5, 8 + len(child), 1) + child
        with self.assertRaisesRegex(ValueError, 'depth'):
            decode_native_graph(encoded, transport(None), pool)

    def test_hia_external_writers_execute_independently_in_vm(self):
        import ast
        from hepta.hia_program import verify_core
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_instruction_policy import SOURCE
        from tools.hia_native_value_graph import BODY, EXTERNAL_BODY
        from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
        own = ast.parse('''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 4120, 0)
    put(w, 4128, 0)
    array = graph_begin(o, w, 5, 2)
    graph_external_ref(o, w, 0)
    put(w, 0, 1)
    put(w, 8, 2)
    graph_external_concat(o, w, 0, 2)
    graph_end(o, w, array)
    return get(w, 4120)
''')
        own.body += [node for node in ast.parse(SOURCE.replace('    DISPATCH', '    pass')).body
                     if isinstance(node, ast.FunctionDef) and node.name in ('get', 'put')]
        own.body += [node for node in ast.parse(BODY).body
                     if node.name in ('graph_word', 'graph_begin', 'graph_end')]
        own.body += ast.parse(EXTERNAL_BODY).body
        class Constants(ast.NodeTransformer):
            def visit_Name(self, node):
                return ast.Constant({'S': 4096, 'O_BYTES': 4096}[node.id]) if node.id in ('S', 'O_BYTES') else node
        nodes = ast.fix_missing_locations(Constants().visit(own)).body
        names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
        signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
        total = total_scalar_functions(nodes); functions = []
        for node in nodes:
            builder = Builder(node, names, signatures, total); builder.statements(node.body)
            functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
        checked = verify_core(compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'pool_test', 'functions': functions}))
        source, output, workspace = _Owner(-1, bytearray()), _Owner(-2, bytearray(4096)), _Owner(-3, bytearray(8192))
        machine = _Machine(checked, 100_000, 1 << 20, None, 256)
        extent = machine.invoke(checked.as_dict()['functions'][0], [_View(source, False), _View(output, True), _View(workspace, True)])[0]
        items = external_reference(0) + external_concatenate([1, 2])
        expected = struct.pack('<3Q', 5, 8 + len(items), 2) + items
        self.assertEqual(bytes(output.data[:extent]), expected)
        value = {'complete': ['native']}; pool = NativeValuePool()
        pool.add(value); pool.add((value,)); pool.add([7, 8])
        actual = decode_native_graph(expected, transport(None), pool)
        self.assertIs(actual[0], value); self.assertIs(actual[1][0], value)
        self.assertEqual(actual[1][1:], [7, 8])


if __name__ == '__main__':
    unittest.main()
