"""Independent graph, SCC and map controls for the pending HIA heap owner.

No public heap selector is installed here. The standalone kernel is built
with an explicitly retained development compiler or the admitted current-source
cold compiler used by the complete static resource owner.
The same input, output, workspace and guard bytes are also observed through
the retained independent VM for representative cases.
"""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_instruction_policy_native import transport
from hepta.hia_program import verify_core
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_heap_bound_graphs import BODY
from tools.hia_program_execution_scalars import ScalarBuilder

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_HEAP_GRAPHS_DEVELOPMENT_COMPILER'
COLD_REPORT = 'HEPTA_HIA_STATIC_BUDGET_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_HEAP_GRAPHS_EVIDENCE'
ABI = 0xfffffff1
MASK = (1 << 64) - 1

WRAPPER = r'''
def heap_graph_probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192 or length(s) > length(w) - 8192 or length(o) < 32:
        return 4294967281
    if src_validate(s, w) == 0:
        return 4294967281
    fill_range(w, 0, 4096, 0)
    copy_in(w, s, 8192, 0, length(s))
    put(w, 64, (8192 + length(s) + 7) & 18446744073709551608)
    packet = 8192
    if tag(w, packet) != 5 or total(w, packet) != 4:
        return 4294967281
    mode = decimal(w, element(w, packet, 0))
    names = element(w, packet, 1)
    edges = element(w, packet, 2)
    ops = element(w, packet, 3)
    if tag(w, names) != 5 or tag(w, edges) != 5 or tag(w, ops) != 5:
        return 4294967281
    graph = heap_graph(w, total(w, names))
    if graph == 0:
        return 1
    index = 0
    while index < total(w, names):
        name = element(w, names, index)
        if tag(w, name) != 4:
            return 4294967281
        put(w, heap_node(w, graph, index), name)
        index = index + 1
    index = 0
    while index < total(w, edges):
        edge = element(w, edges, index)
        if tag(w, edge) != 5 or total(w, edge) != 2:
            return 4294967281
        source = decimal(w, element(w, edge, 0))
        target = decimal(w, element(w, edge, 1))
        if heap_edge(w, graph, source, target) == 0:
            if get(w, 80) != 0:
                return 2
            return 1
        index = index + 1
    put(o, 0, mode)
    put(o, 8, get(w, graph))
    if mode == 0:
        ordered = heap_topological(w, graph)
        if ordered == 18446744073709551615:
            return 3
        if ordered == 0:
            return 1
        count = get(w, ordered)
        if count > (length(o) - 32) // 8:
            return 4294967281
        put(o, 16, count)
        index = 0
        while index < count:
            put(o, 32 + index * 8, get(w, ordered + 8 + index * 8))
            index = index + 1
        return 0
    if mode == 1:
        components = heap_components(w, graph)
        if components == 0:
            return 1
        put(o, 16, get(w, components))
        at = 32
        index = 0
        while index < get(w, components):
            component = get(w, components + 8 + index * 8)
            count = get(w, component)
            if at > length(o) or length(o) - at < 8 or count > (length(o) - at - 8) // 8:
                return 4294967281
            put(o, at, count)
            at = at + 8
            row = 0
            while row < count:
                put(o, at, get(w, component + 8 + row * 8))
                at = at + 8
                row = row + 1
            index = index + 1
        put(o, 24, at)
        return 0
    if mode == 2:
        return heap_map_probe(w, o, graph, ops)
    return 4294967281

def heap_map_probe(w:mutbuf, o:mutbuf, graph:u64, ops:u64) -> u32:
    count = total(w, ops)
    if count > (length(o) - 32) // 24:
        return 4294967281
    table = heap_map(w)
    if table == 0:
        return 1
    put(o, 16, count)
    index = 0
    while index < count:
        operation = element(w, ops, index)
        if tag(w, operation) != 5 or total(w, operation) != 3:
            return 4294967281
        action = decimal(w, element(w, operation, 0))
        key_id = decimal(w, element(w, operation, 1))
        value = decimal(w, element(w, operation, 2))
        if key_id >= get(w, graph):
            return 4294967281
        key = heap_name(w, graph, key_id)
        status = 1
        answer = 0
        if action == 1:
            if heap_map_put(w, table, key, value) == 0:
                return 1
        elif action == 2:
            answer = heap_map_get(w, table, key)
        elif action == 3:
            status = heap_map_drop(w, table, key)
        elif action == 4:
            copied = heap_map_copy(w, table)
            if copied == 0:
                return 1
            table = copied
        else:
            return 4294967281
        put(o, 32 + index * 24, status)
        put(o, 40 + index * 24, answer)
        put(o, 48 + index * 24, get(w, table + 8))
        index = index + 1
    return 0
'''


def document():
    from tools.generate_hia_program_execution import source_program
    shared = {'get', 'put', 'tag', 'word', 'size_of', 'end', 'total', 'element',
              'same_text', 'src_validate', 'src_word', 'decimal'}
    nodes = ast.parse(WRAPPER + BODY).body
    nodes += [node for node in ast.parse(source_program()).body if node.name in shared]
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    class GraphBuilder(ScalarBuilder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_in':
                args = [self.expr(arg) for arg in node.args]
                return self.op('buffer.copy_range', [args[0], args[1], *[self.cast(value, 'usize') for value in args[2:]]])
            return super().expr(node)
    functions = []
    for node in nodes:
        builder = GraphBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'heap_graph_probe', 'functions': functions})


class HeapGraphSourceTests(unittest.TestCase):
    def test_cold_and_development_conflict_before_input_read(self):
        with patch.dict(os.environ, {COLD_REPORT: '/unread-cold', DEVELOPMENT: '/unread-compiler'}), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('read before fixture admission')):
            with self.assertRaisesRegex(RuntimeError, 'mutually exclusive'):
                HeapGraphNativeTests.setUpClass()

    def test_graph_source_is_valid_core_inside_original_compiler_limits(self):
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        value = document()
        self.assertTrue(verify_core(value).sha256)
        self.assertLessEqual(len(value['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in value['functions'] for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in value['functions'] for block in fn['blocks']), 16)


class HeapGraphNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise RuntimeError('cold and retained development graph fixtures are mutually exclusive')
        if not cold and not development:
            raise unittest.SkipTest('an explicit cold report or retained development compiler is required')
        if development and any(key.endswith('_COLD_REPORT') and value for key, value in os.environ.items()):
            raise RuntimeError('this development fixture cannot replace an inherited cold request')
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.cold_bytes = None
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cls.cold_path = Path(cold)
            cls.cold_bytes = cls.cold_path.read_bytes()
            report = json.loads(cls.cold_bytes)
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.cold_sources = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
            cls.scope = 'CURRENT_SOURCE_COLD_COMPILER_STANDALONE_GRAPH_CONTROL'
        else:
            cls.compiler = Path(development)
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.scope = 'RETAINED_COMPILER_DEVELOPMENT_STANDALONE_GRAPH_CONTROL'
        cls.folder = Path(os.environ.get(EVIDENCE) or tempfile.mkdtemp(prefix='hia-heap-graphs-'))
        cls.folder.mkdir(parents=True, exist_ok=True)
        names = ('tools/hia_heap_bound_graphs.py', 'tests/test_hia_heap_graphs_native.py',
                 'tools/generate_hia_program_execution.py', 'tools/generate_hia_instruction_policy.py',
                 'tools/hia_program_execution_scalars.py', 'tools/hia_program_execution_resources.py',
                 'tools/generate_hia_selfhost.py', 'hepta/hia_program_runtime.py', 'hepta/hia_heap_bound.py',
                 'hepta/hia_static_budget.py')
        cls.inputs = {name: (ROOT / name).read_bytes() for name in names}
        cls.document = document(); cls.checked = verify_core(cls.document)
        cls.source = render_assembly(cls.document).encode()
        (cls.folder / 'heap-graph-probe.hiaasm').write_bytes(cls.source)
        cls.image, receipt = compile_stage(cls.folder, 'heap-graph-probe', cls.compiler, cls.source)
        cls.image_bytes = cls.image.read_bytes()
        cls.native = NativeHiaJsonImage(cls.image_bytes, sha256(cls.image_bytes).hexdigest())
        cls.entries = cls.vm_entries = cls.differentials = 0
        for name, raw in cls.inputs.items():
            path = cls.folder / 'frozen-inputs' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        (cls.folder / 'compile-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')

    @classmethod
    def tearDownClass(cls):
        stable = all((ROOT / name).read_bytes() == raw for name, raw in cls.inputs.items())
        build_stable = cls.compiler.read_bytes() == cls.compiler_bytes and cls.image.read_bytes() == cls.image_bytes
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            build_stable = (build_stable and cls.cold_path.read_bytes() == cls.cold_bytes
                            and current_sources() == cls.cold_sources)
        report = {'scope': cls.scope, 'source_unchanged': stable,
            'build_inputs_unchanged': build_stable, 'native_entries': cls.entries,
            'independent_vm_entries': cls.vm_entries, 'independent_differentials': cls.differentials,
            'source_sha256': sha256(cls.source).hexdigest(), 'image_sha256': sha256(cls.image_bytes).hexdigest(),
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest()}
        (cls.folder / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if not stable or not build_stable:
            raise AssertionError('heap graph control inputs changed')

    def invoke(self, mode, names, edges, ops=(), *, vm=False, workspace_size=None):
        packet = transport([mode, names, edges, list(ops)])
        count = len(names)
        if workspace_size is None:
            workspace_size = 16384 + len(packet) * 8 + (count + len(edges) + len(ops) + 1) * 256
        output_size = 64 + max(16 * count, 24 * len(ops))
        guard = b'\xB7' * 16
        source = ctypes.create_string_buffer(guard + packet + guard, len(packet) + 32)
        workspace = ctypes.create_string_buffer(guard + b'\xA5' * workspace_size + guard, workspace_size + 32)
        output = ctypes.create_string_buffer(guard + b'\xC3' * output_size + guard, output_size + 32)
        before_w, before_o = bytes(workspace)[16:-16], bytes(output)[16:-16]
        status = self.native._entry(ctypes.byref(source, 16), len(packet), ctypes.byref(output, 16), output_size,
                                    ctypes.byref(workspace, 16), workspace_size)
        type(self).entries += 1
        for value in (source, workspace, output):
            self.assertEqual(bytes(value)[:16], guard); self.assertEqual(bytes(value)[-16:], guard)
        self.assertEqual(bytes(source)[16:-16], packet)
        observed_w, observed_o = bytes(workspace)[16:-16], bytes(output)[16:-16]
        if vm:
            roots = [_Owner(-1, bytearray(packet)), _Owner(-2, bytearray(before_o)), _Owner(-3, bytearray(before_w))]
            machine = _Machine(self.checked, 10_000_000, 0, None, 256)
            values = machine.invoke(machine.functions['f0'], [_View(root, index != 0) for index, root in enumerate(roots)])
            self.assertEqual(values, [status]); self.assertEqual(bytes(roots[0].data), packet)
            self.assertEqual(bytes(roots[1].data), observed_o); self.assertEqual(bytes(roots[2].data), observed_w)
            type(self).vm_entries += 1
        if status:
            return status, observed_w, observed_o
        amount, = struct.unpack_from('<Q', observed_o, 16)
        if mode == 0:
            result = [names[value[0]] for value in struct.iter_unpack('<Q', observed_o[32:32 + amount * 8])]
        elif mode == 1:
            result = []; at = 32
            for _ in range(amount):
                size, = struct.unpack_from('<Q', observed_o, at); at += 8
                result.append([names[value[0]] for value in struct.iter_unpack('<Q', observed_o[at:at + size * 8])]); at += size * 8
            self.assertEqual(at, struct.unpack_from('<Q', observed_o, 24)[0])
        else:
            result = list(struct.iter_unpack('<3Q', observed_o[32:32 + amount * 24]))
        return status, result

    def compare(self, names, edges, *, vm=False):
        from hepta.hia_static_budget import _topological, HIAStaticBudgetRejected
        from hepta.hia_heap_bound import _payload_components
        graph = {name: set() for name in names}
        for source, target in edges:
            graph[names[source]].add(names[target])
        try:
            order = _topological(names, graph, 'independent heap graph')
        except HIAStaticBudgetRejected as exc:
            self.assertEqual(exc.code, 'E_HIA_BUDGET_UNBOUNDED')
            self.assertEqual(self.invoke(0, names, edges, vm=vm)[0], 3)
        else:
            self.assertEqual(self.invoke(0, names, edges, vm=vm), (0, order))
        self.assertEqual(self.invoke(1, names, edges, vm=vm), (0, _payload_components(graph)))
        type(self).differentials += 2

    def test_stable_fifo_order_and_exact_cyclic_exits(self):
        for names, edges in [([], []), (['z'], []), (['z'], [[0, 0]]),
            (['z', 'a', 'c', 'b'], [[1, 2], [1, 3], [3, 0], [2, 0], [1, 2]]),
            (['exit', 'cycle-z', 'cycle-a', 'entry'], [[3, 1], [1, 2], [2, 1], [2, 0]]),
            (['中', '\ud800', '\ue000', 'a', '😀', ''], [[3, 0], [0, 4]])]:
            self.compare(names, edges, vm=len(names) <= 4)

    def test_random_complete_small_graphs_match_independent_scc_and_dag(self):
        rng = random.Random(26873)
        for count in range(1, 14):
            for trial in range(9):
                names = ['node-' + str(index) for index in range(count)]; rng.shuffle(names)
                edges = [[source, target] for source in range(count) for target in range(count)
                         if rng.randrange(8) == 0 and (trial % 2 == 0 or source < target)]
                self.compare(names, edges)

    def test_large_iterative_chain_and_many_disconnected_components(self):
        for count in (127, 513):
            names = ['n' + str(index) for index in range(count)]
            self.compare(names, [[index, index + 1] for index in range(count - 1)])
            self.compare(names, [])

    def test_private_maps_preserve_absence_values_removal_and_copy(self):
        rng = random.Random(26874)
        names = ['key-' + str(index) for index in range(9)]
        operations = [[rng.randrange(1, 5), rng.randrange(len(names)), rng.randrange(1 << 32)] for _ in range(300)]
        operations[:7] = [[1, 0, 0], [2, 0, 0], [2, 1, 0], [4, 0, 0], [3, 0, 0], [3, 0, 0], [2, 0, 0]]
        table = {}; expected = []
        for action, key, value in operations:
            status, answer = 1, 0
            if action == 1: table[names[key]] = value
            elif action == 2: answer = table.get(names[key], MASK)
            elif action == 3:
                status = int(names[key] in table); table.pop(names[key], None)
            else: table = dict(table)
            expected.append((status, answer, len(table)))
        self.assertEqual(self.invoke(2, names, [], operations), (0, expected))
        self.assertEqual(self.invoke(2, names, [], operations[:7], vm=True), (0, expected[:7]))
        type(self).differentials += len(operations)

    def test_existing_key_overwrite_and_copy_match_complete_vm_buffers(self):
        operations = [[1, 0, 3], [1, 0, 11], [2, 0, 0],
                      [4, 0, 0], [1, 0, 7], [2, 0, 0]]
        expected = [(1, 0, 1), (1, 0, 1), (1, 11, 1),
                    (1, 0, 1), (1, 0, 1), (1, 7, 1)]
        self.assertEqual(self.invoke(2, ['existing'], [], operations, vm=True), (0, expected))
        type(self).differentials += len(operations)

    def test_private_extent_refusals_never_authorize_partial_graph_results(self):
        names = ['a', 'b']; edges = [[0, 1]]
        packet = transport([0, names, edges, []])
        result = self.invoke(0, names, edges, workspace_size=(8192 + len(packet) + 7) & ~7)
        self.assertEqual(result[0], 1)
        self.assertGreater(struct.unpack_from('<Q', result[1], 72)[0], len(result[1]))
        self.assertEqual(self.invoke(0, names, [[0, 2]])[0], 2)


if __name__ == '__main__':
    unittest.main()
