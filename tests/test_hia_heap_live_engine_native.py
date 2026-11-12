"""Complete private live-heap engine differential and actual-byte controls.

Only already verified canonical Core reaches this kernel. Public input/profile
admission and certificate serialization are not claimed here. Untouched Python
analyses are independent oracles; selected native entries never call them.
Original context/depth/transfer limits remain unchanged in the boundary tests.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_heap_bound as original
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_instruction_policy_native import transport
from hepta.hia_program import verify_core, verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from hepta.hia_static_budget import HIAStaticBudgetRejected
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_HEAP_LIVE_ENGINE_DEVELOPMENT_COMPILER'
COLD_REPORT = 'HEPTA_HIA_HEAP_BOUND_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_HEAP_LIVE_ENGINE_EVIDENCE'
ABI = 0xfffffff1
MASK = (1 << 64) - 1

# Independent interpretation of the private status protocol. This reconstructs
# only error spelling; all admission, flow, counters and values come from HIA.
ERROR_TEXT = {
    1: 'incompatible owner inventory at a CFG join',
    2: 'incompatible borrowed owner roots',
    3: 'local owner and external loan roots disagree',
    4: 'missing bounded owner at edge',
    5: 'loan edge lacks its bounded owner',
    10: 'resource arguments have unbounded external extent',
    11: 'owned return needs a caller-size invariant',
    12: 'missing reachable CFG input',
    13: 'finite invocation argument inventory differs',
    14: 'owned argument needs a proved finite extent',
    15: 'external borrowed extent promises are not admitted',
    20: 'allocator extent lacks a finite verified bound',
    21: 'borrowed extent lacks a bounded owner root',
    22: 'ending a loan without a bounded root',
    23: 'owner move lacks a free bounded source',
    24: 'drop lacks a free bounded source',
    25: 'buffer.len lacks a bounded root',
    26: 'unreviewed opcode {extra} has no heap accounting',
    27: 'call lacks a free bounded owned argument',
    28: 'borrowed call lacks its retained caller root',
    29: 'callee return inventory differs',
    30: 'returned owner lacks a bounded extent',
    31: 'invocation cannot return this loan',
    32: 'interprocedural resource transfer requires a separate proof',
    33: 'callee heap bound not available',
    34: 'returned loan lacks its caller root',
    35: 'returned owner has no bounded root',
    36: 'returned loan lacks an external formal root',
    50: 'finite invocation context/depth analysis limit exceeded',
    51: 'finite invocation abstract-transfer work limit exceeded',
    101: 'checked constant arithmetic may trap',
    102: 'unreviewed integer cast mode cannot qualify a heap budget',
    103: 'checked constant shift count traps',
    104: 'checked constant division or remainder traps',
    105: 'checked constant negation may trap',
}

INPUT_NAMES = (
    'tests/test_hia_heap_live_engine_native.py', 'tools/hia_heap_live_engine.py',
    'tools/hia_heap_live_transfers.py', 'tools/hia_heap_live_state.py',
    'tools/hia_heap_scoped_cycle.py', 'tools/hia_heap_bound_graphs.py',
    'tools/hia_native_bigints.py', 'tools/hia_native_heap_intervals.py',
    'tools/generate_hia_program_execution.py', 'tools/generate_hia_instruction_policy.py',
    'tools/generate_hia_core_json_frontend.py', 'tools/generate_hia_selfhost.py',
    'tools/hia_program_execution_scalars.py', 'tools/hia_program_execution_resources.py',
    'tools/qualify_hia_selfhost.py', 'tools/hia_selfhost_limits.py',
    'hepta/hia_heap_bound.py', 'hepta/hia_static_budget.py', 'hepta/hia_program.py',
    'hepta/hia_program_runtime.py', 'hepta/hia_instruction_policy_native.py',
    'hepta/hia_json_preflight_native.py', 'hepta/hia_opcodes.py',
    'tests/test_hia_program.py', 'tests/test_hia_heap_bound.py',
    'tests/test_hia_heap_intervals.py', 'tests/test_hia_heap_borrowed.py',
    'tests/test_hia_scoped_alloc_loops.py', 'tests/test_hia_zero_heap_loops.py',
    'tests/test_hia_returned_loan_budgets.py', 'tests/test_hia_partial_finite_bounds.py',
    'tests/test_hia_finite_v8_heap.py', 'tests/test_hia_borrowed_extent_heap.py',
    'tests/test_hia_rust_finite_heap.py', 'tools/qualify_hia_partial_records.py',
    'tests/test_hia_returned_loans.py', 'tests/test_hia_composite_returned_loans.py',
    'tests/test_hia_static_budget.py',
)


def abstract(value):
    if value is None:
        return ('none',)
    if type(value) is bool:
        return ('bool', value)
    if type(value) is int:
        return ('int', value)
    if type(value) is original._Span:
        return ('span', value.lo, value.hi)
    if type(value) is original._BorrowedExtent:
        return ('borrowed', value.upper)
    raise AssertionError('oracle produced an unreviewed abstract value: ' + repr(value))


def returned(values):
    return None if values is None else tuple(abstract(value) for value in values)


def cache_rows(cache):
    rows = [{'function': name, 'arguments': tuple(abstract(value) for value in arguments),
             'peak': result.peak, 'returned': returned(result.returned)}
            for (name, arguments), result in cache.items()]
    return sorted(rows, key=lambda row: (row['function'], repr(row['arguments'])))


def reference(checked, mode, function=None, arguments=()):
    document = checked.as_dict()
    functions = {fn['name']: fn for fn in document['functions']}
    if mode == 0:
        return {'summaries': list(original.analyze_constant_live_heap(checked).items())}
    if mode == 1:
        calls = {fn['name']: {ins['attrs']['function'] for block in fn['blocks'] for ins in block['ops']
                             if ins['op'] == 'call'} for fn in document['functions']}
        order = original._dag(list(functions), calls, 'v8 borrowed-call heap graph')
        calculated = {}
        for name in reversed(order):
            calculated[name] = original._function(functions[name], functions, calculated, borrowed_local_peaks=True)
        return {'summaries': [(fn['name'], calculated[fn['name']]) for fn in document['functions']]}
    analysis = original._FiniteInvocationAnalysis(functions,
        parameter_loan_returns=mode >= 3, propagate_borrowed_extents=mode == 4)
    result = analysis.invoke(functions[function], tuple(arguments))
    return {'peak': result.peak, 'returned': returned(result.returned),
            'contexts': analysis.contexts, 'steps': analysis.transfer_steps,
            'depth': analysis.depth, 'peak_depth': analysis.peak_depth,
            'cache': cache_rows(analysis.cache)}


def versioned(*functions, version=7, export='entry'):
    source = m(*functions)
    source['schema'] = 'hepta.hia.program.v' + str(version)
    if version >= 7:
        source['exports'] = [export]
    return source


def stopped_callee(*, fallible=False, extent=1 << 63):
    operations = [c('held_size', 'usize', 4), i('buffer.new', ['held_size'], [('held', 'buffer')]),
                  c('huge', 'usize', extent)]
    out = [('impossible', 'buffer')]
    if fallible:
        out.append(('ok', 'bool'))
    operations += [i('buffer.try_new' if fallible else 'buffer.new', ['huge'], out),
                   i('owner.drop', ['impossible']), i('owner.drop', ['held'])]
    child = f('child', [], ['bool'] if fallible else [], ['alloc', 'trap'],
              [b('start', [], operations, ret('ok') if fallible else ret())])
    operations = [c('own_size', 'usize', 3), i('buffer.new', ['own_size'], [('own', 'buffer')]),
                  i('call', [], [('result', 'bool')] if fallible else [], function='child'),
                  c('later_size', 'usize', 99), i('buffer.new', ['later_size'], [('later', 'buffer')]),
                  i('owner.drop', ['later']), i('owner.drop', ['own'])]
    entry = f('entry', [], ['bool'] if fallible else [], ['alloc', 'trap'],
              [b('start', [], operations, ret('result') if fallible else ret())])
    return versioned(child, entry)


class HeapLiveEngineSourceTests(unittest.TestCase):
    def test_typed_source_has_complete_definitions_and_original_limits(self):
        from tools.hia_heap_live_engine import document, source_program
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        nodes = ast.parse(source_program()).body
        names = {node.name for node in nodes}
        intrinsics = {'byte', 'store', 'length', 'choose', 'fill_range', 'copy_in'}
        calls = {node.func.id for fn in nodes for node in ast.walk(fn)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertFalse(calls - names - intrinsics)
        self.assertEqual(len(nodes), len(names))
        value = document()
        self.assertTrue(verify_core(value).sha256)
        blocks = [block for fn in value['functions'] for block in fn['blocks']]
        self.assertLessEqual(len(value['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(len(blocks), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for block in blocks), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for block in blocks), 16)
        self.assertLessEqual(max(len(fn['params']) for fn in value['functions']), 16)
        self.assertLessEqual(max(len(fn['blocks']) for fn in value['functions']), 256)

    def test_original_fixed_analysis_limits_and_status_dictionary(self):
        from tools.hia_heap_live_engine import ERROR_DETAILS
        self.assertEqual(ERROR_DETAILS, ERROR_TEXT)
        self.assertEqual((original._FINITE_MAX_CONTEXTS, original._FINITE_MAX_TRANSFER_STEPS,
                          original._FINITE_MAX_ANALYSIS_DEPTH), (1024, 32768, 64))

    def test_cold_and_development_conflict_before_input_read(self):
        with patch.dict(os.environ, {COLD_REPORT: '/unread-cold', DEVELOPMENT: '/unread-development'}), patch.object(
                Path, 'read_bytes', side_effect=AssertionError('read before conflicting fixture refusal')):
            with self.assertRaisesRegex(RuntimeError, 'mutually exclusive'):
                HeapLiveEngineNativeTests.setUpClass()

    def test_cold_contract_binds_every_actual_input_before_compile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / 'compiler'; compiler.write_bytes(b'never compiled')
            nested = root / 'nested.json'; nested.write_text(json.dumps({'generations': [{'produced_image': str(compiler)}]}))
            cold = root / 'cold.json'; cold.write_text(json.dumps({'nested_report': str(nested)}))
            evidence = root / 'not-created'
            with patch.dict(os.environ, {COLD_REPORT: str(cold), DEVELOPMENT: '', EVIDENCE: str(evidence)}), patch(
                    'tools.build_hia_json_preflight.admit_cold_build', return_value={}), patch(
                    'tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compile before source binding')):
                with self.assertRaisesRegex(ValueError, 'source-bound live heap input'):
                    HeapLiveEngineNativeTests.setUpClass()
            self.assertFalse(evidence.exists())


class HeapLiveEngineNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise RuntimeError('cold and development live-heap fixtures are mutually exclusive')
        if not cold and not development:
            raise unittest.SkipTest('explicit cold report or retained development compiler required')
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.hia_heap_live_engine import document
        from tools.qualify_hia_selfhost import compile_stage
        cls.inputs = {name: (ROOT / name).read_bytes() for name in INPUT_NAMES}
        cls.cold_bytes = None
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cls.cold_bytes = Path(cold).read_bytes()
            report = json.loads(cls.cold_bytes)
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.cold_sources = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
            for name, raw in cls.inputs.items():
                if cls.cold_sources.get(name) != sha256(raw).hexdigest():
                    raise ValueError('missing or changed source-bound live heap input: ' + name)
            cls.scope = 'CURRENT_SOURCE_COLD_COMPILER_PRIVATE_LIVE_HEAP_ENGINE'
        else:
            cls.compiler = Path(development); cls.compiler_bytes = cls.compiler.read_bytes()
            cls.scope = 'RETAINED_COMPILER_DEVELOPMENT_PRIVATE_LIVE_HEAP_ENGINE'
        folder = os.environ.get(EVIDENCE)
        cls.folder = Path(folder) if folder else Path(tempfile.mkdtemp(prefix='hia-live-heap-'))
        cls.folder.mkdir(parents=True, exist_ok=folder is None)
        (cls.folder / 'packets').mkdir()
        (cls.folder / 'raw-cases').mkdir()
        cls.program = document(); cls.checked = verify_core(cls.program)
        cls.source = render_assembly(cls.program).encode()
        cls.image, receipt = compile_stage(cls.folder, 'heap-live-engine', cls.compiler, cls.source)
        cls.image_bytes = cls.image.read_bytes()
        cls.native = NativeHiaJsonImage(cls.image_bytes, sha256(cls.image_bytes).hexdigest())
        cls.entries = cls.vm_entries = cls.differentials = cls.growth_retries = 0
        cls.records = []
        for name, raw in cls.inputs.items():
            path = cls.folder / 'frozen-inputs' / name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        (cls.folder / 'source-before.json').write_text(json.dumps(
            {name: sha256(raw).hexdigest() for name, raw in cls.inputs.items()}, sort_keys=True, indent=2) + '\n')
        (cls.folder / 'compile-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        stable = all((ROOT / name).read_bytes() == raw for name, raw in cls.inputs.items())
        build_stable = cls.image.read_bytes() == cls.image_bytes and cls.compiler.read_bytes() == cls.compiler_bytes
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            build_stable = build_stable and Path(os.environ[COLD_REPORT]).read_bytes() == cls.cold_bytes and current_sources() == cls.cold_sources
        blocks = [block for fn in cls.program['functions'] for block in fn['blocks']]
        report = {'scope': cls.scope, 'source_unchanged': stable, 'build_inputs_unchanged': build_stable,
            'native_entries': cls.entries, 'independent_vm_entries': cls.vm_entries,
            'original_reference_controls': cls.differentials, 'growth_retries': cls.growth_retries,
            'source_sha256': sha256(cls.source).hexdigest(), 'image_sha256': sha256(cls.image_bytes).hexdigest(),
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(), 'source_bytes': len(cls.source),
            'functions': len(cls.program['functions']), 'blocks': len(blocks),
            'instructions': sum(len(block['ops']) for block in blocks),
            'maximum_block_params': max(len(block['params']) for block in blocks),
            'maximum_function_params': max(len(fn['params']) for fn in cls.program['functions']),
            'maximum_blocks_in_one_function': max(len(fn['blocks']) for fn in cls.program['functions']),
            'cases': cls.records, 'public_controller_qualified': False, 'whole_stack_qualified': False}
        (cls.folder / 'observations.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        if not stable or not build_stable:
            raise AssertionError('live heap source/compiler/image changed during controls')

    def word(self, raw, offset):
        self.assertGreaterEqual(offset, 0); self.assertLessEqual(offset + 8, len(raw))
        return struct.unpack_from('<Q', raw, offset)[0]

    def text(self, raw, offset):
        if offset in (0, MASK):
            return None
        self.assertEqual(self.word(raw, offset), 4)
        size = self.word(raw, offset + 8)
        self.assertLessEqual(offset + 16 + size, len(raw))
        return raw[offset + 16:offset + 16 + size].decode('utf-8', errors='surrogatepass')

    def bigint(self, raw, offset):
        self.assertGreater(offset, 0)
        sign, count, capacity = (self.word(raw, offset + 8 * index) for index in range(3))
        self.assertEqual(sign, 0); self.assertLessEqual(count, capacity)
        self.assertLessEqual(offset + 24 + 8 * capacity, len(raw))
        value = 0
        for index in range(count):
            limb = self.word(raw, offset + 24 + 8 * index)
            self.assertLessEqual(limb, (1 << 32) - 1)
            if index == count - 1:
                self.assertNotEqual(limb, 0)
            value += limb << (index * 32)
        return value

    def value(self, raw, offset):
        kind, low_sign, low, high_sign, high = (self.word(raw, offset + 8 * index) for index in range(5))
        self.assertIn(kind, range(5)); self.assertIn(low_sign, (0, 1)); self.assertIn(high_sign, (0, 1))
        self.assertFalse(low_sign and low == 0); self.assertFalse(high_sign and high == 0)
        lower, upper = (-low if low_sign else low), (-high if high_sign else high)
        if kind == 0:
            self.assertEqual((low_sign, low, high_sign, high), (0, 0, 0, 0)); return ('none',)
        if kind == 1:
            self.assertEqual((low_sign, high_sign), (0, 0)); self.assertEqual(low, high); self.assertIn(low, (0, 1))
            return ('bool', bool(low))
        if kind in (2, 4):
            self.assertEqual(lower, upper)
            return ('int' if kind == 2 else 'borrowed', lower)
        self.assertLessEqual(lower, upper)
        return ('span', lower, upper)

    def values(self, raw, offset):
        count = self.word(raw, offset)
        self.assertLessEqual(count, (len(raw) - offset - 8) // 8)
        return tuple(self.value(raw, self.word(raw, offset + 8 + index * 8)) for index in range(count))

    def result(self, raw, offset):
        peak, values = self.word(raw, offset), self.word(raw, offset + 8)
        return {'peak': self.bigint(raw, peak), 'returned': None if values == 0 else self.values(raw, values)}

    def semantic(self, raw, mode):
        code = self.word(raw, 88)
        function, block, extra = (self.text(raw, self.word(raw, index)) for index in (96, 104, 112))
        if code in (40, 41):
            context = function + ' heap control flow' if function else (
                'HIA heap call graph' if mode == 0 else 'v8 borrowed-call heap graph')
            detail = context + (': unknown dependency' if code == 40 else ': recursion or CFG cycle requires a separate invariant')
            error = 'E_HIA_BUDGET_GRAPH' if code == 40 else 'E_HIA_BUDGET_UNBOUNDED'
        else:
            self.assertIn(code, ERROR_TEXT)
            detail = ERROR_TEXT[code].format(extra=extra)
            error = 'E_HIA_BUDGET_LIMIT' if code in (50, 51) else 'E_HIA_BUDGET_UNBOUNDED'
            if code in range(10, 16):
                detail = str(function) + ': ' + detail
            elif code in range(1, 6) or code in range(20, 37) or code == 105:
                detail = str(function) + '/' + str(block) + ': ' + detail
        return {'code': error, 'detail': error + ': ' + detail, 'native_code': code,
                'function': function, 'block': block, 'extra': extra}

    def decode_success(self, raw, output, mode, document, function):
        analysis, graph, selected, reported_mode = struct.unpack('<4Q', output)
        self.assertEqual(reported_mode, mode); self.assertEqual(self.word(raw, analysis), graph)
        self.assertEqual(self.word(raw, analysis + 8), mode); self.assertEqual(self.word(raw, analysis + 16), 0)
        self.assertEqual(self.word(raw, analysis + 40), 0)
        count = self.word(raw, graph)
        self.assertEqual(count, len(document['functions']))
        nodes = self.word(raw, graph + 8)
        functions = {}
        summaries = []
        for index, fn in enumerate(document['functions']):
            at = nodes + index * 48
            name = self.text(raw, self.word(raw, at))
            self.assertEqual(name, fn['name'])
            functions[self.word(raw, at + 8)] = name
            if mode < 2:
                summaries.append((name, self.bigint(raw, self.word(raw, at + 32))))
        if mode < 2:
            self.assertEqual(selected, MASK)
            self.assertEqual(tuple(self.word(raw, analysis + offset) for offset in (24, 32, 40, 48, 56)), (0, 0, 0, 0, 0))
            return {'summaries': summaries}
        self.assertEqual(document['functions'][selected]['name'], function)
        result = self.result(raw, self.word(raw, analysis + 64))
        result.update(contexts=self.word(raw, analysis + 24), steps=self.word(raw, analysis + 32),
                      depth=self.word(raw, analysis + 40), peak_depth=self.word(raw, analysis + 48))
        rows, seen = [], set()
        memo = self.word(raw, analysis + 56)
        while memo:
            self.assertNotIn(memo, seen); seen.add(memo)
            fn = self.word(raw, memo + 8); self.assertIn(fn, functions)
            child = self.result(raw, self.word(raw, memo + 24))
            rows.append({'function': functions[fn], 'arguments': self.values(raw, self.word(raw, memo + 16)), **child})
            memo = self.word(raw, memo)
        self.assertEqual(len(rows), result['contexts'])
        result['cache'] = sorted(rows, key=lambda row: (row['function'], repr(row['arguments'])))
        return result

    def invoke(self, document, mode, function=None, arguments=(), *, vm=False, workspace_size=None, grow=True):
        packet = transport([mode, document, function, list(arguments)])
        digest = sha256(packet).hexdigest()
        packet_path = self.folder / 'packets' / (digest + '.bin')
        if not packet_path.exists():
            packet_path.write_bytes(packet)
        else:
            self.assertEqual(packet_path.read_bytes(), packet)
        size = workspace_size if workspace_size is not None else 65536 + len(packet) * 16
        while True:
            guard = b'\xB7' * 16
            source = ctypes.create_string_buffer(guard + packet + guard, len(packet) + 32)
            workspace = ctypes.create_string_buffer(guard + b'\xA5' * size + guard, size + 32)
            output = ctypes.create_string_buffer(guard + b'\xC3' * 32 + guard, 64)
            before_w, before_o = bytes(workspace)[16:-16], bytes(output)[16:-16]
            status = self.native._entry(ctypes.byref(source, 16), len(packet), ctypes.byref(output, 16), 32,
                                       ctypes.byref(workspace, 16), size)
            type(self).entries += 1
            for value in (source, workspace, output):
                self.assertEqual(bytes(value)[:16], guard); self.assertEqual(bytes(value)[-16:], guard)
            self.assertEqual(bytes(source)[16:-16], packet)
            observed_w, observed_o = bytes(workspace)[16:-16], bytes(output)[16:-16]
            if vm:
                roots = [_Owner(-1, bytearray(packet)), _Owner(-2, bytearray(before_o)), _Owner(-3, bytearray(before_w))]
                machine = _Machine(self.checked, 100_000_000, 0, None, 256)
                result = machine.invoke(machine.functions['f0'], [_View(root, index != 0) for index, root in enumerate(roots)])
                self.assertEqual(result, [status]); self.assertEqual(bytes(roots[0].data), packet)
                self.assertEqual(bytes(roots[1].data), observed_o); self.assertEqual(bytes(roots[2].data), observed_w)
                type(self).vm_entries += 1
            record = {'test': self.id(), 'packet_sha256': digest, 'mode': mode, 'function': function,
                      'arguments': list(arguments), 'workspace_bytes': size, 'status': status}
            if vm or status not in (0, 1):
                prefix = self.folder / 'raw-cases' / ('entry-' + str(self.entries))
                prefix.with_suffix('.workspace.bin').write_bytes(observed_w)
                prefix.with_suffix('.output.bin').write_bytes(observed_o)
                record['full_raw_prefix'] = prefix.name
            if status == 0:
                self.assertEqual(tuple(self.word(observed_w, index) for index in (72, 80, 88)), (0, 0, 0))
                record['result'] = self.decode_success(observed_w, observed_o, mode, document, function)
            elif status == 1:
                self.assertEqual(observed_o, before_o)
                self.assertEqual(tuple(self.word(observed_w, index) for index in (80, 88)), (0, 0))
                needed = self.word(observed_w, 72); self.assertGreater(needed, size)
                record['needed'] = needed
            elif status == 3:
                self.assertEqual(observed_o, before_o)
                record['error'] = self.semantic(observed_w, mode)
            else:
                self.assertEqual(status, ABI)
                self.assertEqual(observed_o, before_o)
                record['abi_error'] = self.word(observed_w, 80) if size >= 88 else None
            type(self).records.append(record)
            with (self.folder / 'actual-cases.jsonl').open('a') as stream:
                stream.write(json.dumps(record, sort_keys=True) + '\n')
            if status == 1 and grow:
                size = max(needed, size * 2)
                type(self).growth_retries += 1
                continue
            return record

    def compare(self, source, mode=0, function=None, arguments=(), *, vm=False, core=False):
        checked = verify_core(source) if core else verify_program(source)
        expected = None
        try:
            expected = reference(checked, mode, function, arguments)
        except (original.HIAHeapBoundRejected, HIAStaticBudgetRejected) as error:
            failure = {'code': error.code, 'detail': str(error)}
        else:
            failure = None
        actual = self.invoke(checked.as_dict(), mode, function, arguments, vm=vm)
        if failure is None:
            self.assertEqual(actual['status'], 0, actual)
            self.assertEqual(actual['result'], expected)
        else:
            self.assertEqual(actual['status'], 3, actual)
            self.assertEqual({name: actual['error'][name] for name in ('code', 'detail')}, failure)
        type(self).differentials += 1
        return actual

    def test_legacy_complete_function_summaries_owner_moves_and_cfg_joins(self):
        from tests.test_hia_heap_bound import local_buffers, joined_max, scalar_call
        from tests.test_hia_heap_intervals import selected, computed, diamond, wrapped_zero
        from tests.test_hia_heap_borrowed import local_borrow_length, nested_reborrow_cross_block, diamond_view_join
        for factory in (local_buffers, joined_max, scalar_call, selected, computed, diamond,
                        wrapped_zero, local_borrow_length, nested_reborrow_cross_block, diamond_view_join):
            with self.subTest(source=factory.__name__):
                self.compare(factory(), vm=factory is local_buffers)
        source = scalar_call()
        source['functions'].reverse()
        observed = self.compare(source)
        self.assertEqual([name for name, _ in observed['result']['summaries']], ['parent', 'inner'])

    def test_legacy_unknown_and_exact_errors_preserve_code_detail_and_context(self):
        from tests.test_hia_heap_bound import unknown_size
        from tests.test_hia_heap_intervals import dynamic_unknown, checked_overflow_unknown
        for factory in (unknown_size, dynamic_unknown, checked_overflow_unknown):
            self.compare(factory())
        # Include an allocation so the historical scalar-only fast path does
        # not intentionally bypass scalar interpretation in legacy mode.
        for op, typ, left, right in (
                ('int.div.checked', 'i8', 3, 0), ('int.shl.checked', 'u8', 1, 8),
                ('int.neg.checked', 'i8', -128, None)):
            ops = [c('left', typ, left)]
            args = ['left']
            if right is not None:
                ops.append(c('right', typ, right)); args.append('right')
            ops += [i(op, args, [('result', typ)]), c('size', 'usize', 1),
                    i('buffer.new', ['size'], [('owner', 'buffer')]), i('owner.drop', ['owner'])]
            self.compare(m(f('failure', [], [typ], ['alloc', 'trap'], [b('only', [], ops, ret('result'))])),
                         vm=op == 'int.neg.checked')

    def test_legacy_cycles_keep_zero_scoped_and_dag_rejection_distinct(self):
        from tests.test_hia_scoped_alloc_loops import scoped_loop
        from tests.test_hia_zero_heap_loops import scalar_loop
        self.compare(scalar_loop())
        self.compare(scoped_loop(two_allocations=True, in_entry=True))
        source = scoped_loop()
        body = next(block for block in source['functions'][0]['blocks'] if block['id'] == 'body')
        body['ops'][0]['attrs']['value'] = 0
        self.compare(source)
        for source in (scalar_loop(), scoped_loop()):
            source['schema'] = 'hepta.hia.program.v7'; source['exports'] = ['count_down']
            self.compare(source, 2, 'count_down', [3])

    def test_borrowed_local_all_function_summaries_match_original_public_reports(self):
        from tests.test_hia_returned_loan_budgets import (fixed_loan_program, temporary_loan_program,
            branch_loan_program, returned_length_program, external_length_program)
        sources = [fixed_loan_program(mode, construction)
                   for mode in ('read', 'mut') for construction in ('forward', 'child', 'cfg')]
        sources += [temporary_loan_program(nested=True, extra_owner=True), branch_loan_program(),
                    returned_length_program(), external_length_program(checked_cast=True)]
        for source in sources:
            entry = source['exports'][0]
            actual = self.compare(source, 1, entry)
            report = original.qualify_entry_live_heap_budget(source, entry, max_live_heap_bytes=original.MAX_REQUEST)
            expected = [(row['function'], row['max_additional_local_payload_bytes']) for row in report['local_peak_summaries']]
            self.assertEqual(actual['result']['summaries'], expected)
            self.assertEqual(dict(expected)[entry], report['peak_bound_bytes'])
        self.compare(external_length_program(), 1)

    def test_finite_owned_transfers_multiple_returns_and_shared_borrowed_actuals(self):
        from tests.test_hia_partial_finite_bounds import nested_owned, borrowed_owned
        for source in (nested_owned(), borrowed_owned()):
            for mode in (2, 3, 4):
                self.compare(source, mode, 'entry', [], vm=mode == 2 and source['functions'][0]['name'] == 'inner')
        consume = f('consume', [('owned', 'buffer')], ['usize'], ['alloc'], [
            b('start', [('owned', 'buffer')], [i('buffer.len', ['owned'], [('size', 'usize')]),
                i('owner.drop', ['owned'])], ret('size'))])
        entry = f('entry', [], [], ['alloc', 'trap'], [b('start', [], [
            c('eight', 'usize', 8), i('buffer.try_new', ['eight'], [('owned', 'buffer'), ('ok', 'bool')]),
            i('call', ['owned'], [('length', 'usize')], function='consume'),
            c('hundred', 'usize', 100), i('int.sub.checked', ['hundred', 'length'], [('next', 'usize')]),
            i('buffer.try_new', ['next'], [('later', 'buffer'), ('later_ok', 'bool')]),
            i('owner.drop', ['later'])], ret())])
        result = self.compare(versioned(consume, entry), 2, 'entry')['result']
        self.assertEqual(result['peak'], 100)
        child = next(row for row in result['cache'] if row['function'] == 'consume')
        self.assertEqual(child['returned'], (('span', 0, 8),))

    def test_finite_returned_loans_preserve_all_caller_roots_and_modes(self):
        from tests.test_hia_finite_v8_heap import mixed_transfer_program, asymmetric_return_program
        for arguments in ([0, False], [9, False], [9, True], [1 << 63, False]):
            for mode in (3, 4):
                self.compare(mixed_transfer_program(), mode, 'entry', arguments)
        for mode in (3, 4):
            self.compare(asymmetric_return_program(), mode, 'entry', [])
        # A canonical v8 function does not gain v2 loan-return authority when
        # the private finite mode lacks that separately selected capability.
        self.compare(mixed_transfer_program(), 2, 'entry', [9, False])

    def test_borrowed_extent_memo_keys_reordering_aliases_and_unknown_predecessors(self):
        from tests.test_hia_borrowed_extent_heap import (baseline_program, borrowed_exchange_program,
            reordered_extent_program, context_program, aliased_extent_program, joined_extent_program,
            interval_program)
        for mode in (2, 3, 4):
            self.compare(baseline_program(), mode, 'entry', [])
        for borrow in ('read', 'mut'):
            for cancel in (False, True):
                self.compare(borrowed_exchange_program(borrow), 4, 'entry', [cancel])
        for source in (reordered_extent_program(), context_program(), aliased_extent_program()):
            actual = self.compare(source, 4, 'entry', [])
            if source['functions'][0]['name'] == 'copy_extent':
                rows = [row for row in actual['result']['cache'] if row['function'] == 'copy_extent']
                self.assertEqual(len(rows), 2)
                self.assertEqual({row['arguments'][0] for row in rows}, {('borrowed', 3), ('borrowed', 11)})
        for flag in (False, True):
            self.compare(joined_extent_program(), 4, 'entry', [flag])
        for extent in (0, 8):
            actual = self.compare(interval_program(extent), 4, 'entry', [])
            self.assertEqual(actual['result']['peak'], 100)
            length = next(row for row in actual['result']['cache'] if row['function'] == 'length')
            self.assertEqual(length['returned'], (('span', 0, extent),))

    def test_finite_none_empty_unit_unknown_bool_and_owned_returns_are_distinct(self):
        samples = [
            f('entry', [], [], [], [b('start', [], [], ret())]),
            f('entry', [], ['unit'], [], [b('start', [], [c('unit', 'unit', None)], ret('unit'))]),
            f('entry', [], ['bool'], [], [b('start', [], [c('answer', 'bool', False)], ret('answer'))]),
            f('entry', [], [], ['trap'], [b('start', [], [], {'op': 'trap', 'code': 'user'})]),
        ]
        expected = [(), (('none',),), (('bool', False),), None]
        for fn, values in zip(samples, expected):
            actual = self.compare(versioned(fn), 2, 'entry', [], vm=values in ((), None))
            self.assertEqual(actual['result']['returned'], values)
        helper = f('empty_owner', [], ['buffer'], ['alloc'], [b('start', [], [c('zero', 'usize', 0),
            i('buffer.try_new', ['zero'], [('owned', 'buffer'), ('ok', 'bool')])], ret('owned'))])
        entry = f('entry', [], [], ['alloc'], [b('start', [], [
            i('call', [], [('returned', 'buffer')], function='empty_owner'),
            i('owner.drop', ['returned'])], ret())])
        result = self.compare(versioned(helper, entry), 2, 'entry')['result']
        self.assertEqual(result['returned'], ())
        self.assertEqual(next(row for row in result['cache'] if row['function'] == 'empty_owner')['returned'], (('int', 0),))
        # Unknown load results are an ordinary return with a None element.
        source = versioned(f('entry', [], ['u8'], ['alloc', 'read', 'trap'], [b('start', [], [
            c('one', 'usize', 1), c('zero', 'usize', 0), i('buffer.new', ['one'], [('owner', 'buffer')]),
            i('borrow.read', ['owner'], [('view', 'readbuf')]),
            i('buffer.load', ['view', 'zero'], [('loaded', 'u8')]),
            i('loan.end', ['view']), i('owner.drop', ['owner'])], ret('loaded'))]))
        self.assertEqual(self.compare(source, 2, 'entry')['result']['returned'], (('none',),))

    def test_allocation_guard_and_no_return_callee_keep_exact_prior_prefix(self):
        for extent in (1 << 63, MASK):
            for mode in (2, 3, 4):
                rejected_path = self.compare(stopped_callee(extent=extent), mode, 'entry')
                self.assertEqual(rejected_path['result']['peak'], 7)
                self.assertIsNone(rejected_path['result']['returned'])
                empty_path = self.compare(stopped_callee(fallible=True, extent=extent), mode, 'entry')
                self.assertEqual(empty_path['result']['peak'], 102)
                self.assertEqual(empty_path['result']['returned'], (('bool', False),))
        crossing = f('entry', [], [], ['alloc', 'trap'], [b('start', [], [
            c('one', 'usize', 1), i('buffer.try_new', ['one'], [('held', 'buffer'), ('ok', 'bool')]),
            i('buffer.len', ['held'], [('length', 'usize')]), c('maximum', 'usize', original.MAX_REQUEST),
            i('int.add.checked', ['maximum', 'length'], [('request', 'usize')]),
            i('buffer.try_new', ['request'], [('other', 'buffer'), ('other_ok', 'bool')]),
            i('owner.drop', ['other']), i('owner.drop', ['held'])], ret())])
        self.compare(versioned(crossing), 2, 'entry')

    def test_all_scalar_ids_types_and_exact_exception_order_through_finite_engine(self):
        binary = ('int.add.checked', 'int.add.wrap', 'int.sub.checked', 'int.sub.wrap',
                  'int.mul.checked', 'int.mul.wrap', 'int.div.checked', 'int.rem.checked',
                  'int.shl.checked', 'int.shr.checked', 'bit.and', 'bit.or', 'bit.xor',
                  'compare.eq', 'compare.ne', 'compare.lt', 'compare.le', 'compare.gt', 'compare.ge')
        for typ in ('i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64', 'isize', 'usize'):
            for op in binary:
                target = 'bool' if op.startswith('compare.') else typ
                params = [('a', typ), ('z', typ)]
                fn = f('entry', params, [target], ['trap'], [b('start', params,
                    [i(op, ['a', 'z'], [('value', target)])], ret('value'))])
                self.compare(versioned(fn), 2, 'entry', [5, 1])
            for op in ('bit.not', 'int.neg.checked'):
                params = [('a', typ)]
                fn = f('entry', params, [typ], ['trap'], [b('start', params,
                    [i(op, ['a'], [('value', typ)])], ret('value'))])
                self.compare(versioned(fn), 2, 'entry', [1])
        for op in ('bool.and', 'bool.or'):
            params = [('a', 'bool'), ('z', 'bool')]
            fn = f('entry', params, ['bool'], [], [b('start', params,
                [i(op, ['a', 'z'], [('value', 'bool')])], ret('value'))])
            for values in ([False, True], [True, False], [True, True]):
                self.compare(versioned(fn), 2, 'entry', values)
        for mode in ('checked', 'wrap'):
            for value in (-1, 0, 255, 256):
                params = [('arg', 'i64')]
                fn = f('entry', params, ['u8'], ['trap'], [b('start', params,
                    [i('int.cast', ['arg'], [('value', 'u8')], mode=mode)], ret('value'))])
                self.compare(versioned(fn), 2, 'entry', [value])

    def test_full_width_public_argument_and_return_inventories_are_not_kernel_caps(self):
        for count in (17, 33):
            params = [('arg' + str(index), 'usize') for index in range(count)]
            helper = f('relay', params, ['usize'] * count, [], [b('start', params, [], ret(*(name for name, _ in params)))])
            outputs = [('out' + str(index), 'usize') for index in range(count)]
            entry = f('entry', params, ['usize'] * count, [], [b('start', params,
                [i('call', [name for name, _ in params], outputs, function='relay')], ret(*(name for name, _ in outputs)))])
            values = list(range(count))
            actual = self.compare(versioned(helper, entry), 2, 'entry', values)
            self.assertEqual(actual['result']['returned'], tuple(('int', value) for value in values))

    def test_large_mathematical_payload_totals_do_not_wrap_u64(self):
        ops = [c('size', 'usize', original.MAX_REQUEST)]
        ops += [i('buffer.new', ['size'], [('owner' + str(index), 'buffer')]) for index in range(3)]
        ops += [i('owner.drop', ['owner' + str(index)]) for index in range(3)]
        entry = f('entry', [], [], ['alloc', 'trap'], [b('start', [], ops, ret())])
        actual = self.compare(m(entry))
        self.assertEqual(actual['result']['summaries'], [('entry', original.MAX_REQUEST * 3)])
        actual = self.compare(versioned(entry), 2, 'entry')
        self.assertEqual(actual['result']['peak'], original.MAX_REQUEST * 3)

    def test_repeated_identical_calls_reuse_full_memo_result_without_work(self):
        params = [('arg', 'usize')]
        helper = f('helper', params, ['usize'], ['trap'], [b('start', params,
            [c('one', 'usize', 1), i('int.add.checked', ['arg', 'one'], [('result', 'usize')])], ret('result'))])
        ops = [c('arg', 'usize', 6)]
        ops += [i('call', ['arg'], [('value' + str(index), 'usize')], function='helper') for index in range(5)]
        entry = f('entry', [], ['usize'], ['trap'], [b('start', [], ops, ret('value4'))])
        actual = self.compare(versioned(helper, entry), 2, 'entry')
        self.assertEqual(actual['result']['contexts'], 2)
        self.assertEqual(actual['result']['steps'], 12)
        self.assertEqual(actual['result']['returned'], (('int', 7),))

    def test_original_fixed_context_depth_and_transfer_boundaries(self):
        from tests.test_hia_rust_finite_heap import context_work, depth_work
        for source, counter, value in ((context_work(1023), 'contexts', 1024),
                                       (depth_work(64), 'peak_depth', 64),
                                       (context_work(762, 39), 'steps', 32768)):
            actual = self.compare(source, 2, 'entry', [], core=True)
            self.assertEqual(actual['result'][counter], value)
        for source, native_code in ((context_work(1024), 50), (depth_work(65), 50),
                                    (context_work(763, 39), 51)):
            actual = self.compare(source, 2, 'entry', [], core=True)
            self.assertEqual(actual['error']['native_code'], native_code)

    def test_storage_growth_is_not_an_empty_bound_or_a_semantic_refusal(self):
        from tests.test_hia_heap_bound import local_buffers
        checked = verify_program(local_buffers()); document = checked.as_dict()
        packet = transport([0, document, None, []])
        size = (8192 + len(packet) + 7) & ~7
        first = self.invoke(document, 0, workspace_size=size, grow=False, vm=True)
        self.assertEqual(first['status'], 1)
        actual = self.invoke(document, 0, workspace_size=size)
        self.assertEqual(actual['result'], reference(checked, 0))
        invalid = self.invoke(document, 5)
        self.assertEqual(invalid['status'], ABI)

    def test_selected_machine_has_no_original_policy_dependency(self):
        from tests.test_hia_partial_finite_bounds import nested_owned
        document = verify_program(nested_owned()).as_dict()
        with patch.object(original, '_function', side_effect=AssertionError('hosted function policy called')), patch.object(
                original, '_FiniteInvocationAnalysis', side_effect=AssertionError('hosted invocation policy called')), patch.object(
                original, '_scoped_allocating_cycle_peak', side_effect=AssertionError('hosted scoped policy called')):
            actual = self.invoke(document, 2, 'entry', [])
        self.assertEqual(actual['status'], 0)
        self.assertEqual(actual['result']['peak'], 19)


if __name__ == '__main__':
    unittest.main()
