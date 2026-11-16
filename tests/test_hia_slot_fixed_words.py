"""Complete original-first Slot controls for fixed eight-byte word access.

The complete loop controller is reconstructed and bound to its original hash.
This supplement adds exact internal-word and packet observations. It never
replaces Source3, Native6, resource controls or their full original observations.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = 'tools/generate_hia_slot_operations.py'
SOURCE = 'examples/hia_bootstrap/slot_operations.hepta'
FIXTURE = 'tests/hia_slot_fixed_word_cases.json'
ORIGINAL_GENERATOR_SHA256 = '9dd4b7dd218c641a0f7f1d36641703356b6ce70587545b0512305206c2e4afaf'
CURRENT_GENERATOR_SHA256 = '574517982242d18fd255b07db8f93b18e26c71d1a425ceae801e9f1cebef20ba'
ORIGINAL_HIA_SHA256 = '55ea9c4f07672f155d38411d9b4464257aad7177019da10b23ce6aa09d73e9b3'
FIXTURE_SHA256 = '82a29e8a20eb3f32f63f35e465a4c2be68f946de8e9b35b9198c8a74d31476d3'
LIMITS = (4_000_000, 16 << 20, None, 128)
EVIDENCE = 'HEPTA_HIA_SLOT_FIXED_WORD_EVIDENCE'
ORIGINAL_HELPERS = {
    "read_word": "def read_word(s:readbuf, index:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 8:\n        value = value | (byte(s, index + i) << (i * 8))\n        i = i + 1\n    return value\n",
    "get": "def get(w:mutbuf, index:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 8:\n        value = value | (byte(w, index * 8 + i) << (i * 8))\n        i = i + 1\n    return value\n",
    "set": "def set(w:mutbuf, index:u64, value:u64) -> u64:\n    i = 0\n    while i < 8:\n        store(w, index * 8 + i, value >> (i * 8))\n        i = i + 1\n    return value\n"
}
FUNCTIONS = {'read_word': 'f28', 'get': 'f29', 'set': 'f30'}
RESOURCE_KINDS = (
    'active-default', 'active-read', 'active-mut', 'expired-view',
    'expired-owner', 'expired-parent', 'cyclic-view', 'bare-owner',
    'invalid-buffer', 'missing-buffer', 'missing-index', 'bad-index',
    'extra-argument',
)
PACKET_KINDS = (
    'valid-initialize', 'magic', 'sequence', 'port', 'observation', 'mode',
    'nonce-low', 'nonce-high', 'reserved', 'short-buffer-0', 'short-buffer-1',
    'short-buffer-2', 'state-byte-0', 'state-byte-8', 'state-byte-16',
    'state-byte-24', 'state-byte-40', 'state-byte-48', 'state-byte-80',
    'state-byte-184', 'valid-claim', 'valid-ack', 'valid-raised', 'replayed-ack',
)


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _helper_text(source, name):
    lines = source.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines)
              if line.startswith('def ' + name + '(')]
    if len(starts) != 1:
        raise AssertionError('helper definition is not unique: ' + name)
    start, end = starts[0], starts[0] + 1
    while end < len(lines) and lines[end].strip() not in ('', '"""', "'''"):
        end += 1
    return ''.join(lines[start:end])


def _restore_helpers(source):
    for name, original in ORIGINAL_HELPERS.items():
        current = _helper_text(source, name)
        if source.count(current) != 1:
            raise AssertionError('helper text is not unique: ' + name)
        source = source.replace(current, original)
    return source


def _author(source):
    from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
    from tools.generate_hia_service_context import ContextBuilder
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                              node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ContextBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'slot_operations', 'functions': functions})


def _outcome(machine, function, arguments):
    try:
        value = machine.invoke(machine.functions[function], arguments)
    except Exception as error:
        return {'kind': 'exception',
                'class': type(error).__module__ + '.' + type(error).__qualname__,
                'code': getattr(error, 'code', None), 'message': str(error)}
    return {'kind': 'return', 'values': value}


class SlotFixedWordSourceTests(unittest.TestCase):
    def setUp(self):
        self.assertNotIn('HEPTA_HIA_JSON_DECODE_MANIFEST', os.environ,
                         'independent Source controls require unselected decoding')
        evidence_root = os.environ.get(EVIDENCE)
        if evidence_root is not None:
            Path(evidence_root).mkdir(mode=0o700, parents=True, exist_ok=True)
        self.evidence = Path(tempfile.mkdtemp(prefix='slot-fixed-word-', dir=evidence_root))
        self.sources = {}
        self.report = {'schema': 'hepta.slot-fixed-word.complete-source-control.v1',
            'status': 'HOLD', 'pid': os.getpid(), 'test_id': self.id(),
            'limits': list(LIMITS), 'planned': [], 'reference': [],
            'current': [], 'differences': [], 'native_executed': False,
            'original_full_gates_replaced': False, 'qualified': False,
            'wall_time_target_claimed': False,
            'arbitrary_smaller_tick_limits_equivalence_claimed': False}
        self.addCleanup(self._finish)
        from tools.build_hia_slot_operations import INPUTS
        names = sorted(set(INPUTS) | {
            GENERATOR, SOURCE, FIXTURE, 'tests/test_hia_slot_fixed_words.py',
            'hepta/hia_program_runtime.py', 'hepta/hia_program_runtime_prepared.py',
            'hepta/hia_slot_operations_protocol.py'})
        self.sources = {name: (ROOT / name).read_bytes() for name in names}
        self.report['source_before'] = {name: _pin(raw) for name, raw in self.sources.items()}
        self.assertEqual(sha256(self.sources[GENERATOR]).hexdigest(), CURRENT_GENERATOR_SHA256)
        self.assertEqual(sha256(_restore_helpers(self.sources[GENERATOR].decode()).encode()).hexdigest(),
                         ORIGINAL_GENERATOR_SHA256)
        self.assertEqual(sha256(self.sources[FIXTURE]).hexdigest(), FIXTURE_SHA256)

    def _finish(self):
        after = {name: (ROOT / name).read_bytes() for name in self.sources}
        self.report['source_after'] = {name: _pin(raw) for name, raw in after.items()}
        stable = after == self.sources
        self.report['source_stable'] = stable
        if not stable:
            self.report['status'] = 'HOLD_SOURCE_CHANGED'
        (self.evidence / 'report.json').write_text(
            json.dumps(self.report, sort_keys=True, indent=2) + '\n')
        self.assertTrue(stable, 'Slot fixed-word source changed during complete control')

    def _prepare(self):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_program import verify_program
        from hepta.hia_program_runtime_prepared import prepare_runtime_program
        from tools import generate_hia_slot_operations as generator
        source = generator.source_program()
        reference_source = _restore_helpers(source)
        current_nodes = ast.parse(source).body
        reference_nodes = ast.parse(reference_source).body
        self.assertEqual(len(current_nodes), 31)
        self.assertEqual([node.name for node in current_nodes],
                         [node.name for node in reference_nodes])
        self.assertEqual(
            [node.name for node, old in zip(current_nodes, reference_nodes)
             if ast.dump(node, include_attributes=False) != ast.dump(old, include_attributes=False)],
            list(ORIGINAL_HELPERS))
        for current, original in zip(current_nodes, reference_nodes):
            self.assertEqual(ast.dump(current.args, include_attributes=False),
                             ast.dump(original.args, include_attributes=False))
            self.assertEqual(ast.dump(current.returns, include_attributes=False),
                             ast.dump(original.returns, include_attributes=False))
        docs = {'reference': _author(reference_source), 'current': generator.document()}
        raw = {name: render_assembly(doc).encode() for name, doc in docs.items()}
        self.assertEqual(sha256(raw['reference']).hexdigest(), ORIGINAL_HIA_SHA256)
        self.assertEqual(raw['current'], self.sources[SOURCE])
        for index, node in enumerate(current_nodes):
            if node.name not in ORIGINAL_HELPERS:
                self.assertEqual(docs['reference']['functions'][index],
                                 docs['current']['functions'][index])
            else:
                self.assertEqual(FUNCTIONS[node.name], 'f' + str(index))
        self.report['controller_sources'] = {name: _pin(value) for name, value in raw.items()}
        self.programs = {name: prepare_runtime_program(verify_program(doc))
                         for name, doc in docs.items()}
        return docs, raw

    def _freeze_reference(self):
        raw = (json.dumps({'planned': self.report['planned'],
                           'reference': self.report['reference']},
                          sort_keys=True, indent=2) + '\n').encode()
        path = self.evidence / 'reference-expectations.json'
        with path.open('xb') as stream:
            stream.write(raw)
        self.frozen_reference = raw
        self.report['reference_frozen_before_current'] = _pin(raw)

    def _compare(self):
        self.assertEqual((self.evidence / 'reference-expectations.json').read_bytes(),
                         self.frozen_reference)
        planned = self.report['planned']
        self.assertEqual([row['id'] for row in self.report['reference']], planned)
        self.assertEqual([row['id'] for row in self.report['current']], planned)
        differences = []
        for before, after in zip(self.report['reference'], self.report['current']):
            # The optimized program intentionally executes fewer instructions.
            # Actual ticks remain recorded and use the unchanged VM budget.
            left = {key: value for key, value in before.items() if key != 'steps'}
            right = {key: value for key, value in after.items() if key != 'steps'}
            if left != right:
                differences.append({'id': before['id'], 'reference': before, 'current': after})
        self.report['differences'] = differences
        self.report['counts'] = {'planned': len(planned),
            'reference': len(self.report['reference']), 'current': len(self.report['current']),
            'different': len(differences)}
        self.assertFalse(differences, 'complete Slot supplemental outcomes differ')
        self.report['status'] = 'PASS_SUPPLEMENTAL_SOURCE_CONTROL'

    def _helper(self, backend, case, shape='active-default'):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owner = _Owner(-1, bytearray.fromhex(case['buffer_hex']))
        view = _View(owner, case['view_mutable'])
        views = [view]
        if shape == 'active-read':
            view.mutable = False
        elif shape == 'active-mut':
            view.mutable = True
        elif shape == 'expired-view':
            view.active = False
        elif shape == 'expired-owner':
            owner.active = False
        elif shape == 'expired-parent':
            parent = _View(owner, True, False)
            view.parent = parent
            views.append(parent)
        elif shape == 'cyclic-view':
            view.parent = view
        buffer_arg = owner if shape == 'bare-owner' else object() if shape == 'invalid-buffer' else view
        index = 'invalid-index' if shape == 'bad-index' else int(case['index_u64'])
        arguments = [buffer_arg, index]
        if case['helper'] == 'set':
            arguments.append('invalid-value' if shape == 'bad-value' else int(case['value_u64']))
        if shape == 'missing-buffer':
            arguments = []
        elif shape == 'missing-index':
            arguments = [buffer_arg]
        elif shape == 'missing-value':
            arguments = arguments[:2]
        elif shape == 'extra-argument':
            arguments.append(91)
        machine = _Machine(self.programs[backend], *LIMITS)
        result = _outcome(machine, case['function'], arguments)
        return {'id': case['id'], 'case': case, 'shape': shape,
            'outcome': result, 'buffer_hex': bytes(owner.data).hex(),
            'owner_active': owner.active,
            'view_active': [item.active for item in views],
            'view_mutable': [item.mutable for item in views],
            'view_parent': ['owner' if item.parent is owner else
                            'self' if item.parent is item else
                            'view-' + str(views.index(item.parent)) for item in views],
            'resources': machine.resources(), 'steps': machine.steps}

    def test_00_exact_source_inverse_full_generation_and_original_profile(self):
        docs, raw = self._prepare()
        from tools import generate_hia_slot_operations as generator
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(render_assembly(generator.document()).encode(), raw['current'])
        self.assertLessEqual(len(raw['current']), 1 << 20)
        self.assertLessEqual(len(raw['current'].splitlines()), 16384)
        doc = docs['current']
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions']
                                 for block in fn['blocks']), 8192)
        for fn in doc['functions']:
            definitions = {value['name'] for value in fn['params']}
            self.assertLessEqual(len(fn['blocks']), 256)
            for block in fn['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                definitions.update(value['name'] for value in block['params'])
                definitions.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(definitions), 2048)
        self.report['status'] = 'PASS_SUPPLEMENTAL_SOURCE_PROFILE'

    def test_01_all_270_actual_old_and_new_helper_outcomes_and_partial_buffers(self):
        self._prepare()
        cases = json.loads(self.sources[FIXTURE])['cases']
        self.assertEqual(len(cases), 270)
        self.assertEqual([case['id'] for case in cases], ['word-%03d' % i for i in range(270)])
        self.report['planned'] = [case['id'] for case in cases]
        for case in cases:
            self.assertEqual(FUNCTIONS[case['helper']], case['function'])
            self.report['reference'].append(self._helper('reference', case))
        self._freeze_reference()
        for case in cases:
            self.report['current'].append(self._helper('current', case))
        self.report['actual_step_totals'] = {
            name: sum(row['steps'] for row in self.report[name])
            for name in ('reference', 'current')}
        self.assertLess(self.report['actual_step_totals']['current'],
                        self.report['actual_step_totals']['reference'])
        self._compare()

    def test_02_all_41_internal_borrow_and_argument_shape_outcomes(self):
        self._prepare()
        cases = []
        for helper in ('read_word', 'get', 'set'):
            kinds = RESOURCE_KINDS + (('missing-value', 'bad-value') if helper == 'set' else ())
            for shape in kinds:
                case = {'id': helper + '.' + shape, 'helper': helper,
                    'function': FUNCTIONS[helper],
                    'buffer_hex': bytes((19 + i * 37) % 256 for i in range(24)).hex(),
                    'index_u64': '0', 'value_u64': '9327626991827298072' if helper == 'set' else None,
                    'view_mutable': helper != 'read_word'}
                cases.append((case, shape))
        self.assertEqual(len(cases), 41)
        self.report['planned'] = [case['id'] for case, _ in cases]
        for case, shape in cases:
            self.report['reference'].append(self._helper('reference', case, shape))
        self._freeze_reference()
        for case, shape in cases:
            self.report['current'].append(self._helper('current', case, shape))
        self._compare()

    def _packet(self, backend, label, buffers):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owners = tuple(_Owner(-index - 1, bytearray(raw)) for index, raw in enumerate(buffers))
        views = tuple(_View(owner, index != 0) for index, owner in enumerate(owners))
        machine = _Machine(self.programs[backend], *LIMITS)
        result = _outcome(machine, 'f0', list(views))
        return {'id': label, 'before': [part.hex() for part in buffers],
            'outcome': result, 'buffers': [bytes(owner.data).hex() for owner in owners],
            'owner_active': [owner.active for owner in owners],
            'view_active': [view.active for view in views],
            'view_mutable': [view.mutable for view in views],
            'resources': machine.resources(), 'steps': machine.steps}

    def test_03_all_360_complete_packet_outcomes_across_fifteen_modes(self):
        from hepta import hia_slot_operations_protocol as p
        self._prepare()
        self.assertEqual(sorted(p.MODES.values()), list(range(1, 16)))
        self.report['planned'] = [
            'mode-%02d.%s' % (mode, kind) for mode in range(1, 16) for kind in PACKET_KINDS]
        cases = []
        def reference(mode, kind, words, state=None, sizes=(128, 96, 192)):
            label = 'mode-%02d.%s' % (mode, kind)
            state = bytes(192) if state is None else state
            buffers = (struct.pack('<16Q', *words)[:sizes[0]],
                       (b'O' * 96)[:sizes[1]], state[:sizes[2]])
            row = self._packet('reference', label, buffers)
            self.report['reference'].append(row)
            cases.append((label, buffers))
            self.assertEqual(row['outcome']['kind'], 'return')
            self.assertEqual(row['buffers'][0], buffers[0].hex())
            return row['outcome']['values'][0], bytes.fromhex(row['buffers'][1]), bytes.fromhex(row['buffers'][2])
        def accepted(code, result):
            return code == 96 and struct.unpack('<12Q', result)[1] == 0
        for mode in range(1, 16):
            request = [p.REQUEST_MAGIC, p.INITIALIZE, 0, 0, 0, mode, 17, 23, *([0] * 8)]
            code, result, state = reference(mode, 'valid-initialize', request)
            self.assertTrue(accepted(code, result))
            out = struct.unpack('<12Q', result)
            self.assertEqual(out[0], p.RESULT_MAGIC)
            self.assertEqual(out[4], p.ISSUED)
            claim = [p.REQUEST_MAGIC, p.CLAIM, out[3], out[2], 0, mode, 17, 23, *([0] * 8)]
            for kind, index, value in (
                    ('magic', 0, 0), ('sequence', 2, 9), ('port', 3, len(p.PORTS) + 1),
                    ('observation', 4, 1), ('mode', 5, mode % 15 + 1),
                    ('nonce-low', 6, 18), ('nonce-high', 7, 24), ('reserved', 15, 1)):
                changed = claim.copy()
                changed[index] = value
                code, result, _ = reference(mode, kind, changed, state)
                self.assertFalse(accepted(code, result))
            for index, sizes in enumerate(((127, 96, 192), (128, 95, 192), (128, 96, 191))):
                code, _, _ = reference(mode, 'short-buffer-' + str(index), request, sizes=sizes)
                self.assertNotEqual(code, 96)
            for offset in (0, 8, 16, 24, 40, 48, 80, 184):
                changed = bytearray(state)
                changed[offset] ^= 1
                code, result, _ = reference(mode, 'state-byte-' + str(offset), claim, bytes(changed))
                self.assertFalse(accepted(code, result))
            code, result, claimed = reference(mode, 'valid-claim', claim, state)
            self.assertTrue(accepted(code, result))
            self.assertEqual(struct.unpack('<12Q', result)[4], p.CLAIMED)
            ack = [p.REQUEST_MAGIC, p.SUCCEEDED, claim[2], claim[3], 0, mode, 17, 23, *([0] * 8)]
            code, result, advanced = reference(mode, 'valid-ack', ack, claimed)
            self.assertTrue(accepted(code, result))
            raised = ack.copy()
            raised[1] = p.RAISED
            code, result, _ = reference(mode, 'valid-raised', raised, claimed)
            self.assertTrue(accepted(code, result))
            code, result, _ = reference(mode, 'replayed-ack', ack, advanced)
            self.assertFalse(accepted(code, result))
        self.assertEqual(len(cases), 360)
        self.assertEqual([label for label, _ in cases], self.report['planned'])
        self._freeze_reference()
        for label, buffers in cases:
            self.report['current'].append(self._packet('current', label, buffers))
        self._compare()


if __name__ == '__main__':
    unittest.main()
