"""Independent controls for the Bootstrap fixed eight-byte word expansion.

These controls retain the complete R18 controller as the loop-based reference.
They do not change the public VM, original component tests, finite inputs, or
their budgets. Root alone executes these supplemental Source controls.
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
GENERATOR = 'tools/generate_hia_service_bootstrap.py'
ORIGINAL_GENERATOR_SHA256 = 'db55c864f6f29837f7b90438ee2a3521850bdadf0b363ceb1726e79c4713cef6'
ORIGINAL_HIA_SHA256 = 'b0e512f4e444eec7715c0133177da66cc593364874a9de942da0e67d18ef4665'
BUDGET_GENERATOR_SHA256 = '039401b733d406fcf91e566942b4940a593f1c8e5561cd5ea3c035ba2862e882'
FIXTURE_SHA256 = '6d8cedbd84295b8011b7a2453be68057797a45d3a20d57b1bbc2427c1cc1557a'
LIMITS = (4_000_000, 16 << 20, None, 128)
EVIDENCE = 'HEPTA_HIA_SERVICE_BOOTSTRAP_FIXED_WORD_EVIDENCE'
ORIGINAL_HELPERS = {
    "read_word": "def read_word(s:readbuf, index:u64) -> u64:\n    value = 0\n    shift = 0\n    while shift < 8:\n        value = value | (byte(s, index + shift) << (shift * 8))\n        shift = shift + 1\n    return value\n",
    "get": "def get(w:mutbuf, index:u64) -> u64:\n    value = 0\n    shift = 0\n    while shift < 8:\n        value = value | (byte(w, index * 8 + shift) << (shift * 8))\n        shift = shift + 1\n    return value\n",
    "set": "def set(w:mutbuf, index:u64, value:u64) -> u64:\n    shift = 0\n    while shift < 8:\n        store(w, index * 8 + shift, value >> (shift * 8))\n        shift = shift + 1\n    return value\n"
}
PACKET_IDS = (
    'valid-initialize', 'magic', 'sequence', 'port', 'observation', 'mode',
    'nonce', 'reserved', 'short-buffer-0', 'short-buffer-1', 'short-buffer-2',
    'state-byte-0', 'state-byte-8', 'state-byte-16', 'state-byte-24',
    'state-byte-40', 'state-byte-48', 'state-byte-80', 'state-byte-184',
    'valid-claim', 'valid-ack', 'replayed-ack',
)


def _helper_text(source, name):
    lines = source.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines)
              if line.startswith('def ' + name + '(')]
    if len(starts) != 1:
        raise AssertionError('helper definition is not unique: ' + name)
    start = starts[0]
    end = start + 1
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
        'module': 'service_bootstrap', 'functions': functions})


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class ServiceBootstrapFixedWordSourceTests(unittest.TestCase):
    def setUp(self):
        self.assertNotIn('HEPTA_HIA_JSON_DECODE_MANIFEST', os.environ,
                         'independent Source controls require unselected decoding')

    def test_only_three_helpers_change_and_recover_the_complete_original_source(self):
        from tools import generate_hia_service_bootstrap as bootstrap
        from tools import generate_hia_execution_budget as budget
        raw = (ROOT / GENERATOR).read_bytes()
        self.assertEqual(sha256(_restore_helpers(raw.decode()).encode()).hexdigest(),
                         ORIGINAL_GENERATOR_SHA256)
        self.assertEqual(sha256((ROOT / 'tools/generate_hia_execution_budget.py').read_bytes()).hexdigest(),
                         BUDGET_GENERATOR_SHA256)
        current = bootstrap.source_program()
        reference = _restore_helpers(current)
        current_nodes = ast.parse(current).body
        reference_nodes = ast.parse(reference).body
        self.assertEqual([node.name for node in current_nodes],
                         [node.name for node in reference_nodes])
        changed = [a.name for a, b in zip(reference_nodes, current_nodes)
                   if ast.dump(a, include_attributes=False) != ast.dump(b, include_attributes=False)]
        self.assertEqual(changed, ['read_word', 'get', 'set'])
        for name in ORIGINAL_HELPERS:
            self.assertEqual(_helper_text(current, name),
                             _helper_text(budget.source_program(), name))
        self.assertEqual((ROOT / GENERATOR).read_bytes(), raw)

    def test_complete_independent_original_270_word_outcomes_and_partial_buffers(self):
        from tools import generate_hia_service_bootstrap as bootstrap
        from tools import generate_hia_execution_budget as budget
        from tools.qualify_hia_fixed_word_access import FIXTURE, helper_comparisons
        fixture = FIXTURE.read_bytes()
        self.assertEqual(sha256(fixture).hexdigest(), FIXTURE_SHA256)
        # Full text equality connects the actual three Bootstrap helper bodies
        # to the existing independent loop-reference matrix, including partial
        # writes on a trap and 64-bit wrapped indices. No old row is removed.
        for name in ORIGINAL_HELPERS:
            self.assertEqual(_helper_text(bootstrap.source_program(), name),
                             _helper_text(budget.source_program(), name))
        self.assertEqual(helper_comparisons('execution-budget'), 270)
        self.assertEqual(FIXTURE.read_bytes(), fixture)

    def test_all_original_22_packet_cases_compare_complete_old_and_new_vm_buffers(self):
        from hepta import hia_service_bootstrap_protocol as p
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_program import verify_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from hepta.hia_program_runtime_prepared import prepare_runtime_program
        from tools import generate_hia_service_bootstrap as generator
        captured = {name: (ROOT / name).read_bytes() for name in (
            GENERATOR, 'hepta/hia_service_bootstrap_protocol.py',
            'examples/hia_bootstrap/service_bootstrap.hepta',
            'hepta/hia_program_runtime.py', 'hepta/hia_program_runtime_prepared.py',
            'tests/hia_service_bootstrap_controls.py',
            'tests/test_hia_service_bootstrap_fixed_words.py')}
        root = os.environ.get(EVIDENCE)
        if root is not None:
            Path(root).mkdir(parents=True, exist_ok=True)
        evidence = Path(tempfile.mkdtemp(prefix='bootstrap-word-packets-', dir=root))
        report = {'schema': 'hepta.bootstrap-fixed-word-packets.v1',
            'status': 'HOLD', 'pid': os.getpid(), 'test_id': self.id(),
            'limits': list(LIMITS), 'planned_packet_ids': list(PACKET_IDS),
            'source_before': {name: _pin(raw) for name, raw in captured.items()},
            'rows': [], 'native_executed': False,
            'full_business_equivalence_claimed': False,
            'wall_time_target_claimed': False}
        try:
            current = generator.document()
            reference = _author(_restore_helpers(generator.source_program()))
            reference_raw = render_assembly(reference).encode()
            current_raw = render_assembly(current).encode()
            self.assertEqual(sha256(reference_raw).hexdigest(), ORIGINAL_HIA_SHA256)
            self.assertEqual(current_raw, captured['examples/hia_bootstrap/service_bootstrap.hepta'])
            names = [node.name for node in ast.parse(generator.source_program()).body]
            self.assertEqual(len(current['functions']), len(reference['functions']))
            for index, name in enumerate(names):
                if name not in ORIGINAL_HELPERS:
                    self.assertEqual(current['functions'][index], reference['functions'][index])
            report['controller_sources'] = {'reference': _pin(reference_raw),
                                            'current': _pin(current_raw)}
            programs = {name: prepare_runtime_program(verify_program(doc))
                        for name, doc in (('reference', reference), ('current', current))}
            def invoke(name, buffers):
                owners = tuple(_Owner(-index - 1, bytearray(raw))
                               for index, raw in enumerate(buffers))
                views = tuple(_View(owner, index != 0)
                              for index, owner in enumerate(owners))
                machine = _Machine(programs[name], *LIMITS)
                value = machine.invoke(machine.functions['f0'], list(views))[0]
                self.assertIs(type(value), int)
                return {'code': value, 'buffers': [bytes(owner.data).hex() for owner in owners],
                        'resources': machine.resources(),
                        'owner_active': [owner.active for owner in owners],
                        'view_active': [view.active for view in views],
                        'view_mutable': [view.mutable for view in views],
                        'steps': machine.steps}
            def direct(label, words, state_raw=None, sizes=(128, 96, 192)):
                raw = struct.pack('<16Q', *words)
                state_raw = bytes(192) if state_raw is None else state_raw
                buffers = (raw[:sizes[0]], (b'O' * 96)[:sizes[1]], state_raw[:sizes[2]])
                before = invoke('reference', buffers)
                after = invoke('current', buffers)
                report['rows'].append({'id': label, 'sizes': list(sizes),
                    'before': [part.hex() for part in buffers],
                    'reference': before, 'current': after})
                # Different authored instruction counts are recorded, not
                # normalized. Every actual instruction still uses old tick().
                self.assertEqual({k: v for k, v in before.items() if k != 'steps'},
                                 {k: v for k, v in after.items() if k != 'steps'}, label)
                self.assertEqual(bytes.fromhex(after['buffers'][0]), buffers[0])
                if label in ('valid-initialize', 'valid-claim', 'valid-ack'):
                    self.assertGreater(after['steps'], 0)
                    self.assertLess(after['steps'], before['steps'])
                return after['code'], bytes.fromhex(after['buffers'][1]), bytes.fromhex(after['buffers'][2])
            request = [p.REQUEST_MAGIC, p.INITIALIZE, 0, 0, 0, p.CLOSE, 17, 23, *([0] * 8)]
            code, result, state = direct('valid-initialize', request)
            self.assertEqual(code, 96)
            self.assertEqual(struct.unpack('<12Q', result)[1], 0)
            out = struct.unpack('<12Q', result)
            claim = [p.REQUEST_MAGIC, p.CLAIM, out[3], out[2], 0, p.CLOSE, 17, 23, *([0] * 8)]
            for label, index, value in (('magic', 0, 0), ('sequence', 2, 9), ('port', 3, 99),
                    ('observation', 4, 1), ('mode', 5, p.PROFILE), ('nonce', 6, 18), ('reserved', 15, 1)):
                changed = claim.copy()
                changed[index] = value
                code, result, _ = direct(label, changed, state)
                self.assertFalse(code == 96 and struct.unpack('<12Q', result)[1] == 0)
            for index, sizes in enumerate(((127, 96, 192), (128, 95, 192), (128, 96, 191))):
                code, _, _ = direct('short-buffer-' + str(index), request, sizes=sizes)
                self.assertNotEqual(code, 96)
            for offset in (0, 8, 16, 24, 40, 48, 80, 184):
                changed = bytearray(state)
                changed[offset] ^= 1
                code, result, _ = direct('state-byte-' + str(offset), claim, bytes(changed))
                self.assertFalse(code == 96 and struct.unpack('<12Q', result)[1] == 0)
            code, result, claimed = direct('valid-claim', claim, state)
            ack = [p.REQUEST_MAGIC, p.SUCCEEDED, claim[2], claim[3], 0, p.CLOSE, 17, 23, *([0] * 8)]
            code, result, advanced = direct('valid-ack', ack, claimed)
            code, result, _ = direct('replayed-ack', ack, advanced)
            self.assertFalse(code == 96 and struct.unpack('<12Q', result)[1] == 0)
            self.assertEqual([row['id'] for row in report['rows']], list(PACKET_IDS))
            self.assertEqual(len(report['rows']), 22)
            report['status'] = 'PASS_SUPPLEMENTAL_VM_PACKET_CONTROL'
        finally:
            after_sources = {name: (ROOT / name).read_bytes() for name in captured}
            report['source_after'] = {name: _pin(raw) for name, raw in after_sources.items()}
            stable = after_sources == captured
            report['source_stable'] = stable
            if not stable:
                report['status'] = 'HOLD_SOURCE_CHANGED'
            (evidence / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
            self.assertTrue(stable, 'supplemental control source changed')


if __name__ == '__main__':
    unittest.main()
