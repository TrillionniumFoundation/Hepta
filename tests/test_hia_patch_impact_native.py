"""Independent original/VM controls and real native patch impact callers."""
from __future__ import annotations

import copy
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_patch_impact as owner
from hepta import hia_patch_impact_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.test_hia_patch_impact import (append_wrapper, isolated_program,
    move_program, patch_initial_byte, patch_packet)
from tools import generate_hia_patch_impact as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/patch_impact_0daf86d.py.txt'
FIXTURE_SHA = 'b61710dc320c4b65206a2e6efed67ac525e900a782886be6c289e8acc681e3a1'


def original():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('frozen patch impact reference changed')
    scope = {'__name__': 'hepta._frozen_patch_impact', '__package__': 'hepta'}
    exec(compile(raw, str(FIXTURE), 'exec'), scope)
    return scope['analyze_patch_impact']


def facts(names, edges=()):
    values = {}
    for name in names:
        operations = [{'op': 'const', 'args': [], 'out': [{'name': 'r', 'type': 'u64'}],
                       'attrs': {'value': 1}}]
        operations += [{'op': 'call', 'args': [], 'out': [], 'attrs': {'function': callee}}
                       for caller, callee in edges if caller == name]
        values[name] = {'name': name, 'params': [], 'returns': ['u64'], 'effects': [],
            'entry': 'entry', 'blocks': [{'id': 'entry', 'params': [], 'ops': operations,
                                         'term': {'op': 'ret', 'values': ['r']}}]}
    return values


def reference(before, after, phase):
    changes, interfaces = owner._reference_changes(before, after)
    value = {'direct_changed_functions': changes, 'interface_changed_functions': interfaces}
    if phase:
        value.update(owner._reference_graph(before, after, changes))
    return value


def witnesses():
    before = facts(['z', 'a', '_', 'aa'], [('z', 'a'), ('aa', 'z'), ('z', 'a')])
    after = copy.deepcopy(before)
    after['a']['blocks'][0]['ops'][0]['attrs']['value'] = 7
    yield before, after
    # Removed edges retain the original callers and cycles terminate exactly.
    before = facts(['c', 'b', 'a', 'island'], [('c', 'b'), ('b', 'a'), ('a', 'b')])
    after = copy.deepcopy(before)
    after['b']['blocks'][0]['ops'] = after['b']['blocks'][0]['ops'][:1]
    yield before, after
    before = facts(['same'])
    after = facts(['new', 'same'], [('new', 'same')])
    yield before, after
    after = copy.deepcopy(before)
    after['same']['returns'] = []
    yield before, after
    yield before, copy.deepcopy(before)


def frame(image, raw, old, count, *, output_adjust=0, state_adjust=0):
    output_size, state_size = native.sizes(old, count)
    output_size += output_adjust
    state_size += state_adjust
    source = ctypes.create_string_buffer(raw, max(1, len(raw)))
    output = ctypes.create_string_buffer(b'\xa5' * (output_size + 16), output_size + 16)
    state = ctypes.create_string_buffer(state_size + 16)
    ctypes.memset(ctypes.addressof(state) + state_size, 0x91, 16)
    code = image._entry(source, len(raw), output, output_size, state, state_size)
    if (source.raw != (raw or b'\0') or output.raw[output_size:] != b'\xa5' * 16
            or state.raw[state_size:] != b'\x91' * 16):
        raise AssertionError('native patch impact changed facts or buffer canaries')
    return code, output.raw[:output_size], state.raw[:state_size]


def interpret(checked, raw, old, count):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    output_size, state_size = native.sizes(old, count)
    values = [_Owner(i + 1, bytearray(value)) for i, value in enumerate(
        (raw, b'\xa5' * output_size, bytes(state_size)))]
    machine = _Machine(checked, 50_000_000, 32 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'], [_View(value, i != 0) for i, value in enumerate(values)])[0]
    if bytes(values[0].data) != raw:
        raise AssertionError('independent VM changed input facts')
    return code, bytes(values[1].data), bytes(values[2].data)


class PatchImpactSourceTests(unittest.TestCase):
    def test_source_is_reproducible_and_within_unchanged_compiler(self):
        self.assertEqual(render_assembly(generator.document(generator.source(), 'patch_impact')), native.SOURCE.read_text())
        data = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(data['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in data['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in data['functions'] for b in f['blocks']), 8192)
        self.assertLessEqual(max(len(b['params']) for f in data['functions'] for b in f['blocks']), 16)
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA)

    def test_independent_vm_decides_sorted_changes_interfaces_and_closure(self):
        checked = assemble_program(native.SOURCE.read_bytes())
        for before, after in witnesses():
            for phase in (0, 1):
                code, output, _ = interpret(checked, native.packet(before, after, phase), len(before), len(after))
                self.assertEqual(code, 0)
                magic, count = struct.unpack_from('<2Q', output)
                self.assertEqual((magic, count), (native.RESULT_MAGIC, len(after)))
                records = [struct.unpack_from('<2Q', output, 16 + i * 16) for i in range(count)]
                names = [list(after)[index] for index, _ in records]
                self.assertEqual(names, sorted(after))
                expected = reference(before, after, phase)
                for bit, field in ((1, 'direct_changed_functions'), (2, 'interface_changed_functions')):
                    self.assertEqual([name for name, (_, flags) in zip(names, records) if flags & bit], expected[field])
                if phase:
                    self.assertEqual([name for name, (_, flags) in zip(names, records) if flags & 4],
                                     expected['potentially_affected_functions'])

    def test_default_preserves_original_public_report_and_exception(self):
        document = move_program()
        append_wrapper(document, 'wrapper', 'move_bytes')
        isolated_program(document)
        request = patch_packet(document, patch_initial_byte(document))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(native.SELECTOR, None)
            expected = original()(document, request)
            with patch('builtins.__import__', wraps=__import__) as imports:
                actual = owner.analyze_patch_impact(document, request)
            self.assertFalse(any('hia_patch_impact_native' in str(call) for call in imports.call_args_list))
        self.assertEqual(actual[0].canonical_bytes, expected[0].canonical_bytes)
        self.assertEqual(actual[1:], expected[1:])

    def test_empty_selector_is_refused_after_original_patch_admission(self):
        document = move_program()
        request = patch_packet(document, patch_initial_byte(document))
        with patch.dict(os.environ, {native.SELECTOR: ''}):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                owner.analyze_patch_impact(document, request)
            invalid = dict(request, expected_sha256='0' * 64)
            with self.assertRaisesRegex(ValueError, 'stale'):
                owner.analyze_patch_impact(document, invalid)


class PatchImpactNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_patch_impact import build
        evidence = os.environ.get('HEPTA_HIA_PATCH_IMPACT_EVIDENCE')
        cls.temp = None
        if evidence is not None:
            if not evidence:
                raise ValueError('patch impact evidence selector must not be empty')
            cls.root = Path(evidence)
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix='hia-patch-impact-')
            cls.root = Path(cls.temp.name)
        cold = os.environ.get('HEPTA_HIA_PATCH_IMPACT_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_PATCH_IMPACT_DEVELOPMENT_COMPILER')
        if cold is not None and development is not None:
            raise ValueError('select one patch impact compiler source')
        if cold is not None:
            if not cold:
                raise ValueError('patch impact cold selector must not be empty')
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        elif development is not None:
            if not development:
                raise ValueError('patch impact development compiler selector must not be empty')
            compiler = Path(development)
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
            seed, _ = build_seed(cls.root)
            compiler, _ = compile_stage(cls.root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
        cls.compiler, cls.compiler_bytes, cls.cold_report = compiler, compiler.read_bytes(), cold
        cls.manifest = build(cls.root / 'build', compiler, cold, development=cold is None)
        cls.image = native.installed_patch_impact(str(cls.manifest))
        cls.checked = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        same = cls.compiler.read_bytes() == cls.compiler_bytes
        (cls.root / 'component-custody.json').write_text(json.dumps({
            'schema': 'hepta.hia.patch-impact-test-custody.v1',
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'compiler_unchanged': same, 'manifest': str(cls.manifest),
            'matching_cold_report': cls.cold_report,
            'test_result_owned_by_outer_runner': True,
        }, indent=2, sort_keys=True) + '\n')
        if cls.temp is not None:
            cls.temp.cleanup()
        if not same:
            raise AssertionError('patch impact compiler changed during controls')

    def test_actual_machine_full_buffers_equal_independent_vm(self):
        for before, after in witnesses():
            for phase in (0, 1):
                raw = native.packet(before, after, phase)
                self.assertEqual(frame(self.image, raw, len(before), len(after)),
                                 interpret(self.checked, raw, len(before), len(after)))
                self.assertEqual(self.image.observe(before, after, phase=phase), reference(before, after, phase))

    def test_random_graphs_both_versions_cycles_and_duplicate_edges(self):
        rng = random.Random(402177)
        for _ in range(80):
            names = ['f' + str(i) for i in range(rng.randrange(1, 20))]
            rng.shuffle(names)
            before = facts(names, [(rng.choice(names), rng.choice(names)) for _ in range(40)])
            after = facts(names, [(rng.choice(names), rng.choice(names)) for _ in range(40)])
            for phase in (0, 1):
                self.assertEqual(self.image.observe(before, after, phase=phase), reference(before, after, phase))

    def test_exact_1024_function_limit_and_long_transitive_chain(self):
        names = ['f%04d' % i for i in range(1024)]
        before = facts(list(reversed(names)), [(names[i], names[i - 1]) for i in range(1, len(names))])
        after = copy.deepcopy(before)
        after[names[0]]['blocks'][0]['ops'][0]['attrs']['value'] = 9
        result = self.image.observe(before, after, phase=1)
        self.assertEqual(result, reference(before, after, 1))
        self.assertEqual(result['potentially_affected_functions'], names)
        invalid = facts(names + ['too_many'])
        with self.assertRaisesRegex(owner.HIAImpactRejected, 'invalid function inventory'):
            self.image.observe(invalid, invalid, phase=0)

    def test_truncation_large_counts_and_exact_buffer_refusals_preserve_canaries(self):
        before, after = next(witnesses())
        raw = native.packet(before, after, 1)
        for size in sorted(set([0, 1, 7, 16, 31, len(raw) - 1, *range(32, len(raw), 67)])):
            code, output, _ = frame(self.image, raw[:size], len(before), len(after))
            self.assertNotEqual(code, 0)
            self.assertEqual(output, b'\xa5' * len(output))
        for at in (0, 8, 16, 24, 32):
            changed = bytearray(raw)
            struct.pack_into('<Q', changed, at, (1 << 64) - 1)
            code, output, _ = frame(self.image, bytes(changed), len(before), len(after))
            self.assertNotEqual(code, 0)
            self.assertEqual(output, b'\xa5' * len(output))
        for output_delta, state_delta in ((-1, 0), (1, 0), (0, -1), (0, 1)):
            code, output, _ = frame(self.image, raw, len(before), len(after),
                                    output_adjust=output_delta, state_adjust=state_delta)
            self.assertEqual(code, 1)
            self.assertEqual(output, b'\xa5' * len(output))

    def test_removed_functions_and_unlisted_original_callee_refuse_in_order(self):
        before = facts(['a', 'b'], [('a', 'new')])
        after = facts(['a', 'new'])
        for phase in (0, 1):
            with self.assertRaisesRegex(owner.HIAImpactRejected, 'removed a function'):
                self.image.observe(before, after, phase=phase)
        after = facts(['a', 'b', 'new'])
        self.image.observe(before, after, phase=0)
        with self.assertRaisesRegex(owner.HIAImpactRejected, 'unlisted callee'):
            self.image.observe(before, after, phase=1)

    def test_selected_public_api_matches_frozen_original_without_python_graph(self):
        document = move_program()
        append_wrapper(document, 'wrapper', 'move_bytes')
        append_wrapper(document, 'top', 'wrapper')
        isolated_program(document)
        request = patch_packet(document, patch_initial_byte(document))
        expected = original()(document, request)
        with (patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}),
              patch.object(owner, '_reference_changes', side_effect=AssertionError('Python changes entered')),
              patch.object(owner, '_reference_graph', side_effect=AssertionError('Python graph entered')),
              patch.object(owner, '_incoming', side_effect=AssertionError('Python edges entered')),
              patch.object(owner, '_interface', side_effect=AssertionError('Python ABI comparison entered'))):
            actual = owner.analyze_patch_impact(document, request)
        self.assertEqual(actual[0].canonical_bytes, expected[0].canonical_bytes)
        self.assertEqual(actual[1:], expected[1:])

    def test_original_complete_patch_impact_module_with_reference_bodies_forbidden(self):
        suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_hia_patch_impact')
        expected = suite.countTestCases()
        with (patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}),
              patch.object(owner, '_reference_changes', side_effect=AssertionError('Python changes entered')),
              patch.object(owner, '_reference_graph', side_effect=AssertionError('Python graph entered'))):
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        self.assertEqual(result.testsRun, expected)
        self.assertFalse(result.errors or result.failures or result.skipped or result.expectedFailures or result.unexpectedSuccesses, stream.getvalue())

    def test_selected_missing_or_modified_source_never_falls_back(self):
        document = move_program()
        request = patch_packet(document, patch_initial_byte(document))
        with (patch.dict(os.environ, {native.SELECTOR: str(self.root / 'missing.json')}),
              patch.object(owner, '_reference_changes', side_effect=AssertionError('fallback entered'))):
            with self.assertRaises(OSError):
                owner.analyze_patch_impact(document, request)
        changed = self.root / 'changed-source.hepta'
        changed.write_bytes(native.SOURCE.read_bytes() + b'\n')
        with patch.object(native, 'SOURCE', changed):
            with self.assertRaisesRegex(ValueError, 'source'):
                native.installed_patch_impact(str(self.manifest))


if __name__ == '__main__':
    unittest.main()
