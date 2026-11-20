"""Full-buffer witnesses for fixed-word SHA stream access expansion.

The original HIA fixture is byte-for-byte from commit
a7710b5727cca43875357f92c6b83308046deb6e, Git blob
a6cf0c0dd43a804db8ff74f979cb0d4eff6b51d3. Independent VM observations of both
sources precede actual compilation. These finite witnesses do not assert an
all-input refinement proof or introduce a performance acceptance threshold.
Overlapping foreign pointer frames are separately labelled ABI stress cases;
they are not admitted affine Core callers or a broader public ownership claim.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program_runtime import HIAProgramTrap, _Machine, _Owner, _View
from hepta.hia_sha256_stream_native import NativeSha256Stream, SOURCE, STATE_BYTES, MAX_CHUNK, MAX_TOTAL
from tools.generate_hia_sha256_stream import MAGIC, document

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/sha256_stream_a7710b5.hepta.txt'
ORIGINAL_SHA256 = '5818184f4decbde6a56741238a9d017fda66a3ed41136f9ceb9533a81c552a20'
REJECTED = 0xfffffffd
COLD_REPORT = 'HEPTA_HIA_SHA256_STREAM_DIFFERENTIAL_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_SHA256_STREAM_DIFFERENTIAL_COMPILER'
COLD_INPUTS = (
    'examples/hia_bootstrap/sha256_stream.hepta',
    'examples/hia_bootstrap/selfhost.hepta',
    'tests/fixtures/sha256_stream_a7710b5.hepta.txt',
    'tests/test_hia_sha256_stream_transition_equivalence.py',
    'tools/generate_hia_sha256_stream.py', 'tools/generate_hia_sha256.py',
    'tools/generate_hia_selfhost.py', 'tools/qualify_hia_selfhost.py',
    'tools/build_hia_source_build.py', 'tools/build_hia_json_preflight.py',
    'hepta/hia_program.py', 'hepta/hia_program_runtime.py',
    'hepta/hia_agent_assembly.py', 'hepta/hia_sha256_stream_native.py',
)


def digest(raw):
    return sha256(raw).hexdigest()


def compiler_selection():
    cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT_COMPILER)
    if cold is not None and development is not None:
        raise ValueError('cold report and development compiler are mutually exclusive')
    if cold == '' or development == '':
        raise ValueError('explicit stream compiler selection must not be empty')
    return cold, development


def recheck_cold_binding(binding):
    if binding is None:
        return
    from tools.build_hia_json_preflight import current_sources
    if (binding['report_path'].read_bytes() != binding['report_bytes']
            or binding['nested_path'].read_bytes() != binding['nested_bytes']
            or binding['compiler_path'].read_bytes() != binding['compiler_bytes']
            or current_sources() != binding['sources']):
        raise ValueError('stream cold compiler, reports or complete source identity changed')


def bind_cold_compiler(report_path, captured):
    from tools.build_hia_json_preflight import admit_cold_build
    report_path = Path(report_path)
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    nested_path = Path(report['nested_report'])
    nested_bytes = nested_path.read_bytes()
    nested = json.loads(nested_bytes)
    compiler_path = Path(nested['generations'][-1]['produced_image'])
    compiler_bytes = compiler_path.read_bytes()
    sources = admit_cold_build(compiler_bytes, report_bytes)
    if any(sources.get(name) != digest(captured[name]) for name in COLD_INPUTS):
        raise ValueError('stream differential inputs are not bound by current cold source')
    binding = {'report_path': report_path, 'report_bytes': report_bytes,
               'nested_path': nested_path, 'nested_bytes': nested_bytes,
               'compiler_path': compiler_path, 'compiler_bytes': compiler_bytes,
               'sources': sources}
    recheck_cold_binding(binding)
    return binding


def programs(captured=None):
    original = FIXTURE.read_bytes() if captured is None else captured[FIXTURE.relative_to(ROOT).as_posix()]
    if digest(original) != ORIGINAL_SHA256:
        raise AssertionError('frozen original SHA stream HIA bytes changed')
    candidate = SOURCE.read_bytes() if captured is None else captured[SOURCE.relative_to(ROOT).as_posix()]
    return assemble_program(original), assemble_program(candidate)


def vm_frame(program, wire, output, state):
    roots = [_Owner(index + 1, bytearray(raw)) for index, raw in enumerate((wire, output, state))]
    machine = _Machine(program, 2_000_000, 32 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
                          [_View(root, index != 0) for index, root in enumerate(roots)])[0]
    return (code, *(bytes(root.data) for root in roots))


def vm_helper(program, function, state, *arguments):
    root = _Owner(1, bytearray(state))
    machine = _Machine(program, 2_000_000, 32 << 20, None, 128)
    try:
        result = machine.invoke(machine.functions[function], [_View(root, True), *arguments])
        outcome = ('returned', tuple(result))
    except HIAProgramTrap as error:
        outcome = ('trapped', error.code)
    return outcome, bytes(root.data)


def vm_alias_frame(program, buffers, aliases):
    roots = [_Owner(index + 1, bytearray(raw)) for index, raw in enumerate(buffers)]
    machine = _Machine(program, 2_000_000, 32 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
                          [_View(roots[index], argument != 0)
                           for argument, index in enumerate(aliases)])[0]
    return code, tuple(bytes(root.data) for root in roots)


def alias_witnesses(original, candidate):
    output = b'\xa5' * 41
    state = bytes((index * 131 + 91) & 255 for index in range(STATE_BYTES))
    initial = vm_frame(original, b'\x00', output, state)[3]
    all_alias_update = bytes([1]) + initial[1:]
    source_state_final = bytes([2]) + initial[1:]
    all_alias_reject = bytes([3]) + initial[1:]
    examples = (
        ('output-state-init', (b'\x00', state), (0, 1, 1), False),
        ('output-state-final', (b'\x02', initial), (0, 1, 1), False),
        ('source-output-update', (b'\x01' + bytes(range(40)), initial), (0, 0, 1), False),
        ('source-state-invalid-final-length', (source_state_final, output), (0, 1, 0), True),
        ('all-views-update', (all_alias_update,), (0, 0, 0), False),
        ('all-views-unknown-command', (all_alias_reject,), (0, 0, 0), True),
    )
    result = []
    for name, buffers, aliases, rejected in examples:
        old = vm_alias_frame(original, buffers, aliases)
        new = vm_alias_frame(candidate, buffers, aliases)
        if old != new:
            raise AssertionError('raw alias VM mismatch: ' + name)
        if rejected and old != (REJECTED, buffers):
            raise AssertionError('raw alias rejection changed shared storage: ' + name)
        result.append({'name': name, 'buffers': buffers, 'aliases': aliases,
                       'expected': old, 'rejected_before_writes': rejected})
    return result


def public_witnesses(original, candidate):
    cases = []
    untouched_output = b'\xa5' * 41
    patterned_state = bytes((index * 131 + 91) & 255 for index in range(STATE_BYTES + 17))

    def observe(name, wire, output, state, *, rejected=False, expected_digest=None):
        old = vm_frame(original, wire, output, state)
        new = vm_frame(candidate, wire, output, state)
        if old != new:
            raise AssertionError('independent full-buffer VM mismatch: ' + name)
        if old[1] != wire:
            raise AssertionError('stream changed read-only source: ' + name)
        if rejected and old != (REJECTED, wire, output, state):
            raise AssertionError('original invalid protocol did not refuse before every write: ' + name)
        if expected_digest is not None and (old[0] != 32 or old[2][:32] != expected_digest):
            raise AssertionError('independent standard SHA result differs: ' + name)
        cases.append({'name': name, 'wire': wire, 'output': output, 'state': state,
                      'expected': old, 'rejected_before_writes': rejected})
        return old

    initial = observe('initialize-patterned-storage', b'\x00', untouched_output, patterned_state)[3]
    for size, splits in ((0, ()), (55, (1, 54)), (56, (55, 1)), (63, (7, 56)),
                         (64, (1, 63)), (65, (63, 0, 2)), (120, (55, 1, 64)), (129, (64, 64, 1))):
        wire = bytes((index * 137 + 29) & 255 for index in range(size))
        state, output, position = initial, untouched_output, 0
        for index, count in enumerate(splits):
            chunk = wire[position:position + count]
            position += count
            result = observe(f'partition-{size}-{index}', b'\x01' + chunk, output, state)
            if result[0] != 0:
                raise AssertionError('valid partition rejected')
            output, state = result[2:]
        if position != size:
            raise AssertionError('partition does not cover its entire input')
        final = observe(f'padding-{size}', b'\x02', output, state, expected_digest=sha256(wire).digest())
        observe(f'after-finalization-{size}', b'\x02', final[2], final[3], rejected=True)

    # Private state is not an authenticated checkpoint. The public transition
    # validates the tag/phase/length relationship but accepts arbitrary full-u64
    # schedule/constants/chaining words. Preserve that complete accepted domain.
    for name, total, command in (
            ('full-word-update', 0, b'\x01' + bytes(range(64))),
            ('full-word-padding-55', (1 << 40) + 55, b'\x02'),
            ('full-word-padding-56', (1 << 40) + 56, b'\x02'),
            ('full-word-maximum-length', MAX_TOTAL, b'\x02')):
        state = bytearray(initial)
        for index in range(136):
            struct.pack_into('<Q', state, index * 8,
                             (0xfedcba9876543210 ^ (index * 0x0102030405060708)) & ((1 << 64) - 1))
        struct.pack_into('<QQQ', state, 1088, total, total & 63, 1)
        struct.pack_into('<Q', state, 1176, MAGIC)
        observe(name, command, untouched_output, bytes(state))

    for name, wire, output, state in (
            ('empty-command', b'', untouched_output, initial),
            ('long-init', b'\x00x', untouched_output, initial),
            ('long-final', b'\x02x', untouched_output, initial),
            ('unknown-command', b'\x03', untouched_output, initial),
            ('command-over-limit', b'\x01' + b'x' * (MAX_CHUNK + 1), untouched_output, initial),
            ('zero-output', b'\x02', b'', initial),
            ('short-output', b'\x02', untouched_output[:31], initial),
            ('short-state', b'\x00', untouched_output, initial[:STATE_BYTES - 1])):
        observe(name, wire, output, state, rejected=True)
    for name, offset, value in (
            ('bad-tag', 1176, MAGIC ^ (1 << 63)),
            ('phase-upper-word', 1104, (1 << 32) | 1),
            ('phase-finalized', 1104, 2),
            ('partial-upper-word', 1096, 1 << 32),
            ('partial-mismatch', 1096, 1),
            ('total-overflow', 1088, MAX_TOTAL + 1)):
        state = bytearray(initial)
        struct.pack_into('<Q', state, offset, value)
        observe(name, b'\x02', untouched_output, bytes(state), rejected=True)
    state = bytearray(initial)
    struct.pack_into('<QQ', state, 1088, MAX_TOTAL, 63)
    observe('update-total-overflow', b'\x01x', untouched_output, bytes(state), rejected=True)
    observe('maximum-empty-update', b'\x01', untouched_output, bytes(state))
    return cases


class Sha256StreamTransitionSourceTests(unittest.TestCase):
    def test_cold_and_development_selection_are_exclusive_and_empty_never_falls_back(self):
        with patch.dict(os.environ, clear=True), patch.object(Path, 'read_bytes', side_effect=AssertionError('selection must precede IO')):
            self.assertEqual(compiler_selection(), (None, None))
            for cold, development in (('cold.json', 'compiler.bin'), ('', 'compiler.bin'), ('cold.json', '')):
                with patch.dict(os.environ, {COLD_REPORT: cold, DEVELOPMENT_COMPILER: development}):
                    with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                        compiler_selection()
            for selector in (COLD_REPORT, DEVELOPMENT_COMPILER):
                with patch.dict(os.environ, {selector: ''}):
                    with self.assertRaisesRegex(ValueError, 'must not be empty'):
                        compiler_selection()

    def test_real_shared_gate_reads_last_nested_compiler_and_rejects_unqualified_report(self):
        from tools import build_hia_json_preflight as admission
        with tempfile.TemporaryDirectory(prefix='hia-stream-cold-refusal-') as temporary:
            folder = Path(temporary)
            first, last = folder / 'first.bin', folder / 'last.bin'
            first.write_bytes(b'nonexecuting first-image refusal witness')
            last.write_bytes(b'nonexecuting last-image refusal witness')
            nested = folder / 'nested.json'
            nested.write_text(json.dumps({'generations': [{'produced_image': str(first)}, {'produced_image': str(last)}]}))
            outer = folder / 'outer.json'
            outer.write_text(json.dumps({'schema': 'intentionally_unqualified_test_input', 'nested_report': str(nested)}))
            captured = {name: (ROOT / name).read_bytes() for name in COLD_INPUTS}
            with patch.object(admission, 'admit_cold_build', wraps=admission.admit_cold_build) as gate:
                with self.assertRaisesRegex(ValueError, 'completed matching native cold qualification'):
                    bind_cold_compiler(outer, captured)
            gate.assert_called_once_with(last.read_bytes(), outer.read_bytes())
            self.assertEqual(sorted(path.name for path in folder.iterdir()), ['first.bin', 'last.bin', 'nested.json', 'outer.json'])

    def test_readback_guard_refuses_report_compiler_or_complete_source_map_drift(self):
        # This only exercises negative byte/map comparisons. No successful cold
        # receipt is fabricated, admitted, compiled or executed by this control.
        from tools import build_hia_json_preflight as admission
        with tempfile.TemporaryDirectory(prefix='hia-stream-readback-refusal-') as temporary:
            folder = Path(temporary)
            binding = {'sources': {'observed_source': 'captured_digest'}}
            for name in ('report', 'nested', 'compiler'):
                path = folder / name
                raw = ('nonexecuting ' + name + ' readback witness').encode()
                path.write_bytes(raw)
                binding[name + '_path'], binding[name + '_bytes'] = path, raw
            with patch.object(admission, 'current_sources', return_value=binding['sources']):
                for name in ('report', 'nested', 'compiler'):
                    path = binding[name + '_path']
                    path.write_bytes(b'changed bytes')
                    with self.assertRaisesRegex(ValueError, 'complete source identity changed'):
                        recheck_cold_binding(binding)
                    path.write_bytes(binding[name + '_bytes'])
            with patch.object(admission, 'current_sources', return_value={'foreign_source': 'changed_digest'}):
                with self.assertRaisesRegex(ValueError, 'complete source identity changed'):
                    recheck_cold_binding(binding)

    def test_frozen_original_and_all_nonword_functions_are_identical(self):
        original, candidate = programs()
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        old, new = original.as_dict(), candidate.as_dict()
        self.assertEqual(old['functions'][:3], new['functions'][:3])
        self.assertEqual(len(old['functions']), 5)
        self.assertEqual(len(new['functions']), 5)
        for left, right in zip(old['functions'], new['functions']):
            self.assertEqual({key: value for key, value in left.items() if key != 'blocks'},
                             {key: value for key, value in right.items() if key != 'blocks'})

    def test_full_u64_word_helpers_and_partial_bounds_write_order(self):
        original, candidate = programs()
        values = (0, 255, 1 << 32, 1 << 63, (1 << 64) - 1, 0xfedcba9876543210)
        for value in values:
            wire = b'prefix' + struct.pack('<Q', value) + b'tail'
            wanted = (('returned', (value,)), wire)
            self.assertEqual(vm_helper(original, 'f3', wire, 6), wanted)
            self.assertEqual(vm_helper(candidate, 'f3', wire, 6), wanted)
            before = b'\xa5' * len(wire)
            wanted = (('returned', (0,)), before[:6] + struct.pack('<Q', value) + before[14:])
            self.assertEqual(vm_helper(original, 'f4', before, 6, value), wanted)
            self.assertEqual(vm_helper(candidate, 'f4', before, 6, value), wanted)
        for available in range(8):
            initial = b'\xa5' * (3 + available)
            for function, args in (('f3', (3,)), ('f4', (3, 0xfedcba9876543210))):
                before = vm_helper(original, function, initial, *args)
                after = vm_helper(candidate, function, initial, *args)
                self.assertEqual(before, after)
                self.assertEqual(after[0], ('trapped', 'bounds'))
                if function == 'f4':
                    self.assertEqual(after[1], initial[:3] + struct.pack('<Q', 0xfedcba9876543210)[:available])


class Sha256StreamTransitionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = compiler_selection()
        cls.before = {path.relative_to(ROOT).as_posix(): path.read_bytes()
                      for folder in ('hepta', 'tools') for path in (ROOT / folder).rglob('*.py')}
        for path in (SOURCE, FIXTURE, Path(__file__), ROOT / 'examples/hia_bootstrap/selfhost.hepta'):
            cls.before[path.relative_to(ROOT).as_posix()] = path.read_bytes()
        cls.cold_binding = None if cold is None else bind_cold_compiler(cold, cls.before)
        retained = os.environ.get('HEPTA_HIA_SHA256_STREAM_DIFFERENTIAL_EVIDENCE')
        cls.temporary = None
        if retained:
            cls.folder = Path(retained)
            cls.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-stream-transitions-')
            cls.folder = Path(cls.temporary.name)
        (cls.folder / 'source-before.json').write_text(json.dumps(
            {name: digest(raw) for name, raw in cls.before.items()}, indent=2, sort_keys=True) + '\n')
        checked = programs(cls.before)
        cls.cases = public_witnesses(*checked)
        cls.alias_cases = alias_witnesses(*checked)
        inputs = cls.folder / 'inputs'
        inputs.mkdir()
        independent = []
        for row in cls.cases:
            path = inputs / (row['name'] + '.bin')
            path.write_bytes(row['wire'])
            independent.append({'case': row['name'], 'input_sha256': digest(row['wire']),
                                'input_path': str(path), 'input_bytes': len(row['wire']),
                                'output_before_hex': row['output'].hex(), 'state_before_hex': row['state'].hex(),
                                'result_u64': row['expected'][0], 'output_hex': row['expected'][2].hex(),
                                'state_hex': row['expected'][3].hex(),
                                'rejected_before_writes': row['rejected_before_writes']})
        (cls.folder / 'independent-VM-before-native.json').write_text(json.dumps(independent, indent=2, sort_keys=True) + '\n')
        alias_reference = [{'case': row['name'], 'aliases': row['aliases'],
                            'owner_bytes_before_hex': [raw.hex() for raw in row['buffers']],
                            'result_u64': row['expected'][0],
                            'owner_bytes_after_hex': [raw.hex() for raw in row['expected'][1]],
                            'rejected_before_writes': row['rejected_before_writes'],
                            'scope': 'foreign pointer alias stress; not affine Core ownership admission'}
                           for row in cls.alias_cases]
        (cls.folder / 'independent-alias-VM-before-native.json').write_text(json.dumps(
            alias_reference, indent=2, sort_keys=True) + '\n')
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from tools.build_hia_source_build import _check_pack_output
        if cls.cold_binding is not None:
            cls.compiler = cls.cold_binding['compiler_path']
            cls.scope = 'MATCHING_SOURCE_COLD_COMPILER_WITH_PINNED_ORIGINAL_REFERENCE'
        elif development is not None:
            cls.compiler = Path(development)
            cls.scope = 'RETAINED_COMPILER_DEVELOPMENT_COMPONENT'
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            cls.compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            if first.read_bytes() != cls.compiler.read_bytes():
                raise AssertionError('actual development compiler fixed point differs')
            cls.scope = 'ISOLATED_CURRENT_SOURCE_BOOTSTRAP_COMPONENT'
        cls.compiler_bytes = (cls.compiler.read_bytes() if cls.cold_binding is None
                              else cls.cold_binding['compiler_bytes'])
        recheck_cold_binding(cls.cold_binding)
        cls.images = {}
        for label, path in (('original', FIXTURE), ('candidate', SOURCE)):
            source = cls.before[path.relative_to(ROOT).as_posix()]
            image, receipt = compile_stage(cls.folder, label, cls.compiler, source)
            full = (cls.folder / (label + '.output.bin')).read_bytes()
            checked = _check_pack_output(receipt, full, artifact=cls.compiler_bytes, source=source)
            if checked != image.read_bytes():
                raise AssertionError('actual compiled image differs from captured output')
            if (cls.compiler.read_bytes() != cls.compiler_bytes
                    or any((ROOT / name).read_bytes() != raw for name, raw in cls.before.items())):
                raise AssertionError('stream construction inputs changed before native mapping')
            recheck_cold_binding(cls.cold_binding)
            cls.images[label] = NativeSha256Stream(checked, digest(checked))
        cls.rows = []
        cls.alias_rows = []

    @classmethod
    def tearDownClass(cls):
        stable = (all((ROOT / name).read_bytes() == raw for name, raw in cls.before.items())
                  and cls.compiler.read_bytes() == cls.compiler_bytes)
        cold_error = None
        try:
            recheck_cold_binding(cls.cold_binding)
        except (OSError, ValueError) as error:
            stable = False
            cold_error = (type(error).__name__, str(error))
        report = {'scope': cls.scope, 'actualCold': cls.cold_binding is not None and stable,
                  'cold_report_selected': cls.cold_binding is not None,
                  'original_source_sha256': ORIGINAL_SHA256,
                  'original_fixture_is_production_source': False,
                  'candidate_source_sha256': digest(SOURCE.read_bytes()),
                  'cold_report_sha256': None if cls.cold_binding is None else digest(cls.cold_binding['report_bytes']),
                  'nested_report_sha256': None if cls.cold_binding is None else digest(cls.cold_binding['nested_bytes']),
                  'cold_source_manifest': None if cls.cold_binding is None else cls.cold_binding['sources'],
                  'cold_readback_error': cold_error,
                  'images': {name: image.image_sha256 for name, image in cls.images.items()},
                  'observations': cls.rows, 'foreign_alias_observations': cls.alias_rows,
                  'alias_stress_broadens_Core_ownership_domain': False,
                  'source_and_compiler_unchanged': stable,
                  'all_input_equivalence_proved': False, 'performance_threshold_added': False}
        (cls.folder / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('stream transition inputs changed')

    def native_frame(self, image, wire, output, state):
        guard = b'\x91\xd3\x4a\x68' * 4
        storage = [ctypes.create_string_buffer(guard + raw + guard, len(raw) + 32)
                   for raw in (wire, output, state)]
        code = image._entry(ctypes.byref(storage[0], 16), len(wire),
                            ctypes.byref(storage[1], 16), len(output),
                            ctypes.byref(storage[2], 16), len(state))
        for buffer in storage:
            self.assertEqual(buffer.raw[:16], guard)
            self.assertEqual(buffer.raw[-16:], guard)
        self.assertEqual(storage[0].raw[16:-16], wire)
        return (code, *(buffer.raw[16:-16] for buffer in storage))

    def compare(self, row):
        for label, image in self.images.items():
            actual = self.native_frame(image, row['wire'], row['output'], row['state'])
            self.assertEqual(actual, row['expected'], (row['name'], label))
            self.rows.append({'case': row['name'], 'image': label, 'result_u64': actual[0],
                              'input_bytes': len(actual[1]), 'input_sha256': digest(actual[1]),
                              'output_hex': actual[2].hex(), 'state_hex': actual[3].hex(),
                              'full_input_output_state_equal_VM': True, 'all_six_canaries_unchanged': True})

    def test_original_and_candidate_images_match_both_VMs_on_every_valid_transition(self):
        for row in self.cases:
            if not row['rejected_before_writes']:
                with self.subTest(case=row['name']):
                    self.compare(row)

    def test_all_original_protocol_refusals_leave_every_public_buffer_unchanged(self):
        for row in self.cases:
            if row['rejected_before_writes']:
                with self.subTest(case=row['name']):
                    self.compare(row)
                    self.assertEqual(row['expected'], (REJECTED, row['wire'], row['output'], row['state']))

    def test_foreign_pointer_alias_frames_preserve_complete_original_memory_effects(self):
        guard = b'\x91\xd3\x4a\x68' * 4
        for row in self.alias_cases:
            for label, image in self.images.items():
                with self.subTest(case=row['name'], image=label):
                    buffers = [ctypes.create_string_buffer(guard + raw + guard, len(raw) + 32)
                               for raw in row['buffers']]
                    arguments = []
                    for index in row['aliases']:
                        arguments.extend((ctypes.byref(buffers[index], 16), len(row['buffers'][index])))
                    code = image._entry(*arguments)
                    after = tuple(buffer.raw[16:-16] for buffer in buffers)
                    for buffer in buffers:
                        self.assertEqual(buffer.raw[:16], guard)
                        self.assertEqual(buffer.raw[-16:], guard)
                    self.assertEqual((code, after), row['expected'])
                    self.alias_rows.append({'case': row['name'], 'image': label, 'aliases': row['aliases'],
                                            'result_u64': code, 'owner_bytes_after_hex': [raw.hex() for raw in after],
                                            'complete_storage_equals_original_VM': True,
                                            'scope': 'foreign pointer alias stress; not affine Core ownership admission'})


if __name__ == '__main__':
    unittest.main()
