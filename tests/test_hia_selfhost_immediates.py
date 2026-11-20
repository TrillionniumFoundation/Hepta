"""Scalar immediates preserve typed values, CFG transfers and scratch reuse."""
from pathlib import Path
import ctypes
import hashlib
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import execute_program, HIAProgramRejected
from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_loans import reference_source
from tools.hia_selfhost_multi_results import _read_word, _write_results, _function, _call, cases as multi_cases
from tools.hia_selfhost_signed_cases import unbatched_cases, refusals

ROOT = Path(__file__).resolve().parents[1]


def sample(name, source, arguments, values, *, versions=None):
    result = {'id': name, 'source': source, 'source_hex': arguments.hex(),
              'initial_hex': 'a5' * (8 * len(values)), 'expected_result': 0,
              'expected_hex': b''.join((int(v) % (1 << 64)).to_bytes(8, 'little') for v in values).hex()}
    if versions is not None:
        result['versions'] = versions
    return result


def versioned_cases():
    rows = []
    for case in cases():
        for version in (8, 9):
            source = case['source'].replace('hepta.hia.program.v8', 'hepta.hia.program.v' + str(version), 1)
            rows.append({**case, 'id': case['id'] + '-v' + str(version), 'source': source, 'version': version})
    return rows


class ImmediateSourceTests(unittest.TestCase):
    def test_typed_literals_transfers_and_calls_match_independent_vm(self):
        fixtures = versioned_cases()
        self.assertEqual(len(fixtures), 206)
        self.assertEqual(len({row['source'] for row in fixtures}), 128)
        for case in fixtures:
            with self.subTest(case=case['id']):
                scalar = case.get('reference_scalar')
                if scalar is None:
                    source = reference_source(case).replace(b'hepta.hia.program.v8',
                        ('hepta.hia.program.v' + str(case['version'])).encode(), 1)
                    actual = execute_program(assemble_program(source), 'reference_entry', [])
                    expected = [case['expected_result'], *bytes.fromhex(case['expected_hex'])]
                else:
                    # Use the original 255-tail-call fixture's scalar VM entry:
                    # two wrapper frames would exceed its unchanged 256 limit.
                    actual = execute_program(assemble_program(case['source'].encode()),
                        scalar['entry'], scalar['arguments'])
                    expected = scalar['expected']
                self.assertEqual(actual['status'], 'returned')
                self.assertEqual(actual['values'], expected)

    def test_invalid_literal_types_and_widths_remain_rejected(self):
        observed = 0
        for case in refusals():
            for version in (8, 9):
                source = case['source'].replace('hepta.hia.program.v8', 'hepta.hia.program.v' + str(version), 1)
                with self.subTest(case=case['id'], version=version):
                    with self.assertRaises(HIAProgramRejected):
                        assemble_program(source.encode())
                    observed += 1
        self.assertEqual(observed, 36)

def cases():
    result = [row for row in unbatched_cases()
              if row['program'].endswith(('-literal', '-select', '-unit-tuple'))
              or row['program'] == 'unit-select-and-call']
    for typ, bits in [('u8', 8), ('u16', 16), ('u32', 32), ('u64', 64), ('usize', 64)]:
        for value in sorted({0, 1, 1 << (bits - 1), (1 << bits) - 1}):
            body = Body()
            literal = body.const(typ, value)
            returned = _write_results(body, [literal], [typ])
            source = HEADER + body.text() + '  ret(' + returned + ')\nend\n'
            result.append(sample(typ + '-literal-' + str(value), source, b'', [value]))
    for value in (False, True):
        body = Body()
        literal = body.const('bool', value)
        returned = _write_results(body, [literal], ['bool'])
        result.append(sample('bool-literal-' + str(value), HEADER + body.text() + '  ret(' + returned + ')\nend\n', b'', [value]))
    for start in range(0, 64, 16):
        values = [0, (1 << 64) - 1] + [1 << bit for bit in range(start, start + 16)]
        body = Body()
        literals = [body.const('u64', value) for value in values]
        returned = _write_results(body, literals, ['u64'] * len(values))
        result.append(sample('all-u64-bits-' + str(start), HEADER + body.text() + '  ret(' + returned + ')\nend\n', b'', values))
    body = Body()
    argument = _read_word(body, 'u64', 0)
    returned_value = body.value('u64', 'call', [argument], {'function': 'f1'})
    returned = _write_results(body, [returned_value], ['u64'])
    helper = _function('f1', ['u64'], ['u64'], '  v1:u64 = const() {"value":1}\n  v2:u64 = int.add.wrap(v0,v1)\n  v3:u64 = int.add.wrap(v2,v1)\n  ret(v3)\n')
    source = HEADER + body.text() + '  ret(' + returned + ')\nend\n' + helper
    for value in (0, 1, (1 << 64) - 3, (1 << 64) - 1):
        result.append(sample('function-constant-reset-' + str(value), source, value.to_bytes(8, 'little'), [(value + 2) % (1 << 64)]))
    for row in multi_cases():
        if row.get('program') not in {'pair-branch', 'pair-loop', 'pair-tail', 'triple-backward-call'}:
            continue
        if row['program'] == 'pair-tail' and row['arguments'][0] == 255:
            row = {**row, 'reference_scalar': {'entry': 'f1', 'arguments': row['arguments'], 'expected': row['expected_values']}}
        result.append(row)
        if row['program'] not in {'pair-loop', 'pair-tail'}:
            continue
        body = Body()
        count = _read_word(body, 'u8', 0)
        left = body.const('u64', row['arguments'][1])
        right = body.const('u64', row['arguments'][2])
        values = _call(body, ['u64', 'u64'], [count, left, right])
        returned = _write_results(body, values, ['u64', 'u64'])
        helpers = row['source'][row['source'].index('\nfn f1') + 1:]
        source = HEADER + body.text() + '  ret(' + returned + ')\nend\n' + helpers
        result.append(sample('constant-arguments-' + row['id'], source,
                             row['arguments'][0].to_bytes(8, 'little'), row['expected_values']))
        if 'reference_scalar' in row:
            result[-1]['reference_scalar'] = row['reference_scalar']
    return result


class ImmediateNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-constant-immediates-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        seed, _ = build_seed(cls.folder)
        compiler = seed
        images = []
        for generation, fill in ((1, 0xa5), (2, 0xff), (3, 0)):
            compiler, _ = compile_stage(cls.folder, 'B' + str(generation), compiler, compiler_source,
                image_format='seed-shared' if generation == 1 else 'flat-x86-64', workspace_fill=fill)
            images.append(compiler.read_bytes())
        if not images[0] == images[1] == images[2]:
            raise AssertionError('Fresh selfhost generations differ')
        cls.compiler, cls.compiler_bytes = compiler, images[-1]
        cls.fixtures = versioned_cases()
        cls.programs = {}
        for case in cls.fixtures:
            source = case['source'].encode()
            if source in cls.programs:
                continue
            folder = cls.folder / ('program-' + str(len(cls.programs)))
            folder.mkdir()
            checked = assemble_program(source)
            direct = folder / 'direct.so'
            machine = emit_program_machine(checked, foreign_buffer_exports=(('f0', 1 << 20),))
            compile_program_machine(machine, program=checked, output=direct, linker='ld')
            native, _ = compile_stage(folder, 'native', cls.compiler, source, workspace_fill=0xa5)
            cls.programs[source] = {'folder': folder, 'direct': direct, 'native': native,
                                    'expected_image': native.read_bytes()}

    def test_values_match_vm_oracles_and_independent_direct_backend(self):
        from tools.qualify_hia_selfhost import invoke
        observed = 0
        self.assertEqual(len(self.fixtures), 206)
        self.assertEqual(len(self.programs), 128)
        for index, case in enumerate(self.fixtures):
            program = self.programs[case['source'].encode()]
            for route in ('direct', 'native'):
                with self.subTest(case=case['id'], route=route):
                    result, output = invoke(program['folder'], route + '-run-' + str(index), program[route],
                        bytes.fromhex(case['source_hex']),
                        image_format='seed-shared' if route == 'direct' else 'flat-x86-64',
                        capacity=len(bytes.fromhex(case['initial_hex'])), workspace_size=64,
                        workspace_fill=0x5a, output_initial=bytes.fromhex(case['initial_hex']))
                    self.assertEqual(result['status'], 'returned')
                    self.assertIs(type(result['abi_status']), int)
                    self.assertEqual(result['abi_status'], 0)
                    self.assertEqual(result['core_u32'], case['expected_result'])
                    self.assertIs(result['source_unchanged'], True)
                    self.assertEqual(result['forbidden_compiler_modules_loaded'], [])
                    self.assertEqual(output.hex(), case['expected_hex'])
                    observed += 1
        self.assertEqual(observed, 412)
        self.assertEqual(self.compiler.read_bytes(), self.compiler_bytes)

    def test_reused_dirty_workspace_capacity_and_error_recovery(self):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_selfhost import CAPACITY, INVALID, NO_SPACE
        code = NativeHiaJsonImage(self.compiler_bytes, hashlib.sha256(self.compiler_bytes).hexdigest())
        left, right = b'\x63' * 32, b'\x37' * 32
        workspace = ctypes.create_string_buffer(left + b'\xff' * CAPACITY + right, CAPACITY + 64)
        workspace_address = ctypes.addressof(workspace) + 32
        observed = 0

        def call(label, source, capacity, expected_image=None, expected_status=None):
            nonlocal observed
            source_before = left + source + right
            source_buffer = ctypes.create_string_buffer(source_before, len(source_before))
            output_before = left + b'\xa5' * CAPACITY + right
            output = ctypes.create_string_buffer(output_before, len(output_before))
            status = code._entry(ctypes.addressof(source_buffer) + 32, len(source),
                ctypes.addressof(output) + 32, capacity, workspace_address, CAPACITY)
            with self.subTest(case=label):
                self.assertEqual(source_buffer.raw, source_before)
                self.assertEqual(workspace.raw[:32], left)
                self.assertEqual(workspace.raw[-32:], right)
                expected_output = output_before
                if expected_image is not None:
                    expected_status = len(expected_image)
                    expected_output = left + expected_image + b'\xa5' * (CAPACITY - len(expected_image)) + right
                self.assertEqual(status, expected_status)
                self.assertEqual(output.raw, expected_output)
                observed += 1

        requested = ['all-u64-bits-0-v9', 'function-constant-reset-0-v8',
            'all-u64-bits-16-v9', 'constant-arguments-pair-loop-3-v8',
            'i64-literal-0-v9', 'u64-literal-18446744073709551615-v8',
            'unit-select-and-call-0-v9', 'unit-select-and-call-1-v8']
        selected = {row['id']: row for row in self.fixtures if row['id'] in requested}
        self.assertEqual(set(selected), set(requested))

        def expected(case):
            return self.programs[case['source'].encode()]['expected_image']

        for name in requested:
            case = selected[name]
            source, image = case['source'].encode(), expected(case)
            call(name + '-full', source, CAPACITY, expected_image=image)
            call(name + '-exact', source, len(image), expected_image=image)
            call(name + '-one-short', source, len(image) - 1, expected_status=NO_SPACE)
            call(name + '-zero', source, 0, expected_status=NO_SPACE)
        for index, name in enumerate(list(reversed(requested)) + requested):
            case = selected[name]
            call(name + '-reorder-' + str(index), case['source'].encode(), CAPACITY, expected_image=expected(case))
        for index, case in enumerate(refusals()):
            for version in (8, 9):
                source = case['source'].replace('hepta.hia.program.v8', 'hepta.hia.program.v' + str(version), 1).encode()
                call(case['id'] + '-refusal-v' + str(version), source, CAPACITY, expected_status=INVALID)
                recovery = selected[requested[(index + version) % len(requested)]]
                call(case['id'] + '-recovery-v' + str(version), recovery['source'].encode(), CAPACITY,
                     expected_image=expected(recovery))
        self.assertEqual(observed, 120)
        self.assertEqual(self.compiler.read_bytes(), self.compiler_bytes)
