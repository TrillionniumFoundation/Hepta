"""Frozen runtime profile, independent Core VM, and actual HIA native owner."""
from __future__ import annotations

import ast
import builtins
import copy
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import hia_multiversion as owner
from hepta import hia_scalar_profile_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from tests.test_hia_program import arithmetic, b, branch, c, f, i, jump, m, ret
from tests.test_hia_program_composite import module, record
from tests.test_hia_scalar_totality import total_division
from tools import generate_hia_scalar_profile as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/scalar_profile_698cc280.py.txt'
FIXTURE_SHA = 'f209aa55c4c990c1e82699c71868c5365749ff424edc440afb52036ee9eb9c09'


def digest(raw):
    return sha256(raw).hexdigest()


def original_functions():
    raw = FIXTURE.read_bytes()
    if digest(raw) != FIXTURE_SHA:
        raise AssertionError('frozen original admission function changed')
    namespace = dict(vars(owner))
    exec(compile(raw, str(FIXTURE), 'exec'), namespace)
    original = namespace['_admit']
    text = raw.decode()
    begin = text.index('    if program.structured_bytes')
    end = text.index('    totality = []\n', begin)
    # The policy-only oracle is the verbatim original contiguous decision body.
    # It deliberately ends before totality and grants no proof authority.
    policy = 'def policy(program, data, *, prove_total=False):\n' + text[begin:end] + '    return abi\n'
    exec(compile(policy, str(FIXTURE) + ':policy-only', 'exec'), namespace)
    return original, namespace['policy']


def outcome(call):
    try:
        return ('returned', call())
    except Exception as error:
        cause = error.__cause__
        return ('raised', type(error).__name__, str(error),
                None if cause is None else (type(cause).__name__, str(cause)))


def serial(value):
    if isinstance(value, owner.ScalarABI):
        return {'function': value.function, 'parameters': list(value.parameters), 'result': value.result}
    if type(value) in (list, tuple):
        return [serial(item) for item in value]
    return value


def basic(name='calculate', typ='u64', parameters=1):
    params = [('x' + str(index), typ) for index in range(parameters)]
    return m(f(name, params, [typ], [], [b('entry', params, [], ret(params[0][0]))]))


def chain(count, *, cycle=False):
    blocks = []
    for index in range(count):
        name = 'b' + str(index)
        variable = 'x' + str(index)
        terminal = jump('b' + str(index + 1), variable) if index + 1 < count else ret(variable)
        blocks.append(b(name, [(variable, 'u64')], [], terminal))
    if cycle:
        blocks[-1]['term'] = jump('b1', 'x' + str(count - 1))
    return m(f('calculate', [('x0', 'u64')], ['u64'], [], blocks))


def repeated_operations(count):
    value = basic()
    value['functions'][0]['blocks'][0]['ops'] = [c('v' + str(index), 'u64', index) for index in range(count)]
    return value


def witnesses():
    samples = [('ordinary', basic(), False)]
    structured = module([record('Box', [('value', 'u64')])], f('unbox', [('box', 'Box')], ['u64'], [], [
        b('entry', [('box', 'Box')], [i('record.unpack', ['box'], [('value', 'u64')])], ret('value'))]))
    samples.append(('structured-record', structured, False))
    for version in (1, 7, 8):
        value = basic(); value['schema'] = 'hepta.hia.program.v' + str(version)
        samples.append(('version-' + str(version), value, False))
    value = basic('z'); value['functions'].append(basic('A')['functions'][0])
    samples.append(('ABI-sort', value, False))
    hidden = copy.deepcopy(value); hidden['exports'] = ['z']
    samples.append(('hidden-export', hidden, False))
    samples.append(('unit-signature', basic(typ='unit'), False))
    samples.append(('too-many-parameters', basic(parameters=17), False))
    value = basic(); value['functions'][0]['effects'] = ['trap']
    samples.extend([('trap-effect-default', value, False), ('trap-effect-proved-profile', value, True)])
    value = m(f('calculate', [('x', 'u64')], ['u64'], [], [
        b('entry', [('x', 'u64')], [c('never', 'bool', False)],
          branch('never', ('dead1', 'x'), ('done', 'x'))),
        b('dead1', [('p1', 'u64')], [], jump('dead2', 'p1')),
        b('dead2', [('p2', 'u64')], [], jump('dead1', 'p2')),
        b('done', [('answer', 'u64')], [], ret('answer'))]))
    samples.append(('unreachable-cycle', value, False))
    value = m(f('choose', [('flag', 'bool'), ('x', 'u64')], ['u64'], [], [
        b('entry', [('flag', 'bool'), ('x', 'u64')], [], branch('flag', ('done', 'x'), ('done', 'x'))),
        b('done', [('answer', 'u64')], [], ret('answer'))]))
    samples.append(('duplicate-branch-target', value, False))
    value = m(f('calculate', [('x', 'u64')], ['u64'], [], [
        b('unit_block', [('unused', 'unit')], [c('result', 'u64', 1)], ret('result')),
        b('entry', [('x', 'u64')], [c('u', 'unit', None)], jump('unit_block', 'u'))]))
    value['functions'][0]['entry'] = 'entry'
    samples.append(('unit-block-parameter', value, False))
    value = m(f('cast', [('x', 'u32')], ['u8'], ['trap'], [
        b('entry', [('x', 'u32')], [i('int.cast', ['x'], [('r', 'u8')], mode='checked')], ret('r'))]))
    samples.append(('checked-cast', value, True))
    for typ in ('u8', 'u16', 'u32', 'i8'):
        samples.append(('division-' + typ, total_division(typ), True))
    return samples


def interpret(checked, wire):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(raw)) for index, raw in enumerate(
        (wire, b'\xa5' * native.OUTPUT_BYTES, b'\0' * native.STATE_BYTES))]
    machine = _Machine(checked, 20_000_000, 32 << 20, None, 128)
    result = machine.invoke(machine.functions['f0'], [_View(value, index != 0) for index, value in enumerate(owners)])[0]
    if bytes(owners[0].data) != wire:
        raise AssertionError('VM changed verified facts')
    return result, bytes(owners[1].data), bytes(owners[2].data)


def decode(result, output, data):
    if result in native.REASONS:
        return ('raised', 'MultiversionRejected', 'E_HIA_MULTIVERSION: ' + native.REASONS[result], None)
    if result:
        raise AssertionError('valid Core facts were refused as transport')
    magic, count = struct.unpack_from('<2Q', output)
    if magic != native.RESULT_MAGIC or count != len(data['functions']):
        raise AssertionError('wrong native ABI inventory')
    indices = struct.unpack_from('<' + 'Q' * count, output, 16)
    functions = data['functions']
    return ('returned', tuple(owner.ScalarABI(functions[index]['name'],
                    tuple(p['type'] for p in functions[index]['params']), functions[index]['returns'][0]) for index in indices))


class ScalarProfileSourceTests(unittest.TestCase):
    def test_generated_source_preserves_existing_compiler_limits(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document(generator.source(), 'scalar_profile')))
        data = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(data['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in data['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in data['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in data['functions'] for block in fn['blocks']), 16)

    def test_frozen_reference_and_fresh_proof_tail_are_unchanged(self):
        original_functions()
        original = FIXTURE.read_text()
        current = Path(owner.__file__).read_text()
        start = original.index('    if program.structured_bytes')
        end = original.index('    totality = []\n', start)
        self.assertIn(original[start:end], current)
        old = ast.parse(original).body[0]
        new = next(node for node in ast.parse(current).body if isinstance(node, ast.FunctionDef) and node.name == '_admit')
        tail = next(index for index, node in enumerate(old.body) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'totality' for target in node.targets))
        new_tail = next(index for index, node in enumerate(new.body) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'totality' for target in node.targets))
        self.assertEqual([ast.dump(node, include_attributes=False) for node in old.body[tail:]],
                         [ast.dump(node, include_attributes=False) for node in new.body[new_tail:]])

    def test_independent_VM_matches_original_decision_and_ABI(self):
        checked = assemble_program(native.SOURCE.read_bytes())
        _, reference = original_functions()
        for name, value, prove_total in witnesses():
            with self.subTest(name=name):
                program = verify_program(value); data = program.as_dict()
                wire = native.packet(program, data, prove_total=prove_total)
                code, output, state = interpret(checked, wire)
                self.assertEqual(decode(code, output, data), outcome(lambda: reference(program, data, prove_total=prove_total)))
                if code:
                    self.assertEqual(output, b'\xa5' * native.OUTPUT_BYTES)

    def test_default_no_optional_import_and_actual_Core_failure_precedes_selection(self):
        original, _ = original_functions()
        real_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if 'hia_scalar_profile_native' in name:
                raise AssertionError('default imported native policy')
            return real_import(name, *args, **kwargs)
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            with patch('builtins.__import__', guarded):
                self.assertEqual(owner._admit(basic()), original(basic()))
        bad = basic(); bad['functions'][0]['blocks'][0]['term']['values'] = ['missing']
        forged = VerifiedProgram(json.dumps(bad).encode())
        with patch.dict(os.environ, {native.SELECTOR: 'must-not-be-opened'}), \
                patch.object(native, 'installed_scalar_profile', side_effect=AssertionError('Core must verify first')) as selected:
            with self.assertRaises(HIAProgramRejected):
                owner._admit(forged)
        selected.assert_not_called()


class ScalarProfileNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_scalar_profile import build
        cold = os.environ.get('HEPTA_HIA_SCALAR_PROFILE_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_SCALAR_PROFILE_DEVELOPMENT_COMPILER')
        if cold and development:
            raise ValueError('development compiler cannot replace matching cold custody')
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_SCALAR_PROFILE_EVIDENCE')
        if evidence:
            parent = Path(evidence); parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.root = parent / 'candidate'; cls.root.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-scalar-profile-')
            cls.root = Path(cls.temporary.name)
        cls.before = {path.relative_to(ROOT).as_posix(): path.read_bytes()
                      for folder in ('hepta', 'tools') for path in (ROOT / folder).rglob('*.py')}
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in',
                     'tests/test_hia_agent_installed_resources.py'):
            cls.before[name] = (ROOT / name).read_bytes()
        for path in (native.SOURCE, FIXTURE, Path(__file__), ROOT / 'tests/test_hia_program.py',
                     ROOT / 'tests/test_hia_program_composite.py',
                     ROOT / 'tests/test_hia_scalar_totality.py', ROOT / 'tests/test_hia_multiversion.py',
                     ROOT / 'tests/test_hia_native_profile_convergence.py'):
            cls.before[path.relative_to(ROOT).as_posix()] = path.read_bytes()
        (cls.root / 'source-before.json').write_text(json.dumps({name: digest(raw) for name, raw in cls.before.items()}, indent=2, sort_keys=True) + '\n')
        cls.checked = assemble_program(native.SOURCE.read_bytes())
        original, reference = original_functions()
        cls.original, cls.reference = staticmethod(original), staticmethod(reference)
        cls.references = []
        for name, value, prove_total in witnesses():
            program = verify_program(value); data = program.as_dict()
            wire = native.packet(program, data, prove_total=prove_total)
            code, output, state = interpret(cls.checked, wire)
            if decode(code, output, data) != outcome(lambda: reference(program, data, prove_total=prove_total)):
                raise AssertionError('independent original/VM mismatch before compiler build: ' + name)
            cls.references.append({'case': name, 'input_sha256': digest(wire), 'code': code,
                                   'output_hex': output.hex(), 'state_sha256': digest(state)})
        (cls.root / 'independent-reference.json').write_text(json.dumps(cls.references, indent=2, sort_keys=True) + '\n')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.scope = 'MATCHING_SOURCE_COLD_COMPONENT'
        elif development:
            compiler = Path(development); cls.scope = 'RETAINED_COMPILER_DEVELOPMENT_COMPONENT'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
            seed, _ = build_seed(cls.root)
            compiler, _ = compile_stage(cls.root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
            cls.scope = 'ISOLATED_CURRENT_SOURCE_BOOTSTRAP_COMPONENT'
        cls.compiler, cls.compiler_bytes = compiler, compiler.read_bytes()
        cls.manifest = build(cls.root / 'build', compiler, cold, development=not bool(cold))
        cls.image = native.installed_scalar_profile(str(cls.manifest))
        cls.rows = []
        cls.integration_rows = []

    @classmethod
    def tearDownClass(cls):
        unchanged = all((ROOT / name).read_bytes() == raw for name, raw in cls.before.items())
        unchanged = unchanged and cls.compiler.read_bytes() == cls.compiler_bytes
        report = {'schema': 'hepta.hia.scalar-profile-component.v1', 'scope': cls.scope,
                  'source_and_compiler_unchanged': unchanged, 'native_image_sha256': cls.image.image_sha256,
                  'observations': cls.rows, 'whole_stack_rewritten_in_hia': False,
                  'installation_and_scope_observations': cls.integration_rows,
                  'all_input_equivalence_proved': False}
        (cls.root / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not unchanged:
            raise AssertionError('scalar profile component inputs changed')

    def compare(self, value, prove_total=False):
        program = verify_program(value); data = program.as_dict()
        original = outcome(lambda: self.reference(program, data, prove_total=prove_total))
        actual = outcome(lambda: self.image.admit(program, data, prove_total=prove_total))
        self.assertEqual(actual, original)
        self.rows.append({'program_sha256': program.sha256, 'input_sha256': program.input_sha256,
                          'prove_total_profile_only': prove_total, 'outcome': serial(actual)})
        return actual

    def frame(self, wire):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(b'\xa5' * (native.OUTPUT_BYTES + 16))
        state = ctypes.create_string_buffer(native.STATE_BYTES + 16)
        ctypes.memset(ctypes.addressof(state) + native.STATE_BYTES, 0x91, 16)
        code = self.image._entry(source, len(wire), output, native.OUTPUT_BYTES, state, native.STATE_BYTES)
        self.assertEqual(source.raw[:len(wire)], wire)
        self.assertEqual(output.raw[native.OUTPUT_BYTES:native.OUTPUT_BYTES + 16], b'\xa5' * 16)
        self.assertEqual(state.raw[native.STATE_BYTES:], b'\x91' * 16)
        return code, output.raw[:native.OUTPUT_BYTES], state.raw[:native.STATE_BYTES]

    def test_actual_machine_full_buffers_equal_independent_VM_and_original(self):
        for name, value, prove_total in witnesses():
            with self.subTest(name=name):
                program = verify_program(value); data = program.as_dict()
                wire = native.packet(program, data, prove_total=prove_total)
                self.assertEqual(self.frame(wire), interpret(self.checked, wire))
                self.compare(value, prove_total)

    def test_original_function_block_instruction_and_signature_capacities(self):
        names = ['z', 'A', '_', 'a', 'aa', 'a0', 'a_', 'Z', '_A', '_z', 'b', 'b0', 'A0', 'AAA', 'z0', 'Z0']
        value = m(*(basic(name)['functions'][0] for name in names))
        self.assertEqual([entry.function for entry in self.compare(value)[1]], sorted(names))
        value['functions'].append(basic('seventeenth')['functions'][0])
        self.assertIn('one to sixteen', self.compare(value)[2])
        for value in (basic(parameters=16), chain(64), repeated_operations(2048)):
            self.assertEqual(self.compare(value)[0], 'returned')
        for value in (chain(65), repeated_operations(2049)):
            self.assertIn('finite block/instruction', self.compare(value)[2])
        self.rows.append({'capacity_controls': {'functions': 16, 'parameters': 16, 'blocks': 64,
                                                  'instructions': 2048, 'limits_unchanged': True}})

    def test_original_refusal_priority_all_functions_and_unreachable_CFG(self):
        value = repeated_operations(2049)
        value['functions'][0]['blocks'][0]['ops'][0] = c('v0', 'unit', None)
        self.assertIn('finite block/instruction', self.compare(value)[2])
        first = basic('first'); first['functions'][0]['effects'] = ['trap']
        resource = f('hidden', [('r', 'readbuf')], [], [], [b('entry', [('r', 'readbuf')], [], ret())])
        first['functions'].append(resource)
        self.assertIn('every function must be', self.compare(first)[2])
        first['schema'] = 'hepta.hia.program.v8'
        self.assertIn('qualified primitive', self.compare(first)[2])
        for name, value, prove_total in witnesses():
            if name in ('unreachable-cycle', 'duplicate-branch-target', 'hidden-export'):
                self.compare(value, prove_total)

    def test_every_original_scalar_ABI_and_checked_operation_profile(self):
        for typ in owner._CTYPES:
            self.assertEqual(self.compare(basic(typ=typ))[0], 'returned')
        for typ in ('u8', 'u16', 'u32', 'i8'):
            expected = 'returned' if typ in ('u8', 'u16') else 'raised'
            self.assertEqual(self.compare(total_division(typ), True)[0], expected)
            self.assertIn('effect-free', self.compare(total_division(typ), False)[2])
        self.assertIn('instruction may trap', self.compare(arithmetic('int.add.checked', 'u8'), True)[2])

    def test_selected_original_public_admission_never_enters_reference(self):
        expected = self.original(basic())
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('Python profile entered')):
            actual = owner._admit(basic())
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0].canonical_bytes, expected[0].canonical_bytes)
            with self.assertRaisesRegex(owner.MultiversionRejected, 'cyclic'):
                owner._admit(chain(2, cycle=True))

    def test_fresh_unknown_totality_never_becomes_native_proof_authority(self):
        from hepta import hia_scalar_totality as total
        source = total_division('u8')
        observed = []
        def unknown(program, *, function, timeout_ms):
            observed.append((program.sha256, program.input_sha256, function, timeout_ms))
            return {'status': 'unknown', 'solver': {'result': 'unknown'}}
        expected = verify_program(source)
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('Python profile entered')), \
                patch.object(total, 'validate_scalar_totality', side_effect=unknown), \
                patch.object(owner, 'build_program_native', side_effect=AssertionError('no native build after unknown')) as build:
            with self.assertRaisesRegex(owner.MultiversionRejected, 'fresh scalar totality'):
                owner._admit(source, prove_total=True, timeout_ms=137)
        self.assertEqual(observed, [(expected.sha256, expected.input_sha256, 'calculate', 137)])
        build.assert_not_called()
        self.rows.append({'controlled_unknown_proof_refused': True, 'fresh_call_identity': observed,
                          'actual_Z3_proof_claim': False})

    def test_actual_fresh_Z3_proofs_preserve_every_export_and_first_failure(self):
        import z3
        from hepta import hia_scalar_totality as total
        actual_validate = total.validate_scalar_totality
        first = total_division('u8')['functions'][0]
        first['name'] = 'A_first'
        last = total_division('u16')['functions'][0]
        last['name'] = 'z_last'
        good = m(last, first)
        bad = copy.deepcopy(good)
        trapping = arithmetic('int.div.checked', 'u8')['functions'][0]
        trapping['name'] = 'b_traps'
        bad['functions'].append(trapping)
        reports = []
        for name, value, expected_names in (
                ('all_exports', good, ['A_first', 'z_last']),
                ('first_failure', bad, ['A_first', 'b_traps'])):
            program = verify_program(value)
            observed_outcomes = []
            for implementation, call in (('frozen_original', self.original), ('selected_HIA', owner._admit)):
                proofs = []
                def observed(checked, *, function, timeout_ms):
                    self.assertIsInstance(checked, VerifiedProgram)
                    self.assertEqual((checked.sha256, checked.input_sha256),
                                     (program.sha256, program.input_sha256))
                    self.assertEqual(timeout_ms, 2000)
                    receipt = actual_validate(checked, function=function, timeout_ms=timeout_ms)
                    proofs.append(receipt)
                    return receipt
                with (patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}),
                      patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('no Python profile')),
                      patch.object(total, 'validate_scalar_totality', side_effect=observed)):
                    result = outcome(lambda: call(value, prove_total=True))
                self.assertEqual([proof['function'] for proof in proofs], expected_names)
                self.assertTrue(all(proof['solver']['version'] == z3.get_version_string() for proof in proofs))
                self.assertTrue(all(len(proof['solver']['identity']['library_sha256']) == 64 for proof in proofs))
                if name == 'all_exports':
                    self.assertEqual(result[0], 'returned', result)
                    checked, abi, frozen = result[1]
                    self.assertEqual(checked.canonical_bytes, program.canonical_bytes)
                    self.assertEqual([signature.function for signature in abi], expected_names)
                    self.assertEqual([json.loads(proof) for proof in frozen], proofs)
                    self.assertEqual([proof['status'] for proof in proofs], ['proved', 'proved'])
                    self.assertEqual([proof['solver']['result'] for proof in proofs], ['unsat', 'unsat'])
                    observed_outcomes.append((result[0], abi))
                else:
                    self.assertEqual(result[0], 'raised', result)
                    self.assertEqual([proof['status'] for proof in proofs], ['proved', 'disproved'])
                    self.assertEqual([proof['solver']['result'] for proof in proofs], ['unsat', 'sat'])
                    self.assertEqual(proofs[-1]['counterexample']['observation'],
                                     {'status': 'trapped', 'code': 'division_by_zero'})
                    observed_outcomes.append(result)
                reports.append({'case': name, 'implementation': implementation, 'proofs': proofs})
            self.assertEqual(observed_outcomes[0], observed_outcomes[1])
        (self.root / 'actual-fresh-totality.json').write_text(json.dumps(reports, indent=2, sort_keys=True) + '\n')
        self.rows.append({'actual_Z3_version': z3.get_version_string(),
                          'actual_fresh_proofs': sum(len(row['proofs']) for row in reports),
                          'all_exports_and_first_failure_match_original': True,
                          'runtime_Clang_build_or_current_cold_claim': False})

    def test_actual_public_metadata_refusal_precedes_deeper_fact_transport(self):
        values = [value for name, value, _ in witnesses() if name in ('structured-record', 'version-8', 'hidden-export')]
        values.append(m(*(basic('f' + str(index))['functions'][0] for index in range(17))))
        for value in values:
            expected = outcome(lambda: self.original(value))
            with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                    patch.object(native, 'packet', side_effect=AssertionError('metadata refusal read later facts')) as deep, \
                    patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('no fallback')):
                observed = outcome(lambda: owner._admit(value))
            self.assertEqual(observed, expected)
            self.assertEqual(observed[0], 'raised')
            deep.assert_not_called()
            self.rows.append({'actual_public_metadata_refusal': serial(observed),
                              'deeper_fact_transport_entered': False})

    def test_original_boundary_modules_under_selected_HIA_owner(self):
        from tests.test_hia_multiversion import MultiversionProfileTests
        from tests.test_hia_native_profile_convergence import NativeProfileBoundaryTests
        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(group)
                                   for group in (MultiversionProfileTests, NativeProfileBoundaryTests)])
        stream = io.StringIO()
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('Python profile entered')):
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        (self.root / 'original-boundaries.log').write_text(stream.getvalue())
        self.assertEqual(result.testsRun, 8)
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual((result.skipped, result.expectedFailures, result.unexpectedSuccesses), ([], [], []))

    def test_empty_missing_changed_source_and_bad_ABI_never_fall_back(self):
        with patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('no fallback')):
            for path, error in (('', ValueError), (str(self.root / 'missing.json'), FileNotFoundError)):
                with patch.dict(os.environ, {native.SELECTOR: path}), self.assertRaises(error):
                    owner._admit(basic())
            with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                    patch.object(Path, 'read_bytes', return_value=b'changed source'), \
                    self.assertRaisesRegex(ValueError, 'source identity'):
                owner._admit(basic())
        entry = self.image._entry
        def high_bits(*arguments):
            return entry(*arguments) | (1 << 32)
        program = verify_program(basic())
        with patch.object(self.image, '_entry', high_bits), self.assertRaisesRegex(RuntimeError, 'ABI'):
            self.image.admit(program, program.as_dict())

    def test_actual_compiler_receipt_pollution_cannot_publish_manifest(self):
        from tools import build_hia_scalar_profile as builder
        compile_stage = builder.compile_stage
        for key in ('abi_status', 'result_u64', 'source_sha256', 'output_sha256'):
            folder = self.root / ('refused-' + key)
            def changed(*args, **kwargs):
                image, receipt = compile_stage(*args, **kwargs)
                receipt = dict(receipt)
                receipt[key] = (1 if key == 'abi_status' else receipt['core_u32'] | (1 << 32)) if key in ('abi_status', 'result_u64') else '0' * 64
                return image, receipt
            with patch.object(builder, 'compile_stage', side_effect=changed), self.assertRaises(ValueError):
                builder.build(folder, self.compiler, development=True)
            self.assertFalse((folder / 'manifest.json').exists())
            self.assertFalse((folder / 'build.json').exists())

    def test_actual_installed_wheel_uses_HIA_and_refuses_warm_source_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        folder = self.root / 'installed-scalar-profile'
        folder.mkdir()
        source = folder / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

        def command(label, arguments):
            with (folder / (label + '.log')).open('xb') as output:
                result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=source,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, (folder / (label + '.log')).read_text())

        command('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
        archive, = (folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as handle:
            name, = (name for name in handle.getnames()
                     if name.endswith('/examples/hia_bootstrap/scalar_profile.hepta'))
            self.assertEqual(handle.extractfile(name).read(), native.SOURCE.read_bytes())
        command('wheel', ['-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation',
                          '--wheel-dir', folder / 'wheels', archive])
        wheel, = (folder / 'wheels').glob('*.whl')
        installed = folder / 'installed'
        command('install', ['-m', 'pip', 'install', '--no-index', '--no-deps', '--target', installed, wheel])
        value = basic('z_last')
        value['functions'].append(basic('A_first', typ='u8')['functions'][0])
        checked, abi, _ = self.original(value)
        request = folder / 'request.json'
        request.write_text(json.dumps({'program': value, 'expected': serial(abi),
                                       'program_sha256': checked.sha256}))
        script = r'''
import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta import hia_multiversion as public
from hepta import hia_scalar_profile_native as native
assert Path(public.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert native.SOURCE == Path(sys.argv[1]) / 'hepta/_data/examples/hia_bootstrap/scalar_profile.hepta'
request = json.loads(Path(sys.argv[3]).read_bytes())
os.environ[native.SELECTOR] = sys.argv[2]
image = native.installed_scalar_profile(sys.argv[2])
actual_entry = image._entry
native_results = []
def entry(*arguments):
    result = actual_entry(*arguments)
    native_results.append(result)
    return result
with (patch.object(public, '_reference_scalar_profile', side_effect=AssertionError('installed policy cannot fallback')),
      patch.object(image, '_entry', side_effect=entry)):
    program, abi, proofs = public._admit(request['program'])
    observed = [{'function': item.function, 'parameters': list(item.parameters), 'result': item.result} for item in abi]
    assert observed == request['expected'] and program.sha256 == request['program_sha256']
    assert proofs == () and native_results == [17, 0]
    source = native.SOURCE.read_bytes()
    refusals = []
    try:
        for replacement in (source + b'\n', None):
            if replacement is None:
                native.SOURCE.unlink()
            else:
                native.SOURCE.write_bytes(replacement)
            try:
                public._admit(request['program'])
            except (ValueError, FileNotFoundError) as error:
                refusals.append((type(error).__name__, str(error)))
            else:
                raise AssertionError('warm image concealed missing or changed package source')
    finally:
        native.SOURCE.write_bytes(source)
    assert refusals[0] == ('ValueError', 'native HIA JSON source identity mismatch')
    assert refusals[1][0] == 'FileNotFoundError'
    assert native_results == [17, 0]
print(json.dumps({'actual_ABI': observed, 'native_results': native_results,
                  'native_image_sha256': image.image_sha256,
                  'installed_source': str(native.SOURCE), 'warm_source_refusals': refusals,
                  'python_policy_fallback': False}, sort_keys=True))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed),
                                 str(self.manifest), str(request)], cwd=folder, capture_output=True, timeout=20)
        (folder / 'installed.stdout.bin').write_bytes(result.stdout)
        (folder / 'installed.stderr.bin').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.integration_rows.append({'case': 'actual-sdist-wheel-installed-scalar-profile',
            'wheel_sha256': digest(wheel.read_bytes()), 'observations': json.loads(result.stdout)})

    def test_actual_pinned_scope_rejects_other_thread_and_selection_drift(self):
        from hepta import hia_native_helpers as authority
        bundle = self.root / 'scalar-profile-helpers.json'
        bundle.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
            'abi': authority.ABI, 'helpers': [{'selector': native.SELECTOR,
                'manifest_path': self.manifest.relative_to(self.root).as_posix(),
                'manifest_sha256': digest(self.manifest.read_bytes())}]}))
        pin = digest(bundle.read_bytes())
        value = basic('z_last')
        value['functions'].append(basic('A_first', typ='u8')['functions'][0])
        expected = self.original(value)
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(owner, '_reference_scalar_profile', side_effect=AssertionError('pinned policy cannot fallback'))):
            with authority.native_helpers_scope(str(bundle), pin):
                self.assertEqual(owner._admit(value), expected)
                refused = []
                def wrong_owner():
                    try:
                        owner._admit(value)
                    except ValueError as error:
                        refused.append(str(error))
                worker = threading.Thread(target=wrong_owner)
                worker.start()
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(refused, ['native helper worker scope belongs to its original process and thread'])
                with patch.dict(os.environ, {native.SELECTOR: str(bundle)}):
                    with self.assertRaisesRegex(ValueError, 'outside the pinned worker bundle'):
                        owner._admit(value)
                    with self.assertRaisesRegex(ValueError, 'selection changed'):
                        authority.native_helpers_identity()
                self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': pin})
            self.assertNotIn(native.SELECTOR, os.environ)
            self.assertEqual(authority.native_helpers_identity(), {})
        self.integration_rows.append({'case': 'operator-pinned-scalar-profile-helper',
            'bundle_sha256': pin, 'actual_ABI': serial(expected[1]), 'foreign_thread_refused': True,
            'changed_selection_refused': True, 'terminal_selector_drift_refused': True,
            'environment_restored': True})


if __name__ == '__main__':
    unittest.main()
