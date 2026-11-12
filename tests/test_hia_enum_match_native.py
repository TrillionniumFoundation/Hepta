"""Complete native enum-match CFG, independent reference and actual effects."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.hia_enum_match_native import (SOURCE, SCHEMA, SELECTOR, MAGIC, ERRORS,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, NativeEnumMatch, packet,
    selected_enum_match, installed_enum_match)
from tests import test_hia_program_composite as fixtures
from tests.test_hia_program import b, f

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_ENUM_MATCH_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_ENUM_MATCH_DEVELOPMENT_MANIFEST'


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode()


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as error:
        return None, (error.code, str(error))


def scalar_program(variants=3, *, repeated=True):
    """Source aliases test carry deduplication and alias-aware inactive slots."""
    types = [fixtures.enum('Choice', [('v' + str(i), [('a', 'u32'), ('b', 'u32')])
                                     for i in range(variants)])]
    ops = [fixtures.i('enum.make', ['x', 'x' if repeated else 'y'],
                      [('choice', 'Choice')], variant='v0')]
    return fixtures.module(types, f('pick', [('x', 'u32'), ('y', 'u32')], ['u32'], ['trap'], [
        b('entry', [('x', 'u32'), ('y', 'u32')], ops,
          fixtures.match('choice', *[('v' + str(i), 'arm' + str(i), ['x', 'x'])
                                    for i in range(variants)])),
        *[b('arm' + str(i), [('a' + str(i), 'u32'), ('b' + str(i), 'u32'),
                            ('x' + str(i), 'u32'), ('z' + str(i), 'u32')],
            [fixtures.i('int.add.wrap', ['a' + str(i), 'b' + str(i)],
                        [('sum' + str(i), 'u32')])], fixtures.ret('sum' + str(i)))
          for i in range(variants)],
    ]))


class EnumMatchSourceTests(unittest.TestCase):
    def test_generator_verifies_and_preserves_compiler_profile(self):
        from tools import generate_hia_enum_match as generator
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        from hepta.hia_agent_assembly import render_assembly
        document = generator.document()
        self.assertEqual(render_assembly(document).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(document['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions']
                                 for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertEqual((generator.MAGIC, generator.INPUT_BYTES, generator.OUTPUT_BYTES,
                          generator.WORKSPACE_BYTES), (MAGIC, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES))
        verify_core(document)

    def test_selected_missing_image_does_not_fall_back(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_enum_match())
        with patch.dict(os.environ, {SELECTOR: '/missing-enum-match-manifest'}), patch.object(
                composite._Elaborator, '_reference_match', side_effect=AssertionError('host match called')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(fixtures.enum_owner_program())

    def test_transport_preserves_interning_without_expanding_nominal_keys(self):
        class ForbiddenKey:
            def __str__(self):
                raise AssertionError('native transport expanded a nominal display key')
            def __hash__(self):
                raise AssertionError('native transport hashed semantic type identity')
            def __eq__(self, other):
                raise AssertionError('native transport decided nominal type equality')
        record = composite._Type(ForbiddenKey(), 'record', ())
        enum = composite._Type(ForbiddenKey(), 'enum', ('u32',),
            variants=(('left', (('payload', record),)), ('right', (('payload', record),))))
        environment = {'value': composite._Value(enum, ('tag',))}
        data = packet(fixtures.match('value', ('left', 'target', []), ('right', 'target', [])),
                      environment, {'target': (('payload', record),)}, 0)
        self.assertIs(type(data), bytes)


class EnumMatchAdapterTests(unittest.TestCase):
    def test_malformed_native_result_and_input_mutation_refuse(self):
        def frame(payload, *, error=0, serial=4, magic=MAGIC, reserved=0):
            raw = wire(payload)
            return struct.pack('<8Q', magic, error, serial, len(raw), reserved, 0, 0, 0) + raw
        block = dict(id='h2internal_1', params=[], ops=[], term={'op': 'trap', 'code': 'user'})
        good = {'first': {'ops': [], 'term': {'op': 'trap', 'code': 'user'}}, 'blocks': [block, block]}
        invalid = [0, 0xfffffff1, frame(good, magic=0), frame(good, reserved=1),
            frame(good, error=99), frame(good, serial=8193), frame(good, serial=0),
            frame(good, error=1), frame(good, error=7), frame({'first': None, 'blocks': None}),
            frame(dict(good, decisions=[])), frame({'first': good['first'], 'blocks': []}),
            frame({'first': dict(good['first'], plan=[]), 'blocks': [block, block]})]
        for data in invalid:
            with self.subTest(data=repr(data)[:90]):
                image = object.__new__(NativeEnumMatch)
                def entry(source, size, output, capacity, workspace, workspace_size):
                    if type(data) is int:
                        return data
                    ctypes.memmove(output, data, len(data))
                    return len(data)
                image._entry = entry
                with self.assertRaises(HIAProgramRejected):
                    image.lower_packet(b'packet', serial=1)
        image = object.__new__(NativeEnumMatch)
        data = frame(good)
        def mutate(source, size, output, capacity, workspace, workspace_size):
            ctypes.memmove(source, b'x', 1)
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = mutate
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            image.lower_packet(b'packet', serial=1)


class EnumMatchNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development enum match cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-enum-match-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development)
            value = json.loads(supplied.read_bytes())
            name = value['image_path']
            assert type(name) is str and Path(name).name == name
            shutil.copyfile(supplied.parent / name, cls.folder / name)
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(supplied.read_bytes())
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='enum-match')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'enum-match', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_enum_match(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def test_independent_hia_vm_matches_actual_image_bytes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        owner = composite._Elaborator(scalar_program(1))
        typ = owner.types.resolve('Choice')
        scalar = owner.types.resolve('u32')
        environment = {'value': composite._Value(typ, ('tag', 'a', 'a')),
                       'a': composite._Value(scalar, ('a',))}
        signatures = {'target': (('one', scalar), ('two', scalar))}
        output = _Owner(-2, bytearray(OUTPUT_BYTES))
        workspace = _Owner(-3, bytearray(WORKSPACE_BYTES))
        for target, serial in [('target', 0), ('missing', 0), ('target', 8192)]:
            term = fixtures.match('value', ('v0', target, []))
            data = packet(term, environment, signatures, serial)
            source = _Owner(-1, bytearray(data))
            machine = _Machine(checked, 20_000_000, 128 << 20, None, 256)
            extent = machine.invoke(checked.as_dict()['functions'][0],
                [_View(source, False), _View(output, True), _View(workspace, True)])[0]
            self.assertTrue(64 <= extent <= OUTPUT_BYTES)
            native_source = ctypes.create_string_buffer(data)
            native_output = ctypes.create_string_buffer(OUTPUT_BYTES)
            native_workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
            native_extent = self.native._entry(native_source, len(data), native_output, OUTPUT_BYTES,
                                               native_workspace, WORKSPACE_BYTES)
            self.assertEqual(native_extent, extent)
            self.assertEqual(ctypes.string_at(native_output, extent), bytes(output.data[:extent]))
            self.assertEqual(bytes(source.data), data)

    def compare_at_actual_match(self, document, *, mutations=(), serials=(0, 8170, 8191, 8192)):
        """Observe real admitted environments; the unchanged old branch is oracle.

        Its closures retain the existing source/name/type/linear edge rules.
        Every comparison happens before the ordinary elaborator advances to
        another block, so no stale loop closure is used as an oracle.
        """
        observations = []
        native = self.native
        case = self
        reference = composite._Elaborator._reference_match

        def compare(owner, term, environment, signatures, current, result, value, edge):
            original_serial = owner.serial
            choices = [deepcopy(term)]
            for mutate in mutations:
                changed = deepcopy(term)
                mutate(changed)
                choices.append(changed)
            for changed in choices:
                for serial in serials:
                    owner.serial = serial
                    first, blocks = deepcopy(current), []
                    original_ops = len(first['ops'])
                    _, error = outcome(lambda: reference(owner, changed, environment, first, blocks, value, edge))
                    expected_serial = owner.serial
                    actual = native.lower(changed, environment, signatures, serial)
                    _, actual_error = outcome(actual.admit)
                    case.assertEqual((actual_error, actual.serial), (error, expected_serial),
                                     (changed, serial))
                    if error is None:
                        expected_first = {'ops': first['ops'][original_ops:], 'term': first['term']}
                        case.assertEqual(actual.first, expected_first)
                        case.assertEqual(actual.blocks, blocks)
                    observations.append((error[0] if error else None, serial, actual.serial))
            owner.serial = original_serial
            return reference(owner, term, environment, current, result, value, edge)

        with patch.object(composite._Elaborator, 'lower_enum_match', compare):
            verify_core(document)
        self.assertTrue(observations, 'fixture must actually reach enum match')
        return observations

    def test_all_composite_versions_exact_core_and_independent_vm_results(self):
        for version in range(1, 5):
            for factory, function, arguments in [
                (fixtures.enum_owner_program, 'choose', [(False, 0), (True, 7), (False, 7), (True, (1 << 64)-1)]),
                (scalar_program, 'pick', [(3, 9), (0xffffffff, 7)]),
            ]:
                document = factory(); document['schema'] = 'hepta.hia.composite.v' + str(version)
                before = deepcopy(document)
                with patch.dict(os.environ, {SELECTOR: ''}):
                    expected = verify_core(document)
                with self.selected(), patch.object(composite._Elaborator, '_reference_match',
                        side_effect=AssertionError('host match called')):
                    actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                self.assertEqual(document, before)
                for args in arguments:
                    for failure in (None, 1):
                        old = execute_program(expected, function, list(args), allocation_fail_at=failure)
                        new = execute_program(actual, function, list(args), allocation_fail_at=failure)
                        self.assertEqual(new, old)
                        self.assertEqual(new['resources']['live_owners'], 0)
                        self.assertEqual(new['resources']['live_local_loans'], 0)

    def test_native_type_session_and_match_compose_without_either_reference_owner(self):
        from tests import test_hia_composite_types_native as type_tests
        from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
        class TypeFixture(unittest.TestCase):
            pass
        self.addCleanup(TypeFixture.doClassCleanups)
        # A requested common cold qualification also binds this supporting
        # image. A development override still conflicts rather than winning.
        extra = {}
        if os.environ.get(COLD_REPORT) and not os.environ.get(type_tests.COLD_REPORT):
            extra[type_tests.COLD_REPORT] = os.environ[COLD_REPORT]
        with patch.dict(os.environ, extra):
            type_tests.CompositeTypesNativeTests.setUpClass.__func__(TypeFixture)
        for version in range(1, 5):
            document = fixtures.enum_owner_program()
            document['schema'] = 'hepta.hia.composite.v' + str(version)
            with patch.dict(os.environ, {SELECTOR: '', TYPE_SELECTOR: ''}):
                expected = verify_core(document)
            with patch.dict(os.environ, {SELECTOR: str(self.manifest),
                                         TYPE_SELECTOR: str(TypeFixture.manifest)}), patch.object(
                    composite, '_Types', side_effect=AssertionError('host nominal type owner called')), patch.object(
                    composite._Elaborator, '_reference_match', side_effect=AssertionError('host match called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))

    def test_original_first_errors_and_fresh_state_at_every_stage(self):
        def replace_first(key, value):
            return lambda term: term['cases'][0].__setitem__(key, value)
        mutations = [lambda term: term.__setitem__('extra', 1),
            lambda term: term.__setitem__('value', 17),
            lambda term: term.__setitem__('value', '__hia_reserved'),
            lambda term: term.__setitem__('value', 'h2internal_1'),
            lambda term: term.__setitem__('value', 'absent'),
            lambda term: term.__setitem__('cases', {}),
            lambda term: term['cases'][0].__setitem__('extra', 1),
            replace_first('variant', True), replace_first('variant', 'h2internal_5'),
            replace_first('args', None), replace_first('args', [False]),
            replace_first('args', ['h2internal_8']),
            lambda term: term['cases'].append(deepcopy(term['cases'][0])),
            lambda term: term['cases'].pop(), replace_first('variant', 'unlisted'),
            replace_first('target', 1), replace_first('target', 'h2internal_8'),
            replace_first('target', 'absent'), replace_first('args', ['absent']),
            replace_first('args', ['value']),
            lambda term: term['cases'][1].__setitem__('target', 'absent'),
            lambda term: term['cases'].reverse(),
        ]
        observed = self.compare_at_actual_match(fixtures.enum_owner_program(), mutations=mutations,
                                               serials=(0, 8170, 8191, 8192))
        categories = {row[0] for row in observed}
        self.assertTrue({'E_HIA_FORMAT', 'E_HIA_NAME', 'E_HIA_SSA', 'E_HIA_RESOURCE',
                         'E_HIA_CFG', 'E_HIA_LIMIT'} <= categories)

    def test_aliases_case_permutations_wide_variants_and_counter_boundaries(self):
        rng = random.Random(20261111)
        for index in range(18):
            document = scalar_program(rng.choice([1, 2, 3, 8, 16, 32]), repeated=bool(index % 2))
            rng.shuffle(document['functions'][0]['blocks'][0]['term']['cases'])
            self.compare_at_actual_match(document, serials=(rng.randrange(128), 8140, 8190, 8192))

    def test_linear_edge_duplicate_loss_type_and_consumed_refusals(self):
        changes = []
        source = fixtures.enum_owner_program()
        # Add an independent live owner to the matching block. Its omission
        # must precede edge type errors; duplication has its own earlier error.
        function = source['functions'][0]
        for block in function['blocks']:
            if block['id'] in {'left', 'right'}:
                block['ops'] += [fixtures.c(block['id'] + '_zero', 'usize', 0),
                    fixtures.i('buffer.try_new', [block['id'] + '_zero'],
                        [(block['id'] + '_extra', 'buffer'), (block['id'] + '_ok', 'bool')])]
                block['term']['args'].append(block['id'] + '_extra')
            elif block['id'] == 'inspect':
                block['params'].append({'name': 'extra', 'type': 'buffer'})
                for case in block['term']['cases']:
                    case['args'] = ['extra']
            elif block['id'] in {'yes', 'no'}:
                block['params'].append({'name': block['id'] + '_extra', 'type': 'buffer'})
                block['ops'].insert(0, fixtures.i('owner.drop', [block['id'] + '_extra']))
        mutations = [lambda term: term['cases'][0].__setitem__('args', []),
            lambda term: term['cases'][0].__setitem__('args', ['extra', 'extra']),
            lambda term: term['cases'][0].__setitem__('args', ['extra', 'value'])]
        observed = self.compare_at_actual_match(source, mutations=mutations, serials=(0, 8190))
        self.assertIn('E_HIA_RESOURCE', {row[0] for row in observed})
        # Retained ordinary rejection tests ensure source-level wrong nominal
        # payload and exhaustiveness failures still reach the actual route.
        name = 'test_exhaustive_match_rejects_missing_duplicate_and_wrong_nominal_payload'
        result = unittest.TestResult()
        with self.selected(), patch.object(composite._Elaborator, '_reference_match',
                side_effect=AssertionError('host match called')):
            fixtures.CompositeRejectionTests(name).run(result)
        self.assertEqual((result.errors, result.failures, result.skipped), ([], [], []))

    def test_private_loan_padding_and_consumed_state_preserve_first_error(self):
        # These intentionally altered admitted-state descriptors are private
        # ABI controls, not accepted source declarations. Public enum types
        # still prohibit loan payloads before the match owner is reached.
        reference = composite._Elaborator._reference_match
        observed = []
        case = self
        def compare(owner, term, environment, signatures, current, result, value, edge):
            matched = environment[term['value']]
            original_type, original_consumed = matched.typ, matched.consumed
            old_signature = signatures['yes']
            original_serial = owner.serial
            loan = owner.types.resolve('readbuf')
            original_variants = original_type.variants
            variants = ((original_variants[0][0], ((original_variants[0][1][0][0], loan),)),
                        original_variants[1])
            for consumed in (False, True):
                matched.typ = replace(original_type, flat=('u32', 'readbuf', 'buffer'), variants=variants)
                matched.consumed = consumed
                signatures['yes'] = ((old_signature[0][0], loan),)
                for serial in (0, 8170, 8191):
                    owner.serial = serial
                    first, blocks = deepcopy(current), []
                    _, expected_error = outcome(lambda: reference(owner, term, environment, first, blocks, value, edge))
                    expected_serial = owner.serial
                    actual = case.native.lower(term, environment, signatures, serial)
                    _, actual_error = outcome(actual.admit)
                    case.assertEqual((actual_error, actual.serial), (expected_error, expected_serial))
                    observed.append(actual.error)
            matched.typ, matched.consumed = original_type, original_consumed
            signatures['yes'] = old_signature
            owner.serial = original_serial
            return reference(owner, term, environment, current, result, value, edge)
        with patch.object(composite._Elaborator, 'lower_enum_match', compare):
            verify_core(fixtures.enum_owner_program())
        self.assertTrue({1, 6, 23} <= set(observed))

    def test_large_repeated_zero_width_and_scalar_targets_keep_original_limits(self):
        for zero_width, count, variants in [(True, 15000, 2), (False, 4096, 32)]:
            types = [fixtures.record('Empty', []),
                     fixtures.enum('Choice', [('v' + str(i), []) for i in range(variants)])]
            payload_type = 'Empty' if zero_width else 'u32'
            entry_ops = ([fixtures.i('record.make', [], [('item', 'Empty')])] if zero_width else
                         [fixtures.c('item', 'u32', 37)])
            entry_ops += [fixtures.i('enum.make', [], [('choice', 'Choice')], variant='v0')]
            document = fixtures.module(types, f('wide', [], ['u32'], ['trap'], [
                b('entry', [], entry_ops, fixtures.match('choice', *[
                    ('v' + str(i), 'target', ['item'] * count) for i in range(variants)])),
                b('target', [('p' + str(i), payload_type) for i in range(count)],
                  [fixtures.c('answer', 'u32', 37)], fixtures.ret('answer'))]))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_match',
                    side_effect=AssertionError('host match called')):
                actual = verify_core(document)
            self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
            self.assertEqual(execute_program(actual, 'wide', [])['result'], 37)

    def test_actual_native_machine_allocator_balance_and_invalid_discriminant(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        import resource
        cc = shutil.which('cc')
        self.assertIsNotNone(cc, 'native effect controls require the retained C toolchain')
        driver = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[16]; static size_t allocations, frees, refusals; static bool refuse;
void *__wrap_calloc(size_t n,size_t w){
  if(refuse){refuse=false;refusals++;return NULL;}
  void *p=__real_calloc(n,w);if(p){for(size_t i=0;i<16;i++)if(!live[i]){live[i]=p;allocations++;return p;}exit(80);}return p;
}
void __wrap_free(void *p){
  if(p){size_t i;for(i=0;i<16 && live[i]!=p;i++);if(i==16)exit(81);live[i]=NULL;frees++;}__real_free(p);
}
size_t choose(uint8_t,size_t);
int main(void){
  for(size_t flag=0;flag<2;flag++){
    if(choose(flag,7)!=7+(flag?0:10))return 82;
    refuse=true;if(choose(flag,7)!=(flag?0:10) || refuse)return 83;
    if(choose(flag,0)!=(flag?0:10))return 84;
  }
  for(size_t i=0;i<16;i++)if(live[i])return 85;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=frees || refusals!=2;
}
'''
        with self.selected(), patch.object(composite._Elaborator, '_reference_match',
                side_effect=AssertionError('host match called')):
            checked = verify_core(fixtures.enum_owner_program())
        object_file = self.folder / 'enum-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked,
                                output=object_file, kind='object', linker=cc)
        source, executable = self.folder / 'enum-effects.c', self.folder / 'enum-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(object_file),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        self.assertEqual((ran.returncode, ran.stderr), (0, b''), ran.stdout)
        values = [int(value) for value in ran.stdout.split()]
        self.assertEqual(values, [2, 2, 2])
        corrupted = checked.as_dict()
        for fn in corrupted['functions']:
            for block in fn['blocks']:
                if block['id'] in {'left', 'right'}:
                    for op in block['ops']:
                        if op['op'] == 'const' and op['out'][0]['type'] == 'u32':
                            op['attrs']['value'] = 99
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(corrupted, 'choose', [True, 7])
        self.assertEqual(caught.exception.code, 'user')
        bad_object = self.folder / 'bad-enum.o'
        bad_program = verify_core(corrupted)
        compile_program_machine(emit_program_machine(bad_program), program=bad_program,
                                output=bad_object, kind='object', linker=cc)
        bad_source, bad_exe = self.folder / 'bad-enum.c', self.folder / 'bad-enum'
        bad_source.write_text('#include <stddef.h>\n#include <stdint.h>\nsize_t choose(uint8_t,size_t);int main(void){return (int)choose(1,7);}\n')
        built = subprocess.run([cc, str(bad_source), str(bad_object), '-o', str(bad_exe)],
                               capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(bad_exe)], capture_output=True, timeout=30,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        self.assertEqual(ran.returncode, -6)

    def test_private_buffers_canaries_short_regions_and_concurrent_calls(self):
        from concurrent.futures import ThreadPoolExecutor
        owner = composite._Elaborator(scalar_program(1))
        typ = owner.types.resolve('Choice')
        scalar = owner.types.resolve('u32')
        env = {'value': composite._Value(typ, ('tag', 'a', 'a')),
               'a': composite._Value(scalar, ('a',))}
        signatures = {'target': (('one', scalar), ('two', scalar))}
        term = fixtures.match('value', ('v0', 'target', []))
        source_bytes = packet(term, env, signatures, 0)
        source = ctypes.create_string_buffer(source_bytes)
        output = ctypes.create_string_buffer(OUTPUT_BYTES + 32)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES + 32)
        ctypes.memset(ctypes.addressof(output) + OUTPUT_BYTES, 0xA7, 32)
        ctypes.memset(ctypes.addressof(workspace) + WORKSPACE_BYTES, 0xB9, 32)
        for oc, wc in [(OUTPUT_BYTES-1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES-1)]:
            self.assertEqual(self.native._entry(source, len(source_bytes), output, oc, workspace, wc), 0xfffffff1)
        extent = self.native._entry(source, len(source_bytes), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        self.assertGreater(extent, 64)
        self.assertEqual(ctypes.string_at(ctypes.addressof(output) + OUTPUT_BYTES, 32), b'\xa7'*32)
        self.assertEqual(ctypes.string_at(ctypes.addressof(workspace) + WORKSPACE_BYTES, 32), b'\xb9'*32)
        self.assertEqual(ctypes.string_at(source, len(source_bytes)), source_bytes)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.native.lower(term, env, signatures, 0), range(6)))
        self.assertTrue(all(result == results[0] for result in results))

    def test_installed_wheel_route_without_reference_or_authoring_modules(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/enum_match.hiaasm', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in (*names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels, installed = self.folder / 'wheels', self.folder / 'installed'
        built = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', str(wheels), str(source)], cwd=source, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.folder, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        child = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed enum match imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_enum_match_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host match called')
composite._Elaborator._reference_match=absent
try: result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','invalid installed code custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        data = self.folder / 'installed-input.json'
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest)})
        for factory in (fixtures.enum_owner_program, scalar_program):
            document = factory(); data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/enum_match.hiaasm'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original + b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'bad-manifest.json'; bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))


if __name__ == '__main__':
    unittest.main()
