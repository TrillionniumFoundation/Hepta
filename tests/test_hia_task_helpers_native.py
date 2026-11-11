"""Complete task-helper native generation, exact refusal state and installation."""
from __future__ import annotations

from copy import deepcopy
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
from hepta.hia_task_helpers_native import (MAGIC, SOURCE, SCHEMA, SELECTOR, ERRORS,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, NativeTaskHelpers, installed_task_helpers,
    selected_task_helpers, packet)
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_composite_v6_resources as resources
from tests.test_hia_program import b, f

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_TASK_HELPERS_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST'
OPERATIONS = ('start', 'poll', 'cancel', 'join', 'close')
FACTORIES = (fixtures.task_program, fixtures.scalar_task_program, fixtures.owned_result_task_program,
             partials.task_partial_program, loans.task_program, resources.composite_range_task_program)


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode()


def outcome(owner, typ, operation, *, reference=False):
    try:
        value = (owner._reference_helper if reference else owner.helper)(typ, operation)
        error = None
    except HIAProgramRejected as exc:
        value, error = None, (exc.code, str(exc))
    return value, error, owner.serial, deepcopy(owner.helpers), dict(owner.helper_names)


def helper_owner(state_types, result_types, *, reverse=False, serial=0, effects=()):
    """Test-only direct-helper descriptor graph, including unreachable loan padding.

    These are not accepted source declarations or qualification manifests. The
    public type owner separately prohibits retained task loans. They preserve
    the old helper's direct-call refusal and partially updated object state.
    """
    def record(name, types):
        return composite._Type(name, 'record', tuple(types))
    state, result = record('State', state_types), record('Result', result_types)
    variants = [('pending', (('state', state),)), ('ready', (('result', result),))]
    if reverse:
        variants.reverse()
    step = composite._Type('Step', 'enum', ('u32',) + tuple(
        item for _, fields in variants for _, typ in fields for item in typ.flat), variants=tuple(variants))
    task = composite._Type('Task', 'task', ('u8', 'buffer') + state.flat + result.flat,
        state=state, result=result, poll='poll', cancel='cancel', linear=True)
    owner = object.__new__(composite._Elaborator)
    owner.native_types = None
    owner.serial, owner.helper_names, owner.helpers = serial, {}, []
    owner.functions = {'poll': {'effects': list(effects)}, 'cancel': {'effects': list(reversed(effects))}}
    owner.signatures = {'poll': ((('state', state),), (step,)), 'cancel': ((('state', state),), ())}
    return owner, task


def maximum_program():
    """Publicly valid 512-slot task, 510 buffer result and maximum source names."""
    poll, cancel = 'P' + 'a' * 127, 'C' + 'a' * 127
    types = [fixtures.record('Empty', []),
        fixtures.record('Chunk', [('f' + str(i), 'buffer') for i in range(64)]),
        fixtures.record('Tail', [('f' + str(i), 'buffer') for i in range(62)]),
        fixtures.record('Dense', [('c' + str(i), 'Chunk') for i in range(7)] + [('tail', 'Tail')]),
        fixtures.enum('Step', [('pending', [('state', 'Empty')]), ('ready', [('result', 'Dense')])]),
        dict(name='Task', params=[], kind='task', state='Empty', result='Dense', poll=poll, cancel=cancel)]
    effects = ['write', 'trap', 'read', 'alloc']
    return fixtures.module(types,
        f(poll, [('state', 'Empty')], ['Step'], effects,
          [b('entry', [('state', 'Empty')], [], {'op': 'trap', 'code': 'user'})]),
        f(cancel, [('state', 'Empty')], [], effects,
          [b('entry', [('state', 'Empty')], [], fixtures.ret())]))


def frame(helper=None, *, error=0, serial=1, name=1, magic=MAGIC, reserved=0, payload=None):
    if payload is None:
        payload = wire({'helper': helper})
    return struct.pack('<8Q', magic, error, serial, name, len(payload), reserved, 0, 0) + payload


class TaskHelpersSourceTests(unittest.TestCase):
    def test_exact_generator_and_unchanged_compiler_profile_limits(self):
        from tools import generate_hia_task_helpers as generator
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        from hepta.hia_agent_assembly import render_assembly
        value = generator.document()
        self.assertEqual(render_assembly(value).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(value['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in value['functions']
                                 for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertEqual((generator.MAGIC, generator.INPUT_BYTES, generator.OUTPUT_BYTES,
                          generator.WORKSPACE_BYTES), (MAGIC, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES))
        verify_core(value)

    def test_selected_missing_manifest_never_uses_reference_helper(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_task_helpers())
        owner, typ = helper_owner([], [])
        with patch.dict(os.environ, {SELECTOR: '/not-a-task-helper-manifest'}), patch.object(
                composite._Elaborator, '_reference_helper', side_effect=AssertionError('host helper called')):
            with self.assertRaises(HIAProgramRejected):
                owner.helper(typ, 'start')
        self.assertEqual((owner.serial, owner.helper_names, owner.helpers), (0, {}, []))


class TaskHelpersAdapterTests(unittest.TestCase):
    def test_strict_frame_payload_and_fresh_state_refuse_without_fallback(self):
        function = dict(name='h2internal_1', params=[], returns=[], effects=[], entry='h2internal_2', blocks=[])
        valid = frame(function, serial=2)
        malformed = [0, 0xfffffff1, frame(function, magic=0), frame(function, reserved=1),
            frame(function, error=9), frame(function, serial=8193), frame(function, name=2),
            frame(function, serial=0), frame(function, error=1, serial=2),
            frame(function, error=2), frame(payload=b'{"helper":null,"helper":null}'),
            frame(payload=wire({'helper': function, 'plan': []})),
            frame(payload=wire({'helper': dict(function, extra=True)}))]
        for data in malformed:
            with self.subTest(frame=repr(data)[:80]):
                image = object.__new__(NativeTaskHelpers)
                def entry(source, size, output, capacity, workspace, workspace_size):
                    if isinstance(data, int):
                        return data
                    ctypes.memmove(output, data, len(data))
                    return len(data)
                image._entry = entry
                with self.assertRaises(HIAProgramRejected):
                    image.generate_packet(b'packet', serial=0)
        image = object.__new__(NativeTaskHelpers)
        def mutate(source, size, output, capacity, workspace, workspace_size):
            ctypes.memmove(source, b'x', 1)
            ctypes.memmove(output, valid, len(valid))
            return len(valid)
        image._entry = mutate
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            image.generate_packet(b'packet', serial=0)


class TaskHelpersNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development task helpers cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-task-helpers-')
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
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='task-helpers')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'task-helpers', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_task_helpers(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def test_five_helpers_complete_objects_fresh_order_and_cache_match(self):
        for factory in FACTORIES:
            document = factory()
            for declaration in document['types']:
                if declaration['kind'] != 'task':
                    continue
                for operation in OPERATIONS:
                    for serial in (0, 23, 8150, 8191, 8192):
                        with self.subTest(factory=factory.__name__, op=operation, serial=serial):
                            old = composite._Elaborator(deepcopy(document))
                            new = composite._Elaborator(deepcopy(document))
                            old.serial = new.serial = serial
                            ot, nt = (owner.types.resolve(declaration['name']) for owner in (old, new))
                            expected = outcome(old, ot, operation, reference=True)
                            with self.selected(), patch.object(composite._Elaborator, '_reference_helper',
                                    side_effect=AssertionError('host helper called')):
                                actual = outcome(new, nt, operation)
                            self.assertEqual(actual, expected)
                            # A failed expansion can already have cached its name.
                            # A repeated call must preserve that same partial state.
                            again = outcome(old, ot, operation, reference=True)
                            with self.selected():
                                self.assertEqual(outcome(new, nt, operation), again)

    def test_random_layouts_reversed_poll_variants_and_exact_effect_union(self):
        rng = random.Random(19403)
        choices = ('bool', 'unit', 'i8', 'u16', 'u32', 'usize', 'buffer', 'chain')
        for index in range(40):
            states = [rng.choice(choices) for _ in range(rng.randrange(12))]
            results = [rng.choice(choices) for _ in range(rng.randrange(12))]
            effects = rng.sample(['alloc', 'read', 'write', 'trap'], rng.randrange(5))
            serial = rng.choice([0, 8190, 8170, rng.randrange(200)])
            for operation in OPERATIONS:
                with self.subTest(index=index, op=operation):
                    old, ot = helper_owner(states, results, reverse=index % 2, serial=serial, effects=effects)
                    new, nt = helper_owner(states, results, reverse=index % 2, serial=serial, effects=effects)
                    expected = outcome(old, ot, operation, reference=True)
                    with self.selected():
                        self.assertEqual(outcome(new, nt, operation), expected)

    def test_loan_padding_first_refusal_counter_and_partial_cache_are_exact(self):
        for states, results in [(['readbuf'], []), ([], ['mutbuf']),
                                (['buffer', 'readbuf'], ['chain']), (['chain'], ['buffer', 'mutbuf'])]:
            for operation in OPERATIONS:
                for serial in (0, 8150, 8191, 8192):
                    with self.subTest(states=states, results=results, op=operation, serial=serial):
                        old, ot = helper_owner(states, results, serial=serial)
                        new, nt = helper_owner(states, results, serial=serial)
                        expected = outcome(old, ot, operation, reference=True)
                        with self.selected():
                            self.assertEqual(outcome(new, nt, operation), expected)
                            self.assertEqual(outcome(new, nt, operation), outcome(old, ot, operation, reference=True))

    def test_512_slot_extent_and_exact_last_fresh_name_capacity(self):
        maximum = {'input_bytes': 0, 'output_bytes': 0, 'heap_bytes': 0}
        original = self.native._entry
        def measured(source, size, output, capacity, workspace, workspace_size):
            before = ctypes.string_at(source, size)
            extent = original(source, size, output, capacity, workspace, workspace_size)
            self.assertEqual(ctypes.string_at(source, size), before)
            maximum['input_bytes'] = max(maximum['input_bytes'], size)
            maximum['output_bytes'] = max(maximum['output_bytes'], extent)
            heap_end = struct.unpack('<Q', ctypes.string_at(ctypes.addressof(workspace) + 4096 + 16, 8))[0]
            maximum['heap_bytes'] = max(maximum['heap_bytes'], heap_end - 32768)
            return extent
        for state_count in (0, 1, 255, 509, 510):
            states, results = ['buffer'] * state_count, ['buffer'] * (510 - state_count)
            for operation in OPERATIONS:
                old, ot = helper_owner(states, results, effects=['write', 'trap', 'read', 'alloc'])
                expected = outcome(old, ot, operation, reference=True)
                needed = old.serial
                for serial in (0, 8192 - needed, 8193 - needed):
                    old, ot = helper_owner(states, results, serial=serial,
                                           effects=['write', 'trap', 'read', 'alloc'])
                    new, nt = helper_owner(states, results, serial=serial,
                                           effects=['write', 'trap', 'read', 'alloc'])
                    for owner in (old, new):
                        owner.functions['poll']['effects'] = ['write', 'trap', 'read', 'alloc']
                    expected = outcome(old, ot, operation, reference=True)
                    with self.selected(), patch.object(self.native, '_entry', side_effect=measured):
                        actual = outcome(new, nt, operation)
                    self.assertEqual(actual, expected)
                    if serial == 8192 - needed:
                        self.assertIsNone(actual[1]); self.assertEqual(actual[2], 8192)
                    elif serial == 8193 - needed:
                        self.assertEqual(actual[1][0], 'E_HIA_LIMIT')
        self.assertLess(maximum['input_bytes'], 65536)
        self.assertLess(maximum['output_bytes'], 1 << 20)
        self.assertLess(maximum['heap_bytes'], 1 << 20)
        document = maximum_program()
        verify_core(document)
        old, new = (composite._Elaborator(deepcopy(document)) for _ in range(2))
        ot, nt = (owner.types.resolve('Task') for owner in (old, new))
        old.serial = new.serial = 4091
        expected = outcome(old, ot, 'cancel', reference=True)
        with self.selected(), patch.object(self.native, '_entry', side_effect=measured):
            self.assertEqual(outcome(new, nt, 'cancel'), expected)
        self.assertEqual(new.serial, 8192)
        self.assertEqual(maximum, {'input_bytes': 45813, 'output_bytes': 354641, 'heap_bytes': 159728})

    def test_malformed_packets_input_custody_and_workspace_canaries(self):
        from hepta.hia_instruction_policy_native import transport
        owner, typ = helper_owner(['buffer'], ['usize'])
        step = owner.check_task(typ)
        valid = packet(typ, step, 'cancel', 0, ['alloc'], ['alloc'])
        bad = [b'', valid[:-1], b'\xff' * 16, transport([]), transport([0] * 11),
               transport([None] * 11), valid + b'x']
        for value in bad:
            with self.subTest(size=len(value)), self.assertRaises(HIAProgramRejected):
                self.native.generate_packet(value, serial=0)
        source = ctypes.create_string_buffer(valid)
        output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
        scratch = ctypes.create_string_buffer(WORKSPACE_BYTES + 16)
        ctypes.memset(scratch, 0xa7, WORKSPACE_BYTES + 16)
        ctypes.memset(output, 0x5c, OUTPUT_BYTES + 16)
        size = self.native._entry(source, len(valid), output, OUTPUT_BYTES, scratch, WORKSPACE_BYTES)
        self.assertGreater(size, 64)
        self.assertEqual(ctypes.string_at(source, len(valid)), valid)
        self.assertEqual(output.raw[OUTPUT_BYTES:], b'\x5c' * 16)
        self.assertEqual(scratch.raw[WORKSPACE_BYTES:], b'\xa7' * 16)
        self.assertEqual(self.native._entry(source, len(valid), output, OUTPUT_BYTES,
                                            scratch, WORKSPACE_BYTES - 1), 0xfffffff1)

    def test_normalized_public_bytes_execution_and_real_resource_lifecycle(self):
        cases = [(fixtures.task_program, 'task_case', [[0], [1], [2], [255]]),
                 (fixtures.scalar_task_program, 'scalar_task', [[]]),
                 (fixtures.owned_result_task_program, 'owned_result', [[0], [9]]),
                 (partials.task_partial_program, 'partial_task', [[9, 0], [9, 1], [9, 2]]),
                 (loans.task_program, 'task_probe', [[9, 0], [9, 1], [9, 2]]),
                 (resources.composite_range_task_program, 'task_case', [[0], [1], [2], [255]])]
        for factory, function, arguments in cases:
            document = factory(); before = deepcopy(document)
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_helper',
                    side_effect=AssertionError('host helper called')):
                actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                for args in arguments:
                    for failure in (None, 1):
                        old = execute_program(expected, function, args, allocation_fail_at=failure)
                        new = execute_program(actual, function, args, allocation_fail_at=failure)
                        self.assertEqual(new, old)
                        self.assertEqual(new['resources']['live_owners'], 0)
                        self.assertEqual(new['resources']['live_local_loans'], 0)
            self.assertEqual(document, before)

    def test_invalid_transitions_and_poll_discriminant_still_trap(self):
        name = 'test_invalid_runtime_task_transitions_trap'
        case = fixtures.CompositeRejectionTests(name)
        result = unittest.TestResult()
        with self.selected(), patch.object(composite._Elaborator, '_reference_helper',
                side_effect=AssertionError('host helper called')):
            case.run(result)
        self.assertEqual((result.errors, result.failures, result.skipped), ([], [], []))
        with self.selected():
            checked = verify_core(fixtures.task_program()).as_dict()
        poll = next(fn for fn in checked['functions'] if fn['name'] == 'poll_owned')
        for block in poll['blocks']:
            for op in block['ops']:
                if op['op'] == 'const' and op['out'][0]['type'] == 'u32':
                    op['attrs']['value'] = 99
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(checked, 'task_case', [2])
        self.assertEqual(caught.exception.code, 'user')

    def test_actual_native_task_state_machine_allocator_and_protocol_aborts(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        import resource
        cc = shutil.which('cc')
        self.assertIsNotNone(cc, 'actual native caller requires the retained C toolchain')
        driver = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[16]; static size_t allocations, frees, refusals; static bool refuse;
static void *remember(void *p){
  if(p){for(size_t i=0;i<16;i++)if(!live[i]){live[i]=p;allocations++;return p;}exit(80);}return p;
}
void *__wrap_malloc(size_t n){if(refuse){refuse=false;refusals++;return NULL;}return remember(__real_malloc(n));}
void *__wrap_calloc(size_t n,size_t w){if(refuse){refuse=false;refusals++;return NULL;}return remember(__real_calloc(n,w));}
void __wrap_free(void *p){
  if(p){size_t i;for(i=0;i<16 && live[i]!=p;i++);if(i==16)exit(81);live[i]=NULL;frees++;}__real_free(p);
}
size_t task_case(uint8_t);
int main(void){
  const uint8_t modes[]={0,1,2,255};const size_t expected[]={33,13,28,28};
  for(size_t i=0;i<4;i++){
    if(task_case(modes[i])!=expected[i])return 85;
    refuse=true;if(task_case(modes[i])!=250 || refuse)return 86;
  }
  for(size_t i=0;i<16;i++)if(live[i])return 87;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=4 || frees!=4 || refusals!=4;
}
'''
        with tempfile.TemporaryDirectory(prefix='hia-task-helper-machine-') as folder:
            folder = Path(folder)
            def object_file(document, label):
                with self.selected(), patch.object(composite._Elaborator, '_reference_helper',
                        side_effect=AssertionError('host helper called')):
                    checked = verify_core(document)
                    image = emit_program_machine(checked)
                    path = folder / (label + '.o')
                    compile_program_machine(image, program=checked, output=path, kind='object', linker=cc)
                return path
            def link_run(document, label, code, wrappers=()):
                obj = object_file(document, label)
                source, binary = folder / (label + '.c'), folder / label
                source.write_text(code)
                linked = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj), *wrappers,
                    '-o', str(binary)], capture_output=True, timeout=30)
                self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
                return subprocess.run([str(binary)], capture_output=True, timeout=30,
                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
            result = link_run(fixtures.task_program(), 'task-allocator', driver,
                              ('-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free'))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'4 4 4\n', b''))
            for mutation, mode in [('double_start', 2), ('join_pending', 0),
                                   ('close_running', 1), ('poll_complete', 2)]:
                document = fixtures.task_program()
                blocks = {block['id']: block for block in document['functions'][2]['blocks']}
                if mutation == 'double_start':
                    blocks['begin']['ops'][1]['op'] = 'task.start'
                elif mutation == 'join_pending':
                    blocks['pending_cancel']['ops'] = [fixtures.i('task.join', ['pending_task'], [('answer', 'usize')])]
                    blocks['pending_cancel']['term'] = fixtures.ret('answer')
                elif mutation == 'close_running':
                    blocks['running_cancel']['ops'] = [fixtures.i('task.close', ['live_task']), fixtures.c('answer', 'usize', 0)]
                    blocks['running_cancel']['term'] = fixtures.ret('answer')
                else:
                    blocks['finish']['ops'][0]['op'] = 'task.poll'
                code = '#include <stddef.h>\n#include <stdint.h>\nsize_t task_case(uint8_t);int main(void){return (int)task_case(' + str(mode) + ');}\n'
                result = link_run(document, mutation, code)
                self.assertEqual(result.returncode, -6, (mutation, result.stdout, result.stderr))

    def test_installed_wheel_complete_helpers_without_checkout_or_reference_owner(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/task_helpers.hiaasm', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
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
            raise AssertionError('installed helper imported checkout tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_task_helpers_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host task helper called')
composite._Elaborator._reference_helper=absent
try:result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','bad installed helper custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        data = self.folder / 'installed-input.json'
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest)})
        for factory in (fixtures.task_program, partials.task_partial_program, loans.task_program):
            document = factory(); data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/task_helpers.hiaasm'
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
        manifest = json.loads(self.manifest.read_bytes())
        image = self.manifest.parent / manifest['image_path']
        original = image.read_bytes()
        try:
            image.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            result = run('refuse')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
        finally:
            image.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
