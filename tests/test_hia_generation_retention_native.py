"""Independent HIA VM, real machine state, and original resource-owner controls.

Small resource fixtures use an explicitly identified GNU as/ld identity DSO.
They exercise the actual memfd, dlopen, lease and retirement implementation;
they do not replace the separate unchanged original Clang/Z3 caller gate.
"""
from __future__ import annotations

from contextlib import contextmanager
import builtins
import copy
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
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_multiversion as public
from hepta.hia_generation_retention_native import (LEASE_MAGIC, NEED_CAPACITY,
    REQUEST_MAGIC, SELECTOR, SOURCE, STATE_MAGIC, NativeGenerationFailure,
    installed_generation_retention)

ROOT = Path(__file__).resolve().parents[1]
ERROR_PROTOCOL, ERROR_STATE, ERROR_OWNER = 4294967293, 4294967292, 4294967291
ERROR_RETIRED, ERROR_UNDERFLOW = 4294967290, 4294967287


def packet(event, *, owner=(11, 17), token=(0, 0)):
    return struct.pack('<8Q', REQUEST_MAGIC, event, *owner, *token, 0, 0)


def independent_checksum(raw, skip):
    accumulator = 1469598103934665603
    for offset, value in enumerate(raw):
        if not skip <= offset < skip + 8:
            accumulator = ((accumulator ^ value) * 1099511628211) % (1 << 64)
    return accumulator


def independent_state(count, *, owner=(11, 17), capacity=None, retired=False, claim=(0, 0)):
    """Test-only mathematical state, never a production import/recovery API."""
    assert type(count) is int and count >= 0
    magnitude = count.to_bytes((count.bit_length() + 7) // 8, 'little')
    capacity = max(1, len(magnitude)) if capacity is None else capacity
    assert len(magnitude) <= capacity
    flags = int(retired) | (2 if claim != (0, 0) else 0)
    raw = bytearray(struct.pack('<8Q', STATE_MAGIC, *owner, flags, len(magnitude), 0, *claim)
                    + magnitude + bytes(capacity - len(magnitude)))
    struct.pack_into('<Q', raw, 40, independent_checksum(raw[:64 + len(magnitude)], 40))
    return bytes(raw)


def count_in(raw):
    size, = struct.unpack_from('<Q', raw, 32)
    return int.from_bytes(raw[64:64 + size], 'little')


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.checked = assemble_program(SOURCE.read_bytes())
        self.entry = self.checked.as_dict()['functions'][0]

    def call(self, raw, cell, state):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        buffers = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(cell)), _Owner(-3, bytearray(state))]
        machine = _Machine(self.checked, 50_000_000, 16 << 20, None, 128)
        returned = machine.invoke(self.entry, [_View(buffers[0], False),
                                  _View(buffers[1], True), _View(buffers[2], True)])[0]
        assert bytes(buffers[0].data) == raw
        return returned, bytes(buffers[1].data), bytes(buffers[2].data)


class Machine:
    def __init__(self, image):
        self.image = image

    def call(self, raw, cell, state):
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        output = ctypes.create_string_buffer(cell + b'\xa5' * 16, len(cell) + 16)
        workspace = ctypes.create_string_buffer(state + b'\x91' * 16, len(state) + 16)
        returned = self.image._entry(source, len(raw), output, len(cell), workspace, len(state))
        assert source.raw == (raw or b'\0')
        assert output.raw[len(cell):] == b'\xa5' * 16
        assert workspace.raw[len(state):] == b'\x91' * 16
        return returned, output.raw[:len(cell)], workspace.raw[:len(state)]


def fixed_trace(engine):
    """Independent fixed expectations, with each whole mutable byte retained."""
    state, cells, rows = bytes(65), {}, []
    def run(event, identity=0, expected=0):
        nonlocal state
        token = (identity, identity + 3) if identity else (0, 0)
        cell = cells.get(identity, bytes(64))
        raw = packet(event, token=token)
        result = engine.call(raw, cell, state)
        assert result[0] == expected, result[0]
        state = result[2]
        if identity and event in (1, 2, 6):
            cells[identity] = result[1]
        rows.append((raw, result))
        return result
    run(0)
    assert state == independent_state(0)
    run(1, 101)
    run(1, 103)
    assert count_in(state) == 2
    before = state
    run(1, 101, ERROR_OWNER)
    assert state == before
    run(6, 101, 1)
    run(3)
    run(5, expected=1)
    run(1, 107, ERROR_RETIRED)
    run(4, 199, ERROR_RETIRED)
    run(2, 101)
    assert count_in(state) == 1
    run(2, 101, 1)
    assert count_in(state) == 1
    run(2, 103)
    run(5, expected=29)
    run(4, 199)
    run(4, 199, 1)
    run(4, 211, ERROR_OWNER)
    run(5, expected=15)
    run(6, 103, 2)
    assert state == independent_state(0, retired=True, claim=(199, 202))
    return rows


def _resource_build(program, output, **options):
    """Explicit test fixture, not the product compiler or a Clang substitute."""
    from hepta.hia_program_llvm import emit_program_llvm
    from hepta.hia_program_runtime import execute_program
    document = program.as_dict()
    assert [(f['name'], [p['type'] for p in f['params']], f['returns'])
            for f in document['functions']] == [('calculate', ['u64'], ['u64'])]
    assert all(execute_program(program, 'calculate', [value])['result'] == value
               for value in (0, 1, (1 << 63), (1 << 64) - 1))
    output = Path(output)
    with tempfile.TemporaryDirectory(prefix='hia-explicit-assembly-fixture-') as temporary:
        folder = Path(temporary)
        source = folder / 'identity.S'
        source.write_text('.text\n.globl calculate\n.type calculate,@function\n'
                          'calculate:\nmovq %rdi,%rax\nret\n.size calculate,.-calculate\n'
                          '.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['as', '--64', str(source), '-o', str(folder / 'identity.o')],
                       check=True, capture_output=True)
        subprocess.run(['ld', '-shared', '-z', 'noexecstack', '-o', str(output),
                        str(folder / 'identity.o')], check=True, capture_output=True)
    data = output.read_bytes()
    return {'core_sha256': program.sha256, 'input_sha256': program.input_sha256,
            'llvm_ir_sha256': emit_program_llvm(program).sha256,
            'artifact_sha256': sha256(data).hexdigest(), 'artifact_bytes': len(data),
            'target': public.TARGET, 'kind': 'shared', 'test_fixture': 'GNU_AS_LD_IDENTITY'}


@contextmanager
def resource_runtime(manifest, **options):
    from tests.test_hia_multiversion import scalar_program
    with tempfile.TemporaryDirectory(prefix='hia-generation-effects-') as directory, \
            patch.dict(os.environ, {SELECTOR: str(manifest)}), \
            patch.object(public, 'build_program_native', side_effect=_resource_build):
        runtime = public.ScalarMultiversionRuntime(scalar_program(), directory, **options)
        try:
            yield runtime
        finally:
            runtime.close()


def fd_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


class GenerationRetentionSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_vm_retained_trace(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_generation_retention import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(fixed_trace(VM())), 18)

    def test_vm_need_capacity_has_no_writes_and_exact_large_borrow(self):
        vm = VM()
        for count in (255, (1 << 64) - 1, (1 << 300) - 1):
            state = independent_state(count)
            result = vm.call(packet(1, token=(19, 23)), bytes(64), state)
            if count.bit_length() % 8 == 0:
                self.assertEqual(result, (NEED_CAPACITY, bytes(64), state))
                state += b'\0'
                result = vm.call(packet(1, token=(19, 23)), bytes(64), state)
            self.assertEqual(result[0], 0)
            self.assertEqual(count_in(result[2]), count + 1)
            closed = vm.call(packet(2, token=(19, 23)), result[1], result[2])
            self.assertEqual(closed[0], 0)
            self.assertEqual(count_in(closed[2]), count)

    def test_default_reference_attributes_and_optional_import_remain_lazy(self):
        from tests.test_hia_multiversion import scalar_program
        importer = builtins.__import__
        def guarded(name, *args, **kwargs):
            if 'generation_retention_native' in name:
                raise AssertionError('default runtime imported optional native adapter')
            return importer(name, *args, **kwargs)
        environment = {name: value for name, value in os.environ.items() if name != SELECTOR}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, environment, clear=True), \
                patch('builtins.__import__', guarded), \
                patch.object(public, 'build_program_native', side_effect=_resource_build):
            with public.ScalarMultiversionRuntime(scalar_program(), directory) as runtime:
                state = runtime._states[0]
                lease = runtime.lease()
                self.assertEqual(state.leases, 1)
                self.assertFalse(state.retired)
                self.assertFalse(lease._closed)
                lease.close()
                self.assertEqual(state.leases, 0)
                self.assertTrue(lease._closed)

    def test_selected_empty_or_unqualified_cold_fails_before_resources(self):
        from tests.test_hia_multiversion import scalar_program
        from tools.build_hia_generation_retention import build
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for selection in ('', str(folder / 'absent')):
                with patch.dict(os.environ, {SELECTOR: selection}), \
                        patch.object(public.tempfile, 'mkdtemp', side_effect=AssertionError('resource created')):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        public.ScalarMultiversionRuntime(scalar_program(), folder)
            (folder / 'compiler').write_bytes(b'unqualified')
            (folder / 'cold').write_text('{}')
            with patch('tools.build_hia_generation_retention.compile_stage',
                       side_effect=AssertionError('compiler entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(folder / 'output', folder / 'compiler', folder / 'cold')
            self.assertFalse((folder / 'output').exists())


class GenerationRetentionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get('HEPTA_HIA_GENERATION_RETENTION_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_GENERATION_RETENTION_DEVELOPMENT_COMPILER')
        if cold and development:
            raise AssertionError('development fixture cannot override cold source custody')
        cls.cold = cold
        retained = os.environ.get('HEPTA_HIA_GENERATION_RETENTION_EVIDENCE')
        cls.temporary = None
        if retained:
            base = Path(retained)
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-generation-retention-')
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        from tools.build_hia_generation_retention import INPUTS, build
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        cls.before = {path.relative_to(ROOT).as_posix(): path.read_bytes()
                      for folder in ('hepta', 'tools') for path in (ROOT / folder).rglob('*.py')}
        for name in (*INPUTS, *RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in',
                     'tests/test_hia_generation_retention_native.py',
                     'tests/test_hia_agent_installed_resources.py'):
            cls.before[name] = (ROOT / name).read_bytes()
        (cls.folder / 'source-before.json').write_text(json.dumps(
            {name: sha256(raw).hexdigest() for name, raw in cls.before.items()}, indent=2, sort_keys=True) + '\n')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'candidate', cls.compiler, Path(cold))
        else:
            if development:
                cls.compiler = Path(development)
            else:
                from tools.qualify_hia_selfhost import build_seed, compile_stage
                seed, _ = build_seed(cls.folder)
                source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
                first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
                cls.compiler, _ = compile_stage(cls.folder, 'B2', first, source)
                if first.read_bytes() != cls.compiler.read_bytes():
                    raise AssertionError('development compiler fixed point differs')
            cls.manifest = build(cls.folder / 'candidate', cls.compiler, development=True)
        cls.compiler_bytes = cls.compiler.read_bytes()
        cls.image = installed_generation_retention(str(cls.manifest))
        cls.rows = []

    @classmethod
    def tearDownClass(cls):
        stable = (all((ROOT / name).read_bytes() == raw for name, raw in cls.before.items())
                  and cls.compiler.read_bytes() == cls.compiler_bytes)
        (cls.folder / 'controls.json').write_text(json.dumps({
            'schema': 'hepta.hia.generation-retention-controls.v1',
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_sha256': cls.image.image_sha256, 'observations': cls.rows,
            'source_and_compiler_unchanged': stable,
            'resource_fixture_compiler': 'GNU_AS_LD_IDENTITY_NOT_ORIGINAL_CLANG',
            'all_input_equivalence_proved': False, 'whole_stack_rewritten_in_hia': False,
            'arbitrary_python_async_unwind_proved': False}, indent=2, sort_keys=True) + '\n')
        if not stable:
            raise AssertionError('generation retention source or compiler changed')

    def test_entire_retained_trace_matches_independent_vm(self):
        vm = fixed_trace(VM())
        native = fixed_trace(Machine(self.image))
        self.assertEqual(native, vm)
        self.rows.append({'control': 'whole_state_vm_native', 'steps': len(native)})

    def test_random_interleaving_matches_independent_unbounded_reference_model(self):
        randomizer = random.Random(0xA771)
        engine = Machine(self.image)
        state, cells, opened = bytes(65), {}, set()
        result = engine.call(packet(0), bytes(64), state)
        state = result[2]
        for index in range(600):
            if not opened or randomizer.randrange(3):
                token = (index + 1, 431)
                result = engine.call(packet(1, token=token), bytes(64), state)
                if result[0] == NEED_CAPACITY:
                    self.assertEqual(result, (NEED_CAPACITY, bytes(64), state))
                    state += bytes(len(state) - 64)
                    result = engine.call(packet(1, token=token), bytes(64), state)
                self.assertEqual(result[0], 0)
                cells[token] = result[1]
                opened.add(token)
            else:
                token = randomizer.choice(sorted(opened))
                result = engine.call(packet(2, token=token), cells[token], state)
                self.assertEqual(result[0], 0)
                cells[token] = result[1]
                opened.remove(token)
            state = result[2]
            self.assertEqual(count_in(state), len(opened))
        self.rows.append({'control': 'independent_reference_interleaving', 'transitions': 600})

    def test_arbitrary_length_count_carries_borrows_and_zero_write_capacity(self):
        engine = Machine(self.image)
        cases = [0, 1, 254, 255, 256, (1 << 63) - 1, 1 << 63, (1 << 64) - 1,
                 1 << 64, (1 << 127) - 1, 1 << 128, (1 << 300) - 1, 1 << 300,
                 (1 << 4096) - 1]
        for count in cases:
            with self.subTest(bits=count.bit_length()):
                before = independent_state(count)
                result = engine.call(packet(1, token=(19, 23)), bytes(64), before)
                if result[0] == NEED_CAPACITY:
                    self.assertEqual(result, (NEED_CAPACITY, bytes(64), before))
                    before += bytes(len(before) - 64)
                    result = engine.call(packet(1, token=(19, 23)), bytes(64), before)
                self.assertEqual(result[0], 0)
                self.assertEqual(count_in(result[2]), count + 1)
                result = engine.call(packet(2, token=(19, 23)), result[1], result[2])
                self.assertEqual(result[0], 0)
                self.assertEqual(count_in(result[2]), count)
        self.rows.append({'control': 'unbounded_counter_boundaries', 'cases': len(cases), 'maximum_bits': 4096})

    def test_hia_rejects_cross_generation_cell_reactivation_and_malformed_state(self):
        engine = Machine(self.image)
        active = engine.call(packet(1, token=(19, 23)), bytes(64), independent_state(0))
        self.assertEqual(active[0], 0)
        controls = [
            (packet(1, token=(19, 23)), active[1], active[2], ERROR_OWNER),
            (packet(2, owner=(29, 31), token=(19, 23)), active[1],
             independent_state(1, owner=(29, 31)), ERROR_OWNER),
            (packet(2, token=(19, 29)), active[1], active[2], ERROR_OWNER),
            (packet(2, token=(19, 23)), active[1], independent_state(0), ERROR_UNDERFLOW),
            (packet(5), bytes(64), bytes(64), ERROR_PROTOCOL),
        ]
        for position in (0, 16, 24, 32, 40, 48, 64):
            broken = bytearray(active[2]); broken[position] ^= 1
            controls.append((packet(5), active[1], bytes(broken), ERROR_STATE))
        for position in (0, 8, 24, 40, 48, 56):
            broken = bytearray(active[1]); broken[position] ^= 1
            controls.append((packet(2, token=(19, 23)), bytes(broken), active[2], ERROR_OWNER))
        for raw, cell, state, expected in controls:
            result = engine.call(raw, cell, state)
            self.assertEqual(result, (expected, cell, state))
        self.rows.append({'control': 'native_binding_and_corruption', 'cases': len(controls)})

    def test_adapter_growth_keeps_previous_alias_and_hia_alone_changes_count(self):
        runtime = SimpleNamespace(_cleanup_pending={})
        state = self.image.owner(runtime)
        previous = state._buffer
        cells = [state.new_cell(object()) for _ in range(260)]
        for cell in cells:
            state.acquire(cell)
        self.assertEqual(state.observe()['references'], 260)
        self.assertEqual(len(state._previous_buffers), 1)
        self.assertIs(state._previous_buffers[0], previous)
        self.assertEqual(count_in(previous.raw), 255)
        for cell in cells:
            state.close(cell)
            state.close(cell)
        self.assertEqual(state.observe()['references'], 0)
        self.assertEqual(state._cells, {})
        self.rows.append({'control': 'actual_retained_growth', 'acquires': 260, 'close_calls': 520})

    def test_runtime_allocation_refusals_preserve_255_cells_and_allow_complete_recovery(self):
        from hepta.hia_generation_retention_native import _QUARANTINED
        for mode in ('capacity', 'custody_before', 'custody_after'):
            with self.subTest(mode=mode), resource_runtime(self.manifest) as runtime:
                state = runtime._states[0]
                policy = state._retention
                leases = [runtime.lease() for _ in range(255)]
                original = policy._buffer
                state_bytes = original.raw
                cells = {identity: (cell, cell.buffer.raw) for identity, cell in policy._cells.items()}
                failure = MemoryError('injected known no-write ' + mode)
                allocate = ctypes.create_string_buffer
                def fail_growth(value, *arguments):
                    if value == 66:
                        raise failure
                    return allocate(value, *arguments)
                class FailedInsert(dict):
                    def __setitem__(self, key, value):
                        if mode == 'custody_after':
                            super().__setitem__(key, value)
                        raise failure
                if mode != 'capacity':
                    policy._cells = FailedInsert(policy._cells)
                entry = policy.image._entry
                entries = []
                def observe_entry(source, *arguments):
                    entries.append(struct.unpack_from('<Q', source, 8)[0])
                    return entry(source, *arguments)
                with patch('hepta.hia_generation_retention_native.ctypes.create_string_buffer',
                           side_effect=fail_growth if mode == 'capacity' else allocate), \
                        patch.object(policy.image, '_entry', side_effect=observe_entry), \
                        self.assertRaises(MemoryError) as caught:
                    runtime.lease()
                self.assertIs(caught.exception, failure)
                self.assertEqual(entries, [1] if mode == 'capacity' else [])
                self.assertIs(policy._buffer, original)
                self.assertEqual(policy._buffer.raw, state_bytes)
                self.assertEqual(policy._previous_buffers, [])
                self.assertIsNone(policy._fenced)
                self.assertIsNone(policy._allocation_error)
                self.assertIsNone(policy._allocation_cell)
                self.assertEqual(_QUARANTINED, {})
                self.assertEqual(policy._cells, {identity: cell for identity, (cell, raw) in cells.items()})
                self.assertTrue(all(cell.buffer.raw == raw for cell, raw in cells.values()))
                self.assertEqual(state.leases, 255)
                policy._cells = dict(policy._cells)
                recovered = runtime.lease()
                self.assertEqual(state.leases, 256)
                self.assertIs(policy._previous_buffers[0], original)
                self.assertEqual(original.raw, state_bytes)
                self.assertEqual(recovered.call('calculate', [271]), 271)
                recovered.close()
                for lease in leases:
                    lease.close()
                self.assertEqual(state.leases, 0)
                self.assertEqual(policy._cells, {})
                runtime.close()
                self.assertFalse(fd_open(state.fd))
                self.assertFalse(runtime._directory.exists())
                self.assertEqual(_QUARANTINED, {})
                self.rows.append({'control': 'no_transition_allocation_failure',
                                  'site': mode, 'held_leases': 255,
                                  'recovered_leases': 256, 'original_exception_preserved': True,
                                  'native_entry_events_before_refusal': entries,
                                  'actual_resources_released': True})

    def test_original_native_retirement_owner_and_generation_owner_compose_without_reference_policy(self):
        from hepta import hia_native_retirement as retirement
        from hepta.hia_retirement_state_native import SOURCE as retirement_source, SCHEMA as retirement_schema
        from tests.test_hia_multiversion import scalar_program
        output = self.folder / 'retirement-component'
        if self.cold:
            from tools.build_hia_retirement_state import build
            manifest = build(output, self.compiler, Path(self.cold))
        else:
            from tools.qualify_hia_selfhost import compile_stage
            from tools.build_hia_source_build import _check_pack_output
            output.mkdir(mode=0o700)
            source = retirement_source.read_bytes()
            image, receipt = compile_stage(output, 'retirement-state', self.compiler, source)
            packed = _check_pack_output(receipt, (output / 'retirement-state.output.bin').read_bytes(),
                                       artifact=self.compiler_bytes, source=source)
            self.assertEqual(packed, image.read_bytes())
            self.assertEqual(source, retirement_source.read_bytes())
            manifest = output / 'manifest.json'
            manifest.write_text(json.dumps({'schema': retirement_schema,
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(packed).hexdigest(),
                'compiler_sha256': sha256(self.compiler_bytes).hexdigest()}, indent=2) + '\n')
        with patch.dict(os.environ, {'HEPTA_HIA_RETIREMENT_STATE_MANIFEST': str(manifest)}), \
                patch.object(retirement._ReferencePathIdentityPin, '__init__',
                             side_effect=AssertionError('hosted pin policy entered')), \
                patch.object(retirement._ReferenceNativeRetirement, '__init__',
                             side_effect=AssertionError('hosted cleanup policy entered')):
            with resource_runtime(self.manifest) as runtime:
                first = runtime.publish(scalar_program(None))
                lease = runtime.lease()
                state = runtime._states[first.generation]
                runtime.publish(scalar_program('bit.xor'))
                self.assertTrue(state.retired)
                self.assertEqual(state.leases, 1)
                self.assertTrue(fd_open(state.fd))
                self.assertEqual(lease.call('calculate', [283]), 283)
                lease.close()
                task = state._retention._task
                self.assertTrue(task.complete)
                self.assertIs(task._generation_retention, state._retention)
                self.assertFalse(fd_open(state.fd))
                runtime.close()
                self.assertTrue(runtime.snapshot()['cleanup']['observed_closed_and_directory_absent'])
        self.rows.append({'control': 'generation_and_existing_native_retirement_composition',
                          'retirement_manifest': str(manifest), 'reference_policy_constructors_forbidden': True})

    def test_actual_runtime_leases_pin_resources_across_publish_rollback_and_close(self):
        from tests.test_hia_multiversion import scalar_program
        with resource_runtime(self.manifest, max_live_generations=2) as runtime:
            baseline = runtime.lease()
            runtime._next = (1 << 200) + 19
            runtime._epoch = (1 << 300) + 23
            generation = runtime.publish(scalar_program(None))
            self.assertEqual(generation.generation, (1 << 200) + 19)
            lease = runtime.lease()
            self.assertEqual(lease.selection_epoch, (1 << 300) + 24)
            lease.selection_epoch = -(1 << 500)
            self.assertEqual(lease.selection_epoch, -(1 << 500))
            state = runtime._states[generation.generation]
            with self.assertRaisesRegex(public.MultiversionRejected, 'live artifact budget exhausted'):
                runtime.publish(scalar_program('bit.xor'))
            runtime.rollback()
            self.assertEqual(runtime._epoch, (1 << 300) + 25)
            self.assertTrue(state.retired)
            self.assertEqual(state.leases, 1)
            self.assertTrue(fd_open(state.fd))
            self.assertEqual(lease.call('calculate', [(1 << 64) - 1]), (1 << 64) - 1)
            runtime.close()
            with self.assertRaisesRegex(public.MultiversionRejected, 'runtime is closed'):
                runtime.lease()
            self.assertEqual(lease.call('calculate', [73]), 73)
            lease.close()
            self.assertFalse(fd_open(state.fd))
            baseline.close()
            self.assertFalse(runtime._directory.exists())
            lease.close()
            self.assertTrue(runtime.snapshot()['cleanup']['owned_native_release_complete'])
        self.rows.append({'control': 'actual_resource_publish_rollback_close',
                          'generation_bits': 201, 'epoch_bits': 301})

    def test_actual_runtime_per_lease_call_lock_and_parallel_count(self):
        from concurrent.futures import ThreadPoolExecutor
        with resource_runtime(self.manifest) as runtime:
            state = runtime._states[0]
            def calls(index):
                for value in range(35):
                    with runtime.lease() as lease:
                        self.assertEqual(lease.call('calculate', [index + value]), index + value)
            with ThreadPoolExecutor(max_workers=6) as pool:
                list(pool.map(calls, range(6)))
            self.assertEqual(state.leases, 0)
            lease = runtime.lease()
            entered, finished = threading.Event(), threading.Event()
            actual = state.functions['calculate']
            def held(value):
                entered.set()
                self.assertTrue(finished.wait(5))
                return actual(value)
            with patch.dict(state.functions, {'calculate': held}), ThreadPoolExecutor(max_workers=2) as pool:
                call = pool.submit(lease.call, 'calculate', [97])
                self.assertTrue(entered.wait(5))
                close = pool.submit(lease.close)
                self.assertFalse(close.done())
                self.assertEqual(state.leases, 1)
                finished.set()
                self.assertEqual(call.result(5), 97)
                close.result(5)
            self.assertEqual(state.leases, 0)
            with self.assertRaisesRegex(public.MultiversionRejected, 'lease is closed'):
                lease.call('calculate', [1])
            for copier in (copy.copy, copy.deepcopy):
                with self.assertRaises(public.MultiversionRejected):
                    copier(lease)
        self.rows.append({'control': 'original_call_close_locks', 'parallel_lease_calls': 210})

    def test_actual_registration_before_after_and_cleanup_return_never_reclose_reused_fd(self):
        from tests.test_hia_multiversion import scalar_program
        for after in (False, True):
            with self.subTest(after=after), resource_runtime(self.manifest) as runtime:
                first = runtime.publish(scalar_program(None))
                state = runtime._states[first.generation]
                class InterruptedInsert(dict):
                    def __setitem__(self, key, value):
                        if key == first.generation:
                            if after:
                                super().__setitem__(key, value)
                            raise KeyboardInterrupt('injected retirement registration')
                        super().__setitem__(key, value)
                runtime._cleanup_pending = InterruptedInsert(runtime._cleanup_pending)
                with self.assertRaises(KeyboardInterrupt):
                    runtime.rollback()
                original_task = state._retention._task
                self.assertIsNotNone(original_task)
                self.assertFalse(original_task.native_attempted)
                self.assertTrue(fd_open(state.fd))
                runtime._cleanup_pending = dict(runtime._cleanup_pending)
                if after:
                    runtime.retry_cleanup()
                else:
                    runtime.close()
                self.assertIs(state._retention._task, original_task)
                self.assertFalse(fd_open(state.fd))
                self.assertTrue(original_task.complete)
        with resource_runtime(self.manifest) as runtime:
            first = runtime.publish(scalar_program(None))
            lease = runtime.lease()
            state = runtime._states[first.generation]
            runtime.rollback()
            attempt = runtime._attempt_cleanup
            def after_release(task):
                attempt(task)
                if task.generation == first.generation:
                    raise KeyboardInterrupt('injected return after actual release')
            with patch.object(runtime, '_attempt_cleanup', side_effect=after_release), self.assertRaises(KeyboardInterrupt):
                lease.close()
            self.assertNotIn(first.generation, runtime._states)
            self.assertFalse(fd_open(state.fd))
            replacement = os.open(os.devnull, os.O_RDONLY)
            if replacement != state.fd:
                os.dup2(replacement, state.fd)
                os.close(replacement)
            try:
                lease.close()
                runtime.retry_cleanup()
                runtime.close()
                self.assertTrue(fd_open(state.fd))
            finally:
                os.close(state.fd)
        self.rows.append({'control': 'actual_registration_and_fd_reuse', 'registration_sides': 2})

    def test_runtime_latches_original_image_and_warm_source_selection_refuses_drift(self):
        from tests.test_hia_multiversion import scalar_program
        with resource_runtime(self.manifest) as runtime:
            with patch.dict(os.environ, {SELECTOR: '/absent-new-selection'}):
                generation = runtime.publish(scalar_program(None))
                self.assertIs(runtime._states[generation.generation]._retention.image,
                              runtime._native_retention_image)
                self.assertEqual(runtime.call('calculate', [31]), 31)
                with self.assertRaises(FileNotFoundError):
                    public.ScalarMultiversionRuntime(scalar_program(), runtime._directory)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'generation.hepta'
            source.write_bytes(SOURCE.read_bytes())
            with patch('hepta.hia_generation_retention_native.SOURCE', source):
                installed_generation_retention(str(self.manifest))
                source.write_bytes(source.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    installed_generation_retention(str(self.manifest))
                source.unlink()
                with self.assertRaises(FileNotFoundError):
                    installed_generation_retention(str(self.manifest))
        self.rows.append({'control': 'latched_runtime_and_warm_source_refusal'})

    def test_actual_sdist_wheel_isolated_install_uses_public_native_lease_and_refuses_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_multiversion import scalar_program
        from hepta.hia_program import verify_program
        folder = self.folder / 'installed-generation-retention'
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
                     if name.endswith('/examples/hia_bootstrap/generation_retention.hepta'))
            self.assertEqual(handle.extractfile(name).read(), SOURCE.read_bytes())
        command('wheel', ['-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation',
                          '--wheel-dir', folder / 'wheels', archive])
        wheel, = (folder / 'wheels').glob('*.whl')
        installed = folder / 'installed'
        command('install', ['-m', 'pip', 'install', '--no-index', '--no-deps', '--target', installed, wheel])
        value = scalar_program()
        request = folder / 'program.json'
        request.write_text(json.dumps(value))
        fixture = folder / 'explicit-assembly-identity.so'
        _resource_build(verify_program(value), fixture)
        script = r'''
import ctypes, json, os, shutil, sys, tempfile
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta import hia_multiversion as public
from hepta import hia_generation_retention_native as native
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
assert Path(public.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert Path(native.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert native.SOURCE == Path(sys.argv[1]) / 'hepta/_data/examples/hia_bootstrap/generation_retention.hepta'
value = json.loads(Path(sys.argv[3]).read_bytes())
expected = verify_program(value)
fixture = Path(sys.argv[4]).read_bytes()
os.environ[native.SELECTOR] = sys.argv[2]
def explicit_resource_fixture(program, output, **options):
    assert program.canonical_bytes == expected.canonical_bytes
    Path(output).write_bytes(fixture)
    return {'core_sha256': program.sha256, 'input_sha256': program.input_sha256,
            'llvm_ir_sha256': emit_program_llvm(program).sha256,
            'artifact_sha256': sha256(fixture).hexdigest(), 'artifact_bytes': len(fixture),
            'target': public.TARGET, 'kind': 'shared', 'test_fixture': 'GNU_AS_LD_IDENTITY'}
generation_get = public._Generation.__getattribute__
lease_get = public.GenerationLease.__getattribute__
def no_generation_reference(state, name):
    if name in ('_reference_leases', '_reference_retired'):
        raise AssertionError('installed runtime entered hosted generation state')
    return generation_get(state, name)
def no_lease_reference(lease, name):
    if name == '_reference_closed':
        raise AssertionError('installed runtime entered hosted lease closure')
    return lease_get(lease, name)
counts = {}
invoke = native.GenerationRetention._invoke
def observed(state, event, *arguments, **keywords):
    result = invoke(state, event, *arguments, **keywords)
    counts[event] = counts.get(event, 0) + 1
    return result
with tempfile.TemporaryDirectory() as directory, \
        patch.object(public, 'build_program_native', side_effect=explicit_resource_fixture), \
        patch.object(public._Generation, '__getattribute__', no_generation_reference), \
        patch.object(public.GenerationLease, '__getattribute__', no_lease_reference), \
        patch.object(native.GenerationRetention, '_invoke', observed):
    runtime = public.ScalarMultiversionRuntime(value, directory)
    state = runtime._states[0]
    lease = runtime.lease()
    assert state.leases == 1 and not lease._closed
    assert lease.call('calculate', [(1 << 64) - 1]) == (1 << 64) - 1
    source = native.SOURCE.read_bytes()
    refusals = []
    try:
        for replacement in (source + b'\n', None):
            if replacement is None:
                native.SOURCE.unlink()
            else:
                native.SOURCE.write_bytes(replacement)
            # Existing custody keeps its original immutable image. New
            # runtime selection must re-read the actual installed source.
            assert runtime.call('calculate', [307]) == 307
            try:
                public.ScalarMultiversionRuntime(value, directory)
            except (ValueError, FileNotFoundError) as error:
                refusals.append((type(error).__name__, str(error)))
            else:
                raise AssertionError('warm cache concealed changed or missing installed source')
    finally:
        native.SOURCE.write_bytes(source)
    assert refusals[0] == ('ValueError', 'native HIA JSON source identity mismatch')
    assert refusals[1][0] == 'FileNotFoundError'
    runtime.close()
    assert state.retired and state.leases == 1
    assert lease.call('calculate', [311]) == 311
    lease.close()
    assert state.leases == 0 and lease._closed
    assert not runtime._directory.exists()
    try:
        os.fstat(state.fd)
    except OSError:
        pass
    else:
        raise AssertionError('installed final lease did not release the real descriptor')
    assert all(counts.get(event, 0) for event in range(7)), counts
print(json.dumps({'installed_source': str(native.SOURCE), 'native_event_counts': counts,
                  'warm_source_refusals': refusals, 'hosted_reference_state_forbidden': True,
                  'actual_descriptor_released': True,
                  'resource_fixture_compiler': 'GNU_AS_LD_IDENTITY_NOT_ORIGINAL_CLANG'}, sort_keys=True))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed),
                                 str(self.manifest), str(request), str(fixture)], cwd=folder,
                                 capture_output=True, timeout=20)
        (folder / 'installed.stdout.bin').write_bytes(result.stdout)
        (folder / 'installed.stderr.bin').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.rows.append({'control': 'actual-sdist-wheel-isolated-installed-public-lease',
                          'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
                          'observations': json.loads(result.stdout)})

    def test_actual_pinned_scope_admits_new_runtime_and_refuses_foreign_thread_or_selector(self):
        from hepta import hia_native_helpers as authority
        from tests.test_hia_multiversion import scalar_program
        bundle = self.folder / 'generation-retention-helpers.json'
        bundle.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
            'abi': authority.ABI, 'helpers': [{'selector': SELECTOR,
                'manifest_path': self.manifest.relative_to(self.folder).as_posix(),
                'manifest_sha256': sha256(self.manifest.read_bytes()).hexdigest()}]}))
        pin = sha256(bundle.read_bytes()).hexdigest()
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        with patch.dict(os.environ, environment, clear=True):
            with authority.native_helpers_scope(str(bundle), pin), resource_runtime(self.manifest) as runtime:
                self.assertEqual(runtime.call('calculate', [313]), 313)
                refused = []
                def wrong_owner():
                    try:
                        public.ScalarMultiversionRuntime(scalar_program(), runtime._directory)
                    except ValueError as error:
                        refused.append(str(error))
                worker = threading.Thread(target=wrong_owner)
                worker.start()
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(refused, ['native helper worker scope belongs to its original process and thread'])
                with patch.dict(os.environ, {SELECTOR: str(bundle)}):
                    self.assertEqual(runtime.call('calculate', [317]), 317)
                    with self.assertRaisesRegex(ValueError, 'outside the pinned worker bundle'):
                        public.ScalarMultiversionRuntime(scalar_program(), runtime._directory)
                    with self.assertRaisesRegex(ValueError, 'selection changed'):
                        authority.native_helpers_identity()
                self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': pin})
            self.assertNotIn(SELECTOR, os.environ)
        self.rows.append({'control': 'operator-pinned-generation-retention-helper', 'bundle_sha256': pin,
                          'foreign_thread_new_runtime_refused': True, 'changed_selection_refused': True,
                          'retained_existing_runtime_image_unchanged': True, 'environment_restored': True})

    def test_interrupted_native_mutation_and_corruption_keep_strong_resource_custody(self):
        cases = ('acquire_before', 'acquire_after', 'acquire_memory_before', 'acquire_memory_after',
                 'close_before', 'close_after',
                 'claim_before', 'claim_after', 'receipt', 'state', 'cell')
        for case in cases:
            with self.subTest(case=case):
                result = subprocess.run([sys.executable, '-B', '-c',
                    'from tests.test_hia_generation_retention_native import fault_case; '
                    'import sys; fault_case(sys.argv[1], sys.argv[2])', str(self.manifest), case],
                    cwd=ROOT, env=dict(os.environ), capture_output=True, text=True, timeout=30)
                (self.folder / ('fault-' + case + '.stdout')).write_text(result.stdout)
                (self.folder / ('fault-' + case + '.stderr')).write_text(result.stderr)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row['status'], 'PASS')
                self.rows.append(row)


def fault_case(manifest, case):
    """Child-process faults leave quarantined real resources until process exit."""
    from tests.test_hia_multiversion import scalar_program
    from hepta.hia_generation_retention_native import _QUARANTINED, generation_quarantine_snapshot
    import gc
    import weakref
    temporary = tempfile.TemporaryDirectory(prefix='hia-generation-quarantine-')
    with patch.dict(os.environ, {SELECTOR: manifest}), \
            patch.object(public, 'build_program_native', side_effect=_resource_build):
        runtime = public.ScalarMultiversionRuntime(scalar_program(), temporary.name)
        state = runtime._states[0]
        policy = state._retention
        actual = policy.image._entry
        lease = None
        if case.startswith('close') or case == 'cell':
            lease = runtime.lease()
        if case.startswith('claim'):
            state.retired = True
        if case == 'state':
            policy._buffer[64] = b'\x01'
        if case == 'cell':
            lease._native_cell.buffer[56] = b'\x01'
        target = (1 if case.startswith('acquire') or case in ('receipt', 'state') else
                  2 if case.startswith('close') or case == 'cell' else 4)
        native_calls = []
        actual_native_calls = []
        def interrupted(source, source_size, output, output_size, workspace, workspace_size):
            event, = struct.unpack_from('<Q', source, 8)
            if event != target:
                return actual(source, source_size, output, output_size, workspace, workspace_size)
            native_calls.append(event)
            if case in ('state', 'cell'):
                actual_native_calls.append(event)
                return actual(source, source_size, output, output_size, workspace, workspace_size)
            if case.endswith('before'):
                if '_memory_' in case:
                    raise MemoryError('injected unknown native call return')
                raise KeyboardInterrupt('injected before actual native transition')
            actual_native_calls.append(event)
            returned = actual(source, source_size, output, output_size, workspace, workspace_size)
            if case == 'receipt':
                return returned | (1 << 32)
            if '_memory_' in case:
                raise MemoryError('injected after actual native transition')
            raise KeyboardInterrupt('injected after actual native transition')
        error = None
        with patch.object(policy.image, '_entry', side_effect=interrupted):
            try:
                if target == 1:
                    runtime.lease()
                elif target == 2:
                    lease.close()
                else:
                    runtime._collect(state)
            except (KeyboardInterrupt, NativeGenerationFailure, MemoryError) as observed:
                error = observed
        assert error is not None
        assert policy._fenced is not None
        assert fd_open(state.fd)
        assert state.library is not None
        later_calls = []
        def watch(source, source_size, output, output_size, workspace, workspace_size):
            event, = struct.unpack_from('<Q', source, 8)
            later_calls.append(event)
            return actual(source, source_size, output, output_size, workspace, workspace_size)
        with patch.object(policy.image, '_entry', side_effect=watch):
            for operation in (runtime.lease, runtime.close, runtime.retry_cleanup):
                try:
                    operation()
                except NativeGenerationFailure:
                    pass
        assert not any(event in (0, 1, 2, 3, 4) for event in later_calls), later_calls
        assert fd_open(state.fd)
        assert state.library is not None
        assert _QUARANTINED[(os.getpid(), policy._owner)] is policy
        if case not in ('state', 'cell'):
            observation = policy.observe()
            expected = (1 if case in ('acquire_after', 'acquire_memory_after', 'receipt', 'close_before') else 0)
            assert observation['references'] == expected, observation
            if case == 'claim_after':
                assert observation['claimed']
        weak_runtime, weak_state, weak_policy = weakref.ref(runtime), weakref.ref(state), weakref.ref(policy)
        owner_key = (os.getpid(), policy._owner)
        del runtime, state, lease, policy, error, operation
        gc.collect()
        assert weak_runtime() is not None and weak_state() is not None
        assert _QUARANTINED[owner_key] is weak_policy()
        assert generation_quarantine_snapshot()[0]['effects_permitted'] is False
        print(json.dumps({'status': 'PASS', 'control': case,
                          'intercepted_native_attempts': len(native_calls),
                          'actual_mutation_entry_calls': len(actual_native_calls),
                          'resource_custody_after_gc': True, 'mutation_replayed': False,
                          'resources_released_only_by_process_exit': True}, sort_keys=True))
    # No production reset/forget or descriptor close is available after fence.
    # Temporary pathname cleanup does not grant native resource release rights.
    temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
