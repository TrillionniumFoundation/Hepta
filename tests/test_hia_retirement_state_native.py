"""Independent VM, actual machine code and actual retained retirement owners."""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
import dis
import errno
import gc
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref

from hepta.hia_retirement_state_native import (EffectToken, NativeRetirementFailure,
    NativeRetirementImage, REQUEST_MAGIC, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE,
    STATE_BYTES, installed_retirement_state)

ROOT = Path(__file__).resolve().parents[1]


def packet(event, token=0, values=(), *, owner=(11, 17), path=b'', now=73):
    words = [REQUEST_MAGIC, event, token, now, *values]
    words.extend([0] * (14 - len(words)))
    return struct.pack('<16Q', *words, *owner) + path


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.checked = assemble_program(SOURCE.read_bytes())
        self.entry = next(f for f in self.checked.as_dict()['functions'] if f['name'] == 'f0')
        self.state = bytearray(STATE_BYTES)

    def call(self, raw, output_size=64):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'\xa5' * output_size)),
                  _Owner(-3, self.state)]
        machine = _Machine(self.checked, 50000000, 16 << 20, None, 128)
        code = machine.invoke(self.entry,
            [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        return code, bytes(owners[1].data), bytes(self.state)


class Machine:
    def __init__(self, image):
        self.image = image
        self.state = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memset(ctypes.addressof(self.state) + STATE_BYTES, 0x91, 16)

    def call(self, raw, output_size=64):
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        output = ctypes.create_string_buffer(b'\xa5' * (output_size + 16), output_size + 16)
        code = self.image._entry(source, len(raw), output, output_size, self.state, STATE_BYTES)
        assert source.raw == (raw or b'\0')
        assert output.raw[output_size:] == b'\xa5' * 16
        assert self.state.raw[STATE_BYTES:] == b'\x91' * 16
        return code, output.raw[:output_size], self.state.raw[:STATE_BYTES]


def receipt(row):
    assert row[0] == 64, row[0]
    fields = struct.unpack('<8Q', row[1])
    assert fields[0] == RESULT_MAGIC, fields
    return fields


def witnesses(engine):
    """Fixed independent state expectations, including descriptor zero."""
    rows = []
    def run(event, token=0, values=(), **kwargs):
        raw = packet(event, token, values, **kwargs)
        row = engine.call(raw)
        rows.append((raw, row))
        return receipt(row)
    r = run(0, values=(0,), path=b'/tmp/pin')
    assert (r[1], r[5], r[6]) == (0, 1, 1)
    r = run(2, values=(1, 7, 9)); acquisition = r[3]
    assert (r[2], acquisition) == (1, 2)
    r = run(3, acquisition, (0,))
    assert r[2] == 3 and r[4] == 0 and r[5] == 0
    r = run(4, acquisition, (7, 9, 0o100400, 7, 9))
    assert r[1] == 0 and r[5] == 2
    r = run(9, values=(0, 7, 9, 0o100400)); observe = r[3]
    assert r[2] == 3
    r = run(10, observe, (0, 7, 9)); observe = r[3]
    assert r[7] == 2
    r = run(20, values=(1, 7, 9, 1, 1, 8, 41), path=b'/tmp/pin')
    assert r[1] == 0
    r = run(21); native = r[3]
    assert r[2] == 7 and r[4] == 3
    r = run(22, native, (1, 1)); assert r[5] == 2
    r = run(22, native, (2, 0)); assert r[5] == 2
    r = run(23, native); assert r[5] == 2
    attempt = run(26)[3]
    observe = run(9, values=(0, 7, 9, 0o100400))[3]
    observe = run(10, observe, (0, 7, 9))[3]
    r = run(24, observe, (attempt,)); assert (r[2], r[4]) == (0, 2)
    attempt = run(26)[3]
    r = run(9, values=(1,)); observe = r[3]
    r = run(24, observe, (attempt,)); assert (r[2], r[4]) == (8, 1)
    r = run(8); assert r[1] == 0
    r = run(6); close = r[3]
    assert (r[2], r[4]) == (4, 0)
    r = run(7, close, (0,)); assert r[5] == 0
    r = run(6); assert r[2] == 0
    r = run(21); assert r[2] == 0
    r = run(1); assert r[5] == 0
    words = struct.unpack('<64Q', rows[-1][1][2][:512])
    assert words[5:7] == (1, 0)
    assert words[8:10] == (7, 9)
    assert words[12] == 2 and words[23:25] == (3, 2)
    assert words[28:30] == (2, 1)
    return rows


def independent_guard(state):
    """Test-only recomputation for canonical-state and overflow refusals."""
    words = list(struct.unpack('<576Q', state))
    value = 1469598103934665603
    for i, word in enumerate(words):
        if i != 49:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    words[49] = value
    return struct.pack('<576Q', *words)


class RetirementStateSourceTests(unittest.TestCase):
    def test_fixed_open_transport_matches_assembled_source(self):
        from hepta.hia_retirement_effects import OPEN_IMAGE, OPEN_SHA256
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['as', '--64', str(ROOT / 'tools/hia_retirement_open_syscalls.S'),
                            '-o', str(root / 'open.o')], check=True, capture_output=True)
            subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text',
                            str(root / 'open.o'), str(root / 'open.bin')], check=True, capture_output=True)
            actual = (root / 'open.bin').read_bytes()
            self.assertEqual(actual, OPEN_IMAGE)
            self.assertEqual(sha256(actual).hexdigest(), OPEN_SHA256)

    def test_generated_source_and_independent_vm_complete_state(self):
        from tools.generate_hia_retirement_state import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        rows = witnesses(VM())
        self.assertEqual(len(rows), 24)

    def test_default_reference_attributes_still_write_the_actual_backend(self):
        from hepta.hia_native_retirement import PathIdentityPin
        with patch.dict(os.environ, {SELECTOR: ''}):
            pin = PathIdentityPin(Path('/unused-no-effects'))
            pin.fd = 37
            pin.acquisition_attempted = True
            self.assertEqual(pin._backend.fd, 37)
            self.assertTrue(pin._backend.acquisition_attempted)
            self.assertNotIn('fd', pin.__dict__)

    def test_vm_wrong_instance_tokens_and_bad_bind_do_not_authorize(self):
        vm = VM()
        receipt(vm.call(packet(0, values=(0,), path=b'/p')))
        before = bytes(vm.state)
        self.assertEqual(receipt(vm.call(packet(2, values=(1, 1, 2), owner=(19, 23))))[1], 4)
        self.assertEqual(bytes(vm.state), before)
        claim = receipt(vm.call(packet(2, values=(1, 1, 2))))[3]
        receipt(vm.call(packet(3, claim, (5,))))
        bad = receipt(vm.call(packet(4, claim, (1, 3, 0o100400, 1, 3))))
        self.assertEqual(bad[1], 5)
        close = receipt(vm.call(packet(6)))
        self.assertEqual((close[2], close[4]), (4, 5))
        receipt(vm.call(packet(7, close[3], (1,))))
        before = bytes(vm.state)
        self.assertEqual(receipt(vm.call(packet(7, close[3], (1,))))[1], 4)
        self.assertEqual(bytes(vm.state), before)

    def test_vm_checksum_reserved_path_and_counter_exhaustion(self):
        for index, value, recalculate, expected in ((512, 255, False, 2), (57, 1, True, 2),
                                                   (2, (1 << 64) - 1, True, 6)):
            vm = VM()
            vm.call(packet(0, values=(0,), path=b'/p'))
            if index == 512:
                vm.state[index] = value
            else:
                struct.pack_into('<Q', vm.state, index * 8, value)
            if recalculate:
                vm.state[:] = independent_guard(vm.state)
            before = bytes(vm.state)
            self.assertEqual(receipt(vm.call(packet(2, values=(1, 1, 2))))[1], expected)
            self.assertEqual(bytes(vm.state), before)

    def test_vm_directory_observation_is_consumed_before_each_effect(self):
        for outcome in (None, 0, 2):
            with self.subTest(outcome=outcome):
                vm = VM()
                vm.call(packet(0, values=(1,), path=b'/directory'))
                claim = receipt(vm.call(packet(2, values=(1, 7, 9))))[3]
                vm.call(packet(3, claim, (42,)))
                vm.call(packet(4, claim, (7, 9, 0o40700, 7, 9)))
                observe = receipt(vm.call(packet(9, values=(0, 7, 9, 0o40700))))[3]
                observe = receipt(vm.call(packet(10, observe, (0, 7, 9))))[3]
                removal = receipt(vm.call(packet(11, observe)))
                self.assertEqual(removal[2], 6)
                if outcome is not None:
                    vm.call(packet(12, removal[3], (outcome,)))
                before = bytes(vm.state)
                replay = receipt(vm.call(packet(11, observe)))
                self.assertEqual((replay[1], replay[2]), (4, 0))
                self.assertEqual(bytes(vm.state), before)
                # A new original-identity observation allows a failed cleanup
                # retry, but a path recreated after successful release does not.
                fresh = receipt(vm.call(packet(9, values=(0, 7, 9, 0o40700))))
                if fresh[2] == 3:
                    fresh = receipt(vm.call(packet(10, fresh[3], (0, 7, 9))))
                decision = receipt(vm.call(packet(11, fresh[3])))
                self.assertEqual(decision[2], 0 if outcome == 0 else 6)

    def test_bad_cold_builder_refuses_before_output_or_compilation(self):
        from tools.build_hia_retirement_state import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not-qualified')
            (root / 'cold').write_bytes(b'{}')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(root / 'output', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'output').exists())


class RetirementStateNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vm_rows = witnesses(VM())
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cls.temporary = None
        retained = os.environ.get('HEPTA_HIA_RETIREMENT_STATE_EVIDENCE')
        if retained:
            base = Path(retained)
            base.mkdir(mode=0o700, exist_ok=True)
            cls.folder = base / cls.__name__
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-retirement-state-')
            cls.folder = Path(cls.temporary.name)
        development = os.environ.get('HEPTA_HIA_RETIREMENT_DEVELOPMENT_COMPILER')
        if development:
            compiler = Path(development)
            identity = {'mode': 'DEVELOPMENT_REUSED_COMPILER', 'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            identity = {'mode': 'DEVELOPMENT_B0_B1_B2', 'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}
        image, compiled = compile_stage(cls.folder, 'retirement-state', compiler, SOURCE.read_bytes())
        cls.image = NativeRetirementImage(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        manifest = {'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': cls.image.image_sha256,
            'compiler_sha256': identity['compiler_sha256']}
        cls.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
        (cls.folder / 'development-build.json').write_text(json.dumps({**identity,
            'source_sha256': manifest['source_sha256'], 'image_sha256': manifest['image_sha256'],
            'compile_receipt': compiled, 'matching_current_source_cold_qualified': False}, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def fixture_release_quarantine(self, before, *, release_task_resources=False):
        """Only these injected tests know no close ran for their returned fd.

        This is explicit fixture cleanup, never a product retry/forget API.
        Keep foreign records and never close a reused fd from an unknown test.
        """
        import hepta.hia_retirement_state_native as adapter
        for key in set(adapter._QUARANTINED) - before:
            owner = adapter._QUARANTINED[key]
            if release_task_resources and owner._retirement_custody is not None:
                import _ctypes
                task = owner._retirement_custody
                self.assertFalse(task.native_attempted)
                task.functions.clear()
                if task.library is not None:
                    _ctypes.dlclose(task.library._handle)
                if task.fd is not None:
                    os.close(task.fd)
            returned = owner._returned_open
            self.assertIsNotNone(returned)
            os.close(returned['descriptor'])
            del adapter._QUARANTINED[key]

    def test_fixed_open_result_slot_errors_flags_canaries_and_interrupted_retry(self):
        import fcntl
        from hepta.hia_retirement_effects import RetirementOpenPrimitive
        primitive = RetirementOpenPrimitive()
        allowed = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        def slot():
            storage = ctypes.create_string_buffer(32)
            ctypes.memset(ctypes.addressof(storage) + 16, 0xa7, 16)
            return storage, (ctypes.c_int64 * 2).from_buffer(storage)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'owned'; path.write_bytes(b'captured')
            link = root / 'link'; link.symlink_to(path)
            for target, flags, expected in ((path, allowed, None),
                    (root, allowed | os.O_DIRECTORY, None),
                    (root / 'missing', allowed, errno.ENOENT),
                    (link, allowed, errno.ELOOP), (path, allowed | os.O_DIRECTORY, errno.ENOTDIR)):
                storage, result = slot()
                if expected is None:
                    descriptor = primitive.open(target, flags, result)
                    try:
                        self.assertEqual(tuple(result), (2, descriptor))
                        self.assertTrue(fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
                        self.assertTrue(fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_NONBLOCK)
                        self.assertEqual(os.fstat(descriptor).st_ino, target.stat().st_ino)
                    finally:
                        os.close(descriptor)
                else:
                    with self.assertRaises(OSError) as caught:
                        primitive.open(target, flags, result)
                    self.assertEqual(caught.exception.errno, expected)
                    self.assertEqual(tuple(result), (2, -expected))
                self.assertEqual(storage.raw[16:], b'\xa7' * 16)
            for target, flags, initial in ((str(path) + '\0ignored', allowed, (0, 0)),
                    (path, allowed | os.O_CREAT, (0, 0)), (path, allowed, (1, 0)),
                    (path, allowed, (2, 0))):
                storage, result = slot(); result[:] = initial
                with patch.object(primitive, '_entry', side_effect=AssertionError('forbidden raw syscall')):
                    with self.assertRaises(ValueError): primitive.open(target, flags, result)
                self.assertEqual(tuple(result), initial)
                self.assertEqual(storage.raw[16:], b'\xa7' * 16)
            for invalid in ((ctypes.c_int64 * 1)(), (ctypes.c_int64 * 3)(),
                            (ctypes.c_int32 * 2)(), [0, 0]):
                with patch.object(primitive, '_entry', side_effect=AssertionError('invalid slot entered syscall')):
                    with self.assertRaisesRegex(ValueError, 'two-word slot'):
                        primitive.open(path, allowed, invalid)
            storage, result = slot()
            real_entry, attempts = primitive._entry, []
            def interrupted_once(pathname, flags, result, *unused):
                attempts.append(tuple(result))
                if len(attempts) == 1:
                    result[:] = (2, -errno.EINTR)
                    return 0
                return real_entry(pathname, flags, result, *unused)
            with patch.object(primitive, '_entry', side_effect=interrupted_once):
                descriptor = primitive.open(path, allowed, result)
            try:
                self.assertEqual(attempts, [(0, 0), (2, -errno.EINTR)])
                self.assertEqual(tuple(result), (2, descriptor))
                self.assertEqual(storage.raw[16:], b'\xa7' * 16)
            finally:
                os.close(descriptor)

    def test_actual_open_result_descriptor_zero_is_held_and_closed_once(self):
        # The child admits the actual image before making fd zero available.
        # Its stdin lifetime is isolated from the runner and other tests.
        program = '''import json, os, sys
from pathlib import Path
from hepta.hia_native_retirement import PathIdentityPin, NativeRetirement
from hepta.hia_retirement_state_native import selected_retirement_state
selected_retirement_state()
path = Path(sys.argv[1])
info = path.stat()
pin = PathIdentityPin(path)
os.close(0)
pin.acquire((info.st_dev, info.st_ino))
assert pin.fd == 0, pin.fd
assert pin._backend._open_result[:] == [2, 0]
assert os.fstat(0).st_ino == info.st_ino
before = pin.snapshot()
assert before['identity_fd_held'] and not before['release_succeeded']
task = NativeRetirement(1, 'actual-fd-zero', path, pin.inode, None, {}, None, pin)
observed = task.attempt()
assert observed['complete'] and not path.exists()
try:
    os.fstat(0)
except OSError:
    pass
else:
    raise AssertionError('fd zero remained open after confirmed identity close')
print(json.dumps({'descriptor': 0, 'before': before, 'after': observed}, sort_keys=True))
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owned'; path.write_bytes(b'fd zero')
            result = subprocess.run([sys.executable, '-c', program, str(path)], cwd=ROOT,
                env={**os.environ, SELECTOR: str(self.manifest)}, input='', text=True,
                capture_output=True, timeout=20)
            (self.folder / 'actual-open-fd-zero.stdout').write_text(result.stdout)
            (self.folder / 'actual-open-fd-zero.stderr').write_text(result.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['descriptor'], 0)

    def test_actual_open_result_survives_line_and_store_opcode_interruption(self):
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        code = adapter.NativePathIdentityPin.acquire.__code__
        instructions = list(dis.get_instructions(code))
        store = next(row for row in instructions if row.opname == 'STORE_FAST' and row.argval == 'descriptor')
        for boundary in ('line-after-open', 'opcode-before-store'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory, self.selected():
                before = set(adapter._QUARANTINED)
                path = Path(directory) / 'owned'; path.write_bytes(b'kernel-recorded descriptor')
                pin = public.PathIdentityPin(path)
                info = path.stat()
                interruption = KeyboardInterrupt(boundary)
                observed = []
                def trace(frame, event, arg):
                    if frame.f_code is code:
                        frame.f_trace_opcodes = True
                        reached = (event == 'opcode' and frame.f_lasti == store.offset
                                   if boundary == 'opcode-before-store' else
                                   event == 'line' and 'descriptor' in frame.f_locals
                                   and pin._backend._returned_open is None)
                        if reached:
                            observed.append({'stage': list(pin._backend._open_result),
                                'local_descriptor_present': 'descriptor' in frame.f_locals})
                            raise interruption
                    return trace
                try:
                    trace_frame = sys._getframe()
                    previous_opcode_flag = trace_frame.f_trace_opcodes
                    trace_frame.f_trace_opcodes = True
                    try:
                        sys.settrace(trace)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            pin.acquire((info.st_dev, info.st_ino))
                    finally:
                        sys.settrace(None)
                        trace_frame.f_trace_opcodes = previous_opcode_flag
                    self.assertIs(caught.exception, interruption)
                    self.assertEqual(len(observed), 1)
                    self.assertEqual(observed[0]['local_descriptor_present'], boundary == 'line-after-open')
                    snapshot = pin.snapshot()
                    descriptor = snapshot['quarantined_open_result']['descriptor']
                    self.assertEqual(observed[0]['stage'], [2, descriptor])
                    self.assertEqual(os.fstat(descriptor).st_ino, info.st_ino)
                    self.assertFalse(snapshot['release_succeeded'])
                    self.assertFalse(snapshot['quarantined_open_result']['native_transition_confirmed'])
                    self.assertEqual(snapshot['foreign_open_result_slot']['kernel_result'], descriptor)
                    self.assertEqual(len(public.retirement_quarantine_snapshot()), len(before) + 1)
                    with patch('hepta.hia_native_retirement.os.close') as close, patch.object(Path, 'unlink') as unlink:
                        with self.assertRaises(NativeRetirementFailure): pin.acquire((info.st_dev, info.st_ino))
                        with self.assertRaises(NativeRetirementFailure): public.PathIdentityPin(path)
                        close.assert_not_called(); unlink.assert_not_called()
                finally:
                    self.fixture_release_quarantine(before)

    def test_unconfirmed_open_primitive_retains_unknown_instead_of_no_fd_success(self):
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        for stage in (0, 1):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory, self.selected():
                before = set(adapter._QUARANTINED)
                path = Path(directory) / 'owned'; path.write_bytes(b'no actual kernel open in this fault')
                pin = public.PathIdentityPin(path)
                info = path.stat()
                def interrupted(path, flags, result):
                    result[0] = stage
                    raise KeyboardInterrupt('fixed foreign primitive interrupted')
                try:
                    with patch.object(pin._backend._state.image._open_primitive, 'open', side_effect=interrupted):
                        with self.assertRaises(KeyboardInterrupt): pin.acquire((info.st_dev, info.st_ino))
                    snapshot = pin.snapshot()
                    self.assertEqual(snapshot['release_succeeded'], stage == 0)
                    self.assertEqual(len(public.retirement_quarantine_snapshot()), len(before) + int(stage == 1))
                    if stage == 1:
                        self.assertEqual(snapshot['foreign_open_result_slot']['outcome'], 'unknown')
                        self.assertIsNone(snapshot['foreign_open_result_slot']['kernel_result'])
                        self.assertNotIn('quarantined_open_result', snapshot)
                        with patch('hepta.hia_native_retirement.os.close') as close:
                            with self.assertRaises(NativeRetirementFailure): pin._close_once()
                            close.assert_not_called()
                finally:
                    # This fixture never entered a syscall; remove only its
                    # deliberately injected unknown marker, with no close.
                    for key in set(adapter._QUARANTINED) - before:
                        self.assertIs(adapter._QUARANTINED[key], pin._backend)
                        del adapter._QUARANTINED[key]

    def test_machine_matches_every_vm_byte_and_preserves_canaries(self):
        machine = Machine(self.image)
        for raw, expected in self.vm_rows:
            self.assertEqual(machine.call(raw), expected)
        before = machine.state.raw
        for raw, capacity in ((b'bad', 64), (packet(1), 63)):
            code, output, _ = machine.call(raw, capacity)
            self.assertEqual(code, 0xfffffffd)
            self.assertEqual(output, b'\xa5' * capacity)
            self.assertEqual(machine.state.raw, before)

    def test_machine_directory_tokens_cannot_replay_pending_removed_or_error(self):
        for outcome in (None, 0, 2):
            with self.subTest(outcome=outcome):
                machine = Machine(self.image)
                machine.call(packet(0, values=(1,), path=b'/directory'))
                claim = receipt(machine.call(packet(2, values=(1, 7, 9))))[3]
                machine.call(packet(3, claim, (42,)))
                machine.call(packet(4, claim, (7, 9, 0o40700, 7, 9)))
                observed = receipt(machine.call(packet(9, values=(0, 7, 9, 0o40700))))[3]
                observed = receipt(machine.call(packet(10, observed, (0, 7, 9))))[3]
                effect = receipt(machine.call(packet(11, observed)))
                self.assertEqual(effect[2], 6)
                if outcome is not None:
                    machine.call(packet(12, effect[3], (outcome,)))
                before = machine.state.raw
                replay = receipt(machine.call(packet(11, observed)))
                self.assertEqual((replay[1], replay[2]), (4, 0))
                self.assertEqual(machine.state.raw, before)

    def test_native_owner_fail_closed_on_state_damage_and_foreign_token(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = self.image.owner(Path(directory) / 'original')
            foreign = self.image.owner(Path(directory) / 'other')
            claim = owner.call(2, values=(1, 3, 5))
            with self.assertRaisesRegex(NativeRetirementFailure, 'state/token'):
                foreign.call(3, token=claim.token, values=(0,))
            self.assertIsNotNone(foreign._fenced)
            self.assertEqual(foreign.query()[1], 0)
            owner._buffer[512] = b'\xff'
            with self.assertRaisesRegex(NativeRetirementFailure, 'state/token'):
                owner.call(3, token=claim.token, values=(0,))
            with self.assertRaisesRegex(NativeRetirementFailure, 'fenced'):
                owner.call(1)

    def test_source_custody_missing_selection_never_enters_reference(self):
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {SELECTOR: str(root / 'missing')}), \
                    patch.object(public._ReferencePathIdentityPin, '__init__', side_effect=AssertionError('hosted fallback')):
                with self.assertRaises(FileNotFoundError): public.PathIdentityPin(root / 'pin')
            copied = root / 'retirement_state.hiaasm'
            copied.write_bytes(SOURCE.read_bytes())
            with patch.object(adapter, 'SOURCE', copied):
                self.assertIsNotNone(installed_retirement_state(str(self.manifest)))
                copied.write_bytes(copied.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    installed_retirement_state(str(self.manifest))

    def test_installed_wheel_actual_retirement_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        case = self.folder / 'installed-wheel-control'
        case.mkdir(mode=0o700)
        source = case / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(source)],
            cwd=case, capture_output=True, timeout=120)
        (case / 'wheel-build.log').write_bytes(built.stdout + built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([packaging, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=case, capture_output=True, timeout=120)
        (case / 'wheel-install.log').write_bytes(copied.stdout + copied.stderr)
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        child = r'''import importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed retirement imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_native_retirement as public
from hepta.hia_retirement_state_native import SOURCE,SELECTOR,installed_retirement_state
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed retirement entered hosted policy')
public._ReferencePathIdentityPin.__init__=forbidden
public._ReferenceNativeRetirement.__init__=forbidden
public._reference_observe_directory=forbidden
public._reference_remove_directory=forbidden
os.environ[SELECTOR]=sys.argv[2]
root=Path(sys.argv[3]);root.mkdir()
directory=public.PathIdentityPin(root,True)
info=root.stat();directory.acquire((info.st_dev,info.st_ino))
path=root/'owned';path.write_bytes(b'installed native retirement')
pin=public.PathIdentityPin(path);info=path.stat();pin.acquire((info.st_dev,info.st_ino))
task=public.NativeRetirement(7,'installed',path,pin.inode,None,{},None,pin)
result=task.attempt()
assert result['complete'] and result['native_release_succeeded'],result
assert result['disk']['status']=='removed' and not path.exists(),result
closed=public.remove_directory(root,directory.inode,directory)
assert closed['status']=='removed' and not root.exists(),closed
assert closed['identity_pin']['release_succeeded'],closed
SOURCE.write_bytes(SOURCE.read_bytes()+b'\n')
try:installed_retirement_state(sys.argv[2])
except ValueError:pass
else:raise AssertionError('warm native image hid installed source drift')
assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
print(json.dumps({'status':'INSTALLED_NATIVE_RETIREMENT_PASS','artifact':result,'directory':closed},sort_keys=True))
'''
        observed = subprocess.run([sys.executable, '-I', '-B', '-c', child, str(installed),
            str(self.manifest), str(case / 'actual-owned')], cwd=case, capture_output=True, timeout=60)
        (case / 'actual-retirement.stdout').write_bytes(observed.stdout)
        (case / 'actual-retirement.stderr').write_bytes(observed.stderr)
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)
        self.assertEqual(json.loads(observed.stdout)['status'], 'INSTALLED_NATIVE_RETIREMENT_PASS')

    def test_clear_interruption_keeps_unknown_handles_and_forbids_replay(self):
        import hepta.hia_native_retirement as public
        class InterruptedFunctions(dict):
            def clear(self): raise KeyboardInterrupt('before native release after claim')
        with tempfile.TemporaryDirectory() as directory, self.selected():
            path = Path(directory) / 'owned'
            path.write_bytes(b'owned bytes')
            info = path.stat()
            pin = public.PathIdentityPin(path)
            pin.acquire((info.st_dev, info.st_ino))
            descriptor = os.open(path, os.O_RDONLY)
            library = type('ForeignLibrary', (), {'_handle': 123})()
            task = public.NativeRetirement(1, 'fault', path, pin.inode, library,
                                           InterruptedFunctions(), descriptor, pin)
            try:
                with patch('_ctypes.dlclose', side_effect=AssertionError('unload after interruption')), \
                     patch('hepta.hia_native_retirement.os.close', side_effect=AssertionError('close after interruption')):
                    with self.assertRaises(KeyboardInterrupt): task.attempt()
                    result = task.attempt()
                    self.assertEqual(result['native']['library']['status'], 'unknown')
                    self.assertEqual(result['native']['fd']['status'], 'unknown')
                    self.assertEqual(result['disk']['status'], 'blocked_by_uncertain_native_release')
                    self.assertFalse(result['complete'])
                os.fstat(descriptor)
            finally:
                # The fixture knows its functions.clear prevented both calls.
                os.close(descriptor)
                path.unlink()
                pin.observe()
                pin.release_absent_path()

    def test_actual_close_effect_then_errno_or_lost_native_ack_never_recloses_reuse(self):
        import hepta.hia_native_retirement as public
        for mode in ('errno-after-effect', 'lost-native-ack'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, self.selected():
                root = Path(directory)
                path, marker = root / 'owned', root / 'foreign'
                path.write_bytes(b'owned'); marker.write_bytes(b'foreign descriptor')
                pin = public.PathIdentityPin(path)
                info = path.stat(); pin.acquire((info.st_dev, info.st_ino))
                descriptor = os.open(path, os.O_RDONLY)
                task = public.NativeRetirement(1, mode, path, pin.inode, None, {}, descriptor, pin)
                real_close = os.close
                reused = []
                def reuse():
                    other = os.open(marker, os.O_RDONLY)
                    if other != descriptor:
                        os.dup2(other, descriptor); real_close(other)
                    reused.append(descriptor)
                def close_then_raise(fd):
                    real_close(fd)
                    if fd == descriptor:
                        reuse()
                        raise OSError(errno.EINTR, 'actual native close completed before reported error')
                state = task._backend._state
                original_call = state.call
                def lost_ack(event, **kwargs):
                    if event == 22 and kwargs.get('values') == (2, 1):
                        reuse()
                        raise KeyboardInterrupt('closed native fd before HIA completion acknowledgment')
                    return original_call(event, **kwargs)
                try:
                    if mode == 'errno-after-effect':
                        with patch('hepta.hia_native_retirement.os.close', close_then_raise):
                            task.attempt()
                    else:
                        with patch.object(state, 'call', side_effect=lost_ack):
                            with self.assertRaises(KeyboardInterrupt): task.attempt()
                    self.assertEqual(reused, [descriptor])
                    with patch('hepta.hia_native_retirement.os.close') as close, patch('_ctypes.dlclose') as unload:
                        observed = task.attempt()
                        close.assert_not_called(); unload.assert_not_called()
                    self.assertEqual(observed['native']['fd']['status'], 'unknown')
                    self.assertFalse(observed['complete'])
                    self.assertEqual(os.pread(descriptor, 7, 0), b'foreign')
                    path.unlink()
                    with patch('hepta.hia_native_retirement.os.close', wraps=real_close) as close:
                        task.attempt()
                        close.assert_called_once_with(pin.fd)
                    self.assertEqual(os.pread(descriptor, 7, 0), b'foreign')
                finally:
                    if reused:
                        real_close(descriptor)

    def test_actual_identity_close_unknown_preserves_recreated_path_and_reused_fd(self):
        import hepta.hia_native_retirement as public
        with tempfile.TemporaryDirectory() as directory, self.selected():
            root = Path(directory)
            path, marker = root / 'owned', root / 'foreign'
            path.write_bytes(b'owned'); marker.write_bytes(b'caller descriptor')
            pin = public.PathIdentityPin(path)
            info = path.stat(); pin.acquire((info.st_dev, info.st_ino))
            descriptor, real_close = pin.fd, os.close
            task = public.NativeRetirement(1, 'identity-close', path, pin.inode, None, {}, None, pin)
            reused = []
            def close_then_raise(fd):
                real_close(fd)
                if fd == descriptor:
                    other = os.open(marker, os.O_RDONLY)
                    if other != descriptor:
                        os.dup2(other, descriptor); real_close(other)
                    reused.append(descriptor)
                    raise OSError(errno.EINTR, 'identity close already took effect')
            try:
                with patch('hepta.hia_native_retirement.os.close', close_then_raise):
                    observed = task.attempt()
                self.assertTrue(observed['native_release_succeeded'])
                self.assertFalse(observed['complete'])
                self.assertEqual(observed['artifact_identity_pin']['close']['status'], 'unknown')
                path.write_bytes(b'new owner at the old path')
                with patch('hepta.hia_native_retirement.os.close') as close, patch('_ctypes.dlclose') as unload:
                    observed = task.attempt()
                    close.assert_not_called(); unload.assert_not_called()
                self.assertEqual(observed['disk']['before']['status'], 'recreated_after_release')
                self.assertEqual(path.read_bytes(), b'new owner at the old path')
                self.assertEqual(os.pread(descriptor, 6, 0), b'caller')
            finally:
                if reused: real_close(descriptor)

    def test_directory_argument_cannot_discharge_another_pinned_path(self):
        import hepta.hia_native_retirement as public
        with tempfile.TemporaryDirectory() as directory, self.selected():
            root = Path(directory)
            owned = root / 'owned'; owned.mkdir()
            pin = public.PathIdentityPin(owned, True)
            info = owned.stat(); pin.acquire((info.st_dev, info.st_ino))
            observed = public.remove_directory(root / 'never-created', pin.inode, pin)
            self.assertEqual(observed['status'], 'already_absent')
            self.assertTrue(owned.is_dir())
            self.assertFalse(pin.path_released)
            os.fstat(pin.fd)
            observed = public.remove_directory(owned, pin.inode, pin)
            self.assertEqual(observed['status'], 'removed')
            self.assertTrue(pin.release_succeeded)

    def test_returned_open_custody_survives_pre_and_post_transition_failure(self):
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        for after in (False, True):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory, self.selected():
                before = set(adapter._QUARANTINED)
                path = Path(directory) / 'owned'; path.write_bytes(b'returned descriptor')
                pin = public.PathIdentityPin(path)
                state = pin._backend._state
                original = state.call
                interruption = KeyboardInterrupt('open handoff after' if after else 'open handoff before')
                def interrupt(event, **kwargs):
                    if event == 3:
                        if after: original(event, **kwargs)
                        raise interruption
                    return original(event, **kwargs)
                try:
                    info = path.stat()
                    with patch.object(state, 'call', side_effect=interrupt):
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            pin.acquire((info.st_dev, info.st_ino))
                    self.assertIs(caught.exception, interruption)
                    self.assertIs(caught.exception.hia_retirement_owner, pin._backend)
                    snapshot = pin.snapshot()
                    returned = snapshot['quarantined_open_result']
                    self.assertFalse(returned['native_transition_confirmed'])
                    self.assertFalse(snapshot['release_succeeded'])
                    self.assertEqual(os.fstat(returned['descriptor']).st_ino, info.st_ino)
                    task = public.NativeRetirement(19, 'fenced-acquisition', path,
                        (info.st_dev, info.st_ino), None, {}, None, pin)
                    with patch('hepta.hia_native_retirement.os.close') as close, \
                         patch.object(Path, 'unlink') as unlink:
                        report = task.attempt()
                        close.assert_not_called(); unlink.assert_not_called()
                    self.assertEqual(report['generation'], 19)
                    self.assertFalse(report['complete'])
                    self.assertFalse(report['quarantined_foreign_resources']['native_task_attachment_confirmed'])
                    self.assertEqual(len(public.retirement_quarantine_snapshot()), len(before) + 1)
                    with self.assertRaisesRegex(NativeRetirementFailure, 'quarantined'):
                        public.PathIdentityPin(Path(directory) / 'not-created')
                finally:
                    self.fixture_release_quarantine(before)

    def test_task_attachment_failure_keeps_foreign_handles_after_exception_and_gc(self):
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        native_code = adapter.NativeRetirement.__init__.__code__
        facade_code = public.NativeRetirement.__init__.__code__
        stores = {row.offset for row in dis.get_instructions(facade_code)
                  if row.opname == 'STORE_ATTR' and row.argval == '_backend'}
        for boundary in ('before-transition', 'after-transition', 'line-after-transition', 'opcode-before-wrapper-store'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory, self.selected():
                before = set(adapter._QUARANTINED)
                path = Path(directory) / 'owned'; path.write_bytes(b'foreign task resources')
                def interrupted_attachment():
                    pin = public.PathIdentityPin(path)
                    info = path.stat(); pin.acquire((info.st_dev, info.st_ino))
                    descriptor = os.open(path, os.O_RDONLY)
                    library = ctypes.CDLL('libm.so.6')
                    functions = {'sqrt': library.sqrt}
                    reference = weakref.ref(library)
                    state, attempts = pin._backend._state, []
                    original = state.call
                    def interrupt(event, **kwargs):
                        if event == 20:
                            attempts.append(event)
                            if boundary == 'after-transition': original(event, **kwargs)
                            if boundary in ('before-transition', 'after-transition'):
                                raise KeyboardInterrupt('task attachment handoff')
                        return original(event, **kwargs)
                    traced = []
                    def trace(frame, event, arg):
                        if frame.f_code is native_code or frame.f_code is facade_code:
                            frame.f_trace_opcodes = True
                            if (boundary == 'line-after-transition' and event == 'line'
                                    and frame.f_code is native_code and state._words[15] == 1
                                    or boundary == 'opcode-before-wrapper-store' and event == 'opcode'
                                    and frame.f_code is facade_code and frame.f_lasti in stores
                                    and state._words[15] == 1):
                                traced.append(boundary)
                                raise KeyboardInterrupt(boundary)
                        return trace
                    trace_frame = sys._getframe()
                    previous_opcode_flag = trace_frame.f_trace_opcodes
                    trace_frame.f_trace_opcodes = True
                    try:
                        if boundary in ('line-after-transition', 'opcode-before-wrapper-store'):
                            sys.settrace(trace)
                        with patch.object(state, 'call', side_effect=interrupt):
                            task = public.NativeRetirement(19, 'attachment', path, pin.inode,
                                                           library, functions, descriptor, pin)
                    finally:
                        sys.settrace(None)
                        trace_frame.f_trace_opcodes = previous_opcode_flag
                    self.assertEqual(attempts, [20])
                    self.assertEqual(traced, [] if boundary in ('before-transition', 'after-transition') else [boundary])
                    recovered = public.NativeRetirement(19, 'attachment', path, pin.inode,
                                                        library, functions, descriptor, pin)
                    self.assertIs(recovered._backend, task._backend)
                    with self.assertRaisesRegex(ValueError, 'different retirement'):
                        public.NativeRetirement(20, 'different', path, pin.inode,
                                                library, functions, descriptor, pin)
                    with patch('hepta.hia_native_retirement.os.close') as close, patch('_ctypes.dlclose') as unload:
                        observed = task.attempt()
                        close.assert_not_called(); unload.assert_not_called()
                    self.assertFalse(observed['complete'])
                    self.assertEqual(observed['quarantined_foreign_resources']['native_task_attachment_confirmed'],
                                     boundary == 'opcode-before-wrapper-store')
                    return reference, descriptor
                try:
                    reference, descriptor = interrupted_attachment()
                    gc.collect()
                    self.assertIsNotNone(reference(), 'quarantine must strongly retain the actual foreign library')
                    self.assertEqual(os.fstat(descriptor).st_ino, path.stat().st_ino)
                    rows = public.retirement_quarantine_snapshot()
                    self.assertEqual(len(rows), len(before) + 1)
                    task = rows[-1]['retirement_task_custody']
                    self.assertEqual(task['generation'], 19)
                    self.assertEqual(task['native_descriptor'], descriptor)
                    self.assertTrue(task['library_held'])
                    self.assertEqual(task['function_references'], 1)
                    self.assertFalse(task['effects_permitted'])
                finally:
                    self.fixture_release_quarantine(before, release_task_resources=True)

    def test_actual_runtime_task_attachment_failure_preserves_original_prepare_error(self):
        from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program
        from hepta.hia_multiversion import ScalarMultiversionRuntime
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        self.assertTrue(_NATIVE, 'actual original Clang/Z3/memfd prerequisites are required')
        for after in (False, True):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory, self.selected():
                before = set(adapter._QUARANTINED)
                runtime = ScalarMultiversionRuntime(scalar_program(), directory, clang=_CLANG,
                                                    max_live_generations=3)
                original_error = OSError(errno.EIO, 'original native mapping admission failure')
                real_call, failed = adapter.RetirementState.call, []
                def interrupt(state, event, **kwargs):
                    if event == 20 and state.path.name == 'generation-1.so' and not failed:
                        failed.append(state)
                        if after: real_call(state, event, **kwargs)
                        raise KeyboardInterrupt('native task attachment interrupted')
                    return real_call(state, event, **kwargs)
                try:
                    with patch('hepta.hia_multiversion.verify_loaded_symbols', side_effect=original_error), \
                         patch.object(adapter.RetirementState, 'call', interrupt):
                        with self.assertRaises(OSError) as caught:
                            runtime.publish(scalar_program(None))
                    self.assertIs(caught.exception, original_error)
                    self.assertEqual(len(failed), 1)
                    task = runtime._cleanup_pending[1]
                    descriptor = task.fd
                    self.assertIsNotNone(task.library)
                    reference = weakref.ref(task.library)
                    os.fstat(descriptor)
                    report = runtime.snapshot()['cleanup']
                    self.assertEqual(report['pending_resource_count'], 1)
                    self.assertEqual(report['pending'][0]['generation'], 1)
                    self.assertFalse(report['pending'][0]['complete'])
                    self.assertEqual(runtime.call('calculate', [31]), 31)
                    runtime.close()
                    with patch('hepta.hia_native_retirement.os.close') as close, patch('_ctypes.dlclose') as unload:
                        report = runtime.retry_cleanup()
                        close.assert_not_called(); unload.assert_not_called()
                    self.assertEqual(len(report['pending']), 1)
                    self.assertFalse(report['pending'][0]['complete'])
                    original_error.__traceback__ = None
                    gc.collect()
                    self.assertIsNotNone(reference())
                    self.assertTrue(public.retirement_quarantine_snapshot()[-1]['retirement_task_custody']['library_held'])
                finally:
                    runtime.close()
                    self.fixture_release_quarantine(before, release_task_resources=True)
                    for state in failed:
                        state.path.unlink(missing_ok=True)
                    runtime.retry_cleanup()

    def test_reentrant_clear_keeps_one_claim_and_original_interruption_behavior(self):
        import _ctypes
        import hepta.hia_native_retirement as public
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt), tempfile.TemporaryDirectory() as directory, self.selected():
                path = Path(directory) / 'owned'; path.write_bytes(b'owned')
                pin = public.PathIdentityPin(path)
                info = path.stat(); pin.acquire((info.st_dev, info.st_ino))
                descriptor = os.open(path, os.O_RDONLY)
                library = ctypes.CDLL('libm.so.6')
                handle, real_unload, real_close = library._handle, _ctypes.dlclose, os.close
                nested = []
                class ReentrantFunctions(dict):
                    def clear(self):
                        nested.append(task.attempt())
                        os.fstat(descriptor)
                        if interrupt: raise KeyboardInterrupt('after reentrant retirement observation')
                        super().clear()
                functions = ReentrantFunctions({'sqrt': library.sqrt})
                task = public.NativeRetirement(3, 'reentrant-clear', path, pin.inode,
                                               library, functions, descriptor, pin)
                try:
                    with patch('_ctypes.dlclose', wraps=real_unload) as unload, \
                         patch('hepta.hia_native_retirement.os.close', wraps=real_close) as close:
                        if interrupt:
                            with self.assertRaises(KeyboardInterrupt): task.attempt()
                            self.assertFalse(task.attempt()['complete'])
                            unload.assert_not_called(); close.assert_not_called()
                        else:
                            self.assertTrue(task.attempt()['complete'])
                            unload.assert_called_once_with(handle)
                            self.assertEqual([call.args[0] for call in close.call_args_list], [descriptor, pin.fd])
                    self.assertEqual(len(nested), 1)
                    self.assertEqual(nested[0]['native']['library']['status'], 'unknown')
                    self.assertEqual(nested[0]['native']['fd']['status'], 'unknown')
                    self.assertFalse(nested[0]['complete'])
                finally:
                    if interrupt:
                        # Fixture has observed neither foreign release ran.
                        real_unload(handle); real_close(descriptor)
                        path.unlink(); pin.observe(); pin.release_absent_path()

    def test_native_readonly_metadata_path_bound_and_observation_interruption(self):
        import hepta.hia_native_retirement as public
        with tempfile.TemporaryDirectory() as directory, self.selected():
            path = Path(directory) / 'owned'; path.write_bytes(b'owned')
            pin = public.PathIdentityPin(path)
            with self.assertRaises(AttributeError): pin.fd = 42
            self.assertNotIn('fd', pin.__dict__)
            info = path.stat(); pin.acquire((info.st_dev, info.st_ino))
            task = public.NativeRetirement(4, 'observe-interruption', path, pin.inode, None, {}, None, pin)
            original = Path.lstat
            def interrupted(current, *args, **kwargs):
                if current == path: raise KeyboardInterrupt('before observation returned')
                return original(current, *args, **kwargs)
            with patch.object(Path, 'lstat', interrupted):
                with self.assertRaises(KeyboardInterrupt): task.attempt()
            observed = task.snapshot()
            self.assertEqual(observed['disk_attempts'], 1)
            self.assertNotIn('before', observed['disk'])
            self.assertNotIn('status', observed['disk'])
            self.assertTrue(task.attempt()['complete'])
            bounded = public.PathIdentityPin(Path('/' + 'x' * 4095))
            self.assertEqual(bounded._backend._state._words[45], 4096)
            with self.assertRaisesRegex(ValueError, '4096-byte'):
                public.PathIdentityPin(Path('/' + 'x' * 4096))

    def test_actual_runtime_acquire_handoff_failure_preserves_error_and_custody(self):
        from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program
        from hepta.hia_multiversion import ScalarMultiversionRuntime
        import hepta.hia_native_retirement as public
        import hepta.hia_retirement_state_native as adapter
        self.assertTrue(_NATIVE, 'actual original Clang/Z3/memfd qualification prerequisites are required')
        for boundary in ('directory-construction', 'artifact-publication'):
            for after in (False, True):
                with self.subTest(boundary=boundary, after=after), tempfile.TemporaryDirectory() as directory, self.selected():
                    before = set(adapter._QUARANTINED)
                    root = Path(directory)
                    runtime = None
                    if boundary == 'artifact-publication':
                        runtime = ScalarMultiversionRuntime(scalar_program(), root, clang=_CLANG,
                                                           max_live_generations=3)
                    real_call = adapter.RetirementState.call
                    failed = []
                    original_error = OSError(errno.EIO, boundary + (' after native fd registration' if after else ' before native fd registration'))
                    def interrupt(state, event, **kwargs):
                        target = (state.path.name.startswith('hia-multiversion-') if boundary == 'directory-construction'
                                  else state.path.name == 'generation-1.so')
                        if event == 3 and target and not failed:
                            failed.append(state)
                            if after: real_call(state, event, **kwargs)
                            raise original_error
                        return real_call(state, event, **kwargs)
                    try:
                        with patch.object(adapter.RetirementState, 'call', interrupt):
                            with self.assertRaises(OSError) as caught:
                                if runtime is None:
                                    ScalarMultiversionRuntime(scalar_program(), root, clang=_CLANG)
                                else:
                                    runtime.publish(scalar_program(None))
                        self.assertIs(caught.exception, original_error)
                        self.assertEqual(len(failed), 1)
                        returned = failed[0]._custodian.snapshot()['quarantined_open_result']
                        os.fstat(returned['descriptor'])
                        quarantines = public.retirement_quarantine_snapshot()
                        self.assertEqual(len(quarantines), len(before) + 1)
                        self.assertFalse(quarantines[-1]['release_succeeded'])
                        if runtime is None:
                            report = caught.exception.hia_cleanup
                            self.assertEqual(report['pending_resource_count'], 1)
                            self.assertEqual(report['directory_cleanup']['status'], 'refused_unowned_or_unobservable')
                            self.assertEqual(report['directory_observation']['status'], 'error')
                            paths = sorted(root.iterdir())
                            with self.assertRaisesRegex(NativeRetirementFailure, 'quarantined'):
                                ScalarMultiversionRuntime(scalar_program(), root, clang=_CLANG)
                            self.assertEqual(sorted(root.iterdir()), paths)
                        else:
                            report = runtime.snapshot()['cleanup']
                            self.assertEqual(report['pending_resource_count'], 1)
                            self.assertEqual(report['pending'][0]['generation'], 1)
                            self.assertFalse(report['pending'][0]['complete'])
                            self.assertEqual(runtime.call('calculate', [29]), 29)
                            with patch('hepta.hia_multiversion.build_program_native', side_effect=AssertionError('new compile after quarantine')):
                                with self.assertRaisesRegex(NativeRetirementFailure, 'quarantined'):
                                    runtime.publish(scalar_program(None))
                            runtime.close()
                            retained = runtime.retry_cleanup()
                            self.assertEqual(len(retained['pending']), 1)
                            self.assertFalse(retained['pending'][0]['complete'])
                    finally:
                        if runtime is not None:
                            runtime.close()
                        self.fixture_release_quarantine(before)
                        if runtime is not None:
                            # Resolve only the fixture's known unopened code
                            # artifact; no production close/retirement replay.
                            for state in failed:
                                state.path.unlink(missing_ok=True)
                            runtime.retry_cleanup()

    def test_actual_runtime_native_directory_owner_is_prepared_before_creation(self):
        from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program
        from hepta.hia_multiversion import ScalarMultiversionRuntime
        import hepta.hia_retirement_state_native as adapter
        self.assertTrue(_NATIVE, 'actual original Clang/Z3/memfd prerequisites are required')
        for after in (False, True):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory, self.selected():
                root = Path(directory)
                before = set(adapter._QUARANTINED)
                original = adapter.RetirementState.call
                error = OSError(errno.EIO, 'native directory initialization interrupted')
                attempted = []
                def interrupt(state, event, **kwargs):
                    if event == 0 and state.path.name.startswith('hia-multiversion-'):
                        attempted.append(state.path)
                        if after: original(state, event, **kwargs)
                        raise error
                    return original(state, event, **kwargs)
                with patch.object(adapter.RetirementState, 'call', interrupt):
                    with self.assertRaises(OSError) as caught:
                        ScalarMultiversionRuntime(scalar_program(), root, clang=_CLANG)
                self.assertIs(caught.exception, error)
                self.assertEqual(len(attempted), 1)
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(set(adapter._QUARANTINED), before)

    def test_actual_runtime_latched_directory_owner_survives_next_image_admission_failure(self):
        from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program
        from hepta.hia_multiversion import ScalarMultiversionRuntime
        import hepta.hia_retirement_state_native as adapter
        self.assertTrue(_NATIVE, 'actual original Clang/Z3/memfd prerequisites are required')
        with tempfile.TemporaryDirectory() as directory, self.selected():
            root = Path(directory)
            error = OSError(errno.EIO, 'next artifact image admission failed')
            with patch.object(adapter, 'selected_retirement_state', side_effect=[self.image, error]) as select:
                with self.assertRaises(OSError) as caught:
                    ScalarMultiversionRuntime(scalar_program(), root, clang=_CLANG)
            self.assertIs(caught.exception, error)
            self.assertEqual(select.call_count, 2)
            report = caught.exception.hia_cleanup
            self.assertTrue(report['owned_identity_release_complete'])
            self.assertTrue(report['observed_closed_and_directory_absent'])
            self.assertEqual(report['directory_cleanup']['status'], 'removed')
            self.assertEqual(list(root.iterdir()), [])

    def test_actual_retained_retirement_interruptions_and_leases_forbid_reference(self):
        import hepta.hia_native_retirement as public
        modules = ('tests.test_hia_native_retirement', 'tests.test_hia_publication_interruptions',
                   'tests.test_hia_multiversion', 'tests.test_hia_scalar_state')
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in modules)
        stream = io.StringIO()
        with self.selected(), ExitStack() as stack:
            for cls in (public._ReferencePathIdentityPin, public._ReferenceNativeRetirement):
                stack.enter_context(patch.object(cls, '__init__', side_effect=AssertionError('old policy constructed')))
            for name in ('_reference_observe_directory', '_reference_remove_directory'):
                stack.enter_context(patch.object(public, name, side_effect=AssertionError('old policy called')))
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        (self.folder / 'retained-actual-native-suite.log').write_text(stream.getvalue())
        (self.folder / 'retained-actual-native-suite.json').write_text(json.dumps({
            'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
            'skipped': len(result.skipped), 'image_sha256': self.image.image_sha256,
            'hosted_policy_constructors_and_functions_forbidden': True,
            'modules': modules}, indent=2) + '\n')
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual(result.skipped, [], stream.getvalue())


if __name__ == '__main__':
    unittest.main()
