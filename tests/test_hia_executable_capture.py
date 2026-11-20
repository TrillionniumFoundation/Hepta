"""Independent additive qualification for the explicit executable-capture owner.

Source: 3 complete methods. Native: 5 complete methods. No old method, fixture,
compiler/Popen assertion, deadline, or installed worker request is changed.
"""
from __future__ import annotations
import ast
import base64
import csv
import ctypes
import fcntl
from hashlib import sha256
import json
import io
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
import zipfile

from tests import hia_executable_capture_originals as originals

ROOT = Path(__file__).resolve().parents[1]


def evidence(case):
    declared = os.environ.get('HEPTA_HIA_EXECUTABLE_CAPTURE_EVIDENCE')
    if declared is None:
        base = Path(tempfile.mkdtemp(prefix='hia-executable-capture-'))
    else:
        base = Path(declared)
        base.mkdir(parents=True, exist_ok=True)
    path = base / case
    path.mkdir(exist_ok=False)
    return path


class VMEntry:
    """Fresh unchanged private VM with explicit component buffer inputs."""
    def __init__(self):
        from tools.generate_hia_executable_capture import document
        from hepta.hia_program import verify_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        self.program = verify_program(document())
        self.machine, self.owner, self.view = _Machine, _Owner, _View
        self.entries = 0

    def __call__(self, source, size, output, capacity, state, extent):
        raw = ctypes.string_at(source, size)
        values = (raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        owners = [self.owner(i + 1, bytearray(value)) for i, value in enumerate(values)]
        machine = self.machine(self.program, 4_000_000, 16 << 20, None, 128)
        result = machine.invoke(machine.functions['f0'],
                                [self.view(owner, i != 0) for i, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('capture policy VM changed the read-only request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        self.entries += 1
        return result


class FakeKernelEntry:
    """Only the seven deterministic kernel primitives, never capture decisions."""
    def __init__(self, world):
        self.world = world

    def __call__(self, source, size, output, capacity, state, extent):
        from hepta.hia_executable_capture import RAW_RECEIPT_MAGIC
        raw = ctypes.string_at(source, size)
        q = struct.unpack('<12Q', raw[:96])
        operation, fd, offset, count = q[2:6]
        if fd == (1 << 64) - 1:
            fd = -1
        result, payload = self.world.kernel(operation, fd, payload=raw[96:],
                                            count=count, arg=q[9])
        bits = result & ((1 << 64) - 1)
        struct.pack_into('<12Q', output, 0, RAW_RECEIPT_MAGIC, 1, operation, 2,
                         bits, q[6], q[7], q[8], 0, 0, 0, 0)
        struct.pack_into('<12Q', state, 0, 2, operation, bits, q[6], q[7], q[8],
                         q[3], offset, count, q[9], 0, 0)
        if payload:
            ctypes.memmove(ctypes.addressof(state) + 96, payload, len(payload))
        return 96


def candidate_factory(entry):
    from hepta.hia_executable_capture import _CaptureFrame
    def prepare(world):
        def errno_constructor(_error_class):
            world.raise_errno(ctypes.get_errno())
        owner = types.SimpleNamespace(
            policy=types.SimpleNamespace(_entry=entry),
            effects=types.SimpleNamespace(_entry=FakeKernelEntry(world)),
            host_abi=(None, world.audit, world.signals, errno_constructor),
            check=lambda: None)
        return lambda raw: _CaptureFrame(owner, raw).finish()
    return prepare


def child(directory, label, script, *, arguments=(), env=None, seconds=180, expected_returncode=0):
    from tools.qualify_hia_store_file_capture_originals import stop_owned
    directory = Path(directory)
    source = directory / (label + '.py')
    source.write_text(script)
    stdout_path, stderr_path = directory / (label + '.stdout.log'), directory / (label + '.stderr.log')
    command = [sys.executable, '-I', '-B', str(source), *map(str, arguments)]
    if env is None:
        env = {key: value for key, value in os.environ.items()
               if not key.startswith('HEPTA_') and not key.startswith('PYTHON')}
    start = time.monotonic()
    process = None
    timed_out = False
    cleanup = None
    cleanup_error = None
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            (directory / (label + '.start.json')).write_text(json.dumps({
                'argv': command, 'cwd': str(directory), 'pid': process.pid, 'pgid': process.pid,
                'body_seconds': seconds, 'cleanup_seconds': 3}, sort_keys=True) + '\n')
            try:
                process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if process is not None:
                try:
                    cleanup = stop_owned(process)
                except BaseException as error:
                    cleanup_error = type(error).__name__ + ': ' + str(error)
    result = {
        'argv': command, 'pid': None if process is None else process.pid,
        'returncode': None if process is None else process.returncode,
        'timeout': timed_out, 'cleanup': cleanup, 'cleanup_error': cleanup_error,
        'elapsed_seconds': time.monotonic() - start,
        'body_seconds': seconds, 'cleanup_seconds': 3, 'expected_returncode': expected_returncode,
        'stdout_sha256': sha256(stdout_path.read_bytes()).hexdigest(),
        'stderr_sha256': sha256(stderr_path.read_bytes()).hexdigest(),
    }
    (directory / (label + '.result.json')).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if process is None or process.returncode != expected_returncode or timed_out or cleanup_error:
        raise AssertionError('owned executable-capture child failed: ' + label)
    return result


def selected():
    from hepta.hia_executable_capture import load_executable_capture
    manifest = os.environ.get('HEPTA_HIA_EXECUTABLE_CAPTURE_MANIFEST')
    digest = os.environ.get('HEPTA_HIA_EXECUTABLE_CAPTURE_MANIFEST_SHA256')
    mode = os.environ.get('HEPTA_HIA_EXECUTABLE_CAPTURE_DEVELOPMENT', '0')
    if manifest is None or digest is None:
        raise unittest.SkipTest('an explicitly built executable-capture bundle is required')
    if mode not in ('0', '1'):
        raise ValueError('development selection must be explicit 0 or 1')
    owner = load_executable_capture(manifest, digest, allow_development=mode == '1')
    return owner, Path(manifest), digest, mode


class ExecutableCaptureSourceTests(unittest.TestCase):
    def test_00_original_whole_body_inputs_and_generated_profile(self):
        from tools.generate_hia_executable_capture import document
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_program import verify_program
        raw, table = originals.inputs()
        self.assertEqual(len(table['ordered_ids']), 218)
        originals.original(originals.World(table['cases'][0]))
        generated = render_assembly(document())
        self.assertEqual((ROOT / 'examples/hia_bootstrap/executable_capture.hepta').read_text(), generated)
        checked = verify_program(document())
        self.assertEqual(checked.as_dict()['module'], 'executable_capture')
        self.assertLessEqual(len(generated.encode()), 1 << 20)
        d = checked.as_dict()
        self.assertLessEqual(len(d['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in d['functions']), 1536)
        operations = sum(len(b['ops']) for f in d['functions'] for b in f['blocks'])
        self.assertLessEqual(operations, 8192)
        from hepta.hia_executable_capture import PACKAGE_RESOURCES, SOURCE_INPUTS
        self.assertEqual(PACKAGE_RESOURCES, tuple(n for n in SOURCE_INPUTS if not n.startswith('hepta/')))

    def test_01_two_complete_originals_then_complete_vm_218(self):
        root = evidence(self._testMethodName)
        frozen = originals.freeze_originals(root / 'original')
        entry = VMEntry()
        originals.write_stream(root / 'candidate', candidate_factory(entry))
        comparison = originals.compare_frozen(root / 'original', frozen, root / 'candidate')
        self.assertEqual(comparison['differences'], [])
        self.assertGreater(entry.entries, 0)

    def test_02_policy_rejects_corruption_before_any_primitive(self):
        from hepta.hia_executable_capture import REQUEST_MAGIC
        entry = VMEntry()
        initial = struct.pack('<16Q', REQUEST_MAGIC, 1, 0, 0, 0, 0, 0, 3, 4, 5, 0, 0, 0, 0, 0, 0) + b'abc'
        for label, position, value in (
                ('magic', 0, 0), ('version', 8, 2), ('event', 16, 7),
                ('initial-sequence', 24, 1), ('initial-action', 32, 1),
                ('declared-length', 56, 4), ('reserved', 80, 1)):
            with self.subTest(label=label):
                packet = bytearray(initial)
                struct.pack_into('<Q', packet, position, value)
                source = ctypes.create_string_buffer(bytes(packet), len(packet))
                output = ctypes.create_string_buffer(b'x' * 128, 128)
                state = ctypes.create_string_buffer(260)
                previous = output.raw, state.raw
                self.assertEqual(entry(source, len(packet), output, 128, state, 260), 0xfffffffd)
                self.assertEqual((output.raw, state.raw), previous)


_KERNEL_SCRIPT = r"""
import fcntl, json, os, stat, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hepta.hia_executable_capture import load_executable_capture
from hepta.hia_program_selfhost import _sealed_executable
owner = load_executable_capture(sys.argv[2], sys.argv[3], allow_development=sys.argv[4] == '1')
rows = []
audit_trace = []
audit_active = False
def audit_hook(event, arguments):
    if audit_active and event in ('os.chmod', 'fcntl.fcntl'):
        audit_trace.append([event, list(arguments)])
sys.addaudithook(audit_hook)
for size in (0, 1, 3, 65537, 1048576):
    raw = (bytes(range(256)) * ((size + 255) // 256))[:size]
    results = []
    for selected in (_sealed_executable, owner.capture):
        audit_trace.clear()
        audit_active = True
        try:
            fd, seals = selected(raw)
        finally:
            audit_active = False
        expected_audit = [
            ['os.chmod', [fd, 0o500, -1]],
            ['fcntl.fcntl', [fd, 1033, 15]],
            ['fcntl.fcntl', [fd, 1034, None]],
        ]
        assert audit_trace == expected_audit, audit_trace
        try:
            before = os.fstat(fd)
            rejected = []
            for name, effect in (
                    ('write', lambda: os.write(fd, b'x')),
                    ('truncate', lambda: os.ftruncate(fd, size + 1)),
                    ('remove_seals', lambda: fcntl.fcntl(fd, 1033, 0))):
                try:
                    value = effect()
                except OSError as error:
                    rejected.append([name, error.errno])
                else:
                    rejected.append([name, 'returned', value])
            results.append({
                'seals': seals, 'actual_seals': fcntl.fcntl(fd, 1034),
                'mode': stat.S_IMODE(before.st_mode), 'size': before.st_size,
                'cloexec': bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC),
                'bytes_equal': os.pread(fd, size + 1, 0) == raw,
                'mutation_results': rejected, 'audit_arguments_exact': True,
            })
        finally:
            os.close(fd)
    assert results[0] == results[1], (size, results)
    assert results[1]['seals'] & 15 == 15 and results[1]['mode'] == 0o500
    assert results[1]['bytes_equal'] and results[1]['cloexec']
    rows.append({'size': size, 'original': results[0], 'candidate': results[1]})
print(json.dumps({'rows': rows, 'original_helper_used': True, 'candidate_explicit': True}, sort_keys=True))
"""

_LOSS_SCRIPT = r"""
import ctypes, fcntl, json, os, struct, sys
sys.path.insert(0, sys.argv[1])
from hepta.hia_executable_capture import load_executable_capture, _CaptureFrame, ExecutableCaptureUnknown
from hepta.hia_native_delivery import custody_snapshot
owner = load_executable_capture(sys.argv[2], sys.argv[3], allow_development=sys.argv[4] == '1')
saved = owner.effects._entry
calls = []
fault = MemoryError('actual-memfd-return-withheld')
def withhold(*args):
    calls.append(struct.unpack('<12Q', ctypes.string_at(args[0], args[1]))[2])
    answer = saved(*args)
    assert answer == 96
    raise fault
owner.effects._entry = withhold
frame = _CaptureFrame(owner, b'abc')
try:
    frame.finish()
except BaseException as error:
    assert error is fault
else:
    raise AssertionError('missing memfd receipt was accepted')
state = struct.unpack('<12Q', bytes(frame.raw_state[:96]))
assert state[0] == 2 and state[1] == 1 and state[2] <= 2147483647
fd = state[2]
assert calls == [1] and fcntl.fcntl(fd, 1034) == 0
assert frame.record.loss is not None and any(row['lost'] for row in custody_snapshot())
try:
    frame.finish()
except ExecutableCaptureUnknown:
    pass
else:
    raise AssertionError('lost workspace was replayed')
assert calls == [1]
fresh = load_executable_capture(sys.argv[2], sys.argv[3], allow_development=sys.argv[4] == '1')
healthy, seals = fresh.capture(b'different-workspace')
os.close(healthy)
assert seals & 15 == 15
print(json.dumps({'actual_syscalls': calls, 'persisted_fd': fd,
                  'same_workspace_refused': True, 'different_workspace_returned': True,
                  'lost_custody': list(custody_snapshot())}, sort_keys=True))
# The diagnostic child owns this fd until process exit. No product retry,
# close, registry clear, or claim that UNKNOWN became acknowledged occurs.
"""

_INSTALLED_SCRIPT = r"""
import fcntl, json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hepta.hia_executable_capture import load_executable_capture
import hepta.hia_program_selfhost as legacy
original = legacy._sealed_executable
owner = load_executable_capture(sys.argv[2], sys.argv[3], allow_development=sys.argv[4] == '1')
fd, seals = owner.capture(b'installed-explicit-capture')
try:
    assert os.pread(fd, 64, 0) == b'installed-explicit-capture' and seals & 15 == 15
finally:
    os.close(fd)
assert legacy._sealed_executable is original
assert not any(name == 'tools' or name.startswith('tools.') for name in sys.modules)
assert str(Path(legacy.__file__).resolve()).startswith(str(Path(sys.argv[1]).resolve()) + os.sep)
print(json.dumps({'scope': 'INSTALLED_EXPLICIT_COMPONENT',
                  'original_default_unchanged': True, 'authoring_imports': [],
                  'actual_module': legacy.__file__, 'seals': seals}, sort_keys=True))
"""


class ExecutableCaptureNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner, cls.manifest, cls.digest, cls.mode = selected()

    def test_00_complete_originals_then_complete_native_policy_218(self):
        root = evidence(self._testMethodName)
        frozen = originals.freeze_originals(root / 'original')
        originals.write_stream(root / 'candidate', candidate_factory(self.owner.policy._entry))
        comparison = originals.compare_frozen(root / 'original', frozen, root / 'candidate')
        self.assertEqual(comparison['differences'], [])

    def test_01_actual_original_and_native_kernel_bytes_mode_and_seals(self):
        root = evidence(self._testMethodName)
        child(root, 'kernel', _KERNEL_SCRIPT,
              arguments=(ROOT, self.manifest, self.digest, self.mode), seconds=180)

    def test_02_actual_memfd_then_lost_receipt_retains_exact_workspace(self):
        root = evidence(self._testMethodName)
        child(root, 'loss', _LOSS_SCRIPT,
              arguments=(ROOT, self.manifest, self.digest, self.mode), seconds=180)

    def test_03_admission_before_executable_fd_and_no_implicit_compiler_authority(self):
        from hepta.hia_executable_capture import load_executable_capture
        from hepta.hia_program_selfhost import SCHEMA as old_schema
        root = evidence(self._testMethodName)
        raw = self.manifest.read_bytes()
        wrong = root / 'wrong.json'
        value = json.loads(raw)
        value['schema'] = old_schema
        wrong.write_text(json.dumps(value))
        wrong.chmod(0o600)
        for name, path, digest, mode in (
                ('wrong-digest', self.manifest, '0' * 64, self.mode == '1'),
                ('old-schema', wrong, sha256(wrong.read_bytes()).hexdigest(), True)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                load_executable_capture(path, digest, allow_development=mode)
        if self.mode == '1':
            with self.assertRaises(ValueError):
                load_executable_capture(self.manifest, self.digest, allow_development=False)
        self.assertEqual(self.manifest.read_bytes(), raw)

    def test_04_actual_wheel_explicit_capture_and_original_default_retained(self):
        root = evidence(self._testMethodName)
        dist, installed = root / 'dist', root / 'installed'
        dist.mkdir()
        installed.mkdir()
        # Only this new wheel command is run; no old installed request is removed.
        script = (
            "import subprocess, sys\n"
            "subprocess.run([sys.executable, '-I', '-m', 'pip', 'wheel', sys.argv[1], "
            "'--no-deps', '--no-build-isolation', '--wheel-dir', sys.argv[2]], check=True)\n")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith('HEPTA_') and not key.startswith('PYTHON')}
        child(root, 'wheel', script, arguments=(ROOT, dist), env=env, seconds=60)
        wheels = tuple(dist.glob('*.whl'))
        self.assertEqual(len(wheels), 1)
        with zipfile.ZipFile(wheels[0]) as archive:
            self.assertIsNone(archive.testzip())
            files = [item.filename for item in archive.infolist() if not item.is_dir()]
            self.assertEqual(len(files), len(set(files)))
            self.assertTrue(all(not Path(name).is_absolute() and '..' not in Path(name).parts
                                for name in files))
            records = [name for name in files if name.endswith('.dist-info/RECORD')]
            self.assertEqual(len(records), 1)
            rows = list(csv.reader(io.StringIO(archive.read(records[0]).decode())))
            self.assertEqual({row[0] for row in rows}, set(files))
            self.assertEqual(len(rows), len(files))
            for name, digest, extent in rows:
                raw = archive.read(name)
                if name == records[0]:
                    self.assertEqual((digest, extent), ('', ''))
                else:
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(
                        sha256(raw).digest()).decode().rstrip('='))
                    self.assertEqual(extent, str(len(raw)))
            (root / 'wheel-RECORD.csv').write_bytes(archive.read(records[0]))
            archive.extractall(installed)
            for item in archive.infolist():
                if not item.is_dir():
                    (installed / item.filename).chmod(stat.S_IMODE(item.external_attr >> 16) or 0o600)
        child(root, 'installed', _INSTALLED_SCRIPT,
              arguments=(installed, self.manifest, self.digest, self.mode),
              env=env, seconds=180)
        extra = installed / 'hepta/capture_unadmitted_extra.py'
        extra.write_bytes(b'# independently unadmitted runtime module\n')
        (root / 'installed-extra-runtime.input.py.txt').write_bytes(extra.read_bytes())
        try:
            child(root, 'installed-extra-runtime', _INSTALLED_SCRIPT,
                  arguments=(installed, self.manifest, self.digest, self.mode),
                  env=env, seconds=180, expected_returncode=1)
            self.assertEqual((root / 'installed-extra-runtime.stdout.log').read_bytes(), b'')
            self.assertIn(b'complete runtime inventory differs',
                          (root / 'installed-extra-runtime.stderr.log').read_bytes())
        finally:
            extra.unlink()
        module = installed / 'hepta/hia_executable_capture.py'
        previous = module.read_bytes()
        module.write_bytes(previous + b'\n')
        (root / 'installed-source-drift.input.py.txt').write_bytes(module.read_bytes())
        try:
            child(root, 'installed-source-drift', _INSTALLED_SCRIPT,
                  arguments=(installed, self.manifest, self.digest, self.mode),
                  env=env, seconds=180, expected_returncode=1)
            self.assertEqual((root / 'installed-source-drift.stdout.log').read_bytes(), b'')
            self.assertIn(b'runtime module differs: hepta/hia_executable_capture.py',
                          (root / 'installed-source-drift.stderr.log').read_bytes())
        finally:
            module.write_bytes(previous)


if __name__ == '__main__':
    unittest.main()
