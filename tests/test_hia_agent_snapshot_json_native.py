"""Direct JSON to native bytes: independent VM, native bootstrap and real CLI."""
from concurrent.futures import ThreadPoolExecutor
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_snapshot_json_native import NativeAgentSnapshotJson, SOURCE, SCHEMA, installed_snapshot_json
from tools.generate_hia_agent_snapshot_json import document
from tools.generate_hia_agent_snapshot_json_cli import MAGIC, document as packer_document
from tools.generate_hia_native_filter import document as default_packer_document

ROOT = Path(__file__).resolve().parents[1]
PACKER = ROOT / 'examples/hia_bootstrap/agent_snapshot_json_packer.hiaasm'


@lru_cache(maxsize=1)
def checked_source(raw):
    from hepta.hia_agent_assembly import assemble_program
    return assemble_program(raw)


def vm_materialize(wire, *, output_size=8192):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = checked_source(SOURCE.read_bytes())
    machine = _Machine(checked, 2000000, 16 << 20, None, 256)
    roots = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(output_size)), _Owner(-3, bytearray(8192))]
    entry = next(f for f in checked.as_dict()['functions'] if f['name'] == 'f0')
    code = machine.invoke(entry, [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)])[0]
    return code, bytes(roots[1].data[:code]) if code <= 1 << 20 else None


def vm_pack(wire, *, capacity=None):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(PACKER.read_bytes())
    machine = _Machine(checked, 20000000, 16 << 20, None, 256)
    capacity = len(wire) + 4096 if capacity is None else capacity
    roots = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(b'\xa5' * capacity)), _Owner(-3, bytearray(1))]
    entry = next(f for f in checked.as_dict()['functions'] if f['name'] == 'f0')
    code = machine.invoke(entry, [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)])[0]
    return code, bytes(roots[1].data[:code]) if code <= 1 << 20 else bytes(roots[1].data)


class AgentSnapshotJsonSourceTests(unittest.TestCase):
    def test_independent_VM_packer_headers_bytes_and_refusal_canary_before_B0(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        payload = b'\x31\xc0\xc3'
        frame = struct.pack('<QQ', MAGIC, len(payload)) + payload
        size, image = vm_pack(frame)
        self.assertEqual(size, len(image)); self.assertEqual(image[-3:], payload)
        inspect_executable(image)
        for raw, capacity, status in [(frame, 64, 4294967294), (frame + b'x', 4096, 4294967295),
                                       (b'bad', 4096, 4294967295)]:
            self.assertEqual(vm_pack(raw, capacity=capacity), (status, b'\xa5' * capacity))

    def test_exact_checked_source_and_independent_VM_before_any_native_seed(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(PACKER.read_text(), render_assembly(packer_document()))
        self.assertEqual((ROOT / 'examples/hia_bootstrap/native_filter_packer.hiaasm').read_text(),
                         render_assembly(default_packer_document()))
        for wire, expected in [(b'{"bytes_hex":"00abff"}', b'\x00\xab\xff'),
                               (b'{"byte_length":3,"fill_byte":7}', b'\x07' * 3),
                               (b'{"fill_byte":-0,"byte_length":2}', b'\x00\x00'),
                               (b'{"bytes_\\u0068ex":"0\\u0030a\\u0062"}', b'\x00\xab'),
                               (b'{"bytes_hex":""}', b'')]:
            self.assertEqual(vm_materialize(wire), (len(expected), expected))

    def test_independent_VM_strict_JSON_and_descriptor_refusals(self):
        for wire in [b'[]', b'null', b'{}', b'{"bytes_hex":"00AF"}',
                     b'{"byte_length":true,"fill_byte":0}', b'{"byte_length":1,"fill_byte":256}',
                     b'{"byte_length":-1,"fill_byte":0}', b'{"byte_length":1,"fill_byte":0.0}',
                     b'{"bytes_hex":"00","bytes_\\u0068ex":"00"}', b'{"bytes_hex":"\\ud800"}',
                     b'{"bytes_hex":"00"} trailing', b'{"other":[]}', b'{"bytes_hex":"\xff"}']:
            with self.subTest(wire=wire):
                self.assertEqual(vm_materialize(wire), (4294967295, None))


class AgentSnapshotJsonNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert vm_materialize(b'{"bytes_hex":"012aff"}') == (3, b'\x01\x2a\xff')
        assert vm_pack(struct.pack('<QQ', MAGIC, 3) + b'\x31\xc0\xc3')[1].endswith(b'\x31\xc0\xc3')
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
        from tools.qualify_hia_selfhost_cli import inspect_executable
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-snapshot-json-')
        cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, source)
        cls.compiler = second
        assert first.read_bytes() == second.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'snapshot-json', second, SOURCE.read_bytes())
        cls.image = NativeAgentSnapshotJson(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps({'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path': image.name, 'image_sha256': cls.image.image_sha256, 'compiler_sha256': sha256(second.read_bytes()).hexdigest()}))
        packer, cls.pack_receipt = compile_stage(cls.folder, 'snapshot-json-packer', second, PACKER.read_bytes())
        frame = struct.pack('<QQ', MAGIC, image.stat().st_size) + image.read_bytes()
        result, packed = invoke(cls.folder, 'snapshot-json-pack', packer, frame)
        count = result['core_u32']; assert 0 < count <= 1 << 20
        raw = packed[:count]; inspect_executable(raw)
        assert vm_pack(frame) == (count, raw)
        cls.executable = cls.folder / 'hia-snapshot-json'; cls.executable.write_bytes(raw); cls.executable.chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_five_hundred_JSON_descriptors_without_foreign_payload_decoder(self):
        rng = random.Random(863)
        cases = []
        for _ in range(500):
            value = rng.randbytes(rng.randrange(1024))
            cases.append((json.dumps({'bytes_hex': value.hex()}).encode(), value))
            size, fill = rng.randrange(1024), rng.randrange(256)
            cases.append((json.dumps({'fill_byte': fill, 'byte_length': size}).encode(), bytes([fill]) * size))
        with patch('json.loads', side_effect=AssertionError('foreign JSON decoder')), \
             patch('hepta.hia_agent_store.decode_data', side_effect=AssertionError('foreign object transport')):
            for wire, expected in cases:
                self.assertEqual(self.image.materialize(wire), expected)

    def test_full_extent_escaped_keys_values_and_all_strict_refusals(self):
        self.assertEqual(self.image.materialize(b'{"bytes_hex":"' + b'ab' * (1 << 20) + b'"}'), b'\xab' * (1 << 20))
        self.assertEqual(self.image.materialize(b'{"byte_length":1048576,"fill_byte":171}'), b'\xab' * (1 << 20))
        self.assertEqual(self.image.materialize(b'{"bytes_\\u0068ex":"0\\u0030a\\u0062"}'), b'\x00\xab')
        for wire in [b'null', b'[]', b'{}', b'{"bytes_hex":false}', b'{"bytes_hex":"00 "}',
                     b'{"bytes_hex":"00aZ"}', b'{"bytes_hex":"0"}', b'{"byte_length":1048577,"fill_byte":0}',
                     b'{"byte_length":18446744073709551616,"fill_byte":0}',
                     b'{"byte_length":1,"fill_byte":true}', b'{"byte_length":1,"fill_byte":-1}',
                     b'{"byte_length":1,"fill_byte":0,"extra":0}', b'{"bytes_hex":"\\ud800"}',
                     b'{"bytes_hex":"\xc0\x80"}', b'{"bytes_hex":"00","bytes_\\u0068ex":"00"}',
                     b'{"bytes_hex":"00"} false']:
            with self.subTest(wire=wire):
                with self.assertRaises(ValueError):
                    self.image.materialize(wire)

    def run_cli(self, wire, *args, **options):
        environment = {'PATH': '', 'LANG': 'C.UTF-8'}
        return subprocess.run([str(self.executable), *args], input=wire, capture_output=True,
                              env=environment, timeout=20, **options)

    def test_actual_standalone_copy_with_empty_PATH_and_no_second_executable(self):
        self.assertEqual((self.run_cli(b'{"bytes_hex":"012aff"}').returncode,
                          self.run_cli(b'{"bytes_hex":"012aff"}').stdout), (0, b'\x01\x2a\xff'))
        self.assertEqual(self.run_cli(b'{"bytes_hex":""}').returncode, 0)
        copied = self.folder / 'installed-copy'; copied.mkdir()
        executable = copied / 'snapshot'; executable.write_bytes(self.executable.read_bytes()); executable.chmod(0o700)
        result = subprocess.run([str(executable)], input=b'{"byte_length":8,"fill_byte":255}', capture_output=True,
                                env={'PATH': ''}, cwd=copied, timeout=20)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'\xff' * 8, b''))
        trace = self.folder / 'runtime.trace'
        tracer = shutil.which('strace'); self.assertIsNotNone(tracer, 'actual syscall tracer required')
        result = subprocess.run([tracer, '-f', '-e', 'trace=execve,openat,clone,fork,vfork', '-o', str(trace), str(executable)],
            input=b'{"bytes_hex":"ab"}', capture_output=True, env={'PATH': ''}, timeout=20)
        self.assertEqual((result.returncode, result.stdout), (0, b'\xab'))
        text = trace.read_text(); self.assertEqual(text.count('execve('), 1)
        for forbidden in ('openat(', 'clone(', 'fork(', 'vfork('):
            self.assertNotIn(forbidden, text)

    def test_standalone_refusals_publish_nothing_and_argument_and_byte_limits_hold(self):
        for wire in [b'{"bytes_hex":"00aZ"}', b'{"bytes_hex":"' + b'00' * (1 << 20) + b'Z0"}',
                     b'{"byte_length":true,"fill_byte":0}', b'{"path":"/not/authorized"}', b'']:
            result = self.run_cli(wire)
            self.assertEqual((result.returncode, result.stdout), (2, b''))
        result = self.run_cli(b' ' * (8 << 20) + b'0')
        self.assertEqual((result.returncode, result.stdout), (3, b''))
        result = self.run_cli(b'{"bytes_hex":"00"}', 'unexpected')
        self.assertEqual((result.returncode, result.stdout), (64, b''))

    def test_private_concurrency(self):
        values = [json.dumps({'byte_length': n, 'fill_byte': n}).encode() for n in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(self.image.materialize, values))
        self.assertEqual(results, [bytes([n]) * n for n in range(64)])

    def test_real_output_and_workspace_capacities_never_touch_outside_guards(self):
        for wire, capacity, scratch_size in [(b'{"byte_length":8192,"fill_byte":7}', 6320, 6320),
                                              (b'{"bytes_hex":"00aZ"}', 6320, 6320),
                                              (b'{"bytes_hex":"00"}', 6320, 6319)]:
            source = ctypes.create_string_buffer(wire)
            output = ctypes.create_string_buffer(b'\xa5' * (capacity + 64), capacity + 64)
            scratch = ctypes.create_string_buffer(scratch_size)
            result = self.image._entry(source, len(wire), output, capacity, scratch, scratch_size)
            self.assertIn(result, (4294967294, 4294967295))
            self.assertEqual(output.raw[capacity:], b'\xa5' * 64)
            if scratch_size < 6320:
                self.assertEqual(output.raw, b'\xa5' * (capacity + 64))

    def test_actual_EINTR_retry_and_nonblocking_partial_write(self):
        tracer = shutil.which('strace'); self.assertIsNotNone(tracer)
        trace = self.folder / 'eintr.trace'
        result = subprocess.run([tracer, '-qq', '-o', str(trace), '-e', 'inject=read:error=EINTR:when=1',
            '-e', 'inject=write:error=EINTR:when=1', str(self.executable)],
            input=b'{"bytes_hex":"012aff"}', capture_output=True, env={'PATH': ''}, timeout=20)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'\x01\x2a\xff', b''))
        self.assertEqual(trace.read_bytes().count(b'(INJECTED)'), 2)
        import fcntl
        read_fd, write_fd = os.pipe()
        try:
            fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
            fcntl.fcntl(write_fd, fcntl.F_SETFL, fcntl.fcntl(write_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
            result = subprocess.run([str(self.executable)], input=b'{"byte_length":1048576,"fill_byte":171}',
                stdout=write_fd, stderr=subprocess.PIPE, env={'PATH': ''}, timeout=20)
            os.close(write_fd); write_fd = -1
            chunks = []
            while chunk := os.read(read_fd, 65536):
                chunks.append(chunk)
            prefix = b''.join(chunks)
            self.assertEqual((result.returncode, result.stderr), (4, b''))
            self.assertGreater(len(prefix), 0); self.assertLess(len(prefix), 1 << 20)
            self.assertEqual(prefix, b'\xab' * len(prefix))
        finally:
            os.close(read_fd)
            if write_fd != -1:
                os.close(write_fd)

    def test_manifest_source_binding_and_builder_refuses_uncompleted_cold_receipt(self):
        import hepta.hia_agent_snapshot_json_native as native
        source_copy = self.folder / 'source-copy.hiaasm'; source_copy.write_bytes(SOURCE.read_bytes())
        with patch.object(native, 'SOURCE', source_copy):
            selected = installed_snapshot_json(str(self.manifest))
            self.assertEqual(selected.materialize(b'{"bytes_hex":"00"}'), b'\x00')
            source_copy.write_bytes(b'not the admitted source')
            with self.assertRaisesRegex(ValueError, 'source identity'):
                installed_snapshot_json(str(self.manifest))
        from tools.build_hia_agent_snapshot_json import build
        failed = self.folder / 'not-cold.json'; failed.write_text('{"status":"FAIL"}')
        with self.assertRaisesRegex(ValueError, 'completed matching'):
            build(self.folder / 'invalid-cold-build', self.compiler, failed)
