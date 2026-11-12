"""Native checked editing: independent packer, original/candidate admission and IO."""
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import resource
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_tools import apply_program_patch
from hepta.hia_core_patch_native import envelope, scratch_sizes, MAX_WIRE
from tools.generate_hia_core_patch_cli import (MAGIC, BUNDLE_LIMIT, WIRE_LIMIT,
    OUTPUT_OFFSET, OUTPUT_BYTES, SCRATCH_OFFSET, PATCH_SCRATCH, CORE_STATE, CORE_ARENA,
    document, template)
from tools.build_hia_core_patch_cli import SOURCE, ADMISSION, PACKER, build
from tests.test_hia_program_tools import scalar_program, add_two_patch
from tests.test_hia_core_patch_native import four_kinds, interpreted, request_wire, wire
from tests.test_hia_core_workspace_facts_native import vm_run


def frame(patch, admission):
    return struct.pack('<3Q', MAGIC, len(patch), len(admission)) + patch + admission


def packed_reference(patch, admission):
    prefix, holes = template()
    out = bytearray(prefix + patch + admission)
    struct.pack_into('<QQ', out, 96, len(out), len(out))
    for name in ('extract', 'apply'):
        struct.pack_into('<i', out, holes[name], len(prefix) - holes[name] - 4)
    for name in ('base_admission', 'candidate_admission'):
        struct.pack_into('<i', out, holes[name], len(prefix) + len(patch) - holes[name] - 4)
    return bytes(out)


class CorePatchCliSourceTests(unittest.TestCase):
    def test_generated_source_and_disjoint_full_profile_scratch(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from hepta.hia_core_admission_native import MAX_BYTES, scratch_sizes as admission_sizes
        self.assertEqual(PACKER.read_text(), render_assembly(document()))
        assemble_program(PACKER.read_bytes())
        state, arena = scratch_sizes(MAX_WIRE)
        self.assertGreaterEqual(OUTPUT_BYTES, state)
        self.assertGreaterEqual(PATCH_SCRATCH, arena)
        state, arena = admission_sizes(MAX_BYTES)
        self.assertGreaterEqual(CORE_STATE, state)
        self.assertGreaterEqual(CORE_ARENA, arena)
        self.assertGreater(OUTPUT_OFFSET, WIRE_LIMIT)
        self.assertEqual(SCRATCH_OFFSET, OUTPUT_OFFSET + OUTPUT_BYTES)

    def test_independent_VM_every_packer_byte_and_refusal_canaries(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        patch, admission = b'\x31\xc0\xc3', b'\x90\x31\xc0\xc3'
        raw = packed_reference(patch, admission)
        request = frame(patch, admission)
        self.assertEqual(vm_run(PACKER, request, len(raw) + 1, 1), (len(raw), raw))
        inspection = inspect_executable(raw)
        self.assertFalse(inspection['dynamic_loader'])
        for request, cap, expected in ((request, 64, 0xfffffffe), (request + b'x', 4096, 0xffffffff),
                (b'wrong', 4096, 0xffffffff), (frame(b'', admission), 4096, 0xffffffff),
                (struct.pack('<3Q', MAGIC, 2**64 - 1, 1) + b'xx', 4096, 0xffffffff)):
            self.assertEqual(vm_run(PACKER, request, cap, 1), (expected, b'\xa5' * cap))

    def test_boolean_cold_returncode_is_refused_before_source_or_output(self):
        from tools.build_hia_core_patch_cli import PROFILE, REQUIRED_CHECKS
        with tempfile.TemporaryDirectory(prefix='hia-patch-cold-type-') as d:
            folder = Path(d); compiler = folder / 'compiler'; compiler.write_bytes(b'not-a-qualified-image')
            cold = folder / 'cold.json'
            cold.write_text(json.dumps({'schema': 'hepta.hia.selfhost-cold-replay.v1',
                'profile': PROFILE, 'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': False,
                'checks': {key: True for key in REQUIRED_CHECKS},
                'generation_sha256': [sha256(compiler.read_bytes()).hexdigest()] * 3}))
            with patch('tools.build_hia_core_patch_cli.current_sources', side_effect=AssertionError('source reached')):
                with self.assertRaisesRegex(ValueError, 'matching-source'):
                    build(folder / 'output', compiler, cold)
            self.assertFalse((folder / 'output').exists())


class CorePatchCliNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CorePatchCliSourceTests().test_independent_VM_every_packer_byte_and_refusal_canaries()
        original = scalar_program(); request = add_two_patch(original)
        expected = apply_program_patch(original, request)[0].canonical_bytes
        code, result = interpreted(request_wire(original, request))
        assert code == len(expected) + 32 and result[32:] == expected
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-core-patch-cli-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from tools.qualify_hia_selfhost_cli import inspect_executable
        selected = os.environ.get('HEPTA_HIA_CORE_PATCH_CLI_COLD_REPORT')
        cls.cold = Path(selected) if selected else None
        if cls.cold:
            report = json.loads(cls.cold.read_bytes())
            assert report['status'] == 'COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256'] == [sha256(compiler.read_bytes()).hexdigest()] * 3
            cls.executable = build(cls.folder / 'qualified', compiler, cls.cold)
            record = json.loads((cls.executable.parent / 'build.json').read_bytes())
            cls.inspection = record['executable']
            cls.receipts = record['native_compile_receipts']
            parts = []
            for filename in ('manifest.json', 'admission-manifest.json'):
                metadata = json.loads((cls.executable.parent / filename).read_bytes())
                parts.append((cls.executable.parent / metadata['image_path']).read_bytes())
            cls.images = parts
            cls.compiler = compiler
        else:
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            cls.compiler = compiler; cls.receipts = {}; parts = []
            for name, source in (('patch', SOURCE), ('admission', ADMISSION), ('packer', PACKER)):
                path, receipt = compile_stage(cls.folder, name, compiler, source.read_bytes())
                cls.receipts[name] = receipt
                if name == 'packer': packer = path
                else: parts.append(path.read_bytes())
            cls.images = parts
            # This app has an explicit two-image bundle profile. Keep the
            # compiler qualification child's unchanged 1-MiB output ceiling.
            from hepta.hia_json_preflight_native import NativeHiaJsonImage
            packer_bytes = packer.read_bytes()
            native = NativeHiaJsonImage(packer_bytes, sha256(packer_bytes).hexdigest())
            request = frame(*parts)
            source_buf = ctypes.create_string_buffer(request, len(request))
            arena = ctypes.create_string_buffer(BUNDLE_LIMIT)
            scratch = ctypes.create_string_buffer(1)
            size = native._entry(source_buf, len(request), arena, BUNDLE_LIMIT, scratch, 0)
            assert 0 < size <= BUNDLE_LIMIT
            raw = ctypes.string_at(arena, size)
            cls.inspection = inspect_executable(raw)
            cls.executable = cls.folder / 'hia-patch-core'
            cls.executable.write_bytes(raw); cls.executable.chmod(0o700)
        # The HIA packer was interpreted before native generation. For the real
        # immutable images, compare all emitted bytes, including all four calls.
        assert cls.executable.read_bytes() == packed_reference(*cls.images)

    @staticmethod
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))

    def run_cli(self, raw, expected=0, *, path=None, argv=(), **kwargs):
        result = subprocess.run([str(path or self.executable), *argv], input=raw,
            capture_output=True, timeout=20, preexec_fn=self.limits,
            env={'PATH': '', 'HOME': '/nonexistent', 'LC_ALL': 'C'}, **kwargs)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result)
        if expected: self.assertEqual(result.stdout, b'')
        return result

    def test_four_edit_kinds_and_copied_empty_PATH_without_sidecars(self):
        original, cases = four_kinds()
        for request in cases:
            expected = apply_program_patch(original, request)[0].canonical_bytes
            self.assertEqual(self.run_cli(request_wire(original, request)).stdout, expected)
        self.assertFalse(self.inspection['dynamic_loader'])
        self.assertFalse(self.inspection['libc'])
        for receipt in self.receipts.values():
            self.assertEqual(receipt['forbidden_compiler_modules_loaded'], [])
        with tempfile.TemporaryDirectory(prefix='hia-core-patch-copied-') as d:
            target = Path(d) / 'patcher'
            shutil.copyfile(self.executable, target); target.chmod(0o700)
            self.assertEqual(list(Path(d).iterdir()), [target])
            self.assertEqual(self.run_cli(request_wire(original, cases[0]), path=target).stdout,
                             apply_program_patch(original, cases[0])[0].canonical_bytes)

    def test_invalid_original_cannot_be_repaired_past_base_admission(self):
        original = scalar_program(); request = add_two_patch(original)
        original['functions'][0]['blocks'][0]['ops'][0]['attrs']['value'] = True
        canonical = json.dumps(original, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        request['expected_sha256'] = sha256(canonical).hexdigest()
        # The patch would replace the malformed operation with a valid const.
        # Rejection proves mandatory original admission precedes any repair.
        self.run_cli(envelope(canonical, wire(request)), 2)

    def test_candidate_semantics_ownership_and_missing_effects_must_admit(self):
        original = scalar_program()
        for change in ('undefined', 'wrong_type', 'missing_effect'):
            request = add_two_patch(original)
            if change == 'undefined':
                request['edits'][0]['operation'] = {'op': 'int.add.wrap', 'args': ['x', 'missing'],
                    'out': [{'name': 'one', 'type': 'u32'}], 'attrs': {}}
            elif change == 'wrong_type': request['edits'][0]['operation']['attrs']['value'] = True
            else:
                definition = copy.deepcopy(original['functions'][0]); definition['effects'] = []
                request['edits'] = [{'action': 'replace_function', 'function': 'increment', 'definition': definition}]
            self.run_cli(request_wire(original, request), 2)
        from tests.test_hia_core_admission_native import borrowed_owner
        program = borrowed_owner()
        definition = program['functions'][0]
        definition['name'] = 'leaking'
        request = add_two_patch(original)
        request.update(schema='hepta.hia.patch.v2', interface_policy='migrate')
        request['edits'] = [{'action': 'add_function', 'function': 'leaking', 'definition': definition}]
        self.run_cli(request_wire(original, request), 2)

    def test_exact_snapshot_policy_and_patch_refusals_emit_nothing(self):
        original = scalar_program()
        for mutation in ('stale', 'duplicate', 'bool', 'unknown', 'schema', 'interface'):
            request = add_two_patch(original)
            if mutation == 'stale': request['expected_sha256'] = '0' * 64
            elif mutation == 'duplicate': request['edits'] *= 2
            elif mutation == 'bool': request['edits'][0]['index'] = False
            elif mutation == 'unknown': request['edits'][0]['action'] = 'execute'
            elif mutation == 'schema': request['schema'] = 'unapproved'
            else:
                definition = copy.deepcopy(original['functions'][0]); definition['effects'] = ['trap', 'read']
                request['edits'] = [{'action': 'replace_function', 'function': 'increment', 'definition': definition}]
            self.run_cli(request_wire(original, request), 2)
        raw = request_wire(original, add_two_patch(original))
        for malformed in (b'', b'{}', b'[{},{}]', b'\xff', raw + b'x',
                           raw.replace(b'"expected_sha256":', b'"expected_sha256":"x","expected_sha256":', 1)):
            self.run_cli(malformed, 2)

    def test_wire_limit_argument_guard_and_real_descriptor_errors(self):
        original = scalar_program(); raw = request_wire(original, add_two_patch(original))
        expected = apply_program_patch(original, add_two_patch(original))[0].canonical_bytes
        self.assertEqual(self.run_cli(raw + b' ' * (WIRE_LIMIT - len(raw))).stdout, expected)
        self.run_cli(raw + b' ' * (WIRE_LIMIT + 1 - len(raw)), 3)
        self.run_cli(raw, 64, argv=('unexpected',))
        for kind in ('input', 'output', 'mapping'):
            def prepare():
                self.limits()
                if kind == 'input': os.close(0)
                elif kind == 'output':
                    fd = os.open('/dev/full', os.O_WRONLY); os.dup2(fd, 1); os.close(fd)
                else: resource.setrlimit(resource.RLIMIT_AS, (2 << 20, 2 << 20))
            result = subprocess.run([str(self.executable)], input=raw, capture_output=True,
                timeout=20, preexec_fn=prepare, env={'PATH': ''})
            self.assertEqual((result.returncode, result.stdout, result.stderr), (4, b'', b''), kind)

    def test_syscalls_and_EINTR_do_not_open_payload_sources_or_spawn(self):
        original = scalar_program(); raw = request_wire(original, add_two_patch(original))
        expected = apply_program_patch(original, add_two_patch(original))[0].canonical_bytes
        for interrupted in (False, True):
            trace = self.folder / ('patch-' + str(interrupted) + '.strace')
            args = ['-e', 'inject=read:error=EINTR:when=1', '-e', 'inject=write:error=EINTR:when=1'] if interrupted else []
            result = subprocess.run(['/usr/bin/strace', '-qq', '-o', str(trace), *args,
                str(self.executable)], input=raw, capture_output=True, timeout=20, env={'PATH': ''})
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
            calls = re.findall(r'^([a-z0-9_]+)\(', trace.read_text(), re.MULTILINE)
            self.assertEqual(set(calls), {'execve', 'mmap', 'read', 'write', 'exit'})
            self.assertEqual(calls.count('execve'), 1)
            if interrupted: self.assertEqual(trace.read_text().count('(INJECTED)'), 2)

    def test_full_Core_function_profile_and_real_partial_stdout(self):
        import fcntl
        original = scalar_program()
        template = copy.deepcopy(original['functions'][0])
        original['functions'] += [{**copy.deepcopy(template), 'name': 'f' + str(i)} for i in range(1023)]
        request = add_two_patch(original)
        expected = apply_program_patch(original, request)[0].canonical_bytes
        raw = request_wire(original, request)
        self.assertEqual(self.run_cli(raw).stdout, expected)
        read_fd, write_fd = os.pipe()
        try:
            fcntl.fcntl(write_fd, fcntl.F_SETFL, fcntl.fcntl(write_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
            result = subprocess.run([str(self.executable)], input=raw, stdout=write_fd,
                stderr=subprocess.PIPE, timeout=20, preexec_fn=self.limits, env={'PATH': ''})
            os.close(write_fd); write_fd = -1
            parts = []
            while True:
                chunk = os.read(read_fd, 65536)
                if not chunk: break
                parts.append(chunk)
            prefix = b''.join(parts)
            self.assertEqual((result.returncode, result.stderr), (4, b''))
            self.assertTrue(0 < len(prefix) < len(expected))
            self.assertEqual(prefix, expected[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd != -1: os.close(write_fd)
        # Adding a function cannot smuggle an over-limit candidate past the
        # mandatory complete Core admission after patch policy has succeeded.
        request.update(schema='hepta.hia.patch.v2', interface_policy='migrate')
        request['edits'] = [{'action': 'add_function', 'function': 'extra',
                            'definition': {**copy.deepcopy(template), 'name': 'extra'}}]
        self.run_cli(request_wire(original, request), 2)

    def test_strict_build_refuses_incomplete_cold_before_output(self):
        cold = self.folder / 'wrong-cold.json'; cold.write_text('{}')
        output = self.folder / 'refused-build'
        with self.assertRaisesRegex(ValueError, 'matching-source'):
            build(output, self.compiler, cold)
        self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
