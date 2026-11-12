"""Independent packing, hostile frame controls and actual HIA patch results."""
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

from hepta.hia_agent_store import wire as diagnostic_wire
from hepta.hia_program import verify_program
from hepta.hia_program_tools import apply_program_patch
from hepta.hia_core_patch_native import envelope, scratch_sizes, MAX_WIRE
from tools.generate_hia_core_patch_result_cli import (MAGIC, EXTRACT_MAGIC, RESULT_MAGIC,
    BUNDLE_LIMIT, WIRE_LIMIT, JSON_LIMIT, RESULT_LIMIT, OUTPUT_OFFSET, OUTPUT_BYTES,
    SCRATCH_OFFSET, PATCH_SCRATCH, CORE_STATE, CORE_ARENA, document, template)
from tools.build_hia_core_patch_result_cli import SOURCE, ADMISSION, PACKER, build
from tests.test_hia_program_tools import scalar_program, add_two_patch
from tests.test_hia_core_patch_native import four_kinds, request_wire, wire
from tests.test_hia_core_workspace_facts_native import vm_run


def frame(patch, admission):
    return struct.pack('<3Q', MAGIC, len(patch), len(admission)) + patch + admission


def packed_reference(patch, admission):
    prefix, holes = template()
    out = bytearray(prefix + patch + admission)
    struct.pack_into('<QQ', out, 96, len(out), len(out))
    for name in ('extract', 'result'):
        struct.pack_into('<i', out, holes[name], len(prefix) - holes[name] - 4)
    for name in ('base_admission', 'candidate_admission'):
        struct.pack_into('<i', out, holes[name], len(prefix) + len(patch) - holes[name] - 4)
    return bytes(out)


def expected_result(original, request):
    candidate, diagnostic = apply_program_patch(original, request)
    first, second = candidate.canonical_bytes, diagnostic_wire(diagnostic)
    return struct.pack('<4Q', RESULT_MAGIC, len(first), len(second), 0) + first + second


def split_result(raw):
    magic, candidate, diagnostic, reserved = struct.unpack_from('<4Q', raw)
    if (magic != RESULT_MAGIC or reserved != 0 or not 2 <= candidate <= JSON_LIMIT
            or not 2 <= diagnostic <= JSON_LIMIT or len(raw) != 32 + candidate + diagnostic):
        raise ValueError('invalid result frame')
    return raw[32:32 + candidate], raw[32 + candidate:]


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))


class CorePatchResultCliSourceTests(unittest.TestCase):
    def test_generated_source_and_unchanged_disjoint_full_profile(self):
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
        self.assertLess(RESULT_LIMIT, OUTPUT_BYTES)

    def test_independent_VM_every_packer_byte_and_refusal_canaries(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        patch_image, admission = b'\x31\xc0\xc3', b'\x90\x31\xc0\xc3'
        raw = packed_reference(patch_image, admission)
        request = frame(patch_image, admission)
        self.assertEqual(vm_run(PACKER, request, len(raw) + 1, 1), (len(raw), raw))
        self.assertFalse(inspect_executable(raw)['dynamic_loader'])
        for value, cap, expected in ((request, 64, 0xfffffffe),
                (request + b'x', 4096, 0xffffffff), (b'wrong', 4096, 0xffffffff),
                (frame(b'', admission), 4096, 0xffffffff),
                (struct.pack('<3Q', MAGIC, 2**64 - 1, 1) + b'xx', 4096, 0xffffffff)):
            self.assertEqual(vm_run(PACKER, value, cap, 1), (expected, b'\xa5' * cap))

    def test_boolean_cold_returncode_refuses_before_source_or_output(self):
        from tools.build_hia_core_patch_result_cli import PROFILE, REQUIRED_CHECKS
        with tempfile.TemporaryDirectory(prefix='hia-patch-result-cold-type-') as d:
            root = Path(d); compiler = root / 'compiler'; compiler.write_bytes(b'not-qualified')
            cold = root / 'cold.json'
            cold.write_text(json.dumps({'schema': 'hepta.hia.selfhost-cold-replay.v1',
                'profile': PROFILE, 'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': False,
                'checks': {key: True for key in REQUIRED_CHECKS},
                'generation_sha256': [sha256(compiler.read_bytes()).hexdigest()] * 3}))
            with patch('tools.build_hia_core_patch_result_cli.current_sources',
                       side_effect=AssertionError('source reached')):
                with self.assertRaisesRegex(ValueError, 'matching-source'):
                    build(root / 'output', compiler, cold)
            self.assertFalse((root / 'output').exists())


def synthetic_patch(result, *, declared=1, result_code=None):
    """Adversarial ABI fixture, never a qualified HIA payload image.

    Each mode checks that old scratch is gone. Two distinct two-byte Core
    markers let the separate admission fixture assert the actual slice passed.
    """
    code = bytearray(); labels = {}; relocations = []
    def emit(value): code.extend(bytes.fromhex(value))
    def word(value): code.extend(struct.pack('<I', value))
    def branch(op, target): emit(op); relocations.append((len(code), target)); word(0)
    def label(name): labels[name] = len(code)
    def output(name, data, result):
        emit('48 89 d7 48 8d 35'); relocations.append((len(code), name)); word(0)
        emit('b9'); word(len(data)); emit('fc f3 a4 b8'); word(result); emit('c3')
    extract = struct.pack('<4Q', EXTRACT_MAGIC, 0, 0, 0) + b'B0'
    emit('49 83 78 10 00'); branch('0f 85', 'bad')
    emit('49 83 38 00'); branch('0f 85', 'result')
    emit('49 83 78 08 00'); branch('0f 85', 'bad')
    emit('49 c7 40 10 34 12 00 00')
    output('base_data', extract, len(extract))
    label('result')
    emit('49 83 38 02'); branch('0f 85', 'bad')
    emit('49 83 78 08'); code.append(declared); branch('0f 85', 'bad')
    output('result_data', result, len(result) if result_code is None else result_code)
    label('bad'); emit('b8 f1 ff ff ff c3')
    label('base_data'); code.extend(extract)
    label('result_data'); code.extend(result)
    for at, target in relocations:
        struct.pack_into('<i', code, at, labels[target] - at - 4)
    return bytes(code)


def synthetic_admission(*, base=0, candidate=0):
    # Verify exact two-byte candidate slice and fresh distinct state/arena. Then
    # poison both scratch regions so the next invocation must clear its state.
    code = bytearray(); branches = []
    def emit(value): code.extend(bytes.fromhex(value))
    def jump(op): emit(op); branches.append(len(code)); code.extend(bytes(4))
    emit('48 83 fe 02'); jump('0f 85')
    emit('48 83 3a 00'); jump('0f 85')
    emit('49 83 38 00'); jump('0f 85')
    emit('48 c7 02 78 56 00 00 49 c7 00 bc 9a 00 00')
    emit('80 3f 42 0f 85'); candidate_at = len(code); code.extend(bytes(4))
    emit('b8'); code.extend(struct.pack('<I', base)); emit('c3')
    candidate_label = len(code)
    emit('80 3f 43'); jump('0f 85')
    emit('b8'); code.extend(struct.pack('<I', candidate)); emit('c3')
    bad = len(code); emit('b8 fd ff ff ff c3')
    struct.pack_into('<i', code, candidate_at, candidate_label - candidate_at - 4)
    for at in branches: struct.pack_into('<i', code, at, bad - at - 4)
    return bytes(code)


class CorePatchResultCliAdapterTests(unittest.TestCase):
    """Actual kernel execution with explicitly synthetic component fixtures."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-patch-result-abi-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.count = 0

    def invoke(self, result, *, argv=('v1',), declared=1, result_code=None,
               base=0, candidate=0):
        self.count += 1
        path = self.root / str(self.count)
        path.write_bytes(packed_reference(
            synthetic_patch(result, declared=declared, result_code=result_code),
            synthetic_admission(base=base, candidate=candidate)))
        path.chmod(0o700)
        return subprocess.run([str(path), *argv], input=b'envelope', capture_output=True,
                              timeout=10, preexec_fn=limits, env={'PATH': ''})

    def test_schema_scratch_and_candidate_slice_then_opaque_complete_frame(self):
        # Invalid JSON diagnostics are intentional here: the literal adapter
        # transports bytes; only the real HIA kernel is entrusted to author them.
        result = struct.pack('<4Q', RESULT_MAGIC, 2, 2, 0) + b'C0\xff\x00'
        for value in (1, 2):
            actual = self.invoke(result, declared=value, argv=('v' + str(value),))
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (0, result, b''))
        actual = self.invoke(result, declared=1, argv=('v2',))
        self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b'', b''))

    def test_no_frame_published_on_base_or_candidate_or_header_refusal(self):
        result = struct.pack('<4Q', RESULT_MAGIC, 2, 2, 0) + b'C0{}'
        for stage in ('base', 'candidate'):
            actual = self.invoke(result, **{stage: 0xffffffff})
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b'', b''), stage)
        malformed = []
        for index, values in ((0, (0,)), (1, (0, 1, JSON_LIMIT + 1, 2**64 - 1)),
                              (2, (0, 1, JSON_LIMIT + 1, 2**64 - 1)), (3, (1, 2**64 - 1))):
            for value in values:
                raw = bytearray(result); struct.pack_into('<Q', raw, index * 8, value)
                malformed.append(bytes(raw))
        for raw in malformed:
            actual = self.invoke(raw)
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (2, b'', b''))
        for value, expected in ((len(result) - 1, 2), (len(result) + 1, 2),
                                 (RESULT_LIMIT + 1, 2), (0xfffffff1, 2),
                                 (0xfffffffe, 3), (0xfffffffd, 4)):
            actual = self.invoke(result, result_code=value)
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (expected, b'', b''))

    def test_argument_guard_requires_one_exact_declared_schema(self):
        result = struct.pack('<4Q', RESULT_MAGIC, 2, 2, 0) + b'C0{}'
        for argv in ((), ('',), ('v',), ('v0',), ('v3',), ('1',), ('v1x',),
                     ('v2x',), ('v1', 'unexpected'), ('\uFF56' + '1',)):
            actual = self.invoke(result, argv=argv)
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (64, b'', b''), argv)


def native_pack(packer_bytes, parts):
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    native = NativeHiaJsonImage(packer_bytes, sha256(packer_bytes).hexdigest())
    raw = frame(*parts)
    request = ctypes.create_string_buffer(raw, len(raw))
    arena = ctypes.create_string_buffer(BUNDLE_LIMIT)
    scratch = ctypes.create_string_buffer(1)
    size = native._entry(request, len(raw), arena, BUNDLE_LIMIT, scratch, 0)
    if not 0 < size <= BUNDLE_LIMIT:
        raise ValueError('native result packer refused images')
    return ctypes.string_at(arena, size)


class CorePatchResultCliNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CorePatchResultCliSourceTests().test_independent_VM_every_packer_byte_and_refusal_canaries()
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-core-patch-result-cli-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from tools.qualify_hia_selfhost_cli import inspect_executable
        selected = os.environ.get('HEPTA_HIA_CORE_PATCH_RESULT_CLI_COLD_REPORT')
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
            cls.images = parts; cls.compiler = compiler
        else:
            # Ordinary local unit execution is development evidence. A strict
            # build with matching full-source cold evidence remains separate.
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
            raw = native_pack(packer.read_bytes(), parts)
            cls.inspection = inspect_executable(raw)
            cls.executable = cls.folder / 'hia-patch-result'
            cls.executable.write_bytes(raw); cls.executable.chmod(0o700)
        assert cls.executable.read_bytes() == packed_reference(*cls.images)

    def run_cli(self, raw, expected=0, *, path=None, declared='v1', argv=None, **kwargs):
        arguments = (declared,) if argv is None else argv
        result = subprocess.run([str(path or self.executable), *arguments], input=raw,
            capture_output=True, timeout=20, preexec_fn=limits,
            env={'PATH': '', 'HOME': '/nonexistent', 'LC_ALL': 'C'}, **kwargs)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result)
        if expected: self.assertEqual(result.stdout, b'')
        return result

    def test_four_edits_complete_diagnostics_and_copied_empty_PATH(self):
        original, cases = four_kinds()
        for request in cases:
            declared = 'v2' if request['schema'].endswith('.v2') else 'v1'
            actual = self.run_cli(request_wire(original, request), declared=declared).stdout
            self.assertEqual(actual, expected_result(original, request))
            candidate, diagnostic = split_result(actual)
            value = json.loads(diagnostic)
            self.assertEqual(value['original_input_sha256'], verify_program(original).sha256)
            self.assertEqual(value['after_sha256'], sha256(candidate).hexdigest())
            self.assertIs(value['claims']['whole_module_rechecked'], True)
            self.assertIs(value['claims']['native_executed'], False)
        self.assertFalse(self.inspection['dynamic_loader'])
        self.assertFalse(self.inspection['libc'])
        for receipt in self.receipts.values():
            self.assertEqual(receipt['forbidden_compiler_modules_loaded'], [])
        with tempfile.TemporaryDirectory(prefix='hia-result-copied-') as d:
            target = Path(d) / 'result'
            shutil.copyfile(self.executable, target); target.chmod(0o700)
            self.assertEqual(list(Path(d).iterdir()), [target])
            self.assertEqual(self.run_cli(request_wire(original, cases[0]), path=target).stdout,
                             expected_result(original, cases[0]))

    def test_v2_preservation_migration_sorted_interfaces_and_exact_edit_limit(self):
        original = scalar_program(); original['schema'] = 'hepta.hia.program.v8'
        request = add_two_patch(original)
        request.update(schema='hepta.hia.patch.v2', interface_policy='preserve')
        definition = copy.deepcopy(original['functions'][0])
        definition['return_loans'] = [None]
        request['edits'] = [{'action': 'replace_function', 'function': 'increment',
                            'definition': definition}]
        expected = expected_result(original, request)
        actual = self.run_cli(request_wire(original, request), declared='v2').stdout
        self.assertEqual(actual, expected)
        receipt = json.loads(split_result(actual)[1])
        self.assertEqual(receipt['interface_changes'], [])
        self.assertIs(receipt['claims']['interface_preserved'], True)
        self.assertIs(receipt['claims']['external_callers_revalidated'], False)
        request['interface_policy'] = 'migrate'
        names = ['new_' + str(i) for i in reversed(range(64))]
        request['edits'] = [{'action': 'add_function', 'function': name,
                            'definition': {**copy.deepcopy(definition), 'name': name}}
                           for name in names]
        expected = expected_result(original, request)
        actual = self.run_cli(request_wire(original, request), declared='v2').stdout
        self.assertEqual(actual, expected)
        receipt = json.loads(split_result(actual)[1])
        self.assertEqual(receipt['interface_changes'], sorted(names))
        self.assertEqual(receipt['edits'], 64)
        self.assertIs(receipt['claims']['interface_preserved'], False)
        request['edits'].append({'action': 'add_function', 'function': 'one_too_many',
                                'definition': {**copy.deepcopy(definition), 'name': 'one_too_many'}})
        self.run_cli(request_wire(original, request), 2, declared='v2')

    def test_declared_schema_and_raw_whitespace_cannot_rebind_result_identity(self):
        original = scalar_program(); request = add_two_patch(original)
        before = json.dumps(original, indent=2, ensure_ascii=False).encode()
        raw = b' \t[\n' + before + b' ,\n' + wire(request) + b'\n] \r\n'
        self.assertNotEqual(sha256(before).hexdigest(), verify_program(original).sha256)
        actual = self.run_cli(raw).stdout
        self.assertEqual(actual, expected_result(original, request))
        self.assertEqual(json.loads(split_result(actual)[1])['original_input_sha256'],
                         verify_program(original).sha256)
        self.run_cli(raw, 2, declared='v2')
        request.update(schema='hepta.hia.patch.v2', interface_policy='preserve')
        self.run_cli(request_wire(original, request), 2, declared='v1')
        self.assertEqual(self.run_cli(request_wire(original, request), declared='v2').stdout,
                         expected_result(original, request))

    def test_invalid_original_cannot_be_repaired_past_base_admission(self):
        original = scalar_program(); request = add_two_patch(original)
        original['functions'][0]['blocks'][0]['ops'][0]['attrs']['value'] = True
        canonical = json.dumps(original, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        request['expected_sha256'] = sha256(canonical).hexdigest()
        self.run_cli(envelope(canonical, wire(request)), 2)

    def test_candidate_semantics_ownership_and_effects_precede_diagnostic_output(self):
        original = scalar_program()
        for change in ('undefined', 'wrong_type', 'missing_effect'):
            request = add_two_patch(original)
            if change == 'undefined':
                request['edits'][0]['operation'] = {'op': 'int.add.wrap', 'args': ['x', 'missing'],
                    'out': [{'name': 'one', 'type': 'u32'}], 'attrs': {}}
            elif change == 'wrong_type':
                request['edits'][0]['operation']['attrs']['value'] = True
            else:
                definition = copy.deepcopy(original['functions'][0]); definition['effects'] = []
                request['edits'] = [{'action': 'replace_function', 'function': 'increment', 'definition': definition}]
            self.run_cli(request_wire(original, request), 2)
        from tests.test_hia_core_admission_native import borrowed_owner
        definition = borrowed_owner()['functions'][0]; definition['name'] = 'leaking'
        request = add_two_patch(original)
        request.update(schema='hepta.hia.patch.v2', interface_policy='migrate')
        request['edits'] = [{'action': 'add_function', 'function': 'leaking', 'definition': definition}]
        self.run_cli(request_wire(original, request), 2, declared='v2')

    def test_snapshot_policy_patch_and_JSON_refusals_emit_no_frame(self):
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
        original = scalar_program(); request = add_two_patch(original)
        raw = request_wire(original, request); expected = expected_result(original, request)
        self.assertEqual(self.run_cli(raw + b' ' * (WIRE_LIMIT - len(raw))).stdout, expected)
        self.run_cli(raw + b' ' * (WIRE_LIMIT + 1 - len(raw)), 3)
        for arguments in ((), ('unexpected',), ('v1', 'v2')):
            self.run_cli(raw, 64, argv=arguments)
        for kind in ('input', 'output', 'mapping'):
            def prepare():
                limits()
                if kind == 'input': os.close(0)
                elif kind == 'output':
                    fd = os.open('/dev/full', os.O_WRONLY); os.dup2(fd, 1); os.close(fd)
                else: resource.setrlimit(resource.RLIMIT_AS, (2 << 20, 2 << 20))
            actual = subprocess.run([str(self.executable), 'v1'], input=raw, capture_output=True,
                timeout=20, preexec_fn=prepare, env={'PATH': ''})
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (4, b'', b''), kind)

    def test_syscalls_and_EINTR_preserve_the_complete_binary_frame(self):
        original = scalar_program(); request = add_two_patch(original)
        raw = request_wire(original, request); expected = expected_result(original, request)
        for interrupted in (False, True):
            trace = self.folder / ('patch-result-' + str(interrupted) + '.strace')
            args = ['-e', 'inject=read:error=EINTR:when=1',
                    '-e', 'inject=write:error=EINTR:when=1'] if interrupted else []
            actual = subprocess.run(['/usr/bin/strace', '-qq', '-o', str(trace), *args,
                str(self.executable), 'v1'], input=raw, capture_output=True, timeout=20, env={'PATH': ''})
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (0, expected, b''))
            calls = re.findall(r'^([a-z0-9_]+)\(', trace.read_text(), re.MULTILINE)
            self.assertEqual(set(calls), {'execve', 'mmap', 'read', 'write', 'exit'})
            self.assertEqual(calls.count('execve'), 1)
            if interrupted: self.assertEqual(trace.read_text().count('(INJECTED)'), 2)

    def test_full_Core_function_profile_and_real_partial_stdout(self):
        import fcntl
        original = scalar_program(); definition = copy.deepcopy(original['functions'][0])
        original['functions'] += [{**copy.deepcopy(definition), 'name': 'f' + str(i)} for i in range(1023)]
        request = add_two_patch(original); expected = expected_result(original, request)
        raw = request_wire(original, request)
        self.assertEqual(self.run_cli(raw).stdout, expected)
        read_fd, write_fd = os.pipe()
        try:
            fcntl.fcntl(write_fd, fcntl.F_SETFL, fcntl.fcntl(write_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
            actual = subprocess.run([str(self.executable), 'v1'], input=raw, stdout=write_fd,
                stderr=subprocess.PIPE, timeout=20, preexec_fn=limits, env={'PATH': ''})
            os.close(write_fd); write_fd = -1
            parts = []
            while True:
                chunk = os.read(read_fd, 65536)
                if not chunk: break
                parts.append(chunk)
            prefix = b''.join(parts)
            self.assertEqual((actual.returncode, actual.stderr), (4, b''))
            self.assertTrue(0 < len(prefix) < len(expected))
            self.assertEqual(prefix, expected[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd != -1: os.close(write_fd)
        request.update(schema='hepta.hia.patch.v2', interface_policy='migrate')
        request['edits'] = [{'action': 'add_function', 'function': 'extra',
                            'definition': {**copy.deepcopy(definition), 'name': 'extra'}}]
        self.run_cli(request_wire(original, request), 2, declared='v2')

    def test_strict_build_refuses_incomplete_cold_before_output(self):
        cold = self.folder / 'wrong-cold.json'; cold.write_text('{}')
        output = self.folder / 'refused-build'
        with self.assertRaisesRegex(ValueError, 'matching-source'):
            build(output, self.compiler, cold)
        self.assertFalse(output.exists())
