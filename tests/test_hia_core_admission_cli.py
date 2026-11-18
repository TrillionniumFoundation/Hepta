"""Independent packer VM, raw-kernel admission and copied empty-PATH CLI."""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import resource
import shutil
import struct
import subprocess
import tempfile
import unittest

from tools.generate_hia_core_admission_cli import (
    INSPECT_MAGIC, MAGIC, NORMALIZE_MAGIC, STATE_BYTES, ARENA_BYTES, NORMALIZE_OUTPUT_BYTES, document,
)
from tools.build_hia_core_admission_cli import SOURCE, PACKER, build
from tests.test_hia_core_admission_native import VALID, borrowed_owner, interpreted, wire
from tests.test_hia_core_workspace_facts_native import vm_run


def frame(image):
    return struct.pack('<QQ', MAGIC, len(image)) + image


def normalize_frame(admission, formatter):
    return struct.pack('<3Q', NORMALIZE_MAGIC, len(admission), len(formatter)) + admission + formatter


class CoreAdmissionCliSourceTests(unittest.TestCase):
    def test_actual_generated_source_and_full_Core_scratch_not_compiler_profile(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from hepta.hia_core_admission_native import MAX_BYTES, scratch_sizes
        self.assertEqual(PACKER.read_text(), render_assembly(document()))
        assemble_program(PACKER.read_bytes())
        state, arena = scratch_sizes(MAX_BYTES)
        self.assertGreaterEqual(STATE_BYTES, state)
        self.assertGreaterEqual(ARENA_BYTES, arena)

    def test_independent_VM_packer_and_no_write_on_refusal_before_native_seed(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable
        payload = b'\x31\xc0\xc3'
        request = frame(payload)
        size, raw = vm_run(PACKER, request, 4096, 1)
        self.assertEqual(size, len(raw))
        self.assertTrue(raw.endswith(payload))
        self.assertFalse(inspect_executable(raw)['dynamic_loader'])
        for request, cap, status in ((request, 64, 0xfffffffe), (request + b'x', 4096, 0xffffffff),
                                     (b'wrong', 4096, 0xffffffff)):
            self.assertEqual(vm_run(PACKER, request, cap, 1), (status, b'\xa5' * cap))

    def test_normalize_sources_and_two_image_packer(self):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_json_decode_native import arena_sizes
        from hepta.hia_program import MAX_BYTES, MAX_NODES, MAX_DEPTH
        from tools.generate_hia_json_canonical import document as pretty_document
        from tools.qualify_hia_selfhost_cli import inspect_executable

        packer = PACKER.with_name('core_normalize_cli_packer.hepta')
        self.assertEqual(packer.read_text(), render_assembly(document(normalize=True)))
        pretty = SOURCE.with_name('core_pretty_json.hepta')
        self.assertEqual(pretty.read_text(),render_assembly(pretty_document(core_pretty=True)))
        arena, keys = arena_sizes(MAX_BYTES, MAX_NODES, MAX_DEPTH)
        self.assertGreaterEqual(ARENA_BYTES, arena)
        self.assertGreaterEqual(NORMALIZE_OUTPUT_BYTES, keys)
        self.assertGreaterEqual(NORMALIZE_OUTPUT_BYTES,
                                1 + MAX_BYTES + MAX_NODES * (4 * MAX_DEPTH + 4))
        first, second = b'\x31\xc0\xc3', b'\x31\xc0\x90\xc3'
        request = normalize_frame(first, second)
        size, raw = vm_run(packer, request, 4096, 1)
        self.assertEqual(size,len(raw))
        self.assertTrue(raw.endswith(first + second))
        self.assertFalse(inspect_executable(raw)['dynamic_loader'])
        for invalid in (normalize_frame(b'', second), normalize_frame(first,b''), request[:-1],
                        request + b'x', frame(first)):
            self.assertEqual(vm_run(packer, invalid, 4096, 1), (0xffffffff, b'\xa5' * 4096))
        self.assertEqual(vm_run(packer, request, 64, 1), (0xfffffffe, b'\xa5' * 64))


    def test_inspection_formatter_and_packer_have_independent_HIA_sources(self):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_program_tools import inspect_program
        from tools.generate_hia_core_inspect_json import document as inspection_doc, source_program

        formatter = SOURCE.with_name('core_inspect_json.hepta')
        packer = SOURCE.with_name('core_inspect_cli_packer.hepta')
        self.assertEqual(packer.read_text(), render_assembly(document(inspect=True)))
        self.assertEqual(formatter.read_text(), render_assembly(
            inspection_doc(source_program(), 'core_inspect_json')))
        request = struct.pack('<3Q', INSPECT_MAGIC, 3, 3) + b'\x31\xc0\xc3' * 2
        size, elf = vm_run(packer, request, 4096, 1)
        self.assertEqual(size, len(elf))
        self.assertTrue(elf.endswith(request[24:]))
        expected = (json.dumps(inspect_program(VALID), sort_keys=True,
                               ensure_ascii=False, indent=2) + '\n').encode()
        raw = b' ' + wire(VALID).replace(b'"module"', b'"m\\u006fdule"') + b'\n'
        self.assertEqual(vm_run(formatter, raw, 16384, 65536), (len(expected), expected))


class CoreAdmissionCliNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CoreAdmissionCliSourceTests().test_independent_VM_packer_and_no_write_on_refusal_before_native_seed()
        assert interpreted(wire(VALID)) == 0
        assert interpreted(wire(borrowed_owner())) == 0xfffffff8
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-core-admission-cli-')
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
        from tools.qualify_hia_selfhost_cli import inspect_executable
        cold = os.environ.get('HEPTA_HIA_CORE_ADMISSION_CLI_COLD_REPORT')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            assert report['status'] == 'COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256'] == [sha256(compiler.read_bytes()).hexdigest()] * 3
        else:
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
        cls.compiler = compiler
        image, cls.kernel_receipt = compile_stage(cls.folder, 'core-admission', compiler, SOURCE.read_bytes())
        cls.admission = image
        cls.cold = Path(cold) if cold else None
        packer, cls.packer_receipt = compile_stage(cls.folder, 'core-admission-cli-packer', compiler, PACKER.read_bytes())
        request = frame(image.read_bytes())
        receipt, arena = invoke(cls.folder, 'core-admission-cli-pack', packer, request)
        assert 0 < receipt['core_u32'] <= 1 << 20
        raw = arena[:receipt['core_u32']]
        cls.inspection = inspect_executable(raw)
        # Every executable byte and its native-image call displacement must
        # match the independently interpreted HIA packer, not just its header.
        assert vm_run(PACKER, request, len(request) + 4096, 1) == (len(raw), raw)
        cls.executable = cls.folder / 'hia-verify-core'
        cls.executable.write_bytes(raw)
        cls.executable.chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @staticmethod
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))

    def run_cli(self, raw, expected=0, path=None):
        result = subprocess.run([str(path or self.executable)], input=raw, capture_output=True,
                                timeout=20, preexec_fn=self.limits,
                                env={'PATH': '/nonexistent', 'HOME': '/nonexistent', 'LC_ALL': 'C'})
        self.assertEqual((result.returncode, result.stdout, result.stderr), (expected, b'', b''))
        return result

    def test_standalone_copy_requires_no_python_source_image_sidecar_or_loader(self):
        self.assertIsNone(self.inspection['interpreter'])
        self.assertFalse(self.inspection['libc'])
        self.assertEqual(self.kernel_receipt['forbidden_compiler_modules_loaded'], [])
        self.assertEqual(self.packer_receipt['forbidden_compiler_modules_loaded'], [])
        with tempfile.TemporaryDirectory(prefix='hia-core-admission-copied-') as d:
            target = Path(d) / 'validator'
            shutil.copyfile(self.executable, target)
            target.chmod(0o700)
            self.assertEqual(list(Path(d).iterdir()), [target])
            self.run_cli(wire(VALID), path=target)
            self.run_cli(wire(borrowed_owner()), 2, path=target)

    def test_raw_json_and_actual_owner_loan_refusals_not_just_structure(self):
        from tests.test_hia_program import joined_loan_program
        self.run_cli(wire(joined_loan_program()))
        self.run_cli(wire(borrowed_owner()), 2)
        safe = borrowed_owner()
        safe['functions'][0]['effects'].append('alloc')
        safe['functions'][0]['blocks'][0]['ops'].insert(1,
            {'op': 'loan.end', 'args': ['view'], 'out': [], 'attrs': {}})
        self.run_cli(wire(safe))
        for raw in (b'', b'{', b'\xff', wire(VALID) + b'x', b'{"schema":0,"schema":1}', b'[]'):
            self.run_cli(raw, 2)
        self.run_cli(b' \n' + wire(VALID) + b'\t\r\n')

    def test_full_function_block_and_arity_profiles_reach_the_native_kernel(self):
        value = copy.deepcopy(VALID)
        fn = value['functions'][0]
        value['functions'] = [{**copy.deepcopy(fn), 'name': 'f' + str(i)} for i in range(1024)]
        self.run_cli(wire(value))
        value['functions'].append({**copy.deepcopy(fn), 'name': 'extra'})
        # The unchanged Core policy calls excess functions FORMAT and excess
        # blocks CFG, not decoder LIMIT. Both must remain semantic refusals.
        self.run_cli(wire(value), 2)
        value = copy.deepcopy(VALID)
        fn = value['functions'][0]
        fn['blocks'] = [{'id': 'b' + str(i), 'params': [], 'ops': [],
                         'term': {'op': 'jump', 'target': 'b' + str(i + 1), 'args': []}
                         if i < 4095 else {'op': 'ret', 'values': []}} for i in range(4096)]
        fn['entry'] = 'b0'
        random.Random(93).shuffle(fn['blocks'])
        self.run_cli(wire(value))
        fn['blocks'].append({'id': 'extra', 'params': [], 'ops': [], 'term': {'op': 'ret', 'values': []}})
        self.run_cli(wire(value), 2)
        value = copy.deepcopy(VALID)
        fn = value['functions'][0]
        fn['params'] = [{'name': 'p' + str(i), 'type': 'u32'} for i in range(16384)]
        fn['blocks'][0]['params'] = copy.deepcopy(fn['params'])
        fn['returns'] = ['u32'] * 1024
        fn['blocks'][0]['term']['values'] = ['p' + str(i) for i in range(1024)]
        self.run_cli(wire(value))

    def test_exact_byte_node_depth_limits_and_descriptor_failures(self):
        # Padding remains part of a valid Core JSON document, not an unknown
        # opcode that could refuse before reaching an allocation boundary.
        raw = wire(VALID)
        padded = raw + b' ' * (8388608 - len(raw))
        self.run_cli(padded)
        self.run_cli(padded + b' ', 3)
        value = copy.deepcopy(VALID)
        value['functions'][0]['blocks'][0]['ops'] = [
            {'op': 'opaque', 'args': [], 'out': [], 'attrs': {'payload': []}}]
        attrs = value['functions'][0]['blocks'][0]['ops'][0]['attrs']
        pending = [value]
        count = 0
        while pending:
            item = pending.pop()
            count += 1
            if type(item) is dict: pending.extend(item.values())
            if type(item) is list: pending.extend(item)
        attrs['payload'].extend([None] * (262144 - count))
        self.run_cli(wire(value), 2)  # Full decoder budget reached; opaque opcode refused.
        attrs['payload'].append(None)
        self.run_cli(wire(value), 3)
        nested = None
        for _ in range(56): nested = [nested]
        attrs['payload'] = nested
        self.run_cli(wire(value), 2)
        attrs['payload'] = [nested]
        self.run_cli(wire(value), 3)
        result = subprocess.run([str(self.executable), 'unexpected'], input=b'', capture_output=True,
                                env={'PATH': '/nonexistent'}, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (64, b'', b''))
        result = subprocess.run([str(self.executable)], input=b'', capture_output=True,
                                preexec_fn=lambda: os.close(0), env={'PATH': '/nonexistent'}, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (4, b'', b''))

    def test_strict_build_refuses_parent_source_before_creating_output(self):
        wrong = self.folder / 'wrong-cold.json'
        wrong.write_text(json.dumps({'status': 'COLD_SELFHOST_REPLAY_PASS', 'profile': 'wrong', 'source_manifest': {}}))
        output = self.folder / 'wrong-build'
        with self.assertRaisesRegex(ValueError, 'matching-source'):
            build(output, self.compiler, wrong)
        self.assertFalse(output.exists())

    def formatted_cli(self, action, formatter, magic):
        from tools.qualify_hia_selfhost import compile_stage, invoke

        folder = self.folder/action
        if self.cold:
            return build(folder, self.compiler, self.cold,
                         normalize=action=='normalize', inspect=action=='inspect')
        folder.mkdir()
        images = []
        for name in (formatter, f'core_{action}_cli_packer'):
            image, _ = compile_stage(folder, name, self.compiler, SOURCE.with_name(name+'.hepta').read_bytes())
            images.append(image)
        admission, rendered = self.admission.read_bytes(), images[0].read_bytes()
        request = struct.pack('<3Q', magic, len(admission), len(rendered)) + admission + rendered
        receipt, arena = invoke(folder, action + '-pack', images[1], request)
        size = receipt['core_u32']
        self.assertTrue(0 < size <= 1 << 20)
        target = folder / ('hia-' + action + '-core')
        target.write_bytes(arena[:size])
        target.chmod(0o700)
        return target

    def test_native_normalize_matches_hosted_output_after_full_admission(self):
        from hepta.hia_program import verify_program
        from hepta.hia_schema import PRIMITIVE_PROFILES
        from tools.qualify_hia_selfhost_cli import inspect_executable

        target = self.formatted_cli('normalize', 'core_pretty_json', NORMALIZE_MAGIC)
        copied=self.folder/'copied-normalize'
        shutil.copyfile(target,copied);copied.chmod(0o500)
        self.assertFalse(inspect_executable(copied.read_bytes())['dynamic_loader'])

        def run(raw, expected=0, args=()):
            stdout = b''
            if expected == 0:
                data = verify_program(raw).as_dict()
                stdout = (json.dumps(data,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
            result = subprocess.run([copied,*args],input=raw,capture_output=True,
                                    env={'PATH':'','HOME':'/nonexistent','LC_ALL':'C'},
                                    timeout=20,preexec_fn=self.limits)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(expected,stdout,b''))

        for schema in PRIMITIVE_PROFILES:
            with self.subTest(schema=schema):
                raw=wire({**VALID,'schema':schema}).replace(b'"module"',b'"m\\u006fdule"',1)
                run(b'\n'+raw+b'\t ')
        for raw in (b'', b'\xff', wire(borrowed_owner()), b'{"schema":0,"\\u0073chema":1}'):
            run(raw, 2)
        value=copy.deepcopy(VALID)
        fn=value['functions'][0]
        value['functions']=[{**fn,'name':'f'+str(i)} for i in range(1024)]
        run(wire(value))
        padded=wire(VALID).ljust(8 << 20,b' ')
        run(padded)
        run(padded+b' ',3)
        run(wire(VALID),64,('unexpected',))


    def test_native_inspect_matches_hosted_methods_and_canonical_identity(self):
        from hepta.hia_program_tools import inspect_program
        from hepta.hia_schema import PRIMITIVE_PROFILES
        from tests.test_hia_program import b, f, i, ret
        from tools.qualify_hia_selfhost_cli import inspect_executable

        target = self.formatted_cli('inspect', 'core_inspect_json', INSPECT_MAGIC)
        copied = self.folder/'copied-inspect'
        shutil.copyfile(target, copied)
        copied.chmod(0o500)
        self.assertFalse(inspect_executable(copied.read_bytes())['dynamic_loader'])

        def run(raw):
            expected = (json.dumps(inspect_program(raw), ensure_ascii=False,
                                   indent=2, sort_keys=True) + '\n').encode()
            result = subprocess.run([copied], input=raw, capture_output=True,
                                    env={'PATH': '', 'HOME': '/nonexistent', 'LC_ALL': 'C'},
                                    timeout=20, preexec_fn=self.limits)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))

        first = f('zulu', [('a', 'u64')], ['u64'], [], [
            b('entry', [('a', 'u64')], [
                i('const', [], [('zero', 'u64')], value=0),
                i('int.add.wrap', ['a', 'zero'], [('sum', 'u64')])], ret('sum'))])
        seconds = f('alpha', [('owner', 'readbuf')], [], ['read'], [
            b('entry', [('owner', 'readbuf')], [], ret())])
        public = f('bravo', [], [], [], [b('entry', [], [], ret())])
        for schema in PRIMITIVE_PROFILES:
            fixture = {**VALID, 'schema': schema, 'functions': [first, seconds, public]}
            raw = json.dumps(fixture, ensure_ascii=False, indent=4).encode()
            with self.subTest(schema=schema):
                run(raw.replace(b'"module"',b'"m\\u006fdule"',1).replace(b'"value": 0',b'"value": -0',1))
        fixture['exports'] = ['zulu', 'bravo']
        run(wire(fixture))
        loan = f('identity', [('source', 'readbuf')], ['readbuf'], [], [
            b('entry', [('source', 'readbuf')], [], ret('source'))])
        loan['return_loans'] = ['source']
        run(wire({**VALID, 'functions': [loan]}))
        maximal = {**VALID, 'functions': [{**VALID['functions'][0], 'name': f'f{i}'}
                                         for i in range(1024, 0, -1)]}
        run(wire(maximal))
        run(wire(VALID).ljust(8 << 20, b' '))
        for invalid in (b'', b'{"schema":0,"\\u0073chema":1}', wire(borrowed_owner())):
            self.run_cli(invalid, 2, copied)
        self.run_cli(wire(VALID).ljust((8 << 20) + 1, b' '), 3, copied)
