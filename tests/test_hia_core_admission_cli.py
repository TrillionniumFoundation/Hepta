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

from tools.generate_hia_core_admission_cli import MAGIC, STATE_BYTES, ARENA_BYTES, document
from tools.build_hia_core_admission_cli import SOURCE, PACKER, build
from tests.test_hia_core_admission_native import VALID, borrowed_owner, interpreted, wire
from tests.test_hia_core_workspace_facts_native import vm_run


def frame(image):
    return struct.pack('<QQ', MAGIC, len(image)) + image


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
            source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
        cls.compiler = compiler
        image, cls.kernel_receipt = compile_stage(cls.folder, 'core-admission', compiler, SOURCE.read_bytes())
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
