"""Actual kernel execution, foreign byte ABI and legacy observation controls."""
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest
import importlib.util
from hashlib import sha256
import json
import subprocess
from unittest.mock import patch

from tools.hia_selfhost_native_observer import frame, execute, invoke as native_invoke, independent_reference, build
from tools import hia_selfhost_native_observer as observer


def _reference_observer():
    """Frozen complete 5831f52 observer, with its original frame/invoke body."""
    path = Path(__file__).with_name('hia_native_observer_v64_reference.py')
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != '1fff85eb393143133cee3140d365fd4d111cee57dd4f6807aae766003d151cf4':
        raise AssertionError('the frozen v64 observer reference source changed')
    spec = importlib.util.spec_from_file_location('hia_observer_v64_test_reference', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def _without_clocks(value):
    if isinstance(value, dict):
        return {k: _without_clocks(v) for k, v in value.items()
                if k not in ('wall_elapsed_ns', 'native_elapsed_ns')}
    if isinstance(value, list):
        return [_without_clocks(v) for v in value]
    return value


class ObserverFrameDifferentialTests(unittest.TestCase):
    def test_complete_frame_bytes_and_all_field_refusals_match_frozen_reference(self):
        old = _reference_observer()
        valid = [
            (b'\xc3', b'', 0, 0, 0, None),
            (b'\xc3', b'\0\xffA', 1, 7, 255, 3),
            (b'\xc3'*17, b'B'*19, 1 << 20, 1 << 20, 90, 2147483647),
            (b'\xc3'*(4 << 20), b'S'*(1 << 20), 0, 0, 0, None),
        ]
        for row in valid:
            self.assertEqual(frame(*row), old.frame(*row))
        base = [b'\xc3', b'A', 1, 8, 90, None]
        invalids = [
            [None, b'', bytearray(b'A'), 'A', b'x' * ((4 << 20) + 1)],
            [None, bytearray(b'A'), 'A', b'x' * ((1 << 20) + 1)],
            [-1, True, False, 1.0, None, (1 << 20) + 1, 1 << 80],
            [-1, True, False, 1.0, None, (1 << 20) + 1, 1 << 80],
            [-1, True, False, 0.0, None, 256, 1 << 80],
            [-1, 0, 1, 2, True, False, 3.0, '3', 2147483648],
        ]
        for position, choices in enumerate(invalids):
            for bad in choices:
                row = list(base); row[position] = bad
                outcomes = []
                for fn in (old.frame, frame):
                    try:
                        fn(*row)
                    except BaseException as exc:
                        outcomes.append((type(exc), str(exc)))
                    else:
                        self.fail(('invalid frame accepted', position, type(bad).__name__))
                self.assertEqual(outcomes[0], outcomes[1], (position, type(bad).__name__))

    def test_byte_subclass_hooks_and_prelaunch_exception_order_are_preserved(self):
        import tools.hia_selfhost_native_observer as current
        old = _reference_observer()
        class Source(bytes):
            def __radd__(self, left):
                raise RuntimeError('source subclass concatenation before preimage check')
        with tempfile.TemporaryDirectory(prefix='hia-observer-frame-order-') as root:
            root = Path(root)
            image = root/'image'; image.write_bytes(b'\xc3')
            observer = root/'observer'; observer.write_bytes(b'not executed')
            rows = [(Source(b'A'), 0, b'BAD'), (b'A', True, b'BAD'), (b'A', 0, b'BAD')]
            for source, capacity, initial in rows:
                outcomes = []
                for module in (old, current):
                    called = []
                    def forbidden(*args, **kwargs):
                        called.append('unexpected prelaunch operation')
                        raise AssertionError('prelaunch failure entered shared_output or execute')
                    with patch.object(module, 'shared_output', new=forbidden), patch.object(module, 'execute', new=forbidden):
                        try:
                            module.invoke(root, 'case', observer, image, source, capacity=capacity,
                                          workspace_size=0, workspace_fill=0, output_initial=initial)
                        except BaseException as exc:
                            outcomes.append((type(exc), str(exc)))
                        else:
                            self.fail('prelaunch control was accepted')
                    self.assertEqual(called, [])
                self.assertEqual(outcomes[0], outcomes[1])
            self.assertEqual(rows[0][0], b'A')


@unittest.skipUnless(platform.system()=='Linux' and platform.machine().lower() in ('x86_64','amd64')
    and shutil.which('ld'), 'Linux x86-64 bootstrap required')
class NativeObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-native-observer-')
        cls.root = Path(cls.temp.name)
        # The VM's actual packer result is established before the seed exists.
        cls.reference = independent_reference()
        seed, _ = build_seed(cls.root)
        cls.compiler, _ = compile_stage(cls.root,'B1',seed,SOURCE.read_bytes(),image_format='seed-shared')
        cls.executable, cls.build = build(cls.root,cls.compiler,cls.reference)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def call(self,name,image,source=b'',capacity=32,workspace_size=128,workspace_fill=90):
        path = self.root/(name+'.image.bin'); path.write_bytes(image)
        return native_invoke(self.root,name,self.executable,path,source,
            capacity=capacity,workspace_size=workspace_size,workspace_fill=workspace_fill)

    def test_actual_hia_emission_matches_independent_VM_every_ELF_byte(self):
        from tools.generate_hia_native_observer import reference_image
        from tools.qualify_hia_selfhost_cli import inspect_executable
        self.assertTrue(self.reference['before_B0'])
        self.assertEqual(self.executable.read_bytes(),reference_image())
        inspected=inspect_executable(self.executable.read_bytes())
        self.assertIsInstance(inspected,dict)
        self.assertFalse(self.build['whole_stack_rewritten_in_hia'])

    def test_actual_builder_rejects_source_and_compiler_change_after_native_compile(self):
        import tools.qualify_hia_selfhost as qualification
        real_compile = qualification.compile_stage
        outcomes = []
        for target in ('source', 'compiler'):
            directory = self.root / ('build-race-' + target)
            directory.mkdir()
            source = directory / 'source.hiaasm'
            source.write_bytes(observer.PACKER.read_bytes())
            compiler = directory / 'compiler.bin'
            compiler.write_bytes(self.compiler.read_bytes())
            calls = []
            def mutate_after_real_compile(*args, **kwargs):
                image, receipt = real_compile(*args, **kwargs)
                calls.append(receipt)
                path = source if target == 'source' else compiler
                path.write_bytes(path.read_bytes() + b'\n')
                return image, receipt
            with patch.object(observer, 'PACKER', source), patch.object(qualification,
                    'compile_stage', mutate_after_real_compile):
                with self.assertRaisesRegex(AssertionError, 'source or compiler changed'):
                    observer.build(directory, compiler, self.reference)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['status'], 'returned')
            self.assertFalse((directory / 'native-observer.elf').exists())
            self.assertFalse((directory / 'native-observer-build.json').exists())
            outcomes.append({'target': target, 'actual_native_compilations': len(calls),
                'actual_compile': calls[0], 'changed_source_sha256': sha256(source.read_bytes()).hexdigest(),
                'changed_compiler_sha256': sha256(compiler.read_bytes()).hexdigest(),
                'refused_before_emission_or_publication': True})
        (self.root / 'actual-builder-input-races.json').write_text(json.dumps(outcomes, indent=2, sort_keys=True) + '\n')

    def test_independent_VM_uses_one_source_snapshot_and_rejects_late_change(self):
        import hepta.hia_agent_assembly as assembly
        directory = self.root / 'reference-source-race'
        directory.mkdir()
        source = directory / 'source.hiaasm'
        original = observer.PACKER.read_bytes()
        source.write_bytes(original)
        real_assemble = assembly.assemble_program
        wrappers = []
        def mutate_after_real_assembly(raw):
            checked = real_assemble(raw)
            wrappers.append(sha256(raw).hexdigest())
            self.assertTrue(raw.endswith(original.split(b'\n', 1)[1]))
            if len(wrappers) == 1:
                source.write_bytes(original + b'\n')
            return checked
        with patch.object(observer, 'PACKER', source), patch.object(assembly,
                'assemble_program', mutate_after_real_assembly):
            with self.assertRaisesRegex(AssertionError, 'reference source changed'):
                observer.independent_reference()
        self.assertEqual(len(wrappers), len(self.reference['vm_windows']))
        (directory / 'result.json').write_text(json.dumps({'actual_VM_windows': len(wrappers),
            'wrappers_sha256': wrappers, 'one_original_source_snapshot': True,
            'final_source_change_refused': True}, indent=2, sort_keys=True) + '\n')

    def test_exact_full_foreign_return_source_output_and_workspace_observations(self):
        from tools.qualify_hia_selfhost import invoke
        # Arbitrary full 64-bit return, with the ABI-status half observable.
        code=bytes.fromhex('48 b8 2a 00 00 00 ef be ad de c3')
        for n,source in enumerate((b'',b'A\0\xff'*137)):
            for capacity in (0,1,257):
                for fill in (0,90,255):
                    name='paired-'+str(n)+'-'+str(capacity)+'-'+str(fill)
                    result,output=self.call(name,code,source,capacity,1032,fill)
                    original,raw=invoke(self.root,name+'-legacy',self.root/(name+'.image.bin'),source,
                        capacity=capacity,workspace_size=1032,workspace_fill=fill)
                    for key in ('status','result_u64','abi_status','core_u32','source_unchanged',
                        'output_unchanged','workspace_header','source_sha256','output_sha256','limits'):
                        self.assertEqual(result[key],original[key],(name,key))
                    self.assertEqual(output,raw)
                    self.assertTrue(result['fresh_native_exec'])
                    self.assertFalse(result['successor_process_reuse'])

    def test_source_mutation_is_actually_observed_not_assumed(self):
        # Deliberately hostile image violates the read-only source obligation.
        result,output=self.call('mutates-source',bytes.fromhex('c6 07 61 31 c0 c3'),b'XYZ')
        self.assertFalse(result['source_unchanged'])
        self.assertTrue(result['output_unchanged'])
        self.assertEqual(output,b'\xa5'*32)

    def test_native_trap_remains_real_SIGILL_and_retained_shared_capture_path(self):
        import tools.qualify_hia_selfhost as q
        result,output=self.call('actual-UD2',b'\x0f\x0b')
        self.assertEqual((result['status'],result['returncode'],output),('child_failed',-4,b''))
        # A write before trapping is observed through actual parent-owned
        # shared memory, not inferred from the native stdout protocol.
        image=self.root/'prior-store-UD2.bin';image.write_bytes(bytes.fromhex('c6 02 63 0f 0b'))
        prior=q.NATIVE_OBSERVER
        try:
            q.NATIVE_OBSERVER=self.executable
            trapped,raw=q.invoke(self.root,'retained-shared-capture',image,b'',capacity=1,
                workspace_size=0,observe_trap_writes=True)
        finally:
            q.NATIVE_OBSERVER=prior
        self.assertEqual(trapped['returncode'],-4)
        self.assertTrue(trapped['shared_output_observation']['available'])
        self.assertEqual(raw,b'c')
        self.assertEqual(trapped['transport'],'HIA-emitted-static-ELF-observer-v2')
        legacy,old=q.invoke(self.root,'legacy-shared-capture-control',image,b'',capacity=1,
            workspace_size=0,observe_trap_writes=True)
        self.assertEqual(old,raw)
        self.assertEqual(legacy['returncode'],trapped['returncode'])

    def test_real_HIA_compiler_bytes_output_and_error_counters_equal_legacy(self):
        from tools.qualify_hia_selfhost import invoke, SAMPLE
        for n,source in enumerate((SAMPLE.read_bytes(),b'invalid')):
            name='compiler-control-'+str(n)
            actual,output=native_invoke(self.root,name,self.executable,self.compiler,source,
                capacity=1<<20,workspace_size=1<<20,workspace_fill=90)
            original,raw=invoke(self.root,name+'-legacy',self.compiler,source,workspace_fill=90)
            self.assertEqual(output,raw)
            for key in ('status','result_u64','core_u32','abi_status','source_unchanged',
                        'output_unchanged','workspace_header'):
                self.assertEqual(actual[key],original[key],(n,key))

    def test_kernel_limits_and_non_dumpable_are_real_not_receipt_constants(self):
        # Linux prlimit64(0, RLIMIT_CPU, NULL, workspace) then PR_GET_DUMPABLE.
        # Store actual results into the output before returning the syscall code.
        code=bytes.fromhex('49 89 d4 4d 89 c2 31 ff 31 f6 31 d2 b8 2e 01 00 00 0f 05'
            ' 49 8b 02 49 89 04 24 49 8b 42 08 49 89 44 24 08'
            ' bf 03 00 00 00 b8 9d 00 00 00 0f 05 c3')
        # Preserve SysV r12 across this deliberately hand-authored foreign image.
        code=b'\x41\x54'+code[:-1]+b'\x41\x5c\xc3'
        result,output=self.call('kernel-limits',code,capacity=16,workspace_size=16)
        self.assertEqual(result['core_u32'],0)
        self.assertEqual(struct.unpack('<2Q',output),(10,10))

    def test_custom_preimages_and_real_post_trap_writes_match_independent_legacy_capture(self):
        from tools.qualify_hia_selfhost import invoke
        codes=[bytes.fromhex('31 c0 c3'),bytes.fromhex('c6 02 63 31 c0 c3'),bytes.fromhex('c6 02 63 0f 0b')]
        for index,code in enumerate(codes):
            image=self.root/('custom-'+str(index)+'.bin');image.write_bytes(code)
            for initial in (b'\0',b'Z\0\xff',b'\xff'*31):
                name='custom-'+str(index)+'-'+str(len(initial))
                actual,out=native_invoke(self.root,name,self.executable,image,b'input',capacity=len(initial),
                    workspace_size=128,workspace_fill=255,output_initial=initial,observe_trap_writes=True)
                old,raw=invoke(self.root,name+'-legacy',image,b'input',capacity=len(initial),workspace_size=128,
                    workspace_fill=255,output_initial=initial,observe_trap_writes=True)
                self.assertEqual(actual['status'],old['status'])
                self.assertEqual(out,raw)
                for key in ('available','initial_sha256','observed_sha256','observed_bytes','unchanged'):
                    self.assertEqual(actual['shared_output_observation'][key],old['shared_output_observation'][key])
                if index==2:self.assertEqual(actual['returncode'],-4)
                else:self.assertEqual(actual['core_u32'],old['core_u32'])

    def test_unexpected_native_stdout_is_refused_and_exact_failure_bytes_retained(self):
        # Deliberate foreign image writes caller bytes to stdout before returning.
        code=bytes.fromhex('48 89 f2 48 89 fe bf 01 00 00 00 b8 01 00 00 00 0f 05 b8 2a 00 00 00 c3')
        result,output=self.call('unexpected-stdout',code,b'injected-prefix')
        self.assertEqual(result['status'],'protocol_failed')
        self.assertEqual(output,b'')
        raw=(self.root/'unexpected-stdout.failure-stdout.raw').read_bytes()
        self.assertTrue(raw.startswith(b'injected-prefixHIAOBR02'))
        self.assertEqual(len(raw),result['response_bytes'])

    def test_shared_extent_seals_allow_real_writes_but_not_growth_or_shrink(self):
        import fcntl,os
        from tools.hia_selfhost_native_observer import shared_output,read_capture
        with shared_output(b'ABC',True) as descriptor:
            self.assertEqual(read_capture(descriptor,3),b'ABC')
            self.assertEqual(fcntl.fcntl(descriptor,getattr(fcntl,'F_GET_SEALS',1034)) & 7,7)
            for size in (0,2,4):
                with self.assertRaises(OSError):os.ftruncate(descriptor,size)
            os.pwrite(descriptor,b'Z',1)
            self.assertEqual(read_capture(descriptor,3),b'AZC')
        with self.assertRaises(OSError):fcntl.fcntl(descriptor,fcntl.F_GETFD)

    def test_prelaunch_storage_failure_does_not_leak_shared_output_descriptor(self):
        import errno
        from unittest.mock import patch
        before=len(list(Path('/proc/self/fd').iterdir()))
        image=self.root/'storage-failure-image.bin';image.write_bytes(bytes.fromhex('31 c0 c3'))
        with patch.object(Path,'write_text',side_effect=OSError(errno.ENOSPC,'injected retained storage failure')):
            with self.assertRaises(OSError):
                native_invoke(self.root,'storage-failure',self.executable,image,b'',capacity=1,
                    workspace_size=0,workspace_fill=0,output_initial=b'X',observe_trap_writes=True)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)

    def test_bad_frames_lengths_overflow_and_arguments_fail_without_output(self):
        image=self.executable.read_bytes()
        good=frame(b'\xc3',b'',0,0,0)
        bad=[b'',good[:47],b'badMAGIC'+good[8:],good+b'\0',good[:-1]]
        for index in range(5):
            altered=bytearray(good);struct.pack_into('<Q',altered,8+index*8,2**64-1);bad.append(bytes(altered))
        for value in (0,1,2,2147483648,2**64-2):
            altered=bytearray(good);struct.pack_into('<Q',altered,48,value);bad.append(bytes(altered))
        for data in bad:
            result=execute(image,data,cwd=self.root)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        result=execute(image,good,cwd=self.root,arguments=('unexpected',))
        self.assertEqual((result.returncode,result.stdout),(64,b''))
        for values in ((b'',b'',0,0,0),(b'x',b'',True,0,0),(b'x',b'',0,0,256)):
            with self.assertRaises(ValueError):frame(*values)

    def _transport_pair(self, name, source=b'XYZ', *, code=None, capacity=7,
                        workspace_size=1032, output_initial=None,
                        observe_trap_writes=False, fault=None):
        import tools.hia_selfhost_native_observer as current
        old = _reference_observer()
        snapshots = []
        for version, module in (('reference', old), ('candidate', current)):
            directory = self.root/(name+'-'+version)
            directory.mkdir()
            observer = directory/'observer.elf'
            observer.write_bytes(self.executable.read_bytes())
            image = directory/'image.bin'
            image.write_bytes(bytes.fromhex('b8 2a 00 00 00 c3') if code is None else code)
            actual = []
            real_execute = module.execute
            def traced_execute(executable_bytes, request, **kwargs):
                process = real_execute(executable_bytes, request, **kwargs)
                actual.append((process.returncode, len(process.stdout), len(process.stderr)))
                if fault is not None:
                    return fault(process, directory, observer, image, kwargs)
                return process
            try:
                with patch.object(module, 'execute', new=traced_execute):
                    result, output = module.invoke(directory, 'case', observer, image, source,
                        capacity=capacity, workspace_size=workspace_size, workspace_fill=90,
                        output_initial=output_initial, observe_trap_writes=observe_trap_writes)
                outcome = {'kind': 'returned', 'result': _without_clocks(result), 'output': output}
            except BaseException as exc:
                outcome = {'kind': 'raised', 'exception': type(exc).__name__,
                           'message': str(exc).replace(str(directory), '<case>')}
            self.assertEqual(len(actual), 1, (name, version))
            if outcome['kind'] == 'returned' and outcome['result']['status'] == 'protocol_failed':
                failed_raw = (directory/'case.failure-stdout.raw').read_bytes()
                self.assertEqual(outcome['result']['response_sha256'], module.digest(failed_raw))
                # The exact raw hash is checked per execution; the native
                # elapsed field makes that hash differ across actual children.
                outcome['result'].pop('response_sha256')
            retained = {p.name: p.read_bytes() for p in directory.iterdir() if p.name.endswith(
                ('.input.bin', '.output.bin', '.failure-stdout.raw', '.modified-source.bin', '.stderr.log'))}
            for filename, raw in list(retained.items()):
                if filename.endswith('.failure-stdout.raw') and len(raw) >= 24:
                    # These faults alter a known real observer response. Keep
                    # its original file and mask only the recorded clock for
                    # cross-run comparison, as for native_elapsed_ns above.
                    retained[filename] = raw[:16]+bytes(8)+raw[24:]
            snapshots.append((outcome, retained))
        self.assertEqual(snapshots[0], snapshots[1], name)
        return snapshots[1][0]

    def test_transport_native_workspace_edges_and_full_header_values_match_reference(self):
        for size in (0, 7, 8, 15, 16, 223, 224, 231, 232, 1023, 1024, 1031, 1032, 1 << 20):
            result = self._transport_pair('workspace-edge-'+str(size), workspace_size=size)
            self.assertEqual(result['kind'], 'returned')
            observed = result['result']['workspace_header']
            expected = {str(at): int.from_bytes(b'Z'*8, 'little')
                        for at in (0,8,16,24,40,48,56,64,72,80,88,96,104,112,224,248,1024)
                        if size >= at+8}
            self.assertEqual(observed, expected)

    def test_transport_source_image_observer_disk_changes_still_fail_after_real_child(self):
        for target in ('observer', 'image', 'input'):
            for mutation in ('changed', 'missing'):
                def fault(process, directory, observer, image, kwargs, target=target, mutation=mutation):
                    path = {'observer': observer, 'image': image, 'input': directory/'case.input.bin'}[target]
                    if mutation == 'changed':
                        path.write_bytes(path.read_bytes()+b'changed')
                    else:
                        path.unlink()
                    return process
                result = self._transport_pair('disk-'+target+'-'+mutation, fault=fault)
                self.assertEqual(result['kind'], 'raised')
                self.assertEqual(result['exception'], 'AssertionError' if mutation == 'changed' else 'FileNotFoundError')

    def test_transport_corrupted_actual_response_and_timeout_branches_match_reference(self):
        def injection(kind):
            def fault(process, directory, observer, image, kwargs):
                raw, stderr, returncode = process.stdout, process.stderr, process.returncode
                if kind == 'short': raw = raw[:-1]
                elif kind == 'extra': raw += b'X'
                elif kind == 'magic': raw = b'BADMAGIC'+raw[8:]
                elif kind == 'stderr': stderr = b'injected stderr'
                elif kind == 'child-status': returncode = 17
                elif kind == 'source': raw = raw[:24]+b'!'+raw[25:]
                elif kind == 'abi-status': raw = raw[:8]+struct.pack('<Q', 0xdeadbeef0000002a)+raw[16:]
                elif kind == 'timeout':
                    # A real child has already run; this injects the parent's
                    # TimeoutExpired branch without pretending 20s elapsed.
                    raise subprocess.TimeoutExpired('post-exec-timeout-control', 20,
                                                    output=raw, stderr=b'injected timeout')
                return subprocess.CompletedProcess(process.args, returncode, raw, stderr)
            return fault
        for kind in ('short', 'extra', 'magic', 'stderr', 'child-status', 'source', 'abi-status', 'timeout'):
            result = self._transport_pair('response-'+kind, fault=injection(kind))
            self.assertEqual(result['kind'], 'returned')
            if kind in ('short', 'extra', 'magic', 'stderr'):
                self.assertEqual(result['result']['status'], 'protocol_failed')
            elif kind == 'child-status':
                self.assertEqual((result['result']['status'], result['result']['returncode']), ('child_failed', 17))
            elif kind == 'source':
                self.assertFalse(result['result']['source_unchanged'])
            elif kind == 'abi-status':
                self.assertEqual(result['result']['abi_status'], 0xdeadbeef)
            else:
                self.assertEqual((result['result']['status'], result['result']['wall_limit_seconds']), ('timeout', 20))

    def test_transport_trap_capture_and_fresh_native_pids_remain_real(self):
        result = self._transport_pair('write-then-trap', code=bytes.fromhex('c6 02 63 0f 0b'),
            capacity=3, workspace_size=0, output_initial=b'ABC', observe_trap_writes=True)
        self.assertEqual((result['result']['status'], result['result']['returncode'], result['output']),
                         ('child_failed', -4, b'cBC'))
        # Linux getpid, returned directly by each new native process.
        code = bytes.fromhex('b8 27 00 00 00 0f 05 c3')
        pids = []
        for index in range(4):
            result, _ = self.call('fresh-pid-'+str(index), code, workspace_size=0)
            self.assertEqual(result['status'], 'returned')
            self.assertTrue(result['fresh_native_exec'])
            self.assertFalse(result['successor_process_reuse'])
            pids.append(result['core_u32'])
        self.assertEqual(len(set(pids)), 4)

    def test_transport_no_digest_reuse_across_changed_invocation_inputs(self):
        import tools.hia_selfhost_native_observer as current
        image = self.root/'same-path-replaced-image.bin'
        for index, source in enumerate((b'first', b'second', b'third')):
            code = b'\xb8'+struct.pack('<I', index+31)+b'\xc3'
            image.write_bytes(code)
            result, output = current.invoke(self.root, 'same-label-replaced-input', self.executable,
                image, source, capacity=3, workspace_size=8, workspace_fill=90)
            self.assertEqual(result['core_u32'], index+31)
            self.assertEqual(result['input_sha256'], current.digest(source))
            self.assertEqual(result['source_sha256'], current.digest(source))
            self.assertEqual(result['artifact_sha256'], current.digest(code))
            self.assertEqual(result['image_sha256'], current.digest(code))
            self.assertEqual(output, b'\xa5'*3)


if __name__=='__main__':
    unittest.main()
