"""Actual dlopen, HIA emission, legacy observations and kernel boundary controls."""
from pathlib import Path
from hashlib import sha256
import json
import os
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_selfhost_linked_observer as observer


class LinkedObserverSourceTests(unittest.TestCase):
    def test_full_source_regenerates_with_unchanged_compiler_limits(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_linked_observer import document
        generated = document()
        self.assertEqual(render_assembly(generated).encode(), observer.PACKER.read_bytes())
        self.assertLessEqual(len(generated['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in generated['functions']), 1536)
        self.assertLessEqual(max(len(fn['blocks']) for fn in generated['functions']), 256)
        self.assertLessEqual(max(len(block['params']) for fn in generated['functions']
            for block in fn['blocks']), 16)

    def test_complete_frame_and_refusals_keep_existing_private_byte_bounds(self):
        from tools.hia_selfhost_native_observer import frame as original
        for row in ((b'X', b'', 0, 0, 0, None), (b'A' * 17, b'B' * 19, 1 << 20,
                1 << 20, 255, 2147483647), (b'A' * (4 << 20), b'B' * (1 << 20), 0, 0, 0, 3)):
            self.assertEqual(observer.frame(*row), b'HIALDS01' + original(*row)[8:])
        base = [b'X', b'', 0, 0, 0, None]
        invalids = [(b'', bytearray(b'A'), None, b'A' * ((4 << 20) + 1)),
            (None, bytearray(b'A'), b'A' * ((1 << 20) + 1)),
            (-1, True, 1.0, (1 << 20) + 1), (-1, False, 0.0, (1 << 20) + 1),
            (-1, True, 256, 1 << 80), (0, 1, 2, True, 3.0, 2147483648)]
        for field, values in enumerate(invalids):
            for value in values:
                row = list(base)
                row[field] = value
                outcomes = []
                for call in (original, observer.frame):
                    try:
                        call(*row)
                    except BaseException as exc:
                        outcomes.append((type(exc), str(exc)))
                    else:
                        self.fail('invalid private field accepted')
                self.assertEqual(outcomes[0], outcomes[1])


class LinkedObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
        destination = os.environ.get('HIA_LINKED_OBSERVER_EVIDENCE_DIR')
        cls.temporary = None
        if destination:
            cls.root = Path(destination)
            cls.root.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-linked-observer-')
            cls.root = Path(cls.temporary.name)
        # This execution really precedes this setup's seed creation.
        cls.reference = observer.independent_reference(before_B0=True)
        (cls.root / 'independent-reference.json').write_text(json.dumps(cls.reference, indent=2, sort_keys=True) + '\n')
        seed, cls.seed_receipt = build_seed(cls.root)
        cls.compiler, cls.compiler_receipt = compile_stage(cls.root, 'B1', seed,
            SOURCE.read_bytes(), image_format='seed-shared')
        cls.executable, cls.build = observer.build(cls.root, cls.compiler, cls.reference)
        cls.commands = []

    @classmethod
    def tearDownClass(cls):
        (cls.root / 'foreign-build-commands.json').write_text(json.dumps(cls.commands, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def linked(self, name, body, *, extra='', now=True, defs=True):
        if isinstance(body, bytes):
            body = ' .byte ' + ','.join(str(byte) for byte in body) + '\n'
        assembly = ('.intel_syntax noprefix\n.text\n.global f0\n.type f0,@function\nf0:\n'
            + body + '\n' + extra + '\n.section .note.GNU-stack,"",@progbits\n')
        source, obj, image = (self.root / (name + suffix) for suffix in ('.S', '.o', '.so'))
        source.write_text(assembly)
        commands = [['as', '--64', '-o', str(obj), str(source)],
            ['ld', '-shared', '-z', 'noexecstack', '-z', 'relro', '--build-id=none',
                *(['-z', 'now'] if now else []), *(['-z', 'defs'] if defs else []),
                '-o', str(image), str(obj)]]
        for ordinal, command in enumerate(commands):
            process = subprocess.run(command, capture_output=True, timeout=20)
            (self.root / (name + '.build-' + str(ordinal) + '.stdout')).write_bytes(process.stdout)
            (self.root / (name + '.build-' + str(ordinal) + '.stderr')).write_bytes(process.stderr)
            self.commands.append({'command': command, 'returncode': process.returncode,
                'source_sha256': sha256(source.read_bytes()).hexdigest()})
            process.check_returncode()
        return image

    def paired(self, name, image, source=b'', *, capacity=32, workspace=1032, fill=90,
               initial=None, capture=False):
        from tools.qualify_hia_selfhost import invoke
        actual, output = observer.invoke(self.root, name + '-new', self.executable, image, source,
            capacity=capacity, workspace_size=workspace, workspace_fill=fill,
            output_initial=initial, observe_trap_writes=capture)
        legacy, raw = invoke(self.root, name + '-legacy', image, source, image_format='linked-selfhost',
            capacity=capacity, workspace_size=workspace, workspace_fill=fill,
            output_initial=initial, observe_trap_writes=capture)
        self.assertEqual(actual['status'], legacy['status'], name)
        self.assertEqual(output, raw, name)
        if actual['status'] == 'returned':
            for key in ('result_u64', 'abi_status', 'core_u32', 'return_encoding', 'source_sha256',
                        'image_sha256', 'output_sha256', 'source_unchanged', 'output_unchanged',
                        'workspace_header', 'limits', 'forbidden_compiler_modules_loaded'):
                self.assertEqual(actual[key], legacy[key], (name, key))
        elif actual['status'] == 'child_failed' and actual['returncode'] < 0:
            self.assertEqual(actual['returncode'], legacy['returncode'])
        if capture:
            for key in ('available', 'initial_sha256', 'observed_sha256', 'observed_bytes', 'unchanged'):
                self.assertEqual(actual['shared_output_observation'][key], legacy['shared_output_observation'][key])
        self.assertTrue(actual['fresh_native_exec'])
        self.assertFalse(actual['successor_process_reuse'])
        return actual, output

    def test_every_executable_byte_from_actual_HIA_matches_independent_pre_B0_VM(self):
        from tools.generate_hia_linked_observer import reference_image
        self.assertEqual(self.executable.read_bytes(), reference_image())
        self.assertTrue(self.reference['before_B0'])
        self.assertTrue(self.reference['every_output_byte_compared'])
        self.assertFalse(self.build['whole_stack_rewritten_in_hia'])
        self.assertEqual(self.build['compiler_sha256'], sha256(self.compiler.read_bytes()).hexdigest())

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
            self.assertFalse((directory / 'linked-observer.elf').exists())
            self.assertFalse((directory / 'linked-observer-build.json').exists())
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
                observer.independent_reference(before_B0=False)
        self.assertEqual(len(wrappers), len(self.reference['vm_windows']))
        (directory / 'result.json').write_text(json.dumps({'actual_VM_windows': len(wrappers),
            'wrappers_sha256': wrappers, 'one_original_source_snapshot': True,
            'final_source_change_refused': True}, indent=2, sort_keys=True) + '\n')

    def test_complete_foreign_return_and_workspace_edges_equal_legacy(self):
        image = self.linked('full-return', bytes.fromhex('48 b8 2a 00 00 00 ef be ad de c3'))
        for ordinal, size in enumerate((0, 1, 7, 8, 15, 16, 23, 24, 39, 40, 47, 48, 63,
                64, 71, 72, 87, 88, 103, 104, 111, 112, 119, 120, 223, 224, 231,
                232, 247, 248, 255, 256, 1023, 1024, 1031, 1032)):
            value, _ = self.paired('edges-' + str(ordinal), image, b'A\0\xff' * 37,
                capacity=ordinal % 4, workspace=size, fill=(ordinal * 97) & 255)
            self.assertEqual(value['result_u64'], 0xdeadbeef0000002a)

    def test_source_output_workspace_mutations_are_real(self):
        image = self.linked('mutations', '''
 mov byte ptr [rdi], 97
 mov byte ptr [rdx], 98
 xor eax, eax
loop_w:
 cmp rax, r9
 jae finish_w
 mov byte ptr [r8+rax], al
 inc rax
 jmp loop_w
finish_w:
 mov eax, 37
 ret''')
        result, raw = self.paired('mutations', image, b'XYZ', capacity=19, workspace=1040)
        self.assertFalse(result['source_unchanged'])
        self.assertFalse(result['output_unchanged'])
        self.assertEqual(raw, b'b' + b'\xa5' * 18)
        self.assertEqual((self.root / 'mutations-new.modified-source.bin').read_bytes(), b'aYZ')
        for offset, value in result['workspace_header'].items():
            at = int(offset)
            self.assertEqual(value, int.from_bytes(bytes((i & 255) for i in range(at, at + 8)), 'little'))

    def test_real_UD2_preserves_actual_shared_writes_and_preimages(self):
        images = [self.linked('capture-' + str(i), code) for i, code in enumerate((
            bytes.fromhex('31 c0 c3'), bytes.fromhex('c6 02 63 31 c0 c3'), bytes.fromhex('c6 02 63 0f 0b')))]
        for ordinal, image in enumerate(images):
            for initial in (b'\0', b'Z\0\xff', b'\xff' * 31):
                result, _ = self.paired('capture-' + str(ordinal) + '-' + str(len(initial)), image,
                    b'input', capacity=len(initial), workspace=128, fill=255, initial=initial, capture=True)
                if ordinal == 2:
                    self.assertEqual(result['returncode'], -4)

    def test_system_dynamic_loader_executes_constructor_and_relocations(self):
        # f0 is intentionally after a trap and a constructor in .text. Both a
        # relative init-array relocation and external getpid relocation execute.
        source = self.root / 'actual-dynamic.S'
        source.write_text('''.intel_syntax noprefix
.text
 ud2
.local init
init:
 mov qword ptr [rip+counter], 69
 ret
.global f0
.type f0,@function
f0:
 push r12
 mov r12, rdx
 call getpid@PLT
 mov [r12], rax
 mov rax, [rip+counter]
 pop r12
 ret
.section .init_array,"aw",@init_array
 .quad init
.bss
.local counter
counter: .zero 8
.section .note.GNU-stack,"",@progbits
''')
        image = self.root / 'actual-dynamic.so'
        for command in (['as', '--64', '-o', str(self.root / 'actual-dynamic.o'), str(source)],
            ['ld', '-shared', '-z', 'defs', '-z', 'now', '-z', 'relro', '-z', 'noexecstack',
                '--build-id=none', '-o', str(image), str(self.root / 'actual-dynamic.o'), '-lc']):
            process = subprocess.run(command, capture_output=True)
            self.commands.append({'command': command, 'returncode': process.returncode,
                'stdout': process.stdout.decode(), 'stderr': process.stderr.decode()})
            process.check_returncode()
        result, raw = observer.invoke(self.root, 'actual-dynamic', self.executable, image, b'',
            capacity=8, workspace_size=0, workspace_fill=0)
        self.assertEqual(result['core_u32'], 69)
        self.assertGreater(struct.unpack('<Q', raw)[0], 0)
        self.assertNotEqual(struct.unpack('<Q', raw)[0], os.getpid())

    def test_RTLD_NOW_rejects_unused_unresolved_lazy_symbol_and_missing_f0(self):
        image = self.linked('unresolved-lazy', ' mov eax,42\n ret',
            extra='unused:\n jmp hia_symbol_that_does_not_exist@PLT', now=False, defs=False)
        result, raw = self.paired('unresolved-lazy', image, capacity=0, workspace=0)
        self.assertEqual((result['status'], result['returncode'], raw), ('child_failed', 5, b''))
        # Change the dynamic symbol name, preserving the otherwise valid ELF.
        good = self.linked('missing-entry-source', ' mov eax,42\n ret')
        changed = good.read_bytes().replace(b'\0f0\0', b'\0g0\0')
        self.assertNotEqual(changed, good.read_bytes())
        missing = self.root / 'missing-entry.so'
        missing.write_bytes(changed)
        result, raw = self.paired('missing-entry', missing, capacity=0, workspace=0)
        self.assertEqual((result['status'], result['returncode'], raw), ('child_failed', 5, b''))

    def test_all_kernel_limits_and_dumpable_are_actually_observed(self):
        body = [' push r12', ' mov r12,rdx']
        expected = []
        for ordinal, (resource, limit) in enumerate(((4, 0), (0, 10), (9, 256 << 20),
                (3, 8 << 20), (1, 16 << 20), (7, 32))):
            body += [' xor edi,edi', ' mov esi,' + str(resource), ' xor edx,edx',
                ' lea r10,[r12+' + str(ordinal * 16) + ']', ' mov eax,302', ' syscall',
                ' test rax,rax', ' jne probe_done']
            expected.extend((limit, limit))
        body += [' mov edi,3', ' mov eax,157', ' syscall', 'probe_done:', ' pop r12', ' ret']
        image = self.linked('limits', '\n'.join(body))
        result, raw = self.paired('limits', image, capacity=96, workspace=0)
        self.assertEqual(result['core_u32'], 0)
        self.assertEqual(struct.unpack('<12Q', raw), tuple(expected))

    def test_fresh_process_has_new_PID_and_fresh_dynamic_state(self):
        image = self.linked('fresh-process', '''
 inc qword ptr [rip+state]
 mov r10,[rip+state]
 mov [rdx],r10
 mov eax,39
 syscall
 ret''', extra='.bss\n.local state\nstate: .zero 8')
        pids = []
        for ordinal in range(6):
            result, raw = observer.invoke(self.root, 'fresh-process-' + str(ordinal), self.executable,
                image, b'', capacity=8, workspace_size=0, workspace_fill=0)
            pids.append(result['result_u64'])
            self.assertEqual(struct.unpack('<Q', raw)[0], 1)
        self.assertEqual(len(set(pids)), 6)
        self.assertNotIn(os.getpid(), pids)

    def test_image_is_fully_sealed_before_actual_dynamic_constructor(self):
        # The constructor runs inside dlopen, while its supplied-image fd is
        # still open. Observe all four actual Linux seals, not receipt text.
        image = self.linked('constructor-seals', ' mov rax,[rip+sealed_count]\n ret', extra='''
.local observe_seals
observe_seals:
 push rbx
 mov ebx,3
seal_loop:
 mov edi,ebx
 mov esi,1034
 xor edx,edx
 mov eax,72
 syscall
 cmp rax,15
 jne next_fd
 inc qword ptr [rip+sealed_count]
next_fd:
 inc ebx
 cmp ebx,32
 jb seal_loop
 pop rbx
 ret
.section .init_array,"aw",@init_array
 .quad observe_seals
.bss
.local sealed_count
sealed_count: .zero 8''')
        from tools.qualify_hia_selfhost import invoke
        actual, _ = observer.invoke(self.root, 'constructor-seals-new', self.executable,
            image, b'', capacity=0, workspace_size=0, workspace_fill=0)
        legacy, _ = invoke(self.root, 'constructor-seals-legacy', image, b'', image_format='linked-selfhost',
            capacity=0, workspace_size=0, workspace_fill=0)
        self.assertEqual(actual['core_u32'], 2)  # executable and supplied shared object
        self.assertEqual(legacy['core_u32'], 1)  # supplied shared object only

    def test_loaded_observer_pages_keep_RX_RELRO_and_nonexecutable_stack(self):
        image = self.linked('observed-maps', '''
 push r12
 push r13
 push rbx
 mov r12,rdx
 mov r13,rcx
 mov rdi,-100
 lea rsi,[rip+maps_path]
 xor edx,edx
 xor r10d,r10d
 mov eax,257
 syscall
 test rax,rax
 js maps_done
 mov rbx,rax
 mov rdi,rax
 mov rsi,r12
 mov rdx,r13
 xor eax,eax
 syscall
 mov r12,rax
 mov rdi,rbx
 mov eax,3
 syscall
 mov rax,r12
maps_done:
 pop rbx
 pop r13
 pop r12
 ret''', extra='.section .rodata\nmaps_path: .asciz "/proc/self/maps"')
        result, raw = observer.invoke(self.root, 'observed-maps', self.executable, image, b'',
            capacity=16384, workspace_size=0, workspace_fill=0)
        self.assertLess(result['core_u32'], len(raw))
        maps = raw[:result['core_u32']].decode('ascii')
        (self.root / 'actual-kernel-maps.txt').write_text(maps)
        entries = []
        for line in maps.splitlines():
            fields = line.split()
            low, high = (int(n, 16) for n in fields[0].split('-'))
            entries.append((low, high, fields[1], fields[-1]))
        def permissions(address):
            return [row[2] for row in entries if row[0] <= address < row[1]]
        self.assertEqual(permissions(0x400200), ['r-xp'])
        self.assertEqual(permissions(0x401800), ['r--p'])
        self.assertEqual([row[2] for row in entries if row[3] == '[stack]'], ['rw-p'])
        self.assertFalse(any('w' in row[2] and 'x' in row[2] for row in entries))

    def test_actual_HIA_object_compiler_self_rebuild_matches_flat_and_legacy(self):
        from tools.qualify_hia_selfhost import SOURCE, SAMPLE, compile_stage, inspect_selfhost_object, observe_native_tool
        for subject, raw_source in (('compiler', SOURCE.read_bytes()), ('sample', SAMPLE.read_bytes())):
            elf_source = raw_source.replace(b'hepta.hia.program.v8 selfhost\n',
                b'hepta.hia.program.v8 selfhost_elf\n', 1)
            self.assertNotEqual(raw_source, elf_source)
            obj, receipt = compile_stage(self.root, 'native-object-' + subject, self.compiler,
                elf_source, output_extension='.o')
            inventory = inspect_selfhost_object(obj.read_bytes())
            if subject == 'compiler':
                self.assertEqual(inventory['text_sha256'], sha256(self.compiler.read_bytes()).hexdigest())
            image = self.root / ('native-object-' + subject + '.so')
            observe_native_tool(self.root, 'native-object-' + subject + '-link', 'ld',
                ['-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack', '-z', 'relro',
                    '-z', 'now', '--build-id=none', obj, '-o', image])
            samples = (raw_source, b'invalid') if subject == 'compiler' else (b'', bytes(range(256)) * 4)
            for ordinal, source in enumerate(samples):
                result, output = self.paired('native-object-' + subject + '-' + str(ordinal),
                    image, source, capacity=1 << 20, workspace=1 << 20)
                if subject == 'compiler' and ordinal == 0:
                    self.assertEqual(output[:result['core_u32']], self.compiler.read_bytes())

    def test_bad_frame_and_argument_refusals_precede_loading(self):
        image = self.executable.read_bytes()
        good = observer.frame(b'\xc3', b'', 0, 0, 0)
        bad = [b'', good[:47], b'badMAGIC' + good[8:], good + b'\0', good[:-1]]
        for index in range(5):
            altered = bytearray(good)
            struct.pack_into('<Q', altered, 8 + index * 8, 2**64 - 1)
            bad.append(bytes(altered))
        for value in (0, 1, 2, 2147483648, 2**64 - 2):
            altered = bytearray(good)
            struct.pack_into('<Q', altered, 48, value)
            bad.append(bytes(altered))
        outcomes = []
        for data in bad:
            result = observer.execute(image, data, cwd=self.root)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))
            outcomes.append({'request_hex': data.hex(), 'returncode': result.returncode})
        result = observer.execute(image, good, cwd=self.root, arguments=('unexpected',))
        self.assertEqual((result.returncode, result.stdout), (64, b''))
        (self.root / 'bad-frame-outcomes.json').write_text(json.dumps(outcomes, indent=2) + '\n')

    def test_unexpected_stdout_is_refused_and_original_bytes_retained(self):
        image = self.linked('stdout-injection', bytes.fromhex(
            '48 89 f2 48 89 fe bf 01 00 00 00 b8 01 00 00 00 0f 05 b8 2a 00 00 00 c3'))
        result, raw = observer.invoke(self.root, 'stdout-injection', self.executable, image,
            b'injected-prefix', capacity=0, workspace_size=0, workspace_fill=0)
        self.assertEqual((result['status'], raw), ('protocol_failed', b''))
        actual = (self.root / 'stdout-injection.failure-stdout.raw').read_bytes()
        self.assertTrue(actual.startswith(b'injected-prefixHIALDR01'))
        self.assertEqual(result['response_sha256'], sha256(actual).hexdigest())

    def test_changed_actual_source_image_or_observer_is_refused_after_execution(self):
        original = self.executable.read_bytes()
        real_execute = observer.execute
        for target in ('source', 'image', 'observer'):
            directory = self.root / ('changed-' + target)
            directory.mkdir()
            executable = directory / 'observer.elf'
            executable.write_bytes(original)
            image = self.linked('changed-' + target, ' mov eax,42\n ret')
            calls = []
            def changed(*args, **kwargs):
                process = real_execute(*args, **kwargs)
                calls.append(process.returncode)
                changed_path = {'source': directory / 'case.input.bin', 'image': image,
                    'observer': executable}[target]
                changed_path.write_bytes(changed_path.read_bytes() + b'x')
                return process
            with patch.object(observer, 'execute', changed):
                with self.assertRaisesRegex(AssertionError, 'immutable inputs changed'):
                    observer.invoke(directory, 'case', executable, image, b'XYZ',
                        capacity=1, workspace_size=0, workspace_fill=0)
            self.assertEqual(calls, [0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
