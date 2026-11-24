"""Exercise the HIA owner through real sealed descriptors and Linux child processes."""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
import errno
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import tempfile
import time
import unittest


SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
FIELDS = ('magic', 'exit_code', 'stop_reason', 'wait_status', 'child_pid', 'stdout_seen',
          'stdout_stored', 'stderr_seen', 'stderr_stored', 'stdout_errno', 'stderr_errno',
          'exec_errno', 'output_complete', 'output_durable', 'elapsed_ns', 'child_reaped')

# An explicit static workload avoids host coreutils dispatchers that reject a
# sealed memfd executable because /proc/self/exe is no longer their installed path.
FIXTURE = r'''
.intel_syntax noprefix
.global _start
.text
_start:
    mov r12,rsp
    cmp QWORD PTR [r12],2
    jb bad
    mov rax,[r12+16]
    mov al,[rax]
    cmp al,'c'
    je cat
    cmp al,'s'
    je streams
    cmp al,'e'
    je environment
    cmp al,'p'
    je directory
    cmp al,'a'
    je arguments
    cmp al,'w'
    je waiting
    cmp al,'i'
    je ignore
    cmp al,'z'
    je zeros
    cmp al,'o'
    je output
    cmp al,'r'
    je ready
    cmp al,'d'
    je passed_directory
    cmp al,'f'
    je descriptor_list
bad:
    mov edi,90
    jmp finish
cat:
    xor eax,eax
    xor edi,edi
    lea rsi,[rip+buffer]
    mov edx,8192
    syscall
    test rax,rax
    js bad
    jz success
    mov rdx,rax
    mov edi,1
    call write_all
    jmp cat
streams:
    mov edi,1
    lea rsi,[rip+out]
    mov edx,3
    call write_all
    mov edi,2
    lea rsi,[rip+err]
    mov edx,3
    call write_all
    mov edi,17
    jmp finish
environment:
    mov rax,[r12]
    lea r13,[r12+rax*8+16]
env_next:
    mov rsi,[r13]
    test rsi,rsi
    jz success
    mov edi,1
    call string
    lea rsi,[rip+newline]
    mov edx,1
    call write_all
    add r13,8
    jmp env_next
directory:
    mov eax,79
    lea rdi,[rip+buffer]
    mov esi,8192
    syscall
    test rax,rax
    jle bad
    lea rsi,[rip+buffer]
    lea rdx,[rax-1]
    mov edi,1
    call write_all
    lea rsi,[rip+newline]
    mov edx,1
    call write_all
    jmp success
passed_directory:
    cmp QWORD PTR [r12],3
    jne bad
    mov rsi,[r12+24]
    call number
    mov rdi,rax
    mov eax,81
    syscall
    test rax,rax
    jnz bad
    jmp directory
descriptor_list:
    cmp QWORD PTR [r12],4
    jne bad
    mov rsi,[r12+24]
    call number
    mov rdi,rax
    mov eax,72
    mov esi,1
    syscall
    test rax,rax
    jnz bad
    mov rsi,[r12+32]
    call number
    mov rdi,rax
    mov eax,72
    mov esi,1
    syscall
    cmp rax,-9
    jne bad
    mov edi,1
    lea rsi,[rip+bounded]
    mov edx,7
    call write_all
    jmp success
arguments:
    cmp QWORD PTR [r12],4
    jne bad
    mov edi,1
    mov rsi,[r12+24]
    call string
    lea rsi,[rip+separator]
    mov edx,1
    call write_all
    mov rsi,[r12+32]
    call string
    jmp success
ignore:
    mov eax,13
    mov edi,15
    lea rsi,[rip+ignored]
    xor edx,edx
    mov r10d,8
    syscall
    jmp waiting
ready:
    mov edi,1
    lea rsi,[rip+started]
    mov edx,5
    call write_all
waiting:
    mov eax,34
    syscall
    jmp waiting
zeros:
    mov r13d,200000
zero_next:
    mov edx,8192
    cmp r13,rdx
    cmovb rdx,r13
    sub r13,rdx
    lea rsi,[rip+buffer]
    mov edi,1
    call write_all
    test r13,r13
    jnz zero_next
    jmp success
output:
    mov edi,1
    lea rsi,[rip+cannot]
    mov edx,12
    call write_all
success:
    xor edi,edi
finish:
    mov eax,60
    syscall
    ud2
string:
    xor edx,edx
string_next:
    cmp BYTE PTR [rsi+rdx],0
    je write_all
    inc rdx
    jmp string_next
write_all:
    test rdx,rdx
    jz wrote
    mov eax,1
    syscall
    cmp rax,-4
    je write_all
    test rax,rax
    jle bad
    add rsi,rax
    sub rdx,rax
    jmp write_all
wrote:
    ret
number:
    xor eax,eax
number_next:
    movzx edx,BYTE PTR [rsi]
    test dl,dl
    jz number_done
    sub edx,'0'
    cmp edx,9
    ja bad
    imul rax,rax,10
    add rax,rdx
    inc rsi
    jmp number_next
number_done:
    ret
.section .rodata
out: .ascii "out"
err: .ascii "err"
newline: .ascii "\n"
separator: .ascii "|"
cannot: .ascii "cannot-grow\n"
started: .ascii "ready"
bounded: .ascii "bounded"
.balign 8
ignored: .quad 1,0,0,0
.bss
.balign 16
buffer: .skip 8192
'''


def memfd(stack, name, data=b'', *, sealed=False, mode=0o600):
    fd = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    stack.callback(os.close, fd)
    os.fchmod(fd, mode)
    if data:
        if os.write(fd, data) != len(data):
            raise OSError('short test fixture write')
    if sealed:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
    return fd


def request(*, parent, deadline, executable, source, output, errors, directory, receipt,
            argv, env, output_limit, error_limit, grace_ns, memory_limit=0, lock=0, pass_fds=()):
    header = struct.pack('<8s15Q', b'HIASUB01', parent, deadline, executable, source, output,
                         errors, directory, receipt, len(argv), len(env), output_limit,
                         error_limit, grace_ns, memory_limit, lock)
    trailer = b''
    if pass_fds:
        trailer = struct.pack('<8sQ', b'HIAPFD01', len(pass_fds)) + b''.join(struct.pack('<Q', fd) for fd in pass_fds)
    return header + b''.join(struct.pack('<Q', len(value)) + value + b'\0' for value in (*argv, *env)) + trailer


@unittest.skipUnless(os.environ.get('HIA_TEST_SUBPROCESS_EXE'), 'requires the installed HIA subprocess owner')
class NativeSubprocessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory(prefix='hia-subprocess-fixtures-')
        cls.addClassCleanup(cls.fixtures.cleanup)
        folder = Path(cls.fixtures.name)
        assembly, object_file, executable = folder/'payload.S', folder/'payload.o', folder/'payload'
        assembly.write_text(FIXTURE)
        subprocess.run(['/usr/bin/as', '--64', str(assembly), '-o', str(object_file)], check=True, capture_output=True)
        subprocess.run(['/usr/bin/ld', '-nostdlib', str(object_file), '-o', str(executable)], check=True, capture_output=True)
        cls.fixture = executable.read_bytes()

    def run_owned(self, mode='c', args=(), *, data=b'', env=(), deadline=.7,
                  cancel_after=None, stdout_limit=1 << 20, stderr_limit=1 << 20,
                  mutate=None, executable_bytes=None, trace=None, timeout=5):
        executable = Path(os.environ['HIA_TEST_SUBPROCESS_EXE']).resolve(strict=True)
        with ExitStack() as stack:
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-owned-run-')))
            directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, directory)
            binary = self.fixture if executable_bytes is None else executable_bytes
            exe = memfd(stack, 'fixture-executable', binary, sealed=True, mode=0o700)
            source = memfd(stack, 'fixture-input', data, sealed=True)
            output = memfd(stack, 'fixture-output')
            errors = memfd(stack, 'fixture-errors')
            receipt = memfd(stack, 'fixture-receipt')
            values = dict(parent=os.getpid(), deadline=time.monotonic_ns() + int(deadline * 1e9),
                          executable=exe, source=source, output=output, errors=errors, directory=directory,
                          receipt=receipt, argv=(b'hia-subprocess-fixture', os.fsencode(mode), *(os.fsencode(x) for x in args)),
                          env=tuple(os.fsencode(x) for x in env), output_limit=stdout_limit,
                          error_limit=stderr_limit, grace_ns=100_000_000)
            if mutate:
                mutate(values, stack)
            ambient_fds = values.pop('_ambient_fds', ())
            payload = request(**values)
            frame = memfd(stack, 'fixture-request', payload, sealed=True)
            fds = (exe, source, output, errors, directory, receipt, values.get('lock', 0),
                   *values.get('pass_fds', ()), *ambient_fds)
            argv = [str(executable)]
            if trace:
                argv = ['/usr/bin/strace', '-D', '-f', '-qq', '-e', 'trace=execve,execveat,fork,clone,wait4,kill,fsync', '-o', str(trace), *argv]
            with subprocess.Popen(argv, stdin=frame, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  pass_fds=tuple(fd for fd in fds if fd), env={'PATH': ''}) as process:
                if cancel_after is not None:
                    time.sleep(cancel_after)
                    process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=timeout)
                returned = process.returncode
            raw = os.pread(receipt, 129, 0)
            record = None
            if raw:
                self.assertEqual(len(raw), 128)
                parsed = struct.unpack('<8sq14Q', raw)
                record = dict(zip(FIELDS, parsed, strict=True))
                self.assertEqual(record['magic'], b'HIASBR01')
            return dict(rc=returned, stdout=os.pread(output, stdout_limit + 1, 0),
                        stderr=os.pread(errors, stderr_limit + 1, 0), wire_stdout=out, wire_stderr=err,
                        receipt=record, cwd=str(folder), payload=payload)

    def assert_reaped(self, result):
        row = result['receipt']
        summary = {'rc': result['rc'], 'receipt': row, 'stdout_bytes': len(result['stdout']),
                   'stderr_bytes': len(result['stderr']), 'wire_stderr': result['wire_stderr'][:512]}
        self.assertEqual(result['rc'], 0, summary)
        self.assertEqual((result['wire_stdout'], result['wire_stderr']), (b'', b''))
        self.assertEqual(row['child_reaped'], 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(row['child_pid'], 0)

    def test_binary_stdin_and_separate_streams_keep_every_byte(self):
        data = bytes(range(256)) * 511
        result = self.run_owned(data=data)
        self.assert_reaped(result)
        self.assertEqual((result['stdout'], result['stderr']), (data, b''))
        self.assertEqual(result['receipt']['stdout_seen'], len(data))
        self.assertEqual(result['receipt']['stdout_stored'], len(data))
        self.assertEqual(result['receipt']['output_complete'], 1)
        self.assertEqual(result['receipt']['output_durable'], 1)
        other = self.run_owned('s')
        self.assert_reaped(other)
        self.assertEqual((other['stdout'], other['stderr']), (b'out', b'err'))
        self.assertEqual(other['receipt']['exit_code'], 17)

    def test_arguments_environment_and_directory_are_explicit(self):
        result = self.run_owned('e', env=('PATH=', 'HEPTA_CASE=a b=c'))
        self.assert_reaped(result)
        self.assertEqual(result['stdout'], b'PATH=\nHEPTA_CASE=a b=c\n')
        directory = self.run_owned('p')
        self.assert_reaped(directory)
        self.assertEqual(directory['stdout'], os.fsencode(directory['cwd']) + b'\n')
        args = self.run_owned('a', ('', 'a b'))
        self.assert_reaped(args)
        self.assertEqual(args['stdout'], b'|a b')

    def test_deadline_stops_and_reaps_the_original_child(self):
        result = self.run_owned('w', deadline=.2)
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['stop_reason'], 1)
        self.assertEqual(result['receipt']['exit_code'], -signal.SIGTERM)
        self.assertLess(result['receipt']['elapsed_ns'], 2_000_000_000)

    def test_cancellation_is_a_real_terminal_outcome(self):
        result = self.run_owned('w', deadline=3, cancel_after=.12)
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['stop_reason'], 2)
        self.assertEqual(result['receipt']['exit_code'], -signal.SIGTERM)

    def test_ignored_term_reaches_bounded_kill(self):
        result = self.run_owned('i', deadline=.15)
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['stop_reason'], 1)
        self.assertEqual(result['receipt']['exit_code'], -signal.SIGKILL)
        self.assertLess(result['receipt']['elapsed_ns'], 2_000_000_000)

    def test_capture_cap_retains_seen_and_stored_counts(self):
        result = self.run_owned('z', stdout_limit=4096)
        self.assert_reaped(result)
        self.assertEqual(result['stdout'], bytes(4096))
        self.assertEqual(result['receipt']['stdout_seen'], 200000)
        self.assertEqual(result['receipt']['stdout_stored'], 4096)
        self.assertEqual(result['receipt']['output_complete'], 0)
        self.assertEqual(result['receipt']['output_durable'], 1)

    def test_release_sized_input_and_output_exceed_the_executable_limit(self):
        data = bytes(range(256)) * (262144 + 1)
        result = self.run_owned(data=data, stdout_limit=len(data), deadline=15, timeout=20)
        self.assert_reaped(result)
        self.assertEqual(len(result['stdout']), len(data))
        self.assertEqual(sha256(result['stdout']).digest(), sha256(data).digest())
        self.assertEqual(result['receipt']['output_complete'], 1)
        self.assertEqual(result['receipt']['stdout_seen'], len(data))

    def test_exec_error_is_preserved_without_successful_payload(self):
        result = self.run_owned(executable_bytes=b'not an executable')
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['exit_code'], 127)
        self.assertEqual(result['receipt']['exec_errno'], errno.ENOEXEC)
        self.assertEqual((result['stdout'], result['stderr']), (b'', b''))

    def test_identity_descriptor_and_environment_refusals_do_not_run(self):
        mutations = (
            lambda v, st: v.update(parent=os.getppid()),
            lambda v, st: v.update(errors=v['output']),
            lambda v, st: v.update(argv=(b'',)),
            lambda v, st: v.update(env=(b'NAME=one', b'NAME=two')),
            lambda v, st: v.update(env=(b'0NAME=value',)),
            lambda v, st: v.update(env=(b'NAME',)),
            lambda v, st: os.write(v['output'], b'existing'),
            lambda v, st: os.fchmod(v['errors'], 0o644),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = self.run_owned('o', mutate=mutation)
                self.assertEqual(result['rc'], 65, result)
                self.assertIsNone(result['receipt'])
                self.assertNotIn(b'executed', result['stdout'])

    def test_capture_failure_stops_and_keeps_error_evidence(self):
        def seal_output(values, stack):
            fcntl.fcntl(values['output'], fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW)
        result = self.run_owned('o', mutate=seal_output)
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['stdout_errno'], errno.EPERM)
        self.assertEqual(result['receipt']['output_complete'], 0)
        self.assertEqual(result['receipt']['stop_reason'], 4)

    def test_expired_request_has_no_child(self):
        result = self.run_owned(deadline=-1)
        self.assertEqual(result['rc'], 0)
        self.assertEqual(result['receipt']['child_pid'], 0)
        self.assertEqual(result['receipt']['child_reaped'], 0)
        self.assertEqual(result['receipt']['exit_code'], -256)
        self.assertEqual(result['receipt']['stop_reason'], 1)

    def test_owner_lock_uses_the_supplied_open_description(self):
        def inherited_lock(values, stack):
            file = stack.enter_context(tempfile.NamedTemporaryFile())
            os.fchmod(file.fileno(), 0o600)
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            values['lock'] = file.fileno()
        inherited = self.run_owned('s', mutate=inherited_lock)
        self.assert_reaped(inherited)
        self.assertEqual(inherited['receipt']['exit_code'], 17)

        def another_description(values, stack):
            file = stack.enter_context(tempfile.NamedTemporaryFile())
            os.fchmod(file.fileno(), 0o600)
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            other = os.open(file.name, os.O_RDWR | os.O_CLOEXEC)
            stack.callback(os.close, other)
            values['lock'] = other
        refused = self.run_owned('s', mutate=another_description)
        self.assertEqual(refused['rc'], 65)
        self.assertIsNone(refused['receipt'])

    def test_explicit_directory_descriptor_survives_execution(self):
        selected = {}
        def pass_directory(values, stack):
            selected['path'] = stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-passed-directory-'))
            fd = os.open(selected['path'], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            values.update(pass_fds=(fd,), argv=(b'fixture', b'd', str(fd).encode()))
        result = self.run_owned(mutate=pass_directory)
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['exit_code'], 0)
        self.assertEqual(result['stdout'], os.fsencode(selected['path'])+b'\n')

        def pass_cwd(values, stack):
            fd = values['directory']
            values.update(pass_fds=(fd,), argv=(b'fixture', b'd', str(fd).encode()))
        result = self.run_owned(mutate=pass_cwd)
        self.assert_reaped(result)
        self.assertEqual(result['stdout'], os.fsencode(result['cwd'])+b'\n')

    def test_only_the_authorized_descriptor_list_survives_execution(self):
        def pass_one(values, stack):
            wanted = memfd(stack, 'explicit-pass', b'resource', sealed=True)
            omitted = memfd(stack, 'ambient-closed', b'must-not-inherit', sealed=True)
            values.update(pass_fds=(wanted,), _ambient_fds=(omitted,),
                          argv=(b'fixture', b'f', str(wanted).encode(), str(omitted).encode()))
        result = self.run_owned(mutate=pass_one)
        self.assert_reaped(result)
        self.assertEqual(result['receipt']['exit_code'], 0)
        self.assertEqual(result['stdout'], b'bounded')

    def test_conflicting_or_repeated_pass_descriptors_do_not_spawn(self):
        def repeated(values, stack):
            fd = memfd(stack, 'duplicate-pass', sealed=True)
            values['pass_fds'] = (fd, fd)
        def receipt_alias(values, stack):
            fd = os.dup(values['receipt'])
            stack.callback(os.close, fd)
            values['pass_fds'] = (fd,)
        def pipe_descriptor(values, stack):
            left, right = os.pipe()
            stack.callback(os.close, left)
            stack.callback(os.close, right)
            values['pass_fds'] = (left,)
        for mutation in (lambda v, s: v.update(pass_fds=(v['receipt'],)), repeated, receipt_alias, pipe_descriptor):
            with self.subTest(mutation=mutation):
                result = self.run_owned('s', mutate=mutation)
                self.assertEqual(result['rc'], 65)
                self.assertIsNone(result['receipt'])

    def test_parent_death_cancels_and_reaps_with_a_durable_receipt(self):
        # Adopt only this test's descendants so their real exit status can be
        # observed after the middle parent dies; restore the process setting.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        owner = middle = 0
        with ExitStack() as stack:
            stack.callback(libc.prctl, 36, previous.value, 0, 0, 0)
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-parent-death-')))
            directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, directory)
            exe = memfd(stack, 'parent-death-payload', self.fixture, sealed=True, mode=0o700)
            source = memfd(stack, 'parent-death-input', sealed=True)
            output = memfd(stack, 'parent-death-output')
            errors = memfd(stack, 'parent-death-errors')
            receipt = memfd(stack, 'parent-death-receipt')
            read_pid, write_pid = os.pipe()
            stack.callback(os.close, read_pid)
            stack.callback(os.close, write_pid)
            middle = os.fork()
            if middle == 0:
                try:
                    payload = request(parent=os.getpid(), deadline=time.monotonic_ns()+5_000_000_000,
                                      executable=exe, source=source, output=output, errors=errors,
                                      directory=directory, receipt=receipt, argv=(b'fixture', b'r'), env=(),
                                      output_limit=4096, error_limit=4096, grace_ns=100_000_000)
                    frame = memfd(stack, 'parent-death-request', payload, sealed=True)
                    process = subprocess.Popen([os.environ['HIA_TEST_SUBPROCESS_EXE']], stdin=frame,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                               pass_fds=(exe, source, output, errors, directory, receipt), env={'PATH': ''})
                    os.write(write_pid, struct.pack('<Q', process.pid))
                    while True:
                        signal.pause()
                except BaseException:
                    os._exit(99)
            try:
                self.assertTrue(select.select((read_pid,), (), (), 3)[0], 'owner parent did not report its child')
                owner = struct.unpack('<Q', os.read(read_pid, 8))[0]
                until = time.monotonic()+3
                while os.pread(output, 5, 0) != b'ready' and time.monotonic() < until:
                    time.sleep(.005)
                self.assertEqual(os.pread(output, 5, 0), b'ready')
                os.kill(middle, signal.SIGKILL)
                self.assertEqual(os.waitpid(middle, 0)[0], middle)
                middle = 0
                finished = 0
                while time.monotonic() < until:
                    finished, status = os.waitpid(owner, os.WNOHANG)
                    if finished:
                        break
                    time.sleep(.005)
                self.assertEqual(finished, owner)
                owner = 0
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                row = dict(zip(FIELDS, struct.unpack('<8sq14Q', os.pread(receipt, 129, 0)), strict=True))
                self.assertEqual((row['magic'], row['stop_reason'], row['exit_code']), (b'HIASBR01', 2, -signal.SIGTERM))
                self.assertEqual((row['child_reaped'], row['output_durable']), (1, 1))
                with self.assertRaises(ProcessLookupError):
                    os.kill(row['child_pid'], 0)
            finally:
                for child in (middle, owner):
                    if child:
                        try:
                            os.kill(child, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitpid(child, 0)
                        except ChildProcessError:
                            pass

    def test_native_process_trace_contains_no_interpreter_or_shell(self):
        with tempfile.TemporaryDirectory(prefix='hia-subprocess-trace-') as folder:
            trace = Path(folder)/'trace'
            result = self.run_owned('s', trace=trace)
            self.assert_reaped(result)
            text = trace.read_text()
            executions = [line for line in text.splitlines() if 'execve(' in line or 'execveat(' in line]
            self.assertEqual(len(executions), 2, text)
            self.assertIn('execveat(', executions[1])
            self.assertIn('AT_EMPTY_PATH', executions[1])
            self.assertNotRegex('\n'.join(executions), r'python|/bin/(sh|bash)')
            self.assertIn('wait4(', text)
            self.assertGreaterEqual(text.count('fsync('), 3)


if __name__ == '__main__':
    unittest.main()
