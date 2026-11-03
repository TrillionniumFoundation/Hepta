"""Real redirected-output errors and line visibility for print_i64 on Linux."""
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from hepta.backend import emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
HELPER = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
void prepare(void) {
    if (getenv("HEPTA_TEST_UNBUFFERED")) setvbuf(stdout, NULL, _IONBF, 0);
    if (getenv("HEPTA_TEST_IGNORE_PIPE")) signal(SIGPIPE, SIG_IGN);
}
void mark(void) { fputs("AFTER_PRINT\n", stderr); }
int64_t wait_input(void) { return getchar(); }
'''
IMPORTS = '''extern "C" fn prepare() -> Unit effects { ffi };
extern "C" fn mark() -> Unit effects { ffi };
extern "C" fn wait_input() -> i64 effects { ffi, block };
'''
FAILURE = IMPORTS + '''fn main() -> Unit effects { unsafe, ffi, io, block, alloc, panic } {
    unsafe { prepare(); } print_i64(42); unsafe { mark(); }
}'''
HANDSHAKE = IMPORTS + '''fn main() -> Unit effects { unsafe, ffi, io, block, alloc, panic } {
    print_i64(42); unsafe { let next: i64 = wait_input(); print_i64(next); }
}'''
NORMAL = '''fn next(n: mut i64) -> i64 effects { write, panic } { n = n + 1; return n; }
fn main() -> Unit effects { io, block, alloc, panic, write } {
    let mut n: i64 = 0; print_i64(next(mut n)); assert(n == 1);
    print_i64(-9223372036854775808); print_i64(9223372036854775807);
}'''
EXPECTED = b'1\n-9223372036854775808\n9223372036854775807\n'


def frontend(source):
    p = parse(source)
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p, c


@unittest.skipUnless(CC and sys.platform.startswith('linux'), 'Linux GCC and /dev/full required')
class CPrintFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'helper.c').write_text(HELPER)

    def build(self, source, opt='-O3', rust=False):
        p, c = frontend(source)
        exe = self.root / ('rust' if rust else 'native')
        if rust:
            helper = self.root / 'helper.o'
            subprocess.run([CC, '-c', str(self.root / 'helper.c'), '-o', str(helper)], check=True, capture_output=True)
            src = self.root / 'source.rs'
            src.write_text(emit_rust(p, c, crate_type='bin'))
            command = [RUSTC, '--edition=2021', '-Cpanic=abort', str(src), '-C', 'link-arg=' + str(helper), '-o', str(exe)]
        else:
            src = self.root / 'source.c'
            src.write_text(emit_c(p, c))
            command = [CC, '-std=c11', opt, '-fsanitize=undefined', '-fno-sanitize-recover=all',
                       str(src), str(self.root / 'helper.c'), '-lm', '-o', str(exe)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return exe

    def full(self, exe, unbuffered=False):
        env = dict(os.environ)
        env.pop('HEPTA_TEST_UNBUFFERED', None)
        env.pop('HEPTA_TEST_IGNORE_PIPE', None)
        if unbuffered:
            env['HEPTA_TEST_UNBUFFERED'] = '1'
        with open('/dev/full', 'wb') as sink:
            run = subprocess.run([str(exe)], stdout=sink, stderr=subprocess.PIPE, env=env, timeout=10)
        self.assertEqual(run.returncode, -signal.SIGABRT, run.stderr)
        self.assertNotIn(b'AFTER_PRINT', run.stderr)
        self.assertNotIn(b'runtime error:', run.stderr)

    def handshake(self, exe):
        process = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            prefix = bytearray()
            deadline = time.monotonic() + 10
            while b'\n' not in prefix:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, 'printed line missed its delivery deadline')
                readable, _, _ = select.select([process.stdout], [], [], remaining)
                self.assertTrue(readable, 'printed line was not delivered before the blocking foreign read')
                chunk = os.read(process.stdout.fileno(), 64)
                self.assertTrue(chunk, 'child exited without delivering its line')
                prefix.extend(chunk)
                self.assertLessEqual(len(prefix), 64)
            self.assertEqual(bytes(prefix), b'42\n')
            output, errors = process.communicate(b'\x07', timeout=10)
            self.assertEqual(process.returncode, 0, errors)
            self.assertEqual(output, b'7\n')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()

    def broken_pipe(self, exe, ignore=False, rust=False):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        env = dict(os.environ)
        env.pop('HEPTA_TEST_UNBUFFERED', None)
        env.pop('HEPTA_TEST_IGNORE_PIPE', None)
        if ignore:
            env['HEPTA_TEST_IGNORE_PIPE'] = '1'
        try:
            run = subprocess.run([str(exe)], stdout=write_fd, stderr=subprocess.PIPE, env=env, timeout=10)
        finally:
            os.close(write_fd)
        # Preserve process signal policy: default C SIGPIPE need not match
        # Rust's startup policy; returned libc errors must abort after ignore.
        self.assertEqual(run.returncode, -signal.SIGABRT if ignore or rust else -signal.SIGPIPE, run.stderr)
        self.assertNotIn(b'AFTER_PRINT', run.stderr)
        self.assertNotIn(b'runtime error:', run.stderr)

    def test_success_bytes_boundaries_and_single_evaluation(self):
        for opt in ('-O0', '-O3'):
            exe = self.build(NORMAL, opt)
            run = subprocess.run([str(exe)], capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, EXPECTED)

    def test_buffered_flush_failure_stops_before_next_operation(self):
        for opt in ('-O0', '-O3'):
            self.full(self.build(FAILURE, opt))

    def test_unbuffered_printf_failure_stops_before_next_operation(self):
        for opt in ('-O0', '-O3'):
            self.full(self.build(FAILURE, opt), unbuffered=True)

    def test_line_visible_before_blocking_pipe_handshake(self):
        for opt in ('-O0', '-O3'):
            self.handshake(self.build(HANDSHAKE, opt))

    def test_broken_pipe_retains_signal_policy_and_refuses_continuation(self):
        for opt in ('-O0', '-O3'):
            exe = self.build(FAILURE, opt)
            self.broken_pipe(exe)
            self.broken_pipe(exe, ignore=True)

    @unittest.skipUnless(RUSTC, 'Rust reference unavailable')
    def test_real_rust_reference_success_errors_and_visibility(self):
        exe = self.build(NORMAL, rust=True)
        run = subprocess.run([str(exe)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, EXPECTED)
        self.handshake(self.build(HANDSHAKE, rust=True))
        exe = self.build(FAILURE, rust=True)
        self.full(exe)
        self.full(exe, unbuffered=True)
        self.broken_pipe(exe, rust=True)
        self.broken_pipe(exe, ignore=True, rust=True)
