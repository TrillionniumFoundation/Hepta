"""Independent kernel/VM observers for explicitly selected process-profile ELFs.

Python/ctypes only arrange execve's raw byte vectors in the child before exec.
The executed static ELF has no interpreter, Python, libc or ctypes dependency.
"""
from __future__ import annotations

from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import os
import resource
import signal
import subprocess
import sys
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


LIMITS = {'wall': 20, 'cleanup': 3, 'cpu': 10, 'address': 256 << 20,
          'stack': 8 << 20, 'filesize': 16 << 20, 'fds': 32, 'core': 0}


def raw_exec(specification):
    """Run only as a fresh pre-exec helper; no profile code runs in this process."""
    spec = json.loads(Path(specification).read_text())
    lib = ctypes.CDLL(None, use_errno=True)
    lib.execve.argtypes = (ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p),
                          ctypes.POINTER(ctypes.c_char_p))
    lib.execve.restype = ctypes.c_int
    arrays = []
    retained = []
    for kind in ('argv_hex', 'environment_hex'):
        values = tuple(bytes.fromhex(s) for s in spec[kind])
        assert all(b'\0' not in value for value in values)
        retained.extend(values)
        array = (ctypes.c_char_p * (len(values) + 1))()
        for i, value in enumerate(values):
            array[i] = value
        array[len(values)] = None
        arrays.append(array)
    image = Path(spec['elf']).read_bytes()
    assert sha(image) == spec['elf_sha256']
    for kind, size in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 10),
            (resource.RLIMIT_AS, 256 << 20), (resource.RLIMIT_STACK, 8 << 20),
            (resource.RLIMIT_FSIZE, 16 << 20), (resource.RLIMIT_NOFILE, 32)):
        resource.setrlimit(kind, (size, size))
    signal.signal(signal.SIGPIPE, signal.SIG_IGN if spec['sigpipe_ignored'] else signal.SIG_DFL)
    for fd in spec['close_fds']:
        os.close(fd)
    result = lib.execve(os.fsencode(spec['elf']), arrays[0], arrays[1])
    error = ctypes.get_errno()
    # This distinct file records a failure before payload entry, even when fd2
    # deliberately closed/broken. Never relabel it as a HIA program outcome.
    dump(Path(spec['exec_failure']), {'returncode': result, 'errno': error,
        'payload_entered': False, 'stage': 'raw_execve'})
    os._exit(125)


def direct(folder, elf, argv, environment, *, stdin=b'', mode='ordinary', ignored=False):
    folder.mkdir(parents=False, exist_ok=False)
    assert type(argv) is tuple and type(environment) is tuple
    assert all(type(x) is bytes and b'\0' not in x for x in argv + environment)
    raw = elf.read_bytes()
    (folder / 'stdin.bin').write_bytes(stdin)
    closed = {'closed-stdin': [0], 'closed-stdout': [1], 'closed-stderr': [2]}.get(mode, [])
    spec = {'elf': str(elf.resolve()), 'elf_sha256': sha(raw),
        'argv_hex': [v.hex() for v in argv], 'environment_hex': [v.hex() for v in environment],
        'sigpipe_ignored': bool(ignored), 'close_fds': closed,
        'exec_failure': str((folder / 'EXEC-FAILURE.json').resolve())}
    dump(folder / 'EXEC-REQUEST.json', spec)
    pipes = []
    read_end = None
    capacity = None
    started = time.perf_counter()
    timed_out = False
    with (folder / 'stdin.bin').open('rb') as inp, (folder / 'stdout.bin').open('wb') as out, \
            (folder / 'stderr.bin').open('wb') as err:
        target_out = out
        target_err = err
        if mode in ('broken-stdout', 'broken-stderr', 'short-stderr'):
            read_end, write_end = os.pipe()
            pipes.extend((read_end, write_end))
            if mode.startswith('broken-'):
                os.close(read_end)
                pipes.remove(read_end)
                read_end = None
            else:
                capacity = fcntl.fcntl(write_end, fcntl.F_GETPIPE_SZ)
                fcntl.fcntl(write_end, fcntl.F_SETFL,
                            fcntl.fcntl(write_end, fcntl.F_GETFL) | os.O_NONBLOCK)
            if mode.endswith('stderr'):
                target_err = write_end
            else:
                target_out = write_end
        command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                   '--raw-exec', str((folder / 'EXEC-REQUEST.json').resolve())]
        try:
            child = subprocess.Popen(command, stdin=inp, stdout=target_out, stderr=target_err,
                                     start_new_session=True, restore_signals=False)
            try:
                rc = child.wait(timeout=LIMITS['wall'])
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                rc = child.wait(timeout=LIMITS['cleanup'])
            consumed = inp.tell()
            if mode == 'short-stderr':
                os.close(write_end)
                pipes.remove(write_end)
                piece = bytearray()
                while True:
                    data = os.read(read_end, 65536)
                    if not data:
                        break
                    piece.extend(data)
                err.write(piece)
        finally:
            for fd in pipes:
                os.close(fd)
    try:
        os.waitpid(child.pid, os.WNOHANG)
    except ChildProcessError:
        reaped = True
    else:
        reaped = False
    after = elf.read_bytes()
    result = {'command': command, 'payload': str(elf.resolve()), 'returncode': rc,
        'timed_out': timed_out, 'reaped_ECHILD': reaped, 'stdin_consumed': consumed,
        'stdout_hex': (folder / 'stdout.bin').read_bytes().hex(),
        'stderr_hex': (folder / 'stderr.bin').read_bytes().hex(),
        'image_sha256': sha(raw), 'image_after_sha256': sha(after),
        'wall_seconds': time.perf_counter() - started, 'limits': LIMITS,
        'pipe_capacity': capacity, 'preexec_python_ctypes': True,
        'runtime_payload_python_or_ctypes': False,
        'exec_failure': json.loads((folder / 'EXEC-FAILURE.json').read_text())
            if (folder / 'EXEC-FAILURE.json').exists() else None}
    dump(folder / 'OBSERVATION.json', result)
    return result


def reference(program, argv, environment, *, stdin=b'', mode='ordinary', ignored=False,
              short_capacity=None):
    from hepta.hia_linux_process import PROFILE, READ, LinuxStartupSnapshot, LinuxProcessSignal
    from hepta.hia_program_runtime import execute_program, HIAProgramTrap
    consumed = 0
    stdout = []
    stderr = []
    def provider(request):
        nonlocal consumed
        if request.operation == READ:
            if mode == 'closed-stdin':
                return -9, b''
            data = stdin[consumed:consumed + request.count]
            consumed += len(data)
            return len(data), data
        if mode == 'closed-stdout' and request.fd == 1 or mode == 'closed-stderr' and request.fd == 2:
            return -9, b''
        if mode == 'broken-stderr' and request.fd == 2 or mode == 'broken-stdout' and request.fd == 1:
            if ignored:
                return -32, b''
            raise LinuxProcessSignal(int(signal.SIGPIPE))
        accepted = request.count
        if mode == 'short-stderr' and request.fd == 2:
            assert type(short_capacity) is int and 0 < short_capacity < request.count
            accepted = short_capacity
        (stdout if request.fd == 1 else stderr).append(request.write_bytes[:accepted])
        return accepted, b''
    try:
        result = execute_program(program, 'f0', (b'', bytes(1048576), bytes(1048576)),
            profile=PROFILE, linux_process_startup=LinuxStartupSnapshot(argv, environment),
            linux_process_provider=provider, max_steps=10000000)
        rc = result['values'][0] & 255
    except HIAProgramTrap as exc:
        result = exc.report
        rc = -int(signal.SIGILL)
    except LinuxProcessSignal as exc:
        result = exc.report
        rc = -exc.number
    result.update(expected_stdout_hex=b''.join(stdout).hex(),
        expected_stderr_hex=b''.join(stderr).hex(), stdin_consumed=consumed, process_returncode=rc)
    return result


if __name__ == '__main__':
    assert len(sys.argv) == 3 and sys.argv[1] == '--raw-exec'
    raw_exec(sys.argv[2])
