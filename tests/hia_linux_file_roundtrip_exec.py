"""Stdlib pre-exec test observer; the real ELF writes its postreturn BSS.

No startup capability, resident target, or memory mapping is made by this host
adapter. The only added child inputs are output file descriptors 29..31. The
payload is still the actual kernel-loaded static ELF with its original startup.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import resource
import signal
import subprocess
import sys
import time

LIMITS = {'wall': 20, 'cleanup': 3, 'cpu': 10, 'address': 256 << 20,
          'stack': 8 << 20, 'filesize': 16 << 20, 'fds': 32, 'core': 0}
DUMPS = (('file', 29, 8388609), ('output', 30, 1048576), ('workspace', 31, 1048576))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def raw_exec(specification):
    spec = json.loads(Path(specification).read_bytes())
    lib = ctypes.CDLL(None, use_errno=True)
    lib.execve.argtypes = (ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p))
    lib.execve.restype = ctypes.c_int
    arrays, retained = [], []
    for kind in ('argv_hex', 'environment_hex'):
        values = tuple(bytes.fromhex(s) for s in spec[kind])
        assert all(b'\0' not in value for value in values)
        retained.extend(values)
        array = (ctypes.c_char_p * (len(values) + 1))()
        for i, value in enumerate(values):
            array[i] = value
        array[len(values)] = None
        arrays.append(array)
    assert sha(Path(spec['elf']).read_bytes()) == spec['elf_sha256']
    for name, fd, extent in DUMPS:
        assert spec['observations'][name]['fd'] == fd and spec['observations'][name]['extent'] == extent
        opened = os.open(spec['observations'][name]['path'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        assert 3 <= opened < 29
        try:
            os.dup2(opened, fd, inheritable=True)
        finally:
            os.close(opened)
    # The observer destinations do not occupy fd3; actual readonly openat keeps
    # the production's first available descriptor and lifetime protocol.
    try:
        os.fstat(3)
    except OSError as exc:
        assert exc.errno == 9
    else:
        raise AssertionError('preexec helper unexpectedly retains fd3')
    for kind, size in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 10),
            (resource.RLIMIT_AS, 256 << 20), (resource.RLIMIT_STACK, 8 << 20),
            (resource.RLIMIT_FSIZE, 16 << 20), (resource.RLIMIT_NOFILE, 32)):
        resource.setrlimit(kind, (size, size))
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    result = lib.execve(os.fsencode(spec['elf']), arrays[0], arrays[1])
    error = ctypes.get_errno()
    dump(Path(spec['exec_failure']), {'returncode': result, 'errno': error,
        'payload_entered': False, 'stage': 'raw_execve'})
    os._exit(125)


def direct(folder, elf, argv, environment):
    folder.mkdir(exist_ok=False)
    assert type(argv) is tuple and type(environment) is tuple
    assert all(type(x) is bytes and b'\0' not in x for x in argv + environment)
    raw = elf.read_bytes()
    (folder / 'stdin.bin').write_bytes(b'')
    spec = {'elf': str(elf.resolve()), 'elf_sha256': sha(raw),
        'argv_hex': [v.hex() for v in argv], 'environment_hex': [v.hex() for v in environment],
        'exec_failure': str((folder / 'EXEC-FAILURE.json').resolve()),
        'observations': {name: {'fd': fd, 'extent': extent, 'path': str((folder / (name + '.bin')).resolve())}
                         for name, fd, extent in DUMPS}}
    dump(folder / 'EXEC-REQUEST.json', spec)
    command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--raw-exec',
               str((folder / 'EXEC-REQUEST.json').resolve())]
    started = time.perf_counter()
    timed_out = False
    with (folder / 'stdin.bin').open('rb') as inp, (folder / 'stdout.bin').open('wb') as out, (folder / 'stderr.bin').open('wb') as err:
        child = subprocess.Popen(command, stdin=inp, stdout=out, stderr=err,
                                 start_new_session=True, restore_signals=False)
        try:
            rc = child.wait(timeout=LIMITS['wall'])
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            rc = child.wait(timeout=LIMITS['cleanup'])
        consumed = inp.tell()
    try:
        os.waitpid(child.pid, os.WNOHANG)
    except ChildProcessError:
        reaped = True
    else:
        reaped = False
    buffers = {}
    for name, fd, extent in DUMPS:
        path = folder / (name + '.bin')
        actual = path.read_bytes() if path.exists() else b''
        buffers[name] = {'path': str(path), 'bytes': len(actual), 'sha256': sha(actual),
                         'complete': len(actual) == extent, 'expected_extent': extent, 'descriptor': fd}
    result = {'command': command, 'payload': str(elf.resolve()), 'returncode': rc,
        'timed_out': timed_out, 'reaped_ECHILD': reaped, 'stdin_consumed': consumed,
        'stdout_hex': (folder / 'stdout.bin').read_bytes().hex(), 'stderr_hex': (folder / 'stderr.bin').read_bytes().hex(),
        'image_sha256': sha(raw), 'image_after_sha256': sha(elf.read_bytes()),
        'wall_seconds': time.perf_counter() - started, 'limits': LIMITS,
        'preexec_python_ctypes': True, 'runtime_payload_python_or_ctypes': False,
        'native_startup_capability_from_actual_kernel': True, 'postreturn_buffers': buffers,
        'exec_failure': json.loads((folder / 'EXEC-FAILURE.json').read_bytes())
            if (folder / 'EXEC-FAILURE.json').exists() else None}
    dump(folder / 'OBSERVATION.json', result)
    return result


if __name__ == '__main__':
    assert len(sys.argv) == 3 and sys.argv[1] == '--raw-exec'
    raw_exec(sys.argv[2])
