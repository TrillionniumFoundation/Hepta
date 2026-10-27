"""Fail-closed production sandbox and bounded subprocess I/O.

Trusted fixture qualification may use process separation without a working
namespace sandbox. Such runs are explicitly ineligible for AI comparisons.
"""
from __future__ import annotations

import functools
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import subprocess
import time


SYSTEM_ROOTS = ('/usr', '/lib', '/lib64', '/bin')


def clean_environment(pass_names=()):
    result = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    for name in pass_names:
        if name not in os.environ:
            raise ValueError('E_ADAPTER_ENV: explicitly requested variable is absent: ' + name)
        result[name] = os.environ[name]
    return result


def _base_bwrap():
    executable = shutil.which('bwrap')
    if not executable:
        raise ValueError('E_SANDBOX_UNAVAILABLE: bubblewrap is not installed')
    args = [executable, '--die-with-parent', '--unshare-all', '--unshare-user',
            '--unshare-pid', '--unshare-ipc', '--unshare-net',
            '--new-session', '--cap-drop', 'ALL']
    for path in SYSTEM_ROOTS:
        if Path(path).is_symlink():
            # Preserve merged-/usr aliases. Flattening /bin into a bind mount
            # makes compilers infer /bin-relative library paths without procfs.
            target = os.readlink(path)
            lexical = Path(os.path.normpath(os.path.join(str(Path(path).parent), target)))
            if not any(lexical.is_relative_to(root) for root in SYSTEM_ROOTS):
                raise ValueError('E_SANDBOX_SYSTEM_PATH: system alias leaves the allowlist: ' + path)
            resolved = Path(path).resolve(strict=True)
            if not any(resolved.is_relative_to(root) for root in SYSTEM_ROOTS):
                raise ValueError('E_SANDBOX_SYSTEM_PATH: system alias resolves outside the allowlist: ' + path)
            args += ['--symlink', target, path]
        elif Path(path).exists():
            args += ['--ro-bind', path, path]
    # A new PID namespace does not require a procfs mount. Some container
    # hosts prohibit mounting procfs even when every namespace can be created.
    # Keep /proc empty rather than exposing the parent's procfs or relaxing
    # user/PID/IPC/network isolation to make a mount succeed.
    args += ['--dir', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    return args


@functools.lru_cache(maxsize=1)
def probe_sandbox():
    proc = None
    try:
        args = _base_bwrap() + ['--', '/usr/bin/true']
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=clean_environment(), start_new_session=True)
        _, stderr = proc.communicate(timeout=3)
        return {'kind': 'bubblewrap_namespaces', 'proc_policy': 'empty_directory',
                'available': proc.returncode == 0,
                'probe_returncode': proc.returncode,
                'reason': '' if proc.returncode == 0 else stderr.strip()[:500]}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {'kind': 'bubblewrap_namespaces', 'proc_policy': 'empty_directory',
                'available': False, 'reason': str(exc)[:500]}
    finally:
        if proc is not None:
            kill_process(proc)
            for pipe in (proc.stdout, proc.stderr):
                if not pipe.closed: pipe.close()


def wrap_command(command, capsule: Path, *, fixture=False, read_only=(), network=False):
    if fixture:
        return list(command)
    probe = probe_sandbox()
    if not probe['available']:
        raise ValueError('E_SANDBOX_UNAVAILABLE: production runs require namespace isolation; ' + probe['reason'])
    args = _base_bwrap()
    rust_libraries = []
    for path in read_only:
        root = Path(path).resolve()
        path = str(root)
        args += ['--ro-bind', path, path]
        # ELF $ORIGIN resolution can depend on /proc/self/exe. Only add the
        # explicitly mounted toolchain's libraries, never a host-provided
        # LD_LIBRARY_PATH or a candidate-controlled directory.
        if (root / 'lib' / 'rustlib').is_dir():
            library = str(root / 'lib')
            if os.pathsep in library:
                raise ValueError('E_TOOLCHAIN: toolchain path contains a library-path separator')
            if library not in rust_libraries:
                rust_libraries.append(library)
    if rust_libraries:
        args += ['--setenv', 'LD_LIBRARY_PATH', os.pathsep.join(rust_libraries)]
    if network:
        args += ['--share-net']
        for path in ('/etc/resolv.conf', '/etc/hosts', '/etc/ssl/certs'):
            if Path(path).exists(): args += ['--ro-bind', path, path]
    args += ['--bind', str(capsule), str(capsule), '--chdir', str(capsule), '--']
    return args + list(command)


def limits(cpu_seconds=30, memory_bytes=2 * 1024**3):
    def apply():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(cpu_seconds)), max(2, int(cpu_seconds) + 1)))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
    return apply


def kill_process(proc):
    # A child can outlive an adapter which already exited. Kill the entire
    # original process group even when its leader has been reaped.
    try: os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    try: proc.wait(timeout=2)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)


def run_bounded(command, *, cwd: Path, timeout=20.0, input_bytes=b'', fixture=False,
                read_only=(), max_output=8 * 1024**2):
    wrapped = wrap_command(command, cwd, fixture=fixture, read_only=read_only)
    proc = subprocess.Popen(wrapped, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=clean_environment(), start_new_session=True,
                            preexec_fn=limits(timeout + 1))
    selector = selectors.DefaultSelector()
    for pipe in (proc.stdout, proc.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    if input_bytes:
        os.set_blocking(proc.stdin.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE)
    else:
        proc.stdin.close()
    output, errors, offset = bytearray(), bytearray(), 0
    deadline = time.monotonic() + timeout
    status = 'exited'
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = 'timeout'; kill_process(proc); break
            for key, events in selector.select(min(remaining, 0.1)):
                pipe = key.fileobj
                if events & selectors.EVENT_WRITE:
                    try: offset += os.write(pipe.fileno(), input_bytes[offset:offset + 65536])
                    except BrokenPipeError: offset = len(input_bytes)
                    if offset == len(input_bytes): selector.unregister(pipe); pipe.close()
                else:
                    chunk = os.read(pipe.fileno(), 65536)
                    if not chunk: selector.unregister(pipe); pipe.close(); continue
                    target = output if pipe is proc.stdout else errors
                    target.extend(chunk)
                    if len(output) + len(errors) > max_output:
                        status = 'output_limit'; kill_process(proc); break
            if status != 'exited': break
        if proc.poll() is None:
            try: proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired: status = 'timeout'; kill_process(proc)
    finally:
        selector.close()
        kill_process(proc)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if not pipe.closed: pipe.close()
    return {'status': status, 'returncode': proc.returncode,
            'stdout': bytes(output).decode('utf-8', 'replace'),
            'stderr': bytes(errors).decode('utf-8', 'replace')}
