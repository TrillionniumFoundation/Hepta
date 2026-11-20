"""Strict bytes and owned subprocess receipts for the explicit cold transport.

The process supervisor is mechanically retained from the recorded Slot support
module, with this new lane's explicit three-second cleanup cap. It imports no
product. It never changes the original child's own 180-second cold deadline.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

CLEANUP_SECONDS = 3
JSON_KW = dict(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def canonical(value):
    return json.dumps(value, **JSON_KW).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    Path(path).write_bytes(canonical(value) + b'\n')


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON key: ' + name)
        result[name] = value
    return result


def read_json(path):
    return json.loads(regular_bytes(path), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def regular_bytes(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError('expected regular immutable input: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('input changed while reading: ' + str(path))
    if len(raw) != after.st_size:
        raise ValueError('short source read')
    return raw


def pin(path):
    raw = regular_bytes(path)
    return {'bytes': len(raw), 'sha256': sha(raw)}


def checked_int(value, expected=None):
    if type(value) is not int or (expected is not None and value != expected):
        raise ValueError('integer identity differs: ' + repr(value))
    return value


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('HEPTA_HIA', 'PYTHON'))}


def group_members(group):
    found = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            raw = (directory / 'stat').read_text()
            parts = raw[raw.rfind(')') + 2:].split()
            if int(parts[2]) == group and int(parts[3]) == group:
                found.append({'pid': int(directory.name), 'pgid': int(parts[2]),
                              'sid': int(parts[3]), 'state': parts[0],
                              'start_ticks': int(parts[19])})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(found, key=lambda row: row['pid'])


def stop_owned(process):
    start = time.monotonic()
    before, signals = group_members(process.pid), []
    if before:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            signals.append('SIGTERM')
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS / 2 - (time.monotonic() - start)))
    except subprocess.TimeoutExpired:
        pass
    middle = group_members(process.pid)
    if middle:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signals.append('SIGKILL')
        except ProcessLookupError:
            pass
    reaped = True
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS - (time.monotonic() - start)))
    except subprocess.TimeoutExpired:
        reaped = False
    return {'before': before, 'middle': middle, 'after': group_members(process.pid),
            'signals': signals, 'reaped': reaped,
            'cleanup_elapsed_seconds': time.monotonic() - start}


def run_owned(command, *, cwd, directory, timeout_seconds, environment=None, stdin=None, deadline=None):
    checked_int(timeout_seconds)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = clean_environment() if environment is None else environment
    start, process, timed_out, interruption = time.monotonic(), None, False, None
    started_ns = time.monotonic_ns()
    stdout_path, stderr_path = directory / 'stdout.log', directory / 'stderr.log'
    spec = {'argv': list(map(str, command)), 'cwd': str(Path(cwd).resolve()),
            'timeout_seconds': timeout_seconds, 'cleanup_seconds': CLEANUP_SECONDS,
            'new_session': True, 'parent_pid': os.getpid(), 'started_monotonic_ns': started_ns,
            'environment': {key: value for key, value in environment.items()
                            if key in ('PATH', 'LD_LIBRARY_PATH', 'CLANG', 'HEPTA_CLANG')
                            or key.startswith(('HEPTA_HIA', 'PYTHON'))}}
    write_json(directory / 'command.json', spec)
    cleanup = None
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            process = subprocess.Popen(spec['argv'], cwd=cwd, env=environment,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                spec.update({'pid': process.pid, 'pgid': process.pid,
                             'owned_initial_members': group_members(process.pid)})
                write_json(directory / 'command.json', spec)
                effective = timeout_seconds if deadline is None else min(timeout_seconds, max(.001, deadline - time.monotonic()))
                spec['effective_timeout_seconds'] = effective
                write_json(directory / 'command.json', spec)
                process.communicate(stdin, timeout=effective)
            except subprocess.TimeoutExpired:
                timed_out = True
            except BaseException as error:
                interruption = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                                'message': str(error)}
                raise
            finally:
                cleanup = stop_owned(process)
    finally:
        result = {'command': spec, 'pid': None if process is None else process.pid,
                  'exit_code': None if process is None else process.returncode,
                  'timed_out': timed_out, 'interruption': interruption,
                  'elapsed_seconds': time.monotonic() - start, 'ended_monotonic_ns': time.monotonic_ns(),
                  'owned_cleanup': cleanup,
                  'stdout': pin(stdout_path) if stdout_path.exists() else None,
                  'stderr': pin(stderr_path) if stderr_path.exists() else None}
        write_json(directory / 'result.json', result)
    return result


def successful_exit(result):
    cleanup = result.get('owned_cleanup')
    return (type(result.get('exit_code')) is int and result['exit_code'] == 0
            and result.get('timed_out') is False and result.get('interruption') is None
            and type(cleanup) is dict and cleanup.get('reaped') is True
            and cleanup.get('after') == [] and cleanup.get('signals') == [])

def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def data_pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


class Captures:
    def __init__(self):
        self.raws = {}

    def raw(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        raw = regular_bytes(path)
        if expected is not None and (
                type(expected) is not dict or type(expected.get("bytes")) is not int
                or type(expected.get("sha256")) is not str or data_pin(raw) != expected):
            raise ValueError("captured raw identity differs: " + str(path))
        prior = self.raws.setdefault(path, raw)
        if prior != raw:
            raise ValueError("captured file changed between consumption points")
        return raw

    def json(self, path, expected=None):
        return parse(self.raw(path, expected))

    def unchanged(self):
        for path, raw in self.raws.items():
            if regular_bytes(path) != raw:
                raise ValueError("terminal captured bytes changed: " + str(path))

    def pins(self):
        return {str(path): data_pin(raw) for path, raw in sorted(self.raws.items(), key=lambda row: str(row[0]))}


def terminal_owned(capture, directory, *, seconds, expected_argv=None, cwd=None):
    directory = Path(directory)
    command = capture.json(directory / "command.json")
    result = capture.json(directory / "result.json")
    checked_int(command["timeout_seconds"], seconds)
    checked_int(command["cleanup_seconds"], CLEANUP_SECONDS)
    if command.get("new_session") is not True or result["command"] != command:
        raise ValueError("actual owned command receipt differs")
    if expected_argv is not None and command["argv"] != list(map(str, expected_argv)):
        raise ValueError("actual owned argv differs")
    if cwd is not None and command["cwd"] != str(Path(cwd).resolve()):
        raise ValueError("actual owned cwd differs")
    pid = checked_int(command["pid"])
    if pid <= 0 or command["pgid"] != pid or checked_int(result["pid"]) != pid:
        raise ValueError("actual owned child identity differs")
    capture.raw(directory / "stdout.log", result["stdout"])
    capture.raw(directory / "stderr.log", result["stderr"])
    if not successful_exit(result):
        raise ValueError("owned child is incomplete or anomalous")
    return command, result
