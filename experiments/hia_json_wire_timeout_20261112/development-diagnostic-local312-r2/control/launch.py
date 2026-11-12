"""Frozen one-shot launcher; only a bound closed owner permits child readback."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ident(s):
    return {key: getattr(s, key) for key in FIELDS}


def read(path, limit):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute fixed input required')
    opened = []
    links = []
    fd = None
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(parent)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            opened.append(child)
            links.append((parent, part, child, os.fstat(child)))
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'bounded single regular input')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            require(size <= limit, 'input grew beyond cap')
        raw = b''.join(chunks)
        require(len(raw) == before.st_size and ident(os.fstat(fd)) == ident(before)
                and ident(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == ident(before), 'leaf identity drift')
        for pfd, name, cfd, old in links:
            for current in (os.fstat(cfd), os.stat(name, dir_fd=pfd, follow_symlinks=False)):
                require(all(getattr(current, k) == getattr(old, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')), 'parent chain drift')
        return raw, ident(before)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(opened):
            os.close(item)


def create(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def snapshot(request):
    found = []
    for pin in request['input_pins']:
        raw, identity = read(pin['path'], pin['bytes'])
        require(len(raw) == pin['bytes'] and sha256(raw).hexdigest() == pin['sha256'], 'frozen input bytes: ' + pin['path'])
        require(all(identity[key] == pin['identity'][key] for key in FIELDS), 'frozen input metadata: ' + pin['path'])
        found.append({'path': pin['path'], 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'identity': identity})
    return found


def main():
    request_raw, _ = read(ROOT / 'REQUEST.json', 1024 * 1024)
    request = json.loads(request_raw)
    output = Path(request['output_root'])
    require(not output.exists(), 'unique diagnostic output already exists')
    before = snapshot(request)
    require(str(Path(sys.executable).resolve()) == request['python'], 'pinned interpreter required')
    fs = os.statvfs(output.parent)
    resource = {'available_bytes': fs.f_bavail * fs.f_frsize, 'available_inodes': fs.f_favail}
    require(resource['available_bytes'] >= request['minimum_free_bytes'] and resource['available_inodes'] >= request['minimum_free_inodes'], 'fresh diagnostic resources insufficient')
    output.mkdir(mode=0o700)
    create(output / 'PRELAUNCH.json', {'request_sha256': sha256(request_raw).hexdigest(), 'resource': resource, 'inputs_before': before})
    final = {'schema': 'hepta.wire89.diagnostic-owned-result.v1', 'status': 'HOLD', 'closed': False,
             'native_diagnostic_ran': False, 'full_wire89_qualification_claimed': False,
             'original_failure_retained': True, 'request_sha256': sha256(request_raw).hexdigest()}
    wrapper = None
    try:
        spec = importlib.util.spec_from_file_location('wire_diagnostic_original_owner', request['owner_path'])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        wrapper = module.run_owned(request['command'], cwd=request['cwd'], env=request['env'],
            stdout_path=output / 'child.stdout', stderr_path=output / 'child.stderr', receipt_path=output / 'lifecycle.json',
            qualification_seconds=180, cleanup_seconds=3)
        create(output / 'wrapper.json', wrapper)
        final['wrapper'] = wrapper
        # Read the small owner's own receipt, not arbitrary child outputs, to establish closure.
        life_raw, _ = read(output / 'lifecycle.json', 4 * 1024 * 1024)
        own_request_raw, _ = read(output / 'lifecycle.json.request.json', 262144)
        life, owned = json.loads(life_raw), json.loads(own_request_raw)
        require(wrapper.get('receipt_sha256') == sha256(life_raw).hexdigest(), 'wrapper raw receipt pin')
        require(all(wrapper.get(k) == value for k, value in life.items()), 'wrapper/raw receipt fields')
        require(life['request_sha256'] == sha256(own_request_raw).hexdigest(), 'owner request raw pin')
        require(owned['command'] == request['command'] and owned['cwd'] == request['cwd'] and owned['env'] == request['env'], 'owner command context')
        require(owned['qualification_seconds'] == life['qualification_seconds'] == 180
                and owned['cleanup_seconds'] == life['cleanup_seconds'] == 3, 'unchanged owner budgets')
        cleanup = life['cleanup']
        require(cleanup['complete'] and cleanup['observed_echild'] and cleanup['leader_reaped']
                and not cleanup['deadline_exceeded'] and not cleanup['errors']
                and cleanup['remaining_direct_children'] == [], 'bound ECHILD closure required')
        final['closed'] = True
        final['native_diagnostic_ran'] = life['qualification_started']
        final['inputs_after'] = snapshot(request)
        require(final['inputs_after'] == before, 'inputs changed during diagnostic')
        report_raw, _ = read(output / 'diagnostic-report.json', 8 * 1024 * 1024)
        report = json.loads(report_raw)
        final['diagnostic_report'] = {'bytes': len(report_raw), 'sha256': sha256(report_raw).hexdigest(), 'status': report['status']}
        require(life['returncode'] == wrapper['supervisor_returncode'] == 0 and life['exit_observed_before_deadline']
                and not life['timed_out'] and life.get('owner_error') is None and not life['interrupted_signals']
                and not life['event_overflow'] and not any(e['kind'] == 'owned_child_sigkill' for e in life['events']), 'original diagnostic failed or did not naturally complete')
        require(report['status'] == 'DIAGNOSTIC_TEST_PASS' and report['original_test_id'] == request['test_id']
                and report['tests_run'] == 1 and report['executed_ids'] == [request['test_id']]
                and report['observer_binding_unchanged'] and not report['recording_failed']
                and not report['recording_errors'], 'diagnostic report incomplete')
        final['status'] = 'DEVELOPMENT_DIAGNOSTIC_TEST_PASS_NOT_WIRE89_QUALIFICATION'
    except BaseException as error:
        final['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if final['closed']:
            originals = []
            try:
                for p in sorted(output.rglob('*')):
                    if p.is_dir():
                        require(not p.is_symlink(), 'unexpected output directory link')
                        continue
                    raw, identity = read(p, request['diagnostic_raw_bytes_limit'])
                    originals.append({'path': str(p.relative_to(output)), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'identity': identity})
                final['closed_originals'] = originals
            except BaseException as error:
                final['status'] = 'HOLD'
                final['preservation_error'] = {'type': type(error).__name__, 'message': str(error)}
        create(output / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'closed': final['closed'], 'report': str(output / 'FINAL.json')}))
    return 0 if final['status'] == 'DEVELOPMENT_DIAGNOSTIC_TEST_PASS_NOT_WIRE89_QUALIFICATION' else 1


if __name__ == '__main__':
    raise SystemExit(main())
