"""One frozen six-method HIA source/Core-VM phase; no native execution."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def record(path):
    path = Path(path)
    before = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1 and before.st_size <= 64 << 20, 'fixed ordinary input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(all(getattr(os.fstat(fd), k) == getattr(before, k) for k in FIELDS), 'input changed at open')
        pieces, size = [], 0
        while block := os.read(fd, 1 << 20):
            size += len(block)
            require(size <= before.st_size, 'input grew')
            pieces.append(block)
        after = os.fstat(fd)
        named = path.lstat()
        require(size == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(named, k)
                                               for k in FIELDS), 'input identity changed')
    finally:
        os.close(fd)
    raw = b''.join(pieces)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': {k: getattr(before, k) for k in FIELDS}}, raw


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(record(path)[1] == raw, 'new control original differs')


def main():
    request_pin, raw = record(ROOT / 'SOURCE6-REQUEST.json')
    request = json.loads(raw)
    require(request['schema'] == 'hepta.hia.json-wire-key-summary.source6-request.v1'
            and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
            and request['expected_tests'] == 6, 'frozen source/Core-VM scope differs')
    require(tuple(sys.version_info[:3]) == (3, 12, 14), 'frozen local Python version differs')
    before = {}
    for name, expected in request['input_pins'].items():
        got, _ = record(name)
        require(got == expected, 'frozen source or runtime differs: ' + name)
        before[name] = got
    output = Path(request['operation_root'])
    require(not os.path.lexists(output), 'fresh source/Core-VM operation only')
    space = os.statvfs(output.parent)
    resource = {'available_bytes': space.f_bavail * space.f_frsize, 'available_inodes': space.f_favail}
    require(resource['available_bytes'] >= request['minimum_free_bytes']
            and resource['available_inodes'] >= request['minimum_free_inodes'], 'source/Core-VM resource precondition failed')
    output.mkdir(mode=0o700)
    save(output / 'REQUEST.original.json', request)
    save(output / 'INPUTS-BEFORE.json', before)
    save(output / 'RESOURCE-CHECK.json', resource)
    final = {'schema': 'hepta.hia.json-wire-key-summary.source6-final.v1', 'status': 'HOLD',
             'closed': False, 'natural': False, 'request': request_pin,
             'wire_test_executed': False, 'native_executed': False}
    try:
        spec = importlib.util.spec_from_file_location('wire_source6_original_owner', request['owner_path'])
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        returned = owner.run_owned(request['command'], cwd=ROOT, env=request['environment'],
            stdout_path=output / 'stdout.log', stderr_path=output / 'stderr.log',
            receipt_path=output / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        save(output / 'OWNER-RETURN.json', returned)
        actual_pin, actual_raw = record(output / 'lifecycle.json')
        life = json.loads(actual_raw)
        projection = dict(returned)
        code = projection.pop('supervisor_returncode', None)
        receipt_sha = projection.pop('receipt_sha256', None)
        require(projection == life and type(code) is int and receipt_sha == actual_pin['sha256'],
                'original wrapper/receipt projection differs')
        owner_request_pin, owner_request_raw = record(output / 'lifecycle.json.request.json')
        owner_request = json.loads(owner_request_raw)
        require(life.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
                and life.get('request_sha256') == owner_request_pin['sha256']
                and life.get('implementation_sha256') == before[request['owner_path']]['sha256']
                and owner_request['command'] == request['command'] and owner_request['env'] == request['environment']
                and owner_request['cwd'] == str(ROOT) and life.get('qualification_seconds') == 180
                and life.get('cleanup_seconds') == 3, 'current source/Core-VM owner identity differs')
        cleanup = life.get('cleanup', {})
        closed = (life.get('subreaper_enabled') is True and life.get('event_overflow') is False
                  and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
                  and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
                  and cleanup.get('errors') == [] and cleanup.get('deadline_exceeded') is False)
        final['closed'] = closed
        require(closed, 'source/Core-VM child closure unknown; no child output read')
        natural = (code == 0 and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
                   and life.get('timed_out') is False and life.get('exit_observed_before_deadline') is True
                   and life.get('interrupted_signals') == [] and life.get('owner_error') is None
                   and not any(e.get('kind') == 'owned_child_sigkill' for e in life.get('events', [])))
        final['natural'] = natural
        report_pin, report_raw = record(output / 'REPORT.json')
        report = json.loads(report_raw)
        after = {name: record(name)[0] for name in before}
        save(output / 'INPUTS-AFTER.json', after)
        final['report'] = report_pin
        source_before_pin, source_before_raw = record(output / 'SOURCE-BEFORE.json')
        source_after_pin, source_after_raw = record(output / 'SOURCE-AFTER.json')
        source_before, source_after = json.loads(source_before_raw), json.loads(source_after_raw)
        require(source_before == request['source_before'] and report.get('source_after') == source_after_pin,
                'physical source before/after originals differ')
        source = Path(request['source_root'])
        actual_files, actual_dirs = {}, []
        for path in sorted(source.rglob('*')):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                require(path.resolve() == path, 'source directory alias refused')
                actual_dirs.append(str(path.relative_to(source)))
            else:
                actual_files[str(path.relative_to(source))] = record(path)[0]
        require(source_after == {'files': actual_files, 'directories': actual_dirs},
                'full source subset differs from actual post-owner bytes')
        expected_files = dict(source_before['files'])
        generated = source / 'examples/hia_bootstrap/json_wire.hiaasm'
        generated_pin, generated_raw = record(generated)
        expected_files['examples/hia_bootstrap/json_wire.hiaasm'] = generated_pin
        require(actual_files == expected_files and generated_pin == report.get('generated_source')
                and actual_dirs == sorted(source_before['directories'] + ['examples', 'examples/hia_bootstrap'])
                and record(output / 'json_wire.hiaasm')[1] == generated_raw,
                'only one exact generated HIA asset may extend the physical subset')
        final['source_before'] = source_before_pin
        final['source_after'] = source_after_pin
        require(before == after and natural and report.get('status') == 'SOURCE6_PASS_ONLY'
                and report.get('tests_run') == 6 and report.get('expected_ids') == request['expected_ids']
                and report.get('actual_ids') == request['expected_ids']
                and report.get('loaded_ids') == request['expected_ids']
                and report.get('inputs_after') == request['input_pins']
                and report.get('forbidden_attempts') == []
                and not report.get('error') and not report.get('preservation_error')
                and all(report.get(k) == [] for k in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
                and all(report.get(k) is False for k in ('native_executed', 'old_wire89_or_native7_or_native6_executed', 'old_5_second_assertion_modified', 'whole_stack_qualification')),
                'complete source/Core-VM denominator or original outcome failed')
        final['status'] = 'SOURCE6_PASS_ONLY'
    except BaseException as error:
        final['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    if final['closed']:
        try:
            originals = {str(p.relative_to(output)): record(p)[0]
                         for p in sorted(output.rglob('*')) if p.is_file()}
            save(output / 'ORIGINALS.json', originals)
            final['closed_originals'] = record(output / 'ORIGINALS.json')[0]
        except BaseException as error:
            final['status'] = 'HOLD'
            final['preservation_error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    save(output / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'closed': final['closed'], 'output': str(output)}))
    return 0 if final['status'] == 'SOURCE6_PASS_ONLY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
