"""Read and archive the closed source/IO run. No supplier or child is executed."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

HERE = Path(__file__).resolve().parent
ACTUAL = Path('/tmp/hia-full32-apt-owner-source-io-22-r2-20261112-e26e')
FROZEN = Path('/tmp/hia-full32-privileged-apt-owner-source-io-r2-20261112-e26e')
ROOT_INVOCATION = Path('/workspace/scratch/e26ed3e2edcf/root/apt-owner-source-io-r2-invocation')
ROOT_REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/apt-owner-source-io-r2-review/CANONICAL-READBACK.json')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
checks = []
raws = {}
records = {}


def check(value, label):
    checks.append({'check': label, 'pass': bool(value)})
    if not value:
        raise AssertionError(label)


def identity(st):
    return {key: getattr(st, key) for key in FIELDS}


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path, limit=2 << 20):
    path = Path(path)
    before = path.lstat()
    check(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode)
          and before.st_nlink == 1 and before.st_size <= limit, 'fixed ordinary file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        check(identity(os.fstat(fd)) == identity(before), 'identity at open: ' + str(path))
        pieces = []
        size = 0
        while chunk := os.read(fd, 1 << 20):
            size += len(chunk)
            check(size <= before.st_size, 'bounded read: ' + str(path))
            pieces.append(chunk)
        check(size == before.st_size and identity(os.fstat(fd)) == identity(before)
              == identity(path.lstat()), 'complete stable read: ' + str(path))
    finally:
        os.close(fd)
    raw = b''.join(pieces)
    return raw, {'path': str(path), 'identity': identity(before), **pin(raw)}


def add(name, path):
    check(name not in records, 'unique archive name: ' + name)
    raw, row = read(path)
    raws[name] = raw
    records[name] = row
    return raw


def load(name):
    return json.loads(raws[name])


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    check(path.read_bytes() == raw, 'created readback: ' + str(path))


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def main():
    directory_records = {}
    for parent, directories, files in os.walk(ACTUAL, followlinks=False):
        for name in sorted(directories):
            path = Path(parent) / name
            st = path.lstat()
            check(stat.S_ISDIR(st.st_mode) and path.resolve(strict=True) == path,
                  'actual directory type: ' + str(path))
            directory_records['actual/' + path.relative_to(ACTUAL).as_posix()] = {
                'path': str(path), 'type': 'directory', 'identity': identity(st)}
        for name in sorted(files):
            path = Path(parent) / name
            add('actual/' + path.relative_to(ACTUAL).as_posix(), path)
    check(len(directory_records) == 55 and len(raws) == 78, 'complete current actual namespace 55 dirs / 78 files')
    check(sum(len(raw) for raw in raws.values()) == 126910, 'complete current actual bytes 126910')
    for path in sorted(FROZEN.rglob('*')):
        if path.is_file():
            add('frozen/' + path.relative_to(FROZEN).as_posix(), path)
        else:
            check(path.is_dir() and not path.is_symlink(), 'frozen namespace type: ' + str(path))
    check(sum(name.startswith('frozen/') for name in raws) == 35, 'complete 35 canonical frozen files')
    for path in sorted(ROOT_INVOCATION.iterdir()):
        add('root-invocation/' + path.name, path)
    add('root-review/CANONICAL-READBACK.json', ROOT_REVIEW)
    add('reader/audit_actual.py', Path(__file__).resolve())
    req = load('frozen/SOURCE-IO-REQUEST.json')
    check(raws['actual/REQUEST.original.json'] == raws['frozen/SOURCE-IO-REQUEST.json'], 'actual request original byte equality')
    check(req['qualification_seconds'] == 180 and req['cleanup_seconds'] == 3 and req['expected_tests'] == 22,
          'original source control population and budgets')
    check('HOME' not in req['environment'] and set(req['environment']) == {
        'PATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED', 'PYTHONNOUSERSITE', 'LANG', 'LC_ALL'}, 'fixed noncredential environment')
    final = load('actual/FINAL.json')
    life = load('actual/lifecycle.json')
    owner_request = load('actual/lifecycle.json.request.json')
    returned = load('actual/OWNER-RETURN.json')
    report = load('actual/tests/REPORT.json')
    projection = dict(returned)
    supervisor_code = projection.pop('supervisor_returncode')
    receipt_sha = projection.pop('receipt_sha256')
    check(projection == life and supervisor_code == 0 and receipt_sha == records['actual/lifecycle.json']['sha256'],
          'complete original wrapper to lifecycle projection')
    check(life['schema'] == owner_request['schema'] == 'hepta.hia.selfhost-process-owner.v1'
          and life['request_sha256'] == records['actual/lifecycle.json.request.json']['sha256']
          and life['implementation_sha256'] == owner_request['implementation_sha256']
          == records['frozen/candidate/process_owner_impl.py']['sha256'], 'actual owner schema/request/implementation binding')
    check(owner_request['command'] == req['command'] and owner_request['env'] == req['environment']
          and owner_request['cwd'] == str(FROZEN) and owner_request['qualification_seconds'] == 180
          and owner_request['cleanup_seconds'] == 3, 'actual original command/environment/cwd/budgets')
    check(owner_request['deadline_ns'] - owner_request['started_ns'] == 180000000000,
          'exact 180s original deadline')
    for name in ('receipt_path', 'stdout_path', 'stderr_path'):
        leaf = {'receipt_path': 'lifecycle.json', 'stdout_path': 'stdout.log', 'stderr_path': 'stderr.log'}[name]
        check(owner_request[name] == str(ACTUAL / leaf), 'original output binding: ' + name)
    cleanup = life['cleanup']
    check(life['subreaper_enabled'] is True and cleanup['complete'] is True
          and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
          and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == []
          and cleanup['deadline_exceeded'] is False, 'actual source owner ECHILD closure')
    check(life['returncode'] == 0 and life['status'] == 'OWNED_PROCESS_COMPLETED'
          and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
          and life['interrupted_signals'] == [] and life.get('owner_error') is None
          and life['event_overflow'] is False, 'actual natural owner success')
    events = life['events']
    check([event['kind'] for event in events] == ['qualification_started', 'owned_child_observed',
          'qualification_exit_observed', 'owned_child_reaped'], 'four natural events and no cleanup kill')
    check(all(event['pid'] == life['qualification_pid'] for event in events)
          and events[1]['start_ticks'] == events[3]['start_ticks']
          and events[2]['si_status'] == events[3]['returncode'] == 0
          and events[0]['monotonic_ns'] < events[2]['monotonic_ns'] < events[3]['monotonic_ns'],
          'same actual qualification child event identity')
    check(life['parent_pid'] == owner_request['parent_pid'], 'actual parent PID binding')
    check(report['tests_run'] == 22 and report['expected_ids'] == report['actual_ids'] == req['expected_ids']
          and len(set(report['actual_ids'])) == 22, 'all original 22 methods exactly once in order')
    for field in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'):
        check(report[field] == [], 'zero anomaly: ' + field)
    check(report['status'] == 'PASS' and report['root_uid_positive_is_synthetic'] is True
          and report['privileged_root_process_execution_proved'] is False, 'finite IO scope excludes root APT proof')
    for field in ('APT_executed', 'sudo_executed', 'network_used', 'product_executed', 'native_executed'):
        check(report[field] is False, 'no additional execution: ' + field)
    check(report['inputs_before'] == report['inputs_after'], 'worker source inputs before/after identical')
    for name, sha in report['inputs_before'].items():
        check(records['frozen/' + name]['sha256'] == sha, 'worker actual source input: ' + name)
    before, after = load('actual/INPUTS-BEFORE.json'), load('actual/INPUTS-AFTER.json')
    check(before == after, 'launcher input records before/after identical')
    for name, expected in req['inputs'].items():
        rec = records['frozen/' + name]
        check(all(rec[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob')), 'request fixed pin: ' + name)
    intent = load('root-invocation/INTENT.json')
    check(intent['canonical'] == '073abcfa888286f08384ca31c03d637630ee69b1'
          and len(intent['inputs_before']) == 35, 'root original 35-file invocation')
    for name, expected in intent['inputs_before'].items():
        rec = records['frozen/' + name]
        check(rec['identity'] == expected['stat'] and all(rec[k] == expected[k] for k in ('bytes','sha256','git_blob')),
              'root before to current original full identity: ' + name)
    runtime_raw, runtime = read(req['runtime']['path'], 40 << 20)
    check(all(runtime[k] == req['runtime'][k] for k in ('path', 'bytes', 'sha256'))
          and runtime['identity'] == intent['runtime']['stat'], 'actual fixed Python 3.12 runtime unchanged')
    del runtime_raw
    check(final['status'] == 'SOURCE_IO_22_PASS_ONLY' and final['closed'] is True and final['natural'] is True
          and final['test_report']['sha256'] == records['actual/tests/REPORT.json']['sha256']
          and final['request']['sha256'] == records['frozen/SOURCE-IO-REQUEST.json']['sha256'], 'final actual original joins')
    check(load('root-invocation/LAUNCHER-RETURN.json')['returncode'] == 0, 'root unique launcher returned 0')
    inventory = {'schema': 'hia.apt-owned.actual-source-io-inventory.v1', 'files': records, 'directories': directory_records}
    create(HERE / 'ORIGINALS-INVENTORY.json', wire(inventory))
    archive = HERE / 'all-originals.tar.gz'
    with archive.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0, compresslevel=6) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, record in sorted(directory_records.items()):
                    meta = record['identity']; item = tarfile.TarInfo(name)
                    item.type = tarfile.DIRTYPE; item.mode = stat.S_IMODE(meta['st_mode'])
                    item.uid = meta['st_uid']; item.gid = meta['st_gid']; item.mtime = meta['st_mtime_ns'] // 1000000000
                    item.pax_headers = {'mtime': str(meta['st_mtime_ns'] // 1000000000) + '.' + f"{meta['st_mtime_ns'] % 1000000000:09d}"}
                    tar.addfile(item)
                for name, raw in sorted(raws.items()):
                    meta = records[name]['identity']; item = tarfile.TarInfo(name)
                    item.size = len(raw); item.mode = stat.S_IMODE(meta['st_mode']); item.uid = meta['st_uid']; item.gid = meta['st_gid']
                    item.mtime = meta['st_mtime_ns'] // 1000000000
                    item.pax_headers = {'mtime': str(meta['st_mtime_ns'] // 1000000000) + '.' + f"{meta['st_mtime_ns'] % 1000000000:09d}"}
                    tar.addfile(item, io.BytesIO(raw))
        output.flush(); os.fsync(output.fileno())
    seen = set()
    with tarfile.open(archive, 'r:gz') as tar:
        for item in tar:
            check(item.name not in seen and not item.name.startswith('/') and '..' not in Path(item.name).parts, 'archive unique relative member: ' + item.name)
            seen.add(item.name)
            if item.isdir():
                check(item.name in directory_records, 'archive actual directory: ' + item.name)
                meta = directory_records[item.name]['identity']
            else:
                check(item.isreg() and item.name in records, 'archive regular member: ' + item.name)
                meta = records[item.name]['identity']
                raw = tar.extractfile(item).read()
                check(raw == raws[item.name] and pin(raw)['sha256'] == records[item.name]['sha256'], 'archive complete raw equality: ' + item.name)
            check(item.mode == stat.S_IMODE(meta['st_mode']) and item.uid == meta['st_uid'] and item.gid == meta['st_gid'], 'archive metadata: ' + item.name)
    check(seen == set(records) | set(directory_records), 'complete archived namespace set')
    for name, record in records.items():
        raw, again = read(record['path'])
        check(again == record and raw == raws[name], 'independent original reread after archive: ' + name)
    for name, record in directory_records.items():
        check(identity(Path(record['path']).lstat()) == record['identity'], 'actual directory unchanged after archive: ' + name)
    packed, packed_pin = read(archive)
    create(HERE / 'all-originals.tar.gz.b64', base64.b64encode(packed) + b'\n')
    check(base64.b64decode((HERE / 'all-originals.tar.gz.b64').read_bytes(), validate=False) == packed, 'base64 whole archive restoration')
    result = {'schema': 'hia.apt-owned.actual-source-io-independent-readback.v1', 'status': 'SOURCE_IO_22_READBACK_PASS_ONLY',
        'canonical_request': '073abcfa888286f08384ca31c03d637630ee69b1', 'actual': str(ACTUAL),
        'expected_methods': 22, 'actual_methods': 22, 'qualification_seconds': 180, 'cleanup_seconds': 3,
        'worker_elapsed_ns': events[2]['monotonic_ns'] - events[0]['monotonic_ns'],
        'natural_owner': True, 'echild': True, 'actual_regular_files': 78, 'actual_regular_bytes': 126910,
        'actual_directories': 55, 'archive_regular_files': len(records), 'archive_directories': len(directory_records),
        'archive_original_bytes': sum(len(raw) for raw in raws.values()), 'archive': packed_pin,
        'root_uid_positive_is_synthetic': True, 'privileged_APT_execution_proved': False,
        'APT_sudo_network_native_or_product_execution_in_this_reader': False,
        'source_IO_was_run_once_by_Root_not_replayed': True, 'all_original_final_test_namespaces_retained': True,
        'old_a548_request_unexecuted': True, 'checks': checks}
    create(HERE / 'AUDIT.json', wire(result))
    for name in ('FINAL.json', 'lifecycle.json', 'lifecycle.json.request.json', 'OWNER-RETURN.json', 'REQUEST.original.json', 'stdout.log', 'stderr.log', 'tests/REPORT.json', 'tests/unittest.log'):
        create(HERE / 'critical-originals' / name.replace('/', '__'), raws['actual/' + name])
    print(json.dumps({key: result[key] for key in ('status','worker_elapsed_ns','actual_regular_files','actual_regular_bytes','archive_regular_files','archive_directories','archive_original_bytes','archive')}, sort_keys=True))


if __name__ == '__main__':
    main()
