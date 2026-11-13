"""Independent source12 readback and lossless body archive, after Root reports closure.

No owner, control, network or product is executed here. The first actual reads
bind the original owner wrapper, raw request and raw receipt. Other child
originals are read only after that independent ECHILD conjunction succeeds.
"""
from hashlib import sha256
from pathlib import Path
import argparse
import gzip
import io
import json
import os
import stat
import tarfile
import zipfile
import zlib

REQUEST_SHA = '0d2cffe505a7915bc183da38bf3aa7a8c966d47cec730a901342559779e8643d'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
SOURCE_COMMIT = 'e72669c33591bd73f5f3feb1c70425263855d34a'
REQUEST_PATH = Path('/home/agent/hia-v92-diagnostics-only-remote-r2-20261113-e26e/CONTROL-REQUEST-r2b.json')
ACTUAL = Path('/home/agent/hia-v92-diagnostics-only-source12-r2b-output-20261113-e26e')
CHECKS = []


def require(condition, label):
    CHECKS.append({'check': label, 'passed': bool(condition)})
    if not condition:
        raise AssertionError(label)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def raw_file(path, maximum=8 << 20, *, links=(1,)):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink in links and before.st_size <= maximum,
                'bounded regular raw: ' + str(path))
        raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(path.lstat()), 'stable full raw: ' + str(path))
    return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                 'identity': identity(before)}


def read_json(path, maximum=4 << 20):
    raw, pin = raw_file(path, maximum)
    return json.loads(raw), pin


def put(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    return raw_file(path, max(1, len(raw)))[1]


def body_pin_matches(path, expected):
    raw, pin = raw_file(path, 64 << 20, links=(1, 2))
    require(all(pin[k] == expected[k] for k in ('path', 'bytes', 'sha256', 'identity')),
            'exact actual original pin: ' + str(path))
    return raw


def closed_boundary(root, request):
    wrapper, wrapper_pin = read_json(root / 'OWNER-WRAPPER.json')
    owner, owner_pin = read_json(root / 'owner.json')
    bound_raw, bound_pin = raw_file(root / 'owner.json.request.json', 262144)
    bound = json.loads(bound_raw)
    command = [request['runtime']['executable'], '-I', '-S', '-B', request['worker_path'],
               '--request', str(REQUEST_PATH), '--request-sha256', REQUEST_SHA, '--output', str(root)]
    require(owner['schema'] == wrapper['schema'] == bound['schema'] == 'hepta.hia.selfhost-process-owner.v1',
            'owner schemas')
    require(owner['request_sha256'] == bound_pin['sha256']
            and wrapper['receipt_sha256'] == owner_pin['sha256']
            and owner['implementation_sha256'] == bound['implementation_sha256'] == OWNER_SHA
            and all(wrapper.get(k) == v for k, v in owner.items()), 'wrapper/raw request/receipt identity')
    require(bound['command'] == command and bound['cwd'] == str(root)
            and bound['env'] == request['environment']
            and bound['stdout_path'] == str(root / 'stdout.log')
            and bound['stderr_path'] == str(root / 'stderr.log')
            and bound['receipt_path'] == str(root / 'owner.json')
            and bound['qualification_seconds'] == owner['qualification_seconds'] == 20
            and bound['cleanup_seconds'] == owner['cleanup_seconds'] == 3, 'exact source12 operation')
    cleanup = owner['cleanup']
    require(owner['subreaper_enabled'] is True and owner['qualification_started'] is True
            and cleanup['attempted'] is True and cleanup['complete'] is True
            and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
            and cleanup['deadline_exceeded'] is False and cleanup['errors'] == []
            and cleanup['remaining_direct_children'] == [], 'bound ECHILD before any child body read')
    natural = (owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0
               and wrapper['supervisor_returncode'] == 0 and owner['timed_out'] is False
               and owner['exit_observed_before_deadline'] is True and owner['event_overflow'] is False
               and owner['interrupted_signals'] == [] and owner.get('owner_error') is None)
    event_kinds = {row['kind'] for row in owner['events']}
    natural = natural and event_kinds <= {'qualification_started', 'owned_child_observed',
        'qualification_exit_observed', 'owned_child_reaped'} and {'qualification_started',
        'qualification_exit_observed', 'owned_child_reaped'} <= event_kinds
    return {'owner': owner_pin, 'request': bound_pin, 'wrapper': wrapper_pin,
            'natural': natural, 'events': len(owner['events']), 'observed_echild': True}


def semantic_read(root, request, closure):
    report, report_pin = read_json(root / 'REPORT.json')
    final, final_pin = read_json(root / 'FINAL.json')
    require(report['expected_ids'] == report['loaded_ids'] == report['executed_ids']
            == report['success_ids'] == request['expected_ids'] and len(request['expected_ids']) == 12,
            'exact twelve loaded/executed/success IDs')
    require(all(report[key] == [] for key in ('failures', 'errors', 'skips', 'expected_failures',
        'unexpected_successes', 'loader_errors', 'forbidden_attempts')) and report['exception'] is None,
        'zero source12 anomalies')
    require(closure['natural'] and report['status'] == final['status']
            == 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY'
            and report['inputs_unchanged'] is True and final['closed'] is True
            and final['natural'] is True and final['errors'] == [], 'source12 natural PASS only')
    for name in ('INPUTS-BEFORE.json', 'INPUTS-AFTER.json', 'PARENT-INPUTS-BEFORE.json', 'PARENT-INPUTS-AFTER.json'):
        values, _ = read_json(root / name)
        require(values == request['inputs'], 'exact 27 identity snapshot: ' + name)
    for row in request['inputs']:
        if row['role'] == 'exact_runtime':
            raw, actual = raw_file(row['path'], 64 << 20, links=(row['identity'][5],))
        else:
            raw, actual = raw_file(row['path'])
        require(all(actual[key] == row[key] for key in actual), 'frozen input remains exact: ' + row['path'])
    inventory, inventory_pin = read_json(root / 'ORIGINALS.json')
    require(final['originals'] == inventory_pin, 'FINAL original-inventory pin')
    records = inventory['files_and_directories']
    require(len(records) == len({row['path'] for row in records}), 'unique actual inventory paths')
    total = 0
    for row in records:
        path = root / row['path']
        observed = path.lstat()
        if row['kind'] == 'regular':
            raw, pin = raw_file(path, 8 << 20, links=(1, 2))
            require(pin['bytes'] == row['bytes'] and pin['sha256'] == row['sha256']
                    and pin['identity'] == row['identity'], 'full indexed regular: ' + row['path'])
            total += len(raw)
        elif row['kind'] == 'symlink_fixture_not_followed':
            require(stat.S_ISLNK(observed.st_mode) and os.readlink(path) == row['target']
                    and identity(observed) == row['identity'], 'typed unchanged synthetic symlink: ' + row['path'])
        else:
            require(row['kind'] == 'directory' and stat.S_ISDIR(observed.st_mode), 'ordinary inventoried directory')
            # Parent adds ORIGINALS and FINAL only after the earlier inventory;
            # that root directory's timestamps are not claimed unchanged.
            require(identity(observed)[:5] == row['identity'][:5] if row['path'] == '.'
                    else identity(observed) == row['identity'], 'directory identity scope: ' + row['path'])
    require(total == inventory['bytes_fully_read'], 'full indexed source/IO bytes')
    case = root / 'fixtures/test_01_all460_originals_three_lists_and_missing5_relocate_exactly'
    folder = case / 'public/small/originals'
    index, index_pin = read_json(folder / 'INDEX.json')
    capture, capture_pin = read_json(case / 'public/small/SMALL-READBACK.json')
    require(capture['complete'] is True and capture['errors'] == []
            and capture['selected_count'] == 460 and capture['selected_bytes'] == 3012789
            and len(capture['files']) == 463, 'real synthetic 460+3 complete mover result')
    missing = ['hia-core-unpack-evidence/callers/integer-report.json',
               'hia-core-unpack-evidence/callers/numeric/numeric-report.json',
               'hia-core-unpack-evidence/callers/numeric/callers/report.json',
               'hia-core-unpack-evidence/callers/numeric/callers/progress.receipt.json',
               'hia-core-unpack-evidence/callers/numeric/callers/core-callers/report.json']
    require(index['missing_expected'] == capture['missing_expected'] == missing
            and index['expected_originals_all_present'] is False, 'same five missing reports stay explicit')
    index_raw = body_pin_matches(folder / 'INDEX.json', next(r['retained'] for r in capture['files'] if r['name'] == 'INDEX.json'))
    retained_rows = {r['name']: r for r in capture['files']}
    require(len(retained_rows) == 463 and len(list(folder.iterdir())) == 463, 'all fixed names unique and present')
    for name, row in retained_rows.items():
        body_pin_matches(folder / name, row['retained'])
        require(row['original']['bytes'] == row['retained']['bytes']
                and row['original']['sha256'] == row['retained']['sha256']
                and row['original']['identity'][:2] == row['retained']['identity'][:2]
                and row['retained']['identity'][5] == 1
                and row['accepted_complete_original'] is True and row['partial_not_promoted'] is False,
                'same-inode complete original relocation: ' + name)
    require(list((case / 'private/diagnostics').iterdir()) == [], 'all accepted private diagnostic names relocated')
    inventory_raw, _ = raw_file(folder / 'FULL-INVENTORY.jsonl', 64 << 20)
    inventory_rows = [json.loads(line) for line in inventory_raw.splitlines()]
    require([r['index'] for r in inventory_rows] == list(range(462)), 'synthetic full ZIP row sequence')
    chosen = {r['name']: r for r in index['selected']}
    with zipfile.ZipFile(case / 'private/original/fixture.zip') as archive:
        infos = archive.infolist()
        require(len(infos) == len(inventory_rows) == 462, 'synthetic full ZIP denominator includes unselected')
        for info, expected in zip(infos, inventory_rows):
            raw = archive.read(info)
            require(info.filename == expected['name'] and len(raw) == expected['bytes']
                    and sha256(raw).hexdigest() == expected['sha256']
                    and zlib.crc32(raw) & 0xffffffff == info.CRC == expected['crc32'],
                    'complete synthetic ZIP body CRC/SHA: ' + info.filename)
            if info.filename in chosen:
                require((folder / chosen[info.filename]['retained_name']).read_bytes() == raw,
                        'public diagnostic equals actual ZIP body: ' + info.filename)
    for method in request['expected_ids'][1:5]:
        case_root = root / 'fixtures' / method.split('.', 1)[1]
        result, _ = read_json(case_root / 'public/small/SMALL-READBACK.json')
        require(result['status'] == 'HOLD' and result['complete'] is False and result['errors']
                and len(result['files']) == 12 and all(x['partial_not_promoted'] for x in result['files']),
                'damaged fixture original preservation: ' + method)
    for number in (9, 11):
        method = request['expected_ids'][number - 1].split('.', 1)[1]
        value, _ = read_json(root / 'fixtures' / method / 'public/small/FINAL.json')
        require(value['status'] == 'DIAGNOSTIC_CUSTODY_HOLD' and 'closed_echild' not in value
                and 'diagnostic_capture' not in value, 'unconfirmed owner has no child-read result: ' + method)
    method = request['expected_ids'][9].split('.', 1)[1]
    value, _ = read_json(root / 'fixtures' / method / 'public/small/FINAL.json')
    require(value['status'] == 'DIAGNOSTIC_CUSTODY_HOLD' and value['closed_echild'] is True
            and value['complete_local_diagnostic_readback'] is False
            and len(value['diagnostic_capture']['files']) == 10, 'closed nonzero remains HOLD with originals')
    return {'report': report_pin, 'parent_final': final_pin, 'inventory': inventory_pin,
            'seconds': report['seconds'], 'positive_capture': capture_pin, 'positive_index': index_pin,
            'indexed_regular_bytes': total, 'indexed_paths': len(records),
            'all_12_method_IDs': request['expected_ids']}


def archive_all(root, output):
    records, total = [], 0
    archive = output / 'source12.actual-originals.tar.gz'
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'wb') as sink:
        with gzip.GzipFile(filename='', mode='wb', fileobj=sink, mtime=0, compresslevel=1) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                def visit(path):
                    nonlocal total
                    before = path.lstat()
                    relative = str(path.relative_to(root))
                    name = 'actual' if relative == '.' else 'actual/' + relative
                    item = tarfile.TarInfo(name)
                    item.uid, item.gid = before.st_uid, before.st_gid
                    item.mode = stat.S_IMODE(before.st_mode)
                    seconds, nanoseconds = divmod(before.st_mtime_ns, 1_000_000_000)
                    item.mtime = seconds
                    item.pax_headers = {'mtime': '%d.%09d' % (seconds, nanoseconds)}
                    row = {'path': relative, 'identity': identity(before)}
                    if stat.S_ISLNK(before.st_mode):
                        item.type = tarfile.SYMTYPE
                        item.linkname = os.readlink(path)
                        row.update(kind='symlink_not_followed', target=item.linkname)
                        tar.addfile(item)
                    elif stat.S_ISDIR(before.st_mode):
                        item.type = tarfile.DIRTYPE
                        row['kind'] = 'directory'
                        tar.addfile(item)
                        records.append(row)
                        for name in sorted(os.listdir(path)):
                            visit(path / name)
                        require(identity(path.lstat()) == identity(before), 'archive directory remained stable: ' + relative)
                        return
                    else:
                        raw, pin = raw_file(path, 8 << 20, links=(1, 2))
                        item.size = len(raw)
                        item.type = tarfile.REGTYPE
                        row.update(kind='regular', bytes=len(raw), sha256=pin['sha256'])
                        total += len(raw)
                        require(total <= 64 << 20, 'complete source12 archive body ceiling')
                        tar.addfile(item, io.BytesIO(raw))
                    require(identity(path.lstat()) == identity(before), 'archive original remained stable: ' + relative)
                    records.append(row)
                    require(len(records) <= 4096, 'archive entry ceiling')
                visit(root)
        sink.flush()
        os.fsync(sink.fileno())
    archive_raw, archive_pin = raw_file(archive, 64 << 20)
    index = {'actual' if r['path'] == '.' else 'actual/' + r['path']: r for r in records}
    restored, seen = 0, set()
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:gz') as tar:
        for item in tar:
            require(item.name in index and item.name not in seen, 'archive unique expected member: ' + item.name)
            seen.add(item.name)
            row = index[item.name]
            if row['kind'] == 'regular':
                require(item.isfile(), 'archive regular type')
                body = tar.extractfile(item).read()
                require(len(body) == row['bytes'] and sha256(body).hexdigest() == row['sha256'], 'archive full raw readback: ' + item.name)
                restored += len(body)
            elif row['kind'] == 'directory':
                require(item.isdir(), 'archive directory type')
            else:
                require(item.issym() and item.linkname == row['target'], 'archive symbolic-link metadata, no following')
    require(seen == set(index) and restored == total, 'complete archive full body and metadata readback')
    manifest = {'schema': 'hia.v92.diagnostic-source12.complete-archive.v1', 'source_commit': SOURCE_COMMIT,
                'source_request_sha256': REQUEST_SHA, 'archive': archive_pin,
                'total_regular_bytes': total, 'members': len(records), 'records': records,
                'regular_aliases_stored_as_separate_complete_bodies': True,
                'original_link_topology_in_identity_records': True,
                'all_regular_bodies_restored_and_hashed': True, 'no_original_deleted_or_changed': True}
    manifest_pin = put(output / 'ARCHIVE-MANIFEST.json', manifest)
    return archive_pin, manifest_pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700, exist_ok=False)
    result = {'schema': 'hia.v92.diagnostic-source12.independent-readback.v1',
              'status': 'HOLD', 'source_commit': SOURCE_COMMIT, 'source_request_sha256': REQUEST_SHA,
              'product_or_control_execution': False, 'network_requests': 0,
              'old_R4_owner_status': 'UNKNOWN_NOT_RECLASSIFIED', 'checks': CHECKS}
    try:
        request_raw, request_pin = raw_file(REQUEST_PATH, 1 << 20)
        require(request_pin['sha256'] == REQUEST_SHA, 'frozen source12 request SHA')
        request = json.loads(request_raw)
        require(request['output_root'] == str(ACTUAL), 'exact source12 actual root')
        closure = closed_boundary(ACTUAL, request)
        result['closed_owner'] = closure
        semantic_ok = False
        try:
            result['source12_semantics'] = semantic_read(ACTUAL, request, closure)
            semantic_ok = True
        except BaseException as exc:
            # A closed failure is still archived in full. This never promotes
            # an incomplete/failed source report or suppresses the audit error.
            result['source12_readback_error'] = {'type': type(exc).__name__, 'message': str(exc)}
        if args.archive:
            result['archive'], result['archive_manifest'] = archive_all(ACTUAL, args.output)
        if semantic_ok:
            result['status'] = 'SOURCE12_ACTUAL_READBACK_PASS_NOT_REMOTE_CUSTODY'
    except BaseException as exc:
        result['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        put(args.output / 'READBACK.json', result)
    return 0 if result['status'] == 'SOURCE12_ACTUAL_READBACK_PASS_NOT_REMOTE_CUSTODY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
