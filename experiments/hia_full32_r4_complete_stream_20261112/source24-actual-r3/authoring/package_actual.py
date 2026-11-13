"""Package fixed, already-read public SOURCE24 originals; never rerun controls."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).resolve().parent
PUB = HERE / 'publication'
PARENT = 'c448d90f6bc7ec8db4dab3d11d85c20a89b55aa9'
TREE = '8983e55a8e2d58f39756bc5b825a004be40cbaf2'
PREFIX = 'experiments/hia_full32_r4_complete_stream_20261112/source24-actual-r3'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def read(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1
    raw = path.read_bytes()
    now = path.lstat()
    assert all(getattr(s, 'st_' + k) == getattr(now, 'st_' + k) for k in
               ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'))
    return raw, s


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    assert read(path)[0] == raw


def main():
    PUB.mkdir(exist_ok=False)
    original = json.loads(read(HERE / 'ORIGINALS-MANIFEST.json')[0])
    report = json.loads(read(HERE / 'AUDIT-r2.json')[0])
    assert report['status'] == 'SOURCE24_ACTUAL_ORIGINALS_INDEPENDENT_READBACK_PASS_ONLY'
    assert report['checks_passed'] == 118
    replay = {
        'schema': 'hia.source24-r3.actual-replay.v1',
        'scope': 'Read already completed evidence only; never execute frozen controls or owner.',
        'original_reader_command': 'python3 -I -S -B audit_actual.py --collect --check-live-inputs --output AUDIT.json',
        'original_reader_result': 'HOLD only because the expected original output also has an empty tmp directory; report and source are preserved.',
        'corrected_actual_reader_command': 'python3 -I -S -B audit_actual_r2.py --collect --check-live-inputs --output AUDIT-r2.json',
        'portable_evidence_replay_command': 'python3 -I -S -B audit_actual_r2.py --root RESTORED_ROOT --output NEW_AUDIT_OUTPUT.json',
        'live_input_option': '--check-live-inputs additionally requires original fixed paths and reads the complete pinned interpreter and eleven control files; no executable is invoked.',
        'complete_archive_members_expected': 45,
        'original_runtime_binary_archived': False,
        'original_runtime_full_read_performed': True,
        'source_control_parent': PARENT,
        'source_control_parent_tree': TREE,
        'restoration': 'Concatenate decoded ordered archive parts, verify complete gzip seal, then inspect every original tar member against ARCHIVE-MANIFEST.json before restoring regular files to a fresh directory. Never execute embedded Root invoker or any original control as part of readback.'}
    write(HERE / 'REPLAY.json', encode(replay))
    source_rows = []
    for row in original['files']:
        source_rows.append(('originals/' + row['relative'], HERE / 'originals' / row['relative'], row['original_identity']))
    for name in ('ORIGINALS-MANIFEST.json', 'audit_actual.py', 'audit_actual_r2.py',
                 'AUDIT.json', 'AUDIT-r2.json', 'READER-CORRECTION-r2.json',
                 'REPLAY.json', 'package_actual.py'):
        raw, s = read(HERE / name)
        source_rows.append((name, HERE / name, {'mode': s.st_mode, 'uid': s.st_uid,
                            'gid': s.st_gid, 'mtime_ns': s.st_mtime_ns}))
    assert len(source_rows) == 45
    archive = PUB / 'all-public-originals.tar.gz'
    rows = []
    with archive.open('xb') as raw_out:
        with gzip.GzipFile(fileobj=raw_out, mode='wb', filename='', compresslevel=6, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for name, path, metadata in sorted(source_rows):
                    data, _ = read(path)
                    ti = tarfile.TarInfo(name)
                    ti.size = len(data); ti.type = tarfile.REGTYPE
                    ti.mode = stat.S_IMODE(metadata['mode'])
                    ti.uid = metadata['uid']; ti.gid = metadata['gid']
                    sec, nano = divmod(metadata['mtime_ns'], 1_000_000_000)
                    ti.mtime = sec
                    ti.pax_headers = {'mtime': str(sec) + '.' + f'{nano:09d}'}
                    tar.addfile(ti, io.BytesIO(data))
                    rows.append({'path': name, 'bytes': len(data), 'sha256': sha(data),
                                 'git_blob': blob(data), 'mode': ti.mode, 'uid': ti.uid,
                                 'gid': ti.gid, 'mtime_exact': ti.pax_headers['mtime']})
        raw_out.flush(); os.fsync(raw_out.fileno())
    archive_raw, _ = read(archive)
    by_name = {r['path']: r for r in rows}
    observed = []
    with tarfile.open(archive, mode='r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.name in by_name
            assert member.name not in observed
            row = by_name[member.name]
            body = tar.extractfile(member).read()
            assert len(body) == row['bytes'] and sha(body) == row['sha256'] and blob(body) == row['git_blob']
            assert (member.mode, member.uid, member.gid, member.pax_headers.get('mtime')) == (
                row['mode'], row['uid'], row['gid'], row['mtime_exact'])
            assert body == read(HERE / member.name)[0]
            observed.append(member.name)
    assert observed == sorted(by_name) and len(observed) == 45
    parts = []
    for ordinal, offset in enumerate(range(0, len(archive_raw), 65536)):
        chunk = archive_raw[offset:offset + 65536]
        encoded = base64.b64encode(chunk) + b'\n'
        name = f'archive-part-{ordinal:03}.base64'
        write(PUB / name, encoded)
        assert base64.b64decode(read(PUB / name)[0][:-1], validate=True) == chunk
        parts.append({'ordinal': ordinal, 'path': name, 'offset': offset, 'raw_bytes': len(chunk),
                      'raw_sha256': sha(chunk), 'bytes': len(encoded), 'sha256': sha(encoded), 'git_blob': blob(encoded)})
    recovered = b''.join(base64.b64decode(read(PUB / r['path'])[0][:-1], validate=True) for r in parts)
    assert recovered == archive_raw
    archive_manifest = {'schema': 'hia.cold.source24-r3.complete-public-archive.v1',
        'canonical_parent': PARENT, 'archive': {'bytes': len(archive_raw), 'sha256': sha(archive_raw)},
        'ordered_parts': parts, 'regular_files': rows, 'regular_count': len(rows),
        'uncompressed_file_bytes': sum(r['bytes'] for r in rows),
        'all_members_full_body_metadata_readback': True,
        'source24_original_regular_count': 7, 'source24_original_regular_bytes': 16258,
        'actual_empty_tmp_directory_recorded_in_manifest': True,
        'no_private_provider_or_proxy_values_included': True,
        'runtime_external_pin_not_runtime_binary': True}
    write(PUB / 'ARCHIVE-MANIFEST.json', encode(archive_manifest))
    selected = {
        'audit/AUDIT-r2.json': HERE / 'AUDIT-r2.json',
        'audit/audit_actual_r2.py': HERE / 'audit_actual_r2.py',
        'audit/ORIGINALS-MANIFEST.json': HERE / 'ORIGINALS-MANIFEST.json',
        'audit/READER-CORRECTION-r2.json': HERE / 'READER-CORRECTION-r2.json',
        'audit/REPLAY.json': HERE / 'REPLAY.json',
        'history/AUDIT-r1-HOLD.json': HERE / 'AUDIT.json',
        'history/audit_actual_r1.py': HERE / 'audit_actual.py',
        'authoring/package_actual.py': HERE / 'package_actual.py',
        'archive/ARCHIVE-MANIFEST.json': PUB / 'ARCHIVE-MANIFEST.json'}
    for row in original['files']:
        if row['relative'].startswith(('actual/', 'owner/', 'root-invocation/')) or row['relative'] == 'root-review/ROOT-REVIEW.json':
            selected['originals/' + row['relative']] = HERE / 'originals' / row['relative']
    for part in parts:
        selected['archive/' + part['path']] = PUB / part['path']
    files = []
    for relative, path in sorted(selected.items()):
        body, _ = read(path)
        body.decode('utf-8')
        assert len(body) < 1 << 20
        files.append({'relative': relative, 'local': str(path), 'bytes': len(body),
                      'sha256': sha(body), 'git_blob': blob(body)})
    plan = {'schema': 'hia.cold.source24-r3.actual-publication-plan.v1',
            'repository': 'TrillionniumFoundation/Hepta', 'parent': PARENT, 'base_tree': TREE,
            'prefix': PREFIX, 'files': files, 'create_ref': False,
            'original_source24_execution_repeated': False,
            'historical_supplier_and_receiver_HOLD_unchanged': True,
            'archive_body_count': len(rows), 'archive_body_bytes': sum(r['bytes'] for r in rows)}
    write(PUB / 'PLAN.json', encode(plan))
    print(json.dumps({'archive_bytes': len(archive_raw), 'archive_original_files': len(rows),
                      'archive_original_bytes': sum(r['bytes'] for r in rows),
                      'publication_files': len(files), 'publication_bytes': sum(r['bytes'] for r in files),
                      'plan_sha256': sha(read(PUB / 'PLAN.json')[0])}))


if __name__ == '__main__':
    main()
