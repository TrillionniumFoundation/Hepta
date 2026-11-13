"""Freeze existing SQLite source8 originals; this script never runs project code."""
from __future__ import annotations
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).resolve().parent
ACTUAL = Path('/home/agent/hia-sqlite-varint-source-eight-actual-r2-20261113-e26e')
REQUEST = Path('/home/agent/hia-sqlite-source8-r2-recovery-20261113-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
PEER = Path('/home/agent/hia-native-peer-reviews-20261113-e26e/sqlite-source8-r2-owner-static-review.json')
PREFIX = 'experiments/hia_sqlite_varint_20261113/source-eight-actual-r2/'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 16 << 20, 'bounded regular original')
        raw = stream.read()
        require(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), 'original identity changed')
    return {**pin(raw), 'path': str(path), 'identity': identity(before)}, raw


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(read(path)[1] == raw, 'written artifact readback')


def js(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def main():
    inputs = {}
    for label, root in (
            ('actual', ACTUAL),
            ('root-invocation', ROOT / 'sqlite-varint-source8-r2-invocation'),
            ('root-review', ROOT / 'sqlite-varint-source8-r2-review')):
        for path in sorted(root.rglob('*')):
            require(not path.is_symlink(), 'no symlink originals')
            if path.is_file():
                inputs[label + '/' + str(path.relative_to(root))] = path
    for name in ('REQUEST.json', 'LAUNCH.json', 'HANDOFF.json', 'STATIC-FREEZE.json',
                 'publication/PLAN.json', 'publication/CANONICAL.json', 'publication/JOURNAL.jsonl',
                 'publication/COMMIT.provider.json', 'publication/REF-GET.provider.json',
                 'publication/TREE-READBACK.json'):
        inputs['request/' + name] = REQUEST / name
    inputs['peer/sqlite-source8-r2-owner-static-review.json'] = PEER
    inputs['independent/AUDIT.json'] = HERE / 'AUDIT.json'
    inputs['independent/audit_actual.py'] = HERE / 'audit_actual.py'
    audit = json.loads((HERE / 'AUDIT.json').read_bytes())
    require(audit['status'] == 'INDEPENDENT_SOURCE8_AND1618_COMPLETE_VM_READBACK_PASS_ONLY', 'independent readback must pass')
    records = []
    originals = {}
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, path in sorted(inputs.items()):
            p, raw = read(path)
            records.append({'name': name, **p})
            originals[name] = raw
            item = tarfile.TarInfo(name)
            item.size = len(raw); item.mode = p['identity'][2] & 0o7777
            item.uid = p['identity'][3]; item.gid = p['identity'][4]
            seconds, nanoseconds = divmod(p['identity'][7], 1_000_000_000)
            item.mtime = seconds
            item.pax_headers['mtime'] = str(seconds) + '.' + str(nanoseconds).zfill(9)
            archive.addfile(item, io.BytesIO(raw))
    tar_raw = tar_buffer.getvalue()
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gzip_buffer, filename='', mode='wb', compresslevel=6, mtime=0) as compressor:
        compressor.write(tar_raw)
    compressed = gzip_buffer.getvalue()
    write(HERE / 'originals.tar.gz', compressed)
    parts = []
    for index, offset in enumerate(range(0, len(compressed), 384 << 10)):
        raw = compressed[offset:offset + (384 << 10)]
        text = base64.b64encode(raw) + b'\n'
        name = f'archive/part-{index:04}.b64'
        write(HERE / name, text)
        parts.append({'index': index, 'offset': offset, 'path': name, 'raw': pin(raw), 'text': pin(text)})
    manifest = {'schema': 'hia.sqlite-source8.complete-original-archive.v1',
                'actual_source8_executions': 1, 'new_native_or_C_executions': 0,
                'request_commit': '045f1ae1e88f9be6680f618bf220857c42a4cbbb',
                'files': records, 'file_count': len(records),
                'original_bytes': sum(p['bytes'] for p in records),
                'tar': pin(tar_raw), 'gzip': pin(compressed), 'parts': parts,
                'raw_source_base_not_duplicated': True,
                'source_reconstruction': 'The exact 1686 source files are identified by the four actual source manifests and the complete source8 request parent tree; this archive preserves those manifests, not a second 40 MB source checkout.',
                'metadata_scope': 'Original identity/uid/gid/mode/mtime/ctime are recorded. Reconstruction restores bytes, permission mode and mtime, not original inode or ctime.'}
    js(HERE / 'ARCHIVE-MANIFEST.json', manifest)
    spec = importlib.util.spec_from_file_location('sqlite_actual_restore_only', HERE / 'restore_originals.py')
    restore = importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)
    returned_manifest, recovered = restore.decode(HERE)
    require(returned_manifest == manifest and recovered == originals, 'every archived original restored byte for byte')
    for row in records:
        p, raw = read(Path(row['path']))
        require(p == {k: v for k, v in row.items() if k != 'name'} and raw == recovered[row['name']], 'original stable after whole archive readback')
    js(HERE / 'ARCHIVE-READBACK.json', {'status': 'COMPLETE_WHOLE_ORIGINAL_ARCHIVE_READBACK_PASS',
          'files': len(records), 'original_bytes': manifest['original_bytes'], 'gzip': manifest['gzip'],
          'tar': manifest['tar'], 'parts': len(parts), 'all_full_bodies_equal': True,
          'original_identity_unchanged_after': True, 'source_or_native_executed_by_packager': False})
    handoff = {'schema': 'hia.sqlite-source8.actual-handoff.v1', 'status': audit['status'],
          'request_commit': manifest['request_commit'], 'request_tree': '39119b916b03d067eb21be97adaa0f9140077eb1',
          'source_commit': audit['source_commit'], 'source_tree': audit['source_tree'],
          'actual_root': str(ACTUAL), 'independent_audit': pin((HERE / 'AUDIT.json').read_bytes()),
          'root_audit': pin((ROOT / 'sqlite-varint-source8-r2-invocation/READBACK.json').read_bytes()),
          'source8': {'expected': 8, 'loaded': 8, 'executed': 8, 'success': 8,
                      'vm_return_count': 1618, 'whole_buffer_independent_arithmetic': True,
                      'worker_elapsed_seconds': audit['worker_elapsed_seconds'],
                      'owner_qualification_seconds': 180, 'owner_cleanup_seconds': 3,
                      'natural_zero': True, 'bound_ECHILD': True},
          'actual_files': 22, 'actual_bytes': 4426961, 'frozen_input_files': 46,
          'physical_source_files': 1686, 'physical_source_bytes': 40890650,
          'generated': audit['generated'], 'complete_original_archive': {k:manifest[k] for k in ('file_count','original_bytes','gzip','tar')},
          'root_original_reader_hold': 'ROOT-OWNER-READER-R1-HOLD.original.json preserves the independent reader optional-key KeyError; no source8 execution was repeated.',
          'old_48path_publication': 'UNKNOWN boundary remains preserved by parent7ab75; not reposted or reclassified.',
          'old_R4_receiver': 'UNKNOWN; not polled, replayed, or promoted by this evidence.',
          'scope': ['Local CPython3.12.14 source/VM only.', 'Neither SQLite C oracle was compiled or executed.',
                    'No native HIA, SQL database, pager/WAL/durability, current matching-cold, installed or Full32 qualification is claimed.',
                    'Next work is an independently frozen finite native request with both original SQLite C oracles and a declared development compiler; no authorization is inferred from this PASS.']}
    js(HERE / 'HANDOFF.json', handoff)
    direct = {name: path for name, path in inputs.items()
              if not name.startswith('root-review/remote-bodies/') and not name.startswith('request/publication/')}
    for name in ('ARCHIVE-MANIFEST.json','ARCHIVE-READBACK.json','HANDOFF.json','restore_originals.py','package_actual.py'):
        direct[name] = HERE / name
    direct.update({p['path']: HERE / p['path'] for p in parts})
    new_files = []
    for name, path in sorted(direct.items()):
        p, raw = read(path)
        raw.decode('utf-8', errors='strict')
        new_files.append({'relative': PREFIX + name, 'local': str(path), 'mode': '100644',
                          **{k:p[k] for k in ('bytes','sha256','git_blob')}})
    plan = {'schema': 'hia.sqlite-source8.actual-publication-plan.v1',
            'parent_commit': manifest['request_commit'], 'base_tree': '39119b916b03d067eb21be97adaa0f9140077eb1',
            'old_leaves_expected':4222, 'prefix':PREFIX,
            'evidence_branch':'codex/hia-sqlite-varint-source8-r2-actual-20261113-e26e',
            'message':'Preserve one SQLite source8 r2 PASS and every original; native and SQL remain open [skip ci]',
            'new_files':new_files, 'unique_blobs':len({p['git_blob'] for p in new_files}),
            'new_raw_bytes':sum(p['bytes'] for p in new_files),
            'whole_original_archive_files':len(records), 'whole_original_archive_bytes':manifest['original_bytes'],
            'unknown_mutations_replayed':False, 'product_or_test_executions_by_publisher':0}
    js(HERE / 'publication/PLAN.json', plan)
    print(json.dumps({k:v for k,v in plan.items() if k != 'new_files'},sort_keys=True))


if __name__ == '__main__':
    main()
