#!/usr/bin/python3
"""Project exact completed evidence without changing original receipts."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

DEST = Path('/tmp/hepta-next-evidence-staging-20261028/evidence/audits/p0_p7_partial_records_incremental')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stable_bytes(path):
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError('Non-regular input: ' + str(path))
    data = path.read_bytes()
    after = path.stat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if key(before) != key(after) or len(data) != after.st_size:
        raise ValueError('Evidence changed while reading: ' + str(path))
    return data


def pack(name, roots):
    archive = DEST / 'archives' / (name + '.tar.gz')
    archive.parent.mkdir(parents=True, exist_ok=True)
    members, omitted = [], []
    with archive.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for prefix, source in roots:
                source = Path(source)
                paths = [source] if source.is_file() else sorted(source.rglob('*'))
                for path in paths:
                    if '__pycache__' in path.parts or path.suffix == '.pyc':
                        continue
                    if path.is_symlink():
                        # External pinned tool links are identities, not portable
                        # archive files. Never create extraction-time symlinks.
                        target = path.resolve(strict=True)
                        data = stable_bytes(target)
                        omitted.append({'original_path': str(path), 'bytes': len(data),
                                        'sha256': digest(data), 'symlink_target': str(target),
                                        'reason': 'external tool symlink identified; target binary excluded from public text projection'})
                        continue
                    if path.is_dir():
                        continue
                    data = stable_bytes(path)
                    item = {'original_path': str(path), 'bytes': len(data), 'sha256': digest(data)}
                    if data.startswith(b'\x7fELF') or path.suffix in {'.o', '.so', '.a'}:
                        omitted.append({**item, 'reason': 'native binary identity retained; binary excluded from public text projection'})
                        continue
                    # This review contains generated source, static inputs,
                    # text process streams and JSON receipts, never model data.
                    data.decode('utf-8')
                    relative = path.name if source.is_file() else str(path.relative_to(source))
                    member = prefix + '/' + relative
                    if member.startswith('/') or '..' in Path(member).parts:
                        raise ValueError('Unsafe archive member')
                    info = tarfile.TarInfo(member)
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    tar.addfile(info, io.BytesIO(data))
                    members.append({**item, 'member': member})
    # Independently reopen the sealed archive and compare every exact byte hash.
    with tarfile.open(archive, 'r:gz') as tar:
        actual = tar.getmembers()
        if len(actual) != len(members) or len({x.name for x in actual}) != len(actual):
            raise ValueError('Archive inventory mismatch')
        for info, wanted in zip(actual, members):
            data = tar.extractfile(info).read()
            if info.name != wanted['member'] or len(data) != wanted['bytes'] or digest(data) != wanted['sha256']:
                raise ValueError('Archive roundtrip mismatch')
    data = archive.read_bytes()
    report = {'schema': 'hepta.evidence.text-archive.v1', 'archive': str(archive.relative_to(DEST)),
              'bytes': len(data), 'sha256': digest(data), 'members': members, 'omitted': omitted,
              'roundtrip_bytes_verified': True, 'original_receipts_rewritten': False,
              'original_108762ba_archive_included': False, 'raw_model_payload_included': False}
    manifest = DEST / 'archives' / (name + '.manifest.json')
    with manifest.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    return {key: report[key] for key in ('archive', 'bytes', 'sha256', 'roundtrip_bytes_verified')} | {
        'member_count': len(members), 'native_binaries_identified_but_omitted': len(omitted)}


if __name__ == '__main__':
    results = []
    results.append(pack('development', [
        ('p1-partial', '/tmp/hepta-partial-v3-validation-20261028'),
        ('p1-independent-admission', '/tmp/hepta-p1-partial-readonly-review-20261028'),
        ('p6-incremental', '/tmp/hepta-p6-incremental-development-20261028'),
        ('root-independent-tests', '/tmp/hepta-next-independent-dev-20261028'),
        ('partial-qualifier-development', '/tmp/hepta-next-partial-qualifier-dev-20261028'),
        ('cpp-constexpr-development', '/tmp/hepta-cpp-constexpr-audit-20261028'),
    ]))
    results.append(pack('partial-record-native', [
        ('frozen-run', '/tmp/hepta-partial-record-final-d942f18b-20261028'),
        ('driver', '/tmp/hepta-next-partial-native-preparation-20261028/run_partial.py'),
    ]))
    results.append(pack('cpp-constexpr-native', [
        ('frozen-run', '/tmp/hepta-cpp-constexpr-final-d942f18b-20261028'),
        ('driver', '/tmp/hepta-cpp-constexpr-audit-20261028/run_frozen_native.py'),
    ]))
    print(json.dumps(results, sort_keys=True))
