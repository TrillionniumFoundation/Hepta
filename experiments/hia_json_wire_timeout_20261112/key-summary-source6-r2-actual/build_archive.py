"""Seal existing closed source6 originals; no project imports or execution."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
REQUEST = Path('/tmp/hia-wire-key-summary-cache-r2-20261112-e26e')
ACTUAL = Path('/tmp/hia-wire-key-summary-source6-r2-output-20261112-e26e')
OUT = Path('/tmp/hia-wire-key-summary-source6-r2-actual-r1-20261112-e26e')
PREFIX = 'experiments/hia_json_wire_timeout_20261112/key-summary-source6-r2-actual/'
PARENT = 'cb51003c4a0305f32cc5908ec3b09e4955ffd07e'
PARENT_TREE = 'e630a9a5bde00e82aee06a9e00e7469130d3777e'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path):
    assert path.resolve() == path
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, str(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        expected = {key: getattr(before, key) for key in FIELDS}
        assert {key: getattr(os.fstat(fd), key) for key in FIELDS} == expected
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        assert {key: getattr(os.fstat(fd), key) for key in FIELDS} == expected
        assert {key: getattr(path.lstat(), key) for key in FIELDS} == expected
    finally:
        os.close(fd)
    assert len(raw) == before.st_size
    return {'path': str(path), 'mode': stat.S_IMODE(before.st_mode),
            'identity': expected, **digest(raw)}, raw


def save(name, raw):
    with (OUT / name).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


OUT.mkdir(mode=0o700)
(OUT / 'publication').mkdir(mode=0o700)
readback_pin, readback_raw = read(ROOT / 'wire04-source6-invocation-r2/READBACK.json')
assert readback_pin['bytes'] == 14682
assert readback_pin['sha256'] == '3b836bac4eac8f8dfecf59c6850fe4697694ecd0934cce877ac71dd02fd0cb21'
readback = json.loads(readback_raw)
assert readback['status'] == 'SOURCE6_PASS_ONLY' and readback['tests_run'] == 6
assert readback['canonical_request_commit'] == PARENT
actual_paths = sorted(p for p in ACTUAL.rglob('*') if p.is_file())
assert len(actual_paths) == len(readback['all_originals']) == 20
paths = [('actual/' + p.relative_to(ACTUAL).as_posix(), p) for p in actual_paths]
paths.extend(('root-invocation/' + p.name, p)
             for p in sorted((ROOT / 'wire04-source6-invocation-r2').iterdir()) if p.is_file())
paths.extend(('request-publication/' + p.name, p)
             for p in sorted((REQUEST / 'publication').iterdir()) if p.is_file())
paths.extend(('root/' + name, ROOT / name) for name in (
    'audit_wire04_source6_r2.py', 'prepare_wire04_source6_r2.py',
    'build_wire04_source6_r2_actual.py'))
paths.extend(('request/' + name, REQUEST / name) for name in (
    'SOURCE6-REQUEST.json', 'SOURCE6-LAUNCH.json', 'HANDOFF.json',
    'PREEXEC.json', 'STATIC-AUDIT-final.json', 'STATIC-PROTOCOL-SPEC.json',
    'REPAIR-RATIONALE.json', 'GENERATOR-r1-to-r2.diff', 'LAUNCHER-r1-to-r2.diff'))
paths.sort()
assert len(paths) == len({name for name, _ in paths})
members, bodies = [], {}
for name, path in paths:
    pin, raw = read(path)
    if name.startswith('actual/'):
        expected = readback['all_originals'][path.relative_to(ACTUAL).as_posix()]
        assert {key: pin[key] for key in ('path', 'bytes', 'sha256', 'identity')} == expected, name
    members.append({'archive_path': name, **pin})
    bodies[name] = raw
archive_path = OUT / 'originals.tar.gz'
with archive_path.open('xb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as archive:
    for row in members:
        entry = tarfile.TarInfo(row['archive_path'])
        entry.size, entry.mode, entry.mtime = row['bytes'], row['mode'], 0
        archive.addfile(entry, io.BytesIO(bodies[row['archive_path']]))
with tarfile.open(archive_path, 'r:gz') as archive:
    entries = archive.getmembers()
    assert len(entries) == len(members)
    for row, entry in zip(members, entries, strict=True):
        assert entry.isfile() and entry.name == row['archive_path'] and entry.mode == row['mode']
        restored = archive.extractfile(entry).read()
        assert restored == bodies[entry.name]
        assert digest(restored) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
archive_raw = archive_path.read_bytes()
parts = []
for index, offset in enumerate(range(0, len(archive_raw), 256 << 10)):
    chunk = archive_raw[offset:offset + (256 << 10)]
    encoded = base64.b64encode(chunk) + b'\n'
    name = f'originals-{index:03d}.base64'
    save(name, encoded)
    parts.append({'path': name, 'offset': offset, 'raw_bytes': len(chunk), **digest(encoded)})
assert b''.join(base64.b64decode((OUT / p['path']).read_bytes().strip(), validate=True) for p in parts) == archive_raw
report = {'schema': 'hepta.root.wire04.source6-r2-actual-archive.v1',
          'status': 'SOURCE6_PASS_ONLY', 'parent': PARENT, 'parent_tree': PARENT_TREE,
          'canonical_request': json.loads((REQUEST / 'publication/CANONICAL.json').read_bytes()),
          'members': members, 'member_count': len(members),
          'original_bytes': sum(row['bytes'] for row in members),
          'all_twenty_actual_originals_and_complete_member_bytes_read': True,
          'all_member_bytes_independently_restored_and_compared': True,
          'archive': digest(archive_raw), 'parts': parts,
          'source6': readback,
          'prior_r1_HOLD_preserved_in_parent': True,
          'current_native_cold_installed_full89_old7_new6_native_executed': False,
          'old_256_case_5_second_assertion_modified': False,
          'whole_rewrite_closed': False, 'default_activated': False,
          'legacy_product_deleted': False}
save('ARCHIVE.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
save('READBACK.json', readback_raw)
save('json_wire.hiaasm', bodies['actual/json_wire.hiaasm'])
save('build_archive.py', (ROOT / 'build_wire04_source6_r2_actual.py').read_bytes())
status = '''# Wire protocol 04: second source qualification, actual originals

The six exact source methods passed once under the original 180-second owner and
3-second cleanup. The worker took 9.541171217 seconds, including 2.284256043 seconds
to generate the HIA source. The owner exited naturally with code 0 and recorded
all four expected lifecycle events and ECHILD; no descendant remained.

All 539 original source inputs and all 543 pinned inputs remained byte-identical.
The only new source file is the generated HIA assembly, 361,637 bytes, SHA-256
f4e353af23b251d645dee41596dd590820322af4bce5b2545375b74f8eed36a5.
Its 53 functions, 909 blocks, 7,208 operations and maximum 1,945 SSA values per
function satisfy the original fixed limits. There were no failures, errors,
skips, expected failures, unexpected successes or forbidden execution attempts.

The first source request remains a recorded HOLD: the unchanged verifier rejected
an unnamed intermediate crossing a short-circuit block. The second request uses
a named intermediate and an explicit conditional, preserving the arithmetic and
all verifier limits. It does not change the Builder or verifier. The request and
the first actual failure are retained in parent cb51003c4a0305f32cc5908ec3b09e4955ffd07e.

The archive contains all 20 actual originals plus root readback, invocation,
request and publication receipts. Every archive member was restored and compared
against its complete original byte string. ARCHIVE.json contains their original
physical identities and complete SHA-256 and Git blob hashes.

This result qualifies only the six source methods. The original native 89-method
group and its 256-case, 5-second assertion, the original native seven cache tests,
the additional native six tests, fresh Cold, installed behavior and the complete
rewrite are still unqualified for this candidate. No default was changed and no
legacy product source was deleted.
'''
save('STATUS.md', status.encode())
files = [{'path': PREFIX + p.name, 'local': str(p), 'mode': '100644', **digest(p.read_bytes())}
         for p in sorted(OUT.iterdir()) if p.is_file() and p.name != 'originals.tar.gz']
save('publication/FILES.json', (json.dumps(files, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps({'members': len(members), 'original_bytes': report['original_bytes'],
                  'archive': report['archive'], 'parts': len(parts), 'git_files': len(files)}, sort_keys=True))
