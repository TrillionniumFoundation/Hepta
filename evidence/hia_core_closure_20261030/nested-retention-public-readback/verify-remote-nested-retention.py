"""Read actual immutable public bytes; never execute archive members or tests."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / 'nested-retention-public-readback-manifest.json'
OUTPUT = ROOT / 'nested-retention-actual-remote-readback.json'
assert not OUTPUT.exists()
input_bytes = INPUT.read_bytes()
producer_bytes = Path(__file__).read_bytes()
manifest = json.loads(input_bytes)
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
items = []
for scope, commit, entries in [('evidence', manifest['immutable_evidence_commit'], manifest['files']),
                                ('source', manifest['source_commit'], manifest['source_files'])]:
    assert re.fullmatch('[0-9a-f]{40}', commit)
    assert len({e['repository_path'] for e in entries}) == len(entries)
    items.extend((scope, commit, e) for e in entries)


def download(item):
    scope, commit, entry = item
    path = entry['repository_path']
    assert not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
    url = 'https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/' + commit + '/' + path
    request = urllib.request.Request(url, headers={'User-Agent': 'Hepta-immutable-readback'})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(entry['bytes'] + 1)
        assert response.status == 200 and response.read(1) == b''
    assert len(data) == entry['bytes'], path
    sha = hashlib.sha256(data).hexdigest()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    assert sha == entry['sha256'] and blob == entry['git_blob_sha1'], path
    return {'scope': scope, 'commit': commit, 'path': path, 'url': url,
            'bytes': len(data), 'sha256': sha, 'git_blob_sha1': blob}, data


records = []
archives = {}
archive_paths = {a['path'] for a in manifest['archives']}
with ThreadPoolExecutor(max_workers=4) as pool:
    pending = [pool.submit(download, item) for item in items]
    for task in as_completed(pending):
        record, data = task.result()
        records.append(record)
        if record['scope'] == 'evidence' and record['path'] in archive_paths:
            archives[record['path']] = data
        if len(records) % 10 == 0 or len(records) == len(items):
            print(json.dumps({'actual_public_byte_streams_verified': len(records), 'total': len(items)}), flush=True)

archive_checks = []
for item in manifest['archives']:
    data = archives[item['path']]
    expanded = gzip.decompress(data) if item['compression'] == 'gz' else lzma.decompress(data)
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        members = archive.getmembers()
        assert len(members) == item['members'] and len({m.name for m in members}) == len(members)
        member_records = []
        for member in members:
            assert member.isfile() and not PurePosixPath(member.name).is_absolute()
            assert '..' not in PurePosixPath(member.name).parts and not member.mode & ~0o777
            raw = archive.extractfile(member).read()
            assert len(raw) == member.size
            member_records.append({'path': member.name, 'bytes': len(raw), 'mode': format(member.mode, '04o'), 'sha256': hashlib.sha256(raw).hexdigest()})
    archive_checks.append({'path': item['path'], 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                           'complete_compression_checksum': True, 'members': member_records,
                           'all_members_read_from_actual_remote_archive': True})
assert INPUT.read_bytes() == input_bytes and Path(__file__).read_bytes() == producer_bytes
report = {'schema': 'hepta.nested-retention-actual-public-readback.v1', 'ok': True,
          'started_utc': started, 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'immutable_evidence_commit': manifest['immutable_evidence_commit'], 'source_commit': manifest['source_commit'],
          'source_tree_from_publication_and_independent_static_review': manifest['source_tree'],
          'evidence_files': len(manifest['files']), 'source_files': len(manifest['source_files']),
          'downloaded_bytes': sum(r['bytes'] for r in records),
          'all_byte_counts_sha256_and_git_blobs_match': True,
          'files': sorted(records, key=lambda r: (r['scope'], r['path'])),
          'archives': archive_checks, 'whole_archive_files_written': False,
          'input_manifest_sha256': hashlib.sha256(input_bytes).hexdigest(),
          'producer_sha256': hashlib.sha256(producer_bytes).hexdigest(), 'producer_inputs_unchanged': True,
          'native_compiler_checker_or_test_executions': 0}
with OUTPUT.open('x') as out:
    out.write(json.dumps(report, indent=2) + '\n')
print(json.dumps({'ok': True, 'evidence_files': report['evidence_files'], 'source_files': report['source_files'],
                  'archives': len(archive_checks), 'receipt': str(OUTPUT)}), flush=True)
