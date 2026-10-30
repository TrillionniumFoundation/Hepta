from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path('/workspace/scratch/b484d4086829')
parser = argparse.ArgumentParser()
parser.add_argument('--commit', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
assert re.fullmatch(r'[0-9a-f]{40}', args.commit)
output = Path(args.output)
assert not output.exists()
manifest_path = ROOT / 'progress-publication-20261029/convergence-guard-p0-normalized-publication.json'
manifest_bytes = manifest_path.read_bytes()
manifest = json.loads(manifest_bytes)
entries = manifest['entries']
triage_map_path = ROOT / 'full-release-failure-triage-package-20261030/publication-files.json'
triage_bytes = triage_map_path.read_bytes()
triage = json.loads(triage_bytes)
entries += triage['files']
entries.append({'repository_path': triage['map_repository_path'], 'bytes': len(triage_bytes), 'sha256': hashlib.sha256(triage_bytes).hexdigest(), 'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(triage_bytes)).encode() + b'\0' + triage_bytes).hexdigest()})
assert len(entries) == 57 and len({e['repository_path'] for e in entries}) == 57
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
downloaded = {}
records = []
for i, entry in enumerate(entries, 1):
    path = entry['repository_path']
    url = 'https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/' + args.commit + '/' + path
    request = urllib.request.Request(url, headers={'User-Agent': 'Hepta-immutable-evidence-readback'})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(entry['bytes'] + 1)
        assert response.read(1) == b'' and response.status == 200
    assert len(data) == entry['bytes']
    digest = hashlib.sha256(data).hexdigest()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    assert digest == entry['sha256'] and blob == entry.get('git_blob_sha1', entry.get('git_blob'))
    records.append({'path': path, 'bytes': len(data), 'sha256': digest, 'git_blob_sha1': blob, 'url': url})
    if '.part' in Path(path).name:
        downloaded[path] = data
    if i % 10 == 0 or i == len(entries):
        print(json.dumps({'actual_remote_files_verified': i, 'total': len(entries)}), flush=True)

archives = []
for relative in ['integration-convergence-e0-evidence/publication-files.json', 'guard-fix-evidence/publication-files.json', 'returned-local-view-package-20261030/publication-files-final.json']:
    original = json.loads((ROOT / relative).read_text())
    archive = original['archive']
    parts = original.get('archive_parts')
    if parts is None:
        parts = [entry for entry in original['files'] if '.tar.gz.part' in entry['repository_path']]
        parts = sorted(parts, key=lambda item: item['repository_path'])
    total = 0
    digest = hashlib.sha256()
    blob = hashlib.sha1(b'blob ' + str(archive['bytes']).encode() + b'\0')
    for part in parts:
        if 'offset' in part:
            assert part['offset'] == total
        data = downloaded[part['repository_path']]
        total += len(data)
        digest.update(data)
        blob.update(data)
    assert total == archive['bytes']
    assert digest.hexdigest() == archive['sha256']
    assert blob.hexdigest() == archive.get('git_blob_sha1', archive.get('git_blob'))
    archives.append({'original_publication_map': relative, 'remote_parts': len(parts), 'bytes': total, 'sha256': digest.hexdigest(), 'git_blob_sha1': blob.hexdigest(), 'actual_ordered_remote_stream_reconstruction_passed': True})

report = {'schema': 'hepta.remote-convergence-evidence-readback.v1', 'started_utc': started, 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'immutable_evidence_commit': args.commit, 'local_normalized_manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(), 'actual_remote_files_downloaded': len(records), 'actual_remote_bytes_downloaded': sum(entry['bytes'] for entry in records), 'all_file_byte_counts_sha256_and_git_blobs_match': True, 'files': records, 'actual_ordered_archive_reconstructions': archives, 'native_or_test_reruns': 0, 'duplicate_whole_archive_files_written': False}
output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': 'PASS', 'actual_remote_files_downloaded': len(records), 'ordered_archives': len(archives), 'receipt': str(output)}), flush=True)
