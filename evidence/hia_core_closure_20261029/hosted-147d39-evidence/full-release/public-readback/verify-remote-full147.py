from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.request

ROOT = Path('/workspace/scratch/b484d4086829')
parser = argparse.ArgumentParser()
parser.add_argument('--commit', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
assert re.fullmatch(r'[0-9a-f]{40}', args.commit)
output = Path(args.output)
assert not output.exists()
manifest_path = ROOT / 'hosted-147d39-evidence/full-release/publication-metadata.json'
manifest_bytes = manifest_path.read_bytes()
manifest = json.loads(manifest_bytes)
parts = manifest['raw_parts']
original = manifest['source_archive']
assert len(parts) == 89 and sum(p['bytes'] for p in parts) == original['bytes']
total_sha = hashlib.sha256()
total_git = hashlib.sha1(b'blob ' + str(original['bytes']).encode() + b'\0')
offset = 0
records = []
attempts = []
started = time.time()
for part in parts:
    assert part['offset'] == offset
    url = 'https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/' + args.commit + '/' + part['repository_path']
    data = None
    for attempt in range(1, 4):
        before = time.monotonic_ns()
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'Hepta-evidence-readback'})
            with urllib.request.urlopen(request, timeout=45) as response:
                body = response.read(part['bytes'] + 1)
                assert response.read(1) == b'', 'Remote part exceeds recorded length'
                status = response.status
            assert len(body) == part['bytes'], 'Remote part byte count differs'
            actual_sha = hashlib.sha256(body).hexdigest()
            actual_git = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
            assert actual_sha == part['sha256'] and actual_git == part['git_blob_sha1'], 'Remote part digest differs'
            attempts.append({'part': part['part'], 'attempt': attempt, 'status': 'passed', 'http_status': status, 'wall_ns': time.monotonic_ns() - before})
            data = body
            break
        except Exception as error:
            attempts.append({'part': part['part'], 'attempt': attempt, 'status': 'failed', 'exception': repr(error), 'wall_ns': time.monotonic_ns() - before})
            output.with_suffix('.attempts.json').write_text(json.dumps(attempts, indent=2) + '\n')
            if attempt == 3:
                raise
            time.sleep(attempt)
    assert data is not None
    total_sha.update(data)
    total_git.update(data)
    offset += len(data)
    records.append({'part': part['part'], 'path': part['repository_path'], 'offset': part['offset'], 'bytes': len(data), 'sha256': actual_sha, 'git_blob_sha1': actual_git, 'url': url})
    if part['part'] % 10 == 0 or part['part'] == len(parts):
        print(json.dumps({'downloaded_and_verified_parts': part['part'], 'ordered_bytes': offset}), flush=True)
assert offset == original['bytes']
assert total_sha.hexdigest() == original['sha256']
assert total_git.hexdigest() == original['git_blob_sha1']
report = {'schema': 'hepta.remote-full147-stream-reconstruction.v1', 'evidence_commit': args.commit, 'publication_map_sha256': hashlib.sha256(manifest_bytes).hexdigest(), 'source_commit': manifest['source_commit'], 'original_artifact': manifest['artifact_id'], 'actual_remote_parts_downloaded': len(records), 'download_attempts': attempts, 'parts': records, 'ordered_complete_bytes': offset, 'complete_sha256': total_sha.hexdigest(), 'complete_git_blob_sha1': total_git.hexdigest(), 'actual_ordered_stream_reconstruction_passed': True, 'duplicate_whole_zip_written': False, 'original_zip_content_crc_audit': 'Retained independently; this readback reconstructed the exact original byte stream without unpacking or executing its members.', 'wall_seconds': time.time() - started, 'native_or_test_reruns': 0}
output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': 'passed', 'actual_remote_parts_downloaded': len(records), 'ordered_complete_bytes': offset, 'complete_sha256': total_sha.hexdigest(), 'receipt': str(output)}), flush=True)
