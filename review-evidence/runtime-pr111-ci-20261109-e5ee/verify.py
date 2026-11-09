from pathlib import Path
import hashlib
import io
import json
import tarfile

ROOT = Path(__file__).resolve().parent
summary = json.loads((ROOT / 'preservation.json').read_text())
manifest_raw = (ROOT / 'original-files.json').read_bytes()
assert hashlib.sha256(manifest_raw).hexdigest() == summary['original_manifest_sha256']
manifest = json.loads(manifest_raw)
expected = {row['path']: (row['bytes'], row['sha256']) for row in manifest['files']}
assert len(expected) == len(manifest['files'])
expected['evidence-manifest.json'] = (len(manifest_raw), hashlib.sha256(manifest_raw).hexdigest())
raw = (ROOT / 'original-ci-records.tar.xz').read_bytes()
assert len(raw) == summary['archive_bytes']
assert hashlib.sha256(raw).hexdigest() == summary['archive_sha256']
seen = {}
with tarfile.open(fileobj=io.BytesIO(raw), mode='r|xz') as archive:
    for entry in archive:
        assert entry.isfile() and entry.name in expected and entry.name not in seen
        data = archive.extractfile(entry).read()
        identity = (len(data), hashlib.sha256(data).hexdigest())
        assert identity == expected[entry.name], entry.name
        seen[entry.name] = identity
assert seen == expected
assert len(seen) == summary['original_file_count'] == 14
assert sum(v[0] for v in seen.values()) == summary['original_file_bytes']
print(json.dumps({'status': 'PASS_ORIGINAL_CI_FILE_IDENTITY', 'original_files': len(seen), 'archive_sha256': summary['archive_sha256'], 'job_reexecutions': 0, 'runtime_executions': 0, 'real_mac_activation': False}, indent=2, sort_keys=True))

