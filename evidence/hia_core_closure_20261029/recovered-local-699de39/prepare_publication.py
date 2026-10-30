from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
PREFIX = 'evidence/hia_core_closure_20261029/recovered-local-699de39/'

def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': '100755' if path.stat().st_mode & 0o111 else '100644'}

def save(path, value):
    with path.open('x') as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

helper_result = json.loads((BASE / 'restore-helper-v2.stdout.log').read_text())
helper_binary = BASE / 'second-package/helper-reassembled-second-v2.tar.gz'
assert helper_result['bytes'] == 16084731
assert helper_result['sha256'] == identity(helper_binary)['sha256'] == '5f460c4e1e2165b1752d4cc6c5143ef86d483459e7697043573a715ee66da0a2'
assert (BASE / 'restore-helper-v2.stderr.log').read_bytes() == b''
save(BASE / 'helper-readback.json', {
    'schema': 'hepta.recovered-second-helper-readback.v1',
    'recorded_utc': datetime.now(timezone.utc).isoformat(),
    'actual_command': ['python', 'archive-recovery-20261029-evening/restore_second_package.py', '--output',
                       'archive-recovery-20261029-evening/second-package/helper-reassembled-second-v2.tar.gz'],
    'observed_exit_code': 0,
    'source_identity_observed_after_execution': identity(BASE / 'restore_second_package.py'),
    'stdout': identity(BASE / 'restore-helper-v2.stdout.log'),
    'stderr': identity(BASE / 'restore-helper-v2.stderr.log'),
    'output': identity(helper_binary),
    'whole_bytes_equal_original_archive': helper_binary.read_bytes() == (BASE / 'second-package/final-699de39-evidence.tar.gz').read_bytes(),
    'language_or_native_qualification_execution': False,
})

names = [
    'README.md', 'known-original-identities.json', 'recovery-summary.json',
    'second-package-readback.json', 'second-package-member-inventory.json',
    'recover_known_blobs.py', 'verify_and_restore_second_package.py', 'restore_second_package.py',
    'prepare_publication.py', 'helper-readback.json', 'helper-history/restore_second_package_v1.py',
    'recovery.stdout.log', 'recovery.stderr.log', 'readback.stdout.log', 'readback.stderr.log',
    'restore-helper.stdout.log', 'restore-helper.stderr.log',
    'restore-helper-v2.stdout.log', 'restore-helper-v2.stderr.log',
]
names += [f'{kind}/part-{i:04d}-recovery.json' for kind in ('second-package', 'third-package') for i in range(1, 5)]

scanner_source = BASE / 'second-package/restored/payload/final-evidence-699de39/evidence_common.py'
spec = importlib.util.spec_from_file_location('recovered_original_scanner', scanner_source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
scanner = module.FiniteCredentialScanner()
for name in names:
    with (BASE / name).open('rb') as data:
        scanner.scan_stream(data, name)
scan = scanner.report()
assert scan['passed'] and not scan['findings']
scan['current_scope'] = 'New small public recovery controls only; recovered archive bytes retain their original complete scan and exact identity.'
scan['scanner_original_identity'] = identity(scanner_source)
save(BASE / 'recovery-controls-scan.json', scan)
names.append('recovery-controls-scan.json')
names += [f'second-package/final-699de39-evidence.tar.gz.part{i:04d}' for i in range(1, 5)]
rows = []
for name in names:
    path = BASE / name
    assert path.is_file() and not path.is_symlink()
    rows.append({'path': name, 'local_path': str(path), 'repository_path': PREFIX + name, **identity(path)})
map_path = BASE / 'publication-payloads.json'
save(map_path, {'schema': 'hepta.local-evidence-recovery-publication.v1',
    'source_commit': '699de39a8e92e0f083df316ecc5333fb3ecf8571',
    'repository_prefix': PREFIX, 'payload_count': len(rows), 'payloads': rows,
    'also_publish_this_map': True,
    'map_repository_path': PREFIX + 'publication-payloads.json',
    'original_second_archive_recovered': True,
    'original_third_archive_recovered': False,
    'first_audit_omission_explicit': True,
    'whole_archive_or_expanded_tree_duplicated_as_payload': False,
    'github_mutations_performed_by_recovery': False,
    'native_or_language_tests_executed': False,
})
print(json.dumps({'payloads': len(rows), 'bytes': sum(row['bytes'] for row in rows),
                  'map_identity': identity(map_path)}, ensure_ascii=False))
