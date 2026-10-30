from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

BASE = Path(__file__).resolve().parent
API = 'https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/'
DECLARATIONS = {
    'second-package': {
        'whole_bytes': 16084731,
        'whole_sha256': '5f460c4e1e2165b1752d4cc6c5143ef86d483459e7697043573a715ee66da0a2',
        'scope': 'Original second archive; it omitted the first 16-file independent audit despite the README retention claim. It is not relabelled as the final third archive.',
        'parts': [
            ('fd67940303e6a79015c992ad796be2a9cefef322', 4194304, '0009aafdeef6458e531fc79406e38806a5586632922880373ef847e91e2bbe39'),
            ('e51cf3120992b0db0a2e69c2a533e91ffff26c7d', 4194304, 'e68429cf6e447ce1eccee9d8a2f804bb11b7c95aec38c710adbf44720b1f562c'),
            ('ec0066e186d172087f6c2c165a306d57b0bbc523', 4194304, 'ad38ed810f0d4a88e7c177132cd740e570a44dab763de7bb5b0e512f1ff236ac'),
            ('bb8c73d10e5c4a9377bb17e28ad5b198832c5fc6', 3501819, '187d73cffdbddde13a87fdf00f6d3ebc8b4c038e93085a0a6492e4ff44c6b5a7'),
        ],
    },
    'third-package': {
        'whole_bytes': 16375670,
        'whole_sha256': '9bcc40d851b7b6bc16ad7b11a9f6d27e2ed27afbf322463bc89d203159d53de2',
        'scope': 'Final third archive, originally reviewed as 513 source files and 550 TAR members. Upload completion was interrupted; availability is measured, not inferred.',
        'parts': [
            ('7e87efaa2a4a50a595fabf925ec20d99fe1f44c7', 4194304, '7c04c946612f1fd6d1736dcd37005b63e316caba04b95e22a790bf414fc11529'),
            ('12b0f371de7468d4d380e5a898425061e646c1b0', 4194304, 'fce420473c7fc47a9538c1826bd92964a3db0b988e15bc0d9e407d1eabff087e'),
            ('6ef4c2794cd89347c6f3e6c7cfd8a15878a481b8', 4194304, '6caac6bd96f8b98927dc2855ae1f68d23445455a7b97662d7357995e1ef4bbaa'),
            ('4019f516773832fa694c509867eb11e2aa9bbf52', 3792758, '82d14e777adfd2d5a2aac6c83175685aeef1c0763f7bc91d48cfc70d68b20144'),
        ],
    },
}

def utc():
    return datetime.now(timezone.utc).isoformat()

def write_json(path, value):
    with path.open('x') as out:
        out.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def recover(package, index, spec):
    blob, expected_size, expected_sha = spec
    directory = BASE / package
    directory.mkdir(exist_ok=True)
    target = directory / ('final-699de39-evidence.tar.gz.part%04d' % index)
    receipt = {'package': package, 'part_number': index, 'git_blob_sha1': blob,
               'expected_bytes': expected_size, 'expected_sha256': expected_sha,
               'started_utc': utc(), 'requests': [], 'verified': False}
    # The bounded second request bypasses a stale shared-cache error if present.
    for attempt, suffix in enumerate(('', '?recovery=20261030-known-blob'), 1):
        url = API + blob + suffix
        row = {'url': url, 'attempt': attempt, 'started_utc': utc()}
        partial = target.with_name(target.name + '.attempt%d.partial' % attempt)
        try:
            request = Request(url, headers={'Accept': 'application/vnd.github.raw+json',
                              'User-Agent': 'HeptaEvidenceRecovery', 'Cache-Control': 'no-cache'})
            with urlopen(request, timeout=45) as response:
                row.update({'http_status': response.status,
                            'content_type': response.headers.get('Content-Type'),
                            'content_length': response.headers.get('Content-Length'),
                            'rate_remaining': response.headers.get('X-RateLimit-Remaining')})
                count = 0
                sha = hashlib.sha256()
                git = hashlib.sha1(b'blob ' + str(expected_size).encode() + b'\0')
                with partial.open('xb') as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                        count += len(chunk)
                        sha.update(chunk)
                        git.update(chunk)
                row.update({'bytes': count, 'sha256': sha.hexdigest(), 'git_blob_sha1': git.hexdigest()})
                if (count, sha.hexdigest(), git.hexdigest()) != (expected_size, expected_sha, blob):
                    raise ValueError('retrieved bytes differ from fixed original identity')
                assert not target.exists()
                partial.rename(target)
                receipt.update({'verified': True, 'local_path': str(target.relative_to(BASE)),
                                'bytes': count, 'sha256': sha.hexdigest()})
        except HTTPError as error:
            row['http_status'] = error.code
            row['rate_remaining'] = error.headers.get('X-RateLimit-Remaining')
            row['response_body'] = error.read(8192).decode('utf-8', errors='replace')
        except Exception as error:
            row['error_type'] = type(error).__name__
            row['error'] = str(error)
        row['finished_utc'] = utc()
        receipt['requests'].append(row)
        if receipt['verified']:
            break
    receipt['finished_utc'] = utc()
    write_json(directory / ('part-%04d-recovery.json' % index), receipt)
    print(json.dumps({'package': package, 'part': index, 'verified': receipt['verified'],
                      'http': [row.get('http_status') for row in receipt['requests']]}, ensure_ascii=False), flush=True)
    return receipt

def assemble(name, declaration, receipts):
    available = sorted((row for row in receipts if row['package'] == name), key=lambda row: row['part_number'])
    result = {'package': name, 'scope': declaration['scope'], 'parts_verified': sum(row['verified'] for row in available),
              'whole_verified': False, 'expected_bytes': declaration['whole_bytes'],
              'expected_sha256': declaration['whole_sha256']}
    if len(available) == 4 and all(row['verified'] for row in available):
        path = BASE / name / 'final-699de39-evidence.tar.gz'
        sha = hashlib.sha256()
        count = 0
        with path.open('xb') as output:
            for row in available:
                with (BASE / row['local_path']).open('rb') as source:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                        sha.update(chunk)
                        count += len(chunk)
        if (count, sha.hexdigest()) != (declaration['whole_bytes'], declaration['whole_sha256']):
            raise ValueError('ordered whole archive identity mismatch')
        result.update({'whole_verified': True, 'local_path': str(path.relative_to(BASE)),
                       'bytes': count, 'sha256': sha.hexdigest(), 'ordered_raw_parts': True})
    return result

def main():
    write_json(BASE / 'known-original-identities.json', DECLARATIONS)
    receipts = []
    # Recover known-complete second bytes first; do not let missing third pieces block them.
    for package in ('second-package', 'third-package'):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(recover, package, i, spec) for i, spec in enumerate(DECLARATIONS[package]['parts'], 1)]
            receipts.extend(f.result() for f in concurrent.futures.as_completed(futures))
    summary = {'schema': 'hepta.known-blob-recovery.v1', 'finished_utc': utc(),
               'source_commit': '699de39a8e92e0f083df316ecc5333fb3ecf8571',
               'github_mutations': False, 'native_or_test_execution': False,
               'archives': [assemble(name, declaration, receipts) for name, declaration in DECLARATIONS.items()],
               'part_receipts': sorted(receipts, key=lambda row: (row['package'], row['part_number']))}
    write_json(BASE / 'recovery-summary.json', summary)
    print(json.dumps({'archives': summary['archives']}, ensure_ascii=False), flush=True)

if __name__ == '__main__':
    main()
