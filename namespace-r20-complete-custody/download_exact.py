"""Receive the single already-published diagnostic artifact; no credentials."""
from pathlib import Path
import hashlib
import json
import os
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
EXPECTED_BYTES = 2684449
EXPECTED_SHA256 = '5e2d6406cb907d20f0f0b73229d42159bc01bd8199767ffc89da9313a269204c'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    response = json.loads((ROOT / 'publication-r1/046-terminal-download.RESPONSE.json').read_bytes())
    url = response['structuredContent']['file_uri']['download_url']
    assert url.startswith('https://sdmntprcentralus.oaiusercontent.com/files/')
    folder = ROOT / 'actual'
    target = folder / 'namespace-r20-expired-sections.zip'
    partial = target.with_suffix('.zip.partial')
    assert not target.exists() and not partial.exists(), 'read-only reconcile existing transfer first'
    volume = os.statvfs(folder)
    free = volume.f_bavail * volume.f_frsize
    assert free >= EXPECTED_BYTES + 128 * 1024 * 1024
    intent = {'expected_bytes': EXPECTED_BYTES, 'expected_sha256': EXPECTED_SHA256,
              'artifact_id': 14104166003, 'run_id': 43569339563, 'free_bytes_before': free,
              'redirects_permitted': False, 'authorization_headers': False,
              'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    (folder / 'TRANSFER-INTENT.json').open('x').write(json.dumps(intent, indent=2) + '\n')
    digest = hashlib.sha256()
    git = hashlib.sha1(b'blob ' + str(EXPECTED_BYTES).encode() + b'\0')
    total = 0
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(urllib.request.Request(url, headers={'Accept-Encoding': 'identity'}), timeout=60) as incoming:
        assert incoming.status == 200
        headers = dict(incoming.headers.items())
        if 'Content-Length' in incoming.headers:
            assert int(incoming.headers['Content-Length']) == EXPECTED_BYTES
        with partial.open('xb') as output:
            while block := incoming.read(min(1024 * 1024, EXPECTED_BYTES + 1 - total)):
                total += len(block)
                assert total <= EXPECTED_BYTES
                digest.update(block)
                git.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    assert total == EXPECTED_BYTES and digest.hexdigest() == EXPECTED_SHA256
    assert not target.exists()
    partial.rename(target)
    with zipfile.ZipFile(target) as archive:
        rows = [{'path': item.filename, 'bytes': item.file_size, 'compressed_bytes': item.compress_size,
                 'crc32': '%08x' % item.CRC, 'external_attr': item.external_attr,
                 'create_system': item.create_system, 'is_dir': item.is_dir()} for item in archive.infolist()]
    report = {**intent, 'status': 'TRANSFER_EXACT_COMPLETE', 'bytes': total,
              'sha256': digest.hexdigest(), 'git_blob': git.hexdigest(), 'headers': headers,
              'finished_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'zip_central_entries': len(rows), 'declared_uncompressed_bytes': sum(row['bytes'] for row in rows),
              'crc_full_read_pending': True}
    (folder / 'TRANSFER.json').open('x').write(json.dumps(report, indent=2) + '\n')
    (folder / 'ZIP-CENTRAL.json').open('x').write(json.dumps(rows, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'headers'}))


if __name__ == '__main__':
    main()
