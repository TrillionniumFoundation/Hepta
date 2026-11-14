"""Preserve and verify the single early-failure R16 Actions artifact; no product execution."""
from pathlib import Path, PurePosixPath
import hashlib, json, os, stat, urllib.request, zipfile

ROOT = Path(__file__).resolve().parent
PUB = ROOT.parent / 'v103-union-r16/formal-preparation-r2/publication'
EXPECTED_SIZE = 357237
EXPECTED_SHA = '448726bc12d0e33683098da8c929876b2ebac9b22543475e1cacb931317152a2'

def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.read_bytes() == data, str(path)
    else:
        with path.open('xb') as f:
            f.write(data)

def dump(path, value):
    put(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def main():
    receipt = json.loads((PUB / 'ARTIFACT-DOWNLOAD-RESPONSE.json').read_bytes())
    archive = ROOT / 'ORIGINAL-ARTIFACT.zip'
    if not archive.exists():
        dump(ROOT / 'DOWNLOAD-INTENT.json', {'artifact_id': 14081878942, 'run': 43520413130,
             'job': 132212950593, 'expected_bytes': EXPECTED_SIZE, 'expected_sha256': EXPECTED_SHA})
        with urllib.request.urlopen(receipt['structuredContent']['file_uri']['download_url'], timeout=60) as r:
            raw = r.read(EXPECTED_SIZE + 1)
        assert len(raw) == EXPECTED_SIZE and hashlib.sha256(raw).hexdigest() == EXPECTED_SHA
        put(archive, raw)
    raw = archive.read_bytes()
    assert len(raw) == EXPECTED_SIZE and hashlib.sha256(raw).hexdigest() == EXPECTED_SHA
    records = []
    with zipfile.ZipFile(archive) as z:
        seen = set()
        for info in z.infolist():
            name = info.filename
            path = PurePosixPath(name)
            assert name and '\\' not in name and not path.is_absolute() and '..' not in path.parts
            assert name not in seen
            seen.add(name)
            mode = info.external_attr >> 16
            typ = stat.S_IFMT(mode)
            assert not stat.S_ISLNK(mode) and typ in (0, stat.S_IFREG, stat.S_IFDIR)
            data = z.read(info)  # zipfile checks the actual CRC while reading the complete bytes.
            row = {'path': name, 'zip_crc32': '%08x' % info.CRC,
                   'zip_external_attr': info.external_attr, 'zip_create_system': info.create_system,
                   'zip_unix_mode': oct(mode), 'directory': info.is_dir(), **pin(data)}
            if info.is_dir():
                assert not data
            else:
                dest = ROOT / 'raw' / path
                put(dest, data)
                if mode & 0o7777:
                    os.chmod(dest, mode & 0o7777)
                assert dest.read_bytes() == data
            records.append(row)
    logs = json.loads((PUB / 'FULL-JOB-RESPONSE.json').read_bytes())['structuredContent']['content'].encode()
    put(ROOT / 'FULL-JOB.log', logs)
    for name in ('RUN-20261113T224004Z.GET.json', 'JOBS-TERMINAL.json', 'ARTIFACTS-TERMINAL.json', 'JOB-20261113T224004Z.GET.json'):
        put(ROOT / name, (PUB / name).read_bytes())
    report = {'schema': 'hepta.r16-early-failure-custody.v1', 'status': 'CUSTODY_PASS_EXECUTION_FAILURE_RETAINED',
              'run': 43520413130, 'job': 132212950593, 'head': '7145c1cca251b6615e3bace54d8e033cad493875',
              'artifact': {'id': 14081878942, **pin(raw)}, 'members': records, 'member_count': len(records),
              'full_job_log': pin(logs), 'execution': {'status': 'FAIL', 'stage': 'harness_files_binding',
              'missing_path': 'tools/materialize_candidate_r16.py', 'repository_created': False,
              'generators_executed': 0, 'source_tests_executed': 0, 'bounded62': 'SKIPPED'},
              'directory_modes': 'Only actual ZIP directory records are evidence; implicit extraction directories are not original modes.',
              'product_execution_in_this_verifier': 0}
    dump(ROOT / 'VERIFICATION.json', report)
    print(json.dumps({k: v for k, v in report.items() if k != 'members'}, sort_keys=True))

if __name__ == '__main__':
    main()
