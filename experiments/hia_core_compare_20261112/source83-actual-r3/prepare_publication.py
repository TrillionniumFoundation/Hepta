from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root/numeric-r3-actual-43287029044')
PEER = Path('/tmp/hia-numeric-r3-actual-peer-20261112-r2')
OUT = HERE / 'git-files'
PREFIX = 'experiments/hia_core_compare_20261112/source83-actual-r3'
CHUNK = 524288


def pin(data: bytes) -> dict:
    return {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def identity(s):
    return {k: getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, path
    data = path.read_bytes()
    after = path.lstat()
    assert identity(before) == identity(after) and len(data) == before.st_size, path
    return data, identity(before)


def write(name, data):
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('xb') as f:
        f.write(data)
    assert p.read_bytes() == data


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def split(label, body):
    parts = []
    for i, offset in enumerate(range(0, len(body), CHUNK)):
        raw = body[offset:offset + CHUNK]
        name = f'parts/{label}.part-{i:03d}.base64'
        encoded = base64.b64encode(raw) + b'\n'
        write(name, encoded)
        parts.append({'index': i, 'offset': offset, 'path': name, 'raw': pin(raw), 'transport': pin(encoded)})
    return {'label': label, 'encoding': 'strict-base64-with-one-terminal-newline', 'chunk_bytes': CHUNK,
            'whole': pin(body), 'parts': parts}


def main():
    OUT.mkdir()
    archive, archive_identity = read(ROOT / 'artifact-13975032410.original.zip')
    assert pin(archive) == {'size': 12968973,
        'sha256': '20ff6d57f71d55b38571b88c6fc559141ecb4e1632d423012ff0cd122b60d2af',
        'git_blob_sha1': 'fbcebcd00a12108595d4c97fdf9f016c984bf39c'}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        rows = z.infolist()
        assert len(rows) == 1935 and len({r.filename for r in rows}) == len(rows)
        assert sum(r.file_size for r in rows) == 48327070
        for row in rows:
            assert len(z.read(row)) == row.file_size
    originals = []
    bodies = {}
    for label, root in [('root', ROOT), ('peer', PEER)]:
        for path in sorted(root.rglob('*')):
            if path.is_dir():
                assert not path.is_symlink(), path
                continue
            if label == 'root' and path.name == 'artifact-13975032410.original.zip':
                continue
            data, observed = read(path)
            relative = label + '/' + str(path.relative_to(root))
            bodies[relative] = data
            originals.append({'path': relative, 'original_path': str(path), 'identity': observed,
                              'mode': stat.S_IMODE(observed['st_mode']), **pin(data)})
    manifest = {'schema': 'hepta.numeric-source83-r3-complete-audit-originals.v1',
                'count': len(originals), 'bytes': sum(r['size'] for r in originals), 'files': originals}
    tar_body = io.BytesIO()
    with tarfile.open(fileobj=tar_body, mode='w', format=tarfile.USTAR_FORMAT) as t:
        for row in originals:
            header = tarfile.TarInfo(row['path'])
            header.size = row['size']
            header.mode = row['mode']
            header.mtime = 0
            t.addfile(header, io.BytesIO(bodies[row['path']]))
    audit_archive = gzip.compress(tar_body.getvalue(), compresslevel=1, mtime=0)
    parts = {'schema': 'hepta.numeric-source83-r3-complete-artifact-transport.v1',
             'actual_run': 43287029044, 'actual_job': 131423025805, 'actual_artifact_id': 13975032410,
             'actual_attempt': 1, 'actual_head': 'c7cf72d26a38d68fdafdf4e515e35645d29e49f1',
             'artifact_original_identity': archive_identity,
             'archives': [split('artifact-13975032410.original.zip', archive), split('audit-originals.tar.gz', audit_archive)],
             'original_product_status': 'SOURCE83_PASS',
             'no_product_or_source_reexecution': True,
             'full_zip_not_repacked': True}
    write('ARCHIVE-PARTS.json', json_bytes(parts))
    write('RAW-MANIFEST.json', json_bytes(manifest))
    for name in ('PEER-READBACK.json', 'READER-PATH-ADAPTATION.json', 'READER-EXECUTION.json', 'PATH-ADAPTATION-r1-ERROR.json',
                 'DERIVED-ORIGINALS.json', 'ROOT-READER-ORIGINAL.py', 'audit_actual_r3_path_only.py'):
        write(name, bodies['peer/' + name])
    for name in ('run.original.json', 'jobs.original.json', 'artifacts.original.json', 'DOWNLOAD-READBACK.json',
                 'PURE-V90-PUBLISH-INTENT.json', 'PURE-V90-READBACK.json', 'V90-CI-INTENT.json', 'V90-CI-REF-ACK.json'):
        write(name, bodies['root/' + name])
    for name in ('actual-source--lifecycle.json', 'actual-source--wrapper.json', 'actual-source--FINAL.json',
                 'actual-source--evidence--source-tests.json', 'actual-source--evidence--report.json'):
        write('key-originals/' + name, bodies['peer/key-originals/' + name])
    write('verify_canonical_evidence.py', (HERE / 'verify_canonical_evidence.py').read_bytes())
    write('prepare_publication.py', Path(__file__).read_bytes())
    readme = '''# Numeric source83 R3 actual evidence

This checkpoint preserves the complete official artifact for run 43287029044, job 131423025805, attempt 1, and independent readback of its exact original bytes. It contains a lossless 25-part representation of the original 12,968,973-byte ZIP (SHA256 20ff6d57f71d55b38571b88c6fc559141ecb4e1632d423012ff0cd122b60d2af), without repacking it. ARCHIVE-PARTS.json specifies every contiguous offset, size, SHA256 and Git blob. The second transport preserves all selected Root and peer reports, original provider metadata, the complete 706,477-byte job log, original readers and the local reader-preparation error. RAW-MANIFEST.json enumerates their exact bytes and observed file identities.

Actual scope: all 62 generators, 4 derivations, 4 idempotence commands and the exact 83 source methods passed. Four genuine negative Python admission commands retained their original 10-second bounds and full request/input/stdout/stderr/receipt records; forbidden attempts were zero. The original 180/3 owner closed naturally with rc0 and ECHILD. The independently repeated readonly audit made 11,421 checks and 2,505 raw joins. The official ZIP contains 1,935 members / 48,327,070 expanded bytes. No generator, test, native compiler or product was reexecuted by this publication.

The earlier source83 failures and this audit's preparation error remain historical originals. This source-only result does not establish numeric Core39, 18/116, matching-cold, installed or whole-runtime qualification. Root separately published pure candidate 6f245ae212e1c6f46f72c1560e86767ca5ddb2bf, tree e1c06d36697aa7444f6f3f9810fe15fab6e24314, by adding only the two actual derived docs to parent 545e7814b97bc767a15810dd99534aaccc23adf4. Its later standard CI has a distinct identity and result.

Run `python3 -I -S -B verify_canonical_evidence.py .` from this directory for a no-project-import, no-extraction readback. It verifies both transports, every preserved audit original, and every official ZIP member against the independently preserved inventory. It does not rerun source tests or grant new product qualification.
'''
    write('README.md', readme.encode())
    files = [{'name': str(p.relative_to(OUT)), 'path': PREFIX + '/' + str(p.relative_to(OUT)),
              'mode': '100644', **pin(p.read_bytes())} for p in sorted(OUT.rglob('*')) if p.is_file()]
    (HERE / 'PUBLICATION-FILES.json').write_bytes(json_bytes(files))
    (HERE / 'PREPARATION.json').write_bytes(json_bytes({'status': 'EXACT_ORIGINALS_TRANSPORT_PREPARED',
        'artifact': pin(archive), 'audit_archive': pin(audit_archive), 'raw_files': manifest['count'],
        'raw_bytes': manifest['bytes'], 'new_files': len(files), 'new_bytes': sum(r['size'] for r in files),
        'parts': [len(a['parts']) for a in parts['archives']], 'prefix': PREFIX}))
    print((HERE / 'PREPARATION.json').read_text())


if __name__ == '__main__':
    main()
