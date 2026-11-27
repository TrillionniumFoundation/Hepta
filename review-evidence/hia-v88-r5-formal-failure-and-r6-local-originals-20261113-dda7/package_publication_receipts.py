"""Freeze the upload receipts and their supporting scripts; no product execution."""
from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def main():
    selected = []
    for path in (ROOT / 'GIT-CUSTODY').rglob('*'):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.parts[1] == 'readback':
            continue
        assert relative.parts[1] != 'staging', relative
        selected.append(path)
    for name in ('ALL-PUBLICATION-RECEIPTS.json', 'PUBLISH-LIST.json',
                 'PUBLICATION-HELPER-R1.js', 'PUBLICATION-HELPER-R2.js',
                 'PUBLICATION-HASH-UTILITY.js', 'PUBLICATION-HELPER-BOUNDARY.json',
                 'PREPARATION-OBSERVATION.json', 'PROGRESS-RAW-031.json',
                 'PROGRESS-RAW-199.json', 'verify_publication_readback.py',
                 'package_publication_receipts.py'):
        selected.append(ROOT / name)
    selected.extend(path for path in (ROOT / 'transport-write-control-r1').rglob('*') if path.is_file())
    files = {}
    for path in sorted(set(selected)):
        item = path.lstat()
        assert stat.S_ISREG(item.st_mode)
        raw = path.read_bytes()
        files[path.relative_to(ROOT).as_posix()] = dict(
            **identity(raw), mode=f'{stat.S_IMODE(item.st_mode):04o}',
            text=raw.decode('utf-8'))
    decoded = encode(dict(schema='hia.complete-utf8-custody-records.v1', files=files))
    capsule = encode(dict(schema='hia.zlib-base64-capsule.v1', encoding='zlib+base64',
                          decoded=identity(decoded), data=base64.b64encode(zlib.compress(decoded, 9)).decode()))
    name = 'PUBLICATION-CUSTODY-CAPSULE.json'
    with (ROOT / name).open('xb') as output:
        output.write(capsule)
    back = json.loads(zlib.decompress(base64.b64decode(json.loads(capsule)['data'], validate=True)))
    assert back['files'] == files
    for relative, row in back['files'].items():
        assert row['text'].encode() == (ROOT / relative).read_bytes()
        assert identity(row['text'].encode()) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
    index = dict(schema='hia.v88.publication-custody-capsule-index.v1',
                 files=len(files), logical_bytes=sum(row['bytes'] for row in files.values()),
                 capsule=dict(file=name, **identity(capsule)),
                 all_members_decoded_and_compared=True,
                 readback_payloads_excluded_because_they_are_the_exact_299_published_objects=True,
                 includes_original_unknown_POST_and_actual_404_and_successful_retry=True,
                 no_product_execution=True)
    with (ROOT / 'PUBLICATION-CUSTODY-INDEX.json').open('xb') as output:
        output.write(encode(index))
    extra = ['FULL-GIT-READBACK.json', 'git-readback-restore.stdout', 'git-readback-restore.stderr',
             'verify-publication.stdout', 'verify-publication.stderr', 'verify_publication_readback.py',
             'package_publication_receipts.py', 'PUBLICATION-CUSTODY-CAPSULE.json',
             'PUBLICATION-CUSTODY-INDEX.json', 'PUBLISH-LIST.json']
    rows = [dict(file=name, **identity((ROOT / name).read_bytes())) for name in extra]
    with (ROOT / 'FINAL-METADATA-PUBLISH-LIST.json').open('xb') as output:
        output.write(encode(rows))
    print(json.dumps(index, sort_keys=True))


if __name__ == '__main__':
    main()
