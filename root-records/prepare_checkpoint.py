"""Freeze exact existing audit records; this does not execute the HIA product."""
from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

WORK = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent


def pin(raw):
    return {
        'bytes': len(raw),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'sha256': hashlib.sha256(raw).hexdigest(),
    }


def write(name, raw):
    with (OUT / name).open('xb') as stream:
        stream.write(raw)


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def main():
    selected = set()
    for relative in (
        'v95-audit-mount-r1/v118-formal-terminal-and-owner-audit',
        'v95-audit-mount-r1/v118-isolated-archive',
        'v95-audit-mount-r1/v121-progress-checkpoint',
        'v95-audit-mount-r1/v121-candidate-core-readbacks',
        'v95-audit-mount-r1/v122-progress-inputs',
        'v120-derived-source-retirement-r1',
        'v122-prepared-r19-source-retirement-r1',
    ):
        directory = WORK / relative
        selected.update(p for p in directory.iterdir() if p.is_file())
    for relative in (
        'v95-audit-mount-r1/ROOT-LOCAL-PATH-REPAIR-V121.json',
        'v120-union-r20/ROOT-PLAN-REVIEW.json',
        'v120-union-r20/FORMAL-HARNESS-ROOT-REVIEW.json',
        'v120-union-r20/PLAN-COMPOSE-READBACK.json',
        'v121-selfhost-small-constant-r1/ROOT-AUTHORING-REVIEW.json',
        'v121-selfhost-small-constant-r1/ROOT-GENERATION-R1-REFUSAL.json',
        'v121-selfhost-small-constant-r1/ROOT-GENERATION-REVIEW.json',
        'v121-selfhost-small-constant-r1/ROOT-SOURCE9-REVIEW.json',
        'v121-selfhost-small-constant-r1/evidence/generation-r1/RESULT.json',
        'v121-selfhost-small-constant-r1/evidence/source-r1/OUTER.json',
        'v121-selfhost-small-constant-r1/evidence/source-r1/SOURCE-TESTS.json',
        'v121-selfhost-small-constant-r1/evidence/source-r1/events.jsonl',
    ):
        path = WORK / relative
        if not path.is_file():
            raise ValueError('required exact record missing: ' + relative)
        selected.add(path)
    records, contents = [], []
    for path in sorted(selected):
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('regular file required: ' + str(path))
        raw = path.read_bytes()
        after = path.lstat()
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, key) != getattr(after, key) for key in keys):
            raise ValueError('record changed while frozen: ' + str(path))
        row = {'path': str(path.relative_to(WORK)), 'mode': stat.S_IMODE(before.st_mode), **pin(raw)}
        records.append(row)
        contents.append({**row, 'base64': base64.b64encode(raw).decode()})
    payload = encode({'schema': 'hia.root-progress-complete-records.v122', 'files': contents})
    capsule = encode({'schema': 'hia.lossless-zlib-wrapper.v1', 'encoding': 'zlib+base64',
                      'payload': pin(payload), 'data': base64.b64encode(zlib.compress(payload, 9)).decode()})
    # Independent full decode before publishing or permitting any retirement.
    wrapped = json.loads(capsule)
    restored = zlib.decompress(base64.b64decode(wrapped['data']))
    if restored != payload or pin(restored) != wrapped['payload']:
        raise ValueError('metadata capsule payload differs')
    recovered = json.loads(restored)['files']
    for row, original in zip(recovered, records, strict=True):
        raw = base64.b64decode(row.pop('base64'), validate=True)
        if row != original or any(pin(raw)[key] != row[key] for key in pin(raw)):
            raise ValueError('metadata capsule member differs')
    write('COMPLETE-ROOT-RECORDS.zlib.json', capsule)
    index = {'schema': 'hia.root-progress-record-index.v122', 'records': records,
             'files': len(records), 'logical_bytes': sum(x['bytes'] for x in records),
             'payload': pin(payload), 'capsule': pin(capsule), 'full_decode_verified': True,
             'new_product_executions': 0, 'whole_native': False,
             'scope': 'Complete selected records. Native generation and Source9 full raw frame archives are separate agent handoffs; this is not a replacement for them.'}
    write('ROOT-RECORDS-INDEX.json', encode(index))
    own = []
    for name in ('prepare_checkpoint.py', 'COMPLETE-ROOT-RECORDS.zlib.json', 'ROOT-RECORDS-INDEX.json'):
        path = OUT / name
        own.append({'path': name, 'local_path': str(path), 'mode': '100644', **pin(path.read_bytes())})
    write('PUBLICATION-INTENT.json', encode({'schema': 'hia.root-progress-publication.v122', 'files': own,
          'parent': 'd035af2a882e348948e6c5571b60ef81dace9892',
          'branch': 'codex/hia-native-progress-v122-20261114-dda7', 'products_executed': 0}))
    print(json.dumps({'files': len(records), 'logical_bytes': index['logical_bytes'],
                      'capsule': pin(capsule), 'new_product_executions': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
