"""Restore the sixteen logical files from original full Git-fetch responses."""
import argparse
import base64
import hashlib
import json
import stat
import zlib
from pathlib import Path, PurePosixPath

INDEX_GIT = '11aa99f846587c6ddf7c4ead89483d25bfa7fafc'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def fetch_bytes(path, expected_git):
    response = json.loads(path.read_bytes())
    assert response.get('isError') is not True
    content = response['structuredContent']['content']
    assert type(content) is str
    raw = content.encode('utf-8')
    assert identity(raw)['git_blob'] == expected_git
    return raw


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--responses', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    args = p.parse_args()
    index = json.loads(fetch_bytes(args.responses/'transport-readback.response.json', INDEX_GIT))
    chunks = []
    for i, row in enumerate(index['parts']):
        assert type(row['sequence']) is int and row['sequence'] == i
        raw = fetch_bytes(args.responses/f'part-{i:03}-readback.response.json', row['git_blob'])
        assert identity(raw) == {k: row[k] for k in ('bytes','sha256','git_blob')}
        chunks.append(raw)
    transport = b''.join(chunks)
    assert identity(transport) == index['reconstructed']
    wrapper = json.loads(transport)
    compressed = base64.b64decode(wrapper['data'], validate=True)
    assert identity(compressed) == wrapper['compressed']
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed) + decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert identity(raw) == wrapper['uncompressed']
    capsule = json.loads(raw)
    assert len(capsule['files']) == index['logical_files'] == 16
    args.output.mkdir()
    rows, total = {}, 0
    for name, record in capsule['files'].items():
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
        assert record['mode'] == '100644'
        data = record['text'].encode('utf-8')
        assert identity(data) == {k: record[k] for k in ('bytes','sha256','git_blob')}
        target = args.output/name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream: assert stream.write(data) == len(data)
        target.chmod(0o644)
        observed = target.lstat()
        assert stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o644
        assert target.read_bytes() == data
        total += len(data)
        rows[name] = {**identity(target.read_bytes()), 'mode': '100644'}
    assert total == index['logical_bytes'] == 3432418
    assert {str(p.relative_to(args.output)) for p in args.output.rglob('*') if p.is_file()} == set(rows)
    proof = {'schema': 'hepta.namespace-git-response-restore-proof.v1',
             'status': 'ALL_16_LOGICAL_FILES_RESTORED_FROM_GIT_RESPONSES',
             'logical_files': len(rows), 'logical_bytes': total, 'files': rows,
             'index_git': INDEX_GIT, 'transport': identity(transport),
             'all_bytes_modes_sha256_git_verified': True, 'product_executions': 0,
             'qualification': False, 'whole_native': False}
    with args.report.open('x') as stream: json.dump(proof, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps({'status': proof['status'], 'logical_files': len(rows), 'logical_bytes': total,
                      'report': identity(args.report.read_bytes())}, sort_keys=True))


if __name__ == '__main__': main()
