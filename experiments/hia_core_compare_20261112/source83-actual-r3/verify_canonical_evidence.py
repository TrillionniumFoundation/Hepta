from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile


def pin(data):
    return {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def require(value, label):
    if not value:
        raise ValueError(label)


def main(directory):
    root = Path(directory).resolve(strict=True)
    parts = json.loads((root / 'ARCHIVE-PARTS.json').read_bytes())
    manifest = json.loads((root / 'RAW-MANIFEST.json').read_bytes())
    require(parts['actual_run'] == 43287029044 and parts['actual_job'] == 131423025805 and
            parts['actual_artifact_id'] == 13975032410 and parts['actual_attempt'] == 1 and
            parts['actual_head'] == 'c7cf72d26a38d68fdafdf4e515e35645d29e49f1', 'actual provider identity')
    require([a['label'] for a in parts['archives']] == ['artifact-13975032410.original.zip', 'audit-originals.tar.gz'], 'archive order')
    archives = []
    all_part_paths = set()
    for archive in parts['archives']:
        require(archive['encoding'] == 'strict-base64-with-one-terminal-newline' and archive['chunk_bytes'] == 524288, 'transport policy')
        blocks = []
        offset = 0
        for i, row in enumerate(archive['parts']):
            path = row['path']
            require(path == f"parts/{archive['label']}.part-{i:03d}.base64" and path not in all_part_paths, 'part path/order')
            all_part_paths.add(path)
            require(row['index'] == i and row['offset'] == offset, 'part contiguous identity')
            text = (root / path).read_bytes()
            require(pin(text) == row['transport'] and text.endswith(b'\n') and b'\n' not in text[:-1], 'transport full pin')
            body = base64.b64decode(text[:-1], validate=True)
            require(base64.b64encode(body) + b'\n' == text and pin(body) == row['raw'], 'canonical full part')
            require(0 < len(body) <= 524288 and (i == len(archive['parts']) - 1 or len(body) == 524288), 'part size')
            blocks.append(body)
            offset += len(body)
        body = b''.join(blocks)
        require(pin(body) == archive['whole'], 'complete archive')
        archives.append(body)
    require(pin(archives[0]) == {'size': 12968973, 'sha256': '20ff6d57f71d55b38571b88c6fc559141ecb4e1632d423012ff0cd122b60d2af',
                               'git_blob_sha1': 'fbcebcd00a12108595d4c97fdf9f016c984bf39c'}, 'official ZIP identity')
    rows = manifest['files']
    require(len(rows) == manifest['count'] and len({r['path'] for r in rows}) == len(rows), 'unique original inventory')
    require(sum(r['size'] for r in rows) == manifest['bytes'], 'complete original sizes')
    originals = {}
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archives[1])), mode='r:') as t:
        members = t.getmembers()
        require(len(members) == len(rows), 'complete tar members')
        for member, row in zip(members, rows):
            require(member.name == row['path'] and member.isfile() and member.mode == row['mode'], 'typed tar original')
            require(not PurePosixPath(member.name).is_absolute() and '..' not in PurePosixPath(member.name).parts, 'relative tar name')
            body = t.extractfile(member).read()
            require(pin(body) == {k: row[k] for k in ('size', 'sha256', 'git_blob_sha1')}, 'full original bytes')
            originals[row['path']] = body
    root_audit = json.loads(originals['root/AUDIT.json'])
    require(root_audit == json.loads(originals['peer/AUDIT.json']), 'independent full audit equality')
    require(root_audit['check_count'] == 11421 and root_audit['bound_raw_pin_joins'] == 2505, 'original audit denominators')
    require(originals['root/ZIP-MANIFEST.json'] == originals['peer/ZIP-MANIFEST.json'], 'independent inventory raw equality')
    inventory = json.loads(originals['peer/ZIP-MANIFEST.json'])
    require(inventory['files'] == 1935 and inventory['expanded_bytes'] == 48327070, 'official member denominators')
    with zipfile.ZipFile(io.BytesIO(archives[0])) as z:
        infos = z.infolist()
        expected = inventory['members']
        require(len(infos) == len(expected) == 1935 and len({i.filename for i in infos}) == 1935, 'official complete unique inventory')
        expanded = 0
        for info, row in zip(infos, expected):
            require(info.filename == row['path'] and info.file_size == row['size'] and info.CRC == row['crc32'] and
                    info.compress_size == row['compressed_bytes'] and info.compress_type == row['compression'] and
                    info.external_attr == row['external_attr'] and info.header_offset == row['header_offset'] and
                    info.is_dir() == row['is_directory'], 'official ZIP metadata')
            body = z.read(info)
            require(pin(body) == {k: row[k] for k in ('size', 'sha256', 'git_blob_sha1')}, 'official ZIP full body/CRC')
            expanded += len(body)
        require(expanded == 48327070, 'official full expanded bytes')
    tests = json.loads(originals['peer/key-originals/actual-source--evidence--source-tests.json'])
    require(tests['expected_ids'] == tests['loaded_ids'] == tests['executed_ids'] and len(tests['expected_ids']) == tests['tests_run'] == 83, 'exact source83 originals')
    require(all(tests[k] == [] for k in ('errors', 'failures', 'expectedFailures', 'skipped', 'unexpectedSuccesses', 'loader_errors')), 'original six anomalies')
    require(tests['allowed_negative_processes'] == 4 and tests['forbidden_attempt_count'] == 0 and tests['zero_process_scope_claimed'] is False, 'original process scope')
    require(pin(originals['root/job-131423025805.original.log'])['sha256'] == 'b782233bb258c79d29e40a20f2085ec99b4b44188e81039584efe1f1f0243683', 'complete original log')
    report = {'status': 'COMPLETE_ORIGINAL_TRANSPORT_READBACK_PASS', 'artifact': pin(archives[0]),
              'transport_parts': [len(a['parts']) for a in parts['archives']], 'original_files': len(originals),
              'original_bytes': manifest['bytes'], 'official_zip_members': 1935, 'official_expanded_bytes': expanded,
              'source83_originals_match': True, 'root_peer_audit_originals_equal': True,
              'no_source_test_or_product_reexecution': True, 'no_new_qualification_result': True}
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'one canonical directory required')
    main(sys.argv[1])
