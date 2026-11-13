#!/usr/bin/env python3
"""Archive or verify already completed evidence; never import product code."""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile


HERE = Path(__file__).resolve().parent
RAW = HERE.parent / 'local-generation-r3' / 'evidence' / 'raw'
CHUNK_BYTES = 128 * 1024
FIXED_HEADS = (
    'f33d8da316de8fdf27b504371f1a5310997ff548',
    'a733926a2786a3d4a37304bd2d18ebb2eac57ac9',
    '5831f52fada45e076f8f68f198a15c0585e6104f',
    '93d66bcc3acb88212c9b153d7852ba22eeab24c8',
)


def check(ok, message):
    if not ok:
        raise ValueError(message)


def identity(raw):
    return {
        'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest(),
    }


def write_json(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(raw)
    return identity(raw)


def snapshot(root):
    check(root.is_dir() and not root.is_symlink(), 'raw root is not a plain directory')
    files = []
    directories = []
    for path in sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        before = path.lstat()
        mode = stat.S_IMODE(before.st_mode)
        if stat.S_ISDIR(before.st_mode):
            directories.append({'path': relative, 'mode': f'{mode:04o}'})
            continue
        check(stat.S_ISREG(before.st_mode), 'nonregular raw member: ' + relative)
        data = path.read_bytes()
        after = path.lstat()
        check((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
               before.st_mode) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
               after.st_mode), 'raw file changed while reading: ' + relative)
        check(len(data) == before.st_size, 'raw size changed: ' + relative)
        files.append({'path': relative, 'mode': f'{mode:04o}', **identity(data)})
    return {'files': files, 'directories': directories}


def verify_tar(archive, members, source_root=None):
    raw_tar = gzip.decompress(archive)  # fully checks gzip CRC and length
    expected = {item['path']: item for item in members}
    check(len(expected) == len(members), 'duplicate expected member')
    observed = []
    names = []
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as tape:
        for member in tape:
            name = member.name
            pp = PurePosixPath(name)
            check(name == pp.as_posix() and not pp.is_absolute() and
                  '..' not in pp.parts and '.' not in pp.parts,
                  'unsafe archive path: ' + name)
            check(name in expected and name not in names, 'unexpected or duplicate archive member: ' + name)
            check(member.isfile() and not member.issym() and not member.islnk(),
                  'nonregular archive member: ' + name)
            check(member.uid == 0 and member.gid == 0 and
                  member.uname == '' and member.gname == '' and member.mtime == 0,
                  'nondeterministic tar metadata: ' + name)
            stream = tape.extractfile(member)
            check(stream is not None, 'missing member stream: ' + name)
            data = stream.read()
            row = {'path': name, 'mode': f'{member.mode:04o}', **identity(data)}
            check(row == expected[name], 'tar identity or mode mismatch: ' + name)
            check(member.size == len(data), 'tar size mismatch: ' + name)
            if source_root is not None:
                original = source_root / name
                original_stat = original.lstat()
                check(stat.S_ISREG(original_stat.st_mode), 'original is not regular: ' + name)
                check(stat.S_IMODE(original_stat.st_mode) == member.mode,
                      'original POSIX mode mismatch: ' + name)
                check(original.read_bytes() == data, 'original byte mismatch: ' + name)
            names.append(name)
            observed.append(row)
    check(names == sorted(expected), 'tar member set or order mismatch')
    return observed, identity(raw_tar)


def prepare():
    check(not (HERE / 'MANIFEST.json').exists(), 'manifest already exists; do not overwrite')
    before = snapshot(RAW)
    check(len(before['files']) == 1008, 'unexpected frozen raw file count')
    check(sum(row['bytes'] for row in before['files']) == 24310976,
          'unexpected frozen raw byte total')
    check(all(row['mode'] == '0644' for row in before['files']), 'unexpected raw mode')
    result = json.loads((RAW / 'LOCAL-RESULT.json').read_text())
    check(result['status'] == 'LOCAL_GENERATION_PASS' and result['failures'] == [],
          'unexpected local terminal result')
    check(result['whole_native'] is False and result['native_qualification'] is False and
          result['product_tests_executed'] == 0, 'local result scope changed')
    check(result['generation'] == {
        'generator_count': 109,
        'physical_paths_retired_in_development_tree': 55,
        'real_generation_passes': 2,
        'tree': 'e295431ac7bfb71058de8b940c8e7457c8100750',
    }, 'unexpected local generation identity')
    index = json.loads((RAW / 'terminal-worktree/INDEX.json').read_text())
    check(index['self_contained'] is False, 'source dependency scope changed')
    check(set(index['fixed_original_dependency_commits']) == set(FIXED_HEADS),
          'original Git dependency heads differ')
    check(len(index['files']) == 2984, 'terminal snapshot file count differs')
    command_paths = sorted((RAW / 'commands').glob('*.json'))
    check(len(command_paths) == 239, 'command count differs')
    write_json(HERE / 'RAW-BEFORE.json', before)
    output_path = HERE / 'checkpoint.tar.gz'
    with output_path.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tape:
                for row in before['files']:
                    data = (RAW / row['path']).read_bytes()
                    check(identity(data) == {k: row[k] for k in ('bytes', 'sha256', 'blob')},
                          'raw changed during archive: ' + row['path'])
                    info = tarfile.TarInfo(row['path'])
                    info.size = len(data)
                    info.mode = int(row['mode'], 8)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = 0
                    tape.addfile(info, io.BytesIO(data))
    archive = output_path.read_bytes()
    observed, tar_identity = verify_tar(archive, before['files'], RAW)
    after = snapshot(RAW)
    check(after == before, 'raw source changed across archive construction')
    write_json(HERE / 'RAW-AFTER-PREPARE.json', after)
    chunks = []
    for offset in range(0, len(archive), CHUNK_BYTES):
        raw = archive[offset:offset + CHUNK_BYTES]
        encoded = base64.b64encode(raw)
        check(b'\n' not in encoded and base64.b64decode(encoded, validate=True) == raw,
              'base64 construction failed')
        filename = f'part-{len(chunks):04d}.b64'
        with (HERE / filename).open('xb') as output:
            output.write(encoded)
        ri, ti = identity(raw), identity(encoded)
        chunks.append({
            'index': len(chunks), 'file': filename, 'offset': offset,
            'decoded_bytes': ri['bytes'], 'decoded_sha256': ri['sha256'],
            'decoded_blob_calculated_not_uploaded': ri['blob'],
            'utf8_bytes': ti['bytes'], 'utf8_sha256': ti['sha256'],
            'text_blob': ti['blob'],
        })
    ai = identity(archive)
    manifest = {
        'schema': 'hepta.local-development-checkpoint-capsule.v1',
        'scope': 'COMPLETE_ORIGINAL_RAW_CUSTODY_ONLY_NOT_QUALIFICATION',
        'raw_root': str(RAW),
        'compressed_bytes': ai['bytes'], 'compressed_sha256': ai['sha256'],
        'compressed_blob_calculated_not_uploaded': ai['blob'],
        'uncompressed_tar': tar_identity,
        'encoding': 'ordered chunks; each UTF-8 file strictly base64-decodes to one gzip segment; concatenate decoded segments',
        'chunk_decoded_bytes': CHUNK_BYTES,
        'gzip': {'mtime': 0, 'filename': '', 'compresslevel': 9},
        'tar': {'format': 'PAX', 'order': 'relative path lexical', 'uid': 0, 'gid': 0,
                'uname': '', 'gname': '', 'mtime': 0, 'member_modes': 'exact original POSIX modes'},
        'members': before['files'], 'directories': before['directories'], 'chunks': chunks,
        'original_core_source_dependencies': list(FIXED_HEADS),
        'self_contained_evidence_raw': True,
        'self_contained_terminal_product_source': False,
        'source_dependency_boundary': 'Every raw evidence file is included. Terminal source INDEX intentionally references unchanged original Git blobs from the four fixed heads; those product-source bytes are not duplicated in this raw archive.',
        'qualification': False, 'result': result,
    }
    mi = write_json(HERE / 'MANIFEST.json', manifest)
    report = {
        'schema': 'hepta.original-checkpoint-preparation.v1',
        'status': 'PREPARED_AND_LOCALLY_VERIFIED_NOT_YET_GIT_CUSTODIED',
        'raw_files': len(observed), 'raw_bytes': sum(row['bytes'] for row in observed),
        'archive': ai, 'tar': tar_identity, 'chunks': len(chunks), 'manifest': mi,
        'raw_before_after_equal': True, 'archive_all_member_bytes_and_modes_equal': True,
        'gzip_full_crc_and_length_verified': True, 'product_executed': False,
        'product_refs_changed': False, 'qualification': False,
    }
    write_json(HERE / 'PREPARATION.json', report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def verify_remote():
    manifest_raw = (HERE / 'GIT-CUSTODY/readback/MANIFEST.json').read_bytes()
    check(manifest_raw == (HERE / 'MANIFEST.json').read_bytes(), 'remote manifest differs')
    manifest = json.loads(manifest_raw)
    archive = bytearray()
    receipts = []
    for number, item in enumerate(manifest['chunks']):
        check(item['index'] == number and item['offset'] == len(archive), 'chunk index/offset mismatch')
        encoded = (HERE / 'GIT-CUSTODY/readback' / item['file']).read_bytes()
        check(re.fullmatch(rb'[A-Za-z0-9+/]*={0,2}', encoded) is not None,
              'base64 wrapper has unexpected bytes: ' + item['file'])
        got = identity(encoded)
        check(got == {'bytes': item['utf8_bytes'], 'sha256': item['utf8_sha256'],
                      'blob': item['text_blob']}, 'remote UTF-8 identity mismatch: ' + item['file'])
        raw = base64.b64decode(encoded, validate=True)
        check(base64.b64encode(raw) == encoded, 'noncanonical base64: ' + item['file'])
        got_raw = identity(raw)
        check(got_raw == {'bytes': item['decoded_bytes'], 'sha256': item['decoded_sha256'],
                          'blob': item['decoded_blob_calculated_not_uploaded']},
              'decoded segment identity mismatch: ' + item['file'])
        receipt = json.loads((HERE / 'GIT-CUSTODY' / (item['file'] + '.receipt.json')).read_text())
        check(receipt['full_get_verified'] is True and receipt['git_blob'] == item['text_blob'],
              'missing successful GET receipt: ' + item['file'])
        receipts.append(receipt)
        archive.extend(raw)
    archive = bytes(archive)
    check(archive == (HERE / 'checkpoint.tar.gz').read_bytes(), 'remote gzip differs from original archive')
    check(len(archive) == manifest['compressed_bytes'] and
          hashlib.sha256(archive).hexdigest() == manifest['compressed_sha256'],
          'remote gzip identity mismatch')
    observed, tar_identity = verify_tar(archive, manifest['members'], RAW)
    check(tar_identity == manifest['uncompressed_tar'], 'remote tar identity mismatch')
    current = snapshot(RAW)
    check(current == {'files': manifest['members'], 'directories': manifest['directories']},
          'original raw changed during Git custody')
    report = {
        'schema': 'hepta.original-checkpoint-independent-read-verification.v1',
        'status': 'VERIFIED_CUSTODY_ONLY',
        'verified_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'remote_manifest': identity(manifest_raw), 'chunks': len(receipts),
        'compressed_bytes': len(archive), 'compressed_sha256': hashlib.sha256(archive).hexdigest(),
        'archive_equals_original_file': True, 'gzip_full_crc_and_length_verified': True,
        'members': len(observed), 'member_bytes': sum(row['bytes'] for row in observed),
        'complete_member_readback': observed, 'tar': tar_identity,
        'all_original_raw_files_and_modes_still_equal': True,
        'original_result': manifest['result']['status'],
        'product_executed': False, 'product_refs_changed': False, 'qualification': False,
        'self_contained_terminal_product_source': False,
        'original_core_source_dependencies': manifest['original_core_source_dependencies'],
    }
    write_json(HERE / 'GIT-CUSTODY/LOCAL-READBACK.json', report)
    print(json.dumps({k:v for k,v in report.items() if k != 'complete_member_readback'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('prepare', 'verify-remote'))
    args = parser.parse_args()
    (prepare if args.operation == 'prepare' else verify_remote)()
