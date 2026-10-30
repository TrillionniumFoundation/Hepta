#!/usr/bin/python3
"""Preserve an authorized CI artifact without an on-disk ZIP or extraction tree.

The signed URL arrives only over a terminal with echo disabled. It is never
written into receipts. Download bytes and compressed output remain in bounded
memory until output size and member-by-member verification are known.
"""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import termios
import time
import urllib.parse
import urllib.request
import zipfile


DEST = Path('/workspace/scratch/8245a7ab856a/run-evidence/final-ci-readonly-1c13/41017484010')
CHUNK = 1024 * 1024
RESERVE = 8 * CHUNK


def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(CHUNK), b''):
            h.update(data)
    return h.hexdigest()


def save(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


class LimitedBuffer(io.BytesIO):
    def __init__(self, limit):
        super().__init__()
        self.limit = limit

    def write(self, data):
        if self.tell() + len(data) > self.limit:
            raise ValueError('compressed_archive_would_exceed_available_space_with_reserve')
        return super().write(data)


class HashReader:
    def __init__(self, source):
        self.source = source
        self.h = hashlib.sha256()
        self.count = 0

    def read(self, count=-1):
        data = self.source.read(count)
        self.h.update(data)
        self.count += len(data)
        return data


def safe_member(info, seen):
    name = info.filename
    body = name[:-1] if info.is_dir() else name
    parts = PurePosixPath(body).parts
    if (not body or '\x00' in name or '\\' in name or body.startswith('/')
            or any(part in ('', '.', '..') for part in body.split('/'))
            or not parts or ':' in parts[0] or str(PurePosixPath(body)) != body
            or body in seen or info.flag_bits & 1):
        raise ValueError('unsafe_duplicate_or_encrypted_zip_member')
    seen.add(body)
    mode = (info.external_attr >> 16) & 0xffff
    kind = stat.S_IFMT(mode)
    permitted = (0, stat.S_IFDIR) if info.is_dir() else (0, stat.S_IFREG)
    if kind not in permitted or (info.is_dir() and info.file_size != 0):
        raise ValueError('non_regular_zip_member')
    return body, mode


def verify_tar(source, members):
    source.seek(0)
    count = 0
    with tarfile.open(fileobj=source, mode='r|xz') as tar:
        for member in tar:
            if count >= len(members):
                raise ValueError('extra_tar_member')
            expected = members[count]
            if (member.name != expected['tar_name'] or member.size != expected['bytes']
                    or member.isdir() != expected['directory']
                    or not (member.isdir() or member.isreg())):
                raise ValueError('tar_member_shape_mismatch')
            h = hashlib.sha256()
            actual_size = 0
            if not member.isdir():
                with tar.extractfile(member) as stream:
                    for data in iter(lambda: stream.read(CHUNK), b''):
                        h.update(data)
                        actual_size += len(data)
            if actual_size != expected['bytes'] or h.hexdigest() != expected['sha256']:
                raise ValueError('tar_member_payload_mismatch')
            count += 1
    if count != len(members):
        raise ValueError('missing_tar_member')
    return count


def main():
    started = time.monotonic_ns()
    attributes = termios.tcgetattr(sys.stdin.fileno())
    quiet = list(attributes)
    quiet[3] &= ~termios.ECHO
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, quiet)
    print('READY_FOR_EPHEMERAL_URL_NO_ECHO', flush=True)
    try:
        request = json.loads(sys.stdin.readline())
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, attributes)
    url = request.pop('download_url')
    metadata = request['artifact']
    if urllib.parse.urlparse(url).scheme != 'https':
        raise ValueError('https_download_required')
    if metadata['id'] != 12960198980 or metadata['workflow_run']['id'] != 41017484010:
        raise ValueError('unexpected_artifact_identity')
    if metadata['workflow_run']['head_sha'] != '1c13caeb08993fcbb2c4d64e6b10f22f3356c18f':
        raise ValueError('unexpected_source_identity')
    artifact_id = metadata['id']
    archive_path = DEST / f'artifact-{artifact_id}.tar.xz'
    partial_path = DEST / f'artifact-{artifact_id}.tar.xz.partial'
    manifest_path = DEST / f'artifact-{artifact_id}.manifest.json'
    metadata_path = DEST / f'artifact-{artifact_id}.api.json'
    if any(path.exists() for path in (archive_path, partial_path, manifest_path, metadata_path)):
        raise ValueError('archive_output_already_exists')
    disk_before = shutil.disk_usage(DEST).free
    output_limit = disk_before - RESERVE
    if output_limit <= 0:
        raise ValueError('insufficient_disk_reserve_before_download')
    download = io.BytesIO()
    download_hash = hashlib.sha256()
    downloaded = 0
    print('DOWNLOADING_ONCE_TO_MEMORY', metadata['size_in_bytes'], flush=True)
    with urllib.request.urlopen(url, timeout=60) as response:
        while True:
            data = response.read(CHUNK)
            if not data:
                break
            downloaded += len(data)
            if downloaded > metadata['size_in_bytes']:
                raise ValueError('zip_size_exceeds_api_size')
            download_hash.update(data)
            download.write(data)
    url = None
    actual_zip_sha = download_hash.hexdigest()
    if downloaded != metadata['size_in_bytes'] or 'sha256:' + actual_zip_sha != metadata['digest']:
        raise ValueError('zip_api_digest_or_size_mismatch')
    print('ZIP_API_DIGEST_MATCH', downloaded, actual_zip_sha, flush=True)
    compressed = LimitedBuffer(output_limit)
    members = []
    with zipfile.ZipFile(download) as original:
        entries = original.infolist()
        if len(entries) > 100000 or sum(i.file_size for i in entries) > 4 * 1024**3:
            raise ValueError('artifact_member_or_uncompressed_size_limit')
        seen = set()
        validated = [(info, *safe_member(info, seen)) for info in entries]
        print('MEMBER_PREFLIGHT_OK', len(entries), 'UNCOMPRESSED_BYTES', sum(i.file_size for i in entries), flush=True)
        with tarfile.open(fileobj=compressed, mode='w:xz', preset=6) as tar:
            for index, (info, name, mode) in enumerate(validated):
                target = tarfile.TarInfo(name)
                target.size = info.file_size
                target.type = tarfile.DIRTYPE if info.is_dir() else tarfile.REGTYPE
                target.mode = stat.S_IMODE(mode) or (0o755 if info.is_dir() else 0o644)
                target.uid = target.gid = 0
                target.mtime = 0
                with original.open(info) as source:
                    stream = HashReader(source)
                    tar.addfile(target, None if info.is_dir() else stream)
                    if stream.read(1) or stream.count != info.file_size:
                        raise ValueError('zip_member_size_mismatch')
                    member_sha = stream.h.hexdigest()
                members.append({'zip_name': info.filename, 'tar_name': name,
                                'directory': info.is_dir(), 'bytes': info.file_size,
                                'sha256': member_sha, 'zip_crc32': f'{info.CRC:08x}',
                                'zip_compressed_bytes': info.compress_size,
                                'zip_compression': info.compress_type,
                                'zip_external_attr': info.external_attr,
                                'zip_create_system': info.create_system,
                                'zip_flag_bits': info.flag_bits,
                                'zip_date_time': list(info.date_time),
                                'zip_extra_hex': info.extra.hex(),
                                'zip_comment_hex': info.comment.hex(),
                                'tar_mode': target.mode})
                if (index + 1) % 100 == 0:
                    print('PACKED', index + 1, 'OF', len(entries), flush=True)
        zip_comment_hex = original.comment.hex()
    compressed_bytes = compressed.tell()
    archive_sha = hashlib.sha256(compressed.getbuffer()).hexdigest()
    verified_memory = verify_tar(compressed, members)
    print('IN_MEMORY_TAR_VERIFIED', verified_memory, 'COMPRESSED_BYTES', compressed_bytes, flush=True)
    download.close()
    if shutil.disk_usage(DEST).free < compressed_bytes + RESERVE:
        raise ValueError('insufficient_disk_reserve_before_final_write')
    compressed.seek(0)
    with partial_path.open('xb') as target:
        shutil.copyfileobj(compressed, target, CHUNK)
        target.flush()
        os.fsync(target.fileno())
    compressed.close()
    if partial_path.stat().st_size != compressed_bytes or sha_file(partial_path) != archive_sha:
        raise ValueError('written_archive_digest_mismatch')
    with partial_path.open('rb') as stored:
        verified_disk = verify_tar(stored, members)
    os.link(partial_path, archive_path)
    partial_path.unlink()
    save(metadata_path, {'schema': 'hepta.ci-artifact-api-observation.v1',
                         'retrieved_at_utc': request['retrieved_at_utc'],
                         'source': 'GitHub connector fetch_workflow_run_artifacts',
                         'artifact': metadata})
    manifest = {
        'schema': 'hepta.ci-artifact-lossless-payload-archive.v1',
        'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'run_id': 41017484010, 'run_attempt': 1,
        'source_commit': metadata['workflow_run']['head_sha'],
        'artifact_id': artifact_id, 'artifact_name': metadata['name'],
        'original_zip_bytes': downloaded, 'original_zip_sha256': actual_zip_sha,
        'github_api_digest': metadata['digest'], 'github_api_digest_verified': True,
        'original_zip_retained_on_disk': False,
        'original_member_bytes_retained': True,
        'original_zip_container_reproducibility_claimed': False,
        'signed_download_url_retained': False,
        'archive': {'path': str(archive_path), 'bytes': compressed_bytes,
                    'sha256': archive_sha, 'format': 'tar.xz', 'xz_preset': 6},
        'api_metadata_path': str(metadata_path),
        'zip_archive_comment_hex': zip_comment_hex,
        'member_count': len(members),
        'total_member_bytes': sum(x['bytes'] for x in members),
        'safe_paths_and_regular_file_directory_types_only': True,
        'before_disk_write_verified_members': verified_memory,
        'after_disk_write_verified_members': verified_disk,
        'all_member_hashes_match_original_zip': True,
        'tar_metadata_policy': 'Original ZIP metadata retained per member in this manifest; tar uid/gid/mtime normalized to zero, member mode derived from ZIP permission bits, names and payload bytes preserved.',
        'disk_free_before_bytes': disk_before,
        'disk_free_after_archive_bytes': shutil.disk_usage(DEST).free,
        'model_requests': 0, 'native_executions': 0,
        'scope': 'Read-only download, digest verification and payload-preserving archive of an already completed CI run; no workflow or benchmark rerun.',
        'archive_operation_wall_ns': time.monotonic_ns() - started,
        'members': members,
    }
    save(manifest_path, manifest)
    print(json.dumps({'status': 'archived_and_all_members_verified',
                      'archive': manifest['archive'], 'manifest_path': str(manifest_path),
                      'manifest_sha256': sha_file(manifest_path),
                      'member_count': len(members), 'member_bytes': manifest['total_member_bytes'],
                      'disk_free_after_bytes': shutil.disk_usage(DEST).free}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # urllib exceptions can embed signed URLs. Do not echo arbitrary errors.
        safe = str(error) if type(error) is ValueError else 'details_omitted_to_protect_ephemeral_url'
        print(json.dumps({'status': 'archive_failed', 'error_type': type(error).__name__,
                          'safe_detail': safe}), flush=True)
        sys.exit(1)
