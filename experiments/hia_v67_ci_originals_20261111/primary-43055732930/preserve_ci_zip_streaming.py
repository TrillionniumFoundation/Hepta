"""Preserve one exact official CI ZIP as checked parts without duplicate storage."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import time

import zstandard

PART_BYTES = 4 * 1024 * 1024


def identity(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and not path.is_symlink()
    return tuple(getattr(s, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert path.read_bytes() == raw


class PartitionSink:
    def __init__(self, root):
        self.root = root
        (root / 'original-zip-parts').mkdir(mode=0o700)
        self.buffer = bytearray()
        self.parts = []
        self.hash = hashlib.sha256()
        self.total = 0

    def write(self, raw):
        self.buffer.extend(raw)
        while len(self.buffer) >= PART_BYTES:
            self.emit(bytes(self.buffer[:PART_BYTES]))
            del self.buffer[:PART_BYTES]
        return len(raw)

    def emit(self, raw):
        name = f'original-zip-parts/original.zip.zst.part{len(self.parts):03d}'
        path = self.root / name
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        assert path.read_bytes() == raw
        self.hash.update(raw)
        self.total += len(raw)
        self.parts.append({'path': name, 'bytes': len(raw),
                           'sha256': hashlib.sha256(raw).hexdigest(),
                           'git_blob_sha1': hashlib.sha1(
                               b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()})

    def finish(self):
        if self.buffer:
            self.emit(bytes(self.buffer))
            self.buffer.clear()


class PartsReader(io.RawIOBase):
    def __init__(self, root, parts):
        super().__init__()
        self.root = root
        self.parts = parts
        self.index = 0
        self.buffer = b''
        self.offset = 0
        self.hash = hashlib.sha256()
        self.total = 0

    def readable(self):
        return True

    def readinto(self, target):
        if self.offset == len(self.buffer):
            if self.index == len(self.parts):
                return 0
            row = self.parts[self.index]
            expected_path = f'original-zip-parts/original.zip.zst.part{self.index:03d}'
            assert row['path'] == expected_path
            path = self.root / expected_path
            before = identity(path)
            raw = path.read_bytes()
            assert before == identity(path)
            assert len(raw) == row['bytes'] <= PART_BYTES
            assert len(raw) > 0 and hashlib.sha256(raw).hexdigest() == row['sha256']
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob_sha1']
            self.hash.update(raw)
            self.total += len(raw)
            self.buffer, self.offset = raw, 0
            self.index += 1
        count = min(len(target), len(self.buffer) - self.offset)
        target[:count] = self.buffer[self.offset:self.offset + count]
        self.offset += count
        return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--bytes', type=int, required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--artifact-id', type=int, required=True)
    parser.add_argument('--workflow-status', choices=['SUCCESS', 'FAILURE'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic_ns()
    before = identity(args.archive)
    assert before[3] == args.bytes and digest(args.archive) == args.sha256
    sink = PartitionSink(args.output)
    parameters = zstandard.ZstdCompressionParameters.from_level(
        9, window_log=27, enable_ldm=True, ldm_hash_log=23,
        threads=0, write_checksum=1, write_content_size=1)
    with args.archive.open('rb') as source:
        read_bytes, written_bytes = zstandard.ZstdCompressor(
            compression_params=parameters).copy_stream(source, sink, size=args.bytes)
    sink.finish()
    assert read_bytes == args.bytes and written_bytes == sink.total
    parts = PartsReader(args.output, sink.parts)
    decoded_sha = hashlib.sha256()
    total = 0
    with zstandard.ZstdDecompressor().stream_reader(parts) as decoded, args.archive.open('rb') as original:
        for block in iter(lambda: decoded.read(1 << 20), b''):
            assert original.read(len(block)) == block
            total += len(block)
            decoded_sha.update(block)
        assert original.read(1) == b''
    assert parts.index == len(sink.parts) and parts.offset == len(parts.buffer)
    assert parts.total == sink.total and parts.hash.hexdigest() == sink.hash.hexdigest()
    assert total == args.bytes and decoded_sha.hexdigest() == args.sha256
    assert identity(args.archive) == before
    report = {
        'schema': 'hia.lossless-original-ci-zip-preservation.v2',
        'status': 'LOCAL_FULL_ORIGINAL_ZIP_ROUNDTRIP_VERIFIED',
        'original': {'path': str(args.archive), 'bytes': args.bytes,
                     'sha256': args.sha256, 'run_id': args.run_id,
                     'artifact_id': args.artifact_id, 'workflow_status': args.workflow_status},
        'compressed': {'bytes': sink.total, 'sha256': sink.hash.hexdigest(),
                       'format': 'zstandard', 'library_version': zstandard.__version__,
                       'level': 9, 'window_log': 27, 'enable_ldm': True,
                       'ldm_hash_log': 23, 'threads': 0, 'checksum': True},
        'parts': sink.parts, 'part_bytes_limit': PART_BYTES,
        'exact_original_bytes_compared_after_decode': True,
        'independent_decoded_bytes': total,
        'independent_decoded_sha256': decoded_sha.hexdigest(),
        'all_parts_read_back_and_combined_sha256_verified': True,
        'source_identity_unchanged': True,
        'elapsed_ns': time.monotonic_ns() - started,
        'original_workflow_status_unchanged': True,
        'original_product_tests_rerun': False,
        'publication_completed': False,
        'whole_native_delivery_qualified': False}
    save(args.output / 'ORIGINAL-ZIP-PRESERVATION.json', report)
    print(json.dumps({key: value for key, value in report.items() if key != 'parts'}))


if __name__ == '__main__':
    main()
