"""Losslessly compress and split the fixed original ZIP without changing it."""
import hashlib
import json
import os
from pathlib import Path
import time
import zstandard

BASE = Path('/tmp/hia-e26e-d2-ci-independent-review-r1')
SOURCE = Path('/tmp/hia-e26e-d2-ci-artifact-13860171868.zip')
EXPECTED = '63f7ddd6c0857956e10cb03823836bb284eb2142bd269a98d124c4b5bf086a56'
SIZE = 111981819
PART_BYTES = 4 * 1024 * 1024

def identity(p):
    s = p.lstat()
    return s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns

def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        while b := f.read(1024 * 1024):
            h.update(b)
    return h.hexdigest()

def save_json(path, obj):
    raw = (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    assert path.read_bytes() == raw

def main():
    started = time.monotonic_ns()
    before = identity(SOURCE)
    assert SOURCE.stat().st_size == SIZE and digest(SOURCE) == EXPECTED
    parameters = zstandard.ZstdCompressionParameters.from_level(9, window_log=27,
        enable_ldm=True, ldm_hash_log=23, threads=0, write_checksum=1, write_content_size=1)
    output = BASE / 'original-zip.zst'
    compressor = zstandard.ZstdCompressor(compression_params=parameters)
    with SOURCE.open('rb') as source, output.open('xb') as target:
        read_bytes, written_bytes = compressor.copy_stream(source, target, size=SIZE)
        target.flush()
        os.fsync(target.fileno())
    assert read_bytes == SIZE and written_bytes == output.stat().st_size
    h = hashlib.sha256()
    total = 0
    with output.open('rb') as source, zstandard.ZstdDecompressor().stream_reader(source) as decoded, SOURCE.open('rb') as original:
        while block := decoded.read(1024 * 1024):
            assert original.read(len(block)) == block
            h.update(block)
            total += len(block)
        assert original.read(1) == b''
    assert total == SIZE and h.hexdigest() == EXPECTED
    compressed_sha = digest(output)
    parts_dir = BASE / 'original-zip-parts'
    parts_dir.mkdir(mode=0o700)
    parts = []
    combined = hashlib.sha256()
    with output.open('rb') as source:
        index = 0
        while block := source.read(PART_BYTES):
            part = parts_dir / f'original.zip.zst.part{index:03d}'
            with part.open('xb') as f:
                f.write(block)
                f.flush()
                os.fsync(f.fileno())
            readback = part.read_bytes()
            assert readback == block
            combined.update(readback)
            parts.append({'path': str(part.relative_to(BASE)), 'bytes': len(block),
                'sha256': hashlib.sha256(block).hexdigest(),
                'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(block)).encode() + b'\0' + block).hexdigest()})
            index += 1
    assert combined.hexdigest() == compressed_sha
    assert sum(p['bytes'] for p in parts) == output.stat().st_size
    assert identity(SOURCE) == before
    receipt = {'schema': 'hia.lossless-original-ci-zip-preservation.v1',
        'status': 'LOCAL_FULL_ORIGINAL_ZIP_ROUNDTRIP_VERIFIED',
        'original': {'path': str(SOURCE), 'bytes': SIZE, 'sha256': EXPECTED,
                     'run_id': 43024566228, 'artifact_id': 13860171868, 'workflow_status': 'FAILURE'},
        'compressed': {'path': str(output), 'bytes': output.stat().st_size, 'sha256': compressed_sha,
            'format': 'zstandard', 'library_version': zstandard.__version__, 'level': 9, 'window_log': 27,
            'enable_ldm': True, 'ldm_hash_log': 23, 'threads': 0, 'checksum': True},
        'parts': parts, 'part_bytes_limit': PART_BYTES,
        'exact_original_bytes_compared_after_decode': True,
        'independent_decoded_sha256': h.hexdigest(), 'independent_decoded_bytes': total,
        'all_parts_read_back_and_combined_sha256_verified': True,
        'source_identity_unchanged': True, 'elapsed_ns': time.monotonic_ns() - started,
        'publication_completed': False, 'whole_native_delivery_qualified': False,
        'original_ci_failure_unchanged': True}
    save_json(BASE / 'ORIGINAL-ZIP-PRESERVATION.json', receipt)
    print(json.dumps(receipt), flush=True)

if __name__ == '__main__':
    main()
