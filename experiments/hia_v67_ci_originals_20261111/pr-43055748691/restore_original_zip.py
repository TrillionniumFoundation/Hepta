"""Restore and independently reread the exact original CI artifact."""
import hashlib
import json
import os
from pathlib import Path
import sys
import zstandard
from preserve_ci_zip_streaming import PartsReader, digest, save

EXPECTED_RECEIPT_SHA256 = '30a4c389270bc63270aab91e96b3874c4279b08d90154a7e3ef39f7232232191'
EXPECTED_BYTES = 138501387
EXPECTED_SHA256 = 'f6b0ed41f41736ecdd307337bc93a83df7866eb20641cea627c21d30a0b5bd1e'
EXPECTED_COMPRESSED_BYTES = 65633833
EXPECTED_COMPRESSED_SHA256 = '23e2884f5cf6297d24a5df66a277a15c65b12fa3eee73d2d6e52500abf505deb'
EXPECTED_PARTS = 16


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: python restore_original_zip.py NEW_PRIVATE_DIRECTORY')
    base = Path(__file__).resolve().parent
    raw = (base / 'ORIGINAL-ZIP-PRESERVATION.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_RECEIPT_SHA256
    receipt = json.loads(raw)
    assert receipt['original']['bytes'] == EXPECTED_BYTES
    assert receipt['original']['sha256'] == EXPECTED_SHA256
    assert receipt['compressed']['bytes'] == EXPECTED_COMPRESSED_BYTES
    assert receipt['compressed']['sha256'] == EXPECTED_COMPRESSED_SHA256
    assert len(receipt['parts']) == EXPECTED_PARTS
    output = Path(sys.argv[1])
    output.mkdir(mode=0o700)
    destination = output / 'hia-v67-ci-artifact-13872969519-original.zip'
    source = PartsReader(base, receipt['parts'])
    h = hashlib.sha256()
    total = 0
    with zstandard.ZstdDecompressor().stream_reader(source) as decoded, destination.open('xb') as f:
        while block := decoded.read(1 << 20):
            f.write(block)
            h.update(block)
            total += len(block)
            assert total <= EXPECTED_BYTES
        f.flush()
        os.fsync(f.fileno())
    assert source.index == EXPECTED_PARTS and source.offset == len(source.buffer)
    assert source.total == EXPECTED_COMPRESSED_BYTES
    assert source.hash.hexdigest() == EXPECTED_COMPRESSED_SHA256
    assert total == EXPECTED_BYTES and h.hexdigest() == EXPECTED_SHA256
    assert destination.stat().st_size == EXPECTED_BYTES and digest(destination) == EXPECTED_SHA256
    result = {'schema': 'hia.original-ci-zip-restoration.v2',
               'status': 'EXACT_ORIGINAL_BYTES_RESTORED',
               'path': str(destination), 'bytes': total, 'sha256': h.hexdigest(),
               'compressed_bytes': source.total, 'compressed_sha256': source.hash.hexdigest(),
               'parts': EXPECTED_PARTS, 'all_parts_git_sha1_sha256_size_verified': True,
               'decoded_file_independently_read_back': True,
               'original_workflow_status': receipt['original']['workflow_status'],
               'product_tests_rerun': False, 'whole_native_delivery_qualified': False}
    save(output / 'RESTORATION.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
