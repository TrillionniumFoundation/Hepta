"""Restore and independently reread the exact original CI artifact."""
import hashlib
import json
import os
from pathlib import Path
import sys
import zstandard
from preserve_ci_zip_streaming import PartsReader, digest, save

EXPECTED_RECEIPT_SHA256 = 'a51422c70fae8724bb61ce4e6c3c3823aae856ca8a69a643d689b9ff885b4cc0'
EXPECTED_BYTES = 138488201
EXPECTED_SHA256 = '471bd77b07d2b3e992f5a3eca2b7f3ac8fcba530e90bc0f8d708f200847a6477'
EXPECTED_COMPRESSED_BYTES = 65734700
EXPECTED_COMPRESSED_SHA256 = '92db978efd67b7f3053531d28aa2a9ef4e1096063350a3d559e98c12ee81b395'
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
    destination = output / 'hia-v67-ci-artifact-13872014360-original.zip'
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
