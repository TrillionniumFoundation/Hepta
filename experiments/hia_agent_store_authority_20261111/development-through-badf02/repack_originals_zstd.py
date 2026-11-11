from pathlib import Path
from hashlib import sha256
import json, lzma, tarfile, time
import zstandard

root = Path(__file__).resolve().parent
source = root / 'raw-development-originals.tar.xz'
target = root / 'raw-development-originals.tar.zst'
if target.exists(): raise FileExistsError(target)
started = time.monotonic()
parameters = zstandard.ZstdCompressionParameters.from_level(7, enable_ldm=True, window_log=28, ldm_hash_log=20)
original_tar_hash = sha256(); original_tar_size = 0
with lzma.open(source, 'rb') as incoming, target.open('xb') as outgoing:
    with zstandard.ZstdCompressor(compression_params=parameters).stream_writer(outgoing, closefd=False) as compressed:
        while raw := incoming.read(1 << 20):
            original_tar_hash.update(raw); original_tar_size += len(raw); compressed.write(raw)
restored_tar_hash = sha256(); restored_tar_size = 0
with target.open('rb') as compressed:
    with zstandard.ZstdDecompressor(max_window_size=1 << 28).stream_reader(compressed) as restored:
        while raw := restored.read(1 << 20):
            restored_tar_hash.update(raw); restored_tar_size += len(raw)
assert (restored_tar_hash.hexdigest(), restored_tar_size) == (original_tar_hash.hexdigest(), original_tar_size)
inventory_raw = (root / 'originals-manifest.json').read_bytes()
inventory = json.loads(inventory_raw)
expected = {row['path']: row for row in inventory['entries']}
observed = []
with target.open('rb') as compressed:
    with zstandard.ZstdDecompressor(max_window_size=1 << 28).stream_reader(compressed) as restored:
        with tarfile.open(fileobj=restored, mode='r|') as tar:
            for member in tar:
                if member.name == 'ORIGINALS_MANIFEST.json':
                    assert tar.extractfile(member).read() == inventory_raw
                    continue
                row = expected[member.name]
                assert (member.mode, member.uid, member.gid, member.size) == (row['mode'], row['uid'], row['gid'], row['size'])
                if row['type'] == 'file':
                    assert member.isfile()
                    h = sha256()
                    with tar.extractfile(member) as handle:
                        while raw := handle.read(1 << 20): h.update(raw)
                    assert h.hexdigest() == row['sha256']
                elif row['type'] == 'directory': assert member.isdir()
                else: assert member.issym() and member.linkname == row['target']
                observed.append(member.name)
assert len(observed) == len(set(observed)) == len(expected) and set(observed) == set(expected)
parts_dir = root / 'zstd-parts'; parts_dir.mkdir(mode=0o700)
archive_hash = sha256(); parts = []
with target.open('rb') as handle:
    while raw := handle.read(524286):
        name = f'raw-development-originals.tar.zst.part-{len(parts):03d}'
        (parts_dir / name).write_bytes(raw); archive_hash.update(raw)
        parts.append({'path': 'zstd-parts/' + name, 'size': len(raw), 'sha256': sha256(raw).hexdigest()})
reassembled = sha256()
for part in parts:
    raw = (root / part['path']).read_bytes(); assert sha256(raw).hexdigest() == part['sha256']
    reassembled.update(raw)
assert reassembled.hexdigest() == archive_hash.hexdigest()
receipt = {'schema': 'hia.agent-store-authority-original-evidence-zstd.v1', 'status': 'PASS',
    'archive': {'path': target.name, 'size': target.stat().st_size, 'sha256': archive_hash.hexdigest()},
    'decompressed_tar': {'size': original_tar_size, 'sha256': original_tar_hash.hexdigest()},
    'original_xz_archive': json.loads((root / 'ARCHIVE.json').read_bytes())['archive'],
    'exact_original_tar_bytes_preserved': True,
    'all_original_bytes_modes_uid_gid_independently_read_back': True,
    'original_inventory_sha256': sha256(inventory_raw).hexdigest(),
    'original_entries': len(expected), 'original_regular_files': sum(r['type'] == 'file' for r in expected.values()),
    'original_regular_bytes': sum(r['size'] for r in expected.values() if r['type'] == 'file'),
    'encoder': {'module': 'zstandard', 'version': zstandard.__version__, 'level': 7, 'enable_ldm': True, 'window_log': 28, 'ldm_hash_log': 20},
    'parts': parts, 'parts_concatenation_matches_archive': True, 'wall_seconds': time.monotonic() - started,
    'originals_deleted': False}
(root / 'ZSTD.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({k:v for k,v in receipt.items() if k!='parts'}, indent=2, sort_keys=True))
