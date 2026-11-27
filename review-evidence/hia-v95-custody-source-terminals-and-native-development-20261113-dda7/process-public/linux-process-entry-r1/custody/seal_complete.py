"""Preserve every original record and exact delta; no project execution."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'custody'
assert OUT.is_dir()
assert not (OUT / 'MANIFEST.json').exists()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode()


def put(name, raw):
    p = OUT / name
    assert not p.exists(), name
    p.write_bytes(raw)
    return {'path': name, 'local_path': str(p), **identity(raw)}


start = time.perf_counter()
source_plan = json.loads((ROOT / 'handoff/GIT-ACK-READBACK.json').read_text())
report = json.loads((ROOT / 'handoff/RESULT.json').read_text())
base = json.loads((ROOT / 'BASE.json').read_text())
paths = {}
for folder in ('authoring', 'evidence'):
    for p in sorted((ROOT / folder).rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts:
            paths[str(p.relative_to(ROOT))] = p
paths['BASE.json'] = ROOT / 'BASE.json'
paths['custody/seal_complete.py'] = Path(__file__)
for p in sorted((ROOT / 'handoff').glob('*')):
    if p.is_file(): paths['handoff/' + p.name] = p
import zlib
packet = json.loads((ROOT / 'handoff/SOURCE-PACKET.zlib.json').read_bytes())
source = json.loads(zlib.decompress(base64.b64decode(packet['payload'])))
for name, row in source['files'].items():
    paths['source-delta/' + name] = ROOT / 'source' / name
    if row['before'] is not None:
        original = Path(base['base']) / name
        assert identity(original.read_bytes()) == {k: row['before'][k] for k in ('bytes','sha256','git_blob')}
        paths['base-preimages/' + name] = original
for name in ('tests/test_hia_program.py', 'tests/test_hia_agent_assembly.py', 'tests/test_hia_linux_stdio.py'):
    paths['frozen-original-tests/' + name] = ROOT / 'source' / name
logical, pool, objects = {}, {}, {}
for name, p in sorted(paths.items()):
    assert p.is_file() and not p.is_symlink(), name
    raw = p.read_bytes()
    row = identity(raw)
    logical[name] = {**row, 'mode': oct(stat.S_IMODE(p.stat().st_mode))}
    pool.setdefault(row['sha256'], p)
    objects[row['sha256']] = row
manifest = {
    'schema': 'hia.content-addressed-originals.v1',
    'logical_files': logical, 'objects': objects,
    'logical_bytes': sum(row['bytes'] for row in logical.values()),
    'unique_bytes': sum(row['bytes'] for row in objects.values()),
    'source_packet': {**source_plan['entries'][0], 'git_blob': source_plan['entries'][0]['sha']},
    'complete_originals_including_all_failures': True,
    'base_tree': base['expected_tree'], 'base_scope': 'Frozen public Linux stdio cold r1 development source; no cold positive',
    'final_source_tree': report['source_tree'],
    'complete_source_recovery': 'Exact base tree3b15e plus12 exact delta paths; source packet0e11 includes full before/after and all3053 manifest; all logical raw originals and preceding failures retained',
    'base_packet': base['source_packet'],
    'matching_cold': False, 'whole': False,
}
manifest_raw = json_bytes(manifest)
manifest_entry = put('MANIFEST.json', manifest_raw)
archive = OUT / 'ORIGINALS.tar.gz'
assert not archive.exists()
with archive.open('wb') as stream:
    with gzip.GzipFile(filename='', fileobj=stream, mode='wb', compresslevel=1, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
            for name, p in [('MANIFEST.json', None)] + [('objects/' + sha, p) for sha, p in sorted(pool.items())]:
                raw = manifest_raw if p is None else p.read_bytes()
                if p is not None:
                    assert identity(raw) == objects[name[8:]], name
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o644
                member.mtime = 0
                member.uid = member.gid = 0
                member.uname = member.gname = ''
                tar.addfile(member, io.BytesIO(raw))
seen = set()
with tarfile.open(archive, mode='r:gz') as tar:
    for member in tar:
        assert member.isfile() and member.name not in seen
        assert member.mode == 0o644 and member.mtime == 0
        seen.add(member.name)
        raw = tar.extractfile(member).read()
        if member.name == 'MANIFEST.json':
            assert raw == manifest_raw
        else:
            sha = member.name.removeprefix('objects/')
            assert sha in pool and identity(raw) == objects[sha]
            assert raw == pool[sha].read_bytes()
assert len(seen) == len(pool) + 1
archive_raw = archive.read_bytes()
parts, entries = [], []
for index, offset in enumerate(range(0, len(archive_raw), 384 * 1024)):
    raw = archive_raw[offset:offset + 384 * 1024]
    wrapper = {'schema': 'hia.raw-gzip-chunk.v1', 'index': index, 'offset': offset,
               'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
               'encoding': 'base64', 'payload': base64.b64encode(raw).decode()}
    e = put('originals-part-%03d.json' % index, json_bytes(wrapper))
    entries.append(e)
    parts.append({'index': index, 'offset': offset, 'raw_bytes': len(raw),
                  'raw_sha256': wrapper['sha256'], 'wrapper': e})
assert b''.join(base64.b64decode(json.loads((OUT / e['path']).read_text())['payload']) for e in entries) == archive_raw
transport = put('TRANSPORT.json', json_bytes({
    'schema': 'hia.complete-originals-transport.v1',
    'archive': {**identity(archive_raw), 'format': 'deterministic tar+gzip1'},
    'manifest': manifest_entry, 'source_packet': {**source_plan['entries'][0], 'git_blob': source_plan['entries'][0]['sha']},
    'logical_files': len(logical), 'unique_objects': len(pool),
    'logical_bytes': manifest['logical_bytes'], 'unique_bytes': manifest['unique_bytes'],
    'parts': parts, 'full_tar_bytes_readback': True,
    'matching_cold': False, 'whole': False,
}))
plan = put('RAW-UPLOAD-PLAN.json', json_bytes({
    'repository': 'TrillionniumFoundation/Hepta',
    'entries': [manifest_entry, transport, *entries],
    'archive': identity(archive_raw), 'source_packet': {**source_plan['entries'][0], 'git_blob': source_plan['entries'][0]['sha']},
    'logical_files': len(logical), 'unique_objects': len(pool),
    'logical_bytes': manifest['logical_bytes'], 'unique_bytes': manifest['unique_bytes'],
    'full_tar_bytes_readback': True, 'product_refs_modified': False,
}))
print(json.dumps({'status': 'RAW_SEALED_LOCALLY', 'transport': transport, 'plan': plan,
    'archive': identity(archive_raw), 'parts': len(parts),
    'logical_files': len(logical), 'unique_objects': len(pool),
    'logical_bytes': manifest['logical_bytes'], 'unique_bytes': manifest['unique_bytes'],
    'wall_seconds': time.perf_counter() - start}, indent=2), flush=True)
