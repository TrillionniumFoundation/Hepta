"""Seal completed root work and the exact delta from published JSON-entry r2."""
from hashlib import sha256
import io
import json
import lzma
from pathlib import Path
import stat
import tarfile
import time

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent
started = time.monotonic_ns()
previous_index = ROOT / 'recovery-completed-r12/json-r2-original-index.json'
previous_raw = previous_index.read_bytes()
previous = {r['path']: r for r in json.loads(previous_raw)}
rows, inherited = [], []
for name in ('native-edit-json-next', 'native-edit-performance-next', 'native-edit-candidate-next'):
    directory = ROOT / name
    for path in sorted(directory.rglob('*')):
        if not path.is_file() or '__pycache__' in path.parts:
            continue
        assert not path.is_symlink()
        raw = path.read_bytes()
        info = path.stat()
        relative = path.relative_to(directory).as_posix()
        digest = sha256(raw).hexdigest()
        mode = stat.S_IMODE(info.st_mode)
        old = previous.get(relative) if name == 'native-edit-json-next' else None
        row = dict(path=path.relative_to(ROOT).as_posix(), source=str(path), bytes=len(raw), sha256=digest, mode=mode)
        if old and (old['bytes'], old['sha256'], old['mode']) == (len(raw), digest, mode):
            inherited.append(row)
            continue
        if old:
            row['previous_archived_sha256'] = old['sha256']
        rows.append(row)
manifest = dict(schema='hia.complete-root-development-originals.v1', files=rows,
                inherited_unchanged_json_r2_files=inherited,
                inherited_source_index_sha256=sha256(previous_raw).hexdigest(),
                inherited_archive_sha256='8e4b36ea73f09525069bba9e1793dfdd7e72fbb3e6e9e3a0711d0184594e4d15',
                inherited_published_commit='815c3ed02025d5532237b8f8a68c7d033f559cd5',
                scope='COMPLETE_PERFORMANCE_AND_CANDIDATE_DIRECTORIES_PLUS_JSON_R3_DELTA_ALL_FAILED_ATTEMPTS_RETAINED')
index = OUT / 'root-completed-index.json'
assert not index.exists()
index.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
index_raw = index.read_bytes()
archive = OUT / 'root-completed-development.tar.xz'
assert not archive.exists()
with lzma.open(archive, 'wb', preset=0) as sink, tarfile.open(fileobj=sink, mode='w|') as tf:
    header = tarfile.TarInfo('MANIFEST.json')
    header.size, header.mode = len(index_raw), 0o644
    tf.addfile(header, io.BytesIO(index_raw))
    for row in rows:
        path = Path(row['source'])
        raw = path.read_bytes()
        assert (len(raw), sha256(raw).hexdigest(), stat.S_IMODE(path.stat().st_mode)) == (row['bytes'], row['sha256'], row['mode'])
        member = tarfile.TarInfo(row['path'])
        member.size, member.mode = len(raw), row['mode']
        tf.addfile(member, io.BytesIO(raw))
expected = {r['path']: r for r in rows}
assert len(expected) == len(rows)
seen = set()
total = 0
with tarfile.open(archive, 'r|xz') as tf:
    for member in tf:
        assert member.isfile() and member.name not in seen
        seen.add(member.name)
        raw = tf.extractfile(member).read()
        if member.name == 'MANIFEST.json':
            assert raw == index_raw and member.mode == 0o644
            continue
        row = expected[member.name]
        assert (len(raw), sha256(raw).hexdigest(), member.mode) == (row['bytes'], row['sha256'], row['mode'])
        path = Path(row['source'])
        assert path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == member.mode
        total += len(raw)
assert seen == {'MANIFEST.json'} | set(expected)
for row in inherited:
    path = Path(row['source'])
    raw = path.read_bytes()
    assert (len(raw), sha256(raw).hexdigest(), stat.S_IMODE(path.stat().st_mode)) == (row['bytes'], row['sha256'], row['mode'])
data = archive.read_bytes()
receipt = dict(status='PASS', archive=str(archive), archive_bytes=len(data), archive_sha256=sha256(data).hexdigest(),
               index=str(index), index_bytes=len(index_raw), index_sha256=sha256(index_raw).hexdigest(),
               archived_members=len(seen), archived_original_bytes=total,
               inherited_json_r2_files=len(inherited), inherited_json_r2_bytes=sum(r['bytes'] for r in inherited),
               all_new_members_full_bytes_modes_and_live_readback_equal=True,
               all_inherited_json_r2_live_bytes_modes_equal_to_published_index=True,
               scope=manifest['scope'], whole_stack_closed=False, elapsed_ns=time.monotonic_ns()-started)
(OUT / 'root-completed-custody.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt, sort_keys=True), flush=True)
