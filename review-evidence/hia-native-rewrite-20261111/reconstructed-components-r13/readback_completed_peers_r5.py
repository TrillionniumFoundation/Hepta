"""Independent full stored-member readback; no rerun or qualification upgrade."""
from hashlib import sha256
import json
from pathlib import Path
import tarfile
import time

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent
items = [
    ('namespace-views', Path('/workspace/scratch/hia-audit-runtime-recovery-20261111/namespace-reconstruction/views-r2-complete-01/namespace-views-r2-development.tar.xz'),
     '08d906217c2d0b3dafc6f264b2306cd833f44d6c30b66e81ad1e0ddf2598bd52',
     Path('/workspace/scratch/hia-audit-runtime-recovery-20261111/namespace-reconstruction/views-r2-complete-01/custody.json')),
]
results = []
for label, archive, pin, index in items:
    start = time.monotonic_ns()
    h = sha256()
    size = 0
    with archive.open('rb') as f:
        while part := f.read(1 << 20):
            h.update(part); size += len(part)
    assert h.hexdigest() == pin
    index_raw = index.read_bytes()
    document = json.loads(index_raw)
    rows = document if isinstance(document, list) else document['members']
    expected = {r.get('path', r.get('name')): r for r in rows}
    assert None not in expected
    assert len(expected) == len(rows)
    seen = set()
    exact_index_members = []
    total = 0
    files = 0
    directories = 0
    with tarfile.open(archive, 'r|xz') as tf:
        for member in tf:
            assert member.name not in seen, (label, member.name)
            seen.add(member.name)
            if member.name == 'CUSTODY.json':
                assert member.isfile() and member.mode == 0o644 and tf.extractfile(member).read() == index_raw
                exact_index_members.append(dict(name=member.name, bytes=len(index_raw), mode=member.mode, sha256=sha256(index_raw).hexdigest()))
                continue
            assert member.name in expected, (label, member.name)
            row = expected[member.name]
            assert member.mode == row['mode'], (label, member.name)
            if row.get('kind', 'file') == 'directory':
                assert member.isdir() and member.size == 0
                directories += 1
                continue
            assert row.get('kind', 'file') == 'file' and member.isfile()
            f = tf.extractfile(member)
            digest = sha256()
            length = 0
            while part := f.read(1 << 20):
                digest.update(part); length += len(part)
            assert (length, digest.hexdigest()) == (row['bytes'], row['sha256']), (label, member.name)
            assert member.size == length
            total += length
            files += 1
    assert seen == set(expected) | {'CUSTODY.json'} and len(exact_index_members) == 1
    result = dict(label=label, status='PASS', archive=str(archive), archive_bytes=size, archive_sha256=pin,
                  index=str(index), index_sha256=sha256(index_raw).hexdigest(),
                  members=len(seen), original_files=files, directories=directories, stored_original_bytes=total,
                  exact_index_members=exact_index_members, archive_member_payload_bytes=total+len(index_raw),
                  all_member_full_bytes_modes_sha256_equal=True, elapsed_ns=time.monotonic_ns()-start,
                  logical_CAS_replay_newly_claimed=False, cold_qualification_newly_claimed=False)
    results.append(result)
    (OUT / 'peer-root-readback-r5.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True), flush=True)
