"""Bind complete r14 originals, lossless JSON compression and ordered Git parts."""
from hashlib import sha1, sha256
import json
import lzma
from pathlib import Path
import stat
OUT=Path(__file__).resolve().parent
ROOT=OUT.parent
RUNTIME=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111/namespace-reconstruction/commit-r2-complete-02')
PREFIX='review-evidence/hia-native-rewrite-20261111/reconstructed-components-r14'
objects=[
 ('root/development.tar.xz',OUT/'root-metadata-development.tar.xz'),
 ('root/original-index.json',OUT/'root-metadata-index.json'),
 ('worker-request/development.tar.xz',ROOT/'hia-native-agent-worker-request-r1-development.tar.xz'),
 ('worker-request/members.json',ROOT/'hia-native-agent-worker-request-r1-development.tar.members.json'),
 ('worker-request/custody.json',ROOT/'hia-native-agent-worker-request-r1-development.tar.custody.json'),
 ('worker-request/cas-count-addendum.json',ROOT/'native-agent-worker-next/development/request-cas-count-addendum-r1.json'),
 ('worker-request/final-seal.log',ROOT/'native-agent-worker-next/development/request-seal-r1.log'),
 ('cli-argv-formatter/development.tar.xz',ROOT/'hia-native-cli-argv-formatter-r1-development.tar.xz'),
 ('cli-argv-formatter/custody.json',ROOT/'hia-native-cli-argv-formatter-r1-development.custody.json'),
 ('cli-argv-formatter/handoff.json',ROOT/'native-hia-cli-next/development/ARGV_FORMATTER_HANDOFF.json'),
 ('namespace-commit/development.tar.xz',RUNTIME/'namespace-commit-r2-development.tar.xz'),
 ('namespace-commit/custody.json',RUNTIME/'custody.json'),
 ('namespace-commit/summary.json',RUNTIME/'summary.json'),
]
for name in ('README.md','seal_root_metadata.py','root-metadata-custody.json','root-metadata-seal-r1.log',
             'readback_completed_peers.py','readback_completed_peers_r2.py','peer-root-readback-r1.json',
             'peer-root-readback-r2.json','peer-root-readback-r1.log','peer-root-readback-r2.log','make_transport_plan.py'):
 objects.append((name,OUT/name))

assert len({name for name, _ in objects}) == len(objects)
(OUT / 'parts').mkdir(exist_ok=True)
(OUT / 'compressed-records').mkdir(exist_ok=True)
plan, originals = [], []


def entry(name, path):
    raw = path.read_bytes()
    mode = '100755' if path.stat().st_mode & 0o111 else '100644'
    return dict(path=PREFIX + '/' + name, local_path=str(path.resolve()), mode=mode, type='blob', bytes=len(raw),
                sha256=sha256(raw).hexdigest(), git_sha=sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


for name, path in objects:
    path = path.resolve()
    original = path.read_bytes()
    record = dict(name=name, source=str(path), original_bytes=len(original), original_sha256=sha256(original).hexdigest(),
                  original_mode=stat.S_IMODE(path.stat().st_mode))
    if path.suffix == '.json' and len(original) > 1 << 20:
        compressed = OUT / 'compressed-records' / (name.replace('/', '--') + '.xz')
        payload = lzma.compress(original, preset=0)
        if compressed.exists():
            assert compressed.read_bytes() == payload
        else:
            compressed.write_bytes(payload)
        assert lzma.decompress(compressed.read_bytes()) == original
        record['lossless_compression'] = dict(algorithm='xz', decompressed_original_equal=True)
        path, name = compressed, name + '.xz'
    raw = path.read_bytes()
    record.update(transport_object_name=name, bytes=len(raw), sha256=sha256(raw).hexdigest())
    if len(raw) <= 3 * 1024 * 1024:
        row = entry(name, path)
        plan.append(row)
        record.update(transport='complete', git_sha=row['git_sha'])
    else:
        pieces, restored = [], bytearray()
        for index, at in enumerate(range(0, len(raw), 3 * 1024 * 1024)):
            part = raw[at:at+3*1024*1024]
            part_name = 'parts/' + name.replace('/', '--') + f'.part{index:03d}'
            target = OUT / part_name
            if target.exists():
                assert target.read_bytes() == part
            else:
                target.write_bytes(part)
            row = entry(part_name, target)
            plan.append(row)
            pieces.append({k: row[k] for k in ('path', 'bytes', 'sha256', 'git_sha')})
            restored.extend(target.read_bytes())
        assert bytes(restored) == raw
        record.update(transport='lossless-ordered-parts', ordered_parts=pieces, whole_reassembly_equal=True)
    assert Path(record['source']).read_bytes() == original
    originals.append(record)
manifest = OUT / 'transport-objects.json'
manifest.write_text(json.dumps(dict(schema='hia.lossless-original-transport.v1', objects=originals), indent=2, sort_keys=True) + '\n')
plan.append(entry('transport-objects.json', manifest))
assert len({r['path'] for r in plan}) == len(plan)
target = OUT / 'publication-plan-v1.json'
assert not target.exists()
target.write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
print(json.dumps(dict(files=len(plan), bytes=sum(r['bytes'] for r in plan), original_objects=len(objects),
                      plan_sha256=sha256(target.read_bytes()).hexdigest()), sort_keys=True))
