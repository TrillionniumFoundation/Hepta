"""Bind complete originals, lossless JSON compression and ordered Git parts."""
from hashlib import sha1, sha256
import json
import lzma
from pathlib import Path
import stat

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent
RUNTIME = Path('/workspace/scratch/hia-audit-runtime-recovery-20261111')
PREFIX = 'review-evidence/hia-native-rewrite-20261111/reconstructed-components-r13'
objects = [
    ('root/development.tar.xz', OUT / 'root-completed-development.tar.xz'),
    ('root/original-index.json', OUT / 'root-completed-index.json'),
    ('audit/candidate-static-inventory.json', OUT / 'candidate-static-inventory.json'),
    ('native-clean-build/development.tar.xz', ROOT / 'hia-native-clean-build-r1-development.tar.xz'),
    ('native-clean-build/custody.json', ROOT / 'hia-native-clean-build-r1-development.custody.json'),
    ('native-clean-build/handoff.json', ROOT / 'hia-native-clean-build-r1-handoff.json'),
    ('worker-report/development.tar.xz', ROOT / 'hia-native-agent-worker-report-r1-development.tar.xz'),
    ('worker-report/members.json', ROOT / 'hia-native-agent-worker-report-r1-development.tar.members.json'),
    ('worker-report/custody.json', ROOT / 'hia-native-agent-worker-report-r1-development.tar.custody.json'),
    ('worker-decode/development.tar.xz', ROOT / 'hia-native-agent-worker-decode-r1-development.tar.xz'),
    ('worker-decode/members.json', ROOT / 'hia-native-agent-worker-decode-r1-development.tar.members.json'),
    ('worker-decode/custody.json', ROOT / 'hia-native-agent-worker-decode-r1-development.tar.custody.json'),
    ('worker-decode/final-seal.log', ROOT / 'native-agent-worker-next/development/decode-seal-r1.log'),
    ('namespace-views/development.tar.xz', RUNTIME / 'namespace-reconstruction/views-r2-complete-01/namespace-views-r2-development.tar.xz'),
    ('namespace-views/custody.json', RUNTIME / 'namespace-reconstruction/views-r2-complete-01/custody.json'),
    ('retirement/application59.json', ROOT / 'hia-native-edit-apply-payload-retirement-r1.json'),
    ('retirement/runtime-compile-duplicates.json', RUNTIME / 'duplicate-compile-buffer-retirement-20261111.json'),
]
for path in sorted((ROOT / 'hia-batch-r2-published-raw-retirement').iterdir()):
    if path.is_file():
        objects.append(('retirement/batch/' + path.name, path))
for name in ('README.md', 'audit_current_candidate.py', 'seal_root_completed.py', 'root-completed-custody.json',
             'root-seal.stdout.log', 'root-seal.stderr.log',
             'reclaim_controller_duplicates.py', 'reclaimed-controller-duplicates.json',
             'reclaim_controller_buffer_duplicates.py', 'reclaimed-controller-buffer-duplicates.json',
             'make_transport_plan.py'):
    objects.append((name, OUT / name))
for pattern in ('readback_completed_peers_r*.py', 'peer-root-readback-r*.json', 'peer-readback-r*.stdout.log', 'peer-readback-r*.stderr.log'):
    for path in sorted(OUT.glob(pattern)):
        objects.append((path.name, path))

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
