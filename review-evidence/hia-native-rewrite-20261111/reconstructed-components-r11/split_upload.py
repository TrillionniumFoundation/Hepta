"""Losslessly split two large original evidence objects after a failed upload."""
from pathlib import Path
from hashlib import sha256, sha1
import json

OUT = Path(__file__).resolve().parent
PLAN = OUT / 'publication-plan.json'
old = json.loads(PLAN.read_text())
assert len(old) == 16
(OUT / 'publication-plan-original.json').write_bytes(PLAN.read_bytes())
prefix = old[0]['path'].rsplit('/', 1)[0] + '/'
parts = OUT / 'parts'
parts.mkdir(exist_ok=False)
rows = []
objects = []

def row(path, name):
    data = path.read_bytes()
    return dict(local_path=str(path), path=prefix+name, bytes=len(data),
                sha256=sha256(data).hexdigest(),
                git_sha=sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),
                mode='100644')

for entry in old:
    if entry['bytes'] < 10_000_000:
        rows.append(entry)
        continue
    data = Path(entry['local_path']).read_bytes()
    assert len(data) == entry['bytes'] and sha256(data).hexdigest() == entry['sha256']
    names = []
    name = entry['path'].rsplit('/', 1)[1]
    for i, offset in enumerate(range(0, len(data), 3*1024*1024)):
        p = parts / (name + f'.part{i:03d}')
        p.write_bytes(data[offset:offset+3*1024*1024])
        item = row(p, 'parts/'+p.name)
        rows.append(item)
        names.append(dict(name='parts/'+p.name, bytes=item['bytes'], sha256=item['sha256']))
    restored = b''.join((OUT / x['name']).read_bytes() for x in names)
    assert restored == data
    objects.append(dict(original_name=name, original_bytes=len(data),
                        original_sha256=entry['sha256'], original_git_sha=entry['git_sha'],
                        ordered_parts=names, full_reassembly_verified=True))

(OUT / 'split-objects.json').write_text(json.dumps(dict(schema='lossless-original-evidence-parts.v1',
    objects=objects), indent=2, sort_keys=True)+'\n')
(OUT / 'upload-attempts.json').write_text(json.dumps(dict(
    original_plan_files=16,
    interrupted_cell='32', interrupted_cell_final_status='unavailable_after_context_continuation',
    original_blob='ecc914ce905045367a4142147c1b0cbb94891467',
    tree_probe_status=422, tree_probe_message='tree.sha ecc914ce905045367a4142147c1b0cbb94891467 is not a valid blob',
    subsequent_full_upload='Tool returned non-JSON text beginning tool call e; parsing failed. No success SHA was observed.',
    action='Split originals into 3 MiB parts; verify complete reassembly; preserve full original hashes.'), indent=2, sort_keys=True)+'\n')
readme = OUT / 'README.md'
readme.write_text(readme.read_text()+'\n## Lossless Git transport\n\n'
    'The two large batch objects are stored as ordered 3 MiB parts because the\n'
    'whole-object upload did not succeed. `split-objects.json` records every part\n'
    'and the complete original length and SHA-256. Concatenate the listed parts\n'
    'in order to reconstruct each original byte for byte. Full reassembly was\n'
    'checked locally. Original manifests and failed upload observations remain\n'
    'in this checkpoint; the split does not change any test result or evidence.\n')
rows = [row(readme, 'README.md') if r['path'].endswith('/README.md') else r for r in rows]
for name in ['publication-plan-original.json', 'split-objects.json', 'upload-attempts.json', 'split_upload.py']:
    rows.append(row(OUT/name, name))
PLAN.write_text(json.dumps(rows, indent=2, sort_keys=True)+'\n')
print(json.dumps(dict(files=len(rows), bytes=sum(r['bytes'] for r in rows), parts=sum(len(o['ordered_parts']) for o in objects))))
