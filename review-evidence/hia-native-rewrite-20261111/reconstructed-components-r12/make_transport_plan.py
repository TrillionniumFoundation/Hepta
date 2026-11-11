"""Prepare exact original objects and lossless small Git transport parts."""
from pathlib import Path
from hashlib import sha256,sha1
import json,lzma,stat
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent
R=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111')
PREFIX='review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12'
objects=[
 ('root/controller-integration.tar.xz',OUT/'root-completed-controller-integration.tar.xz'),
 ('root/controller-integration-index.json.xz',OUT/'root-completed-original-index.json.xz'),
 ('root/json-entry-r2.tar.xz',OUT/'root-json-entry-r2-development.tar.xz'),
 ('root/json-entry-r2-index.json',OUT/'json-r2-original-index.json'),
 ('core-diagnostics/development.tar.xz',ROOT/'hia-core-diagnostics-native-r2-development.tar.xz'),
 ('core-diagnostics/members.json',ROOT/'hia-core-diagnostics-native-r2-development.tar.members.json'),
 ('core-diagnostics/custody.json',ROOT/'hia-core-diagnostics-native-r2-development.tar.custody.json'),
 ('mode2/development.tar.xz',ROOT/'hia-edit-executor-mode2-r1-development.tar.xz'),
 ('mode2/custody.json',ROOT/'hia-edit-executor-mode2-r1-development.tar.xz.custody.json'),
 ('service/development.tar.xz',ROOT/'hia-edit-service-r1-development.tar.xz'),
 ('service/custody.json.xz',ROOT/'hia-edit-service-r1-development.tar.xz.custody.json.xz'),
 ('service/handoff.json',ROOT/'hia-edit-service-r1-handoff.json'),
 ('namespace-objects/development.tar.xz',R/'namespace-reconstruction/objects-r1-complete-01/namespace-objects-r1-development.tar.xz'),
 ('namespace-objects/custody.json',R/'namespace-reconstruction/objects-r1-complete-01/custody.json'),
 ('namespace-log/development.tar.xz',R/'namespace-reconstruction/log-r2-complete-01/namespace-log-r2-development.tar.xz'),
 ('namespace-log/custody.json',R/'namespace-reconstruction/log-r2-complete-01/custody.json'),
 ('prerequisite-lifecycle/development.tar.xz',R/'prerequisite-lifecycle-readback-r1/ndu-prerequisite-lifecycle-readback-r1.tar.xz'),
 ('prerequisite-lifecycle/custody.json',R/'prerequisite-lifecycle-readback-r1/custody.json'),
 ('prerequisite-originals/development.tar.xz',R/'prerequisite-diagnostic-originals-readback-r1/diagnostic-originals.tar.xz'),
 ('prerequisite-originals/custody.json',R/'prerequisite-diagnostic-originals-readback-r1/custody.remote-original.json'),
 ('qualification/raw-originals.tar.xz',R/'v67-final-qualification-readback-r2/raw-qualification.tar.xz'),
 ('qualification/custody.json',R/'v67-final-qualification-readback-r2/custody.remote-original.json'),
 ('qualification/independent-readback.json',R/'v67-final-qualification-readback-r2/independent-readback.json'),
]
for name in ['README.md','seal_root_completed.py','root-completed-custody.json','root-seal.stdout.log','root-seal.stderr.log',
 'seal_json_r2.py','json-r2-custody.json','json-seal.stdout.log','json-seal.stderr.log',
 'readback_peer_originals.py','readback_peer_originals_r2.py','readback_peer_originals_r3.py',
 'peer-root-readback.json','peer-root-readback-r2.json','peer-root-readback-r3.json',
 'peer-readback.stdout.log','peer-readback.stderr.log','peer-readback-r2.stdout.log','peer-readback-r2.stderr.log',
 'peer-readback-r3.stdout.log','peer-readback-r3.stderr.log',
 'reclaim_completed_payloads.py','reclaimed-r10-duplicates.json','reclaim.stdout.log','reclaim.stderr.log',
 'reclaim_envelope_duplicates.py','reclaimed-envelope-duplicates.json','reclaim-envelope.stdout.log','reclaim-envelope.stderr.log',
 'make_transport_plan.py']:
    objects.append((name,OUT/name))
for archive,index in [(OUT/'root-completed-original-index.json.xz',OUT/'root-completed-original-index.json'),
 (ROOT/'hia-edit-service-r1-development.tar.xz.custody.json.xz',ROOT/'hia-edit-service-r1-development.tar.xz.custody.json')]:
    assert lzma.decompress(archive.read_bytes())==index.read_bytes()

parts=OUT/'parts';parts.mkdir(exist_ok=True);plan=[];manifest=[]
def entry(name,path):
    raw=path.read_bytes();mode='100755' if stat.S_IMODE(path.stat().st_mode)&0o111 else '100644'
    return dict(path=PREFIX+'/'+name,local_path=str(path),mode=mode,type='blob',bytes=len(raw),sha256=sha256(raw).hexdigest(),
        git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
for name,path in objects:
    path=path.resolve();whole=path.read_bytes();record=dict(name=name,source=str(path),bytes=len(whole),sha256=sha256(whole).hexdigest())
    if len(whole)<=3*1024*1024:
        row=entry(name,path);plan.append(row);record.update(git_sha=row['git_sha'],transport='complete')
    else:
        chunks=[];restored=bytearray()
        for i,at in enumerate(range(0,len(whole),3*1024*1024)):
            part=whole[at:at+3*1024*1024];part_name='parts/'+name.replace('/','--')+f'.part{i:03d}'
            target=OUT/part_name
            if target.exists():assert target.read_bytes()==part
            else:target.write_bytes(part)
            row=entry(part_name,target);plan.append(row);chunks.append({k:row[k] for k in ('path','bytes','sha256','git_sha')});restored.extend(target.read_bytes())
        assert bytes(restored)==whole
        record.update(transport='lossless-ordered-parts',ordered_parts=chunks,whole_reassembly_equal=True)
    manifest.append(record)
mp=OUT/'transport-objects.json';mp.write_text(json.dumps(dict(schema='hia.lossless-original-transport.v1',objects=manifest),indent=2,sort_keys=True)+'\n')
plan.append(entry('transport-objects.json',mp));assert len({r['path'] for r in plan})==len(plan)
(OUT/'publication-plan-v1.json').write_text(json.dumps(plan,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(files=len(plan),bytes=sum(r['bytes'] for r in plan),whole_objects=len(objects)),sort_keys=True))
