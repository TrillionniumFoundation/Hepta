"""Seal verified recovery evidence; no production or reference owner removal."""
from hashlib import sha256, sha1
from pathlib import Path
import io, json, tarfile

ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'hia-v65-progress-checkpoint'
def digest(b):return sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
audits=[]
for name,expected in [
    ('native-composite-driver-stage4-development','e43693a6184f92c6c1c9ea4cd4aee97ec6694a9789bb27911cb9f1589657d9fa'),
    ('native-composite-driver-stage5-development','b52b5f40b488c5588df0d24cf08e446ec166fe612f9b95812bbf15d2afc63235'),
    ('hia-v64-cold-independent-diagnosis','470ff9c0e1a0f7fd7b59c9977ac38396f85f666fd13ea67bdbe0cb5daf8a87b2')]:
    archive=ROOT/(name+'.tar.xz');raw=archive.read_bytes();assert digest(raw)==expected
    custody=json.loads((ROOT/(name+'-custody.json')).read_bytes())
    files=({r['path']:r for r in custody['members']} if isinstance(custody.get('members'),list) else custody['files'])
    total=0
    with tarfile.open(archive,'r:xz') as t:
        members=t.getmembers();assert len(members)==len(files) and len({m.name for m in members})==len(members)
        for m in members:
            assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
            data=t.extractfile(m).read();record=files[m.name]
            assert len(data)==record['bytes'] and digest(data)==record['sha256'] and m.mode==record['mode'];total+=len(data)
    audits.append({'archive':archive.name,'sha256':expected,'bytes':len(raw),'members':len(files),'raw_bytes':total,'every_member_hash_size_mode_replayed':True})
archive=ROOT/'hia-json-packet-independent-audit.tar.xz';raw=archive.read_bytes()
assert digest(raw)=='6b4c98fd6aa7116569171d71b2065673d0a64e38868fec5798686867ad5fbaf8'
count=total=0
with tarfile.open(archive,'r:xz') as t:
    members=t.getmembers();assert len(members)==len({m.name for m in members})
    for m in members:
        assert m.isfile() and '..' not in Path(m.name).parts
        source=ROOT/'hia-json-packet-independent-audit'/m.name;data=t.extractfile(m).read()
        assert data==source.read_bytes() and m.mode==source.stat().st_mode&0o777
        count+=1;total+=len(data)
audits.append({'archive':archive.name,'sha256':digest(raw),'bytes':len(raw),'members':count,'raw_bytes':total,'every_member_exact_current_frozen_original_and_mode_replayed':True})

def bundle(name,roots):
    files={}
    for prefix,root in roots:
        for p in sorted(root.rglob('*')):
            if p.is_file():
                assert not p.is_symlink();rel=prefix+'/'+p.relative_to(root).as_posix();data=p.read_bytes()
                files[rel]=(data,p.stat().st_mode&0o777)
    manifest={k:{'bytes':len(data),'sha256':digest(data),'mode':mode} for k,(data,mode) in files.items()}
    manifest_raw=(json.dumps({'schema':'hepta.hia.progress-checkpoint-archive.v1','files':manifest},indent=2,sort_keys=True)+'\n').encode()
    path=OUT/name
    with tarfile.open(path,'x:xz') as t:
        for rel,(data,mode) in files.items():
            ti=tarfile.TarInfo(rel);ti.mode=mode;ti.size=len(data);t.addfile(ti,io.BytesIO(data))
        ti=tarfile.TarInfo('CHECKPOINT_CUSTODY.json');ti.mode=0o644;ti.size=len(manifest_raw);t.addfile(ti,io.BytesIO(manifest_raw))
    with tarfile.open(path,'r:xz') as t:
        assert len(t.getmembers())==len(files)+1
        for m in t:
            data=t.extractfile(m).read()
            if m.name=='CHECKPOINT_CUSTODY.json':assert data==manifest_raw
            else:assert data==files[m.name][0] and m.mode==files[m.name][1]
    row={'archive':str(path),'bytes':path.stat().st_size,'sha256':digest(path.read_bytes()),'files':len(files),'raw_bytes':sum(len(v[0]) for v in files.values()),'every_member_original_bytes_and_modes_replayed':True}
    audits.append(row);return path

ci=bundle('v64-github-failure-and-byte-audit.tar.xz',[('audit',ROOT/'v64-github-independent-audit'),('github',ROOT/'hia-ci-v64-final')])
merge=bundle('v65-v64-merge-originals.tar.xz',[('merge',ROOT/'hia-agent-state-integration-development/v64-merge')])
dump(OUT/'independent-archive-readback.json',{'schema':'hepta.hia.progress-checkpoint-readback.v1','archives':audits,'qualification_rerun':False,'production_sources_modified':False})
print(json.dumps(audits,indent=2),flush=True)
