"""Retain restored stage5 originals and developmental r2 source without upgrading failures."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,tarfile
ROOT=Path('/workspace/scratch/9acdfa9f5639')
OUT=ROOT/'hia-v65-stage5-checkpoint'
RAM=Path('/dev/shm/hia-v65-stage5-checkpoint')
OUT.mkdir(exist_ok=True);RAM.mkdir(exist_ok=True,mode=0o700)
PREFIX='review-evidence/hia-native-rewrite-20261111/v65-stage5-restored'
selected=[];reviews=[]
def sha(b):return sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def keep(p,name):
    p=Path(p);assert p.is_file() and not p.is_symlink();selected.append((p,name))
def verify_tar(path,expected,records,extras=None):
    path=Path(path);b=path.read_bytes();assert sha(b)==expected
    records=dict(records);extras=extras or {};total=0
    with tarfile.open(path,'r:xz') as t:
        names=t.getnames();assert len(names)==len(set(names))
        assert set(names)==set(records)|set(extras),(str(path),set(names)^set(records)^set(extras))
        for m in t:
            assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
            raw=t.extractfile(m).read()
            if m.name in extras:assert raw==extras[m.name];continue
            r=records[m.name];assert len(raw)==r['bytes'] and sha(raw)==r['sha256']
            if 'mode' in r:assert m.mode==r['mode']
            total+=len(raw)
    reviews.append({'path':str(path),'bytes':len(b),'sha256':expected,'members':len(names),'checked_payload_bytes':total,'all_recorded_bytes_sha_modes_replayed':True})
    return b
driver=ROOT/'native-composite-driver-next/checkpoints/stage7'
manifest=json.loads((driver/'source.json').read_bytes())
assert sha((driver/'source.json').read_bytes())=='86ed58e9b3e55b9d0a2f25d6e4bce75a1f24f1194d31e21815d26424010bea04'
archive=Path('/dev/shm/native-composite-driver-stage7-development.tar.xz')
verify_tar(archive,'bf1e3be482a9e8b4a349b7a84c84eb171357cddb1136a28d96c4758813ec576a',[(r['path'],r) for r in manifest['members']])
keep(archive,'native-composite-driver-stage7-development.tar.xz')
keep(driver/'custody.json','native-composite-driver-stage7-custody.json')
keep(driver/'source.json','native-composite-driver-stage7-source.json')
diag=ROOT/'hia-v65-cold-independent-diagnosis.custody.json';d=json.loads(diag.read_bytes())
verify_tar(ROOT/'hia-v65-cold-independent-diagnosis.tar.xz','1ce4657db7ff54d25ee331ec49e6cb324aa8c230f2868bf5703a833ee3a8b600',[(r['name'],r) for r in d['rows']])
keep(ROOT/'hia-v65-cold-independent-diagnosis.tar.xz','eef-cold-independent-diagnosis.tar.xz')
keep(diag,'eef-cold-independent-diagnosis-custody.json')
phase=ROOT/'hia-phase-archive-stage5-independent-review'
phase_manifest=(phase/'manifest.json').read_bytes()
with tarfile.open(ROOT/'hia-phase-archive-stage5-independent-review.tar.xz','r:xz') as t:
    names=t.getnames();common=''
    if not 'manifest.json' in names:
        possible=[n for n in names if n.endswith('/manifest.json')];assert len(possible)==1
        common=possible[0][:-len('manifest.json')]
records={common+k:v for k,v in json.loads(phase_manifest).items()}
verify_tar(ROOT/'hia-phase-archive-stage5-independent-review.tar.xz','824465f570b8803b0fee92c49f50fe99fb572e3b020efb2197e87db70cecaaa0',records,{common+'manifest.json':phase_manifest})
keep(ROOT/'hia-phase-archive-stage5-independent-review.tar.xz','stage5-archive-scheduler-independent-review.tar.xz')
keep(phase/'manifest.json','stage5-archive-scheduler-independent-manifest.json')
dev=ROOT/'hia-agent-state-integration-development';frozen=(dev/'draft-stage5-source.json').read_bytes();fd=json.loads(frozen)
with tarfile.open(dev/'draft-stage5-source.tar.xz','r:xz') as t:
    names=t.getnames();extra=set(names)-{'source/'+p for p in fd['files']}
    assert len(extra)==1;embedded=next(iter(extra));assert t.extractfile(embedded).read()==frozen
verify_tar(dev/'draft-stage5-source.tar.xz','578fbfbe3f2aa5cacef158b081b9f03c5e2cc604c0dba048438fe40bc2c298ba',{'source/'+p:r for p,r in fd['files'].items()},{embedded:frozen})
assert fd['source_closure']=={p:sha((ROOT/'native-agent-state-integration'/p).read_bytes()) for p in fd['source_closure']}
source_summary=json.loads((dev/'source-stage5-complete-attempt1/summary.json').read_bytes())
def bundle(name,directories,individuals):
    contents={}
    for label,directory in directories:
        for p in sorted(Path(directory).rglob('*')):
            if p.is_file():
                assert not p.is_symlink();contents[label+'/'+p.relative_to(directory).as_posix()]=(p.read_bytes(),p.stat().st_mode&0o7777)
    for label,p in individuals:
        p=Path(p);assert p.is_file() and not p.is_symlink();contents[label]=(p.read_bytes(),p.stat().st_mode&0o7777)
    rows={k:{'bytes':len(v[0]),'sha256':sha(v[0]),'mode':v[1]} for k,v in contents.items()}
    custody=(json.dumps({'schema':'hepta.hia.restored-original-container.v1','files':rows},indent=2,sort_keys=True)+'\n').encode()
    path=RAM/name
    with tarfile.open(path,'x:xz',preset=1) as t:
        for label,(raw,mode) in sorted(contents.items()):
            ti=tarfile.TarInfo(label);ti.mode=mode;ti.size=len(raw);t.addfile(ti,io.BytesIO(raw))
        ti=tarfile.TarInfo('CHECKPOINT_CUSTODY.json');ti.mode=0o644;ti.size=len(custody);t.addfile(ti,io.BytesIO(custody))
    verify_tar(path,sha(path.read_bytes()),rows,{'CHECKPOINT_CUSTODY.json':custody})
    keep(path,name)
names=[
'draft-stage5-source.json','draft-stage5-source.tar.xz','draft-stage5-custody.json',
'freeze_stage5.py','freeze-stage5.stdout.log','freeze-stage5.stderr.log','run_source_stage5.py',
'source-stage5-complete-attempt1.stdout.log','source-stage5-complete-attempt1.stderr.log',
'run_cold_stage5.py','cold-stage5-controller.stdout.log','cold-stage5-controller.stderr.log',
'cold-stage5-attempt1.stdout.log','cold-stage5-attempt1.stderr.log',
'stage5-static-inventory.stdout.log','stage5-static-inventory.stderr.log'
]
individuals=[(n,dev/n) for n in names]
for n in ['stage4-container-duplicate-removal.json','stage4-saved-original-duplicate-removal.json']:
    p=ROOT/'hia-v65-candidate-checkpoint'/n;assert p.is_file();individuals.append((n,p))
bundle('stage5-source-and-restored-local-originals.tar.xz',[
('source-suite',dev/'source-stage5-complete-attempt1'),
('candidate-publication',ROOT/'hia-v65-stage5-publication')],individuals)
bundle('stage5-github-original-metadata-and-audit.tar.xz',[
('ci',ROOT/'hia-ci-v65-stage5'),('audit',ROOT/'v65-stage5-github-independent-audit')],[])
keep(ROOT/'hia-ci-v65-stage5/workspace-restored-continuity.json','workspace-restored-continuity.json')
keep(OUT/'outage-publication.json','outage-checkpoint-publication.json')
dump(OUT/'independent-original-readback.json',{'schema':'hepta.hia.restored-checkpoint-readback.v1','archives':reviews,'whole_stack_closed':False,'native_qualification_rerun':False})
keep(OUT/'independent-original-readback.json','independent-original-readback.json')
readme="""# v65 stage5 restored originals

Candidate d5da1eb760454ef3df5153c5e80eb046ddb389d9 remains HOLD. The exact GitHub source group passed all 327 tests in 497.666 seconds; cold replay timed out at 180.173765523 seconds with 6/11 outer checks, 34 sealed phases and 3758 completed checks. All seventeen subsequent native groups were skipped. The original 48,390,300-byte ZIP has a successful durable file receipt in the CI capsule. Full independent replay verified all 4,980 outer members, all 636 source files, and all 36,669 archived phase payloads. Those completed phases are not a full 38-phase qualification.

After the workspace returned, every one of the 636 frozen source files matched. The original local 327-test source suite, frozen 62-file source archive, archive-scheduler independent review, prior cold timing diagnosis and ObjectToken r2 development originals were recovered and verified. The interrupted local cold attempt has no recoverable terminal report or RAM evidence; its empty logs and original controller remain preserved without any pass or fail inference. This update supplements, and does not overwrite, the earlier interruption observations.

ObjectToken stage7 preserves the exact r2 source, actual compiled image, nine small paired controls, two large controls with the 71,303,259-byte HIA-producer interop result, and all retained prior failures. It does not qualify the complete eleven-owner native driver. Newly authored ObjectToken IR and type-transport code are excluded from this frozen development package.

Whole-stack native closure, hosted storage/business owners, source authoring, complete composite coordination and default cutover remain OPEN. Production and independent reference owners remain present.
"""
(OUT/'README.md').write_text(readme)
keep(OUT/'README.md','README.md');keep(OUT/'prepare.py','prepare.py')
files=[]
for p,name in selected:
    b=p.read_bytes();files.append({'path':PREFIX+'/'+name,'local_path':str(p),'bytes':len(b),'sha256':sha(b),'git_sha':sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'mode':'100644'})
assert len({r['path'] for r in files})==len(files)
plan={'schema':'hepta.hia.stage5-restored-recovery-plan.v1','repository':'TrillionniumFoundation/Hepta','branch':'recovery/hia-function-9acdfa-20261111','parent':'8b812a4b5d3caf517e5cd802a0bb0d6376e903ec','base_tree':'0c493b7511fdd3af867b9e8b9ad4959d3f0c58ff','main_preserved':'5831f52fada45e076f8f68f198a15c0585e6104f','candidate_head':'d5da1eb760454ef3df5153c5e80eb046ddb389d9','files':files,'whole_stack_closed':False}
dump(OUT/'publication-plan.json',plan)
print(json.dumps({'files':len(files),'bytes':sum(f['bytes'] for f in files),'all_original_archives_read_back':True,'archives':reviews}),flush=True)
