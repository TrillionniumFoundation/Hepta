"""Preserve exact candidate failures and independent development evidence."""
from pathlib import Path
from hashlib import sha256, sha1
import io, json, tarfile

ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'hia-v65-candidate-checkpoint'
PREFIX='review-evidence/hia-native-rewrite-20261111/v65-candidate-eef'
def sha(b):return sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
audits=[];selected=[]
def keep(path,name=None):
    p=ROOT/path;assert p.is_file() and not p.is_symlink();selected.append((p,name or path))
def replay(archive,custody,expected,rows=None,extra=None):
    p=ROOT/archive;c=ROOT/custody;raw=p.read_bytes();assert sha(raw)==expected
    data=json.loads(c.read_bytes())
    files=rows if rows is not None else data['files']
    if isinstance(files,list):files={r['path']:r for r in files}
    total=0
    with tarfile.open(p,'r:xz') as t:
        names=t.getnames();assert len(names)==len(set(names))
        assert set(names)==set(files)|(set(extra) if extra else set())
        for member in t:
            assert member.isfile() and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
            actual=t.extractfile(member).read()
            if extra and member.name in extra:
                assert actual==extra[member.name];continue
            e=files[member.name];assert len(actual)==e['bytes'] and sha(actual)==e['sha256'] and member.mode==e['mode'];total+=len(actual)
    audits.append({'archive':archive,'bytes':len(raw),'sha256':expected,'members':len(names),'raw_bytes':total,'every_member_bytes_sha_mode_replayed':True})
    keep(archive,'archives/'+p.name);keep(custody,'archives/'+c.name)

for stem,h in [
    ('native-observer-pure-r2-development','d81c06f48791a27e0170ae10e285dc06eec8a819d8dd8a978227d8a67e5087d5'),
    ('hia-agent-state-stage2-independent-review','c267f2c8fc70d7ccebf25d89034ac8cbdd20ae10f7a4823ccfca46538f395af3'),
    ('hia-agent-state-stage3-independent-review','da4b847e058e1b46d6e00ac9c79c5bb88bfc317cd2b58f01f802aff6aeab739b')]:
    replay(stem+'.tar.xz',stem+'-custody.json',h)
six=json.loads((ROOT/'native-composite-driver-next/checkpoints/stage6-small/source.json').read_bytes())
replay('native-composite-driver-stage6-small-development.tar.xz','native-composite-driver-stage6-small-development.custody.json','29ba6c75eaacc557d69cda8c7ef347456cc184e69a66f999236eee450c271229',six['members'])
keep('native-composite-driver-next/checkpoints/stage6-small/source.json','driver-stage6-small-source.json')

# This original final ROG package contains top-level records, not nested phases.
v63=ROOT/'v63-rog-full-control-audit-runtime/final-evidence'
custody_raw=(v63/'custody.json').read_bytes();custody=json.loads(custody_raw)
with tarfile.open(v63/'raw-qualification.tar.xz','r:xz') as t:
    names=t.getnames();records={'qualification/'+r['path']:r for r in custody['records']};extra=set(names)-set(records)
    assert len(extra)==1;embedded=next(iter(extra));assert t.extractfile(embedded).read()==custody_raw
replay('v63-rog-full-control-audit-runtime/final-evidence/raw-qualification.tar.xz','v63-rog-full-control-audit-runtime/final-evidence/custody.json','3fa7bf09f9b04412d91a68357235e3519ff72ab917e794716a907819b4c04fb9',records,{embedded:custody_raw})
keep('v63-rog-full-control-audit-runtime/final-evidence/readback-summary.json','rog-v63-final-readback.json')

def bundle(name,roots,individual=()):
    files={}
    for prefix,path in roots:
        directory=ROOT/path
        for p in sorted(directory.rglob('*')):
            if p.is_file():
                assert not p.is_symlink();files[prefix+'/'+p.relative_to(directory).as_posix()]=p
    for label,path in individual:files[label]=ROOT/path
    content={}
    for label,p in files.items():content[label]=(p.read_bytes(),p.stat().st_mode&0o7777)
    records={label:{'bytes':len(data),'sha256':sha(data),'mode':mode} for label,(data,mode) in content.items()}
    manifest=(json.dumps({'schema':'hepta.hia.candidate-checkpoint-container.v1','files':records},indent=2,sort_keys=True)+'\n').encode()
    destination=OUT/name
    with tarfile.open(destination,'x:xz',preset=1) as t:
        for label,(data,mode) in sorted(content.items()):
            ti=tarfile.TarInfo(label);ti.size=len(data);ti.mode=mode;t.addfile(ti,io.BytesIO(data))
        ti=tarfile.TarInfo('CHECKPOINT_CUSTODY.json');ti.size=len(manifest);ti.mode=0o644;t.addfile(ti,io.BytesIO(manifest))
    with tarfile.open(destination,'r:xz') as t:
        assert len(t.getmembers())==len(content)+1
        for m in t:
            actual=t.extractfile(m).read()
            if m.name=='CHECKPOINT_CUSTODY.json':assert actual==manifest
            else:assert actual==content[m.name][0] and m.mode==content[m.name][1]
    keep(str(destination.relative_to(ROOT)),name)
    audits.append({'archive':name,'bytes':destination.stat().st_size,'sha256':sha(destination.read_bytes()),'members':len(content)+1,'raw_bytes':sum(len(v[0]) for v in content.values()),'all_originals_exact_and_modes_replayed':True})

bundle('candidate-ci-original-metadata-and-audit.tar.xz',[
    ('publication','hia-v65-candidate-publication'),('ci','hia-ci-v65-candidate'),('byte-audit','v65-github-independent-audit')])
bundle('independent-small-reviews.tar.xz',[(p,p) for p in ('native-observer-pure-independent-r2','lease-prefix-independent-r1','packet-json-independent-r1','object-json-independent-r1')])
bundle('state-stage3-native-development-reports.tar.xz',[
    ('original58','hia-agent-state-integration-development/native-stage3-development-attempt1'),
    ('recheck3','hia-agent-state-integration-development/journal-stage3-recheck1')],[(n,'hia-agent-state-integration-development/'+n) for n in (
    'run_native_stage3_development.py','recheck_journal_stage3.py','seal_stage3_native.py','native-stage3-development-originals-custody.json','native-stage3-library-upload.result.json','native-stage3-duplicate-removal.json','native-stage3-development-attempt1.stdout.log','native-stage3-development-attempt1.stderr.log','journal-stage3-recheck1.stdout.log','journal-stage3-recheck1.stderr.log','seal-stage3-native.stdout.log','seal-stage3-native.stderr.log')])
bundle('state-stage4-source-and-cold-failure.tar.xz',[],[(n,'hia-agent-state-integration-development/'+n) for n in (
    'draft-stage4-source.json','draft-stage4-source.tar.xz','draft-stage4-custody.json','source-stage4-attempt1.json','source-stage4-attempt1.log','observer-r2-import.json','observer-r2-independent-readback.json','run_cold_stage4.py','cold-stage4-attempt1.json','cold-stage4-attempt1-controller.json','cold-stage4-attempt1.stdout.log','cold-stage4-attempt1.stderr.log','cold-stage4-controller.stdout.log','cold-stage4-controller.stderr.log','cold-stage4-attempt1-raw-custody.json','cold-stage4-library-upload.result.json')])
bundle('stage4-independent-validation-reports.tar.xz',[],[(n,p) for n,p in [
    ('metadata.tar.xz','hia-stage4-independent-validation-metadata.tar.xz'),
    ('FINAL_HANDOFF.json','hia-agent-state-stage4-independent-validation/FINAL_HANDOFF.json'),
    ('root-readback.json','hia-v65-candidate-checkpoint/stage4-root-readback.json'),
    ('original-container.json','hia-v65-candidate-checkpoint/stage4-validation-container.json'),
    ('library-upload.result.json','hia-v65-candidate-checkpoint/stage4-validation-library-upload.result.json'),
    ('retain_stage4.py','hia-v65-candidate-checkpoint/retain_stage4.py'),
    ('retain-stage4.stdout.log','hia-v65-candidate-checkpoint/retain-stage4.stdout.log'),
    ('retain-stage4.stderr.log','hia-v65-candidate-checkpoint/retain-stage4.stderr.log')]])
bundle('rog-v64-final-observations-so-far.tar.xz',[],[(p.name,str(p.relative_to(ROOT))) for p in sorted((ROOT/'v64-rog-full-control-audit-runtime').glob('*.original.json'))]+[(n,'v64-rog-full-control-audit-runtime/'+n) for n in ('full-qualification.authority.json','copy-final-evidence-01.summary.json','copy-final-evidence-01.authority.json')])
bundle('stage5-missing-archive-integration-originals.tar.xz',[('import','hia-agent-state-integration-development/stage5-archive-integration')],[('run_source_stage5.py','hia-agent-state-integration-development/run_source_stage5.py')])
keep('hia-v65-progress-checkpoint/duplicate-evidence-removal.json','earlier-verified-duplicate-removal.json')
dump(OUT/'independent-archive-readback.json',{'schema':'hepta.hia.candidate-checkpoint-readback.v1','archives':audits,'qualification_rerun':False,'whole_stack_closed':False})
keep('hia-v65-candidate-checkpoint/independent-archive-readback.json','independent-archive-readback.json')
readme='''# v65 candidate checkpoint\n\nCandidate eef68334b078eb9fcc414f441c35687e33585bba remains HOLD: GitHub source 327 tests / 3 missing archive implementation import errors, cold 180.146844994s timeout. Local stage4 cold also failed at 180.352510184s. No native or old-owner retirement authority is derived from these failures.\n\nThe full GitHub ZIP, local raw cold archive and independent 20-test installation/observer originals have durable file receipts in the capsules. The evidence here preserves original small reports and exact source snapshots. Stage3 58-test failure and separate unchanged 3-test remediation remain separate. Stage4 has 636 source files, 18 observer + 2 installed development tests, all11 actual nominal images, and full original member replay.\n\nNative ObjectToken stage6-small is developmental; large-stream qualification and the complete native driver remain open. State/storage/business/installation/default cutover remain open. Old production and independent reference owners are retained.\n\nThe stage5 archive integration restores the exact original 3ed implementation matching the retained tests; complete source validation was in progress when this checkpoint was prepared. It does not upgrade candidate eef or either failed cold run.\n'''
(OUT/'README.md').write_text(readme);keep('hia-v65-candidate-checkpoint/README.md','README.md');keep('hia-v65-candidate-checkpoint/prepare.py','prepare.py')
files=[]
for p,name in selected:
    b=p.read_bytes();files.append({'path':PREFIX+'/'+name,'local_path':str(p),'bytes':len(b),'sha256':sha(b),'git_sha':sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'mode':'100644'})
assert len({f['path'] for f in files})==len(files)
plan={'schema':'hepta.hia.candidate-recovery-plan.v1','repository':'TrillionniumFoundation/Hepta','branch':'recovery/hia-function-9acdfa-20261111','parent':'d4354aea3ad56c5e4ce6e2d72d4ce1974344f502','base_tree':'2f91a581234aa08b88cf2e2a934c2bf87328ac4b','main_preserved':'5831f52fada45e076f8f68f198a15c0585e6104f','candidate_head':'eef68334b078eb9fcc414f441c35687e33585bba','files':files,'whole_stack_closed':False}
dump(OUT/'publication-plan.json',plan)
print(json.dumps({'files':len(files),'bytes':sum(f['bytes'] for f in files),'archives':len(audits),'all_read_back':True}),flush=True)
