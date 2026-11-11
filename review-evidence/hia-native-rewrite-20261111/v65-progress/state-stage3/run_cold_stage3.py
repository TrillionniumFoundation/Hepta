"""One retained cold replay of frozen v65 stage3; original limits unchanged."""
from hashlib import sha256
from pathlib import Path
import io, json, os, subprocess, sys, tarfile, time

ROOT=Path('/workspace/scratch/9acdfa9f5639/native-agent-state-integration')
OUT=ROOT.parent/'hia-agent-state-integration-development'
RAW=Path('/dev/shm/hia-v65-stage3-cold')
RAW.mkdir(mode=0o700)
(RAW/'tmp').mkdir(mode=0o700)
frozen=json.loads((OUT/'draft-stage3-source.json').read_bytes())['source_closure']
def snapshot():return {name:sha256((ROOT/name).read_bytes()).hexdigest() for name in frozen}
before=snapshot();assert before==frozen
command=[sys.executable,'-B','tools/replay_hia_selfhost_cold.py','--output',str(RAW/'cold.json')]
started=time.monotonic_ns()
with (OUT/'cold-stage3-attempt1.stdout.log').open('xb') as stdout, (OUT/'cold-stage3-attempt1.stderr.log').open('xb') as stderr:
    proc=subprocess.run(command,cwd=ROOT,stdout=stdout,stderr=stderr,
                        env={**os.environ,'TMPDIR':str(RAW/'tmp'),'PYTHONDONTWRITEBYTECODE':'1'})
after=snapshot()
result={'schema':'hepta.hia.v65-stage3-cold-attempt.v1','command':command,'source_checkpoint':'draft-stage3-source.json','source_manifest_sha256':sha256((OUT/'draft-stage3-source.json').read_bytes()).hexdigest(),'returncode':proc.returncode,'controller_wall_elapsed_ns':time.monotonic_ns()-started,'source_preserved':before==after,'cold_report_exists':(RAW/'cold.json').is_file(),'native_qualification_limits_modified':False,'source_commit_published':False,'whole_stack_closed':False}
if (RAW/'cold.json').is_file():
    raw=(RAW/'cold.json').read_bytes();(OUT/'cold-stage3-attempt1.json').write_bytes(raw)
    cold=json.loads(raw);result['cold_status']=cold['status'];result['cold_wall_elapsed_ns']=cold['wall_elapsed_ns'];result['checks']=cold['checks']
result['passed']=proc.returncode==0 and before==after and result.get('cold_status')=='COLD_SELFHOST_REPLAY_PASS'
(OUT/'cold-stage3-attempt1-controller.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result),flush=True)
# Preserve all original regular bytes and modes, including failure artifacts.
files={};symlinks={};directories={}
for p in sorted(RAW.rglob('*')):
    rel=p.relative_to(RAW).as_posix();st=p.lstat()
    if p.is_symlink():symlinks[rel]=os.readlink(p)
    elif p.is_dir():directories[rel]=st.st_mode&0o777
    elif p.is_file():
        data=p.read_bytes();files[rel]={'bytes':len(data),'sha256':sha256(data).hexdigest(),'mode':st.st_mode&0o777}
    else:raise AssertionError(('unexpected raw node',rel))
custody={'schema':'hepta.hia.v65-stage3-cold-raw.v1','source':str(RAW),'files':files,'symlinks':symlinks,'directories':directories,'qualification_passed':result['passed']}
custody_bytes=(json.dumps(custody,indent=2,sort_keys=True)+'\n').encode()
archive=OUT/'cold-stage3-attempt1-raw.tar.xz'
with tarfile.open(archive,'x:xz') as t:
    for rel in sorted([*files,*symlinks,*directories]):
        p=RAW/rel
        if rel in files:
            data=p.read_bytes();assert sha256(data).hexdigest()==files[rel]['sha256']
            ti=tarfile.TarInfo(rel);ti.mode=files[rel]['mode'];ti.size=len(data);t.addfile(ti,io.BytesIO(data))
        elif rel in symlinks:
            ti=tarfile.TarInfo(rel);ti.type=tarfile.SYMTYPE;ti.linkname=symlinks[rel];ti.mode=0o777;t.addfile(ti)
        else:
            ti=tarfile.TarInfo(rel);ti.type=tarfile.DIRTYPE;ti.mode=directories[rel];t.addfile(ti)
    ti=tarfile.TarInfo('ROOT_RAW_CUSTODY.json');ti.size=len(custody_bytes);ti.mode=0o644;t.addfile(ti,io.BytesIO(custody_bytes))
with tarfile.open(archive,'r:xz') as t:
    assert len(t.getmembers())==len(files)+len(symlinks)+len(directories)+1
    for m in t:
        if m.name=='ROOT_RAW_CUSTODY.json':assert t.extractfile(m).read()==custody_bytes
        elif m.name in files:
            data=t.extractfile(m).read();record=files[m.name]
            assert len(data)==record['bytes'] and sha256(data).hexdigest()==record['sha256'] and m.mode==record['mode']
        elif m.name in symlinks:assert m.issym() and m.linkname==symlinks[m.name]
        else:assert m.isdir() and m.mode==directories[m.name]
seal={'schema':'hepta.hia.v65-stage3-cold-seal.v1','archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha256(archive.read_bytes()).hexdigest(),'files':len(files),'raw_bytes':sum(v['bytes'] for v in files.values()),'symlinks':len(symlinks),'directories':len(directories),'all_originals_read_back':True,'qualification_passed':result['passed'],'source_preserved':before==snapshot()}
(OUT/'cold-stage3-attempt1-raw-custody.json').write_text(json.dumps(seal,indent=2,sort_keys=True)+'\n')
print(json.dumps(seal),flush=True)
raise SystemExit(0 if result['passed'] else 1)
