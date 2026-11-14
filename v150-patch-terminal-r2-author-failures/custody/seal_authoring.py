"""Capture R2 authoring and both actual reader failures. No reader execution."""
import base64,hashlib,json,os,stat,time,zlib
from pathlib import Path
OUT=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-publication-r2-dda7')
R1=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-reader-r1-dda7')
R2=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-reader-r2-dda7')
A1=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-actual-r1-dda7')
A2=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-actual-r2-dda7')
ROOT=Path('/tmp/hia-progress-v150-20261114-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
R1_NAMES=('TERMINAL-BODY.py.txt','assemble_reader.py','freeze_inputs.py','read_terminal.py','STATIC-PROJECTION.json','CONTRACT.md','READBACK-PLAN.json','READBACK-LAUNCH.json','HANDOFF.json')
R2_NAMES=('R1-FAILURE-RETAINED.json','R1-TO-R2.diff','STATIC-INVERSE.json','CONTRACT.md','author_r2.py','PUBLISH-BEFORE.py.txt','READBACK-LAUNCH.json','PUBLISH.py.txt','READBACK-PLAN.json','read_terminal.py','PLAN.diff','HANDOFF.json')
ROOT_NAMES=tuple('PATCH-QUALIFICATION-TERMINAL-READER-'+r+'-'+s+'.json'for r in('R1','R2')for s in('EXEC','RETURN','ROOT-REVIEW','ROOT-REVIEW-EXEC'))+('PATCH-TERMINAL-READER-R1-POST137-ENVIRONMENT.json',)
def seven(s):return {k:getattr(s,k)for k in FIELDS}
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def write(name,b):
 p=OUT/name
 with p.open('xb')as f:f.write(b)
 assert p.read_bytes()==b
 return {'path':str(p),**pin(b)}
def capture(p,name):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);before=seven(s);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and before==seven(p.lstat())
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(s.st_size+1)
  assert len(raw)==s.st_size and before==seven(os.fstat(fd))==seven(p.lstat())
 finally:os.close(fd)
 assert b'X-Amz-Signature='not in raw and b'SharedAccessSignature='not in raw
 return {'name':name,'source_path':str(p),'text':raw.decode(),'pin':pin(raw),'mode':stat.S_IMODE(s.st_mode),'stat':before}
assert sorted(p.name for p in R1.iterdir())==sorted(R1_NAMES)
assert sorted(p.name for p in R2.iterdir())==sorted(R2_NAMES)
assert sorted(p.name for p in A1.iterdir())==['STAGES.json']
assert list(A2.iterdir())==[]
a1stat=seven(A1.lstat());a2stat=seven(A2.lstat())
files=[capture(root/name,prefix+'/'+name)for prefix,root,names in(('author-r1',R1,R1_NAMES),('author-r2',R2,R2_NAMES),('root',ROOT,ROOT_NAMES))for name in names]
files.append(capture(A1/'STAGES.json','actual-r1/STAGES.json'))
for revision in('R1','R2'):
 value=json.loads(next(r for r in files if r['name']=='root/PATCH-QUALIFICATION-TERMINAL-READER-'+revision+'-RETURN.json')['text'])
 assert value['exit_code']==137 and value['output']==''
environment={}
for name in ('/proc/meminfo','/proc/self/cgroup','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.events'):
 try:environment[name]={'observed_text':Path(name).read_text()}
 except OSError as error:environment[name]={'error_type':type(error).__name__,'errno':error.errno}
storage={}
for name in ('/workspace','/tmp','/dev/shm'):
 s=os.statvfs(name);storage[name]={'available_bytes':s.f_bavail*s.f_frsize,'filesystem_device':Path(name).stat().st_dev}
observation={'schema':'hepta.hia.reader-r2-post137-observation.v1','observed_at_ns':time.time_ns(),
 'actual_r1':{'root':str(A1),'root_stat':a1stat,'complete_pathset':['STAGES.json'],'complete_result':False},
 'actual_r2':{'root':str(A2),'root_stat':a2stat,'complete_pathset':[],'complete_result':False},
 'r2_last_durably_proven_boundary':'output root created; no completed result or intermediate file',
 'r1_progress_not_inherited_by_r2':True,'termination_cause_proven':False,'OOM_claim':False,
 'current_environment_only_not_termination_time':environment,'current_storage_only':storage,
 'product_rerun':0,'reader_rerun':0,'original_product_pass_not_independent_terminal_pass':True}
write('R2-FAILURE-OBSERVATION.json',enc(observation));files.append(capture(OUT/'R2-FAILURE-OBSERVATION.json','failure-observation/R2-FAILURE-OBSERVATION.json'))
payload=enc({'schema':'hepta.hia.reader-author.fullfiles.v1','files':files,
 'directories':{'actual-r1':{'path':str(A1),'stat':a1stat},'actual-r2':{'path':str(A2),'stat':a2stat}}})
compressed=zlib.compress(payload,9)
capsule=enc({'schema':'hepta.hia.reader-author.capsule.v1','codec':'zlib9+base64','payload':pin(payload),'compressed':pin(compressed),'data':base64.b64encode(compressed).decode()})
write('AUTHORING-CAPSULE.json',capsule)
stream=zlib.decompressobj();unpacked=stream.decompress(compressed)+stream.flush();assert stream.eof and not stream.unused_data and not stream.unconsumed_tail and unpacked==payload
for row in json.loads(unpacked)['files']:assert capture(Path(row['source_path']),row['name'])==row
assert list(A2.iterdir())==[] and seven(A2.lstat())==a2stat
assert sorted(p.name for p in A1.iterdir())==['STAGES.json']and seven(A1.lstat())==a1stat
report={'status':'PASS_COMPLETE_AUTHOR_AND_RETAINED_FAILURE_CAPSULE_ONLY','files':len(files),
 'logical_bytes':sum(r['pin']['bytes']for r in files),'payload':pin(payload),'compressed':pin(compressed),'capsule':pin(capsule),
 'all_bytes_modes_seven_stats_equal':True,'r1_exit_code':137,'r2_exit_code':137,
 'r1_partial_pathset':['STAGES.json'],'r2_partial_pathset':[],'termination_cause_proven':False,
 'reader_executed_by_this_sealer':False,'products_executed':0}
write('LOCAL-READBACK.json',enc(report))
write('MANIFEST.json',enc({'schema':'hepta.hia.reader-author.manifest.v1','files':[{k:v for k,v in r.items()if k!='text'}for r in files],
 'directories':json.loads(payload)['directories']}))
leaves=[]
for name in ('read_terminal.py','READBACK-PLAN.json','READBACK-LAUNCH.json','STATIC-INVERSE.json','HANDOFF.json','CONTRACT.md','R1-TO-R2.diff','R1-FAILURE-RETAINED.json'):
 raw=(R2/name).read_bytes();leaves.append({'name':'reader-r2/'+name,'text':raw.decode(),**pin(raw)})
for name in ('AUTHORING-CAPSULE.json','LOCAL-READBACK.json','MANIFEST.json','seal_authoring.py','R2-FAILURE-OBSERVATION.json'):
 raw=(OUT/name).read_bytes();leaves.append({'name':'custody/'+name,'text':raw.decode(),**pin(raw)})
write('PUBLICATION-INPUTS.json',enc(leaves))
print(json.dumps({'status':report['status'],'files':len(files),'logical_bytes':report['logical_bytes'],'capsule':pin(capsule),'publication_leaves':len(leaves),'reader_execution':0,'products':0},sort_keys=True))
