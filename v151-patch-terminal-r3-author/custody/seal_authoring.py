"""Preserve complete R3 authoring. No terminal-reader or product execution."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
BASE=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-reader-r3-dda7')
OUT=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-publication-r3-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
EXPECTED=('BOOKKEEPING.py.txt','CONTRACT.md','author_r3.py','read_terminal.py','R2-TO-R3.diff','REPLACEMENTS.json','STATIC-INVERSE.json','AUTHORING-R1-TOOL-RETURN.json','finish_author_r3.py','AUTHORING-R1-ERROR-RETAINED.json','READBACK-PLAN.json','PLAN.diff','READBACK-LAUNCH.json','HANDOFF.json')
def seven(s):return {k:getattr(s,k)for k in FIELDS}
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def write(n,b):
 with (OUT/n).open('xb')as f:f.write(b)
 assert (OUT/n).read_bytes()==b
def capture(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);before=seven(s);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and before==seven(p.lstat())
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(s.st_size+1)
  assert len(raw)==s.st_size and before==seven(os.fstat(fd))==seven(p.lstat())
 finally:os.close(fd)
 return {'name':p.name,'source_path':str(p),'text':raw.decode(),'pin':pin(raw),'mode':stat.S_IMODE(s.st_mode),'stat':before}
assert sorted(p.name for p in BASE.iterdir())==sorted(EXPECTED)
files=[capture(BASE/n)for n in sorted(EXPECTED)]
payload=enc({'schema':'hepta.hia.reader-author.fullfiles.v1','files':files})
compressed=zlib.compress(payload,9);capsule=enc({'schema':'hepta.hia.reader-author.capsule.v1','codec':'zlib9+base64',
 'payload':pin(payload),'compressed':pin(compressed),'data':base64.b64encode(compressed).decode()})
write('AUTHORING-CAPSULE.json',capsule)
d=zlib.decompressobj();back=d.decompress(compressed)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail and back==payload
for row in json.loads(back)['files']:assert capture(Path(row['source_path']))==row
assert sorted(p.name for p in BASE.iterdir())==sorted(EXPECTED)
report={'status':'PASS_COMPLETE_R3_AUTHORING_CAPSULE_ONLY','files':len(files),'logical_bytes':sum(r['pin']['bytes']for r in files),
 'payload':pin(payload),'compressed':pin(compressed),'capsule':pin(capsule),'all_bytes_modes_seven_stats_equal':True,
 'author_r1_capture_error_preserved':True,'reader_execution_by_sealer':0,'products':0}
write('LOCAL-READBACK.json',enc(report));write('MANIFEST.json',enc({'schema':'hepta.hia.reader-author.manifest.v1','root':str(BASE),'files':[{k:v for k,v in r.items()if k!='text'}for r in files]}))
leaves=[]
for n in ('read_terminal.py','READBACK-PLAN.json','READBACK-LAUNCH.json','STATIC-INVERSE.json','HANDOFF.json','CONTRACT.md','R2-TO-R3.diff','BOOKKEEPING.py.txt'):
 raw=(BASE/n).read_bytes();leaves.append({'name':'reader-r3/'+n,'text':raw.decode(),**pin(raw)})
for n in ('AUTHORING-CAPSULE.json','LOCAL-READBACK.json','MANIFEST.json','seal_authoring.py'):
 raw=(OUT/n).read_bytes();leaves.append({'name':'custody/'+n,'text':raw.decode(),**pin(raw)})
write('PUBLICATION-INPUTS.json',enc(leaves));print(json.dumps({'files':len(files),'logical_bytes':report['logical_bytes'],'leaves':len(leaves),'capsule':pin(capsule),'products':0,'reader_execution':0},sort_keys=True))
