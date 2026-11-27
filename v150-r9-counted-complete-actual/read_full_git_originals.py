"""Decode actual full Git GET parts and freshly compare every complete original."""
import base64,hashlib,json,os,stat,time,zlib
from pathlib import Path
GET=Path('/tmp/hia-progress-v150-20261114-dda7/counted-actual-full-get')
OUT=Path('/workspace/hia-r9-cross-counted-git-readback-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def seven(s):return {k:getattr(s,k)for k in FIELDS}

def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}

def read(p):
 p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);st=seven(s);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and st==seven(p.lstat())
  with os.fdopen(fd,'rb',closefd=False)as f:b=f.read(s.st_size+1)
  assert len(b)==s.st_size and st==seven(os.fstat(fd))==seven(p.lstat())
 finally:os.close(fd)
 return b,st

def state(root):
 out={'.':seven(root.lstat())};assert stat.S_ISDIR(out['.']['st_mode'])
 def visit(p,prefix):
  for e in sorted(os.scandir(p),key=lambda e:e.name):
   s=e.stat(follow_symlinks=False);n=prefix+e.name;out[n]=seven(s)
   assert stat.S_ISDIR(s.st_mode)or(stat.S_ISREG(s.st_mode)and s.st_nlink==1)
   if stat.S_ISDIR(s.st_mode):visit(Path(e.path),n+'/')
 visit(root,'');return out

def encode(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def put(n,x):
 b=encode(x)
 with (OUT/n).open('xb')as f:f.write(b)
 assert (OUT/n).read_bytes()==b
 return pin(b)
start=time.monotonic_ns();assert not os.path.lexists(OUT);OUT.mkdir(mode=0o700)
proof={'schema':'hia.actual-counted-full-git-readback.v1','status':'FAIL','product_executions':0,'qualification_PASS_claimed':False,'whole_native':False}
try:
 raw,_=read(GET/'INDEX.json');assert pin(raw)['git_blob']=='50ffdc52a115e86dfea0e5410d9405d46d4ba9cf';index=json.loads(raw)
 pieces=[];get_rows=[];offset=0
 for i,row in enumerate(index['parts']):
  b,s=read(GET/row['path']);assert pin(b)=={k:row[k]for k in ('bytes','git_blob','sha256')}
  p=json.loads(b);part=base64.b64decode(p['base64'],validate=True)
  assert p['index']==i and p['offset']==offset and pin(part)==p['piece']
  pieces.append(part);offset+=len(part);get_rows.append({'path':str(GET/row['path']),'identity':pin(b),'seven_stat':s})
 archive=b''.join(pieces);assert pin(archive)==index['archive']
 d=zlib.decompressobj(31);decoded=d.decompress(archive)+d.flush()
 assert d.eof and not d.unused_data and not d.unconsumed_tail and pin(decoded)==index['capsule']
 cap=json.loads(decoded);rows=cap['files']
 assert len(rows)==index['logical_files']==47 and len({r['logical']for r in rows})==47
 assert sum(r['identity']['bytes']for r in rows)==index['logical_bytes']==11555177
 original_raw,_=read(GET/'ORIGINALS.json');assert pin(original_raw)==index['originals']
 assert json.loads(original_raw)==[{k:v for k,v in r.items()if k!='base64'}for r in rows]
 assert cap['scope_states']==index['scope_states']and cap['scopes']==index['scopes']
 for scope,path in cap['scopes'].items():assert state(Path(path))==cap['scope_states'][scope]
 observed=[]
 for r in rows:
  b,s=read(r['path']);expected=base64.b64decode(r['base64'],validate=True)
  assert b==expected and pin(b)==r['identity']and s==r['seven_stat']and stat.S_IMODE(s['st_mode'])==r['mode']
  observed.append({'logical':r['logical'],'path':r['path'],'identity':pin(b),'mode':stat.S_IMODE(s['st_mode']),'seven_stat':s})
 for scope,path in cap['scopes'].items():assert state(Path(path))==cap['scope_states'][scope]
 for r in observed:assert seven(Path(r['path']).lstat())==r['seven_stat']
 for r in get_rows:assert seven(Path(r['path']).lstat())==r['seven_stat']
 observed_pin=put('OBSERVED.json',{'originals':observed,'actual_git_get_files':get_rows})
 proof.update(status='PASS_COMPLETE_ACTUAL_GET_CAPSULE_AND_ALL_ORIGINALS',logical_files=47,logical_bytes=11555177,parts=len(pieces),archive=index['archive'],capsule=index['capsule'],originals=index['originals'],observed=observed_pin,whole_bytes_modes_seven_stats_equal=True,complete_scope_pathsets_equal=True,full_gzip_crc=True,exact_single_member_end=True,actual_product_status='FAIL',actual_diagnostic_complete=True)
except BaseException:
 import traceback
 proof['error']=traceback.format_exc()
finally:
 proof['elapsed_ns']=time.monotonic_ns()-start
 result_pin=put('RESULT.json',proof)
print(json.dumps({'status':proof['status'],'result':result_pin,'elapsed_ns':proof['elapsed_ns']},sort_keys=True))
raise SystemExit(0 if proof['status']=='PASS_COMPLETE_ACTUAL_GET_CAPSULE_AND_ALL_ORIGINALS'else 1)
