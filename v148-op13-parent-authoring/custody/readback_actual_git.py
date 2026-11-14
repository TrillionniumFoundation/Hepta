"""Read all actual Git-returned UTF-8 leaves and restore the author in memory."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
D=Path('/tmp/hia-op13-execution-custody-r1-dda7');R=Path('/tmp/hia-op13-execution-author-r1-dda7')
F=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b,mode='100644'):return {'bytes':len(b),'mode':mode,'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def capture(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1;b=p.read_bytes();assert all(getattr(p.lstat(),k)==getattr(s,k)for k in F);return b
def state(root):
 out={'.':{k:getattr(root.lstat(),k)for k in F}}
 def walk(p,prefix):
  for x in sorted(os.scandir(p),key=lambda x:x.name):
   s=x.stat(follow_symlinks=False);n=prefix+x.name;assert stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)
   out[n]={k:getattr(s,k)for k in F}
   if stat.S_ISDIR(s.st_mode):walk(Path(x.path),n+'/')
   else:assert s.st_nlink==1
 walk(root,'');return out
plan=json.loads((D/'PUBLISH-PLAN.json').read_bytes());actual={}
for leaf in plan['leaves']:
 b=capture(D/'actual-git'/leaf['label']);assert pin(b)==leaf['pin'];assert b==capture(Path(leaf['path']));actual[leaf['label']]=b
index=json.loads(actual['custody/INDEX.json']);parts=[]
for i,row in enumerate(index['parts']):
 raw=actual['custody/'+row['path']];assert pin(raw)==row['pin'];part=json.loads(raw)
 assert part['index']==i and part['count']==len(index['parts'])and part['offset']==sum(map(len,parts))and part['archive']==index['archive']
 b=base64.b64decode(part['payload'],validate=True);assert pin(b)==part['raw']==row['raw'];parts.append(b)
archive=b''.join(parts);assert pin(archive)==index['archive']
d=zlib.decompressobj();payload=d.decompress(archive,index['decoded']['bytes']+1);payload+=d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail
assert pin(payload)==index['decoded'];v=json.loads(payload)
assert len(v['files'])==index['file_count']and len(v['directories'])==index['directory_count']
expected={r['path']:r for r in index['files']};assert len(expected)==len(v['files']);total=0
before=state(R);want={r['path']:r['new_stat']for r in index['files']+index['directories']};assert before==want
for row in v['files']:
 assert {k:x for k,x in row.items()if k!='base64'}==expected[row['path']]
 name=row['path'];assert not Path(name).is_absolute()and all(p not in ('','.','..')for p in name.split('/'))
 b=base64.b64decode(row['base64'],validate=True);assert pin(b,row['pin']['mode'])==row['pin']
 assert capture(R/name)==b and stat.S_IMODE((R/name).lstat().st_mode)==row['posix_mode'];total+=len(b)
assert total==index['logical_bytes']and state(R)==before
for row in v['directories']:assert stat.S_IMODE((R/row['path']).lstat().st_mode)==row['posix_mode']
result={'schema':'hepta.hia.static-author-actual-git-readback.v1','status':'PASS','actual_complete_Git_leaves':len(actual),'archive_parts':len(parts),'file_count':len(v['files']),'directory_count':len(v['directories']),'logical_bytes':total,'archive':index['archive'],'decoded':index['decoded'],'every_actual_Git_byte_compared':True,'all_members_full_bytes_modes_new_seven_stats_equal':True,'complete_pathset_unchanged':True,'whole_archive_final_eof_checked':True,'project_imports':0,'products':0,'full_source_copy':0,'old_inode_authority_inherited':False,'no_API_response_or_signed_URL_in_payload':True}
raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with(D/'ACTUAL-GIT-READBACK.json').open('xb')as f:f.write(raw)
print(json.dumps({**result,'report':pin(raw)}))
