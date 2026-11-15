"""Decode the exact saved Git GET parts and compare every complete author file."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-cli-owner-bundle-author-custody-r1-20261115-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(path):
 s=Path(path).lstat();return{k:getattr(s,k)for k in FIELDS}
def pin(raw,mode='100644'):
 return{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
def read(path):
 p=Path(path);s=seven(p);assert stat.S_ISREG(s['st_mode'])and s['st_nlink']==1 and s['st_size']<=16<<20
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  assert s=={k:getattr(os.fstat(fd),k)for k in FIELDS}
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(s['st_size']+1)
  assert len(raw)==s['st_size']and seven(p)==s=={k:getattr(os.fstat(fd),k)for k in FIELDS}
 finally:os.close(fd)
 return raw,s
def current(desc):
 raw,s=read(desc['path']);assert s==desc['stat']and pin(raw,'100755'if s['st_mode']&0o111 else'100644')==desc['pin'];return raw
p=json.loads(read(ROOT/'PUBLICATION-INPUTS.json')[0]);actual={}
for i,d in enumerate(p['leaves']):
 raw=read(ROOT/'GIT'/('%03d-GET.txt'%i))[0]
 assert pin(raw,d['pin']['mode'])==d['pin']and current(d)==raw
 assert json.loads(read(ROOT/'GIT'/('%03d-ACK.json'%i))[0])['sha']==d['pin']['git_blob']
 assert json.loads(read(ROOT/'GIT'/('%03d-VERIFIED.json'%i))[0])['full_get_exact']is True
 actual[d['logical']]=raw
index=json.loads(actual['INDEX.json']);blocks=[];offset=0
for i,d in enumerate(index['parts']):
 part=json.loads(actual[d['logical']]);raw=base64.b64decode(part['data'],validate=True)
 assert part['index']==i and part['offset']==offset and part['compressed_whole']==index['compressed']
 assert pin(raw)==part['piece'];blocks.append(raw);offset+=len(raw)
compressed=b''.join(blocks);assert pin(compressed)==index['compressed']
decoder=zlib.decompressobj();payload=decoder.decompress(compressed)+decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(payload)==index['payload']
value=json.loads(payload);members=json.loads(actual['MEMBERS.json']);assert value['root']==members['root']and value['directories']==members['directories']
assert set(value['files'])==set(members['files'])and len(value['files'])==index['files']==47
total=0
for n,row in value['files'].items():
 assert row['descriptor']==members['files'][n]
 raw=row['text'].encode();assert current(row['descriptor'])==raw;total+=len(raw)
assert total==index['logical_bytes']==2703395
root=Path(value['root']);current_files=[];current_dirs={}
def walk(directory):
 current_dirs[str(directory.relative_to(root))]=seven(directory)
 for child in sorted(directory.iterdir()):
  if stat.S_ISDIR(child.lstat().st_mode):walk(child)
  else:current_files.append(str(child.relative_to(root)))
walk(root);assert current_dirs==value['directories']and sorted(current_files)==sorted(value['files'])
for row in value['files'].values():assert seven(row['descriptor']['path'])==row['descriptor']['stat']
report={'status':'PASS_COMPLETE_ACTUAL_GIT_AUTHOR_SOURCE_RESTORE','files':47,'logical_bytes':total,
 'parts':len(blocks),'payload':index['payload'],'compressed':index['compressed'],
 'strict_zlib_eof':True,'all_actual_GET_ACK_and_original_bytes_modes_stats_pathsets':True,
 'project_imports_generation_products':0,'no_qualification_inherited':True}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
with(ROOT/'ACTUAL-GIT-READBACK.json').open('xb')as f:f.write(raw)
print(json.dumps({'report':pin(raw),'files':47,'logical_bytes':total},sort_keys=True))
