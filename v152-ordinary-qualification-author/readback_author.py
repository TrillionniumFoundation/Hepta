"""Decode actual full Git GET author bytes, not project/product data."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
ROOT=Path('/home/agent/hia-ordinary-qualification-author-custody-r1-20261115-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(p):
 s=p.lstat();return{k:getattr(s,k)for k in FIELDS}
def pin(b):return{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def read(p):
 s=seven(p);assert stat.S_ISREG(s['st_mode'])and s['st_nlink']==1 and s['st_size']<=16<<20
 b=p.read_bytes();assert seven(p)==s;return b,s
pub=json.loads(read(ROOT/'PUBLICATION-INPUTS.json')[0]);actual={}
for i,row in enumerate(pub['leaves']):
 b,_=read(ROOT/'GIT'/('%03d-GET.txt'%i));assert pin(b)==row['pin']
 assert read(Path(row['path']))==(b,row['stat'])
 assert json.loads(read(ROOT/'GIT'/('%03d-ACK.json'%i))[0])['sha']==row['pin']['git_blob']
 assert json.loads(read(ROOT/'GIT'/('%03d-VERIFIED.json'%i))[0])['full_get_exact']is True
 actual[row['logical']]=b
capsule=json.loads(actual['AUTHORING-CAPSULE.json']);packed=base64.b64decode(capsule['data_base64'],validate=True)
assert pin(packed)==capsule['packed'];d=zlib.decompressobj();raw=d.decompress(packed)+d.flush()
assert d.eof and not d.unused_data and not d.unconsumed_tail and pin(raw)==capsule['payload']
v=json.loads(raw);m=json.loads(actual['MEMBERS.json']);assert set(v['roots'])==set(m['roots'])
total=0;count=0;root_counts={}
for label,items in v['roots'].items():
 authority=m['roots'][label];assert items['root']==authority['root']and items['directories']==authority['directories']
 assert len(items['files'])==authority['files_count']and set(items['files'])==set(authority['files'])
 for name,row in items['files'].items():
  assert row['descriptor']==authority['files'][name];b=row['text'].encode();p=Path(row['descriptor']['path'])
  assert read(p)==(b,row['descriptor']['stat'])and pin(b)==row['descriptor']['pin'];total+=len(b);count+=1
 root=Path(items['root']);dirs={'.':seven(root)};files=[]
 for p in sorted(root.rglob('*')):
  s=seven(p)
  if stat.S_ISDIR(s['st_mode']):dirs[p.relative_to(root).as_posix()]=s
  else:files.append(p.relative_to(root).as_posix())
 assert dirs==items['directories']and files==sorted(items['files']);root_counts[label]=len(files)
assert count==m['files_count']==82 and total==m['logical_bytes']
result={'status':'PASS_COMPLETE_ACTUAL_GIT_AUTHOR_RESTORE','roots':root_counts,'files':count,'logical_bytes':total,
 'strict_zlib_eof':True,'all_bytes_modes_sevenstats_pathsets':True,'binders_executed':0,'products_executed':0,
 'source_payload_copy':0,'payload':capsule['payload'],'packed':capsule['packed']}
report=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with(ROOT/'ACTUAL-GIT-READBACK.json').open('xb')as f:f.write(report)
print(json.dumps({'report':pin(report),'files':count,'logical_bytes':total},sort_keys=True))
