"""Only the small author capsule's complete actual Git GET inverse."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-patch-custody-transport-author-publication-r1-20261115-dda7')
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
v=json.loads(raw);m=json.loads(actual['MEMBERS.json']);assert v['root']==m['root']and v['directories']==m['directories']
assert len(v['files'])==m['files_count']==16 and set(v['files'])==set(m['files']);total=0
for name,row in v['files'].items():
 assert row['descriptor']==m['files'][name];b=row['text'].encode();p=Path(row['descriptor']['path'])
 assert read(p)==(b,row['descriptor']['stat'])and pin(b)==row['descriptor']['pin'];total+=len(b)
root=Path(v['root']);dirs={'.':seven(root)};files=[]
for p in sorted(root.rglob('*')):
 if p.is_dir():dirs[p.relative_to(root).as_posix()]=seven(p)
 else:files.append(p.relative_to(root).as_posix())
assert dirs==v['directories']and files==sorted(v['files'])
result={'status':'PASS_COMPLETE_ACTUAL_GIT_AUTHOR_RESTORE','files':16,'logical_bytes':total,
 'strict_zlib_eof':True,'all_bytes_modes_sevenstats_pathsets':True,'archive_payload_read_bytes':0,
 'data_transport_or_product_execution':0,'payload':capsule['payload'],'packed':capsule['packed']}
report=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with(ROOT/'ACTUAL-GIT-READBACK.json').open('xb')as f:f.write(report)
print(json.dumps({'report':pin(report),'files':16,'logical_bytes':total},sort_keys=True))
