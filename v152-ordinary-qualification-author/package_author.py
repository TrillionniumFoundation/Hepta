"""Seal only frozen small author roots; do not execute their code."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
ROOT=Path('/home/agent/hia-ordinary-qualification-author-custody-r1-20261115-dda7')
ROOTS={
 'qualification-r1':Path('/workspace/hia-cli-owner-bundle-qualification-author-r1-20261115-dda7'),
 'qualification-r2':Path('/home/agent/hia-cli-owner-bundle-qualification-author-r2-20261115-dda7'),
 'generation-terminal-author':Path('/workspace/hia-cli-owner-bundle-generation-terminal-author-r1-20261115-dda7')}
EXPECTED={'qualification-r1':44,'qualification-r2':29,'generation-terminal-author':9}
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(p):
 s=p.lstat();return{k:getattr(s,k)for k in FIELDS}
def pin(b):return{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def capture(p):
 s=seven(p);assert stat.S_ISREG(s['st_mode'])and s['st_nlink']==1 and s['st_size']<=16<<20
 b=p.read_bytes();assert seven(p)==s
 return b,{'path':str(p),'pin':pin(b),'mode':stat.S_IMODE(s['st_mode']),'stat':s}
def put(name,v):
 b=enc(v)
 with(ROOT/name).open('xb')as f:f.write(b)
 return{'logical':name,**capture(ROOT/name)[1]}
roots={};members={};total=0
for label,path in ROOTS.items():
 files={};dirs={'.':seven(path)}
 for p in sorted(path.rglob('*')):
  s=seven(p);name=p.relative_to(path).as_posix()
  if stat.S_ISDIR(s['st_mode']):dirs[name]=s
  else:
   b,d=capture(p);files[name]={'descriptor':d,'text':b.decode('utf-8')};total+=len(b)
 assert len(files)==EXPECTED[label]
 roots[label]={'root':str(path),'directories':dirs,'files':files}
 members[label]={'root':str(path),'directories':dirs,'files':{n:r['descriptor']for n,r in files.items()},'files_count':len(files)}
payload=enc({'schema':'hepta.hia.ordinary-qualification.complete-authors.v1','roots':roots})
packed=zlib.compress(payload,6);decoder=zlib.decompressobj();decoded=decoder.decompress(packed)+decoder.flush()
assert decoded==payload and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
capsule=put('AUTHORING-CAPSULE.json',{'schema':'hepta.hia.zlib.complete-authors.v1','payload':pin(payload),'packed':pin(packed),'data_base64':base64.b64encode(packed).decode()})
manifest=put('MEMBERS.json',{'roots':members,'files_count':sum(EXPECTED.values()),'logical_bytes':total})
for label,value in roots.items():
 for name,row in value['files'].items():assert capture(Path(row['descriptor']['path']))==(row['text'].encode(),row['descriptor'])
 for name,s in value['directories'].items():assert seven(ROOTS[label]/name)==s
local=put('LOCAL-READBACK.json',{'status':'PASS_COMPLETE_AUTHOR_CAPSULE_LOCAL_INVERSE','roots':{k:len(v['files'])for k,v in roots.items()},'files':sum(EXPECTED.values()),'logical_bytes':total,'payload':pin(payload),'compressed':pin(packed),'strict_zlib_eof':True,'binders_executed':0,'products_executed':0,'source_payload_copy':0,'historical_generation_reader_execution':'ROOT_ALREADY_EXECUTED_SEPARATE_ACTUAL_PASS_NOT_REPLAYED'})
leaves=[capsule,manifest,local]
for name in ('package_author.py','readback_author.py'):
 leaves.append({'logical':name,**capture(ROOT/name)[1]})
for label,relative in [('qualification-r2','HANDOFF.json'),('qualification-r2','PREPARATION-PLAN.json'),('qualification-r2','PREPARATION-LAUNCH.json'),('qualification-r2','WHOLE-INVERSE.json'),('generation-terminal-author','HANDOFF.json')]:
 leaves.append({'logical':label+'/'+relative,**capture(ROOTS[label]/relative)[1]})
put('PUBLICATION-INPUTS.json',{'repository':'TrillionniumFoundation/Hepta','leaves':leaves})
print(json.dumps({'files':sum(EXPECTED.values()),'logical_bytes':total,'capsule':capsule['pin'],'packed':pin(packed),'leaves':len(leaves)},sort_keys=True))
