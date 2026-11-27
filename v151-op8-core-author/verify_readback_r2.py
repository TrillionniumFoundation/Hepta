"""Verify immutable Git readbacks and completely decode the author capsule."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
P=Path(__file__).absolute().parent
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
plan=json.loads((P/'PUBLICATION-PLAN.json').read_bytes());verified=[];capsule=None
for r in plan['files']:
 i=str(r['index']).zfill(3);returned=json.loads((P/'GET'/(i+'.json')).read_bytes())
 raw=returned['structuredContent']['content'].encode();expected={k:r[k]for k in ('bytes','sha256','git_blob')}
 assert pin(raw)==expected and raw==Path(r['path']).read_bytes()
 assert stat.S_IMODE(Path(r['path']).lstat().st_mode)==r['posix_mode']
 v=json.loads((P/'VERIFIED'/(i+'.json')).read_bytes());assert v['full_get_exact']and v['git_blob']==r['git_blob']
 verified.append({'relative':r['relative'],**expected,'mode':r['posix_mode'],'full_get_exact':True})
 if r['index']==0:capsule=json.loads(raw)
c=base64.b64decode(capsule['data'],validate=True);assert pin(c)==capsule['compressed']
d=zlib.decompressobj();payload=d.decompress(c)+d.flush()
assert d.eof and not d.unused_data and not d.unconsumed_tail and pin(payload)==capsule['payload']
value=json.loads(payload);names=[];total=0
for row in value['files']:
 name=row['path'];assert not Path(name).is_absolute()and all(x not in ('','.','..')for x in name.split('/'))and name not in names
 names.append(name);raw=base64.b64decode(row['base64'],validate=True);p=Path(value['root'])/name
 assert pin(raw)=={k:row[k]for k in ('bytes','sha256','git_blob')}and raw==p.read_bytes()
 assert stat.S_IMODE(p.lstat().st_mode)==row['mode'];total+=len(raw)
assert len(names)==capsule['files']==48 and total==capsule['raw_file_bytes']==1321112
assert names==sorted(str(p.relative_to(value['root']))for p in Path(value['root']).rglob('*')if p.is_file())
proof={'status':'PASS_GIT_FULL_GET_AND_COMPLETE_48_AUTHOR_FILE_DECODE','published_leaves':verified,
 'author_files':48,'author_bytes':total,'all_file_bytes_modes_pathset_exact':True,
 'capsule':plan['files'][0],'products':0,'refs':0,'complete_product_source_included':False}
out=P/'FULL-READBACK.json'
with out.open('xb')as f:f.write((json.dumps(proof,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'proof':pin(out.read_bytes()),'author_files':48,'author_bytes':total},sort_keys=True))
