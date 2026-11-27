"""Read-only complete custody of original local R4 generation evidence."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,tarfile,zlib

ROOT=Path('/workspace/scratch/dda74a4fae35/recovered-v85')
RAW=ROOT/'local-generation-r4/evidence/raw'
OUT=Path(__file__).resolve().parent
def ident(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
      'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def enc(value):return (json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode()
def pin(raw,row):assert ident(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
def tree(rows):
    root={}
    for r in rows:
        at=root;parts=r['path'].split('/')
        for p in parts[:-1]:at=at.setdefault(p,{})
        assert parts[-1] not in at;at[parts[-1]]=(r['mode'],r['git_blob'])
    def done(at):
        entries=[]
        for name,v in at.items():
            if isinstance(v,dict):m,o,key='40000',done(v),(name+'/').encode()
            else:m,o=v;key=name.encode()
            entries.append((key,m.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(o)))
        raw=b''.join(v for _,v in sorted(entries));return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return done(root)
pool={};rows=[];directories=[];paths=[]
for p in sorted(RAW.rglob('*')):
    s=p.lstat();name='raw/'+p.relative_to(RAW).as_posix()
    if stat.S_ISDIR(s.st_mode):directories.append({'path':name,'mode':stat.S_IMODE(s.st_mode)});continue
    assert stat.S_ISREG(s.st_mode) and not p.is_symlink();paths.append(p)
assert len(paths)==1913 and sum(p.stat().st_size for p in paths)==120634380
paths.append(ROOT/'LOCAL-CONTROLLER-R4.log')
paths.append(Path(__file__))
for p in paths:
    raw=p.read_bytes();name='raw/'+p.relative_to(RAW).as_posix() if p.is_relative_to(RAW) else p.name
    row={'path':name,'mode':stat.S_IMODE(p.stat().st_mode),**ident(raw)}
    pool.setdefault(row['sha256'],raw);row['pool_member']='objects/'+row['sha256'];rows.append(row)
assert len({r['path'] for r in rows})==len(rows)
source_index=json.loads((RAW/'terminal-worktree/INDEX.json').read_text());source_rows=[];captured=[];dependencies=[]
for r in source_index['files']:
    assert r['kind']=='regular' and r['mode']==0o644
    row={'path':r['path'],'mode':'100644','git_blob':r['blob'],'bytes':r['bytes'],'sha256':r['sha256']};source_rows.append(row)
    c=r['content_custody']
    if c.get('kind')=='exact_fixed_original_git_blob':
        assert c['blob']==r['blob'];dependencies.append(r['path'])
    else:
        assert c['file']=='terminal-worktree-bytes/'+r['blob']+'.blob'
        raw=(RAW/c['file']).read_bytes();pin(raw,row);captured.append(r['path'])
assert len(source_rows)==2989 and len(captured)==303
computed=tree(source_rows);assert computed=='605f1aee77964e2d42690aff5f88be654e635394'
original=json.loads((RAW/'LOCAL-RESULT.json').read_text())
assert original['status']=='LOCAL_GENERATION_PASS' and original['product_tests_executed']==0 and original['native_qualification'] is False
assert original['generation']['tree']==computed
source_evidence={'scope':'Terminal index tree and all303 supplied byte records independently verified; fixed-original source dependencies remain explicitly external.',
   'files':len(source_rows),'computed_git_tree':computed,'captured_byte_records':len(captured),
   'fixed_original_dependency_files':len(dependencies),'fixed_original_dependency_commits':source_index['fixed_original_dependency_commits'],
   'self_contained_full_source_export':False,'original_source_dependency_assertion_preserved':True,
   'original_index':ident((RAW/'terminal-worktree/INDEX.json').read_bytes())}
manifest={'schema':'hia.root-local-r4.complete-originals-content-pool.v1','raw_original_files':1913,'raw_original_bytes':120634380,
   'logical_files':rows,'logical_count':len(rows),'logical_bytes':sum(r['bytes'] for r in rows),'directories':directories,
   'unique_pool_files':len(pool),'unique_pool_bytes':sum(len(x) for x in pool.values()),'source_dependency_verification':source_evidence,
   'original_result':original,'qualification_transferred':False,'custody_process_product_execution_count':0}
manifest_raw=enc(manifest);(OUT/'MANIFEST.json').write_bytes(manifest_raw)
archive_path=OUT/'ORIGINALS.tar.gz'
with archive_path.open('xb') as output,gzip.GzipFile(fileobj=output,mode='wb',compresslevel=1,mtime=0,filename='') as gz,tarfile.open(fileobj=gz,mode='w|') as tar:
    def add(name,data):
        item=tarfile.TarInfo(name);item.mode=0o600;item.size=len(data);item.mtime=0;tar.addfile(item,io.BytesIO(data))
    add('MANIFEST.json',manifest_raw)
    for digest,raw in sorted(pool.items()):add('objects/'+digest,raw)
with tarfile.open(archive_path,'r|gz') as tar:
    count=0
    for member in tar:
        raw=tar.extractfile(member).read();expected=manifest_raw if member.name=='MANIFEST.json' else pool[member.name.split('/',1)[1]]
        assert member.mode==0o600 and raw==expected;count+=1
    assert count==len(pool)+1
before={r['path']:r for r in rows}
for p in paths:
    name='raw/'+p.relative_to(RAW).as_posix() if p.is_relative_to(RAW) else p.name
    raw=p.read_bytes();pin(raw,before[name]);assert stat.S_IMODE(p.stat().st_mode)==before[name]['mode']
assert len([p for p in RAW.rglob('*') if p.is_file()])==1913
raw=archive_path.read_bytes();parts=[]
for index,at in enumerate(range(0,len(raw),384*1024)):
    data=raw[at:at+384*1024];name=f'part-{index:04d}.bin.json'
    wrapped={'schema':'hia.utf8-binary-custody.v1','index':index,'offset':at,**ident(data),'encoding':'base64','payload':base64.b64encode(data).decode()}
    body=enc(wrapped);(OUT/name).write_bytes(body);assert base64.b64decode(json.loads(body)['payload'])==data
    parts.append({'path':name,'index':index,**ident(body)})
wrapped={'schema':'hia.zlib-source-capsule.v1',**ident(manifest_raw),'encoding':'zlib+base64','payload':base64.b64encode(zlib.compress(manifest_raw,9)).decode()}
body=enc(wrapped);(OUT/'MANIFEST.zlib.json').write_bytes(body);assert zlib.decompress(base64.b64decode(json.loads(body)['payload']))==manifest_raw
transport={'schema':'hia.root-local-r4.complete-originals-transport.v1','archive':ident(raw),'manifest':ident(manifest_raw),'manifest_capsule':ident(body),'parts':parts,
   'raw_original_files':1913,'raw_original_bytes':120634380,'additional_files':['LOCAL-CONTROLLER-R4.log','freeze.py'],
   'logical_files':len(rows),'unique_pool_files':len(pool),'source_dependencies':source_evidence,
   'all_archive_members_full_readback':True,'all_original_files_rechecked_after_archive':True,'custody_product_execution_count':0,
   'original_status':'LOCAL_GENERATION_PASS','original_python':'3.12.14','original_native_qualification':False}
(OUT/'TRANSPORT.json').write_bytes(enc(transport))
print(json.dumps({k:v for k,v in transport.items() if k not in ('parts','source_dependencies')},indent=2));print('parts',len(parts))
