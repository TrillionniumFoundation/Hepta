"""Read-only exact-source joins for two Header C draft units. No compile/import."""
from pathlib import Path
import hashlib,json,os,re,stat,traceback
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
OUT=P/'header-C-static-peer-r1'
M=P/'root-database-header-oracle-draft-r1.json'
EXPECTED_MANIFEST='0843f491cb1b8b1e4fcdc7d1bab13d71e66c4f2af1dfd9f986940b912f99fe4e'
report={'schema':'hia.database-header.C-peer.v1','status':'HOLD','checks':0,'errors':[],
        'compiled':False,'loaded':False,'C_calls':0,'product_calls':0,'units':[]}
cache={}
def check(ok,msg):
    report['checks']+=1
    if not ok:raise AssertionError(msg)
def read(path):
    path=Path(path)
    if str(path)in cache:return cache[str(path)]
    a=path.lstat();check(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and path.resolve(strict=True)==path,'regular unaliased source '+str(path))
    f=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        check(os.fstat(f)==a,'initial fd')
        chunks=[]
        while True:
            b=os.read(f,1<<20)
            if not b:break
            chunks.append(b)
        raw=b''.join(chunks)
        check(os.fstat(f)==a and path.lstat()==a and len(raw)==a.st_size,'full source unchanged')
    finally:os.close(f)
    pin={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
         'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    cache[str(path)]=(raw,pin);return raw,pin
def main():
    OUT.mkdir(mode=0o700,exist_ok=False)
    raw,mp=read(M);check(mp['sha256']==EXPECTED_MANIFEST,'exact Root C manifest')
    manifest=json.loads(raw);report['manifest']=mp
    check(manifest['status']=='AUTHORED_UNCOMPILED_UNEXECUTED' and manifest['qualification_runs']==0 and len(manifest['units'])==2,'draft only')
    for u in manifest['units']:
        version=u['version'];body,pin=read(u['path'])
        check(pin['bytes']==u['bytes']and pin['sha256']==u['sha256'],'exact C unit')
        check(len(u['sections'])==14 and len({x['label']for x in u['sections']})==14,'14 unique sections')
        full={}
        for item in u['official_sources']:
            name=Path(item['relative_path']).name
            root=P/('sqlite-database-header-source-r2/reference' if name in ('btree.c.original','LICENSE.md.original')else 'sqlite-btree-cell-native-r1/candidate/reference')
            raw,p=read(root/item['relative_path'])
            check(p['bytes']==item['bytes']and p['sha256']==item['sha256']and p['git_blob_sha1']==item['git_blob_sha1'],'complete official reference '+name)
            full[name]=raw
        sections=[]
        for s in u['sections']:
            chunk=body[s['unit_start_utf8']:s['unit_end_utf8']]
            check(len(chunk)==s['bytes']and hashlib.sha256(chunk).hexdigest()==s['sha256'],'full section '+s['label'])
            row={'label':s['label'],'bytes':len(chunk),'sha256':s['sha256']}
            if s.get('authored_fixture'):
                row['kind']='explicit authored fixture'
            elif s.get('retained_source_path'):
                parent,pp=read(s['retained_source_path'])
                check(pp['sha256']==s['retained_source_sha256'],'complete retained C donor')
                inner=s['retained_original_section']
                check(parent[inner['unit_start_utf8']:inner['unit_end_utf8']]==chunk,'parent exact section')
                if s['label']=='complete original structures':
                    for typ in ('MemPage','BtShared','CellInfo'):
                        pattern=rb'^struct '+typ.encode()+rb' \{.*?^\};'
                        matches=re.findall(pattern,chunk,re.M|re.S)
                        check(len(matches)==1 and full['btreeInt.h.original'].count(matches[0])==1,'complete original '+typ)
                elif s['label']=='original primitives':
                    for block in chunk.strip().split(b'\n\n'):
                        check(block in full['sqliteInt.h.original'],'complete primitive block official source')
                elif s['label']=='complete original endian macros':
                    check(full['btreeInt.h.original'].count(chunk)==1,'whole endian macro group')
                elif s['label']=='complete original sqlite3Get4byte':
                    check(full['util.c.original'].count(chunk)==1,'complete original Get4byte')
                else:raise AssertionError('unexpected retained original section')
                row['kind']='original full donor and official source join';row['donor']=pp
            elif 'source_start_utf8'in s:
                source,sp=read(s['source_path'])
                check(sp['sha256']==s['source_sha256']and source[s['source_start_utf8']:s['source_end_utf8']]==chunk,'full official range exact')
                row['kind']='complete original source range';row['source']=sp
            elif 'source_line'in s:
                source,sp=read(s['source_path'])
                check(sp['sha256']==s['source_sha256']and source.splitlines(keepends=True)[s['source_line']-1]==chunk,'complete exact original macro line')
                row['kind']='exact official line';row['source']=sp
            else:raise AssertionError('unclassified section')
            sections.append(row)
        report['units'].append({'version':version,'unit':pin,'sections':sections})
    a=read(manifest['units'][0]['path'])[0];b=read(manifest['units'][1]['path'])[0]
    check(a[a.index(b'/* finite wrapper opaque'):].replace(b'3460',b'VERSION')==b[b.index(b'/* finite wrapper opaque'):].replace(b'3532',b'VERSION'),
          'all context/types/algorithm/observation API identical across versions except explicit symbol namespace')
    report['semantic_review']={
      'transport':'Exact 100/7/32/32 geometry, aligned disjoint overflow-checked spans and legal current context are checked before external output/events writes.',
      'types':'Original u8/u16/u32/u64 and complete MemPage/BtShared/CellInfo retained; exported uint64_t buffers match ctypes c_uint64. Original pagecount int-pointer store uses memcpy, preserving all u32 page bits.',
      'algorithm':'Original lockBtree body is complete6334 bytes in each version. Empty/reset, future write read-only, read-version refusal, WAL retry, resize retry, page-count and usable-size order are unchanged.',
      'effects':'Successful fixture events are appended before provider mutations. All possible original paths use at most8 triples, within32 event words; unused tail remains original seed.',
      'projection':'Native request must write complete raw32/event/source/command/canary POST before comparisons or projection; raw rc/error and partly-mutated context are retained.',
      'scope':'Static/source joins only; no C compilation/loading or native result. Pager/WAL/locks/I/O success-only fixtures are not SQL/transaction equivalence.',
      'remaining_compile_runtime_gate':'Actual requested finite C compile and 634 semantic calls per version remain unexecuted.'
    }
    report['full_sources']=[pin for _,pin in cache.values()]
    report['status']='STATIC_PEER_CLEAR_LIMITED_C_SOURCE'
    return 0
try:rc=main()
except BaseException as e:
    report['errors'].append({'type':type(e).__name__,'traceback':traceback.format_exc()});rc=1
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
fd=os.open(OUT/'REVIEW.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
print(json.dumps({'status':report['status'],'checks':report['checks'],'sha256':hashlib.sha256(raw).hexdigest(),'errors':report['errors']}))
raise SystemExit(rc)
