from pathlib import Path
import ast,base64,hashlib,json,os,stat,zlib,time
ROOT=Path('/tmp/hia-progress-v150-20261114-dda7')
GET=ROOT/'root-metadata-actual-get'
OUT=Path('/workspace/hia-v150-root-metadata-custody-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def encode(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def seven(s):return [getattr(s,k) for k in FIELDS]
def read(p):
    for a in reversed(p.parents):assert stat.S_ISDIR(a.lstat().st_mode),a
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1,p
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        assert seven(os.fstat(fd))==seven(s)
        chunks=[];left=s.st_size+1
        while left:
            b=os.read(fd,min(left,1048576))
            if not b:break
            chunks.append(b);left-=len(b)
        raw=b''.join(chunks)
        assert len(raw)==s.st_size and seven(os.fstat(fd))==seven(s)==seven(p.lstat())
    finally:os.close(fd)
    return raw,stat.S_IMODE(s.st_mode),seven(s)
def main():
    start=time.monotonic_ns()
    provenance=json.loads(read(GET/'ACTUAL-GET-PROVENANCE.json')[0])
    for row in provenance['leaves']:
        assert pin(read(GET/row['path'])[0])==row['identity'] and row['full_actual_GET_equal']
    index_raw=read(GET/'INDEX.json')[0];index=json.loads(index_raw)
    packed=[];offset=0
    for i,row in enumerate(index['parts']):
        part_raw=read(GET/row['path'])[0];assert pin(part_raw)==row['identity']
        part=json.loads(part_raw);b=base64.b64decode(part['base64'],validate=True)
        assert part['index']==i and part['offset']==offset and len(b)==part['bytes']
        assert hashlib.sha256(b).hexdigest()==part['sha256'];packed.append(b);offset+=len(b)
    packed=b''.join(packed);assert pin(packed)==index['zlib']
    d=zlib.decompressobj();raw=d.decompress(packed,index['capsule']['bytes']+1)+d.flush()
    assert d.eof and not d.unused_data and not d.unconsumed_tail and pin(raw)==index['capsule']
    capsule=json.loads(raw)
    assert capsule['scopes']==index['scopes']
    rows=[{k:v for k,v in row.items() if k!='base64'} for row in capsule['files']]
    assert rows==index['files'] and len(rows)==index['logical_files']==63
    total=0;observed=set()
    for row in capsule['files']:
        assert row['logical'] not in observed;observed.add(row['logical'])
        decoded=base64.b64decode(row['base64'],validate=True)
        assert pin(decoded)==row['identity']
        original,mode,stamp=read(Path(row['path']))
        assert original==decoded and mode==row['mode'] and stamp==row['seven_stats']
        total+=len(decoded)
    assert total==index['logical_bytes']==9601875
    for scope in index['scopes']:
        selected={scope['label']+'/'+n for n in scope['selected_paths']}
        assert selected=={p for p in observed if p.startswith(scope['label']+'/')}
        if scope['label'] in ('patch-generation-independent-terminal','patch-generation-admission'):
            assert sorted(p.name for p in Path(scope['root']).iterdir())==scope['selected_paths']
    result={'schema':'hia.root.v150.metadata.complete-actual-GET-decode.v1','status':'PASS_COMPLETE_ACTUAL_GET_DECODE','logical_files':63,'logical_bytes':total,'parts':len(index['parts']),'index':pin(index_raw),'capsule':pin(raw),'zlib':pin(packed),'actual_GET_transport_leaves':len(provenance['leaves']),'all_original_bytes_mode_seven_stats_equal':True,'complete_selected_pathsets_equal':True,'zlib_full_eof_no_trailing':True,'original_archived_failures_unchanged':True,'new_product_executions':0,'whole_native':False,'elapsed_ns':time.monotonic_ns()-start}
    out=OUT/'FULL-ACTUAL-GET-READBACK.json'
    with out.open('xb') as f:f.write(encode(result))
    assert json.loads(read(out)[0])==result
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
