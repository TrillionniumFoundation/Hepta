from pathlib import Path
import base64,hashlib,json,os,stat,zlib,time
ROOT=Path('/tmp/hia-progress-v151-20261114-dda7')
OUT=Path('/workspace/hia-v151-root-metadata-custody-r1-dda7')
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
def write(name,b):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    assert read(p)[0]==b
def main():
    start=time.monotonic_ns();assert not os.path.lexists(OUT);OUT.mkdir(mode=0o700)
    source=Path('/workspace/hia-cli-as-dict-inspect-qualification-r1-dda7/source18-attempt-r1')
    outer=Path('/workspace/hia-cli-as-dict-inspect-source-qualification-outer-r1-dda7')
    def selected(folder):
        paths=[]
        for p in sorted(folder.rglob('*')):
            st=p.lstat();assert stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode),p
            if stat.S_ISREG(st.st_mode):paths.append(str(p.relative_to(folder)))
        return paths
    assert len(selected(source))==33 and sum((source/n).lstat().st_size for n in selected(source))==357164
    assert len(selected(outer))==5
    scopes=[
        ('root',ROOT,None),
        ('inspect-source18-complete',source,selected(source)),
        ('inspect-source18-outer-complete',outer,selected(outer)),
        ('history',Path('/tmp/hia-progress-v150-20261114-dda7'),['V150-COMMIT-ACK.json','V150-COMMIT-FULL-GET.json','V150-REF-UPDATE-ACK.json','V150-REF-FULL-GET.json','PR-v150-BODY.md','PR-v150-UPDATE-ACK.json','PR-v150-VERIFIED.json','README-LINKS-R2.md','README-v150-PREFIX-LINKS-R2.md'])]
    selections=[];scope_rows=[]
    for label,folder,names in scopes:
        chosen=sorted(names if names is not None else [p.name for p in folder.iterdir() if p.is_file()])
        assert chosen and len(chosen)==len(set(chosen))
        if label in ('inspect-source18-complete','inspect-source18-outer-complete'):
            assert chosen==selected(folder)
        scope_rows.append({'label':label,'root':str(folder),'selected_paths':chosen,'selection':'complete immediate files at explicit snapshot' if names is None else 'explicit listed files'})
        selections.extend((label+'/'+n,folder/n) for n in chosen)
    files=[];logical_bytes=0
    for logical,path in selections:
        raw,mode,stamp=read(path);logical_bytes+=len(raw)
        files.append({'logical':logical,'path':str(path),'mode':mode,'seven_stats':stamp,'identity':pin(raw),'base64':base64.b64encode(raw).decode()})
    capsule={'schema':'hia.root.v151.full-metadata-capsule.v1','scope':'All explicitly selected completed Root metadata, code and original full terminal/admission outputs; no requalification','scopes':scope_rows,'files':files}
    raw=encode(capsule);packed=zlib.compress(raw,9);parts=[];size=196608
    for i,offset in enumerate(range(0,len(packed),size)):
        part=packed[offset:offset+size];name='parts/PART-'+str(i).zfill(3)+'.json'
        value={'schema':'hia.root.v151.metadata.zlib-part.v1','index':i,'offset':offset,'bytes':len(part),'sha256':hashlib.sha256(part).hexdigest(),'base64':base64.b64encode(part).decode()}
        b=encode(value);write(name,b);parts.append({'path':name,'identity':pin(b)})
    manifest={'schema':'hia.root.v151.metadata-custody-index.v1','status':'SEALED_ORIGINAL_BYTES_ONLY','logical_files':len(files),'logical_bytes':logical_bytes,'capsule':pin(raw),'zlib':pin(packed),'zlib_complete_decode_required':True,'scopes':scope_rows,'files':[{k:v for k,v in f.items() if k!='base64'} for f in files],'parts':parts,'product_executions':0,'whole_native':False}
    write('INDEX.json',encode(manifest))
    for logical,path in selections:
        row=next(f for f in files if f['logical']==logical)
        b,m,s=read(path);assert pin(b)==row['identity'] and m==row['mode'] and s==row['seven_stats']
    for scope in scope_rows:
        if scope['label'] in ('inspect-source18-complete','inspect-source18-outer-complete'):
            assert selected(Path(scope['root']))==scope['selected_paths']
    d=zlib.decompressobj();rebuilt=d.decompress(packed)+d.flush()
    assert d.eof and not d.unused_data and not d.unconsumed_tail and rebuilt==raw
    result={'schema':'hia.root.v151.metadata-local-seal.v1','status':'PASS_COMPLETE_LOCAL_SEAL','logical_files':len(files),'logical_bytes':logical_bytes,'parts':len(parts),'capsule':pin(raw),'zlib':pin(packed),'full_original_bytes_mode_seven_stats_before_after_equal':True,'complete_selected_pathsets_equal':True,'whole_zlib_eof':True,'elapsed_ns':time.monotonic_ns()-start,'products':0}
    write('LOCAL-SEAL.json',encode(result))
    leaves=[*parts,*[{'path':n,'identity':pin(read(OUT/n)[0])} for n in ('INDEX.json','LOCAL-SEAL.json')]]
    write('PUBLICATION-INPUTS.json',encode({'root':str(OUT),'leaves':leaves}))
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
