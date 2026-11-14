"""Streaming original-byte custody only; no project import or product execution."""
from pathlib import Path
import argparse,base64,gzip,hashlib,json,os,stat,time,traceback,zlib
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def seven(s):return {k:getattr(s,k) for k in FIELDS}
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def read(p):
    p=Path(p)
    for parent in reversed(p.parents):assert stat.S_ISDIR(parent.lstat().st_mode),str(parent)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);st=seven(s);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and st==seven(p.lstat())
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(s.st_size+1)
        assert len(b)==s.st_size and st==seven(os.fstat(fd))==seven(p.lstat())
    finally:os.close(fd)
    return b,st
def state(root):
    root=Path(root);out={'.':seven(root.lstat())};assert stat.S_ISDIR(out['.']['st_mode'])
    def visit(p,prefix):
        for e in sorted(os.scandir(p),key=lambda e:e.name):
            s=e.stat(follow_symlinks=False);name=prefix+e.name;out[name]=seven(s)
            assert stat.S_ISDIR(s.st_mode) or (stat.S_ISREG(s.st_mode) and s.st_nlink==1)
            if stat.S_ISDIR(s.st_mode):visit(Path(e.path),name+'/')
    visit(root,'');return out
def encode(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def line(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def put(root,name,b):
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(0o644);assert read(p)[0]==b
    return pin(b)
def archive_pin(path):
    s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0');n=0
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):sha.update(b);git.update(b);n+=len(b)
    assert n==s.st_size and seven(s)==seven(path.lstat())
    return {'bytes':n,'sha256':sha.hexdigest(),'git_blob':git.hexdigest()}
def strict_gzip(path):
    decoder=zlib.decompressobj(31);n=0;sha=hashlib.sha256()
    with path.open('rb') as f:
        for piece in iter(lambda:f.read(1048576),b''):
            while piece:
                b=decoder.decompress(piece,1048576);n+=len(b);sha.update(b)
                assert not decoder.unused_data
                piece=decoder.unconsumed_tail
    b=decoder.flush();n+=len(b);sha.update(b)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    return {'bytes':n,'sha256':sha.hexdigest(),'single_member_exact_end':True,'full_CRC':True}
def decode_compare(archive,index):
    crc=strict_gzip(archive);assert {k:crc[k] for k in ('bytes','sha256')}=={k:index['capsule'][k] for k in ('bytes','sha256')}
    git=hashlib.sha1(b'blob '+str(index['capsule']['bytes']).encode()+b'\0');sha=hashlib.sha256();n=0;observed=[];seen=set()
    with gzip.open(archive,'rb') as f:
        raw=f.readline(index['max_line_bytes']+1);assert raw.endswith(b'\n') and len(raw)<=index['max_line_bytes'];git.update(raw);sha.update(raw);n+=len(raw)
        header=json.loads(raw);assert header==index['header']
        for expected in index['originals']:
            raw=f.readline(index['max_line_bytes']+1);assert raw.endswith(b'\n') and len(raw)<=index['max_line_bytes'];git.update(raw);sha.update(raw);n+=len(raw)
            record=json.loads(raw);assert record['kind']=='file';row=record['row']
            assert {k:v for k,v in row.items() if k!='base64'}==expected and row['logical'] not in seen;seen.add(row['logical'])
            b,s=read(row['path']);wanted=base64.b64decode(row['base64'],validate=True)
            assert b==wanted and pin(b)==row['identity'] and s==row['seven_stat'] and stat.S_IMODE(s['st_mode'])==row['mode']
            observed.append({k:v for k,v in row.items() if k!='base64'})
        raw=f.readline(index['max_line_bytes']+1);assert raw.endswith(b'\n') and len(raw)<=index['max_line_bytes'];git.update(raw);sha.update(raw);n+=len(raw)
        assert json.loads(raw)=={'kind':'end','files':index['logical_files'],'logical_bytes':index['logical_bytes']}
        assert f.read(1)==b''
    assert {'bytes':n,'sha256':sha.hexdigest(),'git_blob':git.hexdigest()}==index['capsule']
    for name,path in header['scopes'].items():assert state(Path(path))==header['scope_states'][name]
    for row in observed:assert seven(Path(row['path']).lstat())==row['seven_stat']
    return {'status':'PASS_ALL_ORIGINAL_BYTES_MODES_SEVEN_STATS_AND_PATHSETS','files':len(observed),'logical_bytes':index['logical_bytes'],'archive':archive_pin(archive),'capsule':index['capsule'],'complete_gzip_crc':True,'single_member_exact_end':True,'all_files_freshly_reread':True,'products':0}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',required=True);p.add_argument('--plan-sha256',required=True);args=p.parse_args()
    plan_raw,plan_stat=read(args.plan);assert pin(plan_raw)['sha256']==args.plan_sha256;plan=json.loads(plan_raw)
    dest=Path(plan['output']);assert not os.path.lexists(dest);dest.mkdir(mode=0o700);start=time.monotonic_ns()
    put(dest,'INPUT-PLAN.json',plan_raw);put(dest,'INTENT.json',encode({'plan':pin(plan_raw),'plan_seven_stat':plan_stat,'products':0,'source_inputs_unchanged':True}))
    result={'schema':'hia.R10.actual.streaming-custody-result.v1','status':'FAIL','products':0}
    try:
        scopes={n:Path(s) for n,s in plan['scopes'].items()};states={n:state(s) for n,s in scopes.items()};entries=[]
        for label,root in scopes.items():
            files=[(n,s) for n,s in states[label].items() if stat.S_ISREG(s['st_mode'])]
            assert len(files)==plan['expected_scope_files'][label]
            entries.extend((label+'/'+n,root/n,s) for n,s in files)
        for name,row in plan['selected'].items():entries.append((name,Path(row['path']),row['seven_stat']))
        assert len({n for n,_,_ in entries})==len(entries) and len({str(p) for _,p,_ in entries})==len(entries)
        header={'schema':'hia.R10.actual.lossless-jsonlines.v1','kind':'header','scope':plan['scope'],'scopes':plan['scopes'],'scope_states':states,'qualification_boundary':plan['qualification_boundary'],'historical_inodes_not_recreated':True}
        originals=[];n=0;sha=hashlib.sha256();max_line=0;archive=dest/'ACTUAL-CAPSULE.jsonl.gz'
        with archive.open('xb') as sink,gzip.GzipFile(filename='',mode='wb',fileobj=sink,compresslevel=1,mtime=0) as gz:
            def emit(value):
                nonlocal n,max_line
                raw=line(value);gz.write(raw);n+=len(raw);sha.update(raw);max_line=max(max_line,len(raw))
            emit(header)
            for name,path,expected in entries:
                b,s=read(path);assert s==expected
                row={'logical':name,'path':str(path),'identity':pin(b),'mode':stat.S_IMODE(s['st_mode']),'seven_stat':s}
                if name in plan['selected']:assert row['identity']==plan['selected'][name]['identity']
                originals.append(row);emit({'kind':'file','row':dict(row,base64=base64.b64encode(b).decode())})
            for name,path in scopes.items():assert state(path)==states[name]
            total=sum(r['identity']['bytes'] for r in originals);emit({'kind':'end','files':len(originals),'logical_bytes':total})
        archive.chmod(0o644);ap=archive_pin(archive)
        # Complete bounded stream pass gives the Git header-dependent decoded identity.
        git=hashlib.sha1(b'blob '+str(n).encode()+b'\0');decoded_sha=hashlib.sha256();decoded_n=0
        with gzip.open(archive,'rb') as f:
            for b in iter(lambda:f.read(1048576),b''):git.update(b);decoded_sha.update(b);decoded_n+=len(b)
        assert decoded_n==n and decoded_sha.hexdigest()==sha.hexdigest()
        capsule={'bytes':n,'sha256':sha.hexdigest(),'git_blob':git.hexdigest()}
        index={'schema':'hia.R10.actual.streaming-custody-index.v1','archive':ap,'capsule':capsule,'header':header,'originals':originals,'logical_files':len(originals),'logical_bytes':total,'max_line_bytes':max_line,'parts':[],'products':0}
        proof=decode_compare(archive,index);proof['elapsed_ns']=time.monotonic_ns()-start
        offset=0
        with archive.open('rb') as f:
            for piece in iter(lambda:f.read(196608),b''):
                name='parts/%03d.json'%len(index['parts']);part={'schema':'hia.R10.actual.gzip-contiguous-part.v1','index':len(index['parts']),'offset':offset,'piece':pin(piece),'base64':base64.b64encode(piece).decode()}
                pp=put(dest,name,encode(part));index['parts'].append({'path':name,**pp});offset+=len(piece)
        assert offset==ap['bytes'] and archive_pin(archive)==ap and read(args.plan)==(plan_raw,plan_stat)
        put(dest,'ORIGINALS.json',encode(originals));put(dest,'INDEX.json',encode(index));put(dest,'LOCAL-ROUNDTRIP.json',encode(proof))
        result.update(status=proof['status'],files=len(originals),logical_bytes=total,archive=ap,capsule=capsule,parts=len(index['parts']),full_gzip_crc=True,all_current_bytes_modes_stats_pathsets_equal=True)
    except BaseException:result['error']=traceback.format_exc()
    finally:
        result['elapsed_ns']=time.monotonic_ns()-start;put(dest,'RESULT.json',encode(result));print(json.dumps(result,sort_keys=True))
    return 0 if result['status'].startswith('PASS_') else 1
if __name__=='__main__':raise SystemExit(main())
