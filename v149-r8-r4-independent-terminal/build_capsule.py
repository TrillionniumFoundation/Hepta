#!/usr/bin/env python3
"""Preserve every actual R4 terminal-readback byte; no project imports or execution."""
import base64, hashlib, json, os, re, stat, time, zlib
from pathlib import Path
OUT=Path('/tmp/hia-r8-r4-terminal-readback-custody-r1-dda7')
SOURCE=Path('/tmp/hia-u32-r8-r4-terminal-readback-r1-dda7')
ROOT=Path('/tmp/hia-progress-v148-20261114-dda7')
NAMES=('DIRECTORIES-BEFORE.json','FULL-RAW-INVENTORY.json','INPUT-READBACK.json','INTENT.json','READ-LEDGER.jsonl','RESULT.json')
TOOLS=('R4-TERMINAL-READER-EXEC.json','R4-TERMINAL-READER-RETURN.json')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def dump(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def seven(s):return [getattr(s,k) for k in FIELDS]
def capture(p):
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1,str(p)
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        assert seven(os.fstat(fd))==seven(s),str(p)
        chunks=[];left=s.st_size+1
        while left:
            b=os.read(fd,min(left,1048576))
            if not b:break
            chunks.append(b);left-=len(b)
        raw=b''.join(chunks)
        assert len(raw)==s.st_size and seven(os.fstat(fd))==seven(s)==seven(p.lstat()),str(p)
    finally:os.close(fd)
    return raw,{'path':str(p),'identity':pin(raw),'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)}
def new(p,b):
    with p.open('xb') as f:f.write(b)
    os.chmod(p,0o644)
def inventory(root):
    files=[];dirs=[]
    for here,sub,names in os.walk(root,followlinks=False):
        here=Path(here);s=here.lstat();assert stat.S_ISDIR(s.st_mode)
        dirs.append({'relative_path':here.relative_to(root).as_posix(),'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)})
        for n in sub:assert stat.S_ISDIR((here/n).lstat().st_mode)
        for n in names:
            p=here/n;assert stat.S_ISREG(p.lstat().st_mode);files.append(p)
    return sorted(files),sorted(dirs,key=lambda x:x['relative_path'])
def main():
    started=time.time_ns(); files,dirs=inventory(SOURCE)
    assert [p.name for p in files]==sorted(NAMES) and len(dirs)==1,'readback pathset'
    selected=[('readback/'+n,SOURCE/n) for n in NAMES]+[('root-tools/'+n,ROOT/n) for n in TOOLS]
    rows=[];originals={};inodes=set()
    patterns=[rb'(?i)https?://[^\s\"\x27]+[?&](?:sig|token|x-amz-signature)=',rb'(?i)\"(?:authorization|set-cookie)\"\s*:\s*\"[^\"]+\"',rb'(?im)^Authorization:\s*\S+',rb'(?im)^Set-Cookie:\s*\S+']
    for logical,p in selected:
        b,d=capture(p);assert not any(re.search(q,b) for q in patterns),logical
        ino=tuple(d['seven_stats'][:2]);assert ino not in inodes;inodes.add(ino)
        originals[logical]=b;rows.append({'logical_path':logical,**d,'content_base64':base64.b64encode(b).decode('ascii')})
    assert len(rows)==8 and sum(r['identity']['bytes'] for r in rows)==9512551
    result=json.loads(originals['readback/RESULT.json'])
    assert pin(originals['readback/RESULT.json'])['git_blob']=='4b8c87f5f98161f0dc92530a9ee73947ab0633ba'
    assert result['status']=='PASS_READBACK_OF_ACTUAL_R4_VM_FUEL_FAILURE' and result['qualification']=='FAIL'
    assert result['actual_new_Native_calls']==163 and result['actual_VM_calls']==6 and result['VM_FAIL']==1
    meta=[{k:v for k,v in r.items() if k!='content_base64'} for r in rows]
    intent={'schema':'hepta.r8.r4.terminal-readback-custody-intent.v1','files':meta,'directories':dirs,'source':str(SOURCE),'product_executions':0,'CI':0,'refs':0}
    new(OUT/'INTENT.json',dump(intent))
    capsule={'schema':'hepta.lossless.files.base64.v1','scope':'All six actual independent R4 terminal-readback outputs plus both original Root tool returns; original product fuel failure retained.','files':rows,'source':str(SOURCE),'directories':dirs}
    raw=dump(capsule);packed=zlib.compress(raw,9);dec=zlib.decompressobj();recovered=dec.decompress(packed)+dec.flush()
    assert recovered==raw and dec.eof and not dec.unused_data and not dec.unconsumed_tail
    for r in json.loads(recovered)['files']:
        b=base64.b64decode(r['content_base64'],validate=True);fresh,d=capture(Path(r['path']))
        assert pin(b)==r['identity'] and b==fresh and d['mode']==r['mode'] and d['seven_stats']==r['seven_stats']
    files2,dirs2=inventory(SOURCE);assert files2==files and dirs2==dirs
    (OUT/'parts').mkdir();parts=[]
    for i,off in enumerate(range(0,len(packed),384000)):
        piece=packed[off:off+384000];name='parts/%03d.json'%i
        b=dump({'schema':'hepta.zlib.lossless-capsule-part.v1','index':i,'offset':off,'decoded_part':pin(piece),'complete_archive':pin(packed),'base64':base64.b64encode(piece).decode('ascii')})
        new(OUT/name,b);parts.append({'path':name,'mode':0o644,'identity':pin(b),'decoded_part':pin(piece),'offset':off})
    index={'schema':'hepta.r8.r4.terminal-readback-custody-index.v1','files':meta,'source':str(SOURCE),'directories':dirs,'logical_files':8,'logical_bytes':9512551,'capsule_json':pin(raw),'compressed_zlib':pin(packed),'parts':parts}
    new(OUT/'INDEX.json',dump(index))
    report={'schema':'hepta.r8.r4.terminal-readback-custody.v1','status':'PASS_COMPLETE_CUSTODY_OF_ROOT_ACTUAL_TERMINAL_READBACK','logical_files':8,'logical_bytes':9512551,'parts':len(parts),'compressed_bytes':len(packed),'elapsed_ns':time.time_ns()-started,'all_original_full_bytes_modes_seven_stats_preserved':True,'complete_readback_directory_preserved':True,'Root_reader_session':76134,'Root_reader_exit_code':0,'Root_result':pin(originals['readback/RESULT.json']),'original_qualification':'FAIL','product_executions':0,'CI':0,'refs':0,'credential_carriers_included':0,'main_raw_custody_recipe':'0d3a729ab1c653b1ab054d94061515942ccf0419','reader_author_capsule':'802313dba0b8f90b34f0674154551a0de6e1d8ad','Git_transport':'PENDING_SEPARATE_PUBLICATION'}
    new(OUT/'REPORT.json',dump(report))
    for name,b in [('ROOT-RESULT.json',originals['readback/RESULT.json'])]+[(n,originals['root-tools/'+n]) for n in TOOLS]:new(OUT/name,b)
    pub=[]
    for n in ['INTENT.json','INDEX.json','REPORT.json','ROOT-RESULT.json',*TOOLS,'build_capsule.py']+[p['path'] for p in parts]:
        b,d=capture(OUT/n);pub.append({'path':n,'mode':0o644,'identity':{**pin(b),'mode':0o644}})
    new(OUT/'PUBLICATION-INPUTS.json',dump({'files':pub}))
    print(json.dumps({'status':report['status'],'files':8,'bytes':9512551,'compressed_bytes':len(packed),'parts':len(parts),'report':pin((OUT/'REPORT.json').read_bytes())},sort_keys=True))
if __name__=='__main__':main()
