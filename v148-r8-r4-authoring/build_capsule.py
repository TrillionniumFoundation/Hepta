#!/usr/bin/env python3
"""Freeze the complete R4 author tree without importing any project module."""
import base64, hashlib, json, os, re, stat, time, zlib
from pathlib import Path
OUT=Path('/tmp/hia-r8-r4-author-custody-r1-dda7')
AUTHOR=Path('/tmp/hia-u32-r8-post-reset-r4-dda7')
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
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(0o644)
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
    started=time.time_ns();paths,dirs=inventory(AUTHOR);assert len(paths)==86
    rows=[];inodes=set()
    patterns=[rb'(?i)https?://[^\s\"\x27]+[?&](?:sig|token|x-amz-signature)=',rb'(?i)\"(?:authorization|set-cookie)\"\s*:\s*\"[^\"]+\"',rb'(?im)^Authorization:\s*\S+',rb'(?im)^Set-Cookie:\s*\S+']
    for p in paths:
        b,d=capture(p);assert not any(re.search(q,b) for q in patterns),str(p)
        ino=tuple(d['seven_stats'][:2]);assert ino not in inodes;inodes.add(ino)
        rows.append({'logical_path':p.relative_to(AUTHOR).as_posix(),**d,'content_base64':base64.b64encode(b).decode('ascii')})
    assert sum(r['identity']['bytes'] for r in rows)==6720709
    capsule={'schema':'hepta.lossless.author-files.base64.v1','scope':'Complete isolated R4 author tree including all original 64 authority files, six exact preimages, original launch preimage, all diffs and current review/provenance. No input/source/runtime payload.','directory_sets':[{'path':str(AUTHOR),'directories':dirs,'relative_pathset':[p.relative_to(AUTHOR).as_posix() for p in paths]}],'files':rows}
    raw=dump(capsule);packed=zlib.compress(raw,9);dec=zlib.decompressobj();decoded=dec.decompress(packed)+dec.flush()
    assert decoded==raw and dec.eof and not dec.unused_data and not dec.unconsumed_tail
    for row in json.loads(decoded)['files']:
        b=base64.b64decode(row['content_base64'],validate=True);fresh,d=capture(Path(row['path']))
        assert pin(b)==row['identity'] and b==fresh and d['mode']==row['mode'] and d['seven_stats']==row['seven_stats']
    assert inventory(AUTHOR)==(paths,dirs)
    parts=[]
    for i,off in enumerate(range(0,len(packed),384000)):
        piece=packed[off:off+384000];name='parts/%03d.json'%i
        b=dump({'schema':'hepta.zlib.author-capsule-part.v1','index':i,'offset':off,'decoded_part':pin(piece),'complete_archive':pin(packed),'base64':base64.b64encode(piece).decode('ascii')})
        new(OUT/name,b);parts.append({'path':name,'mode':420,'identity':pin(b),'decoded_part':pin(piece),'offset':off})
    index={'schema':'hepta.r8.r4.complete-author-index.v1','files':[{k:v for k,v in row.items() if k!='content_base64'} for row in rows],'directory_sets':capsule['directory_sets'],'logical_files':86,'logical_bytes':6720709,'capsule_json':pin(raw),'compressed_zlib':pin(packed),'parts':parts}
    new(OUT/'INDEX.json',dump(index))
    report={'schema':'hepta.r8.r4.complete-author-custody.v1','status':'PASS_COMPLETE_AUTHOR_BYTES_ONLY','elapsed_ns':time.time_ns()-started,'logical_files':86,'logical_bytes':6720709,'compressed_bytes':len(packed),'parts':len(parts),'all_bytes_modes_current_seven_stats_exact':True,'all_single_link_distinct_inodes':True,'credentials_observed_or_included':0,'author_control_files':64,'byte_exact_prior_controls':58,'changed_controls':6,'seven_phase_scripts_entirely_unchanged':True,'ORACLE_PLAN_entirely_unchanged':True,'R3_failure_custody_recipe':'234c072875fa88e49ef7db376675f733f4de7a5d','products':0,'binder':0,'CI':0,'refs':0,'future_fresh_reuse_admission_required':True,'current_cold':False,'whole_native':False}
    new(OUT/'REPORT.json',dump(report))
    direct=['HANDOFF-R4.json','CONTRACT-R4.md','STATIC-REVIEW.json','EXECUTION-PLAN.json','PRODUCT-LAUNCH.json','EXACT-INVERSE.json','REUSE-REQUIREMENTS.json','FROZEN-CONTROLS.json']
    pub=[]
    for name in direct:
        b,d=capture(AUTHOR/name);new(OUT/name,b);pub.append({'path':name,'mode':420,'identity':{**pin(b),'mode':420}})
    for name in ['INDEX.json','REPORT.json','build_capsule.py']+[p['path'] for p in parts]:
        b,d=capture(OUT/name);pub.append({'path':name,'mode':420,'identity':{**pin(b),'mode':420}})
    new(OUT/'PUBLICATION-INPUTS.json',dump({'files':pub}))
    print(json.dumps({'status':report['status'],'files':86,'bytes':6720709,'compressed_bytes':len(packed),'parts':len(parts),'leaves_before_Git_verifier':len(pub),'report':pin(dump(report))},sort_keys=True))
if __name__=='__main__':main()
