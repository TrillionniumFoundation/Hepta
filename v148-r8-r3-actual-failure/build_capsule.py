#!/usr/bin/env python3
"""Preserve all original R3 failure bytes. Never import or run project code."""
import base64, hashlib, json, os, re, stat, time, zlib
from pathlib import Path

OUT=Path('/tmp/hia-r8-r3-failure-custody-r1-dda7')
PRODUCT=Path('/dev/shm/hia-u32-r8-controls-r3-dda7')
OUTER=Path('/tmp/hia-r8-original-controls-r3-outer-dda7')
ROOT=Path('/tmp/hia-progress-v148-20261114-dda7')
AUTHOR=Path('/tmp/hia-u32-r8-post-reset-r3-dda7')
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
    started=time.time_ns();selected=[];directory_sets=[]
    for prefix,root in [('product',PRODUCT),('outer',OUTER),('root-readback-r2',ROOT/'r8-r3-failure-root-readback-r2')]:
        files,dirs=inventory(root)
        directory_sets.append({'prefix':prefix,'path':str(root),'directories':dirs,'relative_pathset':[p.relative_to(root).as_posix() for p in files]})
        selected.extend((prefix+'/'+p.relative_to(root).as_posix(),p) for p in files)
    assert len(selected)==40
    root_names=('read_r8_r3_failure.py','read_r8_r3_failure_r2.py','R8-R3-FAILURE-READER-R1-ERROR.json','root_io.py','launch_r8_products.py','launch_r8_products_r2.py','R8-PRODUCT-AUTHORIZATION.json','R8-PRODUCT-AUTHORIZATION-R2.json','R8-PRODUCT-LAUNCH-R1-FAILURE.json')
    selected.extend(('root-controls/'+n,ROOT/n) for n in root_names)
    author_names=('run_controls.py','r8_common.py','EXECUTION-PLAN.json','ORACLE-RESTORE-PLAN.json','PRODUCT-LAUNCH.json','r8_private_reference.py')
    selected.extend(('actual-author/'+n,AUTHOR/n) for n in author_names)
    assert len(selected)==len(set(x[0] for x in selected))==55
    rows=[];originals={};inodes=set()
    patterns=[rb'(?i)https?://[^\s\"\x27]+[?&](?:sig|token|x-amz-signature)=',rb'(?i)\"(?:authorization|set-cookie)\"\s*:\s*\"[^\"]+\"',rb'(?im)^Authorization:\s*\S+',rb'(?im)^Set-Cookie:\s*\S+']
    for logical,p in selected:
        b,d=capture(p);assert not any(re.search(q,b) for q in patterns),logical
        ino=tuple(d['seven_stats'][:2]);assert ino not in inodes;inodes.add(ino)
        originals[logical]=b;rows.append({'logical_path':logical,**d,'content_base64':base64.b64encode(b).decode('ascii')})
    raw_rows=[r for r in rows if r['logical_path'].startswith(('product/','outer/'))]
    prior=json.loads(originals['root-readback-r2/FULL-RAW-INVENTORY.json'])
    assert {r['logical_path'] for r in raw_rows}==set(prior)
    assert len(raw_rows)==38 and sum(r['identity']['bytes'] for r in raw_rows)==12303135
    for r in raw_rows:
        a=prior[r['logical_path']];assert r['identity']==a['identity'] and r['mode']==a['mode']
        assert r['seven_stats']==[a['current_stat'][k] for k in FIELDS]
    proof=json.loads(originals['root-readback-r2/RESULT.json'])
    assert proof['status']=='PASS_READBACK_OF_ACTUAL_R3_QUALIFICATION_FAILURE'
    assert pin(originals['root-readback-r2/RESULT.json'])['git_blob']=='3d0979baf08e441a34af63a1e4c9c027b4ccaacf'
    result=json.loads(originals['product/RESULT.json']);refusal=json.loads(originals['product/public-R5-refusal/REPORT.json'])
    wrapper=json.loads(originals['product/public-R5-refusal/WRAPPER-RESULT.json'])
    owner=json.loads(originals['product/public-R5-refusal/OWNER-RETURNED.json']);outer=json.loads(originals['outer/RESULT.json'])
    assert result['status']=='FAIL' and len(result['rows'])==1 and not result['rows'][0]['pass']
    assert result['not_started']==['native162','semantic-edge-vm','semantic-remaining-vm','kernel130','observer-build','pipeline7','tail2']
    assert refusal['status']=='EXPECTED_PUBLIC_R5_REFUSAL' and refusal['provider_calls']==0 and refusal['VM_execution_reached'] is False
    assert wrapper['original_returncode']==0 and len(wrapper['errors'])==1 and wrapper['errors'][0]['where']=='native_frames'
    assert owner['status']=='QUALIFICATION_FAILED' and owner['returncode']==owner['supervisor_returncode']==1
    assert owner['qualification_seconds']==180 and owner['cleanup_seconds']==3 and not owner['timed_out']
    assert owner['cleanup']['complete'] and owner['cleanup']['observed_echild']
    assert outer['returncode']==1 and outer['ECHILD'] and outer['process_group_absent'] and not outer['timeout']
    runner=originals['actual-author/run_controls.py']
    assert runner.count(b"('native_frames',lambda:S.validate_native_frames(out,name) if phase['standalone_native_calls'] else None)")==1
    assert runner.count(b"S.require(value==phase['standalone_native_calls'],'native complete-frame denominator differs')")==1
    capsule={'schema':'hepta.lossless.files.base64.v1','scope':'All original R3 failed first-group product/outer bytes, actual controls and both Root readback histories. No repeat execution.','directory_sets':directory_sets,'files':rows}
    raw=dump(capsule);packed=zlib.compress(raw,9);dec=zlib.decompressobj();recovered=dec.decompress(packed)+dec.flush()
    assert recovered==raw and dec.eof and not dec.unused_data and not dec.unconsumed_tail
    for r in json.loads(recovered)['files']:
        b=base64.b64decode(r['content_base64'],validate=True);fresh,d=capture(Path(r['path']))
        assert pin(b)==r['identity'] and b==fresh and d['mode']==r['mode'] and d['seven_stats']==r['seven_stats']
    for d in directory_sets:
        files,dirs=inventory(Path(d['path']));assert dirs==d['directories']
        assert [p.relative_to(d['path']).as_posix() for p in files]==d['relative_pathset']
    (OUT/'parts').mkdir();parts=[]
    for i,off in enumerate(range(0,len(packed),384000)):
        piece=packed[off:off+384000];name='parts/%03d.json'%i
        b=dump({'schema':'hepta.zlib.lossless-capsule-part.v1','index':i,'offset':off,'decoded_part':pin(piece),'complete_archive':pin(packed),'base64':base64.b64encode(piece).decode('ascii')})
        new(OUT/name,b);parts.append({'path':name,'mode':0o644,'identity':pin(b),'decoded_part':pin(piece),'offset':off})
    index={'schema':'hepta.r8.r3.failure.complete-custody-index.v1','files':[{k:v for k,v in r.items() if k!='content_base64'} for r in rows],'directory_sets':directory_sets,'logical_files':55,'logical_bytes':sum(r['identity']['bytes'] for r in rows),'actual_raw_files':38,'actual_raw_bytes':12303135,'capsule_json':pin(raw),'compressed_zlib':pin(packed),'parts':parts}
    new(OUT/'INDEX.json',dump(index))
    report={'schema':'hepta.r8.r3.failure.complete-custody.v1','status':'PASS_CUSTODY_OF_ACTUAL_R3_QUALIFICATION_FAILURE','created_unix_ns':time.time_ns(),'elapsed_ns':time.time_ns()-started,'logical_files':55,'logical_bytes':index['logical_bytes'],'compressed_bytes':len(packed),'parts':len(parts),'actual_raw_files':38,'actual_raw_bytes':12303135,'actual_raw_full_payloads_included':True,'original_product_result':result,'original_refusal':refusal,'original_wrapper_result':wrapper,'original_owner':owner,'original_outer':outer,'root_independent_readback':proof,'all_original_full_bytes_modes_seven_stats_preserved':True,'directory_pathsets_modes_seven_stats_preserved':True,'all_files_single_link_and_distinct_inode':True,'actual_control_groups_started':1,'qualified_control_groups':0,'provider_calls':0,'VM_calls':0,'Native162_cases':0,'remaining_seven_groups_started':0,'new_compile_calls':0,'copied_existing_images_are_not_new_executions':True,'first_root_launcher_author_failure_preserved':True,'first_root_reader_wrong_supervisor_exit_assumption_preserved':True,'R3_author_recipe_git':'36766cd7f37f741280990d5b0d58b5c0176c5155','independent_static_review_recipe_git':'aa8113e93d0c5b9579165ebb55478ee40bce3d03','prior_808_stage_recipe_git':'1d6b2979f1d3b1aea44886d3629986b48fbcd713','prior_136_stage_recipe_git':'2ca46d0cd9aac2fe6d444f4491aac9d7ace2b157','credential_carriers_included':0,'credential_scan_matched':0,'products_executed_by_custody':0,'binder_calls':0,'CI':0,'refs':0,'automatic_retry':False,'whole_native':False,'ordinary_compiler_admission':False,'new_current_cold':False,'public_R5_profile_qualification':False,'limit':'Custody success preserves the original qualification FAIL; no remaining group or public-profile qualification is inferred.','index':pin((OUT/'INDEX.json').read_bytes())}
    new(OUT/'REPORT.json',dump(report));pub=[]
    for n in ['INDEX.json','REPORT.json','build_capsule.py']+[p['path'] for p in parts]:
        b,d=capture(OUT/n);pub.append({'path':n,'mode':0o644,'identity':{**pin(b),'mode':0o644}})
    new(OUT/'PUBLICATION-INPUTS.json',dump({'files':pub}))
    print(json.dumps({'status':report['status'],'files':55,'bytes':index['logical_bytes'],'compressed_bytes':len(packed),'parts':len(parts),'report':pin((OUT/'REPORT.json').read_bytes())},sort_keys=True))
if __name__=='__main__':main()
