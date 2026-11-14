"""One exact original-oracle restore, separately authorized from all products.

The original archive and retired paths are read-only. All 2396 CAS objects
are streamed and checked, but only the 136 explicitly selected original
observations are written, to new independent files. No HIA program runs.
"""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import json
import os
import stat
import sys
import tarfile
import traceback
import r8_common as S

ROOT=Path(__file__).resolve().parent
PLAN=json.loads((ROOT/'ORACLE-RESTORE-PLAN.json').read_bytes())
DEST=Path(PLAN['destination'])
OWNER=Path(PLAN['destination']+'.owner')
CHUNK=1<<20


def digest_stream(stream, size, destinations=()):
    h=hashlib.sha256();g=hashlib.sha1(b'blob '+str(size).encode()+b'\0')
    used=0
    while used<size:
        part=stream.read(min(CHUNK,size-used))
        S.require(part and len(part)<=size-used,'truncated or oversized archive object')
        used+=len(part);h.update(part);g.update(part)
        for destination in destinations:destination.write(part)
    S.require(stream.read(1)==b'','archive object has a trailing byte')
    return {'bytes':used,'sha256':h.hexdigest(),'git_blob':g.hexdigest()}


def expected_archive_objects(manifest):
    objects={}
    for name,row in manifest['files'].items():
        p=PurePosixPath(name)
        S.require(p.as_posix()==name and not p.is_absolute() and all(x not in ('.','..','') for x in p.parts),
                  'invalid original logical path')
        identity={k:row[k] for k in ('bytes','sha256','git_blob')}
        previous=objects.setdefault(row['sha256'],identity)
        S.require(previous==identity,'conflicting original CAS alias')
    S.require(len(objects)==2396 and sum(x['bytes'] for x in objects.values())==1658896740,
              'original full CAS denominator differs')
    return objects


def free_requirement():
    fs=os.statvfs(DEST.parent);block=fs.f_frsize
    allocation=sum(((PLAN['required'][n]['identity']['bytes']+block-1)//block)*block
                   for n in PLAN['restore_order'])
    needed=allocation+PLAN['allocation_metadata_allowance_bytes']+PLAN['additional_reserved_bytes']
    free=fs.f_bavail*block
    product_parent=Path(PLAN['product_storage_parent'])
    S.require(product_parent==Path(S.PLAN['output']).parent,'fixed product filesystem differs')
    product_fs=os.statvfs(product_parent)
    product_free=product_fs.f_bavail*product_fs.f_frsize
    product_needed=PLAN['future_product_free_floor_bytes']+PLAN['additional_product_reserved_bytes']
    S.require(free>=needed,'insufficient independent oracle storage plus reserve')
    S.require(product_free>=product_needed,'unchanged product floor plus reserved CLI space unavailable')
    return {'oracle_filesystem':str(DEST.parent),'oracle_free_bytes':free,
        'selected_file_allocated_bound':allocation,
        'metadata_allowance_bytes':PLAN['allocation_metadata_allowance_bytes'],
        'oracle_reserved_bytes':PLAN['additional_reserved_bytes'],'oracle_required_bytes':needed,
        'product_filesystem':str(product_parent),'product_free_bytes':product_free,
        'unchanged_product_floor_bytes':PLAN['future_product_free_floor_bytes'],
        'product_reserved_bytes':PLAN['additional_product_reserved_bytes'],
        'product_required_bytes':product_needed}


def child():
    S.require(not DEST.exists(),'new oracle directory required; never resume or overwrite an old attempt')
    storage=free_requirement()
    captured=S.read_regular(ROOT/'inputs/ORIGINAL-CAS-MANIFEST.json')[0]
    S.require(S.pin(captured,0o644)==PLAN['original_manifest']['identity'],'captured original manifest changed')
    manifest=json.loads(captured);objects=expected_archive_objects(manifest)
    selected={}
    for logical in PLAN['restore_order']:
        row=PLAN['required'][logical];p=PurePosixPath(logical)
        S.require(not p.is_absolute() and p.as_posix()==logical and '..' not in p.parts,'unsafe selected path')
        S.require(row['path']==str(DEST/logical) and row['source']=='exact_archive_restore','restore target differs')
        original=manifest['files'][logical]
        S.require({**{k:original[k] for k in ('bytes','sha256','git_blob','git_mode')},
                   'mode':original['mode_bits']}==row['identity'],'selected identity differs from original manifest')
        selected.setdefault(row['identity']['sha256'],[]).append(logical)
        S.require(not Path(row['original_path']).exists(),'retired path was repopulated; no implicit selection change')
    archive=Path(PLAN['archive']['path']);before=archive.lstat()
    S.require(stat.S_ISREG(before.st_mode) and before.st_size==PLAN['archive']['bytes'],'wrong original archive')
    before_stat={k:getattr(before,k) for k in S.STAT_KEYS}
    fd=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    result={'status':'FAIL','plan_sha256':PLAN['authorization_pin'],'product_executions':0,
        'storage':storage,'restored_files':0,'restored_logical_bytes':0,'restored':{},
        'partial_files_preserved':True,'original_paths_written':False,'source_trees_copied':0}
    seen=set();total=0
    try:
        S.require({k:getattr(os.fstat(fd),k) for k in S.STAT_KEYS}==before_stat,'opened archive inode differs')
        with os.fdopen(fd,'rb',closefd=False) as raw_archive:
            identity=digest_stream(raw_archive,before.st_size)
            S.require(identity=={k:PLAN['archive'][k] for k in ('bytes','sha256','git_blob')},'whole archive identity differs')
            raw_archive.seek(0)
            DEST.mkdir(mode=0o700)
            S.dump(DEST/'STORAGE-BEFORE.json',storage)
            with gzip.GzipFile(fileobj=raw_archive,mode='rb') as uncompressed:
                with tarfile.open(fileobj=uncompressed,mode='r|') as tar:
                    for member in tar:
                        S.require(member.name not in seen and member.isfile() and not member.issym()
                                  and not member.islnk() and member.mode==0o644,'unexpected duplicate/type/mode in original archive')
                        S.require(member.uid==member.gid==member.mtime==0,'unexpected original tar metadata')
                        seen.add(member.name)
                        stream=tar.extractfile(member);S.require(stream is not None,'missing tar body')
                        if member.name=='RAW-MANIFEST.json':
                            S.require(len(seen)==1 and member.size==len(captured),'original manifest order or extent differs')
                            S.require(stream.read()==captured,'embedded complete original manifest differs')
                            continue
                        S.require(member.name.startswith('objects/'),'unexpected original archive member')
                        digest=member.name[len('objects/'):]
                        S.require(digest in objects and member.name=='objects/'+digest
                                  and member.size==objects[digest]['bytes'],'unexpected original CAS object')
                        targets=[];opened=[]
                        try:
                            for logical in selected.get(digest,()):
                                path=DEST/logical
                                path.parent.mkdir(parents=True,exist_ok=True)
                                for parent in (path.parent,*path.parent.parents):
                                    if parent==DEST.parent:break
                                    S.require(stat.S_ISDIR(parent.lstat().st_mode),'oracle parent is not an independent directory')
                                destfd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                                output=os.fdopen(destfd,'wb');opened.append(output);targets.append((logical,path,output))
                            actual=digest_stream(stream,member.size,opened)
                            S.require(actual==objects[digest],'complete original CAS SHA/Git differs')
                            total+=actual['bytes']
                        finally:
                            for output in opened:output.close()
                        for logical,path,_ in targets:
                            row=PLAN['required'][logical];path.chmod(row['identity']['mode'])
                            data,mode,stamp=S.read_regular(path)
                            S.require(S.pin(data,mode)==row['identity'] and stamp['st_nlink']==1,
                                      'actual independent oracle readback differs')
                            result['restored'][logical]={'identity':row['identity'],'stat':stamp,
                                'archive_member':member.name,'original_path':row['original_path']}
                            result['restored_files']+=1;result['restored_logical_bytes']+=len(data)
                # Consume the gzip stream to its actual end so its CRC/length
                # trailer is verified; tar block padding is not evidence data.
                while uncompressed.read(CHUNK):pass
            S.require(seen=={'RAW-MANIFEST.json'}|{'objects/'+d for d in objects}
                      and len(seen)==2397 and total==1658896740,'complete original archive denominator differs')
            S.require(set(result['restored'])==set(PLAN['restore_order']) and result['restored_files']==136
                      and result['restored_logical_bytes']==578353224,'complete selected logical restoration differs')
        S.require({k:getattr(os.fstat(fd),k) for k in S.STAT_KEYS}==before_stat
                  and {k:getattr(archive.lstat(),k) for k in S.STAT_KEYS}==before_stat,'archive changed during readback')
        S.require(S.read_regular(PLAN['original_manifest']['path'])[0]==captured,'original manifest changed')
        for logical,row in result['restored'].items():
            S.require(not Path(row['original_path']).exists(),'retired original path was changed')
        result.update(status='PASS_EXACT_ORIGINAL_ORACLES_ONLY',full_archive_stream_readback=True,
            archive=identity,archive_stat_before=before_stat,archive_stat_after=before_stat,
            original_archive_members=len(seen),original_unique_bytes=total,
            full_gzip_CRC=True,all_original_history_preserved=True,
            known_original_missing_history=PLAN['known_missing_history_not_recovered'])
        return 0
    except BaseException:
        result['error']=traceback.format_exc()
        raise
    finally:
        os.close(fd)
        if DEST.exists():S.dump(DEST/'RESTORE-RESULT.json',result)


def parent():
    S.require(tuple(sys.version_info[:3])==(3,14,4),'actual314 required')
    S.require(not OWNER.exists() and not DEST.exists(),'new restoration attempt required')
    storage=free_requirement();bindings_before=S.guards('_restore')
    OWNER.mkdir(mode=0o700)
    S.dump(OWNER/'STORAGE.json',storage)
    S.dump(OWNER/'BINDINGS-BEFORE.json',bindings_before)
    before=S.source_snapshot(OWNER/'FULL-SOURCE-BEFORE.json')
    result=None
    try:
        sys.path.insert(0,str(S.SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        env=dict(S.PLAN['runtime']['environment'])
        command=[sys.executable,'-B',str(Path(__file__).resolve()),'--plan-sha256',PLAN['authorization_pin'],'--child']
        S.dump(OWNER/'INTENT.json',{'command':command,'environment':env,'qualification_seconds':180,
            'cleanup_seconds':3,'product_executions':0,'automatic_retry':False})
        result=run_owned(command,cwd=S.SOURCE,env=env,supervisor_env=env,
            stdout_path=OWNER/'child.stdout.bin',stderr_path=OWNER/'child.stderr.bin',
            receipt_path=OWNER/'OWNER.json',qualification_seconds=180,cleanup_seconds=3)
        S.dump(OWNER/'OWNER-RETURNED.json',result)
        from run_controls import owner_pass
        S.require(owner_pass(result),'oracle restore owner did not complete with cleanup')
        observed=json.loads(S.read_regular(DEST/'RESTORE-RESULT.json')[0])
        S.require(observed['status']=='PASS_EXACT_ORIGINAL_ORACLES_ONLY','oracle restore did not qualify its raw bytes')
        return 0
    finally:
        after=S.source_snapshot(OWNER/'FULL-SOURCE-AFTER.json')
        bindings_after=S.guards('_restore')
        S.dump(OWNER/'BINDINGS-AFTER.json',bindings_after)
        S.dump(OWNER/'FINAL.json',{'owner':result,'complete_source_equal':before==after,
            'bindings_equal':bindings_after==bindings_before,'product_executions':0,'automatic_retry':False})
        S.require(after==before,'source changed during nonproduct oracle restore')
        S.require(bindings_after==bindings_before,'bindings changed during nonproduct oracle restore')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--child',action='store_true')
    args=parser.parse_args()
    fixed=dict(PLAN);expected=fixed.pop('authorization_pin')
    encoded=(json.dumps(fixed,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    S.require(hashlib.sha256(encoded).hexdigest()==expected==args.plan_sha256,'fixed oracle restore plan differs')
    raise SystemExit(child() if args.child else parent())
