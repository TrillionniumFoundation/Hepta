"""Preserve explicit completed NDU metadata; no build, Git, or child process."""
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile,time,types
from pathlib import Path
ROOT=Path('/home/qian-qi/he26v67fixturesr1')
KEY='hia-e26e-desktop-v67-ndu-supply-originals-preserve-r1'
def require(value,message):
    if not value: raise RuntimeError(message)
def wire(value):
    return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
cfg=json.loads(sys.stdin.buffer.read(1048577))
require(cfg['stable_key']==KEY,'wrong key')
program=cfg['program_text'].encode()
require(hashlib.sha256(program).hexdigest()==cfg['program_sha256'],'control source differs')
root_fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
rstat=os.fstat(root_fd)
require(rstat.st_uid==os.geteuid() and stat.S_IMODE(rstat.st_mode)==0o700,'private supply root differs')
def read(relative):
    pieces=relative.split('/')
    require(pieces and all(x and x not in ('.','..') for x in pieces),'unsafe path')
    fd=os.dup(root_fd)
    try:
        for p in pieces[:-1]:
            nxt=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nxt
        leaf=os.open(pieces[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            before=os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid()
                    and before.st_nlink==1 and before.st_size<=8*1024*1024,'not an owned bounded independent regular file')
            chunks=[];total=0
            while True:
                part=os.read(leaf,65536)
                if not part: break
                total+=len(part);require(total<=8*1024*1024,'source grew beyond bound');chunks.append(part)
            raw=b''.join(chunks)
            after=os.fstat(leaf)
            require(identity(before)==identity(after) and len(raw)==before.st_size,'source changed during read')
            return raw,{'path':relative,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                        'mode':stat.S_IMODE(before.st_mode),'identity':identity(before)}
        finally: os.close(leaf)
    finally: os.close(fd)
collected={}
for relative in cfg['paths']:
    raw,info=read(relative)
    expected=cfg['expected'].get(relative)
    require(expected is None or info['sha256']==expected,'prior pin differs: '+relative)
    collected[relative]=(raw,info)
require(sum(info['size'] for raw,info in collected.values())<=32*1024*1024,'metadata total exceeds bound')
report=json.loads(collected['report.json'][0])
guard=json.loads(collected['guard/guardian.json'][0])
common=types.ModuleType('pinned_supply_retention_common')
common.__file__=str(ROOT/'control/common.py')
exec(compile(collected['control/common.py'][0],common.__file__,'exec'),common.__dict__)
require(common.natural_guardian(guard),'outer supplier not a natural terminated owner')
require(report['status']=='THREE_FIXTURES_READY_PENDING_OUTER_GUARDIAN_NOT_QUALIFICATION'
        and report['head']=='608157e52b0b94e0d294f6b99c4e809869f183aa'
        and report['tree']=='e7c29a60796a1a78946a2c667aa80df86529e532'
        and report['qualification_executed'] is False
        and all(report[k] is True for k in ('source_preserved','pinned_inputs_preserved','upstream_preserved')),
        'supplier result differs')
for profile in ('ranking','raw','dynamic'):
    receipt=json.loads(collected['fixtures/'+profile+'/build-receipt.json'][0])
    require(common.natural_guardian(json.loads(collected['steps/'+profile+'/guard/guardian.json'][0])),'inner owner differs')
    for stream in ('stdout','stderr'):
        row=receipt['build_command_evidence'][stream]
        key='fixtures/'+profile+'/'+row['path']
        require(key in collected and collected[key][1]['sha256']==row['sha256']
                and collected[key][1]['size']==row['bytes'],'pinned original Cargo stream differs')
os.mkdir('preservation-r1',0o700,dir_fd=root_fd)
out_fd=os.open('preservation-r1',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)
OUT=ROOT/'preservation-r1'
def create(name,raw,mode=0o400):
    require('/' not in name and name not in ('.','..'),'unsafe new leaf')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=out_fd)
    try:
        p=0
        while p<len(raw):
            n=os.write(fd,raw[p:]);require(n>0,'short write');p+=n
        os.fchmod(fd,mode);os.fsync(fd)
    finally:os.close(fd)
    return {'path':str(OUT/name),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
preservation={'schema':'hia.v67.ndu-supply-originals-preservation.v1','status':'HOLD','stable_key':KEY,
              'source_root':str(ROOT),'root':str(OUT),'product_run':False,
              'scope':'explicit original regular metadata, logs, snapshots and copied old materialization only; no build target binary archive',
              'qualification_pass_claimed':False,'started_unix_ns':time.time_ns()}
try:
    preservation['control']=create('preserve.py',program)
    preservation['request']=create('request.json',wire(cfg))
    manifest={'schema':'hia.v67.ndu-supply-original-metadata-archive.v1','files':[collected[k][1] for k in sorted(collected)],
              'supplier_report_sha256':collected['report.json'][1]['sha256'],
              'supplier_guardian_sha256':collected['guard/guardian.json'][1]['sha256'],
              'original_materialization_sha256':collected['old-originals/source-materialization.original.json'][1]['sha256'],
              'scope':preservation['scope'],'atime_excluded_from_stability':True,'qualified_product':False}
    m=wire(manifest);preservation['manifest']=create('MANIFEST.json',m)
    stream=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=stream,compresslevel=6,mtime=0) as gz:
        with tarfile.open(mode='w',fileobj=gz,format=tarfile.PAX_FORMAT) as tar:
            for name in sorted(collected):
                raw,info=collected[name]
                item=tarfile.TarInfo(name);item.size=len(raw);item.mode=info['mode']
                item.uid=item.gid=0;item.mtime=0
                tar.addfile(item,io.BytesIO(raw))
    archive=stream.getvalue()
    require(len(archive)<=4*1024*1024,'compressed metadata exceeds bound')
    preservation['archive']=create('original-metadata.tar.gz',archive)
    for name,(raw,info) in collected.items():
        after,after_info=read(name)
        require(after==raw and after_info==info,'original changed during preservation: '+name)
    seen=set()
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
        for member in tar:
            require(member.isfile() and member.name in collected and member.name not in seen,'archive type/member differs')
            raw,info=collected[member.name];restored=tar.extractfile(member).read()
            require(restored==raw and member.mode==info['mode'] and member.size==len(raw),'archive bytes/mode differ')
            seen.add(member.name)
    require(seen==set(collected),'archive inventory incomplete')
    for name,pin in [('MANIFEST.json',preservation['manifest']),('original-metadata.tar.gz',preservation['archive'])]:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=out_fd)
        try:
            h=hashlib.sha256();size=0
            while True:
                part=os.read(fd,65536)
                if not part:break
                size+=len(part);h.update(part)
            require(size==pin['size'] and h.hexdigest()==pin['sha256'],'independent final readback differs')
        finally:os.close(fd)
    preservation['status']='ORIGINAL_METADATA_PRESERVED_NOT_QUALIFICATION'
    preservation['files']=len(collected)
    preservation['original_bytes']=sum(info['size'] for raw,info in collected.values())
    preservation['originals_unchanged']=True
    preservation['archive_all_members_bytes_and_modes_equal']=True
except BaseException as error:
    preservation['failure']={'type':type(error).__name__,'message':str(error)}
finally:
    preservation['ended_unix_ns']=time.time_ns()
    pin=create('PRESERVATION.json',wire(preservation))
    os.fsync(out_fd);os.fsync(root_fd)
    os.close(out_fd);os.close(root_fd)
print(json.dumps({'status':preservation['status'],'receipt':pin,'archive':preservation.get('archive'),'manifest':preservation.get('manifest')},sort_keys=True),flush=True)
raise SystemExit(0 if preservation['status']=='ORIGINAL_METADATA_PRESERVED_NOT_QUALIFICATION' else 1)
