"""Stream one lossless CAS archive of existing entry20 evidence; no products."""
from pathlib import Path, PurePosixPath
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import time
from urllib.parse import parse_qsl, urlsplit

ROOT=Path(__file__).resolve().parent
PLAN_PATH=ROOT/'PLAN.json'
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def require(value,message):
    if not value:raise AssertionError(message)

def pin(raw,mode=None):
    value={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None:value.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return value

def capture(path):
    path=Path(path);before=path.lstat();state={k:getattr(before,k) for k in KEYS}
    require(stat.S_ISREG(before.st_mode),'ordinary evidence file required')
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        require({k:getattr(os.fstat(fd),k) for k in KEYS}==state,'opened evidence identity differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
        require(len(raw)==before.st_size and {k:getattr(os.fstat(fd),k) for k in KEYS}==state
            and {k:getattr(path.lstat(),k) for k in KEYS}==state,'evidence changed during full read')
    finally:os.close(fd)
    return raw,stat.S_IMODE(before.st_mode),state

def encoded(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()

def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw)
    path.chmod(0o644)
    require(capture(path)[0]==raw,'new custody record mismatch')

def dump(name,value):write(ROOT/name,encoded(value))

def credential_findings(raw):
    """Return only category/count; no URL/header/token content is emitted."""
    found={}
    def add(kind):found[kind]=found.get(kind,0)+1
    text=raw.decode('utf-8','ignore')
    # Recursively decode JSON strings for nested provider transport envelopes.
    def visit(value,depth=0):
        if depth>12:return
        if isinstance(value,dict):
            for key,item in value.items():
                if str(key).lower() in ('authorization','proxy-authorization','cookie','set-cookie'):
                    if item not in (None,'','***','basic ***','Bearer ***','bearer ***'):add('credential_header')
                visit(item,depth+1)
        elif isinstance(value,list):
            for item in value:visit(item,depth+1)
        elif isinstance(value,str):
            normalized=value.replace('\\/','/')
            for match in re.finditer(r'https?://[^\s<>"\x00]+',normalized):
                candidate=match.group(0).rstrip('\\')
                try:
                    keys={key.lower() for key,_ in parse_qsl(urlsplit(candidate).query,keep_blank_values=True)}
                except ValueError:continue
                if keys&{'sig','signature','x-amz-signature','x-goog-signature','access_token','token'}:add('signed_or_token_URL')
            for line in normalized.splitlines():
                match=re.match(r'\s*(?:authorization|proxy-authorization|set-cookie|cookie)\s*:\s*(.*)',line,re.I)
                if match and match.group(1).strip() not in ('','***','basic ***','Bearer ***','bearer ***'):
                    add('credential_header_line')
            if re.search(r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}',normalized):add('literal_access_token')
            if value.lstrip().startswith(('{','[')):
                try:nested=json.loads(value)
                except (ValueError,RecursionError):return
                if not isinstance(nested,str):visit(nested,depth+1)
    try:value=json.loads(text)
    except (ValueError,RecursionError):value=text
    visit(value)
    return found

def tar_member(tar,name,raw,mode=0o400):
    info=tarfile.TarInfo(name);info.size=len(raw);info.mode=mode;info.mtime=0
    info.uid=info.gid=0;info.uname=info.gname=''
    tar.addfile(info,io.BytesIO(raw))

def run(expected):
    plan_raw,_,_=capture(PLAN_PATH);require(pin(plan_raw)['sha256']==expected,'reviewed custody plan differs')
    plan=json.loads(plan_raw)
    require(str(Path(__file__).resolve())==plan['archive_code']['path']
        and pin(capture(Path(__file__).resolve())[0])=={k:plan['archive_code'][k] for k in ('bytes','sha256','git_blob')},
        'fixed custody code identity differs')
    require(not (ROOT/'STARTED.json').exists(),'one custody pass only; reconcile existing attempt')
    require(os.statvfs(ROOT).f_bavail*os.statvfs(ROOT).f_frsize>=plan['required_free_bytes'],'custody headroom unavailable')
    dump('STARTED.json',{'started_ns':time.time_ns(),'plan':pin(plan_raw),'product_executions':0})
    start=time.monotonic_ns();result={'status':'FAIL','product_executions':0,'originals_deleted':0,'originals_modified':0}
    try:
        origin=Path(plan['original_root']);index_raw,imode,_=capture(origin/'RAW-INVENTORY.json')
        require(pin(index_raw)==plan['raw_inventory_pin'],'original 830-file index differs')
        inventory=json.loads(index_raw);expected_files=inventory['files']
        require(len(expected_files)==830 and inventory['logical_bytes']==173880184,'exact original denominator differs')
        directories=[];actual=set()
        for folder,dirs,names in os.walk(origin,followlinks=False):
            for name in dirs:
                p=Path(folder)/name;s=p.lstat();require(stat.S_ISDIR(s.st_mode),'original directory symlink')
                directories.append({'path':p.relative_to(origin).as_posix(),'mode':stat.S_IMODE(s.st_mode),
                    'current_stat':{k:getattr(s,k) for k in KEYS},'authority':'current custody observation; no historical creation-mode claim'})
            for name in names:actual.add((Path(folder)/name).relative_to(origin).as_posix())
        require(actual==set(expected_files)|{'RAW-INVENTORY.json'},'complete original pathset differs')
        targets=[('actual/'+name,origin/name,row) for name,row in sorted(expected_files.items())]
        targets+=[(row['path'],Path(row['local_path']),row['identity']) for row in plan['metadata']]
        files=[];unique={};findings=[]
        for name,path,wanted in targets:
            p=PurePosixPath(name);require(not p.is_absolute() and '..' not in p.parts,'unsafe member name')
            raw,mode,state=capture(path);identity=pin(raw,mode)
            require(identity==wanted,'original complete bytes/mode differs: '+name)
            found=credential_findings(raw)
            if found:findings.append({'path':name,'categories':found,'disposition':'LOCAL_ONLY_NO_PUBLIC_ARCHIVE'})
            sha=identity['sha256']
            if sha in unique:
                require({k:unique[sha]['identity'][k] for k in ('bytes','sha256','git_blob')}
                    ==pin(raw),'same content key differs')
            else:unique[sha]={'path':str(path),'identity':identity,'stat':state}
            files.append({'path':name,'local_path':str(path),'identity':identity,'stat':state,'object':'objects/'+sha})
        classification={'files_checked':len(files),'access_credential_carriers':findings,
            'URL_or_header_values_printed':False,'automatic_redaction':False,
            'if_any_found_all_public_archive_creation_is_stopped':True}
        dump('CREDENTIAL-CLASSIFICATION.json',classification)
        require(not findings,'local-only credential carriers found; classify before public packaging')
        manifest={'schema':'hia.entry20.actual-original-CAS.v1','original_root':str(origin),
            'original_raw_index':pin(index_raw,imode),'original_raw_files':830,'original_raw_bytes':173880184,
            'metadata_files':len(plan['metadata']),'files':files,'original_current_directories':directories,
            'unique_objects':len(unique),'unique_bytes':sum(r['identity']['bytes'] for r in unique.values()),
            'source_tree_copy':False,'product_executions':0,'credentials':classification,
            'qualification_scope':'Retained actual finite 20 entry-layout checks; no ordinary/current-cold/all-language transfer'}
        manifest_raw=encoded(manifest);write(ROOT/'MANIFEST.json',manifest_raw)
        archive=ROOT/'ENTRY20-CAS.tar.gz'
        with archive.open('xb') as physical:
            with gzip.GzipFile(filename='',fileobj=physical,mode='wb',compresslevel=1,mtime=0) as packed:
                with tarfile.open(fileobj=packed,mode='w|',format=tarfile.GNU_FORMAT) as tar:
                    tar_member(tar,'MANIFEST.json',manifest_raw,0o644)
                    for sha,row in sorted(unique.items()):
                        raw,mode,state=capture(row['path'])
                        require(pin(raw,mode)==row['identity'] and state==row['stat'],'object drift during compression')
                        tar_member(tar,'objects/'+sha,raw)
        archive.chmod(0o644)
        # Read the complete gzip stream, validate every tar body and EOF, with no restored directory.
        observed=set()
        with gzip.open(archive,'rb') as stream:
            with tarfile.open(fileobj=stream,mode='r|') as tar:
                for member in tar:
                    require(member.isfile() and member.name not in observed,'unexpected tar type/duplicate')
                    observed.add(member.name);raw=tar.extractfile(member).read()
                    if member.name=='MANIFEST.json':require(raw==manifest_raw and member.mode==0o644,'manifest readback differs')
                    else:
                        sha=member.name.removeprefix('objects/');require(sha in unique and member.mode==0o400,'unexpected CAS member')
                        require(pin(raw)=={k:unique[sha]['identity'][k] for k in ('bytes','sha256','git_blob')},'CAS full bytes mismatch')
                while True:
                    tail=tar.fileobj.read(64<<10)
                    if not tail:break
                    require(not tail.strip(b'\0'),'unexplained buffered tar trailing bytes')
            require(not stream.read().strip(b'\0'),'unexplained tar trailing bytes')
        require(observed=={'MANIFEST.json'}|{'objects/'+sha for sha in unique},'complete archive member set differs')
        for row in files:
            raw,mode,state=capture(row['local_path'])
            require(pin(raw,mode)==row['identity'] and state==row['stat'],'original drift after full readback')
        for row in directories:
            now=(origin/row['path']).lstat()
            require({k:getattr(now,k) for k in KEYS}==row['current_stat'],'original directory drift')
        archive_raw,archive_mode,_=capture(archive)
        parts=[]
        for index,offset in enumerate(range(0,len(archive_raw),384<<10)):
            chunk=archive_raw[offset:offset+(384<<10)]
            wrapper={'schema':'hia.CAS-compressed-contiguous-span.v1','index':index,'offset':offset,
                'archive':pin(archive_raw),'span':pin(chunk),'data_base64':base64.b64encode(chunk).decode()}
            name='parts/part-%03d.json'%index;dump(name,wrapper)
            check=json.loads(capture(ROOT/name)[0]);require(base64.b64decode(check['data_base64'],validate=True)==chunk,'part complete readback differs')
            parts.append({'path':name,'offset':offset,'span':pin(chunk),'wrapper':pin(capture(ROOT/name)[0],0o644)})
        dump('PARTS.json',{'archive':pin(archive_raw,archive_mode),'parts':parts,'decoded_span_maximum':384<<10})
        result.update(status='PASS_COMPLETE_830_ORIGINALS_AND_METADATA_CUSTODY_ONLY',
            original_raw_files=830,original_raw_bytes=173880184,total_logical_files=len(files),
            total_logical_bytes=sum(r['identity']['bytes'] for r in files),unique_objects=len(unique),
            unique_bytes=manifest['unique_bytes'],archive=pin(archive_raw,archive_mode),
            archive_members=len(observed),parts=len(parts),full_gzip_CRC_and_all_member_SHA_Git=True,
            full_original_before_after_bytes_modes_and_seven_stats=True,
            public_credential_carriers=0,excluded_original_files=0,
            manifest=pin(manifest_raw,0o644),new_expanded_restore=False)
    except BaseException as error:
        import traceback
        result.update(error_type=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        raise
    finally:
        result['elapsed_ns']=time.monotonic_ns()-start;dump('RESULT.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('traceback',)},sort_keys=True),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-sha256',required=True)
    args=parser.parse_args();run(args.plan_sha256)
