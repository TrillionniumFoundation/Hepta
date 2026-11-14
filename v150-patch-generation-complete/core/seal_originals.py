"""Data-only complete CAS/tar custody. No products, imports from project, or source writes."""
import argparse,gzip,hashlib,io,json,os,re,stat,tarfile,time,traceback
from pathlib import Path
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def require(ok,message):
    if not ok:raise AssertionError(message)

def seven(path):return {k:getattr(Path(path).lstat(),k)for k in FIELDS}

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
    with os.fdopen(fd,'wb')as stream:stream.write(raw)

def read(path,expected=None):
    path=Path(path);s=path.lstat();before=seven(path)
    require(stat.S_ISREG(s.st_mode)and s.st_nlink==1,'single-link regular original required: '+str(path))
    for parent in path.parents:require(stat.S_ISDIR(parent.lstat().st_mode),'special original ancestor')
    if expected is not None:require(before==expected,'original seven-stat changed before read')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require({k:getattr(os.fstat(fd),k)for k in FIELDS}==before,'opened original differs')
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(s.st_size+1)
        require(len(raw)==s.st_size and {k:getattr(os.fstat(fd),k)for k in FIELDS}==before==seven(path),
            'original changed around complete read')
    finally:os.close(fd)
    return raw,stat.S_IMODE(s.st_mode),before

def scan(plan):
    files={};directories={}
    for entry in plan['roots']:
        root=Path(entry['path']);label=entry['label'];exclude=entry.get('exclude',[])
        require(root.is_absolute()and '..'not in root.parts and stat.S_ISDIR(root.lstat().st_mode),'invalid fixed original root')
        def walk(path,relative):
            name=label+'/'+relative;directories[name]={'source_path':str(path),'stat':seven(path)}
            for item in sorted(os.scandir(path),key=lambda e:e.name):
                suffix=item.name if relative=='.'else relative+'/'+item.name
                if any(suffix==n or suffix.startswith(n+'/')for n in exclude):continue
                child=Path(item.path);s=item.stat(follow_symlinks=False)
                if stat.S_ISDIR(s.st_mode):walk(child,suffix)
                else:
                    require(stat.S_ISREG(s.st_mode)and s.st_nlink==1,'unexpected link/special original')
                    logical=label+'/'+suffix;require(logical not in files,'duplicate logical original')
                    files[logical]={'path':str(child),'stat':seven(child)}
        walk(root,'.')
    for logical,path in plan['extras'].items():
        require(logical not in files and not logical.startswith('/')and '..'not in Path(logical).parts,'invalid extra logical path')
        files[logical]={'path':path,'stat':seven(path)}
    return dict(sorted(files.items())),dict(sorted(directories.items()))

def no_credentials(name,raw):
    if not name.endswith(('.json','.jsonl','.py','.md','.txt','.log','.diff','.raw')):return
    require(not re.search(rb'(?i)authorization\s*:\s*(bearer|basic)\s+[A-Za-z0-9+/_.=-]+',raw),'credential authorization header')
    require(not re.search(rb'(?i)set-cookie\s*:',raw),'credential cookie header')
    require(not re.search(rb'https?://[^\s"<>]+[?&](?:sig|X-Amz-Signature|X-Goog-Signature)=',raw),'signed access URL')

def main(plan_path,plan_sha):
    started=time.monotonic_ns();plan_raw,_,_=read(plan_path)
    require(hashlib.sha256(plan_raw).hexdigest()==plan_sha,'exact custody plan differs')
    plan=json.loads(plan_raw);output=Path(plan['output'])
    require(plan['schema']=='hepta.hia.patch.complete-custody-input.v1'and plan['products']==0,
        'invalid data-only scope')
    require(not output.exists(),'unique custody attempt already exists')
    output.mkdir(mode=0o700)
    report={'status':'FAIL_CUSTODY','product_executions':0,'reader_executions':0,'originals_preserved':True,
        'original_product_status':plan['original_product_status']}
    try:
        files,dirs=scan(plan)
        require(files==plan['files']and dirs==plan['directories'],'complete fixed original pathset/stat differs')
        free=os.statvfs(output);require(free.f_bavail*free.f_frsize>=plan['minimum_free_bytes'],'custody storage floor')
        write(output/'INPUT-PLAN.json',plan_raw)
        write(output/'INTENT.json',encode({'plan':pin(plan_raw),'files':len(files),'directories':len(dirs),
            'products':0,'archive_only_no_unpacked_copy':True,'originals_preserved':True,'started_ns':started}))
        rows={};objects={};aliases={}
        for name,item in files.items():
            raw,mode,s=read(item['path'],item['stat']);no_credentials(name,raw);identity=pin(raw);key=identity['sha256']
            rows[name]={'source_path':item['path'],'identity':identity,'mode':mode,'seven_stats':s,
                'storage_path':'objects/'+key}
            aliases.setdefault(key,[]).append(name)
            if key not in objects:objects[key]={'identity':identity,'source_path':item['path'],'stat':s}
            else:require(objects[key]['identity']==identity,'CAS identity collision')
        for requirement in plan['fixed_originals']:
            raw,mode,s=read(requirement['path'],requirement['stat']);actual=pin(raw)
            require(all(actual[k]==v for k,v in requirement['pin'].items()if k!='mode'),'fixed original bytes differ')
            if'mode'in requirement['pin']:
                require(('100755'if mode&0o111 else'100644')==requirement['pin']['mode'],'fixed original mode differs')
        manifest={'schema':'hepta.hia.patch.complete-custody-manifest.v1','files':rows,'directories':dirs,
            'file_count':len(rows),'logical_bytes':sum(r['identity']['bytes']for r in rows.values()),
            'objects':objects,'unique_objects':len(objects),'unique_bytes':sum(r['identity']['bytes']for r in objects.values()),
            'boundaries':plan['boundaries'],'products':0,'whole_native':False,
            'all_original_modes_explicit':True,'transport_modes_do_not_replace_original_modes':True}
        mb=encode(manifest);write(output/'MANIFEST.json',mb)
        archive=output/'COMPLETE-ORIGINALS.tar.gz'
        with archive.open('xb')as wire:
            with gzip.GzipFile(filename='',mode='wb',fileobj=wire,compresslevel=1,mtime=0)as gz:
                with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT)as tar:
                    def add(name,raw):
                        item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o444
                        item.uid=item.gid=item.mtime=0;item.uname=item.gname=''
                        tar.addfile(item,io.BytesIO(raw))
                    add('MANIFEST.json',mb)
                    for key,obj in sorted(objects.items()):
                        raw,_,_=read(obj['source_path'],obj['stat']);require(pin(raw)==obj['identity'],'CAS original drifted')
                        add('objects/'+key,raw)
                        require(wire.tell()<=plan['maximum_archive_bytes'],'archive cap reached; partial retained')
                        available=os.statvfs(output)
                        require(available.f_bavail*available.f_frsize>=plan['reserved_free_bytes'],'custody reserve exhausted')
        archive_raw,_,_=read(archive);archive_identity=pin(archive_raw);del archive_raw
        seen=set();compared=0
        with gzip.open(archive,'rb')as gz:
            with tarfile.open(fileobj=gz,mode='r|')as tar:
                for item in tar:
                    require(item.isfile()and item.mode==0o444 and item.name not in seen,'transport member differs')
                    seen.add(item.name);stream=tar.extractfile(item);raw=stream.read(item.size+1)
                    require(len(raw)==item.size,'incomplete transport member')
                    if item.name=='MANIFEST.json':require(raw==mb,'transport manifest differs');continue
                    require(item.name.startswith('objects/'),'unknown transport member')
                    key=item.name[8:];require(key in objects and pin(raw)==objects[key]['identity'],'full transport object differs')
                    for logical in aliases[key]:
                        row=rows[logical];current,mode,s=read(row['source_path'],row['seven_stats'])
                        require(current==raw and mode==row['mode']and s==row['seven_stats'],'full logical restoration differs')
                        compared+=1
            while gz.read(1048576):pass
        require(len(seen)==len(objects)+1 and compared==len(rows),'incomplete full archive readback')
        final_files,final_dirs=scan(plan)
        require(final_files==files and final_dirs==dirs,'complete final original pathset/stat drifted')
        report.update(status='PASS_COMPLETE_ORIGINAL_BYTES_MODES_AND_FULL_ARCHIVE_READBACK',
            files=len(rows),logical_bytes=manifest['logical_bytes'],unique_objects=len(objects),unique_bytes=manifest['unique_bytes'],
            directories=len(dirs),archive=archive_identity,manifest=pin(mb),archive_members=len(seen),
            complete_gzip_CRC=True,logical_members_full_byte_compared=compared,pathsets_seven_stats_unchanged=True,
            no_uncompressed_duplicate_tree=True,remote_blob_custody='PENDING_SEPARATE_TRANSPORT',
            elapsed_ns=time.monotonic_ns()-started)
    except BaseException:
        report['traceback']=traceback.format_exc();report['partial_files_retained']=True
    finally:write(output/'REPORT.json',encode(report))
    print(json.dumps(report,sort_keys=True))
    return 0 if report['status'].startswith('PASS_')else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--plan',required=True);p.add_argument('--plan-sha256',required=True)
    a=p.parse_args();raise SystemExit(main(Path(a.plan),a.plan_sha256))
