"""Expose complete public evidence only after the original owner proves ECHILD."""
from __future__ import annotations
import argparse,hashlib,json,os,stat
from pathlib import Path
def require(value,message):
    if not value: raise RuntimeError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def wire(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def identity(s):
    return tuple(getattr(s,k) for k in
        ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path):
    path=Path(path).absolute();require(path.resolve(strict=True)==path,'alias')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and a.st_nlink==1,'regular single-link file')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read()
        require(identity(a)==identity(os.fstat(fd))==identity(path.lstat()),'changed evidence')
    finally: os.close(fd)
    return raw
def regulars(root):
    require(root.resolve(strict=True)==root.absolute(),'aliased evidence root')
    for path in sorted(root.rglob('*')):
        s=path.lstat()
        require(not stat.S_ISLNK(s.st_mode),'evidence symlink')
        if stat.S_ISDIR(s.st_mode):
            require(path.resolve(strict=True)==path.absolute(),'aliased evidence directory')
            continue
        require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'evidence special file or alias')
        yield path
def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    require(path.parent.resolve(strict=True)==path.parent.absolute(),'output parent alias')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(read(path)==raw,'whole copy readback')
def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();os.umask(0o077)
    work=a.work.absolute();base=Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(work.parent==base and work.name=='hia-core-fixture-source6-derive8-'+os.environ['GITHUB_RUN_ID']+'-1','work scope')
    public=work/'public';parent_final=public/'FINAL.json'
    final_raw=read(parent_final) if parent_final.is_file() else None
    final=json.loads(final_raw) if final_raw is not None else None
    closed=type(final) is dict and final.get('closed') is True
    if closed:
        # The only admission to child bodies is the original launcher's strict
        # owner/request/wrapper/ECHILD join; retain its raw receipts unchanged.
        request_raw=read(work/'control'/'REQUEST.json');request=json.loads(request_raw)
        require(final['request_sha256']==sha(request_raw),'parent final request')
        import sys
        sys.path.insert(0,str(work/'control'))
        import source_common as common
        request['worker_command']=[*request['worker_command_template'][:-1],sha(request_raw)]
        wrapper=common.decode(read(public/'owner-wrapper.json'))
        common.bind_closed(request,wrapper,public/'process-owner.json')
        destination=public
        put(destination/'metadata'/'REQUEST.json',request_raw)
        for root,label in ((work/'metadata','metadata/frozen'),(work/'control','metadata/control')):
            for path in regulars(root):
                put(destination/label/path.relative_to(root),read(path))
        scope='complete closed original qualification evidence, including failures'
    else:
        # Do not enumerate any child output, even when the parent returns nonzero.
        destination=work/'hold-public';destination.mkdir(mode=0o700,parents=True,exist_ok=False)
        put(destination/'FINAL.json',wire(dict(status='HOLD',closed=False,
            scope='No child-body custody claimed; original Source6/derive8 result unavailable')))
        if final_raw is not None: put(destination/'PARENT-FINAL.original.json',final_raw)
        for relative in ('metadata/METADATA-INTENT.json','metadata/PREEXEC.json','metadata/LAUNCH.json','control/REQUEST.json'):
            path=work/relative
            if path.is_file(): put(destination/relative,read(path))
        scope='parent-only hold; no child enumeration'
    rows=[];total=0
    for path in regulars(destination):
        raw=read(path);require(len(raw)<=64*1024**2,'whole evidence member exceeds retained small-reader capacity')
        total+=len(raw);require(total<=224*1024**2,'whole public evidence exceeds retained small-reader capacity')
        rows.append(dict(path=path.relative_to(destination).as_posix(),bytes=len(raw),sha256=sha(raw)))
    require(len(rows)<=100000,'member population exceeds retained reader capacity')
    manifest=wire(dict(schema='hia.source6-derive8.complete-public-evidence.v1',scope=scope,
        closed=closed,files=rows,files_count=len(rows),expanded_bytes_excluding_this_manifest=total,
        no_private_URL_or_inherited_environment=True,complete_or_HOLD=True))
    require(len(manifest)<=64*1024**2 and total+len(manifest)<=224*1024**2,'public manifest capacity')
    put(destination/'PUBLIC-CATALOG.json',manifest)
    with Path(os.environ['GITHUB_OUTPUT']).open('a',encoding='utf-8') as stream:
        stream.write('upload_root='+str(destination)+'\n');stream.flush();os.fsync(stream.fileno())
    print(json.dumps(dict(scope=scope,closed=closed,files=len(rows)+1,expanded_bytes=total+len(manifest)),sort_keys=True))
if __name__=='__main__': main()
