"""New pre-request permission preparation only, then the same static freezer.
This never changes a frozen request, donor source, system file, or product body.
"""
from pathlib import Path
import hashlib,json,os,runpy,stat
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-wal-snapshot-native-r1')
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def require(v,m):
    if not v:raise RuntimeError(m)
for p in (ROOT/'REQUEST.json',ROOT/'LAUNCH.json',ROOT/'STATIC-FREEZE.json',ROOT/'PREEXEC.json',ROOT.parent/'sqlite-wal-snapshot-native-r1-actual'):
    require(not os.path.lexists(p),'no frozen or actual output may exist')
rows=[]
for base,dirs,names in os.walk(ROOT,followlinks=False):
    for n in dirs:require(stat.S_ISDIR((Path(base)/n).lstat().st_mode),'directory symlink')
    for n in sorted(names):
        p=Path(base)/n;s=p.lstat()
        require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid()==1000
            and s.st_gid==os.getgid()==1000 and stat.S_IMODE(s.st_mode)in (0o600,0o660),'new own file role')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            require(ident(os.fstat(fd))==ident(s),'fd identity')
            before=os.read(fd,s.st_size+1)
            require(len(before)==s.st_size and ident(os.fstat(fd))==ident(s),'whole before')
            if stat.S_IMODE(s.st_mode)==0o660:os.fchmod(fd,0o600)
            t=os.fstat(fd)
            require(t.st_dev==s.st_dev and t.st_ino==s.st_ino and t.st_uid==s.st_uid and t.st_gid==s.st_gid
                and t.st_nlink==1 and stat.S_IMODE(t.st_mode)==0o600 and t.st_size==s.st_size
                and t.st_mtime_ns==s.st_mtime_ns,'only permitted mode/ctime change')
            os.lseek(fd,0,os.SEEK_SET);after=os.read(fd,t.st_size+1)
            require(after==before and ident(os.fstat(fd))==ident(t)==ident(p.lstat()),'unchanged bytes')
        finally:os.close(fd)
        rows.append({'path':str(p),'before':ident(s),'after':ident(t),'bytes':len(before),
            'sha256':hashlib.sha256(before).hexdigest(),'content_unchanged':True})
body=(json.dumps({'schema':'hia.wal-snapshot.pre-request-metadata-preparation.v1',
    'status':'STATIC_PREPARATION_ONLY','all_old_request_or_actual_paths_absent':True,
    'scope':'Only current new unpublished request directory; 0660 to0600 before request pinning. No runtime bytes changed.',
    'files':rows,'qualification_executions':0},sort_keys=True,indent=2)+'\n').encode()
fd=os.open(ROOT/'MODE-PREPARATION.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb')as f:f.write(body);f.flush();os.fsync(f.fileno())
require((ROOT/'MODE-PREPARATION.json').read_bytes()==body,'mode report readback')
runpy.run_path(str(ROOT/'proof/freeze_native_request.py'),run_name='__main__')
