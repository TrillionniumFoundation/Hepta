"""Clean external invocation envelope; new WAL controls retain all original ten method bodies."""
import hashlib,json,os,stat,sys
from pathlib import Path
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-wal-native-r1')
LAUNCH_SHA='ba3301ee5ade194876f2e2b7cb230895942b46c5ac1d7474ebfca7b6303529ce'
def main():
    if len(sys.argv)!=1:
        raise RuntimeError('clean launch takes no arguments')
    path=ROOT/'LAUNCH.json'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size!=1385:
            raise RuntimeError('original launch role or length differs')
        raw=os.read(fd,1386)
        after=os.fstat(fd)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(raw)!=1385 or identity(before)!=identity(after) or identity(after)!=identity(path.lstat()):
            raise RuntimeError('original launch changed while reading')
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest()!=LAUNCH_SHA:
        raise RuntimeError('original launch SHA differs')
    launch=json.loads(raw)
    command=launch['argv']
    if command[0]!='/usr/bin/python3.14' or launch['cwd']!=str(ROOT):
        raise RuntimeError('frozen executable or cwd differs')
    os.chdir(launch['cwd'])
    os.execve(command[0],command,launch['environment'])
if __name__=='__main__':
    main()
