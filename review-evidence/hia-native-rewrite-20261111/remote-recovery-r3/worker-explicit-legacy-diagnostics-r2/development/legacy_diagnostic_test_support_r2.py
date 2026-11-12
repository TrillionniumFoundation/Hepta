"""Mechanical evidence helpers for one new explicit importer experiment.

No business oracle, JSON parser, schema choice or diagnostic text is present.
The helpers load exact supplied images, preserve every ABI buffer and supervise
one fixed ELF process with the original resource limits.
"""
from __future__ import annotations
import ctypes,gzip,json,os,resource,signal,stat,subprocess,time
from hashlib import sha256
from pathlib import Path

def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
    path.chmod(0o644)
def usage():
    a=resource.getrusage(resource.RUSAGE_SELF);b=resource.getrusage(resource.RUSAGE_CHILDREN)
    return a.ru_utime+a.ru_stime+b.ru_utime+b.ru_stime
def fact(path):
    path=Path(path);st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(st.st_mode))
class CAS:
    def __init__(self,root):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.seen={}
    def keep(self,raw):
        raw=bytes(raw);sha=digest(raw);path=self.root/(sha+".gz")
        if sha not in self.seen:
            compressed=gzip.compress(raw,compresslevel=1,mtime=0)
            with path.open("xb") as f:f.write(compressed)
            path.chmod(0o644)
            assert gzip.decompress(path.read_bytes())==raw
            self.seen[sha]=len(raw)
        else:assert self.seen[sha]==len(raw)
        return dict(path=str(path),bytes=len(raw),sha256=sha,compression="gzip",mode=0o644)
    def verify(self):
        for sha,n in self.seen.items():
            path=self.root/(sha+".gz")
            assert stat.S_IMODE(path.stat().st_mode)==0o644 and not path.is_symlink()
            raw=gzip.decompress(path.read_bytes())
            assert (len(raw),digest(raw))==(n,sha)

_LIB=ctypes.CDLL(None,use_errno=True)
_LIB.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
_LIB.mmap.restype=ctypes.c_void_p
_LIB.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
_LIB.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
_LIB.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
_LIB.prctl.restype=ctypes.c_int
class Buffer:
    def __init__(self,raw=b"",size=None,readonly=False):
        raw=bytes(raw);self.size=len(raw) if size is None else size
        assert type(self.size) is int and 0<=len(raw)<=self.size
        self.extent=((max(1,self.size)+128+4095)//4096)*4096
        ptr=_LIB.mmap(None,self.extent,3,0x22,-1,0)
        assert ptr is not None and ptr!=ctypes.c_void_p(-1).value
        self.base=int(ptr);self.address=self.base+64;self.readonly=False
        ctypes.memset(self.base,0x69,self.extent)
        ctypes.memset(self.address,0,max(1,self.size))
        if raw:ctypes.memmove(self.address,raw,len(raw))
        if readonly:self.protect(True)
    def value(self):return ctypes.string_at(self.address,self.size)
    def write(self,at,raw):
        raw=bytes(raw);assert not self.readonly and 0<=at<=self.size and len(raw)<=self.size-at
        if raw:ctypes.memmove(self.address+at,raw,len(raw))
    def check(self):
        assert ctypes.string_at(self.base,64)==bytes([0x69])*64
        tail=self.extent-64-max(1,self.size)
        assert ctypes.string_at(self.address+max(1,self.size),tail)==bytes([0x69])*tail
    def protect(self,readonly):
        assert _LIB.mprotect(self.base,self.extent,1 if readonly else 3)==0
        self.readonly=bool(readonly)
    def close(self):
        if self.base is None:return
        try:self.check()
        finally:
            ptr=self.base;self.base=None
            assert _LIB.munmap(ptr,self.extent)==0
class NativeCalls:
    def __init__(self,out):
        self.out=Path(out);self.out.mkdir(parents=True,exist_ok=True)
        self.cas=CAS(self.out/"cas");self.entries=[];self.attempts=0
    def call(self,image,s,o,w,*,label,out_extent=None,work_extent=None):
        self.attempts+=1
        n=self.attempts;folder=self.out/("entry-%06d"%n);folder.mkdir()
        before=[s.value(),o.value(),w.value()]
        oldrights=[s.readonly,o.readonly,w.readonly]
        assert oldrights==[True,False,False]
        advertised=[s.size,o.size if out_extent is None else out_extent,
            w.size if work_extent is None else work_extent]
        assert 0<=advertised[1]<=o.size and 0<=advertised[2]<=w.size
        pending=dict(label=label,entry=n,advertised=advertised,
            full_before=[self.cas.keep(x) for x in before],actual_rights=oldrights)
        save(self.out/"pending-native-entry.json",pending)
        result=int(image._entry(s.address,advertised[0],o.address,advertised[1],w.address,advertised[2]))
        after=[s.value(),o.value(),w.value()]
        guards=[]
        for buf in (s,o,w):
            tail=buf.extent-64-max(1,buf.size)
            head_raw=ctypes.string_at(buf.base,64)
            tail_raw=ctypes.string_at(buf.address+max(1,buf.size),tail)
            guards.append(dict(head=self.cas.keep(head_raw),tail=self.cas.keep(tail_raw),
                intact=head_raw==bytes([0x69])*64 and tail_raw==bytes([0x69])*tail))
        row=dict(pending,returned=result,full_after=[self.cas.keep(x) for x in after],
            readonly_source_unchanged=after[0]==before[0],guards=guards,
            canaries_intact=all(g["intact"] for g in guards),
            rights_unchanged=oldrights==[s.readonly,o.readonly,w.readonly])
        # A returned failing entry retains its actual full output before asserts.
        save(folder/"entry.json",row);self.entries.append(row)
        save(self.out/"pending-native-entry.json",dict(status="NO_PENDING_ENTRY",completed=n))
        assert row["readonly_source_unchanged"] and row["canaries_intact"] and row["rights_unchanged"]
        return result
    def verify(self):
        self.cas.verify()
        assert self.attempts==len(self.entries)
        save(self.out/"all-completed-entries.json",self.entries)

def run_elf(executable,source,empty,out,cas):
    executable=Path(executable).resolve();empty=Path(empty).resolve();out=Path(out)
    out.mkdir(parents=True,exist_ok=False)
    source=bytes(source)
    parent=os.getpid()
    def limits():
        assert _LIB.prctl(1,signal.SIGKILL,0,0,0)==0
        if os.getppid()!=parent:os._exit(70)
        assert _LIB.prctl(4,0,0,0,0)==0 and _LIB.prctl(3,0,0,0,0)==0
        resource.setrlimit(resource.RLIMIT_CPU,(90,90))
        resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
        resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    env=dict(PATH=str(empty),HOME=str(empty),LANG="C",LC_ALL="C")
    before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic_ns()
    original_input=cas.keep(source);timed_out=False
    process=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,cwd=empty,env=env,preexec_fn=limits,start_new_session=True,close_fds=True)
    save(out/"pending-process.json",dict(pid=process.pid,executable=str(executable),
        input=original_input,env=env,limits=dict(cpu=90,wall=180,address=1<<30,core=0)))
    try:
        stdout,stderr=process.communicate(source,timeout=180)
    except subprocess.TimeoutExpired:
        timed_out=True
        os.killpg(process.pid,signal.SIGKILL)
        stdout,stderr=process.communicate()
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.communicate()
        raise
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    row=dict(pid=process.pid,returncode=process.returncode,timed_out=timed_out,
        elapsed_ns=time.monotonic_ns()-start,
        child_cpu_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
        input=original_input,stdout=cas.keep(stdout),stderr=cas.keep(stderr),env=env,
        limits=dict(cpu=90,wall=180,address=1<<30,core=0),
        executable=fact(executable),fixed_ELF_no_host_business_callback=True,
        syscall_trace_performed=False,stderr_is_complete_unmodified_bytes=True)
    save(out/"process.json",row);save(out/"pending-process.json",dict(status="COMPLETED",pid=process.pid))
    return stdout,stderr,row
