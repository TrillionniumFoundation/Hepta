"""Fresh disposable development native call with shared full-buffer trap capture.
No HIA syntax or domain semantics are implemented here. The parent owns exact
source/image/case identities; this carrier only maps, calls, waits and copies.
"""
from __future__ import annotations
import ctypes,json,mmap,os,resource,signal,time,traceback
from pathlib import Path
CANARY=bytes(range(160,192))
def call(image,source,output,workspace,directory):
    directory=Path(directory);directory.mkdir(exist_ok=False)
    buffers=[];maps=[];code=None;receipt=None;pid=None;waited=None;primary=None
    started=time.monotonic_ns();data=(bytes(source),bytes(output),bytes(workspace))
    try:
        for raw in data:
            n=len(raw)+64
            mm=mmap.mmap(-1,n,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
            mm[:]=CANARY+raw+CANARY;maps.append(mm)
            buffers.append((ctypes.c_char*n).from_buffer(mm))
        result=mmap.mmap(-1,64,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        maps.append(result);result[:]=bytes(64)
        before=os.getpid()
        with (directory/"stdout").open("xb") as stdout,(directory/"stderr").open("xb") as stderr:
            pid=os.fork()
            if pid==0:
                try:
                    os.setsid()
                    libc=ctypes.CDLL(None,use_errno=True)
                    libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong];libc.prctl.restype=ctypes.c_int
                    if libc.prctl(1,signal.SIGKILL,0,0,0) or os.getppid()!=before:os._exit(125)
                    if libc.prctl(4,0,0,0,0) or libc.prctl(3,0,0,0,0):raise OSError(ctypes.get_errno(),"dumpability")
                    signal.setitimer(signal.ITIMER_REAL,0)
                    resource.setrlimit(resource.RLIMIT_CPU,(10,10))
                    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
                    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                    resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
                    os.dup2(stdout.fileno(),1);os.dup2(stderr.fileno(),2)
                    code=mmap.mmap(-1,len(image),prot=mmap.PROT_READ|mmap.PROT_WRITE);code[:]=image
                    address=ctypes.addressof(ctypes.c_char.from_buffer(code))
                    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
                    if libc.mprotect(address,len(image),mmap.PROT_READ|mmap.PROT_EXEC):raise OSError(ctypes.get_errno(),"code RX")
                    if libc.mprotect(ctypes.addressof(buffers[0]),len(data[0])+64,mmap.PROT_READ):raise OSError(ctypes.get_errno(),"source RO")
                    entry=ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_void_p,ctypes.c_uint64]*3))(address)
                    returned=entry(*[x for buf,raw in zip(buffers,data) for x in (ctypes.addressof(buf)+32,len(raw))])
                    result[:8]=returned.to_bytes(8,"little");result[8:16]=b"RETURNED"
                    os._exit(0)
                except BaseException:
                    traceback.print_exc();os._exit(126)
            try:
                while waited is None:
                    got,status,usage=os.wait4(pid,os.WNOHANG)
                    if got:waited=(status,usage);break
                    if time.monotonic_ns()-started>=20_000_000_000:
                        raise TimeoutError("native development child 20 wall")
                    time.sleep(0.001)
            finally:
                if waited is None:
                    try:os.killpg(pid,signal.SIGKILL)
                    except ProcessLookupError:
                        try:os.kill(pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    got,status,usage=os.wait4(pid,0);assert got==pid;waited=(status,usage)
        status,usage=waited;rc=os.waitstatus_to_exitcode(status)
        observed=[]
        for mm,raw in zip(maps,data):
            full=mm[:];assert full[:32]==CANARY and full[-32:]==CANARY
            observed.append(full[32:-32])
        assert observed[0]==data[0]
        assert rc in (0,-signal.SIGILL),(rc,(directory/"stderr").read_bytes())
        assert (result[8:16]==b"RETURNED")==(rc==0)
        cpu=usage.ru_utime+usage.ru_stime;elapsed=time.monotonic_ns()-started
        assert 0<=cpu<10 and 0<=elapsed<20_000_000_000
        receipt=dict(returncode=rc,result=int.from_bytes(result[:8],"little") if rc==0 else None,
            raw_wait_status=status,child_wait4_complete=True,cpu_seconds=cpu,wall_ns=elapsed,
            maxrss_kib=usage.ru_maxrss,source_unchanged=True,canaries_unchanged=True,
            limits=dict(cpu=10,wall=20,address_bytes=256<<20,stack_bytes=8<<20,core_bytes=0),
            trap_not_intercepted=True,shared_all_three_actual_buffers=True)
        (directory/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        return receipt,observed
    except BaseException as exc:
        primary=exc
        raise
    finally:
        buffers.clear()
        for mm in reversed(maps):
            try:mm.close()
            except BaseException as exc:
                if primary is None:primary=exc
                else:primary.add_note(repr(exc))
        if primary is not None:raise primary
