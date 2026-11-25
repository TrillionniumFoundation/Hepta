"""External Linux ptrace controls for actual native process-transport QA only."""
from pathlib import Path
import ctypes as C,os,signal,struct,time
MASK=(1<<64)-1
FIELDS='r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
class Registers(C.Structure):_fields_=[(name,C.c_ulonglong) for name in FIELDS]
def trace(argv,env,stderr,*,syscall_offset,phase=None,number=None,ordinal=1,error=None,retval=None,short_write=None):
    libc=C.CDLL(None,use_errno=True);libc.ptrace.argtypes=[C.c_uint,C.c_int,C.c_void_p,C.c_void_p];libc.ptrace.restype=C.c_long
    def ptrace(req,pid,addr=0,data=0):
        C.set_errno(0);r=libc.ptrace(req,pid,C.c_void_p(addr) if isinstance(addr,int) else addr,C.c_void_p(data) if isinstance(data,int) else data)
        if r==-1 and C.get_errno():raise OSError(C.get_errno(),os.strerror(C.get_errno()),(req,pid))
        return r
    def peek(pid,at,n):
        out=bytearray()
        while len(out)<n:out.extend(struct.pack('<Q',ptrace(2,pid,at+len(out),0)&MASK))
        return bytes(out[:n])
    pid=os.fork()
    if pid==0:
        try:
            fd=os.open(stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.dup2(fd,2);os.close(fd)
            ptrace(0,0);os.kill(os.getpid(),signal.SIGSTOP);os.execve(argv[0],argv,env)
        except BaseException:os._exit(111)
    events=[];injected=[];entering=True;active=False;base=None;pending=None;seen=0;delivery=0;started=time.monotonic_ns()
    _,status=os.waitpid(pid,0);assert os.WIFSTOPPED(status)
    ptrace(0x4200,pid,0,1|(1<<20))
    try:
        while True:
            ptrace(24,pid,0,delivery);delivery=0
            _,status=os.waitpid(pid,0)
            if os.WIFEXITED(status):code=os.WEXITSTATUS(status);break
            if os.WIFSIGNALED(status):code=-os.WTERMSIG(status);break
            sig=os.WSTOPSIG(status)
            if sig!=(signal.SIGTRAP|0x80):
                if sig not in (signal.SIGTRAP,signal.SIGSTOP):delivery=sig
                continue
            regs=Registers();ptrace(12,pid,0,C.byref(regs))
            if entering:
                pending=None
                if regs.orig_rax==1 and regs.rdi==2 and 1<=regs.rdx<=256:
                    text=peek(pid,regs.rsi,regs.rdx)
                    if text.startswith(b'MV_BEGIN '):
                        base=int(text.split()[1],16);active=True
                    elif text.startswith(b'MV_END'):active=False
                if active and base is not None and regs.rip==base+syscall_offset+2:
                    state=struct.unpack('<Q',peek(pid,regs.r14,8))[0]
                    item={'phase':state,'number':regs.orig_rax,'args':[regs.rdi,regs.rsi,regs.rdx,regs.r10,regs.r8,regs.r9]}
                    events.append(item);pending={'event':item}
                    if phase==state and number==regs.orig_rax:
                        seen+=1
                        if seen==ordinal:
                            regs.orig_rax=MASK;ptrace(13,pid,0,C.byref(regs));pending['inject']=True
                    if short_write is not None and regs.orig_rax==1 and regs.rdx>short_write:
                        pending['short']=regs.rdx;regs.rdx=short_write;ptrace(13,pid,0,C.byref(regs))
            else:
                if pending is not None:
                    item=pending['event'];actual=regs.rax
                    if pending.get('inject'):
                        regs.rax=((-(error or 0)) if error is not None else retval)&MASK;ptrace(13,pid,0,C.byref(regs))
                        item['injected']={'error':error,'retval':retval,'skipped_result':actual};injected.append(item)
                    if 'short' in pending:
                        regs.rdx=pending['short'];ptrace(13,pid,0,C.byref(regs));item['actual_short_request']=short_write;item['original_request']=pending['short'];injected.append(item)
                    item['result']=regs.rax
            entering=not entering
            if time.monotonic_ns()-started>30_000_000_000:raise TimeoutError('external ptrace QA guard')
    except BaseException:
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:os.waitpid(pid,0)
        except ChildProcessError:pass
        raise
    return {'returncode':code,'events':events,'injected':injected,'wall_ns':time.monotonic_ns()-started}

