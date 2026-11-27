"""Actual value cleanup with kernel fault injection confined to owned children.

The normal qualification calls a complete native value image. A separate
--self-test checks only the Linux notification fixture and never claims a value
component result. No syscall provider substitutes for the native owner.
"""
from pathlib import Path
import argparse
import array
import concurrent.futures
import ctypes as C
import errno
import hashlib
import json
import mmap
import os
import select
import signal
import socket
import struct
import time
import traceback

ZERO=(0,0,0)
MASK=(1<<64)-1
BAD=0xfffffffd
LIBC=C.CDLL(None,use_errno=True)
LIBC.syscall.restype=C.c_long
LIBC.ioctl.restype=C.c_int

def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def digest(raw):return hashlib.sha256(raw).hexdigest()

class Filter(C.Structure):
    _fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
class Program(C.Structure):
    _fields_=[('length',C.c_ushort),('items',C.POINTER(Filter))]
class SyscallData(C.Structure):
    _fields_=[('nr',C.c_int),('arch',C.c_uint),('ip',C.c_ulonglong),('args',C.c_ulonglong*6)]
class Notification(C.Structure):
    _fields_=[('id',C.c_ulonglong),('pid',C.c_uint),('flags',C.c_uint),('data',SyscallData)]
class Response(C.Structure):
    _fields_=[('id',C.c_ulonglong),('value',C.c_longlong),('error',C.c_int),('flags',C.c_uint)]

def notify_filter(address,size=None,ip=None):
    # Bind mediation to the exact owned native syscall as well as its arena.
    # After successful munmap libc may reuse the same address for other work;
    # those unrelated calls must never be counted as product cleanup.
    checks=[(0,11),(16,address&0xffffffff),(20,address>>32)]
    if size is not None:checks.extend(((24,size&0xffffffff),(28,size>>32)))
    if ip is not None:checks.extend(((8,ip&0xffffffff),(12,ip>>32)))
    count=len(checks)*2+2
    instructions=[]
    for at,value in checks:
        instructions.append(Filter(0x20,0,0,at))
        index=len(instructions)
        instructions.append(Filter(0x15,0,count-index-2,value))
    instructions.extend((Filter(0x06,0,0,0x7fc00000),Filter(0x06,0,0,0x7fff0000)))
    native=(Filter*count)(*instructions)
    program=Program(count,native)
    if LIBC.prctl(38,1,0,0,0)!=0:raise OSError(C.get_errno(),'prctl private no_new_privs')
    fd=LIBC.syscall(317,1,8,C.byref(program))
    if fd<0:raise OSError(C.get_errno(),'seccomp private NEW_LISTENER')
    return int(fd)

def send_json(sock,value,fd=None):
    raw=json.dumps(value,sort_keys=True).encode()
    ancillary=[] if fd is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]
    assert sock.sendmsg([raw],ancillary)==len(raw)

def request(op,a=ZERO,*,extended=True):
    return struct.pack('<8s15Q',b'HIABVQ02'if extended else b'HIABVQ01',op,0,*a,*ZERO,*ZERO,0,0,0,0)

class Native:
    def __init__(self,path):
        self.raw=Path(path).read_bytes()
        self.mapping=mmap.mmap(-1,len(self.raw),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
        self.mapping.write(self.raw)
        self.view=(C.c_ubyte*len(self.raw)).from_buffer(self.mapping)
        assert self.raw[:616].count(b'\x0f\x05')==1
        self.syscall_ip=C.addressof(self.view)+self.raw[:616].index(b'\x0f\x05')+2
        self.function=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(C.addressof(self.view))
        self.context=C.create_string_buffer(256)
        self.rows=[]
        self.old(0)
    def raw_call(self,raw):
        source=C.create_string_buffer(raw)
        output=C.create_string_buffer(b'\xa5'*(8192+64))
        rc=int(self.function(source,len(raw),output,8192,self.context,256))
        assert source.raw==raw+b'\0'
        assert output.raw[8192:8256]==b'\xa5'*64
        return rc,output.raw[:8192]
    def old(self,op,a=ZERO,want=0):
        rc,out=self.raw_call(request(op,a,extended=False))
        assert rc==0 and out[:8]==b'HIABVR01' and word(out,8)==want,(op,rc,out[:128])
        return out
    def new(self,op,a=ZERO,want=None):
        rc,out=self.raw_call(request(op,a))
        assert rc==0 and out[:8]==b'HIABVR02',(op,rc,out[:128])
        row=dict(op=op,status=word(out,8),pending=word(out,80),known=word(out,88),consumed=word(out,96))
        assert all(row[k]in(0,1)for k in('pending','known','consumed'))
        assert row['known']or not row['consumed']
        status,known,consumed,pending=(row[k]for k in('status','known','consumed','pending'))
        assert status in ((0,6,11)if op==31 else(0,1,6,11)),row
        if status==0:assert (known,consumed,pending)==(1,0 if op==31 else 1,0),row
        if status==1:assert (known,consumed,pending)==(1,0,0),row
        if status==6:assert (known,consumed)==(1,0),row
        if consumed:assert status in(0,11),row
        if not known:assert op!=31 and(status,consumed,pending)==(11,0,0),row
        if op==31:assert(known,consumed)==(1,0),row
        assert out[16:80]==bytes(64) and out[104:128]==bytes(24)
        if want is not None:
            actual=tuple(row[k]for k in('status','known','consumed','pending'))
            assert actual==want,(row,want)
        self.rows.append(row)
        return row
    def value(self):
        out=self.old(3)
        return tuple(word(out,p)for p in(24,32,40))
    def token(self):
        out=self.old(21)
        return tuple(word(out,p)for p in(24,32,40))
    def retain(self,cap):
        out=self.old(5,cap)
        return tuple(word(out,p)for p in(24,32,40))
    def pending_state(self,address,size,pending):
        w=self.context.raw
        assert word(w,0)==int.from_bytes(b'HIABVC01','little')
        assert word(w,8)==os.getpid() and word(w,24)==1 and word(w,56)==0
        assert word(w,32)==0
        assert word(w,80)==pending
        if pending:
            assert word(w,16)==word(w,88)==address
            assert word(w,40)==word(w,96)==size
            assert word(w,104)==((-errno.EIO)&MASK)
        else:
            assert all(word(w,p)==0 for p in(16,40,80,88,96,104))

def inject_ready(sock,address,size,ip=None):
    listener=notify_filter(address,size,ip)
    send_json(sock,dict(ready=True,address=address,size=size,ip=ip),listener)
    os.close(listener)

def fixture_child(sock):
    address=LIBC.syscall(9,0,4096,3,34,-1,0)
    assert address>0
    inject_ready(sock,address,4096)
    outcomes=[]
    for i in range(3):
        C.set_errno(0)
        rc=LIBC.syscall(11,C.c_void_p(address),4096)
        outcomes.append((rc,C.get_errno()))
    assert outcomes==[(-1,errno.EIO),(-1,errno.EIO),(0,0)],outcomes
    return dict(scope='kernel-fixture-only',outcomes=outcomes)

def failure_child(sock,image,kind,legacy=False):
    n=Native(image)
    if kind=='anchor':
        cap=ZERO;op=30;oldop=22
    elif kind=='token':
        cap=n.token();n.new(30,want=(0,1,1,0));op=30;oldop=22
    else:
        cap=n.value();n.new(30,want=(0,1,1,0));op=29;oldop=6
    address=word(n.context.raw,16);size=word(n.context.raw,40)
    inject_ready(sock,address,size,n.syscall_ip)
    if legacy:
        n.old(oldop,cap,want=11)
        # Q01 did not attest a retry record. Q02 cannot adopt it as if it had.
        n.new(31,want=(6,1,0,0))
        n.new(op,cap,want=(6,1,0,0))
        assert word(n.context.raw,16)==address and word(n.context.raw,80)==0
        return dict(scope='unchanged-legacy-cleanup-failure',rows=n.rows)
    n.new(op,cap,want=(11,1,1,1))
    n.pending_state(address,size,1)
    n.new(op,cap,want=(6,1,0,1))
    n.new(31,want=(11,1,0,1))
    n.pending_state(address,size,1)
    # Threads race only the single locked retained cleanup, not the consumed
    # capability. Exactly one further munmap is issued; other calls are idle.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        values=list(pool.map(lambda _:n.new(31,want=(0,1,0,0)),range(16)))
    assert len(values)==16
    n.pending_state(address,size,0)
    n.new(31,want=(0,1,0,0))
    n.new(op,cap,want=(6,1,0,0))
    return dict(scope='actual-native-cleanup-retry',rows=n.rows)

def normal_child(sock,image):
    n=Native(image);a=n.value();other=n.retain(a);token=n.token()
    n.new(31,want=(6,1,0,0))
    n.new(30,a,want=(1,1,0,0))
    n.new(29,token,want=(1,1,0,0))
    n.new(29,a,want=(0,1,1,0))
    n.new(29,a,want=(1,1,0,0))
    n.new(30,want=(0,1,1,0))
    n.new(30,want=(6,1,0,0))
    n.new(29,other,want=(0,1,1,0))
    n.new(30,token,want=(0,1,1,0))
    n.new(31,want=(0,1,0,0))
    n.new(30,token,want=(6,1,0,0))
    n.pending_state(0,0,0)
    return dict(scope='actual-native-consumption',rows=n.rows)

def concurrent_child(sock,image):
    n=Native(image);a=n.value();caps=[n.retain(a)for _ in range(32)]
    n.new(29,a,want=(0,1,1,0));n.new(30,want=(0,1,1,0))
    with concurrent.futures.ThreadPoolExecutor(max_workers=16)as pool:
        list(pool.map(lambda cap:n.new(29,cap,want=(0,1,1,0)),caps))
    n.pending_state(0,0,0);n.new(31,want=(0,1,0,0))
    return dict(scope='actual-native-concurrent-last-drop',rows=n.rows)

def fork_child(sock,image):
    n=Native(image);a=n.value();before=n.context.raw
    reader,writer=os.pipe();pid=os.fork()
    if pid==0:
        os.close(reader)
        try:
            n.new(29,a,want=(6,1,0,0));n.new(30,want=(6,1,0,0));n.new(31,want=(6,1,0,0))
            assert n.context.raw==before
            os.write(writer,b'PASS');os._exit(0)
        except BaseException:
            os.write(writer,traceback.format_exc().encode());os._exit(1)
    os.close(writer);captured=os.read(reader,65536);os.close(reader)
    _,status=os.waitpid(pid,0);assert status==0 and captured==b'PASS',(status,captured)
    n.new(29,a,want=(0,1,1,0));n.new(30,want=(0,1,1,0))
    return dict(scope='actual-native-captured-process',rows=n.rows)

def controls_child(sock,image):
    n=Native(image);a=n.value();frames=[]
    for op in range(25):frames.append(request(op))
    for op in tuple(range(25,33))+(MASK,):frames.append(request(op,extended=False))
    for op in(32,MASK):frames.append(request(op))
    for op in(29,30,31):
        base=request(op,a if op!=31 else ZERO)
        for at in(16,48,56,64,72,80,88,96,104,112,120):
            raw=bytearray(base);struct.pack_into('<Q',raw,at,1);frames.append(bytes(raw))
        frames.extend((base[:-1],base+b'\0'))
    frames.append(request(31,a))
    for frame in frames:
        before=n.context.raw;rc,out=n.raw_call(frame)
        expected=bytearray(b'\xa5'*8192)
        # The established fixed capsule initializes only this private phase
        # word before request grammar admission; original V01 does the same.
        struct.pack_into('<Q',expected,128,0)
        assert rc==BAD and n.context.raw==before and out==expected,(frame[:128],rc)
    n.new(29,a,want=(0,1,1,0));n.new(30,want=(0,1,1,0))
    return dict(scope='actual-native-original-and-new-private-domain',controls=len(frames),rows=n.rows)

def run_case(name,body,failures,expected_notifications):
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    pid=os.fork()
    if pid==0:
        parent.close();os.setsid();signal.alarm(30)
        try:
            result=body(child);send_json(child,dict(done=True,passed=True,result=result));os._exit(0)
        except BaseException:
            try:send_json(child,dict(done=True,passed=False,error=traceback.format_exc()))
            finally:os._exit(1)
    child.close();listener=None;notifications=[];reply=None;ready=None;limit=time.monotonic()+35
    try:
        while reply is None:
            if time.monotonic()>=limit:raise TimeoutError(name)
            fds=[parent.fileno()]+([]if listener is None else[listener])
            readable,_,_=select.select(fds,[],[],min(1,max(0,limit-time.monotonic())))
            if parent.fileno()in readable:
                raw,ancillary,flags,_=parent.recvmsg(1<<20,socket.CMSG_SPACE(4))
                if not raw:raise RuntimeError('child closed without a complete reply')
                assert not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)
                value=json.loads(raw)
                if value.get('ready'):
                    assert listener is None;ready=value
                    received=[]
                    for level,kind,data in ancillary:
                        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                            a=array.array('i');a.frombytes(data[:len(data)//4*4]);received.extend(a)
                    assert len(received)==1,received;listener=received[0]
                else:reply=value
            if listener is not None and listener in readable:
                notice=Notification()
                r=LIBC.ioctl(listener,0xc0502100,C.byref(notice))
                if r<0:
                    if C.get_errno()in(errno.EINTR,errno.ENOENT):continue
                    raise OSError(C.get_errno(),'SECCOMP_IOCTL_NOTIF_RECV')
                assert notice.data.nr==11 and notice.data.args[0]==ready['address'] and notice.data.args[1]==ready['size'] and (ready.get('ip') is None or notice.data.ip==ready['ip']), (name,ready,dict(nr=notice.data.nr,args=list(notice.data.args),ip=notice.data.ip))
                deny=len(notifications)<failures
                response=Response(notice.id,0,-errno.EIO if deny else 0,0 if deny else 1)
                notifications.append(dict(tid=notice.pid,nr=notice.data.nr,ip=notice.data.ip,args=list(notice.data.args),error=-errno.EIO if deny else 0,continued=not deny))
                assert LIBC.ioctl(listener,0xc0182101,C.byref(response))==0,(C.get_errno(),notifications)
        _,status=os.waitpid(pid,0);pid=0
        assert reply.get('done')and reply.get('passed')and status==0,reply
        assert len(notifications)==expected_notifications,(name,len(notifications),expected_notifications)
        return dict(name=name,passed=True,notifications=notifications,result=reply['result'])
    finally:
        if pid:
            try:os.killpg(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        if listener is not None:os.close(listener)
        parent.close()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image');ap.add_argument('--output',required=True);ap.add_argument('--self-test',action='store_true');args=ap.parse_args()
    if not args.self_test and not args.image:ap.error('--image is required for native qualification')
    out=Path(args.output);out.mkdir(parents=True,exist_ok=False)
    rows=[]
    try:
        rows.append(run_case('private-kernel-notification-fixture',fixture_child,2,3))
        if not args.self_test:
            for name,body in(('normal-consumption',normal_child),('concurrent-last-drop',concurrent_child),('captured-pid',fork_child),('original-private-domain',controls_child)):
                rows.append(run_case(name,lambda s,body=body:body(s,args.image),0,0))
            for kind in('anchor','token','value'):
                rows.append(run_case('actual-munmap-'+kind,lambda s,kind=kind:failure_child(s,args.image,kind),2,3))
                rows.append(run_case('legacy-munmap-'+kind,lambda s,kind=kind:failure_child(s,args.image,kind,True),1,1))
        report=dict(schema='hia.native-value.cleanup.v2.qualification',passed=True,scope='kernel-fixture-only'if args.self_test else'actual-native-value-cleanup',rows=rows)
        if args.image:
            raw=Path(args.image).read_bytes();report['image']=dict(bytes=len(raw),sha256=digest(raw))
        (out/'qualification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print('KERNEL_FIXTURE_ONLY'if args.self_test else'NATIVE_VALUE_CLEANUP_QUALIFIED',len(rows),flush=True)
    except BaseException:
        (out/'failure.json').write_text(json.dumps(dict(rows=rows,error=traceback.format_exc(),passed=False),indent=2)+'\n')
        raise

if __name__=='__main__':main()
