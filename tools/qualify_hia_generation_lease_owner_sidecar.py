"""Actual native sole-owner sidecar bind, fences, pending and retirement gates."""
from pathlib import Path
import argparse,ctypes as C,errno,fcntl,hashlib,json,os,struct,threading
from concurrent.futures import ThreadPoolExecutor
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_bound as fault
from tools import qualify_hia_generation_lease_owner_tempdir as tq
from tools import generate_hia_generation_lease_owner_sidecar_capsule_packer as capsule
Q=int.from_bytes(b'HIAGSCQ1','little')
R=int.from_bytes(b'HIAGSCR1','little')
NONE=(1<<64)-1
BAD=4294967293
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def u64(b,at):return struct.unpack_from('<Q',b,at)[0]
def frame(op):return struct.pack('<16Q',Q,op,*([0]*14))
class Bound:
    def __init__(self,path):
        self.owner=q.Owner(path);self.owner.initialize()
        self.entry=self.owner.lib.hia_generation_lease_owner_sidecar
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value;self.path=path
        self.calls=0
        self.code=self.address+capsule.HOLES['code']+4+struct.unpack('<i',C.string_at(self.address+capsule.HOLES['code'],4))[0]
        self.tempdir=self.address+capsule.HOLES['tempdir']+4+struct.unpack('<i',C.string_at(self.address+capsule.HOLES['tempdir'],4))[0]
        self.value=u64(self.owner.context,40)
        assert C.string_at(self.value,(path.parent/'hia-generation-lease-values.core.bin').stat().st_size)==(path.parent/'hia-generation-lease-values.core.bin').read_bytes()
        assert C.string_at(self.code,(path.parent/'code-owner.flat').stat().st_size)==(path.parent/'code-owner.flat').read_bytes()
    def raw(self,data,context=None):
        source=C.create_string_buffer(data);output=C.create_string_buffer(bytes([165])*128)
        ctx=self.owner.context if context is None else context
        rc=int(self.entry(source,len(data),output,128,ctx,2048))
        assert source.raw==data+b'\0'
        self.calls+=1
        assert output.raw[128:]==b'\0'
        return rc,output.raw[:128]
    def call(self,op):
        rc,raw=self.raw(frame(op))
        assert rc==0 and u64(raw,0)==R,(op,rc,raw.hex())
        return dict(op=op,status=u64(raw,8),error=u64(raw,16),pending=u64(raw,24),retired=u64(raw,32),
                    known=u64(raw,40),state=u64(raw,48),extent=u64(raw,56),active=u64(raw,64),
                    token=u64(raw,72),code=u64(raw,80),fence=u64(raw,88),fd=u64(raw,96),n=u64(raw,104),
                    seals=u64(raw,112),stage=u64(raw,120))
    def bind(self):
        row=self.call(0);assert row['status']==0 and row['state']==2 and row['pending']==0,row
        w=self.owner.context;ptr=u64(w,1152)
        assert ptr and u64(w,1160)==212992 and u64(w,1168)
        assert u64(w,1176)==self.address and u64(w,72)==1 and u64(w,1208)==0
        assert u64(w,704)==self.address+capsule.CODE_EXPORT and u64(w,712)==ptr+1024 and u64(w,720)==256
        code=C.string_at(ptr+1024,256)
        assert u64(w,728)==u64(code,128)!=0
        assert u64(code,136)==C.addressof(w)+512 and u64(code,144)==u64(w,40)
        assert u64(w,1184)and u64(w,1192)and u64(w,1200)
        assert u64(w,680)==6
        assert C.string_at(ptr+1280,2816)==bytes(2816),'unbound Future and BG spans remain zero'
        return row
    def get(self):
        row=self.call(3)
        assert row['status']==0 and row['pending']==0 and row['fd']!=NONE and row['seals']==15,row
        fd=row['fd']
        try:
            assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15 and fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
            assert os.fstat(fd).st_size==row['n']
            return os.pread(fd,row['n']+1,0).decode('utf-8','surrogatepass')
        finally:os.close(fd)
    def close(self,op=1):
        row=self.call(op)
        assert row['status']==0 and row['retired']==1 and row['pending']==0 and row['state']==0,row
        assert bytes(self.owner.context)[1136:1280]==bytes(144)
        assert bytes(self.owner.context)[704:736]==bytes(32) and u64(self.owner.context,672)==0
        assert u64(self.owner.context,72)==0 and u64(self.owner.context,680)==6
        row2=self.call(1);assert row2['status']==0 and row2['retired']==1
        final=self.owner.call(3);assert final['status']==0 and final['state']==3
        return row
    def value_probe(self):
        source=bytearray(128);struct.pack_into('<8sQ',source,0,b'HIABVQ04',47)
        row=self.owner.call(4,bytes(source));raw=row['result']
        assert row['status']==0 and row['child_rc']==0 and raw[:8]==b'HIABVR01' and u64(raw,8)==0
        return u64(raw,48)

def normal(path,out):
    before=tq.fdset();root=out/'normal';root.mkdir()
    with tq.environment(dict(TMPDIR=str(root))):
        b=Bound(path);row=b.bind();assert b.value_probe()==1
        stable=bytes(b.owner.context)
        again=b.call(0);assert again['status']==6 and bytes(b.owner.context)==stable
        refused=b.owner.call(3);assert refused['status']==2 and refused['state']==1
        assert b.get()==str(root)
        with ThreadPoolExecutor(max_workers=8)as pool:
            paths=list(pool.map(lambda _:b.get(),range(32)))
        assert paths==[str(root)]*32 and u64(b.owner.context,1208)==0
        b.close();assert not list(root.iterdir())
    assert tq.fdset()==before
    return dict(passed=True,actual_native_sidecar_mapping=True,actual_random_nonces=True,
                actual_context_token=True,same_value_entry_and_arena=True,real_code_context_initialized=True,
                raw_owner_destroy_blocked=True,duplicate_bind_refused=True,concurrent_gets=32,actual_retirement=True)

def live_value_fence(path,out):
    before=tq.fdset();b=Bound(path);b.bind()
    values=q.Values(q.ValueTransport(b.owner));cap=values.scalar('strong value outlives a refused sidecar close')
    assert b.value_probe()==2
    row=b.call(1)
    assert row['status']==6 and row['state']==2 and row['pending']==0 and row['token']==1 and row['fence']==0,row
    assert b.value_probe()==2 and values.python(cap)=='strong value outlives a refused sidecar close'
    assert u64(C.string_at(u64(b.owner.context,712),256),80)==0
    values.drop(cap);b.close();assert tq.fdset()==before
    return dict(passed=True,actual_value_destroy_fence_busy=True,actual_context_token_reacquired=True,
                actual_code_fence_rolled_back=True,no_extra_capability=True)

def guards(path,out):
    before=tq.fdset();b=Bound(path)
    for data in [b'',bytes(127),frame(0)+b'x',struct.pack('<16Q',Q,5,*([0]*14)),
                 struct.pack('<16Q',Q,0,1,*([0]*13))]:
        stable=bytes(b.owner.context);rc,raw=b.raw(data)
        assert rc==BAD and raw==bytes([165])*128 and bytes(b.owner.context)==stable
    b.bind();stable=bytes(b.owner.context)
    copied=C.create_string_buffer(stable)
    rc,raw=b.raw(frame(1),copied)
    assert rc==BAD and raw==bytes([165])*128 and copied.raw[:2048]==stable and bytes(b.owner.context)==stable
    reader,writer=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(reader);rc,raw=b.raw(frame(1))
            os.write(writer,json.dumps(dict(rc=rc,unchanged=bytes(b.owner.context)==stable,output=raw==bytes([165])*128)).encode())
            os._exit(0)
        except BaseException:os._exit(91)
    os.close(writer);row=json.loads(os.read(reader,16384));os.close(reader)
    _,status=os.waitpid(pid,0);assert status==0 and row==dict(rc=BAD,unchanged=True,output=True)
    request=bytearray(128);struct.pack_into('<8sQ',request,0,b'HIABVQ06',21)
    raw=q.envelope(4,bytes(request));s=C.create_string_buffer(raw)
    with q.mmap.mmap(-1,q.OUT) as output:
        output[:128]=bytes([165])*128
        rc=b.owner.entry(s,len(raw),q.address(output),q.OUT,b.owner.context,2048)
        assert rc==BAD and output[:128]==bytes([165])*128 and bytes(b.owner.context)==stable
    b.close();assert tq.fdset()==before
    return dict(passed=True,wire_no_write=5,copied_owner_refused=True,fork_refused=True,
                public_q06_refused_without_writes=True)

def actual_init_failures(path,out):
    before=tq.fdset();rows=[]
    for kind,nr,err in [('sidecar-getrandom',318,errno.EIO),('sidecar-mmap',9,errno.ENOMEM),
                        ('value-token',318,errno.EIO),('code-init',318,errno.EIO)]:
        b=Bound(path)
        start=b.value if kind=='value-token' else b.code if kind=='code-init' else b.address
        extent=(path.parent/'hia-generation-lease-values.core.bin').stat().st_size if kind=='value-token' else (path.parent/'code-owner.flat').stat().st_size if kind=='code-init' else len(capsule.BRIDGE)
        def denied():
            fault.deny_fixed_syscall(start,start+extent,nr,err)
            return b.call(0)
        row=fault.thread_result(denied)
        assert row['status']!=0 and row['pending']==1 and row['known']==1 and row['state']==4,row
        assert u64(b.owner.context,72)==1 and u64(b.owner.context,1208)==0
        assert b.owner.call(3)['status']==2
        count=b.value_probe()
        assert count==(1 if row['token'] else 0)
        retry=b.call(2)
        assert retry['status']==0 and retry['state']==2 and retry['pending']==0,retry
        assert b.value_probe()==1
        b.close();assert tq.fdset()==before
        rows.append(dict(kind=kind,syscall=nr,errno=err,failed=row,actual_retry=retry))
    b=Bound(path)
    def denied_empty():
        fault.deny_fixed_syscall(b.address,b.address+len(capsule.BRIDGE),9,errno.ENOMEM)
        return b.call(0)
    row=fault.thread_result(denied_empty);assert row['pending']==1 and row['extent']==0,row
    b.close();assert tq.fdset()==before
    return dict(passed=True,cases=rows,empty_failed_init_can_retire_without_allocating=True)

def actual_retirement_failures(path,out):
    before=tq.fdset();rows=[]
    for kind,nr,err in [('tempdir-close',436,errno.EIO),('code-munmap',11,errno.EIO),('sidecar-munmap',11,errno.EIO)]:
        root=out/kind;root.mkdir()
        with tq.environment(dict(TMPDIR=str(root))):
            b=Bound(path);b.bind();assert b.get()==str(root);ptr=u64(b.owner.context,1152)
            start=b.tempdir if kind=='tempdir-close' else b.code if kind=='code-munmap' else b.address
            extent=(path.parent/'tempdir-component.flat').stat().st_size if kind=='tempdir-close' else (path.parent/'code-owner.flat').stat().st_size if kind=='code-munmap' else len(capsule.BRIDGE)
            def denied():
                fault.deny_fixed_syscall(start,start+extent,nr,err)
                return b.call(1)
            row=fault.thread_result(denied)
            assert row['status']!=0 and row['pending']==1 and row['known']==1 and row['retired']==0 and row['state']==4,row
            assert u64(b.owner.context,1152)==ptr and u64(b.owner.context,72)==1 and u64(b.owner.context,1208)==0
            assert b.owner.call(3)['status']==2
            if kind=='tempdir-close':
                assert row['stage']==140 and row['fence']==1 and row['token']==0
                context=C.string_at(ptr+4096,204800);held=u64(context,40)
                assert held!=NONE;os.fstat(held)
            elif kind=='code-munmap':assert row['stage']==150 and row['fence']==1 and row['token']==0
            else:
                assert row['stage']==180 and row['fence']==0 and row['token']==0
                assert bytes(b.owner.context)[704:736]==bytes(32)
            b.close(2);assert not list(root.iterdir())
        assert tq.fdset()==before
        rows.append(dict(kind=kind,syscall=nr,errno=err,failed=row,actual_retry_and_retirement=True))
    return dict(passed=True,cases=rows,one_native_mapping_retained_until_actual_unmap=True,
                code_and_value_fences_retained_until_dependencies_retire=True)

def concurrent_bind(path,out):
    before=tq.fdset();b=Bound(path)
    with ThreadPoolExecutor(max_workers=8)as pool:rows=list(pool.map(lambda _:b.call(0),range(8)))
    assert sum(r['status']==0 for r in rows)==1 and sum(r['status']==6 for r in rows)==7,rows
    assert b.value_probe()==1 and u64(b.owner.context,72)==1
    b.close();assert tq.fdset()==before
    return dict(passed=True,threads=8,exactly_one_actual_mapping_and_token_owner=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cases',default='normal,live-value-fence,guards,init-failures,retirement-failures,concurrent-bind')
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    build=json.loads((args.owner.parent/'build.json').read_bytes());assert pin(args.owner.read_bytes())==build['product']
    cases=dict(normal=normal,**{'live-value-fence':live_value_fence,'guards':guards,'init-failures':actual_init_failures,
                               'retirement-failures':actual_retirement_failures,'concurrent-bind':concurrent_bind})
    rows={}
    for name in args.cases.split(','):
        print('SIDECAR_CASE_BEGIN',name,flush=True)
        row=cases[name](args.owner,args.output);rows[name]=row
        (args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
        print('SIDECAR_CASE_PASS',name,flush=True)
    report=dict(schema='hepta.hia.generation-owner-sidecar.qualification.v1',passed=True,cases=rows,
                complete=len(rows)==len(cases),product=pin(args.owner.read_bytes()),build=pin((args.owner.parent/'build.json').read_bytes()),
                actual_native_trusted_binding=True,request_supplied_callbacks=False,host_context_prefix_writes=False,
                callable_kinds_enabled=False,future_kind_enabled=False,background_kind_enabled=False,
                public_constructor_qualified=False,whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(rows),complete=report['complete'])),flush=True)
if __name__=='__main__':main()
