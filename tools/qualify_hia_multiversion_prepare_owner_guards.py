"""Native prepare-owner failures, exact ordering and same-holder cleanup."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,threading,time
from tools.qualify_hia_multiversion_prepare_owner import Owner,packet,operation,get,sha
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_prepare_intake import abi_bytes
from tools.qualify_hia_multiversion_call import function,document
from tools.qualify_hia_multiversion_components import ENTRY
from hepta.hia_multiversion import _admit
CTRL=186<<20
class FaultDriver:
    """Only fault injection; every role and policy is the same native image."""
    def __init__(self,owner,after=None,before=None):
        self.owner=owner;self.after=after;self.before=before;self.trace=[]
        base=C.cast(owner.f,C.c_void_p).value
        def target(h):return ENTRY(base+h+4+struct.unpack('<i',C.string_at(base+h,4))[0])
        self.policy=target(114)
        self.roles={2:target(205),3:target(212),4:target(219),5:target(198)}
        self.libc=C.CDLL(None,use_errno=True);self.libc.syscall.restype=C.c_long
    def __call__(self,s,sn,o,on,w,wn):
        wa,sa,oa=map(C.addressof,(w,s,o));struct.pack_into('<Q',w,CTRL,0)
        for i in range(128):
            action=self.policy(s,sn,o,on,w,wn)
            if action==0:return get(o,8)
            if action>=0xfffffff0:return action
            if action==1:
                nr=get(o,0);mask=get(o,8)
                args=[get(o,16+j*8)+(0,wa,sa,oa)[(mask>>(j*2))&3] for j in range(6)]
                C.set_errno(0);r=self.libc.syscall(C.c_long(nr),*[C.c_uint64(x) for x in args])
                if r==-1:r=-C.get_errno()
            else:
                v=[get(o,j) for j in range(0,48,8)]
                if self.before:self.before(action,w,v)
                ptr=(wa+v[0],v[1],wa+v[2],v[3],wa+v[4],v[5])
                r=self.roles[action](*ptr);self.trace.append(dict(action=action,status=r))
                if self.after:self.after(action,r,w,v)
            struct.pack_into('<Q',w,CTRL+8,r&NONE)
        raise AssertionError('native owner continuation did not terminate')
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);a=p.parse_args()
    D=a.output;D.mkdir(exist_ok=True,parents=True);image=a.builder.read_bytes();fd=sealed(image);rows=[]
    raw=json.dumps(document([function('f0',[],result='u64'),function('f1',['u64'],result='u64',selected=0)]),separators=(',',':')).encode()
    original,sigs,_=_admit(raw);core=original.canonical_bytes;abi=abi_bytes(original,sigs)
    def record(label,owner,raw,want,path=None,driver=None,detail=None,oc=None,wc=None,preserve=False):
        baseline=set(os.listdir('/proc/self/fd'))
        rc,out,receipt,streams,wall=owner.run(raw,driver=driver,oc=oc,wc=wc)
        assert rc==want,(label,rc,want,[get(out,x) for x in range(8,128,8)] if rc<0xfffffff0 else None,streams)
        if detail is not None:assert get(out,16)==detail,(label,get(out,16),detail)
        assert set(os.listdir('/proc/self/fd'))==baseline,(label,'FD leak')
        if path is not None and not preserve:assert not path.exists(),(label,'owned path not retired')
        if rc<0xfffffff0:
            assert get(out,40)==0 and out[768:1024]==bytes(256),(label,'unready addresses escaped')
            for f in streams:
                if f is not None:assert isinstance(f,bytes)
        row=dict(case=label,status=rc,detail=None if rc>=0xfffffff0 else get(out,16),retirement_status=None if rc>=0xfffffff0 else get(out,32),wall_ns=wall,response_sha256=sha(out),
                 native_trace=[] if driver is None else driver.trace,streams=[None if x is None else dict(bytes=len(x),sha256=sha(x)) for x in streams])
        rows.append(row);(D/'cases-progress.json').write_text(json.dumps(rows,indent=2)+'\n');(D/(label.replace('/','-')+'.response')).write_bytes(out)
        print('PREPARE_OWNER_GUARD_PASS',label,rc,flush=True)
        return out
    owner=Owner(a.directory);path=D/'never-built-private.so';first=packet(core,abi,path,fd,image)
    variants=[('magic',b'INVALID!'+first[8:]),('truncated',first[:-1]),('tail',first+b' ')]
    for at,values in [(8,[3,NONE]),(16,[0,2,1<<31]),(24,[0]),(32,[1,3]),(40,[0,8388609,NONE]),(48,[0,335,5137,NONE]),(56,[0,4096,NONE])]+[(i,[1]) for i in list(range(64,128,8))+list(range(160,256,8))]:
        for value in values:
            r=bytearray(first);struct.pack_into('<Q',r,at,value);variants.append((str(at)+'-'+str(value),bytes(r)))
    for label,r in variants:record('frame/'+label,owner,r,0xfffffffd,path)
    for op in (1,2):record('empty-holder-op'+str(op),owner,operation(op),0xfffffffd,path)
    for oc,wc in [(2047,len(owner.w)),(len(owner.o)-1,len(owner.w)),(len(owner.o),len(owner.w)-1)]:
        record('short-'+str(oc)+'-'+str(wc),owner,first,0xfffffffd,path,oc=oc,wc=wc)
    del owner
    def native_case(label,*,data=core,actual=image,handle=fd,cancel=0,deadline=None,pin_flip=False,preserve=False):
        owner=Owner(a.directory);path=D/(label+'.so')
        if preserve:path.write_bytes(b'owned QA sentinel before rejected capture')
        r=bytearray(packet(data,abi,path,handle,actual,cancel,deadline))
        if pin_flip:r[128]^=1
        before=path.read_bytes() if preserve else None
        out=record(label,owner,bytes(r),1,path,preserve=preserve)
        if preserve:assert path.read_bytes()==before
        return out
    native_case('wrong-sealed-image-sha',pin_flip=True)
    native_case('capture-refusal-preserves-unacquired-path',pin_flip=True,preserve=True)
    for label,mode,seals in [('unsealed',0o500,0),('nonexec',0o600,15)]:
        bad=sealed(image,mode=mode,seal=seals)
        try:native_case(label,handle=bad)
        finally:os.close(bad)
    native_case('expired-before-child',deadline=time.monotonic_ns()-1)
    token=C.c_uint64(1);native_case('cancel-before-child',cancel=C.addressof(token))
    bad=sealed(b'X'*64)
    try:native_case('actual-exec-refusal',actual=b'X'*64,handle=bad)
    finally:os.close(bad)
    native_case('actual-constructor-invalid-Core',data=b'!')
    # Parent capture must observe cancellation after a real owned child is visible.
    owner=Owner(a.directory);path=D/'cancel-during-child.so';token=C.c_uint64(0);seen=[];stop=threading.Event()
    def cancel_child():
        children=Path('/proc/self/task/'+str(os.getpid())+'/children')
        while not stop.is_set():
            ids=children.read_text().split()
            if ids:seen.extend(map(int,ids));token.value=1;return
            time.sleep(.001)
    t=threading.Thread(target=cancel_child);t.start()
    try:record('cancel-during-actual-child',owner,packet(core,abi,path,fd,image,C.addressof(token)),1,path)
    finally:stop.set();t.join()
    assert seen
    for pid in seen:
        try:os.waitpid(pid,os.WNOHANG)
        except ChildProcessError:pass
        else:raise AssertionError(('owned child not reaped',pid))
    changes={
      'schema':lambda r:r.update(schema='wrong'),'profile':lambda r:r.update(profile='wrong'),'target':lambda r:r.update(target='wrong'),'kind':lambda r:r.update(kind='object'),'status':lambda r:r.update(status='proved'),'ok':lambda r:r.update(ok=False),
      'Core-binding':lambda r:r.update(core_sha256='0'*64),'input-binding':lambda r:r.update(input_sha256='0'*64),'artifact-binding':lambda r:r.update(artifact_sha256='0'*64),'object-format':lambda r:r.update(object_sha256='x'*64),'text-format':lambda r:r.update(machine_text_sha256='x'*64),
      'artifact-min':lambda r:r.update(artifact_bytes=63),'artifact-max':lambda r:r.update(artifact_bytes=67108865),'artifact-type':lambda r:r.update(artifact_bytes=True),'text-zero':lambda r:r.update(machine_text_bytes=0),'text-max':lambda r:r.update(machine_text_bytes=16777217),'exports':lambda r:r.update(exports=[]),'foreign-exports':lambda r:r.update(foreign_buffer_exports=['other']),
      'Core-reverified':lambda r:r['claims'].update(standalone_core_reverified=False),'fallback':lambda r:r['claims'].update(fallback_used=True),'llvm-ir':lambda r:r['claims'].update(llvm_ir_used=True),'external-linker':lambda r:r['claims'].update(external_linker_used=True),
      'inventory-schema':lambda r:r['binary_inventory'].update(schema='wrong'),'inventory-format':lambda r:r['binary_inventory'].update(format='wrong'),'inventory-kind':lambda r:r['binary_inventory'].update(kind='wrong'),'inventory-machine':lambda r:r['binary_inventory'].update(machine=3),'inventory-exports':lambda r:r['binary_inventory'].update(dynamic_exports=[]),'inventory-source':lambda r:r['binary_inventory'].update(source_exports_rechecked=False)
    }
    for i,(label,change) in enumerate(changes.items()):
        owner=Owner(a.directory);path=D/('captured-'+str(i)+'.so')
        def after(action,rc,w,v):
            if action==2 and rc==0:
                at=v[2];r=json.loads(C.string_at(C.addressof(w)+at+512,get(w,at+80)));change(r);updated=json.dumps(r,separators=(',',':')).encode()
                assert len(updated)<=1<<20;C.memmove(C.addressof(w)+at+512,updated,len(updated));struct.pack_into('<Q',w,at+80,len(updated))
        driver=FaultDriver(owner,after=after)
        out=record('captured/'+label,owner,packet(core,abi,path,fd,image),2,path,driver=driver,detail=12)
        assert get(out,536)!=NONE and [x['action'] for x in driver.trace]==[2,3,5]
        del driver,owner
    # Two simultaneous faults: path capture must fail before malformed receipt.
    owner=Owner(a.directory);path=D/'order-missing-path.so';moved=D/'order-captured-artifact.retained'
    def missing_after(action,rc,w,v):
        if action==2 and rc==0:
            os.rename(path,moved);at=v[2];C.memmove(C.addressof(w)+at+512,b'!',1);struct.pack_into('<Q',w,at+80,1)
    driver=FaultDriver(owner,after=missing_after);out=record('missing-path-before-invalid-receipt',owner,packet(core,abi,path,fd,image),2,path,driver=driver)
    assert get(out,16)!=12 and moved.exists()
    # A real ELF function with the wrong behavior is supplied to the actual native
    # probe through a private memory fault, never a substituted expected result.
    owner=Owner(a.directory);path=D/'actual-wrong-function.so'
    def wrong_before(action,w,v):
        if action==4:struct.pack_into('<Q',w,2056,get(w,2048))
    driver=FaultDriver(owner,before=wrong_before)
    out=record('wrong-native-function-before-live-VM',owner,packet(core,abi,path,fd,image),3,path,driver=driver,detail=7)
    assert get(out,88)>0 and [x['action'] for x in driver.trace]==[2,3,4,5]
    os.close(fd)
    report=dict(schema='hepta.hia.multiversion-prepare-owner-guards.v1',whole_native_runtime=False,passed=len(rows),failed=0,
                scope='Actual fixed HIA owner image. Captured receipt corruption is external QA only; all fixed native construction, pin/read, validation, VM, and retirement execute. The simultaneous missing-path/malformed-report case proves original capture-before-report ordering.',
                image_sha256=sha((a.directory/'prepare-owner.so').read_bytes()),builder_sha256=sha(image),cases=rows)
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PREPARE_OWNER_GUARDS_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
