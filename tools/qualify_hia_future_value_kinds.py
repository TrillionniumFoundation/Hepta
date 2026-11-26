"""Actual native Future semantics for the complete Value kind domain.

The Python class is an independent oracle. Product compilation, packing and
every Future/Value transition below execute actual native HIA code. Dynamic
__bool__/__len__ callable dispatch remains an explicit unresolved protocol;
its original oracle cases stay recorded, never silently counted as equivalent.
"""
from pathlib import Path
import argparse, ctypes as C, hashlib, json, mmap, os, platform, struct, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
BOOT = 'examples/hia_bootstrap/'
COMPILER_SHA = '494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
VALUE = ('result_value_owner','result_value_core','result_value_import','result_value_export',
         'background_optimizer_json_capture','agent_binary64_format','result_value_binary64',
         'result_value_dict_iterator','result_value_classes','native_class_mro','result_value_records')
PUBLIC = ('background_optimizer_future_public_owner','background_optimizer_future_public_carrier',
          'background_optimizer_future_public_timeout','background_optimizer_future_public_log',
          'multiversion_background_future_cell','multiversion_future')
EXTRA = ('result_value_records_packer','background_optimizer_future_public_observers_notify',
         'background_optimizer_future_public_observers_notify_packer','background_optimizer_future_public_packer')
SOURCE_FILES = (
    'tools/generate_hia_background_optimizer_future_public_owner.py',
    'tools/hia_background_optimizer_future_public_bridge.S',
    'tools/generate_hia_background_optimizer_future_public_packer.py',
    'tools/hia_result_value_records_bridge.S',
    'tools/generate_hia_result_value_records_packer.py',
    'tools/qualify_hia_future_value_kinds.py',
    'tools/qualify_hia_native_seccomp_notify.py',
    'tools/qualify_hia_result_value_records.py',
    'tools/qualify_hia_result_value_classes.py',
    'tools/qualify_hia_result_value_dict_iterator.py',
    'tools/qualify_hia_multiversion_components.py',
    'hepta/hia_background_optimizer.py','hepta/hia_multiversion.py',
)

def digest(raw): return hashlib.sha256(raw).hexdigest()
def word(raw, at): return struct.unpack_from('<Q', raw, at)[0]
def put_json(path, value): path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')
def pin(raw): return dict(bytes=len(raw), sha256=digest(raw))

def build(compiler, output):
    from tools.generate_hia_result_value_records_packer import reference_flat as value_reference
    from tools.generate_hia_background_optimizer_future_public_packer import reference_flat as public_reference
    from tools.qualify_hia_multiversion_components import Image
    compiler=Path(compiler).resolve()
    raw=compiler.read_bytes()
    assert len(raw)==813129 and digest(raw)==COMPILER_SHA
    source_files={name:digest((ROOT/name).read_bytes()) for name in SOURCE_FILES}
    modules=[]; flats={}
    paths=[BOOT+name+'.hepta' for name in VALUE+PUBLIC+EXTRA]
    for path in paths:
        source=(ROOT/path).read_bytes(); source_files[path]=digest(source); rounds=[]
        for _ in range(2):
            p=subprocess.run([str(compiler),'compile'],input=source,capture_output=True,timeout=30)
            assert p.returncode==0 and not p.stderr and p.stdout,(path,p.returncode,p.stderr)
            rounds.append(p.stdout)
        assert rounds[0]==rounds[1],path
        flat=rounds[0]; name=Path(path).stem; flats[name]=flat
        (output/(name+'.flat')).write_bytes(flat)
        modules.append(dict(source_path=path,source_bytes=len(source),source_sha256=digest(source),
                            flat_bytes=len(flat),flat_sha256=digest(flat),double_compile_identical=True))
        print('FUTURE_KIND_NATIVE_COMPILE',name,len(flat),flush=True)
    def pack(name, wire, status_extent=False):
        image=Image(output/(name+'.flat')); out=C.create_string_buffer(16<<20); work=C.create_string_buffer(16<<20)
        rc=image(wire,out,work)
        if status_extent:
            assert rc==0,(name,rc); size=word(work.raw,0)
        else: size=rc
        assert 0<size<len(out),(name,rc,size)
        return out.raw[:size]
    pieces=[flats[name] for name in VALUE]
    wire=b'HIABVP04'+struct.pack('<13Q',11,*(len(x)for x in pieces),1)+b''.join(pieces)
    value=pack('result_value_records_packer',wire)
    assert value==value_reference(pieces)
    n=flats['background_optimizer_future_public_observers_notify']
    wire=b'HIABFNPK'+struct.pack('<3Q',len(n),0,0)+n
    notify=pack('background_optimizer_future_public_observers_notify_packer',wire,True)
    pieces=[flats[name] for name in PUBLIC]+[value,notify]
    wire=b'HIABFPP2'+struct.pack('<10Q',8,*(len(x)for x in pieces),1)+b''.join(pieces)
    public=pack('background_optimizer_future_public_packer',wire)
    assert public==public_reference(pieces)
    products={'hia-result-value.core.bin':value,'hia-future-notify.core.bin':notify,'hia-future-public.core.bin':public}
    for name, product in products.items(): (output/name).write_bytes(product)
    for name, expected in source_files.items(): assert digest((ROOT/name).read_bytes())==expected,('source changed during build',name)
    result=dict(schema='hepta.hia.future-value-kinds-build.v1',component_qualified=False,
                whole_public_future_closed=False,compiler=pin(raw),modules=modules,source_files=source_files,
                products={name:pin(data)for name,data in products.items()},
                native_pack=True,independent_relocation_comparison=True)
    put_json(output/'build.json',result)
    return result

class Public:
    def __init__(self, value, image):
        self.value=value;self.image=image;self.ctx=C.create_string_buffer(256);self.calls=0;self.futures=[];self.factories=[]
        self.call(0,fid=(C.addressof(value.engine.context),256,0))
    def call(self,op,fid=(0,0,0),cap=(0,0,0),value=(0,0,0),kind=0,status=0):
        raw=bytearray(192);raw[:8]=b'HIABFP02' if op>=22 else b'HIABFP01';struct.pack_into('<Q',raw,8,op)
        for at,part in ((16,fid),(40,cap),(64,value)):struct.pack_into('<3Q',raw,at,*part)
        struct.pack_into('<Q',raw,96,kind)
        out=C.create_string_buffer(b'\xa5'*65568,65568)
        src=C.create_string_buffer(bytes(raw),192)
        self.output_address=C.addressof(out)
        rc=self.image.entry(src,192,out,65536,self.ctx,256);self.calls+=1
        assert src.raw==bytes(raw)and out.raw[65536:]==b'\xa5'*32
        r=out.raw[:65536]
        assert rc==0 and r[:8]==b'HIABFRP1',(op,rc,r[:128].hex())
        assert status is None or word(r,8)==status,(op,status,r[:128].hex())
        return r
    def factory(self):
        r=self.call(1);f=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48))
        assert word(r,16)==3;self.factories.append(f);return f
    def make(self,f):
        r=self.call(4,*f);n=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48))
        assert word(r,16)==2;self.futures.append(n);return n
    def finish(self):
        for f in self.futures:self.call(6,*f)
        for f in self.factories:self.call(3,*f)
        self.call(18)
        assert word(self.ctx.raw,200)==0

def error_value(v,r):
    assert word(r,16)==200,r[:128].hex()
    cap=v.keep(r,72);result={}
    for key in ('class','message'):
        k=v.scalar(key);field=v.keep(v.raw(9,a=cap,b=k));result[key]=v.python(field);v.drop(field);v.drop(k)
    v.drop(cap)
    return result

def identity(v,cap):
    r=v.raw(7,a=cap);return word(r,104),word(r,112)

def original_call(f,name,*args):
    try:return dict(status=0,value=getattr(f,name)(*args))
    except BaseException as error:return dict(status=2 if not isinstance(error,Exception)else 1,
        error={'class':type(error).__name__,'message':str(error)})

def construct(v,case):
    from hepta.hia_multiversion import ScalarABI,GenerationInfo
    from pathlib import PosixPath
    if case=='tuple-empty':return v.tuple([]),()
    if case=='tuple-full':return v.tuple([v.scalar(False),v.scalar(2)]),(False,2)
    if case=='tuple-nested':return v.tuple([v.tuple([])]),((),)
    if case in ('ScalarABI','ScalarABI-unvalidated'):
        py=ScalarABI('f',('i64',),'i64')if case=='ScalarABI'else ScalarABI(None,False,0)
        a=v.scalar(py.function);b=v.tuple([v.scalar(x)for x in py.parameters])if type(py.parameters)is tuple else v.scalar(py.parameters)
        c=v.scalar(py.result);return v.keep(v.raw(41,a=a,b=b,c=c)),py
    if case=='GenerationInfo':
        fields=[7,'1'*64,'2'*64,'3'*64,4096,(),1,2,True,'profile',0,b'']
        caps=[v.tuple([])if type(x)is tuple else v.scalar(x)for x in fields]
        return v.keep(v.raw(42,a=v.tuple(caps))),GenerationInfo(*fields)
    if case in ('PosixPath','Path-derived'):
        cls=v.builtin(18);pycls=PosixPath
        if case=='Path-derived':
            cls=v.cls('PathAlias',[cls]);pycls=type('PathAlias',(PosixPath,),{})
        base=v.lst([v.scalar('/'),v.scalar('tmp'),v.scalar('hia')])
        return v.instance(cls,base),pycls('/tmp/hia')
    if case in ('class','class-tuple','class-ScalarABI'):
        if case=='class':
            cls=v.cls('UserClass',[]);return cls,type('UserClass',(),{})
        if case=='class-tuple':return v.builtin(28),tuple
        return v.builtin(29),ScalarABI
    if case in ('object','object-fake-class-field','unicode-class','long-class'):
        name={'object':'NativeObject','object-fake-class-field':'ActualClass',
              'unicode-class':'Éclair_🙂','long-class':'Long'+('X'*4096)}[case]
        cls=v.cls(name,[]);pycls=type(name,(),{})
        namespace=v.dictionary([('class','SpoofedClass')])if case=='object-fake-class-field'else None
        result=v.instance(cls,env=namespace);py=pycls()
        if namespace is not None:py.__dict__['class']='SpoofedClass'
        return result,py
    if case.startswith('str-')or case.startswith('bytes-'):
        raw=''if case.endswith('empty')else 'nonempty'
        typ=str if case.startswith('str-')else bytes
        if typ is bytes:raw=raw.encode()
        name='StringAlias'if typ is str else 'BytesAlias'
        cls=v.cls(name,[v.builtin(6 if typ is str else 7)]);pycls=type(name,(typ,),{})
        return v.instance(cls,v.scalar(raw)),pycls(raw)
    if case.startswith('iterator-'):
        mode={'iterator-keys':0,'iterator-items':1,'iterator-values':2}[case]
        native=v.dictionary([]);py={}
        return v.iterator(native,mode),(iter(py)if mode==0 else iter(py.items())if mode==1 else iter(py.values()))
    scalar={'None':None,'False':False,'True':True,'zero':0,'negative':-1,'float-zero':-0.0,'float-nonzero':1.5,
            'str-empty':'','str-full':'x','bytes-empty-plain':b'','bytes-full-plain':b'x'}
    if case in scalar:return v.scalar(scalar[case]),scalar[case]
    if case=='plain-list':return v.lst([]),[]
    if case=='plain-dict-spoof':return v.dictionary([('class','Spoof'),('message','ordinary')]),{'class':'Spoof','message':'ordinary'}
    raise AssertionError(case)

CASES=('None','False','True','zero','negative','float-zero','float-nonzero','plain-list','plain-dict-spoof',
       'tuple-empty','tuple-full','tuple-nested','ScalarABI','ScalarABI-unvalidated','GenerationInfo','PosixPath','Path-derived',
       'class','class-tuple','class-ScalarABI','object','object-fake-class-field','unicode-class','long-class',
       'str-empty','str-full','bytes-empty','bytes-full','iterator-keys','iterator-items','iterator-values')

def behavior(output):
    from tools.qualify_hia_result_value_records import Values,NativeEngine
    from tools.qualify_hia_multiversion_components import Image
    from hepta.hia_background_optimizer import _OptimizationFuture,PublicationCancellation
    image=Image(output/'hia-future-public.core.bin');rows=[]
    for case in CASES:
        for mode in ('result','exception'):
            v=Values(NativeEngine(output/'hia-result-value.core.bin'));p=Public(v,image);fac=p.factory();f=p.make(fac)
            expected=_OptimizationFuture(PublicationCancellation())
            cap,py=construct(v,case);empty=v.scalar(None);kind=word(v.raw(7,a=cap),16)
            assert not (case=='tuple-empty' and bool(py))
            getattr(expected,'set_'+mode)(py);r=p.call(22 if mode=='result'else 23,*f,value=cap,kind=1)
            assert word(r,8)==0
            stable_caps=word(v.raw(47),48)
            native_id=word(p.call(21,*f),96)
            for method,op in (('result',10),('exception',11)):
                want=original_call(expected,method);got=p.call(op,*f,status=want['status'])
                if want['status']:
                    assert error_value(v,got)==want['error'],(case,mode,method,want)
                elif word(got,72):
                    returned=v.keep(got,72)
                    if method==mode:assert identity(v,returned)==identity(v,cap),(case,mode,method)
                    else:assert v.python(returned)is None
                    v.drop(returned)
                else:assert want['value']is None,(case,mode,method)
            for method,op in (('set_result',22),('set_exception',23)):
                want=original_call(expected,method,None)
                assert want['status']==1 and want['error']['class']=='InvalidStateError'
                want['error']['message']=want['error']['message'].replace(hex(id(expected)),hex(native_id))
                got=p.call(op,*f,value=empty,kind=1,status=1);actual=error_value(v,got)
                assert actual==want['error'],(case,mode,method,actual,want['error'])
            assert word(v.raw(47),48)==stable_caps,(case,mode,'unaccounted temporary caps',word(v.raw(47),48),stable_caps)
            p.finish();v.finish()
            rows.append(dict(case=case,mode=mode,value_kind=kind,python_truth=bool(py),python_type=type(py).__name__,
                             result_identity=True,exception_is_not_none=True,invalid_state_repr_exact=True,
                             all_caps_consumed=True,arena_unmapped=True,passed=True))
            print('FUTURE_VALUE_KIND',case,mode,flush=True)
    deferred=[]
    for method in ('__bool__','__len__'):
        for return_value in (False,True)if method=='__bool__'else(0,3):
            v=Values(NativeEngine(output/'hia-result-value.core.bin'));p=Public(v,image);fac=p.factory();f=p.make(fac)
            name='Override_'+method.strip('_')+'_'+str(return_value)
            pycls=type(name,(),{method:lambda self,value=return_value:value});py=pycls()
            expected=_OptimizationFuture(PublicationCancellation());expected.set_exception(py)
            cls=v.cls(name,[]);placeholder=v.scalar(101);v.attr(cls,method,placeholder);cap=v.instance(cls);empty=v.scalar(None)
            p.call(23,*f,value=cap,kind=1)
            want=original_call(expected,'set_result',None);assert want['status']==1
            got=p.call(22,*f,value=empty,kind=1,status=1)
            assert word(got,16)==107 and word(got,72)==0 and word(p.ctx.raw,200)==0
            # The original oracle remains in the qualification ledger as pending.
            deferred.append(dict(case=name,python_truth=bool(py),python_error=want['error'],native_status=word(got,8),
                native_kind=word(got,16),actual_equivalence=False,reason='native callable capture/bound dispatch is not connected'))
            p.finish();v.finish()
    return rows,deferred


def kernel_and_private_cases(output):
    import errno, resource, signal, traceback
    from tools.qualify_hia_result_value_records import Values,NativeEngine
    from tools.qualify_hia_multiversion_components import Image
    from tools.generate_hia_result_value_records_packer import BRIDGE as value_bridge
    image=Image(output/'hia-future-public.core.bin')
    value_at=279+struct.unpack_from('<i',image.raw,275)[0]
    assert image.raw[value_at:value_at+len(value_bridge)]==(output/'hia-result-value.core.bin').read_bytes()[:len(value_bridge)]
    value_code=image.address+value_at
    public_code=image.address
    libc=C.CDLL(None,use_errno=True)
    libc.ptrace.argtypes=[C.c_uint,C.c_uint,C.c_void_p,C.c_void_p];libc.ptrace.restype=C.c_long
    class Registers(C.Structure):
        _fields_=[(n,C.c_ulonglong)for n in (
            'r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax',
            'rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]
    def ptrace(req,pid,a=0,b=0):
        C.set_errno(0)
        result=libc.ptrace(req,pid,C.c_void_p(a),C.cast(b,C.c_void_p)if not isinstance(b,int)else C.c_void_p(b))
        assert result!=-1 or C.get_errno()==0,(req,pid,C.get_errno())
        return result
    def peek(pid,at):return C.c_ulonglong(ptrace(2,pid,at,0)).value
    def free_bytes(v):
        start=word(v.engine.context.raw,16);count=0
        for k in range(6,64):
            at=C.c_uint64.from_address(start+512+k*8).value
            while at:
                count+=1<<k;at=C.c_uint64.from_address(start+at+16).value
        return count
    rows=[]
    for case in ('record-mmap-enomem','type-name-growth-enomem','record-munmap-einval-retry','record-read-esrch-retry'):
        readfd,writefd=os.pipe();pid=os.fork()
        if pid==0:
            try:
                os.close(readfd);signal.alarm(120)
                v=Values(NativeEngine(output/'hia-result-value.core.bin'));p=Public(v,image);fac=p.factory();f=p.make(fac)
                value=v.tuple([]);empty=v.scalar(None);p.call(22,*f,value=value,kind=1)
                tokens=[]
                if case=='type-name-growth-enomem':
                    while free_bytes(v)>384:
                        tokens.append(struct.unpack_from('<3Q',v.raw(21),24))
                        assert len(tokens)<200000
                before=word(v.raw(47),48);arena=(word(v.engine.context.raw,16),word(v.engine.context.raw,40))
                limits=resource.getrlimit(resource.RLIMIT_AS)
                virtual=int(Path('/proc/self/statm').read_text().split()[0])*os.sysconf('SC_PAGE_SIZE')
                resource.setrlimit(resource.RLIMIT_AS,(virtual+(64<<20),limits[1]))
                ptrace(0,0);os.kill(os.getpid(),signal.SIGSTOP)
                got=p.call(22,*f,value=empty,kind=1,status=1)
                if case.endswith('enomem'):
                    assert word(got,16)==103,(case,got[:128].hex())
                    assert word(p.ctx.raw,200)==0
                    assert word(v.raw(47),48)==before
                    assert (word(v.engine.context.raw,16),word(v.engine.context.raw,40))==arena
                else:
                    assert word(got,16)==107 and word(got,120)==(1<<64)-1
                    assert word(p.ctx.raw,200)==1
                    assert word(v.raw(47),48)==before,('lost unpublished error or type cap',before,word(v.raw(47),48))
                    closed=p.call(18,status=1)
                    assert word(closed,16)==107 and word(closed,120)==(1<<64)-1
                    retry=p.call(20,status=1)
                    assert word(retry,16)==107 and word(retry,120)==(1<<64)-1 and word(p.ctx.raw,200)==1
                os.kill(os.getpid(),signal.SIGSTOP)
                resource.setrlimit(resource.RLIMIT_AS,limits)
                for token in tokens:v.raw(30,a=token)
                quarantine_private_controls=0
                if not case.endswith('enomem'):
                    if case=='record-read-esrch-retry':
                        registry=f[0][0]+200
                        original=C.string_at(registry,32)
                        head,tag0,tag1,extent=struct.unpack('<4Q',original)
                        assert head and head%4096==0 and extent==4096 and (tag0 or tag1)
                        for at,invalid in ((0,0),(0,1),(0,4096),(8,tag0^1),(16,tag1^1),(24,0),(24,4095),(24,8192)):
                            altered=bytearray(original);struct.pack_into('<Q',altered,at,invalid)
                            C.memmove(registry,bytes(altered),32)
                            refused=p.call(20,status=1)
                            assert word(refused,16)==107 and word(refused,120)==(1<<64)-1
                            assert C.string_at(registry,32)==bytes(altered)
                            assert word(p.ctx.raw,200)==1 and word(v.raw(47),48)==before
                            C.memmove(registry,original,32)
                            quarantine_private_controls+=1
                        copied=Public.__new__(Public);copied.value=v;copied.image=image
                        copied.ctx=C.create_string_buffer(p.ctx.raw,256);copied.calls=0
                        refused=copied.call(20,status=1)
                        assert word(refused,16)==107 and C.string_at(registry,32)==original
                        assert word(p.ctx.raw,200)==1 and word(v.raw(47),48)==before
                        quarantine_private_controls+=1
                    retry=p.call(20)
                    assert word(retry,120)==0 and word(p.ctx.raw,200)==0
                got=p.call(22,*f,value=empty,kind=1,status=1)
                assert error_value(v,got)['class']=='InvalidStateError'
                p.finish();v.finish()
                os.write(writefd,json.dumps(dict(passed=True,case=case,all_temporary_caps_consumed=True,
                    registry_empty=True,arena_unmapped=True,real_retry_completed=True,
                    quarantine_private_controls=quarantine_private_controls)).encode())
                os.close(writefd);os._exit(0)
            except BaseException:
                try:os.write(writefd,traceback.format_exc().encode())
                except BaseException:pass
                os._exit(71)
        os.close(writefd)
        _,state=os.waitpid(pid,0);assert os.WIFSTOPPED(state),(case,state)
        ptrace(0x4200,pid,0,0x100001)
        entering=True;armed=True;forced=[];forcing=None;owned={};allocation=None
        while True:
            ptrace(24,pid);_,state=os.waitpid(pid,0)
            if os.WIFEXITED(state)or os.WIFSIGNALED(state):break
            sig=os.WSTOPSIG(state)
            if sig==(signal.SIGTRAP|128):
                regs=Registers();ptrace(12,pid,0,C.byref(regs))
                if entering:
                    forcing=None;allocation=None
                    public=0<=regs.rip-public_code<800
                    phase=peek(pid,regs.r13+128)if public else 0
                    if ((public and phase in (1500,1571,1622))or 2283<=regs.rip-public_code<2458)and regs.orig_rax in(9,11):
                        allocation=(regs.orig_rax,regs.rdi,regs.rsi)
                    if armed and case=='record-mmap-enomem'and public and regs.orig_rax==9 and phase==1500:
                        regs.rsi=1<<60;forcing=(9,phase,-errno.ENOMEM)
                    elif armed and case=='type-name-growth-enomem'and 0<=regs.rip-value_code<len(value_bridge)and regs.orig_rax==25:
                        op=peek(pid,regs.r12+8)
                        if op in(36,38):
                            regs.rdx=1<<40;forcing=(25,op,-errno.ENOMEM)
                    elif armed and case in ('record-munmap-einval-retry','record-read-esrch-retry')and public:
                        if regs.orig_rax==11 and (phase==1571 or(case=='record-munmap-einval-retry'and phase==1622)):
                            regs.rdi+=1;forcing=(11,phase,-errno.EINVAL)
                        elif case=='record-read-esrch-retry'and regs.orig_rax==310 and phase==1602:
                            regs.rdi=(1<<31)-1;forcing=(310,phase,-errno.ESRCH)
                    if forcing:ptrace(13,pid,0,C.byref(regs))
                else:
                    if forcing:
                        actual=C.c_longlong(regs.rax).value
                        assert actual==forcing[2],(case,forcing,actual)
                        forced.append(dict(syscall=forcing[0],continuation=forcing[1],errno=-actual));forcing=None
                    if allocation:
                        number,address,size=allocation
                        if number==9 and regs.rax<(1<<63):owned[regs.rax]=size
                        if number==11 and regs.rax==0 and address in owned:
                            assert owned.pop(address)==size
                        allocation=None
                entering=not entering
            elif sig==signal.SIGSTOP:
                assert armed;armed=False
            else:raise AssertionError((case,'unexpected signal',sig))
        data=b''
        while True:
            part=os.read(readfd,65536)
            if not part:break
            data+=part
        os.close(readfd)
        assert os.WIFEXITED(state)and os.WEXITSTATUS(state)==0,(case,state,data.decode(errors='replace'),forced,owned)
        assert not owned,('owned mapping leaked after actual retry',case,owned)
        assert forced and not armed,(case,forced)
        if case=='type-name-growth-enomem':assert all(row['syscall']==25 for row in forced)
        if case in ('record-munmap-einval-retry','record-read-esrch-retry'):assert len(forced)==2,(case,forced)
        row=json.loads(data);row['actual_kernel_errors']=forced;row['owned_mapping_count_after_retry']=len(owned)
        rows.append(row);print('FUTURE_KIND_KERNEL',case,forced,flush=True)
    # These are explicit private-input negative controls, separate from fault
    # injection. No product code, status or lock word is patched in the OS cases.
    v=Values(NativeEngine(output/'hia-result-value.core.bin'));p=Public(v,image);fac=p.factory();f=p.make(fac)
    before=word(v.raw(47),48);controls=0
    for bad in (1,4096,(1<<64)-1):
        C.c_uint64.from_address(C.addressof(p.ctx)+200).value=bad
        for op in (18,20):
            out=p.call(op,status=1)
            assert word(out,16)==107 and word(out,120)==(1<<64)-1
            assert word(p.ctx.raw,200)==bad and word(v.raw(47),48)==before
            controls+=1
        C.c_uint64.from_address(C.addressof(p.ctx)+200).value=0
    copied=Public.__new__(Public);copied.value=v;copied.image=image;copied.ctx=C.create_string_buffer(p.ctx.raw,256);copied.calls=0
    snapshot=p.ctx.raw
    for op in (18,20):
        out=copied.call(op,status=1)
        assert word(out,16)==107 and p.ctx.raw==snapshot and word(v.raw(47),48)==before
        controls+=1
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(readfd);out=p.call(20,status=1);assert word(out,16)==107 and p.ctx.raw==snapshot
            os.write(writefd,b'OK');os._exit(0)
        except BaseException:os._exit(71)
    os.close(writefd);_,state=os.waitpid(pid,0);message=os.read(readfd,32);os.close(readfd)
    assert os.WIFEXITED(state)and os.WEXITSTATUS(state)==0 and message==b'OK'
    controls+=1;p.finish();v.finish()
    rows.append(dict(case='reserved-count-context-copy-and-fork',controls=controls,passed=True,
                     no_untrusted_pointer_dereference=True,all_temporary_caps_consumed=True,arena_unmapped=True))
    return rows


def actual_drop_contention_case(output):
    import select, signal, threading, traceback
    from tools.qualify_hia_result_value_records import Values,NativeEngine,frame
    from tools.qualify_hia_multiversion_components import Image
    from tools.generate_hia_result_value_records_packer import BRIDGE as value_bridge
    from tools.qualify_hia_native_seccomp_notify import install,receive,continue_syscall
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(readfd);signal.alarm(120)
            image=Image(output/'hia-future-public.core.bin')
            v=Values(NativeEngine(output/'hia-result-value.core.bin'));p=Public(v,image);fac=p.factory();f=p.make(fac)
            value=v.tuple([]);empty=v.scalar(None);p.call(22,*f,value=value,kind=1)
            baseline=word(v.raw(47),48)
            value_offset=279+struct.unpack_from('<i',image.raw,275)[0]
            embedded=image.address+value_offset
            standalone=v.engine.image.address
            ready=threading.Event();go=threading.Event();worker_done=threading.Event()
            main_ready=threading.Event();stop=threading.Event()
            worker_fd=[];main_fd=[];worker_result=[];errors=[];events=[]
            def worker():
                try:
                    fd=install(standalone,standalone+len(value_bridge),318)
                    worker_fd.append(fd);ready.set();assert go.wait(30)
                    rc,out=v.engine.call(frame(36,a=value))
                    assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==0
                    worker_result.append(out)
                except BaseException:errors.append(traceback.format_exc())
                finally:worker_done.set()
            def controller():
                held=None;tripped=False
                try:
                    assert main_ready.wait(30)and ready.wait(30)
                    while not stop.is_set():
                        listeners=[main_fd[0]]+([]if worker_done.is_set()else[worker_fd[0]])
                        fds,_,_=select.select(listeners,[],[],0.1)
                        for fd in fds:
                            if fd==worker_fd[0]and worker_done.is_set():continue
                            notification=receive(fd)
                            if fd==worker_fd[0]:
                                assert held is None and notification.data.nr==318
                                held=notification
                                assert word(v.engine.context.raw,32)==1
                                events.append('native-auxiliary-value-lock-held-at-real-getrandom')
                                continue
                            assert notification.data.nr==39
                            phase=C.c_uint64.from_address(p.output_address+128).value
                            if phase==1560 and not tripped:
                                tripped=True;go.set()
                                while held is None:
                                    readyfds,_,_=select.select([worker_fd[0]],[],[],10)
                                    assert readyfds
                                    held=receive(worker_fd[0]);assert held.data.nr==318
                                    assert word(v.engine.context.raw,32)==1
                                    events.append('native-auxiliary-value-lock-held-at-real-getrandom')
                                events.append('future-op29-entered-while-real-value-lock-held')
                                continue_syscall(fd,notification)
                                continue
                            if held is not None:
                                assert phase==1401,(phase,events)
                                assert word(p.ctx.raw,200)==1
                                events.append('actual-futex-policy-failure-retained-temporary-caps')
                                continue_syscall(worker_fd[0],held);held=None
                                while not worker_done.is_set():
                                    more,_,_=select.select([worker_fd[0]],[],[],0.05)
                                    if more and not worker_done.is_set():continue_syscall(worker_fd[0],receive(worker_fd[0]))
                                assert worker_result and not errors,errors
                            continue_syscall(fd,notification)
                    assert tripped and held is None,events
                except BaseException:
                    errors.append(traceback.format_exc())
                    print('CONTROLLER_FAILURE',traceback.format_exc(),file=sys.stderr,flush=True)
                    os.write(writefd,('CONTROLLER_FAILURE '+traceback.format_exc()).encode())
            worker_thread=threading.Thread(target=worker);control_thread=threading.Thread(target=controller)
            worker_thread.start();control_thread.start();assert ready.wait(30)
            main_fd.append(install(embedded,embedded+len(value_bridge),39,deny_private_wait=True))
            main_ready.set()
            result=p.call(22,*f,value=empty,kind=1,status=1)
            assert word(result,16)==107 and word(result,120)==(1<<64)-1 and word(p.ctx.raw,200)==1
            assert not errors,errors
            assert worker_done.is_set()and len(worker_result)==1
            worker_cap=v.keep(worker_result[0])
            retained=word(v.raw(47),48)
            assert retained==baseline+3,('two actual pending type/name caps plus worker result',baseline,retained)
            forbidden=p.call(18,status=1)
            assert word(forbidden,16)==107 and word(forbidden,120)==(1<<64)-1
            retried=p.call(20)
            assert word(retried,120)==0 and word(p.ctx.raw,200)==0
            assert word(v.raw(47),48)==baseline+1
            v.drop(worker_cap)
            result=p.call(22,*f,value=empty,kind=1,status=1)
            assert error_value(v,result)['class']=='InvalidStateError'
            p.finish();v.finish()
            stop.set();worker_thread.join(10);control_thread.join(10)
            assert not worker_thread.is_alive()and not control_thread.is_alive()and not errors,errors
            os.close(main_fd[0]);os.close(worker_fd[0])
            row=dict(case='actual-value-mutex-contention-drop29-kernel-eacces-and-native-retry',passed=True,
                actual_seccomp_policy_errno=13,events=events,retained_type_and_name_caps=2,
                exact_tickets_revalidated=True,pending_mapping_checked_separately=True,
                all_caps_consumed=True,registry_empty=True,arena_unmapped=True,
                no_product_code_mutex_word_or_return_modified=True)
            os.write(writefd,json.dumps(row).encode());os.close(writefd);os._exit(0)
        except BaseException:
            try:os.write(writefd,traceback.format_exc().encode())
            except BaseException:pass
            os._exit(71)
    os.close(writefd);_,state=os.waitpid(pid,0);data=b''
    while True:
        part=os.read(readfd,65536)
        if not part:break
        data+=part
    os.close(readfd)
    assert os.WIFEXITED(state)and os.WEXITSTATUS(state)==0,(state,data.decode(errors='replace'))
    result=json.loads(data);print('FUTURE_KIND_DROP_CONTENTION_PASS',flush=True);return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler',required=True)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--build-only',action='store_true')
    parser.add_argument('--reuse-build',action='store_true')
    args=parser.parse_args();output=args.output.resolve()
    assert platform.system()=='Linux' and platform.machine()=='x86_64'
    assert platform.python_version()=='3.14.4'
    if args.reuse_build:
        result=json.loads((output/'build.json').read_bytes())
        for name,expected in result['source_files'].items():assert digest((ROOT/name).read_bytes())==expected,name
        for name,expected in result['products'].items():assert pin((output/name).read_bytes())==expected,name
    else:
        output.mkdir(parents=True,exist_ok=False);result=build(args.compiler,output)
    if args.build_only:return
    rows,deferred=behavior(output)
    kernel_cases=kernel_and_private_cases(output)
    kernel_cases.append(actual_drop_contention_case(output))
    report=dict(schema='hepta.hia.future-value-kinds-qualification.v1',component_qualified=True,
        whole_public_future_closed=False,whole_native_runtime=False,final_aggregate_claimed=False,
        scope='actual native default Value kind protocols and retained original Future oracle',
        compiler=result['compiler'],modules=result['modules'],source_files=result['source_files'],
        value_image_sha256=result['products']['hia-result-value.core.bin']['sha256'],
        public_product=result['products']['hia-future-public.core.bin'],build_report_sha256=digest((output/'build.json').read_bytes()),
        cases=rows,case_count=len(rows),passed_count=sum(row['passed']for row in rows),
        deferred_original_semantics=deferred,
        kernel_and_private_cases=kernel_cases,
        dynamic_truth_callable_closed=False,unknown_drop_quarantine_retry_closed=False,
        mapping_quarantine_retry_qualified=True,known_unconsumed_cap_retry_qualified=True,
        unknown_receipt_handling='same exact-ticket lookup and pending-state checks; an unknown receipt is not fabricated from the fixed native Value',
        python_version=sys.version,oracle_sha256=digest((ROOT/'hepta/hia_background_optimizer.py').read_bytes()))
    put_json(output/'results.json',report)
    if args.receipt:
        target=args.receipt.resolve();target.relative_to(ROOT);put_json(target,report)
    print('FUTURE_VALUE_KINDS_PASS',len(rows),'DEFERRED_CALLABLE',len(deferred),flush=True)

if __name__=='__main__':main()
