"""Original path comparisons with exact author or actual native components.

Author mode executes the real machine-code mechanical capsule, but both HIA
policies and the value engine are development interpreters. It is deliberately
reported as mechanical/author evidence, never native HIA qualification.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,mmap,os,platform,struct,sys,traceback
ROOT=Path(__file__).resolve().parents[1]
VALUE=ROOT.parent/'native_value_extension/tree'
ORIGINAL=ROOT.parents[1]/'root_native_recovery'
sys.path[:0]=[str(ROOT),str(VALUE),str(ORIGINAL)]
import tools
tools.__path__=[str(ROOT/'tools'),str(VALUE/'tools'),str(ORIGINAL/'tools')]
from tools import generate_hia_native_path_value as owner
from tools import generate_hia_native_path_value_error as error
from tools import generate_hia_native_path_value_packer as packer
from tools.qualify_hia_result_value_dict_iterator import AuthorEngine,NativeEngine,Values,wire,word,put
MASK=(1<<64)-1
SIG=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
ZERO=(0,0,0)
def view(p,n):return memoryview((C.c_ubyte*n).from_address(p or 0)).cast('B')
def ptr(x):return C.cast(x,C.c_void_p).value
def caps(b,p):return struct.unpack_from('<3Q',b,p)
def original(value,mode):
    try:
        result=os.fspath(value)if mode==0 else Path(value)
        if mode==1:
            assert len(result._raw_paths)==1
            result=result._raw_paths[0]
        return ('ok',result)
    except TypeError as exc:return ('type',str(exc))
    except BaseException as exc:return ('raised',exc)
class Flat:
    def __init__(self,raw):
        self.raw=raw;self.m=mmap.mmap(-1,len(raw),prot=7);self.m.write(raw)
        self.v=(C.c_ubyte*len(raw)).from_buffer(self.m);self.f=SIG(C.addressof(self.v))
class Pipeline:
    def __init__(self,image=None,value_image=None):
        self.failures=[];self.value_faults=[];self.drop_faults=[];self.callbacks=[];self.callback_calls=0
        self.engine=NativeEngine(value_image)if value_image else AuthorEngine()
        self.values=Values(self.engine);self.context=C.create_string_buffer(256)
        self.value_func=SIG(self.value_call)
        self.w=C.create_string_buffer(4096)
        for at,x in((0,int.from_bytes(b'HIANPVC1','little')),(8,ptr(self.value_func)),(16,C.addressof(self.context)),(24,256),(32,os.getpid())):put(self.w,at,x)
        self.munmap_faults=0;self.munmap_injected=0;self.mmap_faults=set();self.callback_fault=None
        if image:self.image=Flat(Path(image).read_bytes())
        else:
            ns=dict(length=len,byte=lambda b,i:b[i],store=lambda b,i,v:b.__setitem__(i,v&255),word_load=word,word_store=put)
            exec('from __future__ import annotations\n'+owner.source_program(),ns);self.owner_ns=ns
            errns=dict(ns);exec('from __future__ import annotations\n'+error.source_program(),errns);self.error_ns=errns
            self.policy_func=SIG(self.policy_call);self.error_func=SIG(self.error_call)
            trampoline=lambda f:b'\x48\xb8'+struct.pack('<Q',ptr(f))+b'\xff\xe0'
            self.image=Flat(packer.reference_flat([trampoline(self.policy_func),trampoline(self.error_func)]))
    def value_call(self,s,sn,o,on,w,wn):
        try:
            assert w==C.addressof(self.context)and wn==256
            raw=C.string_at(s,sn);op=word(raw,8)
            if self.value_faults and self.value_faults[0][0]==op:
                _,reply=self.value_faults.pop(0);C.memmove(o,reply,len(reply));return 0
            if self.drop_faults and op in(29,31):
                fault=self.drop_faults.pop(0)
                if fault.get('consume'):
                    rc,data=self.engine.call(raw,on);assert rc==0 and word(data,96)==1
                reply=bytearray(128);reply[:8]=b'HIABVR02'
                for at,x in((8,fault.get('status',11)),(80,fault.get('pending',0)),(88,fault.get('known',1)),(96,fault.get('consumed',int(fault.get('consume',False))))):put(reply,at,x)
                C.memmove(o,bytes(reply),128);return 0
            rc,data=self.engine.call(raw,on);C.memmove(o,data,len(data));return rc
        except BaseException:
            self.failures.append(traceback.format_exc());return 0xfffffffd
    def policy_call(self,s,sn,o,on,w,wn):
        try:
            ov,wv=view(o,on),view(w,wn)
            rc=self.owner_ns['native_path_value'](view(s,sn),ov,wv)
            if rc==1 and word(ov,128)==9 and word(ov,256) in self.mmap_faults:
                self.mmap_faults.remove(word(ov,256));put(ov,3840,(-12)&MASK);return 10
            if rc==1 and word(ov,128)==11 and self.munmap_faults:
                self.munmap_faults-=1;self.munmap_injected+=1;put(ov,3840,(-5)&MASK);return 10
            return rc
        except BaseException:self.failures.append(traceback.format_exc());return 0xfffffffd
    def error_call(self,s,sn,o,on,w,wn):
        try:return self.error_ns['native_path_value_error'](view(s,sn),view(o,on),view(w,wn))
        except BaseException:self.failures.append(traceback.format_exc());return 0xfffffffd
    def convert(self,cap=ZERO,mode=0):
        raw=bytearray(128);raw[:8]=b'HIANPV01';put(raw,8,mode);struct.pack_into('<3Q',raw,16,*cap)
        s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(b'\xa5'*(32768+32));before=self.w.raw[:128]
        rc=self.image.f(s,128,o,32768,self.w,4096)
        assert not self.failures,self.failures
        assert rc==0,(rc,o.raw[:128].hex(),word(self.w,128))
        assert o.raw[:8]==b'HIANPVR1'and o.raw[32768:]==b'\xa5'*32+b'\0'
        assert self.w.raw[:128]==before and s.raw==bytes(raw)+b'\0'
        return o.raw[:128]
    def read(self,cap):
        rc,out=self.engine.call(wire(7,a=cap));assert rc==0 and word(out,8)==0
        n=word(out,72);rc,data=self.engine.call(wire(19,a=cap,arg1=n),max(16384,8192+n));assert rc==0 and word(data,8)==0
        return data[8192:8192+n]
    def adopt(self,cap):assert cap[0]and cap not in self.values.held;self.values.held.add(cap)
    def native_object(self,name,method=None,base=None,expected_env=None):
        v=self.values;env=v.scalar(37);class_name=v.scalar(name);basecap=v.scalar(base)if base is not None else ZERO
        entry=0
        if method is not None:
            def invoke(s,sn,o,on,w,wn):
                try:
                    raw=C.string_at(s,sn);ctx=C.string_at(w,128)
                    assert sn==128 and raw[:8]==b'HIAPFSP1'and raw[8:16]==bytes(8)and raw[64:]==bytes(64)
                    assert wn==4096 and ctx[:8]==b'HIANPFC1'and ctx[8:40]==self.w.raw[8:40]and ctx[40:]==bytes(88)
                    assert self.values.python(caps(raw,40))==37
                    self.callback_calls+=1;status,result=method()
                    rc,data=self.engine.call(wire(5,a=result));assert rc==0 and word(data,8)==0
                    reply=bytearray(128);reply[:8]=b'HIAPFSR1';put(reply,8,status);struct.pack_into('<3Q',reply,16,*caps(data,24))
                    if self.callback_fault=='bad-context':put(view(w,wn),40,1)
                    if self.callback_fault=='bad-magic':reply[0]^=1
                    if self.callback_fault=='bad-reserved':put(reply,40,1)
                    if self.callback_fault=='borrowed-cap':struct.pack_into('<3Q',reply,16,*caps(raw,16))
                    C.memmove(o,bytes(reply),128);return 0
                except BaseException:self.failures.append(traceback.format_exc());return 0xfffffffd
            callback=SIG(invoke);self.callbacks.append(callback);entry=ptr(callback)
        out=v.raw(25,a=env,b=basecap,c=class_name,arg0=4 if type(base)is str else 7 if type(base)is bytes else 0,arg1=entry)
        result=v.keep(out)
        for c in(env,class_name,basecap):
            if c!=ZERO:v.drop(c)
        return result
    def check(self,actual_cap,python_value,mode):
        expected=original(python_value,mode);out=self.convert(actual_cap,mode);status=word(out,8)
        assert word(out,96)==word(out,104)==0,out.hex()
        if expected[0]=='ok':
            assert status==0,(expected,out.hex())
            cap=caps(out,16);self.adopt(cap);raw=self.read(cap)
            assert raw==(expected[1].encode('utf-8','surrogatepass')if isinstance(expected[1],str)else expected[1]),(raw,expected)
            if isinstance(python_value,(str,bytes)):
                assert self.values.raw(8,a=actual_cap,b=cap)[48]==1
            self.values.drop(cap)
        elif expected[0]=='type':
            assert status==1,(expected,out.hex())
            cap=caps(out,64);self.adopt(cap);data=json.loads(self.read(cap));self.values.drop(cap)
            assert data==dict(type='TypeError',message=expected[1]),(data,expected)
        else:assert status==2,(expected,out.hex())
        return dict(mode=mode,expected=expected[0],status=status)
    def finish(self):
        assert word(self.w,128)==0 and word(self.w,136)==0
        self.values.finish()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image');ap.add_argument('--value-image');ap.add_argument('--output',required=True);args=ap.parse_args()
    if bool(args.image)!=bool(args.value_image):ap.error('both actual native images are required together')
    dest=Path(args.output);dest.mkdir(parents=True,exist_ok=False);rows=[]
    p=Pipeline(args.image,args.value_image);v=p.values
    for value in(None,False,True,-1,3.25,'','simple','a\0b','汉字\ud800',b'',b'abc',b'\xff'):
        cap=v.scalar(value)
        for mode in(0,1):rows.append(p.check(cap,value,mode))
        v.drop(cap)
    # Actual iterator modes come from live kind9 object metadata, not guesses.
    for mode in range(3):
        d=v.dictionary([('a',1)]);iterator=v.iterator(d,mode);original_dict={'a':1}
        pyiter=iter(original_dict)if mode==0 else iter(original_dict.items())if mode==1 else iter(original_dict.values())
        info=v.raw(7,a=iterator);assert word(info,16)==9 and word(info,56)==mode and word(info,72)==0
        for op in(0,1):rows.append(p.check(iterator,pyiter,op))
        assert v.next(iterator,mode)==('value','a' if mode==0 else ('a',1) if mode==1 else 1)
        v.drop(iterator);v.drop(d)
    for name in('Missing','a.b','汉字🙂','x'*201,'a'*199+'汉','q\n\"'):
        obj=p.native_object(name);py=type(name,(),{})()
        for mode in(0,1):rows.append(p.check(obj,py,mode))
        v.drop(obj)
    # Real source and result references survive descriptor acquisition/drop.
    for value in('','returned','汉字\ud800',b'returned',None,3):
        result=v.scalar(value);obj=p.native_object('ActualPathLike',lambda result=result:(0,result))
        py=type('ActualPathLike',(),{'__fspath__':lambda self,value=value:value})()
        for mode in(0,1):rows.append(p.check(obj,py,mode))
        v.drop(obj);v.drop(result)
    for base in('subclass',b'subclass'):
        cls=type('OverridesFspath',(str if type(base)is str else bytes,),{'__fspath__':lambda self:None})
        result=v.scalar(None);obj=p.native_object('OverridesFspath',lambda:(0,result),base)
        before=p.callback_calls
        for mode in(0,1):rows.append(p.check(obj,cls(base),mode))
        assert p.callback_calls==before
        v.drop(obj);v.drop(result)
    # Each raised object is the same retained identity on propagation. Path
    # catches TypeError before issuing its own full-name TypeError.
    for exc in(TypeError('actual'),ValueError('actual'),KeyboardInterrupt('actual')):
        exception=p.native_object(type(exc).__name__);status=1 if isinstance(exc,TypeError) else 2
        def raiser(self,exc=exc):raise exc
        obj=p.native_object('Raises',lambda:(status,exception));py=type('Raises',(),{'__fspath__':raiser})()
        for mode in(0,1):
            expected=original(py,mode);out=p.convert(obj,mode)
            if expected[0]=='type'and mode==1:
                assert word(out,8)==1;cap=caps(out,64);p.adopt(cap);assert json.loads(p.read(cap))['message']==expected[1];v.drop(cap)
            else:
                assert word(out,8)==2;cap=caps(out,40);p.adopt(cap);assert word(v.raw(8,a=cap,b=exception),48)==1;v.drop(cap)
            rows.append(dict(mode=mode,expected='original-exception-identity',status=word(out,8)))
        v.drop(obj);v.drop(exception)
    p.finish()
    # Retry resumes only cleanup. The method is never repeated.
    for fault in('known-drop-error','mapping-unmap-error'):
        p=Pipeline(args.image,args.value_image);v=p.values;result=v.scalar('done');obj=p.native_object('Retry',lambda:(0,result))
        if fault=='known-drop-error':p.drop_faults=[dict(status=11,consumed=0)]
        elif args.image:continue # actual munmap fault qualifier is separate
        else:p.munmap_faults=1
        out=p.convert(obj);assert word(out,8)==4 and word(out,96)==1 and word(out,104)==0 and p.callback_calls==1
        out=p.convert(mode=2);assert word(out,8)==0 and word(out,96)==0 and p.callback_calls==1
        cap=caps(out,16);p.adopt(cap);assert p.read(cap)==b'done';v.drop(cap);v.drop(obj);v.drop(result);p.finish()
        rows.append(dict(name=fault,method_calls=1,passed=True))
    report=dict(schema='hia.native-path-value.component.qualification.v1',scope='actual-native-components'if args.image else'actual-mechanical-bridge-with-development-authors',native_hia_executed=bool(args.image),python=platform.python_version(),passed=len(rows),rows=rows,whole_pathlike_closed=False,purepath_factory_closed=False)
    (dest/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in('scope','native_hia_executed','passed')}),flush=True)
if __name__=='__main__':main()
