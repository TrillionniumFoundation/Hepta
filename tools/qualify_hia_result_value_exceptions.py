"""Actual native exception capture, real classes, strong edges and failure facts.

This gate captures already materialized exception args/namespace. It does not
claim Python constructor auto-specialization, formatting, or traceback support.
"""
from pathlib import Path
import argparse, ctypes as C, hashlib, json, platform, queue, struct, threading
from tools.qualify_hia_result_value_resources import Values as PriorValues, NativeEngine, frame as prior_frame, word, ZERO
from tools.qualify_hia_native_callable_code_owner import deny_native
from tools import generate_hia_result_value_callables_packer as original_pack
from tools import generate_hia_result_value_invocations_packer as invocation_pack
from hepta.hia_program import HIAProgramRejected
from hepta.hia_multiversion import MultiversionRejected

def frame(op, **kw):
    raw=bytearray(prior_frame(op,**kw))
    if op>=48:raw[:8]=b'HIABVQ05'
    return bytes(raw)

class GuardEngine(NativeEngine):
    def call(self,request,on=16384):
        source=C.create_string_buffer(request)
        output=C.create_string_buffer(b'\xa5'*(on+64))
        rc=int(self.image.entry(source,len(request),output,on,self.context,len(self.context)))&0xffffffff
        assert source.raw==request+b'\0'
        assert output.raw[on:]==b'\xa5'*64+b'\0'
        self.calls+=1
        return rc,output.raw[:on]

class Values(PriorValues):
    def raw(self,op,*,want=0,on=16384,**kw):
        rc,out=self.engine.call(frame(op,**kw),on=on)
        assert rc==0 and out[:8]==(b'HIABVR02'if 29<=op<=31 else b'HIABVR01'),(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want,out[:128].hex())
        return out
    def builtin(self,index):
        return self.keep(self.raw(87,arg0=index))if index>=38 else super().builtin(index)
    def exception(self,cls,args,namespace=ZERO):
        return self.keep(self.raw(75,a=cls,b=args,c=namespace))
    def parts(self,exception):
        out=self.raw(26,a=exception)
        assert word(out,8200)==0
        return [self.keep(out,8224+i*24)for i in range(3)]

def sweep(v):
    for cap in list(v.held):v.drop(cap)
    assert word(v.raw(47),48)==0

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert platform.python_version()=='3.14.4'
    args.output.mkdir(parents=True,exist_ok=False)
    v=Values(GuardEngine(args.image));rows=[]
    cases=[(21,BaseException),(22,Exception),(23,TypeError),(24,ValueError),(25,OSError),(26,RuntimeError),(27,MemoryError),(38,ArithmeticError),(39,OverflowError),(40,StopIteration),(41,MultiversionRejected),(42,HIAProgramRejected)]
    for index,cls in cases:
        actual=cls('message')if cls is HIAProgramRejected else cls('message',17)
        actual.hia_cleanup={'operation':'close','errno':5}
        nativecls=v.builtin(index)
        arguments=v.tuple([v.scalar(x)for x in actual.args])
        namespace=v.dictionary([])
        for key,value in vars(actual).items():
            if type(value)is dict:
                k=v.scalar(key);d=v.dictionary(list(value.items()));v.raw(10,a=namespace,b=k,c=d)
            else:v.set(namespace,key,value)
        cap=v.exception(nativecls,arguments,namespace)
        typ=v.keep(v.raw(36,a=cap));assert v.same(typ,nativecls)
        assert v.isinst(cap,v.builtin(21)) and v.isinst(cap,nativecls)
        env,stored,name=v.parts(cap)
        assert v.same(env,namespace) and v.same(stored,arguments)
        assert v.python_value(stored)==actual.args and v.python_value(env)==vars(actual)
        assert v.python(name)==type(actual).__name__
        alias=v.keep(v.raw(5,a=cap))
        for item in list(v.held):
            if item!=alias:v.drop(item)
        env,stored,name=v.parts(alias)
        assert v.python_value(stored)==actual.args and v.python_value(env)==vars(actual)
        sweep(v);rows.append(dict(case='real-class-captured-exception-and-retained-args-namespace',id=index,name=cls.__name__))
    base=v.builtin(24);sub=v.cls('ValueAlias',[base]);arguments=v.tuple([v.scalar('failure')])
    captured=v.exception(sub,arguments);assert v.isinst(captured,base)
    actualtype=v.keep(v.raw(36,a=captured));assert v.same(actualtype,sub)
    fake=v.cls('ValueError',[]);v.raw(75,a=fake,b=arguments,want=2)
    for wrong in (v.scalar('ValueError'),v.scalar(None),v.scalar(24)):
        v.raw(75,a=wrong,b=arguments,want=2)
    for wrong in (v.lst([]),v.scalar(None),v.dictionary([])):
        v.raw(75,a=base,b=wrong,want=2)
    v.raw(75,a=base,b=arguments,c=v.lst([]),want=2)
    v.raw(75,a=(1,2,3),b=arguments,want=1)
    v.raw(75,a=base,b=(1,2,3),want=1)
    v.raw(75,a=base,b=arguments,c=(1,2,3),want=1)
    sweep(v);rows.append(dict(case='real-exception-subclass-and-type-precedence'))
    cls=v.builtin(22);one=v.exception(cls,v.tuple([]));two=v.exception(cls,v.tuple([]))
    e1,a1,n1=v.parts(one);e2,a2,n2=v.parts(two)
    assert not v.same(e1,e2)
    v.set(e1,'trace',True);assert v.python_value(e1)=={'trace':True} and v.python_value(e2)=={}
    sweep(v);rows.append(dict(case='independent-default-dictionaries'))
    cls=v.builtin(24);namespace=v.dictionary([]);arguments=v.tuple([v.lst([])])
    cap=v.exception(cls,arguments,namespace);k=v.scalar('self');v.raw(10,a=namespace,b=k,c=cap)
    sweep(v);rows.append(dict(case='exception-namespace-and-tuple-cycle-real-collection'))
    cls=v.builtin(23);arguments=v.tuple([v.scalar('x')]);namespace=v.dictionary([])
    before=word(v.raw(47),48)
    image=args.image.read_bytes();matches=[]
    for candidate in (original_pack,invocation_pack):
        prefix=bytearray(image[:len(candidate.BRIDGE)])
        for at in candidate.HOLES:prefix[at:at+4]=bytes(4)
        if bytes(prefix)==candidate.BRIDGE:matches.append(candidate)
    assert len(matches)==1,[m.__name__ for m in matches]
    bridge=matches[0].BRIDGE
    sites=[i+2 for i in range(len(bridge)-1)if bridge[i:i+2]==b'\x0f\x05']
    assert len(sites)==1,sites
    ip=v.engine.image.address+sites[0]
    result=queue.Queue()
    def fail_random():
        try:
            deny_native(ip,318,5)
            out=v.raw(75,a=cls,b=arguments,c=namespace,want=11)
            assert out[24:48]==bytes(24)
            result.put(dict(status=11,no_cap_published=True))
        except BaseException as exc:result.put(exc)
    worker=threading.Thread(target=fail_random);worker.start();worker.join(30);assert not worker.is_alive()
    fault=result.get_nowait()
    if isinstance(fault,BaseException):raise fault
    assert word(v.raw(47),48)==before
    actual=v.exception(cls,arguments,namespace);v.drop(actual)
    sweep(v);rows.append(dict(case='native-getrandom-eio-before-publication',**fault))
    cls=v.builtin(24);arguments=v.tuple([v.scalar('x')]);namespace=v.dictionary([])
    result=queue.Queue()
    def fail_growth():
        owned=[]
        try:
            deny_native(ip,25,12)
            for index in range(10000):
                rc,out=v.engine.call(frame(75,a=cls,b=arguments,c=namespace))
                assert rc==0 and out[:8]==b'HIABVR01'
                status=word(out,8);cap=struct.unpack_from('<3Q',out,24)
                if status:
                    assert status==5 and cap==ZERO,(status,cap)
                    result.put(dict(successes=len(owned),status=status,no_hidden_cap=True,owned=owned));return
                assert all(cap);owned.append(cap)
            raise AssertionError('native arena mremap ENOMEM was not exercised')
        except BaseException as exc:result.put(exc)
    worker=threading.Thread(target=fail_growth);worker.start();worker.join(30);assert not worker.is_alive()
    fault=result.get_nowait()
    if isinstance(fault,BaseException):raise fault
    owned=fault.pop('owned');assert owned
    for cap in owned:v.raw(29,a=cap)
    cap=v.exception(cls,arguments,namespace);v.drop(cap)
    sweep(v);rows.append(dict(case='native-mremap-enomem-no-hidden-exception-custody',**fault))
    context=v.engine.context.raw;invalid=[]
    for op in (75,87):
        valid=frame(op,arg0=38)if op==87 else frame(op)
        for at in (16,96,112,120):
            raw=bytearray(valid);struct.pack_into('<Q',raw,at,1);invalid.append(bytes(raw))
        invalid.extend([valid[:-1],valid+b'\0'])
    for index in (0,37,43,(1<<64)-1):invalid.append(frame(87,arg0=index))
    invalid.append(frame(75,arg0=1))
    invalid.append(frame(87,arg0=38,a=(1,2,3)))
    for raw in invalid:
        rc,out=v.engine.call(raw);assert rc==0xfffffffd and v.engine.context.raw==context
        expected=bytearray(b'\xa5'*len(out));expected[128:136]=bytes(8)
        assert out==bytes(expected)
    rows.append(dict(case='exact-frame-boundaries-and-unchanged-output',controls=len(invalid)))
    v.finish()
    report=dict(schema='hia.native-exception-capture.component.v1',actual_native_image=True,image_bytes=args.image.stat().st_size,image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),oracle=platform.python_version(),groups=rows,component_qualified=True,native_callable_qualified=False,exception_constructor_auto_specialization_qualified=False,exception_formatting_traceback_qualified=False,whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows))))
if __name__=='__main__':main()
