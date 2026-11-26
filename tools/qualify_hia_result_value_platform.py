"""Actual platform records, OS exception slots and capability custody."""
from pathlib import Path
import argparse,builtins,ctypes as C,dataclasses,errno,hashlib,json,os,platform,queue,struct,threading,traceback
from tools.qualify_hia_result_value_invocations import Bound,Engine,Values as PriorValues,sweep,word,ZERO
from tools.qualify_hia_result_value_exceptions import frame
from tools.qualify_hia_result_value_verified_program import make_value
from tools.qualify_hia_result_value_records import equivalent
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_result_value_invocation_custody import ip_at,code_pack
from tools.qualify_hia_native_callable_code_owner import deny_native
from tools import generate_hia_result_value_platform_packer as values_pack
from tools.generate_hia_result_value_platform import PLATFORM_CLASSES
from hepta.clang_capture import CaptureFailure,CaptureResult

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
class Values(PriorValues):
    def raw(self,op,*,want=0,on=16384,**kw):
        if op<99:return super().raw(op,want=want,on=on,**kw)
        packet=bytearray(frame(op,**kw));packet[:8]=b'HIABVQ05'
        rc,out=self.engine.call(bytes(packet),on=on)
        assert rc==0 and out[:8]==b'HIABVR01',(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want,out[:128].hex())
        return out
    def builtin(self,index):
        if index>=48:return self.keep(self.raw(101,arg0=index))
        if index>=46:return self.keep(self.raw(99,arg0=index))
        if index>=43:return self.keep(self.raw(98,arg0=index))
        return super().builtin(index)
    def capture(self,op,fields,cls=ZERO):
        seq=self.lst(fields);reply=self.raw(op,a=seq,b=cls)
        assert (word(reply,64),word(reply,80),word(reply,88),word(reply,96),word(reply,104))==(1,0,1,1,0)
        result=self.keep(reply);self.drop(seq);return result
    def os_error(self,cls,fields):
        seq=self.tuple(fields);reply=self.raw(104,a=cls,b=seq);self.drop(seq)
        assert tuple(word(reply,i)for i in(80,88,96,104))==(0,1,1,0),reply[:128].hex()
        return self.keep(reply),word(reply,64)
    def slot(self,cap,index,want=0):
        reply=self.raw(105,a=cap,arg0=index,want=want)
        if want:assert word(reply,96)==0;return ZERO
        assert word(reply,96)==1;return self.keep(reply)
def name(v,cap):
    cls=v.keep(v.raw(36,a=cap));text=v.keep(v.raw(38,a=cls));result=v.python_value(text)
    v.drop(text);v.drop(cls);return result
def periodic_gc(v,probe):
    # Exercise the original native 4096-operation collection trigger, without
    # writing its counters or inventing an immediate pure-cycle contract.
    for _ in range(4097):v.raw(7,a=probe)
def thread_result(fn):
    q=queue.Queue()
    def wrapped():
        try:q.put(fn())
        except BaseException as error:q.put(error)
    t=threading.Thread(target=wrapped);t.start();t.join(30);assert not t.is_alive()
    result=q.get_nowait()
    if isinstance(result,BaseException):raise result
    return result
def objects(v):
    return word(C.string_at(word(v.engine.context,16)+104,8),0)
def args_and_dict(v,obj):
    out=v.raw(26,a=obj)
    result=[]
    for at in(8224,8248,8272):
        cap=struct.unpack_from('<3Q',out,at);assert all(cap);v.held.add(cap);result.append(cap)
    return result
def compare_os(v,native,expected):
    assert name(v,native)==type(expected).__name__
    for i,key in enumerate(('errno','strerror','filename','filename2')):
        cap=v.slot(native,i);assert equivalent(v.python_value(cap),getattr(expected,key)),(key,v.python_value(cap),getattr(expected,key));v.drop(cap)
    if hasattr(expected,'characters_written'):
        cap=v.slot(native,4);assert v.python_value(cap)==expected.characters_written
        assert name(v,cap)=='int';v.drop(cap)
    else:v.slot(native,4,want=3)
    cap=v.slot(native,5);assert equivalent(v.python_value(cap),expected.args),(v.python_value(cap),expected.args);v.drop(cap)
    namespace,base,typename=args_and_dict(v,native)
    assert v.python_value(namespace)=={}
    assert equivalent(v.python_value(base),expected.args)
    for cap in(namespace,base,typename):v.drop(cap)
def run(path,out):
    out.mkdir(parents=True,exist_ok=False);assert platform.python_version()=='3.14.4'
    report=dict(schema='hia.native-value-platform.component.v1',passed=False,
        product=pin(path.read_bytes()),whole_public_runtime_qualified=False,
        public_platform_owner_qualified=False,custom_index_constructor_qualified=False)
    rows=[];before=set(os.listdir('/proc/self/fd'))
    try:
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));classes={}
        for index,(expected,baseid)in enumerate(PLATFORM_CLASSES,48):
            cls=v.builtin(index);classes[index]=cls
            text=v.keep(v.raw(38,a=cls));assert v.python_value(text)==expected;v.drop(text)
            same=v.builtin(index);assert v.same(same,cls);v.drop(same)
            mro=v.keep(v.raw(38,a=cls,arg0=2));ix=v.scalar(1);direct=v.keep(v.raw(12,a=mro,b=ix));base=v.builtin(baseid)
            assert v.same(direct,base)
            for cap in(mro,ix,direct,base):v.drop(cap)
        rows.append(dict(case='all-23-canonical-class-identities-and-real-bases'))
        print('PLATFORM_PASS catalog',flush=True)
        for op,index,python_type,count in((102,53,CaptureFailure,6),(103,54,CaptureResult,5)):
            assert python_type.__dataclass_params__.frozen
            fields=[v.scalar(i)for i in range(count)]
            value=v.capture(op,fields);actual=v.keep(v.raw(36,a=value));assert v.same(actual,classes[index])
            assert word(v.raw(7,a=value),16)==12
            for i,child in enumerate(fields):
                field=v.field(value,i);assert v.same(field,child);v.drop(field)
            other=v.capture(op,fields);assert word(v.raw(62,a=value,b=other),48)==1
            assert struct.unpack_from('<q',v.raw(63,a=value),48)[0]==hash(python_type(*range(count)))
            subclass=v.cls(python_type.__name__+'Child',[classes[index]])
            sub=v.capture(op,fields,subclass);typ=v.keep(v.raw(36,a=sub))
            assert v.same(typ,subclass)and v.isinst(sub,classes[index])
            assert word(v.raw(62,a=value,b=sub),48)==0
            for cap in(value,actual,other,sub,typ,subclass,*fields):v.drop(cap)
            rows.append(dict(case='capture-record-fields-hash-and-subclass',class_name=python_type.__name__,fields=count))
        for op,count in((102,6),(103,5)):
            mutable=v.lst([]);fields=[mutable]+[v.scalar(i)for i in range(count-1)];value=v.capture(op,fields)
            one=v.scalar(9);v.raw(16,a=mutable,b=one);field=v.field(value,0)
            assert v.same(field,mutable)and v.python_value(field)==[9];v.raw(63,a=value,want=2)
            for cap in [value,field,one,*fields]:v.drop(cap)
        rows.append(dict(case='capture-records-preserve-mutable-alias-and-unhashability'))
        print('PLATFORM_PASS records',flush=True)
        osclass=v.builtin(25);count=0
        for number in range(-2,142):
            expected=OSError(number,'native errno')
            fields=[v.scalar(number),v.scalar('native errno')]
            obj,disposition=v.os_error(osclass,fields);assert disposition==1
            compare_os(v,obj,expected)
            for cap in [obj,*fields]:v.drop(cap)
            count+=1
        rows.append(dict(case='actual-errno-specialization-map',errno_cases=count))
        print('PLATFORM_PASS errno-map',flush=True)
        cases=[(),(2,),(2,'x'),(2,'x',None),(2,'x','a'),(2,'x',b'a'),(2,'x','a',5),
               (2,'x','a',5,'b'),(2,'x',None,None,'b'),(2,'x','a',5,'b',6),
               (None,'x'),('2','x'),(True,'x'),(1<<100,'x'),(-1,'x'),
               (11,'x',4),(11,'x',True),(11,'x',-1),(11,'x',-2),
               (11,'x',-(1<<63)),(11,'x',(1<<63)-1),(11,'x','a'),(11,'x',None),
               (11,'x',4,None,'b'),(11,'x',1<<100),(11,'x',-(1<<100))]
        for python_cls,cls in((OSError,osclass),(BlockingIOError,classes[56])):
            for args in cases:
                fields=[make_value(v,item)for item in args]
                try:expected=python_cls(*args);raised=False
                except BaseException as error:expected=error;raised=True
                obj,disposition=v.os_error(cls,fields)
                assert disposition==(2 if raised else 1),(python_cls,args,disposition)
                if raised:
                    assert name(v,obj)==type(expected).__name__
                    cap=v.slot(obj,5);assert v.python_value(cap)==expected.args;v.drop(cap)
                else:compare_os(v,obj,expected)
                for cap in [obj,*fields]:v.drop(cap)
        rows.append(dict(case='full-native-argument-count-filename-written-and-range-domain',cases=len(cases)*2))
        print('PLATFORM_PASS argument-domain',flush=True)
        for pybase,nativebase in((OSError,osclass),(BlockingIOError,classes[56])):
            pycls=type('ActualOSChild',(pybase,),{});cls=v.cls('ActualOSChild',[nativebase])
            for args in((2,'x'),(2,'x','a',None,'b'),(11,'x',4),(11,'x',1<<100)):
                fields=[make_value(v,item)for item in args];obj,disp=v.os_error(cls,fields);assert disp==1
                actual=v.keep(v.raw(36,a=obj));assert v.same(actual,cls);v.drop(actual)
                compare_os(v,obj,pycls(*args))
                for cap in [obj,*fields]:v.drop(cap)
            v.drop(cls)
        rows.append(dict(case='real-OS-subclass-identity-without-canonical-auto-specialization'))
        print('PLATFORM_PASS subclasses',flush=True)
        integer=v.builtin(3);icls=v.cls('数值',[integer]);ns=v.keep(v.raw(4));base=v.scalar(1<<100)
        special=v.keep(v.raw(50,a=icls,b=ns,c=base))
        fields=[v.scalar(11),v.scalar('x'),special]
        obj,disp=v.os_error(osclass,fields);assert disp==2
        arg=v.slot(obj,5);expected=type('数值',(int,),{})(1<<100)
        try:OSError(11,'x',expected)
        except ValueError as error:assert v.python_value(arg)==error.args
        else:raise AssertionError('oracle failed to reject oversized index')
        first=v.keep(v.raw(12,a=arg,b=v.scalar(0)))
        assert word(v.raw(7,a=first),48)==len(v.python_value(first))
        for cap in [obj,arg,first,*fields,integer,icls,ns,base]:v.drop(cap)
        rows.append(dict(case='integer-subclass-range-error-real-Unicode-type-name'))
        print('PLATFORM_PASS integer-subclass',flush=True)
        periodic_gc(v,osclass)
        baseline=objects(v)
        filename=v.lst([]);fields=[v.scalar(2),v.scalar('file'),filename]
        obj,disp=v.os_error(osclass,fields);assert disp==1
        slot=v.slot(obj,2);assert v.same(slot,filename)
        for cap in fields:v.drop(cap)
        v.raw(16,a=slot,b=obj)
        v.drop(obj);v.drop(slot)
        # Pure Value cycles follow the existing periodic native collector; no
        # resource queue exists here to request an immediate finalizer pass.
        periodic_gc(v,osclass)
        assert objects(v)==baseline,(objects(v),baseline)
        rows.append(dict(case='actual-OS-slot-container-cycle-collection'))
        print('PLATFORM_PASS slot-cycle',flush=True)
        base=v.builtin(22);args=v.tuple([])
        def get_chain(obj,selector):
            reply=v.raw(107,a=obj,arg0=selector)
            assert tuple(word(reply,j)for j in(64,80,88,96,104))==(1,0,1,1,0)
            return v.keep(reply)
        def set_chain(obj,value,selector,want=0):
            reply=v.raw(106,a=obj,b=value,arg0=selector,want=want)
            assert (word(reply,88),word(reply,96))==(1,int(want==0))
            if want:assert reply[24:48]==bytes(24);return
            returned=v.keep(reply);assert v.python_value(returned)is None;v.drop(returned)
        matrix=0
        for selector,attribute in enumerate(('__cause__','__context__','__suppress_context__')):
            for value in(None,False,True,0,1,'x','exception'):
                pyvalue=Exception('x')if value=='exception'else value
                native=v.exception(base,args)
                target=v.exception(base,args)if value=='exception'else v.scalar(value)
                original=Exception()
                try:setattr(original,attribute,pyvalue);valid=True
                except TypeError:valid=False
                set_chain(native,target,selector,want=0 if valid else 2)
                for index,field in enumerate(('__cause__','__context__','__suppress_context__')):
                    result=get_chain(native,index);expected=getattr(original,field)
                    if isinstance(expected,BaseException):assert v.same(result,target)
                    else:assert v.python_value(result)is expected
                    v.drop(result)
                namespace,stored,typename=args_and_dict(v,native);assert v.python_value(namespace)=={}
                for cap in(namespace,stored,typename,native,target):v.drop(cap)
                matrix+=1
        rows.append(dict(case='real-cause-context-suppress-slots-and-original-setter-domain',cases=matrix))
        print('PLATFORM_PASS chain-setters',flush=True)
        namespace=v.dictionary([('__cause__','dictionary-only'),('__context__',3)])
        notes=v.lst([v.scalar('note')]);key=v.scalar('__notes__');v.raw(10,a=namespace,b=key,c=notes)
        outer=v.exception(base,args,namespace);inner=v.exception(classes[49],args)
        set_chain(outer,inner,0);set_chain(outer,inner,1);v.drop(inner)
        cause=get_chain(outer,0);context=get_chain(outer,1)
        assert v.same(cause,context)and name(v,cause)=='ToolIdentityRejected'
        ns,stored,typename=args_and_dict(v,outer)
        assert v.same(ns,namespace)and v.python_value(ns)=={'__cause__':'dictionary-only','__context__':3,'__notes__':['note']}
        for cap in(ns,stored,typename,cause,context,outer,namespace,notes,key):v.drop(cap)
        rows.append(dict(case='strong-exception-chain-is-separate-from-namespace-and-real-notes'))
        periodic_gc(v,base);baseline=objects(v)
        first=v.exception(base,args);second=v.exception(base,args)
        set_chain(first,second,0);set_chain(second,first,1);set_chain(first,first,1)
        v.drop(first);v.drop(second);periodic_gc(v,base)
        assert objects(v)==baseline,(objects(v),baseline)
        rows.append(dict(case='actual-self-and-mutual-exception-chain-cycle-collection'))
        print('PLATFORM_PASS chain-cycles',flush=True)
        first=v.exception(base,args);target=v.exception(base,args)
        def denied_setter():
            deny_native(ip_at(b.value,values_pack),318,errno.EIO)
            return v.raw(106,a=first,b=target,want=11)
        failed=thread_result(denied_setter)
        assert tuple(word(failed,j)for j in(80,88,96,104))==(0,1,0,11)and failed[24:48]==bytes(24)
        old=get_chain(first,0);assert v.python_value(old)is None;v.drop(old)
        set_chain(first,target,0);v.drop(first);v.drop(target)
        rows.append(dict(case='real-getrandom-failure-preserves-old-chain-and-no-delivery'))
        print('PLATFORM_PASS chain-precommit-failure',flush=True)
        periodic_gc(v,base);baseline=objects(v)
        first=v.exception(base,args);existing=v.exception(base,args);target=v.exception(base,args)
        set_chain(existing,target,0)
        def denied_chain_growth():
            deny_native(ip_at(b.value,values_pack),25,errno.ENOMEM)
            retained=[]
            for _ in range(131072):
                rc,reply=v.engine.call(frame(5,a=base))
                assert rc==0 and reply[:8]==b'HIABVR01'
                if word(reply,8)==0:
                    retained.append(v.keep(reply))
                else:
                    assert word(reply,8)==5 and reply[24:48]==bytes(24),reply[:128].hex()
                    break
            else:raise AssertionError('real arena growth fault was not reached')
            failures=[]
            for obj in(first,existing):
                rc,reply=v.engine.call(frame(106,a=obj,b=target,arg0=1))
                assert rc==0 and reply[:8]==b'HIABVR01'and word(reply,8)==5,reply[:128].hex()
                assert (word(reply,88),word(reply,96))==(1,0)and reply[24:48]==bytes(24)
                failures.append(reply[:128].hex())
            return retained,failures
        retained,failures=thread_result(denied_chain_growth)
        untouched=get_chain(first,1);assert v.python_value(untouched)is None;v.drop(untouched)
        untouched=get_chain(existing,1);assert v.python_value(untouched)is None;v.drop(untouched)
        prior=get_chain(existing,0);assert v.same(prior,target);v.drop(prior)
        for cap in [*retained,first,existing,target]:v.drop(cap)
        periodic_gc(v,base)
        assert objects(v)==baseline,(objects(v),baseline)
        rows.append(dict(case='real-mremap-ENOMEM-preserves-fresh-and-existing-chain',
            retained_capabilities=len(retained),failures=failures))
        print('PLATFORM_PASS chain-growth-atomicity',flush=True)
        fields=[v.scalar(2),v.scalar('file'),v.scalar('native-path')];osargs=v.tuple(fields)
        osobj,disp=v.os_error(osclass,fields);assert disp==1
        recordfields=v.tuple([v.scalar(i)for i in range(6)])
        record5=v.tuple([v.scalar(i)for i in range(5)])
        chained=v.exception(base,args);target=v.exception(base,args)
        requests=[
            (101,dict(arg0=48)),(102,dict(a=recordfields)),(103,dict(a=record5)),
            (104,dict(a=osclass,b=osargs)),(105,dict(a=osobj,arg0=2)),
            (106,dict(a=chained,b=target,arg0=0)),(107,dict(a=chained,arg0=0))]
        receipts=[]
        for operation,kw in requests:
            pending_function(v,b)
            def denied_cleanup():
                deny_native(ip_at(b.code,code_pack),11,errno.EIO)
                return v.raw(operation,**kw,want=11)
            delivered=thread_result(denied_cleanup)
            assert tuple(word(delivered,j)for j in(64,80,88,96,104))==(1,1,1,1,11),delivered[:128].hex()
            result=v.keep(delivered);assert all(result)
            receipts.append(dict(operation=operation,receipt=delivered[:128].hex()))
            v.raw(47);assert word(v.engine.context,176)==word(v.engine.context,184)==0
            v.drop(result)
        check=get_chain(chained,0);assert v.same(check,target);v.drop(check)
        for cap in [osargs,osobj,recordfields,record5,chained,target,*fields,args,base]:v.drop(cap)
        rows.append(dict(case='all-seven-platform-operations-keep-primary-after-real-code-munmap-EIO',cases=receipts))
        print('PLATFORM_PASS actual-post-publication-custody',flush=True)
        cls=v.cls('HasIndex',[]);key=v.scalar('__index__');none=v.scalar(None);v.raw(34,a=cls,b=key,c=none)
        instance=v.instance(cls);fields=[v.scalar(11),v.scalar('index'),instance];args=v.tuple(fields)
        failed=v.raw(104,a=osclass,b=args,want=27)
        assert tuple(word(failed,i)for i in(88,96))==(1,0)and failed[24:48]==bytes(24)
        for cap in [args,*fields,cls,key,none]:v.drop(cap)
        rows.append(dict(case='custom-index-explicit-enclosing-protocol-required',status=27,user_code_under_Value_mutex=False))
        print('PLATFORM_PASS explicit-index-boundary',flush=True)
        invalid=[]
        for op in range(101,108):
            normal=bytearray(frame(op,arg0=48 if op==101 else 0))
            for magic in(b'HIABVQ01',b'HIABVQ02',b'HIABVQ03',b'HIABVQ04',b'HIABVQ06',b'HIABVQ07',b'HIABVQ08',b'HIABVQ09',b'HIABVQ10'):
                raw=bytearray(normal);raw[:8]=magic;invalid.append(bytes(raw))
            for at in(16,96,112,120):
                raw=bytearray(normal);struct.pack_into('<Q',raw,at,1);invalid.append(bytes(raw))
            invalid.extend((bytes(normal[:-1]),bytes(normal)+b'\0'))
        for op,arg in((101,47),(101,71),(105,6),(106,3),(107,3),(99,48),(98,46),(87,43)):invalid.append(frame(op,arg0=arg))
        for raw in invalid:
            old=bytes(v.engine.context);rc,reply=v.engine.call(raw)
            assert rc==0xfffffffd and bytes(v.engine.context)==old,(rc,raw[:128].hex())
            expected=bytearray(b'\xa5'*len(reply));expected[128:136]=bytes(8);assert reply==expected
        rows.append(dict(case='new-domains-and-preserved-old-rejection-edges',controls=len(invalid)))
        for cap in list(v.held):v.drop(cap)
        sweep(v,b);b.close()
        print('PLATFORM_PASS domain-and-retirement',flush=True)
        report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()))
        assert set(os.listdir('/proc/self/fd'))==before
    except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:save(out/'report.json',report)
    return report
def main():
    p=argparse.ArgumentParser()
    for key in('owner','output'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
