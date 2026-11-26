"""Actual native truth prerequisites: graph retirement, classified invoke and canonical errors."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,platform,queue,struct,threading,traceback
from tools.qualify_hia_result_value_invocations import Bound,Engine,Values,echo_field,sweep,word
from tools.qualify_hia_result_value_exceptions import frame
from tools.qualify_hia_result_value_invocations import code_call
from hepta.hia_program_llvm import HIAProgramLLVMRejected
from tools.qualify_hia_result_value_invocation_custody import ip_at,notified,values_pack,code_pack
from tools.qualify_hia_native_callable_code_owner import deny_native

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(path,obj):path.write_text(json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=True)+'\n')

def builtin(v,index):
    return v.keep(v.raw(98,arg0=index)) if index>=43 else v.builtin(index)

def run(path,output):
    output.mkdir(parents=True,exist_ok=False)
    assert platform.python_version()=='3.14.4'
    b=Bound(path);initialized=b.call(0);assert initialized['status']==0 and initialized['state']==2
    v=Values(Engine(b));rows=[]
    def passed(case_name,**detail):
        rows.append(dict(case=case_name,passed=True,**detail));save(output/'partial.json',rows)
        print('TRUTH_PREREQUISITE_PASS',case_name,flush=True)
    report=dict(schema='hia.value.truth-prerequisites.v1',passed=False,product=pin(path.read_bytes()),
        whole_public_runtime_qualified=False,unicode_constructor_specialization_qualified=False)
    try:
        for holder_kind in ('instance','list','dict','tuple'):
            cls=v.cls('DescendantCycle',[])
            fn=v.function(echo_field(1),env=v.scalar(False));v.attr(cls,'__bool__',fn)
            instance=v.instance(cls)
            if holder_kind=='list':last=v.lst([instance])
            elif holder_kind=='dict':
                last=v.dictionary([]);key=v.scalar('last');v.raw(10,a=last,b=key,c=instance)
            elif holder_kind=='tuple':last=v.tuple([instance])
            else:last=instance
            for cap in list(v.held):
                if cap!=last:v.drop(cap)
            assert tuple(word(code_call(b,7),i)for i in(48,56))==(1,1)
            v.drop(last)
            sweep(v,b)
            passed('last-'+holder_kind+'-exposes-class-method-descendant-cycle-with-live-context-token')
        specifications=[
            (43,UnicodeError,UnicodeError('message',17),(43,24,22,21)),
            (44,UnicodeEncodeError,UnicodeEncodeError('ascii','\udcff',0,1,'ordinal not in range(128)'),(44,43,24,22,21)),
            (45,HIAProgramLLVMRejected,HIAProgramLLVMRejected('compiler failure'),(45,24,22,21)),
        ]
        for index,pytype,oracle,lineage in specifications:
            cls=builtin(v,index);alias=builtin(v,index);assert v.same(cls,alias)
            args=v.tuple([v.scalar(x)for x in oracle.args]);ns=v.dictionary([('hia_cleanup','retained')])
            exc=v.exception(cls,args,ns);typ=v.keep(v.raw(36,a=exc));assert v.same(cls,typ)
            for parent in lineage:assert v.isinst(exc,builtin(v,parent))
            env,stored,name=v.parts(exc)
            assert v.same(env,ns)and v.same(stored,args)and v.python_value(stored)==oracle.args
            assert v.python(name)==pytype.__name__
            shadow=v.cls(pytype.__name__,[]);assert not v.isinst(exc,shadow)
            for i in range(512):
                temp=v.scalar('catalog slot survives allocator '+str(i));v.drop(temp)
            assert v.same(builtin(v,index),cls)
            sweep(v,b);passed('canonical-error-class-args-and-mro',id=index,name=pytype.__name__)
        for disposition,kind in ((1,'scalar'),(1,'exception'),(2,'exception'),(2,'base'),(2,'subexception'),(2,'subbase')):
            if kind=='scalar':env=v.scalar(13);category=0
            else:
                cls=v.builtin(24 if kind in ('exception','subexception')else 21)
                if kind.startswith('sub'):cls=v.cls('ActualErrorSubclass',[cls])
                env=v.exception(cls,v.tuple([v.scalar('classified')]))
                category=0 if disposition==1 else 1 if kind in ('exception','subexception')else 2
            fn=v.function(echo_field(1,disposition),env=env);arguments=v.tuple([])
            for opcode in (70,97):
                out=v.raw(opcode,a=fn,b=arguments)
                assert tuple(word(out,i)for i in(64,80,88,96,104))==(disposition,0,1,1,0),out[:128].hex()
                assert word(out,56)==(category if opcode==97 else 0),out[:128].hex()
                primary=v.keep(out);assert v.same(primary,env);v.drop(primary)
            sweep(v,b);passed('private-classification-preserves-old70-reserved-zero',disposition=disposition,kind=kind,category=category)
        def deferred(op,**kw):
            raw=bytearray(frame(op,**kw));raw[:8]=b'HIABVQ07'if op in(3,12,16,18,24)else b'HIABVQ06'
            rc,out=v.engine.call(bytes(raw),on=16384)
            assert rc==0 and out[:8]==b'HIABVR01'and word(out,8)==0,(op,rc,out[:128].hex())
            return out
        items=v.keep(deferred(3));one=v.scalar(1);two=v.scalar(2);zero=v.scalar(0)
        deferred(16,a=items,b=one);got=v.keep(deferred(12,a=items,b=zero));assert v.same(got,one)
        summed=v.keep(deferred(24,a=one,b=two));assert v.python_value(summed)==3
        plain=v.keep(v.raw(18,a=items));frozen=v.keep(deferred(18,a=items))
        assert v.python_value(plain)==v.python_value(frozen)==b'[1]' and v.python_value(items)==[1]
        assert not v.same(plain,frozen)
        before=tuple(word(code_call(b,7),i)for i in(48,56,64,80))
        domains=((b'HIABVQ06',(3,12,16,18,24,48,56,61,68,69,70,75,77,78,80,85,87,91,92,93,97,98)),
                 (b'HIABVQ07',(0,1,2,4,5,6,7,8,9,10,11,13,14,15,17,19,20,21,22,23,25,26,32,36,39,48,49,56,61,68,69,70,75,77,78,80,85,87,91,92,93,97,98)))
        for magic,opcodes in domains:
            for opcode in opcodes:
                raw=bytearray(frame(opcode));raw[:8]=magic
                prior=bytes(v.engine.context)
                rc,out=v.engine.call(bytes(raw),on=16384)
                assert rc==0xfffffffd and bytes(v.engine.context)==prior,(magic,opcode,rc,out[:128].hex())
        after=tuple(word(code_call(b,7),i)for i in(48,56,64,80));assert before==after
        sweep(v,b);passed('fixed-deferred-list-index-append-export-integer-and-executable-domain-refusal')
        for class_id,category in ((24,1),(21,2)):
            for component in ('code','value'):
                env=v.exception(v.builtin(class_id),v.tuple([v.scalar('keep actual raised exception')]))
                fn=v.function(echo_field(1,2),env=env);arguments=v.tuple([])
                ip=ip_at(b.code,code_pack)if component=='code'else ip_at(b.value,values_pack)
                target=output/('private97-'+str(category)+'-'+component+'.json')
                reply,notes=notified(v,frame(97,a=fn,b=arguments),ip,[11],target,lambda notice,index:errno.EIO)
                assert notes and all(x['errno']==errno.EIO for x in notes)
                assert tuple(word(reply,i)for i in(8,56,64,80,88,96,104))==(0,category,2,1,1,1,11),reply[:128].hex()
                primary=v.keep(reply)
                assert word(v.engine.context,184)==1
                v.raw(47)
                assert word(v.engine.context,184)==0 and v.same(primary,env)
                sweep(v,b)
                passed('private97-actual-raise-survives-'+component+'-unmap-eio',category=category,notifications=len(notes))
        one=v.scalar(1);two=v.scalar(2);zero=v.scalar(0)
        fn=v.function(echo_field(1),env=one);result=queue.Queue()
        ip=ip_at(b.code,code_pack)
        def deferred_retirement_fault():
            try:
                deny_native(ip,11,errno.EIO)
                result.put(v.engine.call(frame(29,a=fn),on=16384))
            except BaseException as exc:result.put(exc)
        worker=threading.Thread(target=deferred_retirement_fault);worker.start();worker.join(30)
        assert not worker.is_alive();answer=result.get_nowait()
        if isinstance(answer,BaseException):raise answer
        rc,reply=answer
        assert rc==0 and reply[:8]==b'HIABVR02'and tuple(word(reply,i)for i in(8,80,88,96))==(11,1,1,1),reply[:128].hex()
        v.held.remove(fn);assert word(v.engine.context,176)==1
        items=v.keep(deferred(3));assert word(v.engine.context,176)==1
        deferred(16,a=items,b=one);assert word(v.engine.context,176)==1
        item=v.keep(deferred(12,a=items,b=zero));assert word(v.engine.context,176)==1
        frozen=v.keep(deferred(18,a=items));assert word(v.engine.context,176)==1
        difference=v.keep(deferred(24,a=one,b=two,arg0=1));assert word(v.engine.context,176)==1
        v.raw(47)
        assert word(v.engine.context,176)==word(v.engine.context,184)==0
        assert v.same(item,one)and v.python_value(frozen)==b'[1]'and v.python_value(difference)==-1
        sweep(v,b);passed('actual-code-retirement-pending-five-fixed-Q07-ops-never-drain-before-outer-native-entry')
        b.close();report.update(passed=True,groups=rows,same_arena=True,native_code_binding=True,
            descendant_class_callable_gc_qualified=True,private_classified_invocation_qualified=True,
            old70_reserved56_zero=True,canonical_error_ids=[43,44,45],old_q06_rejection_domain_preserved=True,q07_fixed_ops=[3,12,16,18,24])
        return report
    except BaseException as error:
        report['error']=repr(error);report['traceback']=traceback.format_exc();raise
    finally:save(output/'report.json',report)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--owner',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
