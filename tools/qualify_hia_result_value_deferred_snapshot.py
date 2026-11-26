"""Private atomic child snapshots preserve original Q01/23 ownership and defer retirement."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,queue,struct,threading,traceback
from tools.qualify_hia_result_value_invocations import Bound,Engine,Values,sweep,word
from tools.qualify_hia_result_value_exceptions import frame
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_result_value_invocation_custody import ip_at,values_pack
from tools.qualify_hia_native_callable_code_owner import deny_native
ZERO=(0,0,0)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def call(v,op,magic=b'HIABVQ09',on=16384,**kw):
    raw=bytearray(frame(op,**kw));raw[:8]=magic
    rc,out=v.engine.call(bytes(raw),on=on)
    assert rc==0 and out[:8]==b'HIABVR01',(rc,out[:128].hex())
    return out
def ident(v,cap):
    out=call(v,7,magic=b'HIABVQ06',a=cap)
    assert word(out,8)==0
    return tuple(word(out,k)for k in(104,112))
def take_rows(v,out):
    assert word(out,8)==0
    result=[]
    for i in range(word(out,64)):
        at=8192+i*64
        key=struct.unpack_from('<3Q',out,at+16)
        value=struct.unpack_from('<3Q',out,at+40)
        assert all(value)
        if key!=ZERO:assert all(key);v.held.add(key)
        v.held.add(value)
        result.append((word(out,at),word(out,at+8),key,value))
    return result
def release_deferred(v,cap):
    rc,out=v.engine.call(frame(78,a=cap))
    assert rc==0 and out[:8]==b'HIABVR02'
    assert tuple(word(out,k)for k in(8,88,96,104,120))==(0,1,1,0,1),out[:128].hex()
    v.held.remove(cap)
    return out
def run(path,out):
    out.mkdir(parents=True,exist_ok=False);assert platform.python_version()=='3.14.4'
    report=dict(schema='hia.native-value-deferred-snapshot.component.v1',passed=False,
        product=pin(path.read_bytes()),whole_public_runtime_qualified=False,
        public_q09_profile_refusal_qualified=False,original_full_regression_qualified=False)
    rows=[];before=set(os.listdir('/proc/self/fd'))
    try:
        for kind in('list','tuple','dict'):
            b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
            values=[v.scalar(x)for x in(71,'two',False,71)]
            expected=[ident(v,c)for c in values]
            keys=[]
            if kind=='dict':
                parent=v.keep(v.raw(4))
                for i,value in enumerate(values):
                    key=v.scalar('key'+str(i));keys.append(key);v.raw(10,a=parent,b=key,c=value)
                keyids=[ident(v,k)for k in keys]
            elif kind=='tuple':parent=v.tuple(values)
            else:parent=v.lst(values)
            raw=call(v,23,a=parent,arg1=100)
            assert (word(raw,48),word(raw,64),word(raw,72))==(4,4,8448)
            children=take_rows(v,raw)
            assert [x[0]for x in children]==list(range(4))
            assert [ident(v,x[3])for x in children]==expected
            assert [x[1]for x in children]==[2,4,1,2]
            if keys:assert [ident(v,x[2])for x in children]==keyids
            else:assert all(x[2]==ZERO for x in children)
            old=call(v,23,magic=b'HIABVQ01',a=parent,arg0=1,arg1=2)
            oldchildren=take_rows(v,old)
            partial=call(v,23,a=parent,arg0=1,arg1=2)
            part=take_rows(v,partial)
            assert (word(partial,48),word(partial,64),word(partial,72))==(4,2,8320)
            assert [x[0]for x in part]==[1,2]
            assert [ident(v,x[3])for x in oldchildren]==[ident(v,x[3])for x in part]==expected[1:3]
            for start in(4,2**64-1):
                empty=call(v,23,a=parent,arg0=start,arg1=2**64-1)
                assert (word(empty,8),word(empty,48),word(empty,64),word(empty,72))==(0,4,0,8192)
            # Original inputs and the parent are gone; the atomic snapshot owns real children.
            for cap in [parent,*values,*keys]:v.drop(cap)
            assert [ident(v,x[3])for x in children]==expected
            if keys:assert [ident(v,x[2])for x in children]==keyids
            for cap in list(v.held):v.drop(cap)
            sweep(v,b);b.close()
            rows.append(dict(case=kind,original23_compatible=True,actual_child_lifetime=True))
            print('DEFERRED_SNAPSHOT_PASS',kind,flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
        values=[v.scalar(x)for x in(13,17,19)];parent=v.lst(values)
        expected=[ident(v,c)for c in values]
        pending_function(v,b)
        raw=call(v,23,a=parent,arg1=3);children=take_rows(v,raw)
        assert word(raw,8)==0 and word(v.engine.context,176)==1
        for cap in [parent,*values]:
            receipt=release_deferred(v,cap)
            assert word(receipt,112)==1 and word(receipt,80)==1
        assert [ident(v,x[3])for x in children]==expected
        assert word(v.engine.context,176)==1
        v.raw(47);assert word(v.engine.context,176)==word(v.engine.context,184)==0
        for cap in list(v.held):v.drop(cap)
        sweep(v,b);b.close()
        rows.append(dict(case='real-code-munmap-pending-and-child-custody',single_entry_deferred=True,actual_outer_retry=True))
        print('DEFERRED_SNAPSHOT_PASS actual-pending',flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
        values=[v.scalar(4),v.scalar(5)];parent=v.lst(values)
        small=call(v,23,a=parent,arg1=2,on=8192+63)
        assert (word(small,8),word(small,48),word(small,64),word(small,72))==(13,0,0,8320)
        wrong=call(v,23,a=values[0],arg1=2)
        assert word(wrong,8)==2 and word(wrong,64)==0
        result=queue.Queue()
        def fail_random():
            try:
                deny_native(ip_at(b.value,values_pack),318,errno.EIO)
                result.put(call(v,23,a=parent,arg1=2))
            except BaseException as e:result.put(e)
        thread=threading.Thread(target=fail_random);thread.start();thread.join(30);assert not thread.is_alive()
        failed=result.get_nowait()
        if isinstance(failed,BaseException):raise failed
        assert word(failed,8)==11 and word(failed,48)==word(failed,64)==0
        assert failed[24:48]==bytes(24)
        retry=call(v,23,a=parent,arg1=2);take_rows(v,retry)
        for cap in list(v.held):v.drop(cap)
        sweep(v,b);b.close()
        rows.append(dict(case='atomic-prepublication-failures',getrandom_actual_errno=errno.EIO,children_not_published_on_failure=True))
        print('DEFERRED_SNAPSHOT_PASS prepublication-failures',flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));controls=[]
        for op in(0,1,2,3,4,5,6,7,19,20,21,22,24,29,30,31,48,49,56,61,68,69,70,75,77,78,91,92,93,97,98,99,100):
            bad=bytearray(frame(op));bad[:8]=b'HIABVQ09';controls.append(bytes(bad))
        valid=bytearray(frame(23));valid[:8]=b'HIABVQ09'
        for at in(16,48,72,96,120):
            bad=bytearray(valid);struct.pack_into('<Q',bad,at,1);controls.append(bytes(bad))
        for raw in controls:
            context=bytes(v.engine.context);rc,reply=v.engine.call(raw)
            assert rc==0xfffffffd and bytes(v.engine.context)==context
            expected=bytearray(b'\xa5'*len(reply));expected[128:136]=bytes(8);assert reply==expected
        sweep(v,b);b.close()
        rows.append(dict(case='exact-Q09-domain-and-unchanged-refusal',controls=len(controls)))
        print('DEFERRED_SNAPSHOT_PASS domain',flush=True)
        assert set(os.listdir('/proc/self/fd'))==before
        report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),fd_baseline_restored=True)
    except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:save(out/'report.json',report)
    return report
def main():
    p=argparse.ArgumentParser()
    for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
