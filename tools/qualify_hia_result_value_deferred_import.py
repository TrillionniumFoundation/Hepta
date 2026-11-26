"""Actual JSON import with one-entry deferred native retirement."""
from pathlib import Path
import argparse,errno,hashlib,json,math,os,platform,queue,struct,threading,traceback
from tools.qualify_hia_result_value_invocations import Bound,Engine,Values,sweep,word
from tools.qualify_hia_result_value_exceptions import frame
from tools.qualify_hia_result_value_deferred_capture import pending_function
from tools.qualify_hia_result_value_invocation_custody import ip_at,values_pack
from tools.qualify_hia_native_callable_code_owner import deny_native
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def imported(v,raw,magic=b'HIABVQ10'):
    packet=bytearray(frame(1,tail=raw));packet[:8]=magic
    rc,out=v.engine.call(bytes(packet))
    assert rc==0 and out[:8]==b'HIABVR01',(rc,out[:128].hex())
    return out
def export(v,cap):
    value=v.keep(v.raw(18,a=cap));meta=v.raw(7,a=value);n=word(meta,72)
    raw=v.raw(19,a=value,arg0=0,arg1=n)
    assert word(raw,64)==n
    result=json.loads(raw[8192:8192+n]);v.drop(value)
    return result
def run(path,out):
    out.mkdir(parents=True,exist_ok=False);assert platform.python_version()=='3.14.4'
    report=dict(schema='hia.native-value-deferred-import.component.v1',passed=False,
        product=pin(path.read_bytes()),whole_public_runtime_qualified=False,
        public_q10_profile_refusal_qualified=False,original_full_regression_qualified=False)
    rows=[];before=set(os.listdir('/proc/self/fd'))
    try:
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
        values=[None,False,True,0,-1,10**80,0.0,-0.0,1.25,'','quote"\\\n','λ🌍',[],{},[1,{'two':[False,None,'λ']},3],{'z':[],'a':{'b':-2}},list(range(128))]
        for value in values:
            data=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
            new=imported(v,data);old=imported(v,data,b'HIABVQ01')
            assert word(new,8)==word(old,8)==0
            a=v.keep(new);c=v.keep(old)
            got=export(v,a);prior=export(v,c)
            assert got==prior==value
            if isinstance(value,float)and value==0:assert math.copysign(1,got)==math.copysign(1,value)
            v.drop(a);v.drop(c)
        sweep(v,b);b.close();rows.append(dict(case='original-import-equivalence',values=len(values)))
        print('DEFERRED_IMPORT_PASS original-equivalence',flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
        pending_function(v,b)
        reply=imported(v,b'{"ready":[13,17,19],"tag":"actual native JSON"}')
        assert word(reply,8)==0 and word(v.engine.context,176)==1
        cap=v.keep(reply)
        packet=bytearray(frame(7,a=cap));packet[:8]=b'HIABVQ06'
        rc,meta=v.engine.call(bytes(packet));assert rc==0 and word(meta,8)==0 and word(meta,16)==6
        assert word(v.engine.context,176)==1
        v.raw(47);assert word(v.engine.context,176)==word(v.engine.context,184)==0
        assert export(v,cap)=={'ready':[13,17,19],'tag':'actual native JSON'}
        v.drop(cap);sweep(v,b);b.close()
        rows.append(dict(case='real-code-munmap-pending',single_entry_deferred=True,actual_outer_retry=True))
        print('DEFERRED_IMPORT_PASS actual-pending',flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b))
        malformed=[b'',b'{',b'{bad}',b'[1,]',b'00',b'null false',b'"\xff"',b'{"a":\0}']
        statuses=[]
        for raw in malformed:
            original=imported(v,raw,b'HIABVQ01');candidate=imported(v,raw)
            assert word(original,8)!=0 and word(candidate,8)==word(original,8)
            assert original[24:48]==candidate[24:48]==bytes(24)
            statuses.append(word(candidate,8))
        sweep(v,b);b.close();rows.append(dict(case='original-invalid-json-atomicity',statuses=statuses))
        print('DEFERRED_IMPORT_PASS parse-failures',flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));pending_function(v,b)
        results=queue.Queue()
        def deny():
            try:
                deny_native(ip_at(b.value,values_pack),318,errno.EIO)
                results.put(imported(v,b'{"one":[1,2,{"deep":3}],"two":false}'))
            except BaseException as e:results.put(e)
        thread=threading.Thread(target=deny);thread.start();thread.join(30);assert not thread.is_alive()
        failed=results.get_nowait()
        if isinstance(failed,BaseException):raise failed
        assert word(failed,8)==11 and failed[24:48]==bytes(24)
        assert word(v.engine.context,176)==1
        v.raw(47);assert word(v.engine.context,176)==word(v.engine.context,184)==0
        retry=imported(v,b'{"one":[1,2,{"deep":3}],"two":false}')
        assert word(retry,8)==0
        cap=v.keep(retry);assert export(v,cap)=={'one':[1,2,{'deep':3}],'two':False}
        v.drop(cap);sweep(v,b);b.close()
        rows.append(dict(case='actual-getrandom-EIO-no-publication',original_pending_preserved=True))
        print('DEFERRED_IMPORT_PASS getrandom-failure',flush=True)
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));controls=[]
        for op in(0,2,3,4,5,6,7,19,20,21,22,23,24,29,30,31,48,49,56,61,68,69,70,75,77,78,91,92,93,97,98,99,100):
            raw=bytearray(frame(op));raw[:8]=b'HIABVQ10';controls.append(bytes(raw))
        valid=bytearray(frame(1,tail=b'{}'));valid[:8]=b'HIABVQ10'
        for at in(16,24,48,72,104,112,120):
            raw=bytearray(valid);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
        raw=bytearray(valid);struct.pack_into('<Q',raw,96,3);controls.append(bytes(raw))
        for raw in controls:
            context=bytes(v.engine.context);rc,reply=v.engine.call(raw)
            assert rc==0xfffffffd and bytes(v.engine.context)==context
            expected=bytearray(b'\xa5'*len(reply));expected[128:136]=bytes(8);assert reply==expected
        sweep(v,b);b.close();rows.append(dict(case='exact-Q10-domain-and-unchanged-refusal',controls=len(controls)))
        print('DEFERRED_IMPORT_PASS domain',flush=True)
        assert set(os.listdir('/proc/self/fd'))==before
        report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()),fd_baseline_restored=True)
    except BaseException as e:report.update(error=repr(e),traceback=traceback.format_exc());raise
    finally:save(out/'report.json',report)
    return report
def main():
    p=argparse.ArgumentParser()
    for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
