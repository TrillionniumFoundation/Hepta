"""Private deferred resource capture uses real carrier custody and native retirement."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,queue,struct,threading,traceback
import tools
SHARED=Path('/home/qian-qi/hia-native-followthrough-20261126-620a')
if str(SHARED/'tools')not in tools.__path__:tools.__path__.append(str(SHARED/'tools'))
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_result_value_invocations import Bound,Engine,Values,FRESH,sweep,word
from tools.qualify_hia_result_value_exceptions import frame
from tools.qualify_hia_result_value_invocation_custody import ip_at,values_pack,code_pack
from tools.qualify_hia_native_callable_code_owner import deny_native
ZERO=(0,0,0)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def capture(v,carrier):
    raw=bytearray(frame(48,arg0=1,tail=struct.pack('<3Q',*carrier)));raw[:8]=b'HIABVQ08'
    rc,out=v.engine.call(bytes(raw),on=16384)
    assert rc==0 and out[:8]==b'HIABVR01'
    return out
def pending_function(v,b):
    fn=v.function(FRESH);result=queue.Queue()
    def deny():
        try:
            deny_native(ip_at(b.code,code_pack),11,errno.EIO)
            r=v.raw(29,a=fn,want=11)
            assert tuple(word(r,i)for i in(80,88,96))==(1,1,1)
            result.put(r)
        except BaseException as error:result.put(error)
    t=threading.Thread(target=deny);t.start();t.join(30);assert not t.is_alive()
    r=result.get_nowait()
    if isinstance(r,BaseException):raise r
    v.held.remove(fn);assert word(v.engine.context,176)==1
def run(path,custody,out):
    out.mkdir(parents=True,exist_ok=False);assert platform.python_version()=='3.14.4'
    report=dict(schema='hia.native-value-deferred-capture.component.v1',passed=False,
                product=pin(path.read_bytes()),whole_public_runtime_qualified=False,
                public_q08_profile_refusal_qualified=False,original_full_regression_qualified=False)
    rows=[];files=[]
    before=set(os.listdir('/proc/self/fd'))
    try:
        for name in('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'):
            raw=(custody/name).read_bytes();files.append((q.old.sealed(raw),raw))
        for mode in('normal','queued','getrandom-failure'):
            b=Bound(path);init=b.call(0);assert init['status']==0 and init['state']==2
            v=Values(Engine(b));carrier=q.Carrier(b.owner)
            parent=out/(mode+'-artifacts');parent.mkdir()
            actual=q.old.create(carrier,files,parent)
            if mode!='normal':pending_function(v,b)
            if mode=='getrandom-failure':
                results=queue.Queue()
                def denied_capture():
                    try:
                        deny_native(ip_at(b.value,values_pack),318,errno.EIO)
                        results.put(capture(v,actual))
                    except BaseException as error:results.put(error)
                thread=threading.Thread(target=denied_capture);thread.start();thread.join(30);assert not thread.is_alive()
                reply=results.get_nowait()
                if isinstance(reply,BaseException):raise reply
                assert word(reply,8)==11 and reply[24:48]==bytes(24),reply[:128].hex()
                assert tuple(word(reply,i)for i in(80,88,96,104,112,120))==(1,1,0,0,1,1),reply[:128].hex()
                assert word(v.engine.context,176)==1
                carrier.q(3,actual)
            else:
                reply=capture(v,actual)
                assert word(reply,8)==0 and tuple(word(reply,i)for i in(88,96,104,120))==(1,1,0,1),reply[:128].hex()
                pending=int(mode=='queued')
                assert tuple(word(reply,i)for i in(80,112))==(pending,pending)
                value=v.keep(reply)
                assert word(v.engine.context,176)==pending
            v.raw(47)
            assert word(v.engine.context,176)==word(v.engine.context,184)==0
            if mode!='getrandom-failure':
                assert v.isinst(value,v.builtin(20));v.drop(value)
            for cap in list(v.held):v.drop(cap)
            sweep(v,b);b.close()
            assert not list(parent.iterdir())
            rows.append(dict(case=mode,reply=reply[:128].hex(),actual_native_custody=True,
                unconsumed_input_released_only_by_caller=mode=='getrandom-failure',
                single_entry_deferred=True,actual_outer_native_retry=True))
            print('DEFERRED_CAPTURE_PASS',mode,flush=True)
        b=Bound(path);init=b.call(0);assert init['status']==0;v=Values(Engine(b))
        controls=[]
        for op in(0,1,2,3,4,5,6,19,20,21,29,30,31,49,50,56,61,68,69,70,75,77,78,91,92,93,97,98,100):
            raw=bytearray(frame(op));raw[:8]=b'HIABVQ08';controls.append(bytes(raw))
        valid=bytearray(frame(48,arg0=1,tail=bytes(24)));valid[:8]=b'HIABVQ08'
        for at in(16,112,120):
            bad=bytearray(valid);struct.pack_into('<Q',bad,at,1);controls.append(bytes(bad))
        for raw in controls:
            context=bytes(v.engine.context);rc,reply=v.engine.call(raw)
            assert rc==0xfffffffd and bytes(v.engine.context)==context
            expected=bytearray(b'\xa5'*len(reply));expected[128:136]=bytes(8);assert reply==expected
        sweep(v,b);b.close();rows.append(dict(case='exact-Q08-domain-and-unchanged-refusal',controls=len(controls)))
        report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()))
    except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:
        for fd,_ in files:os.close(fd)
        save(out/'report.json',report)
    assert set(os.listdir('/proc/self/fd'))==before
    return report
def main():
    p=argparse.ArgumentParser()
    for name in('owner','custody','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.owner,a.custody,a.output)
if __name__=='__main__':main()
