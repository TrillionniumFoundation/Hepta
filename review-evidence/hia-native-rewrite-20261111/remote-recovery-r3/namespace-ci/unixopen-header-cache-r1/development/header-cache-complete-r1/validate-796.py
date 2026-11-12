"""Complete old/new VM/native byte, trap and fixed-caller witness differential.
Private isolated loop probes cover otherwise unreachable empty/wrap states.
No original 28-case runtime group is replaced or split by this development test.
"""
from __future__ import annotations
import hashlib,importlib.util,json,os,resource,signal,struct,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/"nine-role-local-r4"
INPUT=ROOT.parent/"unix9-header-cache-r1"
REF=Path("/workspace/scratch/9acdfa9f5639/reference0ef")
MASK=(1<<64)-1
def sha(b):return hashlib.sha256(b).hexdigest()
def ident(p):
    p=Path(p);b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=p.stat().st_mode&0o777,gitsha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest())
def save(p,v):
    raw=(json.dumps(v,sort_keys=True,indent=2)+"\n").encode();p.write_bytes(raw);assert p.read_bytes()==raw
def put(b,at,n):struct.pack_into("<Q",b,at,n&MASK)
def q(b,at):return struct.unpack_from("<Q",b,at)[0]
def load(name,p):
    spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(Path(p).read_bytes(),str(p),"exec"),m.__dict__);return m
def main():
    started=time.monotonic_ns();primary=None;pins={};cas={};ledger=[];counts={}
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def timeout(*_):raise TimeoutError("180 wall")
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
    out=ROOT/"paired";out.mkdir(exist_ok=False);(out/"cas").mkdir();(out/"native").mkdir()
    report=dict(status="INCOMPLETE",scope="LOCAL_HEADER_READ_HOIST_COMPLETE_DIFFERENTIAL_NOT_WHOLE_GATE",
        pairs=0,old_VM=0,new_VM=0,old_native=0,new_native=0,new_B3_in_this_test=0,
        no_arbitrary_fuel_equivalence=True,no_concurrent_W_writer_equivalence=True)
    def pin(p):
        p=Path(p);pins[str(p)]=ident(p);return p.read_bytes()
    def kept(b):
        b=bytes(b);h=sha(b);p=out/"cas"/h
        if h not in cas:p.write_bytes(b);cas[h]=dict(bytes=len(b),sha256=h,path="cas/"+h)
        assert p.read_bytes()==b
        return cas[h]
    try:
        pin(__file__);carrier=load("header_capture",ROOT/"native_capture_r2.py");pin(ROOT/"native_capture_r2.py")
        build=json.loads(pin(ROOT/"build-r2/summary.json"));assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_B3"]==8
        sys.path[:0]=[str(BASE/"source"),str(REF)]
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View,HIAProgramTrap
        programs={};images={}
        for name,row in build["rows"].items():
            source=pin(row["source"]["path"]);image=pin(row["image"]["path"])
            assert sha(source)==row["source"]["sha256"] and sha(image)==row["image"]["sha256"]
            programs[name]=assemble_program(source);images[name]=image
        replay=load("frozen_record_decoder",BASE/"source/inputs/actual-unixopen-replay.py");pin(BASE/"source/inputs/actual-unixopen-replay.py")
        assert ident(BASE/"source/inputs/actual-unixopen-replay.py")["gitsha"]=="b8854ced763c3df029137ae0e82e586e5f20ea55"
        trace=BASE/"evidence/actual-unixopen-raw-prefix-r1/cases/main_PID_match/trace.bin";pin(trace)
        rows=list(replay.records(trace));windows=[];before={}
        for r in rows:
            if r["role"]!=9:continue
            serial=r["header"][2]
            if r["kind"]==1:
                assert serial not in before;before[serial]=r
            elif r["kind"]==2:
                a=before.pop(serial);windows.append((a,r))
        assert not before and len(windows)==10
        def vm(name,s,o,w):
            owners=[_Owner(-1,bytearray(s)),_Owner(-2,bytearray(o)),_Owner(-3,bytearray(w))]
            m=_Machine(programs[name],4_000_000,32<<20,None,64);begin=time.process_time_ns()
            try:
                returned=m.invoke(m.functions["f0"],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                result=dict(status="returned",result=returned)
            except HIAProgramTrap as exc:result=dict(status="trap",code=exc.code,message=str(exc))
            result.update(steps=m.steps,resources=m.resources(),CPU_ns=time.process_time_ns()-begin)
            actual=[bytes(owner.data) for owner in owners];assert actual[0]==s
            return result,actual
        def compare(family,label,s,o,w,expected=None,recorded=None):
            index=len(ledger);pre=dict(source=kept(s),output=kept(o),workspace=kept(w))
            current=dict(index=index,family=family,label=label,pre=pre)
            save(out/"frontier.json",dict(status="BEFORE_OLD_VM",**current))
            a,ab=vm("old-"+family,s,o,w);report["old_VM"]+=1
            save(out/"frontier.json",dict(status="BEFORE_NEW_VM",old_VM=a,**current))
            b,bb=vm("new-"+family,s,o,w);report["new_VM"]+=1
            for k in ("status","result","code","message","resources"):assert a.get(k)==b.get(k),(label,k,a,b)
            assert ab==bb,(label,"complete VM buffers")
            if expected is not None:assert (a["status"],a.get("result"))==expected,(label,a,expected)
            if recorded is not None:
                assert a["status"]=="returned" and a["result"]==recorded["header"][6]
                assert ab[1]==recorded["output"] and ab[2]==recorded["workspace"]
            native=[]
            for side in ("old","new"):
                save(out/"frontier.json",dict(status="BEFORE_"+side.upper()+"_NATIVE",old_VM=a,new_VM=b,**current))
                receipt,nb=carrier.call(images[side+"-"+family],s,o,w,out/"native"/(str(index)+"-"+side))
                report[side+"_native"]+=1
                assert nb==ab,(label,side,"complete native buffers")
                assert receipt["returncode"]==(0 if a["status"]=="returned" else -signal.SIGILL)
                if a["status"]=="returned":assert receipt["result"]==a["result"]
                native.append(receipt)
            current.update(old_VM=a,new_VM=b,native=native,actual_source=kept(ab[0]),actual_output=kept(ab[1]),actual_workspace=kept(ab[2]),
                full_buffers_equal=True,actual_canaries_equal=True,recorded_original_equal=recorded is not None)
            ledger.append(current);counts[family]=counts.get(family,0)+1
            report["pairs"]+=1
            with (out/"entries.jsonl").open("ab") as stream:
                stream.write((json.dumps(current,sort_keys=True,separators=(",",":"))+"\n").encode());stream.flush()
            save(out/"frontier.json",dict(status="COMPLETE",**current))
            return a
        # Every actual role9 window from the original first completed case.
        for a,b in windows:
            compare("full","actual-main-serial-"+str(a["header"][2]),a["input"],a["output"],a["workspace"],recorded=b)
        # Complete-helper probes retain the original nonentry functions byte for byte.
        seed=next(a for a,b in windows if a["header"][2]==9)
        s=seed["input"];w=seed["workspace"];marker=bytes([165])*17
        compare("shape","actual-shape",s,marker,w,expected=("returned",1))
        for n in (0,1,7,8,15,16,23,24,55,56,63,64,215,216,223,224,231,232,239,240,247,248,255,256,263,264,271,272,279,280):
            compare("shape","short-work-"+str(n),s,marker,w[:n])
        for n in (0,1,15,16,23,63,64,71,72,79,80,255,256,263,264,271,279,287,303,304,311,312,319,359,360,367,368,375,376,383,384,len(s)-1):
            compare("shape","short-source-"+str(n),s[:n],marker,w)
        for at in (16,24,32,40,48,56,64,80,208,256,264,272,280,288,296,304,312,320,328,336,344,352,360,368,376,384,len(s)-1):
            raw=bytearray(s);raw[at]^=1;compare("shape","changed-source-byte-"+str(at),bytes(raw),marker,w)
        for at,value in ((224,MASK),(224,len(w)),(232,0),(232,MASK),(240,MASK),(240,len(w)),(248,0),(248,MASK)):
            raw=bytearray(w);put(raw,at,value);compare("shape","changed-W-word-"+str(at)+"-"+str(value),s,marker,bytes(raw))
        # Exact isolated loop slices: complete every short W length, including
        # original header partial reads and original zero-iteration behavior.
        for lane in (0,1):
            for n in range(256):
                ss=bytearray(400);ww=bytearray(n)
                if lane:put(ss,304,8)
                compare("loop"+str(lane),"every-short-W-"+str(n),bytes(ss),marker,bytes(ww))
        def loop_input(lane,size,base=320,wlen=512,slen=512,prefix=8,mismatch=None):
            ss=bytearray((i*17+13)&255 for i in range(slen))
            ww=bytearray((i*29+7)&255 for i in range(wlen))
            size_at=232 if lane==0 else 248;base_at=224 if lane==0 else 240
            if len(ww)>=size_at+8:put(ww,size_at,size)
            if len(ww)>=base_at+8:put(ww,base_at,base)
            if lane and len(ss)>=312:put(ss,304,prefix)
            start=384 if lane==0 else (384+prefix)&MASK
            for i in range(min(size,64)):
                x=(start+i)&MASK;y=(base+i)&MASK
                if x<len(ss) and y<len(ww):ss[x]=ww[y]
            if mismatch is not None:
                x=(start+mismatch)&MASK
                if x<len(ss):ss[x]^=1
            return bytes(ss),marker,bytes(ww)
        for lane in (0,1):
            family="loop"+str(lane)
            for n in (0,1,2,7,8,9,16,31,32):
                compare(family,"equal-"+str(n),*loop_input(lane,n),expected=("returned",1))
            for i in range(32):
                compare(family,"first-mismatch-"+str(i),*loop_input(lane,32,mismatch=i),expected=("returned",0))
            for n in (256,257,263,264):
                compare(family,"guard-edge-empty-"+str(n),*loop_input(lane,0,base=MASK,wlen=n),expected=("returned",1))
            for base in (511,512,513,MASK-7,MASK-1,MASK):
                compare(family,"bad-W-span-"+str(base),*loop_input(lane,2,base=base))
            for n in (0,1,303,304,305,306,307,308,309,310,311,312,383,384,385,391,392):
                compare(family,"short-S-"+str(n),*loop_input(lane,8,slen=n))
            compare(family,"huge-size-first-inequality",*loop_input(lane,MASK,mismatch=0),expected=("returned",0))
            compare(family,"huge-size-next-bounds",*loop_input(lane,MASK,base=511,slen=386))
            for output_len in (0,1,7,8,31):
                ss,_,ww=loop_input(lane,8,base=512)
                compare(family,"trap-after-marker-output-"+str(output_len),ss,bytes([165])*output_len,ww,expected=("trap",None))
        # Actual u64 prefix additions wrap, followed by original ordered byte reads.
        for prefix in (MASK-383,MASK-382,MASK-380,MASK-375,MASK-1,MASK):
            for mismatch in (None,0,3):
                compare("loop1","wrapped-start-"+str(prefix)+"-"+str(mismatch),*loop_input(1,4,prefix=prefix,mismatch=mismatch))
        # Empty second loop still reads its original start header first.
        for n in (0,303,304,305,310,311,312,384):
            compare("loop1","empty-second-short-source-"+str(n),*loop_input(1,0,slen=n,base=MASK))
        assert counts=={"full":10,"shape":98,"loop0":331,"loop1":357},counts
        assert len(ledger)==796 and report["old_VM"]==report["new_VM"]==report["old_native"]==report["new_native"]==796
        for h,meta in cas.items():
            b=(out/meta["path"]).read_bytes();assert len(b)==meta["bytes"] and sha(b)==h
        save(out/"cas-index.json",list(cas.values()))
        for module in tuple(sys.modules.values()):
            path=getattr(module,"__file__",None)
            if path:
                p=Path(path).resolve()
                if p.suffix==".py" and (p.is_relative_to(REF) or p.is_relative_to(BASE/"source")):pin(p)
        report.update(status="PASS",families=counts,complete_cases=len(ledger),full_buffer_trap_resource_equivalence=True,
            old_new_steps_recorded_not_required_equal=True,original_recorded_role9_windows=10,
            per_function_VM=dict(steps=4_000_000,heap_bytes=32<<20,depth=64),
            isolated_loop_controls_not_public_source_reachability=True,ordinary_original_28_cases_not_executed_here=True)
    except BaseException as exc:
        primary=exc;report.update(status="FAIL",error=repr(exc),traceback=traceback.format_exc());traceback.print_exc()
    finally:
        errors=[]
        for path,before in pins.items():
            try:assert ident(path)==before
            except BaseException as exc:
                errors.append(dict(path=path,error=repr(exc)))
                if primary is None:primary=exc
                else:primary.add_note(repr(exc))
        report.update(source_before=pins,after_errors=errors,families=counts)
        if primary is not None:report["status"]="FAIL"
        try:
            save(out/"summary.json",report);print(json.dumps({k:v for k,v in report.items() if k not in ("source_before","traceback")},sort_keys=True),flush=True)
            usage=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu=usage.ru_utime+usage.ru_stime+child.ru_utime+child.ru_stime;elapsed=time.monotonic_ns()-started
            assert 0<=cpu<90 and 0<=elapsed<180_000_000_000
        except BaseException as exc:
            if primary is None:primary=exc
            else:primary.add_note(repr(exc))
        if primary is not None:
            report.update(status="FAIL",final_error=repr(primary))
            try:save(out/"summary.json",report)
            except BaseException as exc:primary.add_note("FAILreceipt:"+repr(exc))
        signal.setitimer(signal.ITIMER_REAL,0)
    if primary is not None:raise primary
if __name__=="__main__":main()
