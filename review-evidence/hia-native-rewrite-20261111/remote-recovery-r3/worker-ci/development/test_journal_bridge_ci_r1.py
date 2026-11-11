"""Fresh actual-image journal bridge differential groups; not a namespace test."""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json,os,random,resource,struct,sys,time,traceback
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from journal_bridge_ci_harness_r1 import Harness,Pair,Session,Buffer,M,BAD,CANARY,pack,word,forbidden,REFERENCE
from hepta.hia_agent_journal_native import TOOLS,HEADER_OFFSET,PRIVATE_BYTES,_foreign_tool_types
OUT=Path(sys.argv[1]);MODE=sys.argv[2]
SELF=Path(__file__).resolve();test_raw=SELF.read_bytes()
h=Harness(OUT);rows=[];lease=1000
started=time.monotonic_ns()
summary=dict(status="INCOMPLETE",mode=MODE,environment="github-actions",
    scope="ACTUAL_JOURNAL_AND_HIA_TRANSPORT_COMPONENT_NOT_NAMESPACE_OR_COMPLETE_WORKER",
    namespace_effects=0,historical_test_counts_inherited=False,
    child_cpu_seconds=90,child_address_space_bytes=1<<30)
def wire(value):return json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(",",":")).encode()
def pair():
    global lease
    lease+=1;return Pair(h,lease)
def step(p,label,stage,raw=b"",foreign=b"",profile=False,fault=None):
    row,got=p.step(label,stage,raw,foreign,profile,fault)
    rows.append(row)
    with (OUT/"cases.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
    print(json.dumps(dict(case=label,status="PASS",stage=stage,error=row["oracle"].get("error_class")),sort_keys=True),flush=True)
    return got
def cached(p,tool="hia_verify"):
    step(p,"cache/prepare",0,wire(dict(tool=tool,arguments=dict(request_key="cache"))))
    digest=p.reference.request_digest
    step(p,"cache/lookup",1,wire(dict(digest=digest,state="completed")))
def scalar_fault(offset,value):
    def fault(code,s,n,o,on,w,wn):
        struct.pack_into("<Q",(ctypes.c_ubyte*on).from_address(o.value if isinstance(o,ctypes.c_void_p) else ctypes.addressof(o)),HEADER_OFFSET+offset,value)
        return code
    return fault
try:
    if MODE=="smoke":
        p=pair()
        step(p,"catalog/full-current",9,(REFERENCE/"docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json").read_bytes())
        p.close()
        p=pair();step(p,"utf8/valid-full",10,"雪🙂\n".encode());p.close()
        p=pair()
        for stage in (2,4,5,7,8):step(p,"early-invalid-stage-"+str(stage),stage)
        p.close()
        for tool in ("hia_artifact","hia_verify","hia_adopt"):
            p=pair()
            step(p,tool+"/prepare",0,wire(dict(tool=tool,arguments=dict(request_key="phase"))))
            step(p,tool+"/lookup",1,b"null")
            step(p,tool+"/reserved",2)
            step(p,tool+"/duplicate-reserved",2)
            step(p,tool+"/effect",5)
            response=wire(dict(status="completed",result={"z":-0.0,"a":1.25}))
            if tool=="hia_adopt":
                step(p,tool+"/inline",6,response)
                step(p,tool+"/committed",7)
                step(p,tool+"/duplicate-commit",7)
            step(p,tool+"/finish",8,response)
            step(p,tool+"/duplicate-finish",8,response)
            p.close()
        p=pair()
        step(p,"alias/prepare",0,wire(dict(tool="hia_resource_read",arguments={})))
        step(p,"alias/ack",4);step(p,"alias/effect",5)
        step(p,"alias/finish",8,wire(dict(status="rejected",error={"message":"observed"})));p.close()
        for tool in ("hia_artifact","hia_verify"):
            for status in ("completed","rejected"):
                p=pair();cached(p,tool)
                step(p,tool+"/cached-"+status,3,('{"z":2,"status":"'+status+'","a":-0.0}').encode())
                step(p,tool+"/cached-finally-no-write",8);p.close()
        assert set(r["stage"] for r in rows)==set(range(11))
    elif MODE=="semantic":
        keys=("", "a", "雪"*192, "🧪"*193,7,None)
        numbers=(0,-0.0,1.25,1e15,1e-300,5e-324,1.7976931348623157e308,10**300)
        for ti,tool in enumerate((*TOOLS,"unknown",[],{})):
            for ki,key in enumerate(keys):
                p=pair()
                arguments=dict(request_key=key,number=numbers[(ti+ki)%len(numbers)],nested={"request_key":"not-outer"})
                raw=json.dumps(dict(tool=tool,arguments=arguments),ensure_ascii=False,separators=(",",":")).encode()
                step(p,"identity-%d-%d"%(ti,ki),0,raw);p.close()
        for tool in (("hia_verify",),([],),({},),("x",[]),("x",{})):
            p=pair();step(p,"foreign-"+str(lease),0,wire(dict(tool=tool,arguments={})),_foreign_tool_types(tool));p.close()
        for state,changed in (("running",False),("completed",True),("alien",False)):
            p=pair();step(p,"row/prepare-"+state,0,wire(dict(tool="hia_verify",arguments=dict(request_key="r"))))
            step(p,"row/"+state,1,wire(dict(digest="0"*64 if changed else p.reference.request_digest,state=state)));p.close()
        for value in (None,False,0,"",[],{},{"status":"completed"},{"status":"rejected"},{"x":"雪"},1.25):
            p=pair();cached(p)
            step(p,"cached-root-"+str(lease),3,wire(value));p.close()
        rng=random.Random(881);values=list(numbers)
        while len(values)<210:
            value=struct.unpack("<d",rng.getrandbits(64).to_bytes(8,"little"))[0]
            if value==value and abs(value)!=float("inf"):values.append(value)
        p=pair();step(p,"binary64/prepare",0,wire(dict(tool="hia_describe",arguments=dict(values=values))))
        step(p,"binary64/finish",8,wire(dict(status="completed",result=values)));p.close()
    elif MODE=="diagnostics":
        texts=("", " ", "[","{","[1","[1,","[1,]","[1 2]",'{1:2}','{"a"}','{"a":}',
          '{"a":1,}','{"a":1 "b":2}',"true false","NaN","Infinity","-","+1",".1","01","1.","1e","1e+","-1.0e-",
          "[1.2e,0]",'{"x":1e+}','"','"abc','"abc\\','"\\x"','"\\u"','"\\u12"','"\\uQQQQ"',
          '"\\ud800"','"\\ud800\\u0041"','"\\udc00"','"a\x01b"','"\\u𐐷','"\\u𐐷ab"',
          '"\\u"123456e7','"\\uG"12345e7','"\\u𐐷"12345e7','"\\u00"12345e7',
          "--1.0","[1.0,--2e0]",'["雪",--1.0]',"[1-1.0]",'{"a":1-1.0}',"10-1.0","-1-1e0",
          "[--1.0,0]",'{"x":--1e0}',"\n[1,\n --2e1]",'{"a":1,"\\u0061":2}',"["*129+"0"+"]"*129,
          '{"x":1e400,"x":0}','{"x":'+"9"*4301+',"x":0}')
        p=pair();cached(p)
        state=p.reference._state
        for profile in (False,True):
            for i,text in enumerate(texts):
                p.replace_state(state)
                step(p,"syntax-%d-%d"%(profile,i),3,text.encode("utf-8"),profile=profile)
        p.close()
        p=pair()
        for lead in range(128,256):step(p,"utf8-lead-"+str(lead),10,bytes([lead]))
        for i,raw in enumerate((b"x\xff",b"\xe0\x80\x80",b"\xed\xa0\x80",b"\xf0\x80\x80\x80",
                               b"\xf4\x90\x80\x80",b"\xe2\x82",b"\xf0\x9f\x92",b"\xc2x",
                               b"\xe2\x82x",b"\xf0\x9f\x92x",b"\n\xff",b"\xe2\x82\xac\xff")):
            step(p,"utf8-span-"+str(i),10,raw)
        p.close()
    elif MODE=="faults":
        # Actual image output is deliberately faulted inside a private executor
        # control. This is never counted as a malformed ordinary source case.
        def base_pair():
            p=pair();step(p,"fault/prepare-"+str(lease),0,wire(dict(tool="hia_describe",arguments={})))
            return p
        for offset,value in ((0,0),(8,9),(8,12),(16,13),(24,2),(32,2),(40,2),
                             (48,99),(264,3),(272,(8<<20)+1),(280,(8<<20)+1),(288,4),
                             (288,1),(272,1),(280,1),(264,1),(64,0)):
            p=base_pair()
            step(p,"state-fault-%d-%d"%(offset,value),5,fault=scalar_fault(offset,value));p.close()
        def code_fault(value):
            return lambda code,s,n,o,on,w,wn:value
        for code in (0xffffffe8,0xffffffe7,0xffffffe4,0xffffffe6,0xffffffe5,0xffffffff,
                     0xfffffffc,0xfffffffe,0xfffffff0,0xffffffea,0xfffffffd,99):
            p=base_pair();step(p,"return-fault-"+str(code),5,fault=code_fault(code));p.close()
        for where in ("output","scratch"):
            def corrupt(code,s,n,o,on,w,wn,where=where):
                p=o if where=="output" else w; n=on if where=="output" else wn
                address=p.value if isinstance(p,ctypes.c_void_p) else ctypes.addressof(p)
                ctypes.c_ubyte.from_address(address+n).value=255
                return code
            p=base_pair();step(p,"canary-"+where,5,fault=corrupt);p.close()
        p=base_pair()
        state=bytearray(p.reference._state);state[192]=255
        p.replace_state(bytes(state));step(p,"prior-request-id-ascii-order",5);p.close()
    elif MODE=="boundary-exact":
        p=pair()
        prefix=b'{"arguments":{"x":"';suffix=b'"},"tool":"hia_describe"}'
        raw=prefix+b"a"*((8<<20)-len(prefix)-len(suffix))+suffix
        assert len(raw)==8<<20
        step(p,"request-exact-8MiB",0,raw);p.close()
    elif MODE=="boundary-plusone":
        p=pair();raw=b"a"*((8<<20)+1)
        step(p,"request-8MiB-plus-one-before-image",0,raw)
        step(p,"utf8-full-8MiB-plus-one-still-enters-image",10,raw)
        step(p,"utf8-invalid-after-8MiB",10,raw+b"\xff")
        p.close()
    elif MODE=="foreign-boundary":
        for n in (0,1,262144,262145):
            p=pair()
            step(p,"foreign-max-"+str(n),0,wire(dict(tool="hia_describe",arguments={})),b"\0"*n);p.close()
        p=pair();step(p,"foreign-disallowed-stage-before-image",1,b"null",b"x");p.close()
    else:raise AssertionError(("unknown group",MODE))
    assert rows
    summary.update(status="PASS",cases=len(rows),entries=h.entries,
        stages=sorted(set(r["stage"] for r in rows)),semantic_owner_disabled_during_actual_forwarding=True,
        private_fault_controls=MODE=="faults",borrowed_source_is_private_issued_lease=True)
except BaseException as exc:
    summary.update(status="FAIL",cases=len(rows),entries=h.entries,error_class=type(exc).__name__,error=str(exc))
    traceback.print_exc();raise
finally:
    summary["elapsed_ns"]=time.monotonic_ns()-started
    summary["test_source_unchanged"]=SELF.read_bytes()==test_raw
    try:h.close()
    except BaseException as exc:
        summary.update(status="FAIL",close_error_class=type(exc).__name__,close_error=str(exc))
        raise
    finally:
        (OUT/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
        print(json.dumps(summary,sort_keys=True),flush=True)
    assert summary["test_source_unchanged"]
