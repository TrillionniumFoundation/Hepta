"""Mechanical native journal bridge harness; reference semantics are oracle-only.

NEW CI DEVELOPMENT. Source-bound image mapping is done only after full readback.
The actual forwarding interval forbids the retained transport/record owners.
No SQLite, namespace publication, tool business or ordinary Worker is claimed.
"""
from __future__ import annotations
from contextlib import contextmanager,ExitStack
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct,sys,zlib
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT.parent
REFERENCE=BASE/"Hepta-agent-edit-native"
sys.path.insert(0,str(REFERENCE))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_agent_journal_native import NativeAgentJournal,JournalSession
M=lambda s:int.from_bytes(s,"little")
BAD=0xfffffffd
CANARY=bytes(range(64))
CLASS={1:"ValueError",4:"OverflowError",6:"RuntimeError",7:"UnicodeDecodeError",8:"JSONDecodeError"}
def word(b,at=0): return struct.unpack_from("<Q",b,at)[0]
def pack(*values): return struct.pack("<"+"Q"*len(values),*values)
def current_pin(path):
    path=Path(path).resolve(); b=path.read_bytes()
    return dict(path=str(path),bytes=len(b),sha256=sha256(b).hexdigest(),raw=b)
def disabled(*a,**kw): raise AssertionError("retained semantic/transport owner entered during native forwarding")
@contextmanager
def forbidden():
    with ExitStack() as stack:
        for name in ("hepta.hia_agent_journal_native.JournalSession._run",
                     "hepta.hia_agent_journal_native.buffer_sizes",
                     "hepta.hia_agent_journal_native.materialize_data",
                     "hepta.hia_agent_journal_native.wire",
                     "hepta.hia_agent_journal_native.call_with_native_journal",
                     "hepta.hia_agent_service.HIAAgentService._reference_call","json.loads"):
            stack.enter_context(patch(name,new=disabled))
        yield

class Buffer:
    def __init__(self,size,initial=b""):
        assert 0<=len(initial)<=size
        self.size=size
        self.array=ctypes.create_string_buffer(size+64)
        if initial: ctypes.memmove(self.address,initial,len(initial))
        ctypes.memmove(self.address+size,CANARY,64)
    @property
    def address(self): return ctypes.addressof(self.array)
    def bytes(self): return ctypes.string_at(self.address,self.size)
    def guard(self): assert ctypes.string_at(self.address+self.size,64)==CANARY
    def view(self,at,size):
        assert 0<=at<=self.size and 0<=size<=self.size-at
        return ctypes.c_void_p(self.address+at)
    def write(self,at,raw):
        assert 0<=at<=self.size and len(raw)<=self.size-at
        ctypes.memmove(self.address+at,raw,len(raw))

class Harness:
    def __init__(self,out):
        self.out=Path(out)
        self.pins={}
        def read(path):
            path=Path(path).resolve();raw=path.read_bytes()
            if path in self.pins: assert self.pins[path]==raw
            self.pins[path]=raw
            return raw
        manifest=ROOT/"development/compile-ci-r1/bundle.json"
        bundle=json.loads(read(manifest))
        assert bundle["status"]=="PASS" and bundle["fresh_ci_compilation"] is True
        assert bundle["scope"]=="NEW_CI_JOURNAL_TRANSPORT_DEVELOPMENT_NOT_NAMESPACE_OR_COMPLETE_WORKER_OR_COLD"
        assert set(bundle["components"])=={"bridge","journal"}
        images={}
        for role,row in bundle["components"].items():
            assert row["schema"]=="hepta.hia.agent-service-journal-"+role+"-development.v1"
            src=read(row["source_path"])
            current=(ROOT/"examples/hia_bootstrap/agent_service_journal_bridge.hiaasm" if role=="bridge"
                     else REFERENCE/"examples/hia_bootstrap/agent_journal.hiaasm")
            assert src==read(current)
            assert (len(src),sha256(src).hexdigest())==(row["source_bytes"],row["source_sha256"])
            image=read(row["image_path"])
            assert (len(image),sha256(image).hexdigest())==(row["image_bytes"],row["image_sha256"])
            compiler=read(row["compiler_path"])
            assert len(compiler)==668608 and sha256(compiler).hexdigest()==row["compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
            receipt=json.loads(read(row["receipt_path"]))
            assert (receipt["input_sha256"],receipt["produced_sha256"],receipt["image_sha256"])==(row["source_sha256"],row["image_sha256"],row["compiler_sha256"])
            images[role]=(image,row["image_sha256"])
        for path in [Path(__file__),*sorted((ROOT/"tools").glob("*.py")),
                     REFERENCE/"hepta/hia_agent_journal_native.py",
                     REFERENCE/"hepta/hia_json_preflight_native.py",
                     REFERENCE/"hepta/hia_json_decode_native.py"]:
            read(path)
        self.readback()
        self.out.mkdir(parents=True,exist_ok=False)
        (self.out/"cas").mkdir()
        self.entries=dict(bridge=0,journal=0,oracle=0)
        self.saved=set()
        self.ledger=(self.out/"entries.jsonl").open("w")
        self.images={k:NativeHiaJsonImage(*v) for k,v in images.items()}
        self.oracle_image=NativeAgentJournal(*images["journal"])
        self.oracle_entry=self.oracle_image._entry
        self.fault=None
        def oracle(s,n,o,on,w,wn):
            before_s=ctypes.string_at(s,n+64)
            before_w=ctypes.string_at(w,wn)
            before_o=ctypes.string_at(o,on)
            result=int(self.oracle_entry(s,n,o,on,w,wn))
            if self.fault is not None: result=self.fault(result,s,n,o,on,w,wn)
            self.entries["oracle"]+=1
            self.record("oracle",result,source_before=before_s,source_after=ctypes.string_at(s,n+64),
                        output_before=before_o,output_after=ctypes.string_at(o,on+64),
                        scratch_before=before_w,scratch_after=ctypes.string_at(w,wn+64))
            return result
        self.oracle_image._entry=oracle
        self.savepins("source-before.json")
    def save(self,raw):
        raw=bytes(raw);key=sha256(raw).hexdigest()
        if key not in self.saved:
            p=self.out/"cas"/(key+".zlib")
            compressed=zlib.compress(raw,1)
            with p.open("xb") as f:f.write(compressed)
            assert zlib.decompress(p.read_bytes())==raw
            self.saved.add(key)
        return dict(bytes=len(raw),sha256=key,cas="cas/"+key+".zlib")
    def record(self,role,result,**buffers):
        row=dict(entry=sum(self.entries.values()),role=role,result=result,
                 buffers={k:self.save(v) for k,v in buffers.items()})
        self.ledger.write(json.dumps(row,sort_keys=True)+"\n");self.ledger.flush()
    def readback(self):
        assert all(p.read_bytes()==raw for p,raw in self.pins.items())
    def savepins(self,name):
        (self.out/name).write_text(json.dumps([dict(path=str(p),bytes=len(b),sha256=sha256(b).hexdigest()) for p,b in self.pins.items()],indent=2,sort_keys=True)+"\n")
    def bridge(self,source,request,work,*,advertised=None):
        source_before=source.bytes();request_before=request.bytes();before=work.bytes()
        n=work.size if advertised is None else advertised
        assert 0<=n<=work.size
        result=int(self.images["bridge"]._entry(source.view(0,source.size),source.size,
                   request.view(0,request.size),request.size,work.view(0,n),n))
        source.guard();request.guard();work.guard()
        assert source.bytes()==source_before and request.bytes()==request_before
        if n<work.size: assert work.bytes()[n:]==before[n:],"write outside borrowed extent"
        self.entries["bridge"]+=1
        self.record("bridge",result,source=source_before,request=request_before,workspace_before=before,workspace_after=work.bytes())
        return result
    def journal(self,source,event,work,fault=None):
        n=event[7];oo,on=event[9:11];wo,wn=event[11:13]
        assert event[8]==0 and n<=source.size
        before_s=source.bytes();before_w=work.bytes()
        result=int(self.images["journal"]._entry(source.view(0,n),n,work.view(oo,on),on,work.view(wo,wn),wn))
        if fault is not None:
            result=fault(result,source.view(0,n),n,work.view(oo,on),on,work.view(wo,wn),wn)
        source.guard();work.guard()
        intact=source.bytes()==before_s
        self.entries["journal"]+=1
        self.record("journal",result,source_before=before_s,source_after=source.bytes(),
                    workspace_before=before_w,workspace_after=work.bytes())
        return result,intact
    def close(self):
        self.readback();self.savepins("source-after.json")
        self.ledger.close()
        self.oracle_image._entry=self.oracle_entry
        for image in [*self.images.values(),self.oracle_image]:
            image._entry=None
            image._mapping.close()
        self.images.clear()
        self.oracle_image=None

class Session:
    def __init__(self,h,lease):
        self.h=h;self.lease=lease;self.sequence=0;self.event_sequence=0
        self.work=Buffer(4096)
    def replace_state(self,state):
        assert len(state)==512
        self.work.write(512,state)
    def call(self,stage,raw=b"",foreign=b"",profile=False,digits=None,fault=None):
        if digits is None:digits=sys.get_int_max_str_digits()
        self.sequence+=1
        source=Buffer(len(raw)+len(foreign),raw+foreign)
        command=pack(M(b"HIASJB01"),self.lease,self.sequence,stage,len(raw),len(foreign),int(profile),digits,*([0]*8))
        request=Buffer(len(command),command)
        calls=0;grows=0;actual_codes=[]
        with forbidden():
            while True:
                result=self.h.bridge(source,request,self.work)
                assert result==512,("unexpected bridge refusal",result,self.work.bytes()[:512].hex())
                event=struct.unpack_from("<32Q",self.work.bytes(),256)
                assert event[:5]==(M(b"HIASJE01"),event[1],self.lease,self.sequence,self.event_sequence+1)
                assert event[5]==stage and event[7]==len(raw) and event[8]==0
                self.event_sequence=event[4]
                if event[1]==1:
                    assert event[6]>self.work.size and event[6]<(1<<30)
                    self.work=Buffer(event[6],self.work.bytes());grows+=1
                    continue
                if event[1]==2:
                    assert calls==0
                    result,intact=self.h.journal(source,event,self.work,fault=fault)
                    calls+=1;actual_codes.append(result)
                    ack=pack(M(b"HIASJA01"),self.lease,self.sequence,event[4],result,
                             len(raw),event[10],event[12],int(intact),*([0]*7))
                    request=Buffer(128,ack)
                    continue
                assert event[1] in (0,3),event
                state=self.work.bytes()
                def view(at,n):
                    assert at<=len(state) and n<=len(state)-at
                    return state[at:at+n]
                assert event[14:16]==(512,512)
                observation=dict(action=event[1],code=event[13],flags=event[16],status=event[17],
                    response=view(event[18],event[19]),cost_details=view(event[20],event[21]),
                    arena=view(event[22],event[23]),error_class=CLASS.get(event[24]),
                    message=view(event[25],event[26]).decode("utf-8"),saved_state=state[512:1024],
                    event=event,journal_calls=calls,grows=grows,actual_codes=actual_codes)
                return observation
    def close(self):self.work=None

class Pair:
    def __init__(self,h,lease):
        self.h=h;self.native=Session(h,lease);self.reference=h.oracle_image.session()
    def replace_state(self,state):
        self.reference._state=state;self.native.replace_state(state)
    def step(self,label,stage,raw=b"",foreign=b"",profile=False,fault=None):
        self.h.fault=fault
        try:
            try:
                result=self.reference._run(stage,raw,foreign,data_profile=profile)
                expected=dict(ok=True,code=result.action,flags=result.flags,
                              response=result.response,cost_details=result.cost_details,
                              status={None:0,"completed":1,"rejected":2}[result.status],arena=result.arena)
            except Exception as exc:
                expected=dict(ok=False,error_class=type(exc).__name__,message=str(exc))
        finally:self.h.fault=None
        before=dict(self.h.entries)
        got=self.native.call(stage,raw,foreign,profile,fault=fault)
        assert got["saved_state"]==self.reference._state,(label,"saved state differs")
        if expected["ok"]:
            assert got["action"]==0,(label,got["event"],got["message"])
            for key in ("code","flags","response","cost_details","status","arena"):
                assert got[key]==expected[key],(label,key,got[key] if not isinstance(got[key],bytes) else self.h.save(got[key]),
                                               expected[key] if not isinstance(expected[key],bytes) else self.h.save(expected[key]))
        else:
            assert got["action"]==3,(label,expected,got["event"])
            assert (got["error_class"],got["message"])==(expected["error_class"],expected["message"]),(label,expected,got)
        row=dict(case=label,stage=stage,status="PASS",data_profile=profile,
            input=self.h.save(raw),foreign=self.h.save(foreign),saved_state=self.h.save(got["saved_state"]),
            event=got["event"],journal_calls=got["journal_calls"],grows=got["grows"],
            oracle={k:(self.h.save(v) if isinstance(v,bytes) else v) for k,v in expected.items()},
            actual_entries={k:self.h.entries[k]-before[k] for k in before},
            namespace_effect_performed=False)
        return row,got
    def close(self):self.native.close()
