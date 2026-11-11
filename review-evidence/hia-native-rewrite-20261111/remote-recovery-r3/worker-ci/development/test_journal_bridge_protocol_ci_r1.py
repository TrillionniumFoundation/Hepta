"""Actual-image journal transport protocol controls, distinct from source semantics."""
from __future__ import annotations
import json,resource,struct,sys,time,traceback
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from journal_bridge_ci_harness_r1 import Harness,Buffer,M,BAD,pack,word,forbidden
OUT=Path(sys.argv[1]);SELF=Path(__file__).resolve();test_raw=SELF.read_bytes()
h=Harness(OUT);rows=[];start=time.monotonic_ns()
source=b'{"tool":"hia_describe","arguments":{}}'
command=pack(M(b"HIASJB01"),771,1,0,len(source),0,0,4300,*([0]*8))
def change(raw,at,value):
    result=bytearray(raw);struct.pack_into("<Q",result,at,value);return bytes(result)
def invoke(s,r,w,label,advertised=None):
    src=Buffer(len(s),s);req=Buffer(len(r),r);work=Buffer(len(w),w)
    with forbidden():result=h.bridge(src,req,work,advertised=advertised)
    return result,work.bytes()
def row(label,**kw):
    item=dict(case=label,status="PASS",scope="PRIVATE_PROTOCOL_CONTROL_NOT_ORDINARY_SOURCE",**kw)
    rows.append(item)
    with (OUT/"cases.jsonl").open("a") as f:f.write(json.dumps(item,sort_keys=True)+"\n")
    print(json.dumps(dict(case=label,status="PASS")),flush=True)
def bad(label,s=source,r=command,w=None,reason=None):
    w=bytes(4096) if w is None else w
    result,after=invoke(s,r,w,label)
    assert result==BAD and word(after,8)==5,(label,result,after[:512].hex())
    if reason is not None:assert word(after,216)==reason,(label,word(after,216),reason)
    result2,last=invoke(s,command,after,label+"/after-poison")
    assert result2==BAD and last==after,(label,"not permanent refusal")
    row(label,private_reason=word(after,216),poisoned=True)
summary=dict(status="INCOMPLETE",scope="PRIVATE_RAW_BRIDGE_PROTOCOL_NOT_NAMESPACE_OR_WHOLE_WORKER",
    cpu_limit_seconds=90,address_space_bytes=1<<30)
try:
    for size in (0,1,7,8,255,511,4095):
        result,after=invoke(source,command,bytes(size),"short-work-"+str(size))
        assert result==BAD and after==bytes(size)
        row("short-work-"+str(size),native_poison_possible=False,driver_must_discard=True)
    for n in (0,1,64,127,129):
        bad("command-length-"+str(n),r=(command+b"x")[:n],reason=1)
    bad("unknown-wire",r=change(command,0,0),reason=2)
    for at,value in ((8,0),(16,0),(24,11),(48,2)):
        bad("command-value-"+str(at),r=change(command,at,value),reason=3)
    for at in range(64,128,8):bad("command-reserved-"+str(at),r=change(command,at,1),reason=4)
    for at,value in ((32,len(source)+1),(40,1),(32,(1<<64)-1)):
        bad("source-extent-"+str(at)+"-"+str(value),r=change(command,at,value),reason=5)
    dirty=bytearray(4096);dirty[2000]=1
    bad("new-work-not-zero",w=bytes(dirty),reason=6)
    result,grow=invoke(source,command,bytes(4096),"real-initial-grow")
    assert result==512 and word(grow,264)==1 and word(grow,304)>4096
    row("real-initial-grow",needed=word(grow,304))
    for at in range(0,128,8):
        bad("grow-command-drift-"+str(at),r=change(command,at,word(command,at)^1),w=grow)
    bad("grow-lease-drift",r=change(command,8,772),w=grow,reason=7)
    # The state cannot be reused with a different phase or a second BEGIN.
    needed=word(grow,304)
    initial=grow+b"\0"*(needed-len(grow))
    result,ready=invoke(source,command,initial,"real-grow-resume")
    assert result==512 and word(ready,264)==2
    event=struct.unpack_from("<32Q",ready,256)
    row("real-grow-resume-requests-one-image",event=list(event))
    bad("begin-before-pending-response",w=ready,reason=9)
    src=Buffer(len(source),source);work=Buffer(len(ready),ready)
    with forbidden():code,intact=h.journal(src,event,work)
    assert intact
    replied=work.bytes()
    ack=pack(M(b"HIASJA01"),771,1,event[4],code,len(source),event[10],event[12],1,*([0]*7))
    for n in (0,1,64,127,129):bad("ack-length-"+str(n),r=(ack+b"x")[:n],w=replied,reason=1)
    for at,value in ((8,772),(16,2),(24,event[4]+1)):
        bad("ack-correlation-"+str(at),r=change(ack,at,value),w=replied,reason=13)
    for at,value in ((40,len(source)+1),(48,event[10]+1),(56,event[12]+1)):
        bad("ack-extent-"+str(at),r=change(ack,at,value),w=replied,reason=14)
    for at,value in ((32,1<<32),(64,2)):
        bad("ack-value-"+str(at),r=change(ack,at,value),w=replied,reason=15)
    for at in range(72,128,8):
        bad("ack-reserved-"+str(at),r=change(ack,at,1),w=replied,reason=16)
    result,short_after=invoke(source,ack,replied,"ack-short-borrow",advertised=4096)
    assert result==BAD and word(short_after,8)==5 and word(short_after,216)==17
    assert short_after[4096:]==replied[4096:]
    row("ack-short-borrow-rejected-before-output-access",reason=17)
    result,done=invoke(source,ack,replied,"real-response-accepted")
    assert result==512 and word(done,264)==0 and word(done,8)==1
    row("real-response-accepted",full_saved_state=h.save(done[512:1024]))
    bad("duplicate-response",r=ack,w=done,reason=12)
    bad("replay-command-sequence",r=command,w=done,reason=9)
    next_command=change(command,16,2)
    result,next_state=invoke(source,next_command,done,"next-command-accepted")
    assert result==512 and word(next_state,264)==2
    row("next-command-accepted")
    overflow=change(done,32,(1<<64)-1)
    result,poisoned=invoke(source,next_command,overflow,"event-sequence-overflow")
    assert result==BAD and word(poisoned,8)==5
    result,after=invoke(source,next_command,poisoned,"event-overflow-permanent")
    assert result==BAD and after==poisoned
    row("event-sequence-overflow",stale_event_must_not_be_consumed=True)
    # Same-size replacement is not an authority. The eventual fixed executor
    # must retain the same immutable input lease for every GROW/ACK.
    altered=source.replace(b"describe",b"artifact")
    assert len(altered)==len(source)
    result,other=invoke(altered,command,initial,"private-same-size-source")
    assert result==512 and word(other,264)==2
    row("private-same-size-source-is-not-authentication",accepted_private_control=True,
        public_driver_requirement="retain exact original immutable input lease")
    summary.update(status="PASS",cases=len(rows),entries=h.entries,
        native_entry_used=True,actual_journal_dependency_entries=h.entries["journal"])
except BaseException as exc:
    summary.update(status="FAIL",cases=len(rows),entries=h.entries,error_class=type(exc).__name__,error=str(exc))
    traceback.print_exc();raise
finally:
    summary["elapsed_ns"]=time.monotonic_ns()-start
    summary["source_unchanged"]=SELF.read_bytes()==test_raw
    try:h.close()
    except BaseException as exc:
        summary.update(status="FAIL",close_error_class=type(exc).__name__,close_error=str(exc))
        raise
    finally:
        (OUT/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
        print(json.dumps(summary,sort_keys=True),flush=True)
    assert summary["source_unchanged"]
