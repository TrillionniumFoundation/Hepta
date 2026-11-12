"""New six-role original trace replay; the four-role verifier is unchanged.

The original trace is partitioned by complete records only. Every record and
every byte belongs to exactly one partition. DB5 and outer6 get fresh retained
CoreVM replay here; roles1..4 go through the exact predecessor replayer, with
all of its full-byte, actual primitive, source and context assertions intact.
Outer links are additionally reconstructed from original actual completions.
"""
from __future__ import annotations
import gzip,hashlib,json,struct
from pathlib import Path
from hepta.hia_program_runtime import _Machine,_Owner,_View
BAD=0xfffffffd
JOIN=int.from_bytes(b"HIANDJ01","little")
JCHANNEL=int.from_bytes(b"HIANDJX1","little")
DB=int.from_bytes(b"HIANDB01","little")
DMS=int.from_bytes(b"HIANDM03","little")
DCHANNEL=int.from_bytes(b"HIANDX03","little")
MAGICS={int.from_bytes(b"HIANFT03","little"):1,int.from_bytes(b"HIASMT01","little"):2,
 int.from_bytes(b"HIANMT01","little"):3,int.from_bytes(b"HIANDT03","little"):4,
 int.from_bytes(b"HIADBT01","little"):5,int.from_bytes(b"HIADJT01","little"):6}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def q(raw,index):return struct.unpack_from("<Q",raw,index*8)[0]
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def digest(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        while data:=stream.read(65536):h.update(data)
    return h.hexdigest()

def replay(directory,programs,inner_replayer,*,fatal_code=0,steps=4000000):
    directory=Path(directory);trace=directory/"trace.bin"
    before=dict(bytes=trace.stat().st_size,sha256=digest(trace))
    requests=json.loads((directory/"requests.json").read_bytes())
    original_requests=[(directory/"requests"/str(r["index"])/"input.bin").read_bytes() for r in requests]
    extracted=directory/"four-role-original-partition"
    extracted.mkdir(exist_ok=False)
    inner_requests=[];inner_active=None;inner_fatal=0
    states={};active={};next_db_context=2;pending=None;completed=None;retiring=None
    next_user=0;last_action=0;retire_sequence=0;offset=0
    growth={5:0,6:0};entries={i:0 for i in range(1,7)}
    links=[];retirements=[];partitions=[];fatals=[]
    ledger_path=directory/"outer-db-full-vm-replay.jsonl.gz"
    def new_state(role,node,sequence):
        return dict(role=role,node=node,sequence=sequence,serial=0,last=None,waiting=None,retired=False)
    with trace.open("rb") as stream,(extracted/"trace.bin").open("wb") as inner_trace,gzip.open(ledger_path,"wt",encoding="utf-8") as ledger:
        def take(n):
            nonlocal offset
            assert 0<=n<=before["bytes"]-offset
            b=stream.read(n);assert len(b)==n;offset+=n;return b
        while offset<before["bytes"]:
            record_start=offset;raw_header=take(96);h=struct.unpack("<12Q",raw_header)
            assert h[0] in MAGICS and h[11]==0
            role=MAGICS[h[0]];kind=h[1];node=h[8];sequence=h[9]
            assert h[10]==role and sequence>0 and role in programs
            if kind==1:
                original=take(h[3]);pre_output=take(h[4]);pre_work=take(h[5])
                payload=original+pre_output+pre_work
                entries[role]+=1
            elif kind==2:
                output=take(h[4]);work=take(h[5]);payload=output+work
            elif kind==3:
                payload=take(h[3])
            elif kind==4:
                assert h[3:6]==(0,0,0) and h[7]==0 and h[6]==fatal_code and fatal_code
                payload=b"";fatals.append(dict(role=role,context=sequence,code=h[6],offset=record_start))
                assert offset==before["bytes"]
            else:raise AssertionError(("unknown original trace kind",h))
            record=raw_header+payload
            part=dict(source_offset=record_start,bytes=len(record),sha256=sha(record),role=role,kind=kind)
            if role<=4:
                part["partition"]="unchanged-four-role"
                part["target_offset"]=inner_trace.tell()
                inner_trace.write(record)
                assert pending is not None and pending["role"]==4 and completed is None
                if role==4 and kind==1:
                    assert node==0 and sequence==1
                    if inner_active is None:
                        assert original==pending["source"]
                        wrapper=struct.unpack_from("<8Q",original)
                        assert wrapper==(DCHANNEL,1,0,0,len(original)-64,0,4096,0)
                        index=len(inner_requests)
                        place=extracted/"requests"/str(index);place.mkdir(parents=True)
                        data=original[64:];(place/"input.bin").write_bytes(data)
                        row=dict(index=index,status="INCOMPLETE",input_sha256=sha(data),input_bytes=len(data))
                        inner_requests.append(row);inner_active=index
                if role==4 and kind==2 and h[6] in (0,BAD):
                    assert inner_active is not None
                    row=inner_requests[inner_active];place=extracted/"requests"/str(inner_active)
                    (place/"output.bin").write_bytes(output)
                    row.update(status="COMPLETE",output_sha256=sha(output),output_bytes=len(output))
                    save(place/"result.json",row)
                    completed=dict(role=4,node=1,sequence=1,serial=h[2],code=h[6],
                        source=pending["source"],output=output,work=work)
                    inner_active=None
                if kind==4:inner_fatal=fatal_code
                partitions.append(part)
                continue
            part["partition"]="outer-db"
            partitions.append(part)
            assert role in (5,6) and kind in (1,2,4)
            key=(role,sequence)
            if key not in states:
                if role==6:
                    assert node==0 and sequence==1 and (6,0) not in active
                else:
                    assert pending is not None and pending["role"]==5 and pending["node"]==node
                    assert pending["create"]==1 and node>0 and (5,node) not in active
                    assert sequence==next_db_context
                    next_db_context+=1
                states[key]=new_state(role,node,sequence)
                active[(role,node)]=sequence
            state=states[key]
            assert not state["retired"] and active[(role,node)]==sequence
            assert (state["role"],state["node"])==(role,node)
            if kind==1:
                assert state["waiting"] is None and h[2]==state["serial"]+1 and h[6:8]==(0,0)
                assert len(pre_output)>=256 and len(pre_work)>=(4096 if role==6 else 1536)
                old=state["last"]
                if old is None:
                    assert pre_output==bytes(len(pre_output)) and pre_work==bytes(len(pre_work))
                else:
                    assert len(pre_output)>=len(old["output"]) and len(pre_work)>=len(old["work"])
                    assert pre_output[:len(old["output"])]==old["output"]
                    assert pre_work[:len(old["work"])]==old["work"]
                    assert pre_output[len(old["output"]):]==bytes(len(pre_output)-len(old["output"]))
                    assert pre_work[len(old["work"]):]==bytes(len(pre_work)-len(old["work"]))
                growing=old is not None and old["code"]==2
                if growing:
                    assert original==old["input"]
                    assert len(pre_output)>len(old["output"]) or len(pre_work)>len(old["work"])
                    growth[role]+=1
                if role==6:
                    wrapper=struct.unpack_from("<16Q",original)
                    assert wrapper[0]==JCHANNEL and wrapper[11]==4096 and wrapper[13:]==(0,0,0)
                    if not growing:
                        if wrapper[1]==1:
                            assert pending is None and completed is None and retiring is None
                            assert wrapper[2:4]==(0,0) and not any(wrapper[5:11]) and wrapper[12]==0
                            assert wrapper[4]==len(original)-128
                            assert next_user<len(original_requests) and original[128:]==original_requests[next_user]
                            next_user+=1
                        elif wrapper[1]==2:
                            assert pending is not None and completed is not None and retiring is None
                            actual=completed
                            assert (actual["role"],actual["node"])==(pending["role"],pending["node"])
                            assert actual["source"]==pending["source"]
                            words=[JCHANNEL,2,actual["role"],actual["code"],len(actual["source"]),
                                len(actual["output"]),len(actual["work"]),actual["serial"],actual["node"],
                                actual["sequence"],pending["action"],4096,0,0,0,0]
                            expected=struct.pack("<16Q",*words)+actual["source"]+actual["output"]+actual["work"]
                            assert original==expected
                            links.append(dict(parent_action=pending["action"],role=actual["role"],
                                node=actual["node"],context=actual["sequence"],serial=actual["serial"],
                                source_sha256=sha(actual["source"]),output_sha256=sha(actual["output"]),
                                workspace_sha256=sha(actual["work"]),capsule_sha256=sha(original),
                                create=pending["create"],stage=pending["stage"]))
                            pending=None;completed=None
                        elif wrapper[1]==3:
                            assert pending is None and completed is None and retiring is not None
                            event=retiring;ident=q(event,7)
                            actual_sequence=active[(5,ident)];actual=states[(5,actual_sequence)]
                            assert actual["waiting"] is None and actual["last"]["code"]==0
                            assert q(actual["last"]["output"],24)==4 and q(actual["last"]["work"],1)==4
                            retire_sequence+=1
                            words=[JCHANNEL,3,5,0,0,0,0,actual["serial"],ident,
                                actual_sequence,q(event,5),4096,retire_sequence,0,0,0]
                            assert original==struct.pack("<16Q",*words)
                            assert q(event,24)==retire_sequence and q(event,25)==actual_sequence
                            actual["retired"]=True;del active[(5,ident)]
                            retirements.append(dict(node=ident,context=actual_sequence,
                                parent_action=q(event,5),entry_serial=actual["serial"],
                                actual_retirement_sequence=retire_sequence,
                                event_sha256=sha(event),ack_sha256=sha(original)))
                            retiring=None
                        else:raise AssertionError(("unissued outer channel",wrapper))
                else:
                    assert pending is not None and completed is None and pending["role"]==5 and pending["node"]==node
                    assert original==pending["source"]
                    assert pending["sequence"] in (None,sequence)
                    pending["sequence"]=sequence
                    if pending["create"] and not growing:assert state["serial"]==0
                program=programs[role]
                own=[_Owner(-1,bytearray(original)),_Owner(-2,bytearray(pre_output)),_Owner(-3,bytearray(pre_work))]
                machine=_Machine(program,steps,32<<20,None,64)
                code=machine.invoke(program.as_dict()["functions"][0],
                    [_View(own[0],False),_View(own[1],True),_View(own[2],True)])[0]
                assert bytes(own[0].data)==original
                state["waiting"]=dict(serial=h[2],input=original,output=bytes(own[1].data),
                    work=bytes(own[2].data),code=code)
                state["serial"]=h[2]
                ledger.write(json.dumps(dict(role=role,node=node,context=sequence,serial=h[2],
                    original_offset=record_start,input_hex=original.hex(),
                    pre_output_hex=pre_output.hex(),pre_workspace_hex=pre_work.hex(),
                    expected_return=code,expected_output_hex=bytes(own[1].data).hex(),
                    expected_workspace_hex=bytes(own[2].data).hex(),vm_step_budget=steps),
                    sort_keys=True,separators=(",",":"))+"\n")
            elif kind==2:
                waiting=state["waiting"]
                assert waiting is not None and h[2]==waiting["serial"]
                assert h[3]==len(waiting["input"]) and h[4]==len(waiting["output"]) and h[5]==len(waiting["work"])
                assert h[6]==waiting["code"] and h[7]==0
                assert output==waiting["output"] and work==waiting["work"] and q(output,1)==h[6]
                state["last"]=waiting;state["waiting"]=None
                if role==5:
                    assert pending is not None and pending["role"]==5 and pending["node"]==node
                    assert h[6] in (0,1,2,BAD)
                    if h[6] in (0,1,BAD):
                        assert completed is None
                        completed=dict(role=5,node=node,sequence=sequence,serial=h[2],
                            code=h[6],source=pending["source"],output=output,work=work)
                else:
                    assert q(output,0)==JOIN and q(output,22)==1
                    assert h[6] in (0,1,2,3,BAD)
                    if h[6] in (1,3):
                        assert pending is None and completed is None and retiring is None
                        assert q(output,5)>last_action;last_action=q(output,5)
                    if h[6]==1:
                        selected=q(output,6);ident=q(output,7);create=q(output,9)
                        assert selected in (4,5) and create in (0,1)
                        assert q(output,8)==q(output,16)<=len(output)-256
                        source=output[256:256+q(output,16)]
                        if selected==4:
                            assert ident==1 and create==0
                            seq=1
                        else:
                            assert ident>0
                            seq=active.get((5,ident))
                            if create:assert seq is None and q(output,25)==0
                            else:assert seq is not None and q(output,25)==seq
                        pending=dict(role=selected,node=ident,sequence=seq,source=source,
                            action=q(output,5),create=create,stage=q(output,12),call=q(output,4))
                    elif h[6]==3:
                        assert q(output,6)==5 and q(output,16)==0 and q(output,24)==retire_sequence+1
                        retiring=output[:256]
                    elif h[6] in (0,BAD):
                        assert pending is None and completed is None and retiring is None
                        row=requests[next_user-1]
                        assert row["status"]=="COMPLETE"
                        actual=(directory/"requests"/str(row["index"])/"output.bin").read_bytes()
                        assert actual==output and row["output_sha256"]==sha(output)
    save(extracted/"requests.json",inner_requests)
    save(directory/"original-trace-partition.json",partitions)
    assert sum(row["bytes"] for row in partitions)==before["bytes"]
    assert all(row["waiting"] is None for row in states.values())
    if not fatal_code:
        assert pending is None and completed is None and retiring is None and inner_active is None
        assert next_user==len(requests) and all(row["status"]=="COMPLETE" for row in requests)
        assert not fatals
    else:assert len(fatals)==1
    inner=inner_replayer.replay(extracted,{r:programs[r] for r in (1,2,3,4)},
        fatal_code=inner_fatal,steps=steps)
    assert inner["native_entries"]==sum(entries[r] for r in (1,2,3,4))
    assert inner["vm_entries"]==inner["native_entries"]
    assert trace.stat().st_size==before["bytes"] and digest(trace)==before["sha256"]
    result=dict(status="PASS",scope="NEW_ACTUAL_SIX_ROLE_FULL_BYTES_AND_NESTED_CUSTODY",
        native_entries=sum(entries.values()),vm_entries=inner["vm_entries"]+entries[5]+entries[6],
        entries_by_role={str(k):v for k,v in entries.items()},
        all_original_records_partitioned_exactly_once=True,partition_records=len(partitions),
        outer_db_contexts=[{k:v for k,v in state.items() if k in ("role","node","sequence","serial","retired")}
                          for state in states.values()],
        complete_outer_links=links,actual_DB_context_retirements=retirements,
        outer_DB_growth={str(k):v for k,v in growth.items()},original_requests_consumed=next_user,
        unchanged_inner_replayer=inner,outer_DB_ledger=dict(bytes=ledger_path.stat().st_size,sha256=digest(ledger_path)),
        original_trace_before=before,original_trace_after=dict(bytes=trace.stat().st_size,sha256=digest(trace)),
        all_input_output_workspace_return_bytes_equal=True,no_masks=True,no_inherited_counts=True,
        no_OS_primitive_executed_by_replayer=True,fatal_records=fatals)
    assert result["native_entries"]==result["vm_entries"]
    save(directory/"six-role-replay.json",result)
    return result
