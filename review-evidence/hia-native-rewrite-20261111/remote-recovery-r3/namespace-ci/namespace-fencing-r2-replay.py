"""Full three-role actual trace replay and source-issued child correlation.

All original native bytes are retained in trace.bin. Every native entry runs a
fresh retained CoreVM computation on the exact pre-state; no result field mask
or correctness cache is used. This reader executes no filesystem primitive.
"""
import gzip,hashlib,json,struct
from pathlib import Path
from hepta.hia_program_runtime import _Machine,_Owner,_View
MASK=(1<<64)-1
FS=int.from_bytes(b"HIANFR03","little")
COORD=int.from_bytes(b"HIANFC01","little")
CHANNEL=int.from_bytes(b"HIANFX01","little")
MAGICS={int.from_bytes(b"HIANFT03","little"):1,int.from_bytes(b"HIANIT01","little"):2,
        int.from_bytes(b"HIANCT01","little"):3}
SYSCALLS={1:257,2:17,3:18,4:5,5:77,6:74,7:264,8:3,9:263,10:258,11:73,
          12:228,13:35,14:318,15:5,16:107,17:72,18:262,19:267,20:79,21:91,22:268,23:72}
BAD=0xfffffffd
def sha(raw):return hashlib.sha256(raw).hexdigest()
def q(raw,word):return struct.unpack_from("<Q",raw,8*word)[0]
def replay(process_directory,programs,*,fatal_code=0,signal_termination=False,steps=4000000):
    directory=Path(process_directory);trace=(directory/"trace.bin").read_bytes()
    requests=json.loads((directory/"requests.json").read_bytes())
    originals=[(directory/"requests"/str(row["index"])/"input.bin").read_bytes() for row in requests]
    states={role:dict(serial=0,waiting=None,last=None,acks=None,original=None) for role in (1,2,3)}
    issued=None;completed=None;client_index=0;offset=0;fatals=[];counts={};links=[];growth={1:0,2:0,3:0}
    ledger_path=directory/"three-role-vm-replay.jsonl.gz"
    def take(length):
        nonlocal offset
        assert 0<=length<=len(trace)-offset
        data=trace[offset:offset+length];offset+=length;return data
    with gzip.open(ledger_path,"wt",encoding="utf-8") as ledger:
        while offset<len(trace):
            start=offset;header=struct.unpack("<8Q",take(64))
            assert header[0] in MAGICS
            role=MAGICS[header[0]];state=states[role];kind=header[1]
            if kind==1:
                assert state["waiting"] is None and header[2]==state["serial"]+1 and header[6:]==(0,0)
                original=take(header[3]);pre_output=take(header[4]);pre_work=take(header[5])
                assert len(pre_output)>=256 and len(pre_work)>=(1536 if role==3 else 512)
                last=state["last"]
                if last is None:
                    assert pre_output==bytes(len(pre_output)) and pre_work==bytes(len(pre_work))
                else:
                    assert len(pre_output)>=len(last["output"]) and len(pre_work)>=len(last["work"])
                    assert pre_output[:len(last["output"])]==last["output"]
                    assert pre_work[:len(last["work"])]==last["work"]
                    assert pre_output[len(last["output"]):]==bytes(len(pre_output)-len(last["output"]))
                    assert pre_work[len(last["work"]):]==bytes(len(pre_work)-len(last["work"]))
                if role==3:
                    wrapper=struct.unpack_from("<8Q",original)
                    assert wrapper[0]==CHANNEL
                    if last is not None and last["code"]==2:
                        assert original==last["input"]
                        assert len(pre_work)>len(last["work"]) or len(pre_output)>len(last["output"])
                        growth[role]+=1
                    elif wrapper[1]==1:
                        assert issued is None and completed is None
                        assert wrapper[2:4]==(0,0) and wrapper[5:]==(0,0,0)
                        assert wrapper[4]==len(original)-64 and client_index<len(originals)
                        assert original[64:]==originals[client_index]
                        client_index+=1
                    else:
                        assert wrapper[1]==2 and issued is not None and completed is not None
                        selected=issued["role"];actual=completed
                        assert actual["role"]==selected and wrapper[2]==selected
                        expected=struct.pack("<8Q",CHANNEL,2,selected,actual["code"],len(issued["source"]),
                            len(actual["output"]),len(actual["work"]),actual["serial"])
                        expected+=issued["source"]+actual["output"]+actual["work"]
                        assert original==expected
                        links.append(dict(action=issued["action"],role=selected,child_entry_serial=actual["serial"],
                            child_source_sha256=sha(issued["source"]),child_output_sha256=sha(actual["output"]),
                            child_workspace_sha256=sha(actual["work"]),exact_private_wrapper_sha256=sha(original)))
                        issued=None;completed=None
                else:
                    assert issued is not None and issued["role"]==role and completed is None
                    if last is not None and last["code"]==2 and state["original"]==issued["source"]:
                        assert original==issued["source"]
                        assert len(pre_work)>len(last["work"]) or len(pre_output)>len(last["output"])
                        growth[role]+=1
                    elif role==1 and state["acks"] is not None:
                        assert last is not None and last["code"]==1 and original==state["acks"]
                        state["acks"]=None
                    else:
                        assert original==issued["source"]
                        state["original"]=issued["source"]
                program=programs[role];document=program.as_dict();entry=document["functions"][0]
                owners=[_Owner(-1,bytearray(original)),_Owner(-2,bytearray(pre_output)),_Owner(-3,bytearray(pre_work))]
                machine=_Machine(program,steps,16<<20,None,64)
                returned=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                assert bytes(owners[0].data)==original
                state["waiting"]=dict(serial=header[2],input=original,output=bytes(owners[1].data),
                    work=bytes(owners[2].data),code=returned)
                state["serial"]=header[2]
                ledger.write(json.dumps(dict(role=role,serial=header[2],trace_offset=start,
                    input_hex=original.hex(),pre_output_hex=pre_output.hex(),pre_workspace_hex=pre_work.hex(),
                    expected_return=returned,expected_output_hex=bytes(owners[1].data).hex(),
                    expected_workspace_hex=bytes(owners[2].data).hex(),vm_step_budget=steps),
                    sort_keys=True,separators=(",",":"))+"\n")
            elif kind==2:
                waiting=state["waiting"];assert waiting is not None and header[2]==waiting["serial"]
                assert header[3]==len(waiting["input"]) and header[4]==len(waiting["output"]) and header[5]==len(waiting["work"])
                assert header[6]==waiting["code"] and header[7]==0
                output=take(header[4]);work=take(header[5])
                assert output==waiting["output"] and work==waiting["work"]
                assert q(output,1)==header[6]
                state["last"]=waiting;state["waiting"]=None
                if role==3:
                    assert q(output,0)==COORD and header[6] in (0,1,2,BAD)
                    if header[6]==1:
                        assert issued is None and completed is None and q(output,6) in (1,2)
                        assert q(output,8)==q(output,16)<=len(output)-256
                        source=output[256:256+q(output,16)]
                        assert len(source)>=256
                        action=q(output,7)
                        assert action>0 and (not links or action>links[-1]["action"])
                        issued=dict(role=q(output,6),action=action,source=source)
                    elif header[6] in (0,BAD):
                        assert issued is None and completed is None
                        row=requests[client_index-1]
                        assert row["status"]=="COMPLETE"
                        raw=(directory/"requests"/str(row["index"])/"output.bin").read_bytes()
                        assert raw==output and row["output_sha256"]==sha(output)
                else:
                    assert issued is not None and issued["role"]==role
                    if header[6] in ((0,BAD) if role==1 else (0,1,BAD)):
                        assert state["acks"] is None and completed is None
                        completed=dict(role=role,code=header[6],output=output,work=work,serial=header[2])
            elif kind==3:
                assert role==1 and state["waiting"] is None and state["acks"] is None
                last=state["last"]
                assert last is not None and last["code"]==1 and header[2]==state["serial"]
                event=struct.unpack_from("<32Q",last["output"]);op=event[6]
                assert op in SYSCALLS and header[4]==SYSCALLS[op] and header[5]==op and header[7]==event[5]
                ack=take(header[3]);a=struct.unpack_from("<32Q",ack)
                assert a[0]==FS and a[1]==3 and a[2:7]==event[2:7]
                assert a[7]==header[6] and a[12]==len(ack)-256 and a[13]==event[14]
                assert not any(a[8:12]) and not any(a[14:])
                state["acks"]=ack
                counts[op]=counts.get(op,0)+1
            elif kind==4:
                assert fatal_code and header[2]==state["serial"] and header[3:6]==(0,0,0)
                assert header[6]==fatal_code and header[7]==0 and offset==len(trace)
                fatals.append(dict(role=role,code=header[6],trace_offset=start))
            else:raise AssertionError(("unknown trace kind",role,kind))
    assert all(row["waiting"] is None and row["acks"] is None for row in states.values())
    assert states[3]["serial"]>0
    if fatal_code:
        assert len(fatals)==1
    else:
        assert not fatals and issued is None and completed is None
        assert states[3]["last"]["code"] in (0,BAD)
    complete_requests=sum(row["status"]=="COMPLETE" for row in requests)
    assert client_index==complete_requests
    if not fatal_code and not signal_termination:assert client_index==len(requests)
    result=dict(status="PASS",scope="ACTUAL_THREE_ROLE_FULL_BYTE_REPLAY_AND_PRIVATE_CHILD_BINDING",
        native_entries=sum(v["serial"] for v in states.values()),vm_entries=sum(v["serial"] for v in states.values()),
        entries_by_role={str(k):v["serial"] for k,v in states.items()},
        exact_completed_child_links=links,actual_primitive_acks=sum(counts.values()),
        primitive_operation_counts={str(k):v for k,v in sorted(counts.items())},
        growth_by_role={str(k):v for k,v in growth.items()},requests=client_index,fatal_records=fatals,
        explicit_signal_termination=signal_termination,all_return_output_workspace_bytes_equal=True,
        no_field_masks=True,all_child_replies_bound_to_actual_original_source_output_workspace=True,
        no_primitive_executed_by_replayer=True,trace_bytes=len(trace),trace_sha256=sha(trace),
        ledger_bytes=ledger_path.stat().st_size,ledger_sha256=sha(ledger_path.read_bytes()))
    (directory/"three-role-replay.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return result
