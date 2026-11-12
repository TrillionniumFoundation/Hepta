"""New actual four-role trace replay with dynamic context and receipt custody.

Every native entry is replayed in a fresh retained CoreVM on the complete
original input/output/workspace. No field mask or correctness cache is used.
The replay issues no filesystem or memory primitive. The fixed executable,
actual syscall trace and original full records remain the execution evidence.
"""
from __future__ import annotations
import gzip,hashlib,json,struct
from pathlib import Path
from hepta.hia_program_runtime import _Machine,_Owner,_View
MASK=(1<<64)-1
FS=int.from_bytes(b"HIANFR03","little")
DMS=int.from_bytes(b"HIANDM03","little")
CHANNEL=int.from_bytes(b"HIANDX03","little")
MEM=int.from_bytes(b"HIANML01","little")
MEM_CHANNEL=int.from_bytes(b"HIANMX01","little")
MAGICS={int.from_bytes(b"HIANFT03","little"):1,
        int.from_bytes(b"HIASMT01","little"):2,
        int.from_bytes(b"HIANMT01","little"):3,
        int.from_bytes(b"HIANDT03","little"):4}
SYSCALLS={1:257,2:17,3:18,4:5,5:77,6:74,7:264,8:3,9:263,10:258,11:73,
          12:228,13:35,14:318,15:5,16:107,17:72,18:262,19:267,20:79,21:91,
          22:268,23:72,24:93}
BAD=0xfffffffd
def sha(raw):return hashlib.sha256(raw).hexdigest()
def q(raw,word):return struct.unpack_from("<Q",raw,8*word)[0]
def file_sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        while chunk:=f.read(65536):h.update(chunk)
    return h.hexdigest()
def save(path,value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def replay(process_directory,programs,*,fatal_code=0,signal_termination=False,steps=4000000):
    directory=Path(process_directory);trace_path=directory/"trace.bin"
    original_size=trace_path.stat().st_size;original_sha=file_sha(trace_path)
    requests=json.loads((directory/"requests.json").read_bytes())
    originals=[(directory/"requests"/str(row["index"])/"input.bin").read_bytes() for row in requests]
    states={};active={};maximum_context=2
    issued=None;completed=None;retiring=None;retire_serial=0
    client_index=0;offset=0;fatals=[];links=[];retirements=[]
    counts={};memory_counts={};growth={role:0 for role in (1,2,3,4)}
    role_entries={role:0 for role in (1,2,3,4)}
    last_root_action=0;actual_page=None
    ledger_path=directory/"four-role-vm-replay.jsonl.gz"
    def new_state(role,node,sequence):
        return dict(role=role,node=node,sequence=sequence,serial=0,waiting=None,last=None,
                    acks=None,original=None,retired=False,primitive_sequence=0)
    with trace_path.open("rb") as stream,gzip.open(ledger_path,"wt",encoding="utf-8") as ledger:
        def take(length):
            nonlocal offset
            assert 0<=length<=original_size-offset
            raw=stream.read(length)
            assert len(raw)==length
            offset+=length
            return raw
        while offset<original_size:
            start=offset;header=struct.unpack("<12Q",take(96))
            assert header[0] in MAGICS and header[11]==0
            role=MAGICS[header[0]];kind=header[1];node=header[8];sequence=header[9]
            assert header[10]==role and sequence>0 and role in programs
            if sequence not in states:
                if role in (1,4):
                    assert node==0 and sequence==(2 if role==1 else 1)
                    assert (role,node) not in active
                else:
                    assert issued is not None and issued["role"]==role and issued["node"]==node
                    assert issued["create"]==1 and node>0
                    assert (role,node) not in active and sequence==maximum_context+1
                    maximum_context=sequence
                states[sequence]=new_state(role,node,sequence)
                active[(role,node)]=sequence
            state=states[sequence]
            assert (state["role"],state["node"])==(role,node)
            assert not state["retired"] and active[(role,node)]==sequence
            if kind==1:
                assert state["waiting"] is None
                assert header[2]==state["serial"]+1 and header[6:8]==(0,0)
                original=take(header[3]);pre_output=take(header[4]);pre_work=take(header[5])
                assert len(pre_output)>=(257 if role==2 else 1280 if role==4 else 256)
                assert len(pre_work)>=(8192 if role==4 else 512 if role==1 else 1536)
                last=state["last"]
                if last is None:
                    assert pre_output==bytes(len(pre_output)) and pre_work==bytes(len(pre_work))
                else:
                    assert len(pre_output)>=len(last["output"]) and len(pre_work)>=len(last["work"])
                    assert pre_output[:len(last["output"])]==last["output"]
                    assert pre_work[:len(last["work"])]==last["work"]
                    assert pre_output[len(last["output"]):]==bytes(len(pre_output)-len(last["output"]))
                    assert pre_work[len(last["work"]):]==bytes(len(pre_work)-len(last["work"]))
                if role==4:
                    wrapper=struct.unpack_from("<8Q",original)
                    assert wrapper[0]==CHANNEL and wrapper[7]==0
                    assert wrapper[4]==len(original)-64
                    assert wrapper[6]==4096
                    if actual_page is None:actual_page=wrapper[6]
                    assert wrapper[6]==actual_page
                    if last is not None and last["code"]==2:
                        assert original==last["input"]
                        assert len(pre_work)>len(last["work"]) or len(pre_output)>len(last["output"])
                        growth[role]+=1
                    elif wrapper[1]==1:
                        assert issued is None and completed is None and retiring is None
                        assert wrapper[2:4]==(0,0) and wrapper[5]==0
                        assert client_index<len(originals) and original[64:]==originals[client_index]
                        client_index+=1
                    elif wrapper[1] in (2,5,6):
                        assert issued is not None and completed is not None and retiring is None
                        selected=issued["role"];actual=completed
                        assert actual["role"]==selected and actual["node"]==issued["node"]
                        assert wrapper[1]==(2 if selected==1 else selected+3)
                        assert wrapper[2]==selected and wrapper[3]==actual["code"]
                        assert wrapper[5]==actual["serial"]
                        words=[0]*32
                        words[:8]=[DMS,8 if selected==1 else selected+15,
                            *issued["session"],issued["call"],issued["action"],issued["lease"],selected]
                        words[8:13]=[len(issued["source"]),len(actual["output"]),len(actual["work"]),
                                     actual["code"],actual["serial"]]
                        if selected!=1:
                            words[13:16]=[issued["node"],issued["create"],issued["stage"]]
                        body=issued["source"]+actual["output"]+actual["work"]
                        words[16]=len(body)
                        expected=struct.pack("<8Q",CHANNEL,wrapper[1],selected,actual["code"],
                            256+len(body),actual["serial"],actual_page,0)
                        expected+=struct.pack("<32Q",*words)+body
                        assert original==expected
                        links.append(dict(action=issued["action"],root_call=issued["call"],
                            role=selected,node=issued["node"],context=actual["context"],
                            child_entry_serial=actual["serial"],create=issued["create"],
                            child_source_sha256=sha(issued["source"]),
                            child_output_sha256=sha(actual["output"]),
                            child_workspace_sha256=sha(actual["work"]),
                            complete_private_capsule_sha256=sha(original)))
                        issued=None;completed=None
                    elif wrapper[1]==7:
                        assert issued is None and completed is None and retiring is not None
                        event=retiring["event"];mask=q(event,6);retired_node=q(event,7)
                        retire_serial+=1
                        assert wrapper[2:6]==(4,0,512,retire_serial)
                        selected_states=[]
                        for selected,bit in ((2,1),(3,2)):
                            actual_sequence=active.get((selected,retired_node))
                            if mask&bit:
                                assert actual_sequence is not None
                                selected_state=states[actual_sequence]
                                assert selected_state["last"] is not None
                                assert selected_state["waiting"] is None and selected_state["acks"] is None
                                if selected==3:
                                    assert q(selected_state["last"]["work"],10)==0
                                    assert q(selected_state["last"]["work"],11)==q(event,9)
                                selected_states.append(selected_state)
                            else:assert actual_sequence is None
                        assert len(selected_states)==(mask&1)+((mask>>1)&1)
                        if not mask&2:assert q(event,9)==0
                        words=[0]*32
                        words[:8]=[DMS,19,q(event,2),q(event,3),q(event,4),q(event,5),q(event,8),4]
                        words[8:14]=[retired_node,mask,len(selected_states),q(event,9),retire_serial,256]
                        words[16]=256
                        expected=struct.pack("<8Q",CHANNEL,7,4,0,512,retire_serial,actual_page,0)
                        expected+=struct.pack("<32Q",*words)+event
                        assert len(expected)==576 and original==expected
                        for selected_state in selected_states:
                            selected_state["retired"]=True
                            del active[(selected_state["role"],selected_state["node"])]
                        retirements.append(dict(node=retired_node,mask=mask,
                            contexts=[row["sequence"] for row in selected_states],
                            actual_retirement_sequence=retire_serial,quarantined_mappings=q(event,9),
                            original_event_sha256=sha(event),actual_ack_sha256=sha(original)))
                        retiring=None
                    else:raise AssertionError(("unexpected actual root origin",wrapper))
                else:
                    assert issued is not None and completed is None
                    assert (issued["role"],issued["node"])==(role,node)
                    assert issued["context"] in (None,sequence)
                    if issued["context"] is None:issued["context"]=sequence
                    if last is not None and last["code"]==2 and state["original"]==issued["source"]:
                        assert original==issued["source"]
                        assert len(pre_work)>len(last["work"]) or len(pre_output)>len(last["output"])
                        growth[role]+=1
                    elif role in (1,3) and state["acks"] is not None:
                        assert last is not None and last["code"]==1 and original==state["acks"]
                        state["acks"]=None
                    else:
                        assert original==issued["source"]
                        state["original"]=issued["source"]
                        if issued["create"]:assert state["serial"]==0
                program=programs[role];document=program.as_dict();entry=document["functions"][0]
                owners=[_Owner(-1,bytearray(original)),_Owner(-2,bytearray(pre_output)),
                        _Owner(-3,bytearray(pre_work))]
                machine=_Machine(program,steps,32<<20,None,64)
                returned=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),
                                               _View(owners[2],True)])[0]
                assert bytes(owners[0].data)==original
                state["waiting"]=dict(serial=header[2],input=original,output=bytes(owners[1].data),
                    work=bytes(owners[2].data),code=returned)
                state["serial"]=header[2]
                role_entries[role]+=1
                ledger.write(json.dumps(dict(role=role,node=node,context=sequence,serial=header[2],
                    trace_offset=start,input_hex=original.hex(),pre_output_hex=pre_output.hex(),
                    pre_workspace_hex=pre_work.hex(),expected_return=returned,
                    expected_output_hex=bytes(owners[1].data).hex(),
                    expected_workspace_hex=bytes(owners[2].data).hex(),vm_step_budget=steps),
                    sort_keys=True,separators=(",",":"))+"\n")
            elif kind==2:
                waiting=state["waiting"]
                assert waiting is not None and header[2]==waiting["serial"]
                assert header[3]==len(waiting["input"]) and header[4]==len(waiting["output"])
                assert header[5]==len(waiting["work"]) and header[6]==waiting["code"] and header[7]==0
                output=take(header[4]);work=take(header[5])
                assert output==waiting["output"] and work==waiting["work"] and q(output,1)==header[6]
                state["last"]=waiting;state["waiting"]=None
                if role==4:
                    assert q(output,0)==DMS and header[6] in (0,1,2,5,6,BAD)
                    if header[6] in (1,5):
                        assert issued is None and completed is None and retiring is None
                        selected=q(output,6)
                        assert selected in ((1,) if header[6]==1 else (2,3))
                        assert q(output,8)==q(output,16)<=len(output)-256
                        source=output[256:256+q(output,16)]
                        assert len(source)>=(256 if selected==1 else 320)
                        action=q(output,5);assert action>last_root_action
                        last_root_action=action
                        selected_node=0 if selected==1 else q(output,7)
                        create=0 if selected==1 else q(output,11)
                        assert create in (0,1) and (selected==1 or selected_node>0)
                        existing=active.get((selected,selected_node))
                        if create:assert existing is None
                        elif selected!=1:assert existing is not None
                        issued=dict(role=selected,node=selected_node,source=source,action=action,
                            call=q(output,4),session=(q(output,2),q(output,3)),create=create,
                            stage=q(output,7) if selected==1 else q(output,14),
                            lease=q(output,9) if selected==1 else q(output,15),context=existing)
                    elif header[6]==6:
                        assert issued is None and completed is None and retiring is None
                        assert q(output,6) in (1,2,3) and q(output,7)>0 and q(output,10)==0
                        assert q(output,11)==retire_serial+1 and q(output,16)==0
                        action=q(output,5);assert action>last_root_action
                        last_root_action=action
                        retiring=dict(event=output[:256])
                    elif header[6] in (0,BAD):
                        assert issued is None and completed is None and retiring is None
                        row=requests[client_index-1];assert row["status"]=="COMPLETE"
                        raw=(directory/"requests"/str(row["index"])/"output.bin").read_bytes()
                        assert raw==output and row["output_sha256"]==sha(output)
                else:
                    assert issued is not None and issued["role"]==role and issued["node"]==node
                    terminal=(0,1,BAD) if role==2 else (0,BAD)
                    if header[6] in terminal:
                        assert state["acks"] is None and completed is None
                        completed=dict(role=role,node=node,context=sequence,code=header[6],
                            output=output,work=work,serial=header[2])
            elif kind==3:
                assert role in (1,3) and state["waiting"] is None and state["acks"] is None
                last=state["last"]
                assert last is not None and last["code"]==1 and header[2]==state["serial"]
                event=last["output"][:256]
                ack=take(header[3])
                if role==1:
                    op=q(event,6)
                    assert op in SYSCALLS and header[4]==SYSCALLS[op] and header[5]==op
                    assert header[7]==q(event,5)>state["primitive_sequence"]
                    a=struct.unpack_from("<32Q",ack)
                    assert a[0]==FS and a[1]==3 and a[2:7]==struct.unpack_from("<32Q",event)[2:7]
                    assert a[7]==header[6] and a[12]==len(ack)-256 and a[13]==q(event,14)
                    assert not any(a[8:12]) and not any(a[14:])
                    counts[op]=counts.get(op,0)+1
                else:
                    op=q(event,8)
                    assert op in (1,2,3,4) and header[5]==op
                    assert header[4]==({1:9,2:0,3:11,4:0}[op])
                    assert header[7]==state["primitive_sequence"]+1
                    actual=header[6]
                    error=(-actual)&MASK if actual>=MASK-4094 else 0
                    value=0 if error else actual
                    words=[0]*32
                    words[:8]=[MEM,3,q(event,2),q(event,3),q(event,4),q(event,5),q(event,6),q(event,7)]
                    words[8:14]=[op,error,value,0,header[7],256]
                    expected=struct.pack("<8Q",MEM_CHANNEL,2,op,0,512,header[7],0,0)
                    expected+=struct.pack("<32Q",*words)+event
                    assert len(ack)==576 and ack==expected
                    memory_counts[op]=memory_counts.get(op,0)+1
                state["primitive_sequence"]=header[7]
                state["acks"]=ack
            elif kind==4:
                assert fatal_code and header[2]==state["serial"] and header[3:6]==(0,0,0)
                assert header[6]==fatal_code and header[7]==0 and offset==original_size
                fatals.append(dict(role=role,node=node,context=sequence,code=header[6],trace_offset=start))
            else:raise AssertionError(("unknown trace kind",role,kind))
    assert all(row["waiting"] is None and row["acks"] is None for row in states.values())
    assert role_entries[4]>0
    if fatal_code:assert len(fatals)==1
    else:
        assert not fatals and issued is None and completed is None and retiring is None
        assert states[1]["last"]["code"] in (0,BAD)
    complete_requests=sum(row["status"]=="COMPLETE" for row in requests)
    assert all(row["status"]=="COMPLETE" for row in requests[:complete_requests])
    if fatal_code or signal_termination:
        assert complete_requests<=client_index<=complete_requests+1
        assert complete_requests<=len(requests)<=complete_requests+1
    else:
        assert client_index==complete_requests==len(requests)
    assert trace_path.stat().st_size==original_size and file_sha(trace_path)==original_sha
    result=dict(status="PASS",scope="NEW_ACTUAL_FOUR_ROLE_FULL_BYTE_REPLAY_AND_CONTEXT_CUSTODY",
        native_entries=sum(role_entries.values()),vm_entries=sum(role_entries.values()),
        entries_by_role={str(k):v for k,v in role_entries.items()},
        actual_contexts=[dict(role=s["role"],node=s["node"],sequence=s["sequence"],
            entries=s["serial"],retired=s["retired"]) for s in states.values()],
        exact_completed_child_links=links,actual_primitive_acks=sum(counts.values())+sum(memory_counts.values()),
        filesystem_primitive_operation_counts={str(k):v for k,v in sorted(counts.items())},
        memory_primitive_operation_counts={str(k):v for k,v in sorted(memory_counts.items())},
        exact_retirements=retirements,actual_auxv_page_bytes=actual_page,
        growth_by_role={str(k):v for k,v in growth.items()},requests_consumed=client_index,
        completed_requests=complete_requests,fatal_records=fatals,
        explicit_signal_termination=signal_termination,all_return_output_workspace_bytes_equal=True,
        no_field_masks=True,no_inherited_entry_counts=True,
        all_child_replies_bound_to_actual_original_source_output_workspace=True,
        no_primitive_executed_by_replayer=True,trace_bytes=original_size,trace_sha256=original_sha,
        ledger_bytes=ledger_path.stat().st_size,ledger_sha256=file_sha(ledger_path))
    save(directory/"four-role-replay.json",result)
    return result
