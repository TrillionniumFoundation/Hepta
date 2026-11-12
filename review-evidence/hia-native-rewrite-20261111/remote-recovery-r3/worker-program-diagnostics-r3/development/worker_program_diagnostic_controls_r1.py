"""Mechanical private continuation controls for the Worker fixed catalog route.

These controls deliberately issue synthetic private child terminals. They are
not public-input admission or namespace evidence. The root and formatter are
actual source-bound images; every invoked source is actually read-only.
"""
from __future__ import annotations
import ctypes,json,struct
from pathlib import Path

BAD=0xfffffffd
NEED=0xfffffffe
MAX=(1<<64)-1

def run(ns):
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    bundle=ns["bundle"];out=ns["OUT"];cas=ns["cas"];save=ns["save"];pin=ns["pin"]
    proof=json.loads(pin(bundle["diagnostic_adaptation"]));c=proof["constants"]
    catalog=json.loads(pin(bundle["diagnostic_catalog"]))
    texts={(row["group"],row["error"]):(row["code"]+": "+row["message"]).encode("utf-8")
           for row in catalog["entries"]}
    role_rows={role:bundle["role_bindings"][str(role)] for role in (51,56)}
    images={}
    for role,row in role_rows.items():
        raw=pin(row["image_path"])
        assert len(raw)==row["image_bytes"] and ns["digest"](raw)==row["image_sha256"]
        images[role]=NativeHiaJsonImage(raw,expected_sha256=row["image_sha256"])
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mmap.restype=ctypes.c_void_p
    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    by_role={51:0,56:0};case_number=0
    class Buffer:
        def __init__(self,raw=b"",size=None,readonly=False):
            raw=bytes(raw)
            self.size=len(raw) if size is None else size
            assert 0<=len(raw)<=self.size
            self.extent=((max(1,self.size)+128+4095)//4096)*4096
            self.base=int(libc.mmap(None,self.extent,3,0x22,-1,0))
            assert self.base!=ctypes.c_void_p(-1).value
            self.ptr=self.base+64;self.readonly=False
            ctypes.memset(self.base,0x6b,self.extent)
            ctypes.memset(self.ptr,0,max(1,self.size))
            if raw:ctypes.memmove(self.ptr,raw,len(raw))
            if readonly:self.protect(True)
        def value(self):return ctypes.string_at(self.ptr,self.size)
        def write(self,at,raw):
            raw=bytes(raw)
            assert not self.readonly and 0<=at<=self.size and len(raw)<=self.size-at
            if raw:ctypes.memmove(self.ptr+at,raw,len(raw))
        def check(self):
            assert ctypes.string_at(self.base,64)==bytes([0x6b])*64
            assert ctypes.string_at(self.ptr+max(1,self.size),self.extent-64-max(1,self.size))==bytes([0x6b])*(self.extent-64-max(1,self.size))
        def protect(self,readonly):
            assert libc.mprotect(self.base,self.extent,1 if readonly else 3)==0
            self.readonly=readonly
        def close(self):
            if self.base is not None:
                self.check();assert libc.munmap(self.base,self.extent)==0
                self.base=None
    def put(raw,name,value):struct.pack_into("<Q",raw,c[name] if isinstance(name,str) else name,value)
    def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
    def ack(lease,seq,action,returned=0,observed=b""):
        return struct.pack("<8Q",c["ACK_MAGIC"],lease,seq,action,0,returned,len(observed),0)+observed
    def initial(group,error,occupied):
        lease=0x57444701;request=37
        raw=bytearray(c["MIN_WORK"])
        values={"C_MAGIC":c["EDIT_STATE"],"C_STATUS":1,"C_LEASE":lease,"C_SEQUENCE":7,
          "C_PENDING":15,"C_NEXT":2,"C_OBSERVE":160,
          "L_MAGIC":c["LOWER_MAGIC"],"L_STATUS":1,"L_DRIVER":56,
          "A_MAGIC":c["A_STATE_MAGIC"],"WP_MAGIC":c["WP_STATE"],"WP_MODE":1,
          "WP_REQUEST":request,"WP_INPUT_BYTES":2,"WP_TREE":int(occupied),
          "WP_SELECTED_SLOT":1,"E_CHILD_LEASE":lease+1,"E_CHILD_TARGET":6,
          "E_DIGITS":4300,"E_REQUEST":request}
        if occupied:values.update(AS_MAGIC=c["AS_STATE_MAGIC"],AS_MODE=0)
        for name,value in values.items():put(raw,name,value)
        slots={0:Buffer(b"\0",readonly=True),1:Buffer(b"{}",readonly=True)}
        if occupied:
            for number in range(51,59):slots[number]=Buffer(bytes([number])*32,readonly=True)
        for number,buf in slots.items():put(raw,c["CAPS"]+number*8,buf.size)
        put(raw,c["CAPS"]+16,c["MIN_WORK"])
        slots[2]=Buffer(raw)
        child=struct.pack("<16Q",c["EVENT_MAGIC"],7,lease+2,31,group,error,19,0,0,0,0,0,
                          0x123456789abcdef,0xfedcba9876543210,0x1111222233334444,0xaaaabbbbccccdddd)
        command=ack(lease,7,15,128,child+struct.pack("<4Q",0,6,46,0))
        return slots,command,lease,request,child
    def native(role,source,offset,extent,output,output_extent,workspace,workspace_extent,label):
        assert source is not output and source is not workspace and output is not workspace
        assert 0<=offset<=source.size and extent<=source.size-offset
        assert output_extent<=output.size and workspace_extent<=workspace.size
        before_source=source.value();before_output=output.value();before_work=workspace.value()
        was=source.readonly
        if not was:source.protect(True)
        assert source.readonly and not output.readonly and not workspace.readonly
        serial=ns["KERNEL_ENTRIES"]+1
        pending=dict(entry=serial,role=role,label=label,
          source=cas(before_source),source_offset=offset,source_extent=extent,
          output=cas(before_output),output_extent=output_extent,
          workspace=cas(before_work),workspace_extent=workspace_extent,
          actual_source_mprotect_readonly=True,
          image_sha256=role_rows[role]["image_sha256"])
        save(out/"pending-native-entry.json",pending)
        try:
            ret=int(images[role]._entry(source.ptr+offset,extent,output.ptr,output_extent,
                                       workspace.ptr,workspace_extent))
            ns["KERNEL_ENTRIES"]+=1;by_role[role]+=1
        finally:
            if not was:source.protect(False)
        for value in (source,output,workspace):value.check()
        assert source.value()==before_source
        row=dict(pending,returned=ret,source_after=cas(source.value()),
                 output_after=cas(output.value()),workspace_after=cas(workspace.value()),
                 complete_input_and_canaries_unchanged=True)
        save(out/"entries"/(str(serial).zfill(6)+".json"),row)
        return ret,output.value()
    def replay_poison(slots,command,label):
        src=Buffer(command,readonly=True);dst=Buffer(b"",128)
        try:
            ret,_=native(56,src,0,len(command),dst,128,slots[2],slots[2].size,label)
            assert ret==BAD,label
        finally:src.close();dst.close()
    def one(spec):
        nonlocal case_number
        case_number+=1;label=spec["label"];first_entry=ns["KERNEL_ENTRIES"]+1
        group,error=spec.get("pair",(1,4));occupied=spec.get("occupied",False)
        slots,command,lease,request,child=initial(group,error,occupied)
        original_command=command;mutated=False;calls=0;steps=[]
        keep={number:buf.value() for number,buf in slots.items() if number>=51}
        want_bad=spec["kind"]!="success"
        if spec["kind"]=="child-word":
            changed=bytearray(command);struct.pack_into("<Q",changed,spec["at"],spec["value"]);command=bytes(changed);mutated=True
        elif spec["kind"]=="child-extent":
            command=command[:spec["size"]] if spec["size"]<len(command) else command+b"\0"
            mutated=True
        elif spec["kind"]=="busy-slot":
            slot=spec["slot"];slots[slot]=Buffer(b"x"*16)
            slots[2].write(c["CAPS"]+slot*8,struct.pack("<Q",16));mutated=True
        save(out/"private-cases"/label/"plan.json",dict(spec,issued_child=cas(child),
             private_unissued_fixture=True,not_public_input_authentication=True,
             original_command=cas(original_command),first_command=cas(command)))
        final=None
        try:
            for iteration in range(80):
                src=Buffer(command,readonly=True);dst=Buffer(b"",128)
                advertised=c["MIN_WORK"]-1 if spec["kind"]=="short-workspace" else c["MIN_WORK"]
                try:
                    ret,event=native(56,src,0,len(command),dst,128,slots[2],advertised,label)
                finally:src.close();dst.close()
                if ret==BAD:
                    assert want_bad and (mutated or spec["kind"]=="short-workspace"),(label,ret)
                    if spec["kind"]!="short-workspace":
                        assert word(slots[2].value(),c["L_STATUS"])==3
                        replay_poison(slots,original_command,label+"-permanent-refusal")
                    final=dict(status="PASS",classification="PRIVATE_CONTINUATION_REFUSAL",
                       short_workspace_requires_outer_lease_discard=spec["kind"]=="short-workspace",
                       permanent_refusal_checked=spec["kind"]!="short-workspace")
                    break
                assert ret==128,(label,ret)
                words=struct.unpack("<16Q",event)
                assert words[0]==c["EVENT_MAGIC"] and words[2]==lease
                action=words[1];args=words[4:];steps.append(dict(event=cas(event),action=action))
                if action==7:
                    assert not want_bad,(label,"bad case reached terminal")
                    assert set(keep).issubset(slots)
                    assert all(slots[n].value()==raw for n,raw in keep.items())
                    assert c["WD_OUTPUT"] not in slots and c["WD_WORK"] not in slots
                    assert calls==2 and slots[30].readonly
                    frame=slots[30].value()
                    expected=dict(kind=4,domain=1,phase=0,line=0,
                        code=texts[group,error].split(b": ",1)[0].decode("ascii"),
                        payload=texts[group,error],program=None)
                    ns["parse_result"]({"returncode":2},b"",event+frame,
                        {"expected":expected,"mode":1},lease,request)
                    replay_poison(slots,original_command,label+"-terminal-not-reusable")
                    final=dict(status="PASS",classification="PRIVATE_COMPLETE_NATIVE_ROUTE",
                        actual_catalog_calls=calls,complete_payload_equal=True,
                        diagnostic_slots_released_before_terminal=True,
                        borrowed_assembly_slots_unchanged=True,
                        terminal_not_reusable=True,result=cas(frame))
                    break
                returned=0;observed=b""
                if action==2:
                    slot,needed=args[:2];assert slot not in (0,1,2) and needed>0
                    old=slots.get(slot);raw=old.value() if old else b""
                    assert len(raw)<needed
                    fresh=Buffer(raw,needed)
                    if old:old.close()
                    slots[slot]=fresh
                elif action==1:
                    image,first,at,size,second,second_n,work,work_n,observe,observe_at,count,reserved=args
                    assert (image,first,second,work,observe,observe_at,count,reserved)==(51,2,47,48,47,0,128,0)
                    calls+=1;assert calls in (1,2)
                    returned,_=native(51,slots[first],at,size,slots[second],second_n,
                                       slots[work],work_n,label+"-actual-catalog-"+str(calls))
                    observed=slots[observe].value()[observe_at:observe_at+count]
                    if calls==1:
                        # This exact malformed actual-child fixture reaches the
                        # formatter's existing error999 refusal, not measurement.
                        if spec["kind"]=="child-word" and spec["at"]==104 and spec["value"]==999:
                            assert returned==BAD and second_n==128,(label,returned,second_n)
                        else:
                            assert returned==NEED and second_n==128,(label,returned,second_n)
                    else:
                        assert returned==second_n and second_n>128
                    if spec["kind"]=="measurement-word" and calls==1:
                        raw=bytearray(observed);raw[spec["at"]]^=1;observed=bytes(raw);mutated=True
                    elif spec["kind"]=="complete-word" and calls==2:
                        raw=bytearray(observed);raw[spec["at"]]^=1;observed=bytes(raw);mutated=True
                    elif spec["kind"]=="returned" and calls==spec["call"]:
                        returned=(returned+spec["delta"])&MAX;mutated=True
                elif action==4:
                    source,at,target,to,size=args[:5]
                    assert source in slots and target in slots and source!=target
                    raw=slots[source].value();assert at<=len(raw) and size<=len(raw)-at
                    slots[target].write(to,raw[at:at+size])
                elif action==5:
                    slot=args[0];assert slot in (47,48) and slot in slots
                    slots.pop(slot).close()
                elif action==6:
                    slot,readonly=args[:2];assert readonly in (0,1)
                    slots[slot].protect(bool(readonly))
                elif action==14:
                    slot,at,size=args[:3];raw=slots[slot].value()
                    assert at<=len(raw) and size<=len(raw)-at and size<=256
                    observed=raw[at:at+size]
                else:
                    raise AssertionError((label,"unexpected native mechanical action",action))
                command=ack(lease,words[3],action,returned,observed)
                if spec["kind"]=="ACK-word" and action==1 and calls==1:
                    raw=bytearray(command);at=spec["at"];struct.pack_into("<Q",raw,at,word(raw,at)^1)
                    command=bytes(raw);mutated=True
                save(out/"private-cases"/label/"last-completed-step.json",
                     dict(iteration=iteration,action=action,next_ACK=cas(command),
                          slots={str(n):dict(bytes=b.size,readonly=b.readonly,value=cas(b.value()))
                                 for n,b in slots.items()}))
            assert final is not None,(label,"finite controller did not terminate")
            final.update(label=label,first_native_entry=first_entry,last_native_entry=ns["KERNEL_ENTRIES"],
                         actual_catalog_entries=calls,foreign_child_fixture=True,
                         actual_program_child=False)
            ns["ROWS"].append(final);save(out/"cases-completed.json",ns["ROWS"])
            save(out/"private-cases"/label/"summary.json",dict(final,steps=steps,
                 final_slots={str(n):dict(bytes=b.size,readonly=b.readonly,value=cas(b.value()))
                              for n,b in slots.items()}))
        finally:
            for buf in list(slots.values()):buf.close()
    plan=[]
    for pair in ((1,4),(2,18),(3,1),(4,1),(5,1)):
        for occupied in (False,True):
            plan.append(dict(label="complete-"+str(pair[0])+"-"+str(int(occupied)),kind="success",
                             pair=pair,occupied=occupied))
    for at in list(range(0,96,8))+list(range(96,128)):
        plan.append(dict(label="measurement-byte-"+str(at),kind="measurement-word",at=at))
    for at in range(0,128,8):
        plan.append(dict(label="complete-header-byte-"+str(at),kind="complete-word",at=at))
    for call in (1,2):
        for delta in (-1,1):plan.append(dict(label="return-"+str(call)+"-"+str(delta),kind="returned",call=call,delta=delta))
    # Exact offsets are in the whole ACK (64-byte header + actual child frame).
    mutations=[(64,0),(72,6),(80,0),(88,0),(96,0),(96,6),(96,9),(96,11),
               (104,0),(104,999),(192,1),(200,5),(208,44),(216,1)]
    for index,(at,value) in enumerate(mutations):
        plan.append(dict(label="child-binding-"+str(index),kind="child-word",at=at,value=value))
    for slot in (47,48):plan.append(dict(label="occupied-diag-slot-"+str(slot),kind="busy-slot",slot=slot))
    plan.append(dict(label="short-workspace",kind="short-workspace"))
    for size in (223,225):plan.append(dict(label="child-ACK-extent-"+str(size),kind="child-extent",size=size))
    for at in (0,8,16,24,32,48,56):plan.append(dict(label="catalog-ACK-binding-"+str(at),kind="ACK-word",at=at))
    assert len(plan)==100
    assert plan[83]["label"]=="child-binding-9" and plan[83]["value"]==999
    save(out/"private-control-plan.json",dict(cases=plan,count=len(plan),
        selected_indices=list(range(83,100)),selected_cases=plan[83:],
        original_follow45_job=131126029053,prior_83_not_reexecuted=True,
        actual_program_child=False,namespace_issued=False,publication_fixture_only=True))
    try:
        for spec in plan[83:]:one(spec)
        assert case_number==17 and len(ns["ROWS"])==17
        return dict(planned_cases=17,original_inventory_cases=100,
                    original_inventory_selected_range=[83,100],
                    prior_83_passes_not_reexecuted_or_inherited=True,
                    actual_entries_by_role=by_role,
                    issued_child_from_native_program=False,
                    all_actual_native_source_views_readonly=True)
    finally:
        for image in images.values():image._mapping.close()
