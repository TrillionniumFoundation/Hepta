"""Actual P16 private type-capsule and mechanical ACK controls.

Every child frame here is explicitly PRIVATE_UNISSUED. These controls verify
the fixed root's handling of already issued immutable views; they do not prove
foreign headers authenticate a type workspace or a namespace capability.
Public ELF cases separately exercise the real type, validator and reader chain.
"""
from __future__ import annotations
import ctypes,json,struct
from pathlib import Path

BAD=0xfffffffd
MAX=(1<<64)-1

def run(ns):
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    bundle=ns["bundle"];out=ns["OUT"];cas=ns["cas"];save=ns["save"];pin=ns["pin"]
    fixed=json.loads(pin(bundle["diagnostic_adaptation"]))
    context=json.loads(pin(bundle["native_type_context_adaptation"]))
    c=dict(fixed["constants"])
    assert not(set(c)&set(context["new_constants"]))
    c.update(context["new_constants"])
    inventory=json.loads(pin(bundle["native_type_context_reader_inventory"]))
    rows=[r for r in inventory["rows"] if (r["code"],r["where"],r["mask"])==(5,1,0)]
    assert len(rows)==1
    text=rows[0]["text"].encode("ascii")
    role=bundle["role_bindings"]["56"]
    image_raw=pin(role["image_path"]);source_raw=pin(role["source_path"])
    assert (len(image_raw),ns["digest"](image_raw))==(role["image_bytes"],role["image_sha256"])
    assert (len(source_raw),ns["digest"](source_raw))==(role["source_bytes"],role["source_sha256"])
    image=NativeHiaJsonImage(image_raw,expected_sha256=role["image_sha256"])
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mmap.restype=ctypes.c_void_p
    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    case_number=0;entries=0
    class Buffer:
        def __init__(self,raw=b"",size=None,readonly=False):
            raw=bytes(raw);self.size=len(raw) if size is None else size
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
            tail=self.extent-64-max(1,self.size)
            assert ctypes.string_at(self.ptr+max(1,self.size),tail)==bytes([0x6b])*tail
        def protect(self,readonly):
            assert libc.mprotect(self.base,self.extent,1 if readonly else 3)==0
            self.readonly=readonly
        def close(self):
            if self.base is not None:
                self.check();assert libc.munmap(self.base,self.extent)==0;self.base=None
    def put(raw,name,value):struct.pack_into("<Q",raw,c[name] if isinstance(name,str) else name,value)
    def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
    def ack(lease,seq,action,returned=0,observed=b""):
        return struct.pack("<8Q",c["ACK_MAGIC"],lease,seq,action,0,returned,len(observed),0)+observed
    def initial(occupied,spec):
        lease=0x57444301;request=37
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
        capsule=bytearray(struct.pack("<16Q",c["TC_RESULT"],1,lease+4,7,19,1,5,1,0,
                             33554432+64,len(text),128+len(text),0,0,0,0)+text)
        if spec["kind"]=="context-word":struct.pack_into("<Q",capsule,spec["at"],spec["value"])
        slots={0:Buffer(b"\0",readonly=True),1:Buffer(b"{}",readonly=True)}
        if occupied:
            for number in range(51,59):slots[number]=Buffer(bytes([number])*32,readonly=True)
        for number,buf in slots.items():put(raw,c["CAPS"]+number*8,buf.size)
        put(raw,c["CAPS"]+2*8,c["MIN_WORK"])
        # The original parent target is empty. The actual completion ACK is
        # what commits the capacity; this fixture supplies its immutable loan.
        slots[6]=Buffer(capsule,readonly=True)
        if spec["kind"]=="busy-field":put(raw,spec["field"],1)
        slots[2]=Buffer(raw)
        child=struct.pack("<16Q",c["EVENT_MAGIC"],7,lease+2,31,2,5,19,0,0,0,0,0,
                          0x123456789abcdef,0xfedcba9876543210,0x1111222233334444,0xaaaabbbbccccdddd)
        command=ack(lease,7,15,128,child+struct.pack("<4Q",len(capsule),6,46,0))
        return slots,command,lease,request,child,bytes(capsule)
    def native(source,output,workspace,workspace_extent,label):
        nonlocal entries
        assert source.readonly and not output.readonly and not workspace.readonly
        assert len({source.ptr,output.ptr,workspace.ptr})==3
        before_source=source.value();before_output=output.value();before_work=workspace.value()
        serial=ns["KERNEL_ENTRIES"]+1
        pending=dict(entry=serial,role=56,label=label,
          source=cas(before_source),source_extent=source.size,
          output=cas(before_output),output_extent=output.size,
          workspace=cas(before_work),workspace_extent=workspace_extent,
          actual_source_mprotect_readonly=True,image_sha256=role["image_sha256"])
        save(out/"pending-native-entry.json",pending)
        returned=int(image._entry(source.ptr,source.size,output.ptr,output.size,
                                   workspace.ptr,workspace_extent))
        entries+=1;ns["KERNEL_ENTRIES"]+=1
        for value in (source,output,workspace):value.check()
        assert source.value()==before_source
        save(out/"entries"/(str(serial).zfill(6)+".json"),dict(pending,returned=returned,
             source_after=cas(source.value()),output_after=cas(output.value()),
             workspace_after=cas(workspace.value()),complete_input_and_canaries_unchanged=True))
        return returned,output.value()
    def replay(slots,command,label):
        first=Buffer(command,readonly=True);output=Buffer(size=128)
        try:
            returned,_=native(first,output,slots[2],slots[2].size,label);assert returned==BAD,label
        finally:first.close();output.close()
    def one(spec):
        nonlocal case_number
        case_number+=1;label=spec["label"];first_entry=ns["KERNEL_ENTRIES"]+1
        slots,command,lease,request,child,capsule=initial(spec.get("occupied",False),spec)
        original=command;steps=[];final=None;view_count=0;copies=0;released=False
        keep={n:b.value() for n,b in slots.items() if n>=51}
        kind=spec["kind"];want_bad=kind!="success"
        mutated=kind in ("context-word","busy-field")
        if kind=="child-word":
            changed=bytearray(command);struct.pack_into("<Q",changed,spec["at"],spec["value"])
            command=bytes(changed);mutated=True
        elif kind=="child-extent":
            command=command[:spec["size"]] if spec["size"]<len(command) else command+b"\0";mutated=True
        save(out/"private-cases"/label/"plan.json",dict(spec,
             original_child=cas(child),private_capsule=cas(capsule),
             original_ACK=cas(original),first_ACK=cas(command),
             classification="PRIVATE_UNISSUED",actual_type_or_reader_not_invoked=True))
        try:
            for iteration in range(80):
                first=Buffer(command,readonly=True);output=Buffer(size=128)
                extent=c["MIN_WORK"]-1 if kind=="short-workspace" else c["MIN_WORK"]
                try:returned,event=native(first,output,slots[2],extent,label)
                finally:first.close();output.close()
                if returned==BAD:
                    assert want_bad and (mutated or kind=="short-workspace"),(label,returned)
                    if kind!="short-workspace":
                        assert word(slots[2].value(),c["L_STATUS"])==3
                        replay(slots,original,label+"-permanent-refusal")
                    final=dict(status="PASS",classification="PRIVATE_CONTINUATION_REFUSAL",
                         permanent_refusal_checked=kind!="short-workspace",
                         short_workspace_requires_outer_lease_discard=kind=="short-workspace")
                    break
                assert returned==128,(label,returned)
                words=struct.unpack("<16Q",event)
                assert words[0]==c["EVENT_MAGIC"] and words[2]==lease
                action=words[1];args=words[4:];steps.append(dict(event=cas(event),action=action))
                if action==7:
                    assert not want_bad and view_count==1 and copies==1 and released
                    assert 6 not in slots and slots[30].readonly
                    assert all(n in slots and slots[n].value()==raw for n,raw in keep.items())
                    frame=slots[30].value()
                    expected=dict(kind=4,domain=1,phase=0,line=0,
                        code=text.split(b": ",1)[0].decode("ascii"),payload=text,program=None)
                    ns["parse_result"]({"returncode":2},b"",event+frame,
                        {"expected":expected,"mode":1},lease,request)
                    replay(slots,original,label+"-terminal-not-reusable")
                    final=dict(status="PASS",classification="PRIVATE_COMPLETE_NATIVE_ROOT_ROUTE",
                        complete_payload_equal=True,capsule_released_before_publication=True,
                        assembly_slots_unchanged=True,terminal_not_reusable=True,result=cas(frame))
                    break
                returned=0;observed=b""
                if action==2:
                    slot,needed=args[:2];assert slot==30 and slot not in slots and needed>=256
                    slots[slot]=Buffer(size=needed)
                elif action==4:
                    source,at,target,to,size=args[:5]
                    assert source in slots and target in slots and source!=target
                    raw=slots[source].value();assert at<=len(raw) and size<=len(raw)-at
                    if source==6:
                        assert at==128 and size==len(text) and raw==capsule
                        copies+=1
                    else:assert source==2
                    slots[target].write(to,raw[at:at+size])
                elif action==5:
                    assert args[0]==6 and not released and copies==1 and slots[6].readonly
                    assert slots[6].value()==capsule
                    slots.pop(6).close();released=True
                elif action==6:
                    slot,readonly=args[:2];assert slot==30 and readonly==1
                    slots[slot].protect(True)
                elif action==14:
                    slot,at,size=args[:3]
                    assert (slot,at,size)==(6,0,128) and not released
                    assert slots[6].readonly and slots[6].value()==capsule
                    observed=slots[6].value()[:128];view_count+=1
                else:raise AssertionError((label,"unexpected mechanical operation",action))
                command=ack(lease,words[3],action,returned,observed)
                if kind=="ACK-word" and action==14:
                    changed=bytearray(command);at=spec["at"]
                    struct.pack_into("<Q",changed,at,word(changed,at)^1)
                    command=bytes(changed);mutated=True
                save(out/"private-cases"/label/"last-completed-step.json",
                    dict(iteration=iteration,event=cas(event),next_ACK=cas(command),
                        slots={str(n):dict(bytes=b.size,readonly=b.readonly,value=cas(b.value()))
                               for n,b in slots.items()}))
            assert final is not None,(label,"finite root did not terminate")
            final.update(label=label,first_native_entry=first_entry,last_native_entry=ns["KERNEL_ENTRIES"],
                         actual_program_type_and_reader=False,foreign_immutable_child_fixture=True)
            ns["ROWS"].append(final);save(out/"cases-completed.json",ns["ROWS"])
            save(out/"private-cases"/label/"summary.json",dict(final,steps=steps,
                final_slots={str(n):dict(bytes=b.size,readonly=b.readonly,value=cas(b.value()))
                             for n,b in slots.items()}))
        finally:
            for value in slots.values():value.close()
    plan=[dict(label="success-assembly-slots-"+str(int(occupied)),kind="success",occupied=occupied)
          for occupied in (False,True)]
    changes=[(0,0),(8,2),(16,0),(24,0),(32,0),(40,7),(48,6),(56,19),
             (64,1),(72,MAX),(80,len(text)+1),(88,129+len(text)),(104,MAX),(120,1)]
    plan.extend(dict(label="context-header-"+str(at),kind="context-word",at=at,value=value)
                for at,value in changes)
    plan.extend(dict(label="view-ACK-"+str(at),kind="ACK-word",at=at)
                for at in (0,8,16,24,32,48,56))
    plan.extend(dict(label="child-binding-"+str(at),kind="child-word",at=at,value=value)
                for at,value in ((208,44),(104,18),(192,129+len(text)),(80,0)))
    plan.extend(dict(label="child-extent-"+str(size),kind="child-extent",size=size)
                for size in (223,225))
    plan.extend(dict(label="busy-"+field,kind="busy-field",field=field)
                for field in ("WC_ACTIVE","WP_RESULT_KIND"))
    plan.append(dict(label="short-workspace",kind="short-workspace"))
    assert len(plan)==32
    save(out/"private-context-plan.json",dict(cases=plan,count=32,
         private_unissued=True,actual_type_reader_not_invoked=True,
         public_context_issuer_proved_only_in_separate_real_ELF_cases=True))
    try:
        for spec in plan:one(spec)
        assert case_number==32 and len(ns["ROWS"])==32
        return dict(planned_cases=32,actual_entries_by_role={"56":entries},
          complete_sources_outputs_workspaces_and_canaries_recorded=True,
          private_unissued=True,actual_program_type_reader=False,
          no_namespace_authority=True,old_counts_not_inherited=True)
    finally:image._mapping.close()
