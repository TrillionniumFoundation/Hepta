"""Private actual-root controls for late Core diagnostics.

All seeded child terminals are PRIVATE_UNISSUED. The public cases separately
run the real producer -> visitor -> program -> parent path. This fixture
cannot authenticate an external arena or manufacture namespace authority.
"""
from __future__ import annotations
import ast,ctypes,json,struct

BAD=0xfffffffd

def run(ns):
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    bundle=ns["bundle"];out=ns["OUT"];cas=ns["cas"];save=ns["save"];pin=ns["pin"]
    fixed=json.loads(pin(bundle["diagnostic_adaptation"]))
    context=json.loads(pin(bundle["native_type_context_adaptation"]))
    late=json.loads(pin(bundle["native_late_Core_adaptation"]))
    c=dict(fixed["constants"]);c.update(context["new_constants"])
    # Recover the fixture address from the exact retained source keyword, not
    # from an assumed public offset or the diagnostic report's partial table.
    prefix_raw=pin(ns["PROJECT"]/"tools/program_service_root_reference.py")
    assert ns["digest"](prefix_raw)=="f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9"
    assignments=[node for node in ast.parse(prefix_raw).body
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="CONSTANTS"
                                             for t in node.targets)]
    assert len(assignments)==1 and isinstance(assignments[0].value,ast.Call)
    expression=assignments[0].value
    assert isinstance(expression.func,ast.Name) and expression.func.id=="dict"
    keywords=[item for item in expression.keywords if item.arg=="PREFIX_TEXT"]
    assert len(keywords)==1
    c["PREFIX_TEXT"]=ast.literal_eval(keywords[0].value)
    assert type(c["PREFIX_TEXT"]) is int and 0<c["PREFIX_TEXT"]<=c["MIN_WORK"]-128
    messages={row["status"]:row["text"].encode("ascii") for row in late["messages"]}
    assert set(messages)=={1,2,3}
    role=bundle["role_bindings"]["56"]
    raw_image=pin(role["image_path"]);raw_source=pin(role["source_path"])
    assert (len(raw_image),ns["digest"](raw_image))==(role["image_bytes"],role["image_sha256"])
    assert (len(raw_source),ns["digest"](raw_source))==(role["source_bytes"],role["source_sha256"])
    image=NativeHiaJsonImage(raw_image,expected_sha256=role["image_sha256"])
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mmap.restype=ctypes.c_void_p
    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    entries=0
    class Buffer:
        def __init__(self,raw=b"",size=None,readonly=False):
            raw=bytes(raw);self.size=len(raw) if size is None else size
            assert 0<=len(raw)<=self.size
            self.extent=((max(1,self.size)+128+4095)//4096)*4096
            self.base=int(libc.mmap(None,self.extent,3,0x22,-1,0))
            assert self.base!=ctypes.c_void_p(-1).value
            self.ptr=self.base+64;self.readonly=False
            ctypes.memset(self.base,0x69,self.extent)
            ctypes.memset(self.ptr,0,max(1,self.size))
            if raw:ctypes.memmove(self.ptr,raw,len(raw))
            if readonly:self.protect(True)
        def value(self):return ctypes.string_at(self.ptr,self.size)
        def write(self,at,raw):
            raw=bytes(raw)
            assert not self.readonly and 0<=at<=self.size and len(raw)<=self.size-at
            if raw:ctypes.memmove(self.ptr+at,raw,len(raw))
        def check(self):
            assert ctypes.string_at(self.base,64)==bytes([0x69])*64
            tail=self.extent-64-max(1,self.size)
            assert ctypes.string_at(self.ptr+max(1,self.size),tail)==bytes([0x69])*tail
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
    def initial(spec):
        lease=0x574c4301;request=43;code=spec.get("code",2)
        raw=bytearray(c["MIN_WORK"])
        values={"C_MAGIC":c["EDIT_STATE"],"C_STATUS":1,"C_LEASE":lease,"C_SEQUENCE":7,
            "C_PENDING":15,"C_NEXT":2,"C_OBSERVE":160,"L_MAGIC":c["LOWER_MAGIC"],
            "L_STATUS":1,"L_DRIVER":56,"A_MAGIC":c["A_STATE_MAGIC"],
            "WP_MAGIC":c["WP_STATE"],"WP_MODE":1,"WP_REQUEST":request,
            "WP_INPUT_BYTES":2,"WP_TREE":int(spec.get("occupied",False)),
            "WP_SELECTED_SLOT":1,"E_CHILD_LEASE":lease+1,"E_CHILD_TARGET":6,
            "E_DIGITS":4300,"E_REQUEST":request}
        if spec.get("occupied"):values.update(AS_MAGIC=c["AS_STATE_MAGIC"],AS_MODE=0)
        for key,value in values.items():put(raw,key,value)
        slots={0:Buffer(b"\0",readonly=True),1:Buffer(b"{}",readonly=True)}
        if spec.get("occupied"):
            for number in range(51,59):slots[number]=Buffer(bytes([number])*32,readonly=True)
        if spec["kind"]=="busy-slot":slots[spec["slot"]]=Buffer(b"x",readonly=True)
        for number,buf in slots.items():put(raw,c["CAPS"]+number*8,buf.size)
        put(raw,c["CAPS"]+2*8,c["MIN_WORK"])
        if spec["kind"]=="busy-field":put(raw,spec["field"],1)
        slots[2]=Buffer(raw)
        extent=8388609 if code==3 else 1024
        child=struct.pack("<16Q",c["EVENT_MAGIC"],7,lease+2,31,6,code,19,7,11,1,0,extent,
                          0x0123456789abcdef,0xfedcba9876543210,0x1111222233334444,0xaaaabbbbccccdddd)
        command=ack(lease,7,15,128,child+struct.pack("<4Q",0,6,46,0))
        return slots,command,lease,request,child,code
    def native(source,output,workspace,extent,label):
        nonlocal entries
        assert source.readonly and not output.readonly and not workspace.readonly
        assert len({source.ptr,output.ptr,workspace.ptr})==3
        before_source=source.value();serial=ns["KERNEL_ENTRIES"]+1
        pending={"entry":serial,"role":56,"label":label,"image_sha256":role["image_sha256"],
            "source":cas(before_source),"source_extent":source.size,
            "output":cas(output.value()),"output_extent":output.size,
            "workspace":cas(workspace.value()),"workspace_extent":extent,
            "actual_source_mprotect_readonly":True}
        save(out/"pending-native-entry.json",pending)
        returned=int(image._entry(source.ptr,source.size,output.ptr,output.size,workspace.ptr,extent))
        entries+=1;ns["KERNEL_ENTRIES"]+=1
        for value in (source,output,workspace):value.check()
        assert source.value()==before_source
        save(out/"entries"/(str(serial).zfill(6)+".json"),dict(pending,returned=returned,
            source_after=cas(source.value()),output_after=cas(output.value()),
            workspace_after=cas(workspace.value()),complete_input_and_canaries_unchanged=True))
        return returned,output.value()
    def replay(slots,command,label):
        source=Buffer(command,readonly=True);output=Buffer(size=128)
        try:
            returned,_=native(source,output,slots[2],slots[2].size,label)
            assert returned==BAD
        finally:source.close();output.close()
    def one(spec):
        label=spec["label"];first_entry=ns["KERNEL_ENTRIES"]+1
        slots,command,lease,request,child,code=initial(spec)
        original=command;kind=spec["kind"];want_bad=kind!="success";steps=[];final=None
        keep={n:b.value() for n,b in slots.items() if n not in (2,30)}
        if kind=="child-word":
            change=bytearray(command);struct.pack_into("<Q",change,64+spec["at"],spec["value"])
            command=bytes(change)
        elif kind=="ACK-word":
            change=bytearray(command);at=spec["at"]
            struct.pack_into("<Q",change,at,word(change,at)^1);command=bytes(change)
        elif kind=="ACK-extent":
            command=command[:spec["size"]] if spec["size"]<len(command) else command+b"\0"
        save(out/"private-cases"/label/"plan.json",dict(spec,
            original_child=cas(child),original_ACK=cas(original),first_ACK=cas(command),
            classification="PRIVATE_UNISSUED_CHILD_TERMINAL",
            actual_lower_program_visitor_not_invoked=True))
        try:
            for iteration in range(64):
                source=Buffer(command,readonly=True);output=Buffer(size=128)
                extent=c["MIN_WORK"]-1 if kind=="short-workspace" else c["MIN_WORK"]
                try:returned,event=native(source,output,slots[2],extent,label)
                finally:source.close();output.close()
                if returned==BAD:
                    assert want_bad,(label,"unexpected native refusal")
                    if kind!="short-workspace":
                        assert word(slots[2].value(),c["L_STATUS"])==3
                        replay(slots,original,label+"-permanent-refusal")
                    final={"label":label,"status":"PASS",
                        "classification":"PRIVATE_LATE_CORE_CONTINUATION_REFUSAL",
                        "permanent_refusal_checked":kind!="short-workspace",
                        "short_workspace_requires_outer_lease_discard":kind=="short-workspace"}
                    break
                assert returned==128,(label,returned)
                words=struct.unpack("<16Q",event)
                assert words[0]==c["EVENT_MAGIC"] and words[2]==lease
                action=words[1];args=words[4:]
                steps.append({"event":cas(event),"action":action})
                if action==7:
                    assert not want_bad and 30 in slots and slots[30].readonly
                    assert all(n in slots and slots[n].value()==raw for n,raw in keep.items())
                    frame=slots[30].value();text=messages[code]
                    expected={"kind":4,"domain":1,"phase":0,"line":0,
                        "code":"E_HIA_LIMIT","payload":text,"program":None}
                    ns["parse_result"]({"returncode":2},b"",event+frame,
                        {"expected":expected,"mode":1},lease,request)
                    replay(slots,original,label+"-terminal-not-reusable")
                    final={"label":label,"status":"PASS",
                        "classification":"PRIVATE_COMPLETE_NATIVE_LATE_CORE_ROUTE",
                        "complete_payload_equal":True,"result":cas(frame),
                        "unrelated_slots_unchanged":True,"terminal_not_reusable":True}
                    break
                assert not want_bad,(label,"bad original terminal advanced",action)
                observed=b""
                if action==14:
                    source_slot,at,size=args[:3]
                    assert source_slot==2 and at==c["PREFIX_TEXT"] and size==min(len(messages[code]),64)
                    data=slots[source_slot].value()
                    assert at<=len(data) and size<=len(data)-at
                    observed=data[at:at+size]
                elif action==2:
                    slot,needed=args[:2]
                    assert slot==30 and slot not in slots and needed==256+len(messages[code])
                    slots[slot]=Buffer(size=needed)
                elif action==4:
                    source_slot,at,target,to,size=args[:5]
                    assert source_slot==2 and target==30
                    data=slots[source_slot].value()
                    assert at<=len(data) and size<=len(data)-at
                    slots[target].write(to,data[at:at+size])
                elif action==6:
                    slot,readonly=args[:2]
                    assert (slot,readonly)==(30,1)
                    slots[slot].protect(True)
                else:raise AssertionError((label,"unexpected mechanical operation",action))
                command=ack(lease,words[3],action,observed=observed)
                save(out/"private-cases"/label/"last-completed-step.json",{
                    "iteration":iteration,"event":cas(event),"next_ACK":cas(command),
                    "slots":{str(n):{"bytes":b.size,"readonly":b.readonly,"value":cas(b.value())}
                             for n,b in slots.items()}})
            assert final is not None,(label,"finite continuation did not finish")
            final.update(first_native_entry=first_entry,last_native_entry=ns["KERNEL_ENTRIES"],
                actual_lower_program_visitor=False,foreign_immutable_child_fixture=True,
                public_depth_status1_reachability_not_claimed=True)
            ns["ROWS"].append(final);save(out/"cases-completed.json",ns["ROWS"])
            save(out/"private-cases"/label/"summary.json",dict(final,steps=steps))
        finally:
            for buffer in slots.values():buffer.close()
    plan=[{"label":"late-code"+str(code)+"-occupied"+str(int(occupied)),
           "kind":"success","code":code,"occupied":occupied}
          for code in (1,2,3) for occupied in (False,True)]
    child_changes=((0,0),(8,0),(16,0),(24,0),(32,9),(40,0),(40,4),(88,0),
                   (128,1),(136,7),(144,44),(152,1))
    plan.extend({"label":"child-"+str(at)+"-"+str(value),"kind":"child-word","at":at,"value":value}
                for at,value in child_changes)
    plan.append({"label":"byte-late-at-capacity","kind":"child-word","code":3,"at":88,"value":8388608})
    plan.extend({"label":"ACK-"+str(at),"kind":"ACK-word","at":at} for at in range(0,64,8))
    plan.extend({"label":"ACK-size-"+str(size),"kind":"ACK-extent","size":size} for size in (223,225))
    plan.extend({"label":"busy-"+field,"kind":"busy-field","field":field}
                for field in ("WD_ACTIVE","WC_ACTIVE","WP_RESULT_KIND","WP_HAS_RECEIPT","E_ERROR_BYTES"))
    plan.extend({"label":"busy-slot-"+str(slot),"kind":"busy-slot","slot":slot} for slot in (6,47,48))
    plan.append({"label":"short-workspace","kind":"short-workspace"})
    assert len(plan)==38 and len({row["label"] for row in plan})==38
    save(out/"private-late-Core-plan.json",{"cases":plan,"count":38,
        "private_unissued":True,"actual_lower_program_visitor_not_invoked":True,
        "public_late_depth_reachability_not_claimed":True})
    try:
        for spec in plan:one(spec)
        assert len(ns["ROWS"])==38
        return {"planned_cases":38,"actual_entries_by_role":{"56":entries},
            "complete_sources_outputs_workspaces_and_canaries_recorded":True,
            "private_unissued":True,"actual_lower_program_visitor":False,
            "namespace_authority":False,"old_counts_inherited":False}
    finally:image._mapping.close()
