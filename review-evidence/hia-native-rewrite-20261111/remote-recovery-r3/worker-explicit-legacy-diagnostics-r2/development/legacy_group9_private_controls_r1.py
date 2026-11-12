"""Forty-eight new private continuation controls for actual explicit importer46.

Inputs at these continuation points are deliberately unissued fixtures. They
exercise the actual old/new HIA images, full terminal preservation and new
mechanical diagnostic lifetime, without claiming public reachability of code4.
"""
from __future__ import annotations
import struct
from pathlib import Path
from legacy_diagnostic_test_support_r2 import Buffer,save
MASK=(1<<64)-1
def words(raw):return struct.unpack("<"+"Q"*(len(raw)//8),raw)
def pack(*values):return struct.pack("<"+"Q"*len(values),*values)

def run(bundle,old_image,new_image,trace,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    C=bundle["constants"];bad=C["ABI"];rows=[];mechanics=[]
    expected_messages={int(k):v.encode("utf-8") for k,v in bundle["diagnostic_messages"].items()}
    def get(w,key):return struct.unpack_from("<Q",w.value(),C[key])[0]
    def put(w,key,value):w.write(C[key],pack(value))
    def at(w,offset,value):w.write(offset,pack(value))
    def acknowledgment(w,observed=b"",returned=0):
        assert len(observed)==get(w,"C_OBSERVE")
        return pack(C["ACK_MAGIC"],get(w,"C_LEASE"),get(w,"C_SEQUENCE"),
            get(w,"C_PENDING"),0,returned,len(observed),0)+observed
    def call(image,w,o,raw,label,**kw):
        s=Buffer(raw,readonly=True)
        try:return trace.call(image,s,o,w,label=label,**kw)
        finally:s.close()
    def seed(error):
        w=Buffer(size=C["MIN_WORK"]);o=Buffer(size=128)
        for key,value in {
            "C_MAGIC":C["IMPORT_STATE"],"C_STATUS":1,"C_LEASE":91,"C_SEQUENCE":7,
            "L_MAGIC":C["LOWER_MAGIC"],"L_STATUS":1,"L_DRIVER":46,
            "L_FN_SERIAL":17,"L_FN_SLOTS":23,"L_FN_COUNT":2,"L_HELP_COUNT":3,
            "L_FINAL_BYTES":101,"L_DIGEST0":111,"L_DIGEST1":222,
            "L_DIGEST2":333,"L_DIGEST3":444}.items():put(w,key,value)
        for slot,size in ((0,1),(1,82),(2,C["MIN_WORK"])):at(w,C["CAPS"]+slot*8,size)
        if error in (1,2):
            for key,value in {"C_PENDING":1,"C_OBSERVE":64,"C_NEXT":5,
                              "M_ORIGINAL_PACKET":16}.items():put(w,key,value)
            observed=pack(C["PROJECTION"],error,64,0,16,0,0,0);returned=64
        elif error==3:
            for key,value in {"C_PENDING":15,"C_OBSERVE":160,"C_NEXT":28,
                    "M_CHILD_MODE":1,"M_CHILD_TARGET":54,"M_CHILD_LEASE":92,
                    "M_RENAMED_BYTES":C["INPUT_LIMIT"]+1}.items():put(w,key,value)
            observed=pack(C["EVENT_MAGIC"],7,92,1,0,0,0,9,8,7,6,127,11,22,33,44,
                          127,54,47,0);returned=128
        else:
            assert error==4
            for key,value in {"C_PENDING":1,"C_OBSERVE":64,"C_NEXT":31,
                             "M_OLD_BYTES":127,"M_NEW_BYTES":129}.items():put(w,key,value)
            observed=pack(C["COMPARISON"],1,127,129,0,0,0,0);returned=64
        return w,o,acknowledgment(w,observed,returned)
    def effect(w,raw,slots,label):
        event=words(raw);assert len(event)==16 and event[:1]==(C["EVENT_MAGIC"],)
        assert event[2]==get(w,"C_LEASE") and event[3]==get(w,"C_SEQUENCE")
        op=event[1];a=event[4:]
        before={str(k):trace.cas.keep(v.value()) for k,v in slots.items()}
        if op==2:
            assert a[0]==57 and a[1]>0 and a[2:]==(0,)*10 and 57 not in slots
            slots[57]=Buffer(size=a[1])
        elif op==4:
            assert a[0]==2 and a[2]==57 and a[5:]==(0,)*7
            assert a[1]<=w.size and a[4]<=w.size-a[1]
            slots[57].write(a[3],w.value()[a[1]:a[1]+a[4]])
        elif op==6:
            assert a[:2]==(57,1) and a[2:]==(0,)*10
            slots[57].protect(True)
        else:raise AssertionError(("unexpected private mechanical opcode",op))
        for v in slots.values():v.check()
        after={str(k):trace.cas.keep(v.value()) for k,v in slots.items()}
        row=dict(label=label,command=trace.cas.keep(raw),before=before,after=after,
            actual_readonly={str(k):v.readonly for k,v in slots.items()},business_callback=False)
        mechanics.append(row);save(out/"mechanical-actions.json",mechanics)
        return acknowledgment(w)
    def close(w,o,slots=None):
        errors=[]
        for value in list((slots or {}).values())+[o,w]:
            try:value.close()
            except BaseException as exc:errors.append(exc)
        if errors:raise errors[0]
    def complete(label,entry_start,**extra):
        row=dict(label=label,status="PASS",actual_entries=len(trace.entries)-entry_start,
            private_unissued=True,namespace_authority=False,public_reachability_claimed=False,**extra)
        rows.append(row);save(out/"completed-cases.json",rows)
    def rejected(label,w,o,raw,*,work_extent=None,out_extent=None,poison=True):
        before=w.value();start=len(trace.entries)
        ret=call(new_image,w,o,raw,label,work_extent=work_extent,out_extent=out_extent)
        assert ret==bad,(label,ret)
        if poison:
            assert get(w,"L_STATUS")==3
            again=call(new_image,w,o,raw,label+"-same-lease-reuse")
            assert again==bad and get(w,"L_STATUS")==3
        else:assert w.value()==before
        return start
    # Four actual original terminals and four complete new COPY/PROTECT chains.
    for error in range(1,5):
        label="old-new-terminal-code-"+str(error);start=len(trace.entries)
        w,o,raw=seed(error);original=Buffer(w.value());original_o=Buffer(size=128);slots={}
        try:
            assert call(old_image,original,original_o,raw,label+"-actual-old")==128
            old=words(original_o.value());assert old[1]==7 and old[4:6]==(9,error)
            for step in range(5):
                ret=call(new_image,w,o,raw,label+"-new-"+str(step));assert ret==128
                event=words(o.value())
                if event[1]==7:break
                raw=effect(w,o.value(),slots,label+"-mechanic-"+str(step))
            else:raise AssertionError("no terminal within exact finite chain")
            actual=words(o.value());expected=list(old);expected[3]+=3
            assert actual==tuple(expected) and step==3
            diagnostic=slots[57].value();message=expected_messages[error]
            assert slots[57].readonly
            assert words(diagnostic[:64])==(C["LG_DIAGNOSTIC"],1,9,error,91,actual[3],
                                            64+len(message),len(message))
            assert diagnostic[64:]==message and get(w,"LG_STATE")==2
            assert get(w,"LG_ORIGINAL_PHASE")=={1:5,2:5,3:28,4:31}[error]
            assert call(new_image,w,o,raw,label+"-retired-reuse")==bad
            complete(label,start,original_terminal=trace.cas.keep(original_o.value()),
                full_new_terminal=trace.cas.keep(pack(*actual)),full_diagnostic=trace.cas.keep(diagnostic),
                all_other_15_terminal_words_equal=True,three_actual_mechanical_events=True,
                code4_public_case=False)
        finally:close(w,o,slots);original.close();original_o.close()
    # Exactly the eight ACK words, a short header and a trailing byte.
    for key,index,value in (("magic",0,0),("lease",1,92),("sequence",2,8),("opcode",3,2),
            ("status",4,1),("return",5,65),("observe",6,63),("reserved",7,1),
            ("short",None,0),("trailing",None,1)):
        label="ack-"+key;w,o,raw=seed(1)
        try:
            if index is not None:
                changed=bytearray(raw);struct.pack_into("<Q",changed,index*8,value);raw=bytes(changed)
            elif key=="short":raw=raw[:63]
            else:raw+=b"\0"
            start=rejected(label,w,o,raw);complete(label,start,permanent_refusal=True)
        finally:close(w,o)
    for label,kind in (("short-advertised-workspace","work"),("short-advertised-output","out")):
        w,o,raw=seed(1)
        try:
            start=rejected(label,w,o,raw,
                work_extent=C["MIN_WORK"]-1 if kind=="work" else None,
                out_extent=127 if kind=="out" else None,poison=kind!="work")
            complete(label,start,permanent_native_poison_claimed=kind!="work",
                driver_discards_unadvertised_short_workspace=True)
        finally:close(w,o)
    changes=(("status",("L_STATUS",0)),("magic",("L_MAGIC",0)),
        ("driver",("L_DRIVER",45)),("context",("C_MAGIC",0)),
        ("already-started",("LG_STATE",1)),("existing-slot",("CAP57",1)),
        ("projection-magic",("OBS0",0)),("projection-count",("OBS32",17)),
        ("projection-reserved",("OBS48",1)),("projection-enum",("OBS8",3)))
    for name,(key,value) in changes:
        label="begin-"+name;w,o,raw=seed(1)
        try:
            if key=="CAP57":at(w,C["CAPS"]+57*8,value)
            elif key.startswith("OBS"):
                raw=bytearray(raw);struct.pack_into("<Q",raw,64+int(key[3:]),value);raw=bytes(raw)
            else:put(w,key,value)
            start=rejected(label,w,o,raw);complete(label,start,permanent_refusal=True)
        finally:close(w,o)
    for name,key,value in (
            ("state","LG_STATE",0),("context","C_MAGIC",0),("driver","L_DRIVER",45),
            ("error-zero","LG_ERROR",0),("error-high","LG_ERROR",5),
            ("text-extent","LG_TEXT_BYTES",1),("frame-extent","LG_FRAME_BYTES",64),
            ("allocated-extent","C_ALLOC_BYTES",256),("sequence-overflow","C_SEQUENCE",MASK-1),
            ("unknown-phase","C_NEXT",90004)):
        label="grow-continuation-"+name;w,o,raw=seed(1);slots={};start=len(trace.entries)
        try:
            assert call(new_image,w,o,raw,label+"-real-grow")==128 and words(o.value())[1]==2
            raw=effect(w,o.value(),slots,label+"-actual-grow")
            put(w,key,value)
            if key=="C_SEQUENCE":raw=acknowledgment(w)
            rejected(label,w,o,raw)
            complete(label,start,first_GROW_actual=True,permanent_refusal=True)
        finally:close(w,o,slots)
    for name,offset,value in (
            ("terminal-magic",0,0),("child-lease",16,93),("child-role",144,40),
            ("short-owned-core",128,126),("inconsistent-success-error",40,1)):
        label="old-Core-before-byte-error-"+name;w,o,raw=seed(3)
        try:
            changed=bytearray(raw);struct.pack_into("<Q",changed,64+offset,value);raw=bytes(changed)
            start=rejected(label,w,o,raw)
            complete(label,start,original_child_validation_precedes_group9_error3=True)
        finally:close(w,o)
    for name,offset,value in (("magic",0,0),("enum",8,2),("old-size",16,126),("reserved",56,1)):
        label="comparison-before-mismatch-"+name;w,o,raw=seed(4)
        try:
            changed=bytearray(raw);struct.pack_into("<Q",changed,64+offset,value);raw=bytes(changed)
            start=rejected(label,w,o,raw)
            complete(label,start,original_full_comparison_header_precedes_error4=True)
        finally:close(w,o)
    for name,key,value in (("capacity","CAP57",1),("final-sequence","LG_SEQUENCE",100),
                          ("protect-ACK-return","ACK_RETURN",1)):
        label="protect-continuation-"+name;w,o,raw=seed(1);slots={};start=len(trace.entries)
        try:
            for expected_opcode in (2,4,6):
                assert call(new_image,w,o,raw,label+"-actual-"+str(expected_opcode))==128
                assert words(o.value())[1]==expected_opcode
                raw=effect(w,o.value(),slots,label+"-mechanic-"+str(expected_opcode))
            if key=="CAP57":at(w,C["CAPS"]+57*8,value)
            elif key=="ACK_RETURN":
                changed=bytearray(raw);struct.pack_into("<Q",changed,40,value);raw=bytes(changed)
            else:put(w,key,value)
            rejected(label,w,o,raw)
            complete(label,start,actual_COPY_then_PROTECT_before_terminal=True,
                diagnostic_readonly=slots[57].readonly,permanent_refusal=True)
        finally:close(w,o,slots)
    assert len(rows)==48 and len({r["label"] for r in rows})==48
    save(out/"private-result.json",dict(status="PASS",cases=48,results=rows,
        exact_original_and_new_terminal_cases=4,public_cases=0,
        old_and_new_actual_images=True,all_full_buffers_and_canaries_preserved=True,
        fixed_executor_fault_injection=False,error4_public_reachability_proved=False))
    return rows
