"""Actual-context-derived private reader controls; never external authentication."""
from __future__ import annotations
import ctypes,struct
from pathlib import Path
from type_context_mechanical_r1 import (Pair,BAD,NEED,MAX,WORK,OUTPUT,S,CONTEXT,word,q)

def controls():
    rows=[]
    for index,(at,value) in enumerate([
      (0,0),(8,2),(16,0),(24,0),(32,0),(40,0),(40,7),(40,2),(40,3),
      (48,63),(48,OUTPUT+1),(56,1)]):
        rows.append(dict(label="command-"+str(index),kind="command",at=at,value=value,want="BAD"))
    for index,(at,value) in enumerate([
      (64,0),(72,0),(72,6),(80,1),(88,0),(96,1),(104,1),(112,1),(120,1)]):
        rows.append(dict(label="native-header-"+str(index),kind="command",at=at,value=value,want="BAD"))
    for index,(at,value) in enumerate([
      (S,0),(S+8,0),(S+8,6),(S+16,15),(S+24,1),(S+32,1),(S+48,1),
      (CONTEXT,0),(CONTEXT+8,2),(CONTEXT+16,6)]):
        rows.append(dict(label="state-"+str(index),kind="work",at=at,value=value,want="BAD"))
    for index,(at,value) in enumerate([
      (CONTEXT+24,0),(CONTEXT+24,19),(CONTEXT+32,1),(CONTEXT+40,0),
      (CONTEXT+40,32*1024*1024+63),(CONTEXT+40,32*1024*1024+65),
      (CONTEXT+40,64*1024*1024-1),(CONTEXT+40,MAX),
      (CONTEXT+48,1),(CONTEXT+56,1)]):
        rows.append(dict(label="context-"+str(index),kind="work",at=at,value=value,want="BAD"))
    for name,index,value in (("short-work",0,WORK-1),("long-work",0,WORK+1),
                            ("short-command",1,127),("long-command",1,129),
                            ("zero-output",2,0),("short-output",2,127)):
        rows.append(dict(label=name,kind="extent",index=index,value=value,want="BAD"))
    for size in ("header","needed-minus-one","needed","needed-plus-17"):
        rows.append(dict(label="capacity-"+size,kind="capacity",size=size,want="CAPACITY"))
    rows.extend([
      dict(label="private-nonzero-correlations-are-not-authentication",kind="correlation",want="SUCCESS"),
      dict(label="private-alternate-context-is-not-authentication",kind="work",
           at=CONTEXT+24,value=8,want="OTHER_CONTEXT"),
      dict(label="private-in-range-node-is-not-authentication",kind="work",
           at=CONTEXT+40,value=64*1024*1024+64,want="SUCCESS")])
    assert len(rows)==64
    return rows

def run(m,prepared):
    plan=controls()
    m.save(Path("private-control-plan.json"),dict(cases=plan,count=len(plan),
       origin="One actual completed type-context call is copied as a private malformed-input fixture",
       private_unissued_mutations_are_not_public_inputs=True,
       nonce_and_context_integers_are_not_authenticators=True))
    pair=Pair(m);loan=None
    try:
        actual=pair.command(prepared[0]["steps"][0],"protocol-issued-baseline")
        frame_bytes=actual["actual_native_frame_bytes"]
        header=pair.new_output.value(0,64)
        original_context=pair.new_work.value(CONTEXT,64)
        expected=prepared[0]["steps"][0]["public_message"].encode("utf-8")
        other=prepared[1]["steps"][0]["public_message"].encode("utf-8")
        needed=128+len(expected)
        loan=m.buffer(WORK)
        ctypes.memmove(loan.ptr,pair.new_work.ptr,WORK)
        actual_snapshot=m.snapshot(pair.new_work);clone_snapshot=m.snapshot(loan)
        assert actual_snapshot==clone_snapshot
        m.save(Path("private-clone-source.json"),dict(
            actual_completed_context=actual,actual_workspace=actual_snapshot,
            private_clone=clone_snapshot,byte_identity=True,issued_authority_inherited=False))
    finally:pair.close()
    command=struct.pack("<8Q",int.from_bytes(b"HIATDC01","little"),1,
                        0x54594301,1,1,1,frame_bytes,0)+header
    rows=[]
    try:
        for case in plan:
            raw=bytearray(command);saved=None;output_size=4096
            if case["kind"]=="command":struct.pack_into("<Q",raw,case["at"],case["value"])
            elif case["kind"]=="work":
                saved=(case["at"],loan.value(case["at"],8))
                loan.write(case["at"],q(case["value"]))
            elif case["kind"]=="correlation":
                for at in (16,24,32):struct.pack_into("<Q",raw,at,word(raw,at)+17)
            elif case["kind"]=="capacity":
                output_size={"header":128,"needed-minus-one":needed-1,
                             "needed":needed,"needed-plus-17":needed+17}[case["size"]]
            elif case["kind"]!="extent":raise AssertionError(case)
            second=m.buffer(129,bytes(raw)+b"\0",readonly=True)
            out=m.buffer(output_size)
            extents=[WORK,128,output_size]
            if case["kind"]=="extent":extents[case["index"]]=case["value"]
            loan.protect(True)
            first_entry=m.entries+1
            try:
                ret,entry=m.invoke("context-reader",loan,second,out,case["label"],extents=extents)
                full=out.value()
                if case["want"]=="BAD":
                    assert ret==BAD and full==bytes(output_size),(case,ret)
                else:
                    text=other if case["want"]=="OTHER_CONTEXT" else expected
                    total=128+len(text)
                    want=NEED if extents[2]<total else total
                    assert ret==want,(case,ret,want)
                    words=struct.unpack_from("<16Q",full)
                    assert words[:7]==(int.from_bytes(b"HIATDE01","little"),1,
                      word(raw,16),word(raw,24),word(raw,32),1,5),(case,words)
                    expected_where=8 if case["want"]=="OTHER_CONTEXT" else 1
                    expected_node=case["value"] if case["kind"]=="work" and case["at"]==CONTEXT+40 else word(original_context,40)
                    assert words[7:10]==(expected_where,0,expected_node),(case,words)
                    assert words[10:]==(len(text),total,0,0,0,0),(case,words)
                    if ret==NEED:assert full[128:]==bytes(output_size-128),case
                    else:assert full[128:total]==text and full[total:]==bytes(output_size-total),case
                row=dict(case,status="PASS",actual_entry=entry["entry"],
                    complete_result=m.cas(full),returned=ret,
                    actual_source_readonly=True,source_is_private_clone=True,
                    original_issuer_authority_not_inferred=True)
                rows.append(row);m.save(Path("protocol-cases-completed.json"),rows)
            finally:
                loan.protect(False)
                if saved is not None:loan.write(*saved)
                second.close();out.close()
            assert m.entries==first_entry
        assert len(rows)==64 and loan.value(CONTEXT,64)==original_context
        assert m.snapshot(loan)==clone_snapshot
        return dict(status="PASS",controls=64,case_rows=rows,actual_baseline=actual,
                    original_clone_restored_byte_for_byte=True,
                    actual_program_driver_not_joined=True,private_unissued_scope=True)
    finally:
        if loan is not None:loan.close()
