"""Original-public late Core boundary fixtures, prepared before actual native.

NEW SOURCE / 0 AST / 0 native at submission. No expected message is taken
from the native enum table. Direct original elaboration is used only to
measure the fixture; the public original verify_program supplies the oracle.
"""
from __future__ import annotations
import json,traceback
from hashlib import sha256
from pathlib import Path

REFERENCE_PROGRAM_SHA="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
REFERENCE_COMPOSITE_SHA="cc5ab4c8dc68214e8868aab30405820c3662572de63952dec5f1fd1aaf180951"
NODES=262144
BYTES=8388608
GROUPS={
    "late-node-below":1,"late-node-equal":1,"late-node-over":1,
    "late-byte-below":1,"late-byte-equal":1,"late-byte-over":1,
    "late-depth-and-order":4,
}

def stats(value):
    pending=[(value,0)];count=0;maximum=0
    while pending:
        node,depth=pending.pop();count+=1;maximum=max(maximum,depth)
        kind=type(node)
        if kind is dict:
            assert all(type(key) is str for key in node)
            pending.extend((child,depth+1) for child in node.values())
        elif kind is list:
            pending.extend((child,depth+1) for child in node)
        else:
            assert kind in (str,int,bool,type(None))
    return {"nodes":count,"depth":maximum}

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")

def fixture(padding):
    return {"schema":"hepta.hia.composite.v1","module":"late_core",
      "types":[],"functions":[{
        "name":"f","params":[],"returns":[],"effects":[],"entry":"entry",
        "blocks":[{"id":"entry","params":[],"ops":[{
            "op":"const","args":[],"out":[{"name":"v","type":"u8"}],
            "attrs":{"value":0,"padding":padding}}],
            "term":{"op":"ret","values":[]}}]}]}

def plan(ns,group):
    assert group in GROUPS and not ns["PLAN"]
    reference=Path(ns["REF"])
    for relative,expected in (
        ("hepta/hia_program.py",REFERENCE_PROGRAM_SHA),
        ("hepta/hia_program_composite.py",REFERENCE_COMPOSITE_SHA)):
        assert sha256(ns["pin"](reference/relative)).hexdigest()==expected
    from hepta.hia_program import _decode,verify_program,HIAProgramRejected
    from hepta.hia_program_composite import elaborate_program
    evidence=[]
    def trace(raw):
        try:verify_program(raw)
        except HIAProgramRejected as exc:
            return {"code":exc.code,"text":str(exc),
                    "frames":[{"file":frame.filename,"function":frame.name,"line":frame.lineno}
                              for frame in traceback.extract_tb(exc.__traceback__)]}
        raise AssertionError("late-boundary negative fixture was accepted")
    def measured(label,value,dimension,target,expected_late):
        raw=ns["transport"](value)
        # Actual original public input decoding must succeed before measuring
        # an elaborated candidate. This prevents a preflight refusal from
        # impersonating a later Core failure.
        decoded,decoded_raw=_decode(raw)
        assert len(raw)<=BYTES and stats(decoded)["nodes"]<=NODES
        assert stats(decoded)["depth"]<=64 and decoded_raw==canonical(decoded)
        core=elaborate_program(decoded)
        core_raw=canonical(core)
        before,after=stats(decoded),stats(core)
        actual_extent=after["nodes"] if dimension=="nodes" else len(core_raw)
        assert actual_extent==target,(label,actual_extent,target)
        assert "types" not in core and core["exports"]==["f"]
        assert before["nodes"]+1==after["nodes"]
        assert len(core_raw)==len(decoded_raw)+3
        assert after["depth"]==before["depth"]
        public=trace(raw)
        if expected_late==2:
            assert public["text"]=="E_HIA_LIMIT: caller-owned tree exceeds queued-node budget"
            assert any(row["function"]=="_bounded_detached_snapshot" for row in public["frames"])
        elif expected_late==3:
            assert public["text"]=="E_HIA_LIMIT: program exceeds byte budget before encoding"
            assert any(row["function"]=="_structure" for row in public["frames"])
        else:
            # The deliberately extra primitive attrs field is checked only
            # after the complete late snapshot/byte gates have accepted.
            assert public["code"]!="E_HIA_LIMIT",public
            assert not any(row["function"] in ("_bounded_detached_snapshot","_structure")
                           for row in public["frames"]),public
        ns["add"](label,1,raw,raw=True,accept=False)
        assert ns["PLAN"][-1]["expected"]["payload"]==public["text"].encode("utf-8")
        evidence.append({"label":label,"original_public_trace":public,
            "source":ns["cas"](raw),"canonical_source":ns["cas"](decoded_raw),
            "actual_original_elaborated_Core":ns["cas"](core_raw),
            "source_stats":before,"Core_stats":after,
            "source_bytes":len(raw),"canonical_source_bytes":len(decoded_raw),
            "Core_bytes":len(core_raw),"expected_actual_late_status":expected_late,
            "ordinary_legacy_importer_not_invoked":True,
            "all_original_semantics_finished_before_native_interval":True})
    if group.startswith("late-node-"):
        target=NODES+{"below":-1,"equal":0,"over":1}[group.rsplit("-",1)[1]]
        seed=fixture([])
        decoded,_=_decode(ns["transport"](seed))
        base=stats(elaborate_program(decoded))["nodes"]
        assert 0<base<target
        measured(group,fixture([0]*(target-base)),"nodes",target,2 if target>NODES else 0)
    elif group.startswith("late-byte-"):
        target=BYTES+{"below":-1,"equal":0,"over":1}[group.rsplit("-",1)[1]]
        seed=fixture("")
        decoded,_=_decode(ns["transport"](seed))
        base=len(canonical(elaborate_program(decoded)))
        assert 0<base<target
        measured(group,fixture("x"*(target-base)),"bytes",target,3 if target>BYTES else 0)
    else:
        seed=fixture(0);base_depth=stats(seed)["depth"]
        padding_path=("functions",0,"blocks",0,"ops",0,"attrs","padding")
        cursor=seed
        for key in padding_path:cursor=cursor[key]
        assert cursor==0 and base_depth<64
        padding_depth=len(padding_path)
        for wanted in (64,65):
            padding=0
            for _ in range(wanted-padding_depth):padding=[padding]
            value=fixture(padding);raw=ns["transport"](value)
            assert stats(value)["depth"]==wanted
            public=trace(raw)
            if wanted==64:
                decoded,_=_decode(raw)
                core=elaborate_program(decoded)
                assert stats(core)["depth"]==64
                assert public["code"]!="E_HIA_LIMIT"
            else:
                assert public["text"]=="E_HIA_LIMIT: program exceeds structural budget before JSON allocation"
            ns["add"]("source-depth-"+str(wanted),1,raw,raw=True,accept=False)
            evidence.append({"label":"source-depth-"+str(wanted),"source":ns["cas"](raw),
                "original_public_trace":public,"source_stats":stats(value),
                "scope":"INPUT_DEPTH_ACCEPT_OR_REFUSE_NOT_PUBLIC_LATE_DEPTH_STATUS1"})
        value=fixture([]);value["module"]="9bad"
        ns["add"]("module-first-before-payload",1,value,accept=False)
        assert ns["PLAN"][-1]["expected"]["payload"]==b"E_HIA_NAME: module: invalid/reserved ASCII identifier"
        evidence.append({"label":"module-first-before-payload","source":ns["cas"](ns["PLAN"][-1]["source"]),
            "scope":"EARLIER_ACTUAL_CONSTRUCTOR_REFUSAL"})
        value=fixture([]);value["types"]=[{"name":"9bad","kind":"record","params":[],"fields":[]}]
        ns["add"]("type-context-before-payload",1,value,accept=False)
        assert ns["PLAN"][-1]["expected"]["payload"]==b"E_HIA_NAME: nominal type: invalid/reserved ASCII identifier"
        evidence.append({"label":"type-context-before-payload","source":ns["cas"](ns["PLAN"][-1]["source"]),
            "scope":"EARLIER_ACTUAL_TYPE_CONTEXT_REFUSAL"})
    assert len(ns["PLAN"])==GROUPS[group]
    ns["save"](ns["OUT"]/"original-late-Core-fixture-evidence.json",{
        "schema":"hia-original-public-late-Core-fixtures-r1","group":group,
        "cases":evidence,"planned_actual_public_ELF_processes":GROUPS[group],
        "actual_native_calls_in_this_preparation":0,
        "public_depth_status1_reachability_not_claimed":True,
        "private_force_status_is_not_a_public_fixture":True,
        "expected_full_payloads_from_original_verify_program":True})
