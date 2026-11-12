"""Reference-only explicit nominal importer public plans.

New unexecuted fixture author. All original Python semantics must finish
before the actual native interval. No expected error is obtained from a
native enum table, private terminal or newly written diagnostic formatter.
The large valid-source witness uses unused, individually valid enum fields;
an illegal primitive attrs padding field would fail the old Core first.
"""
from __future__ import annotations
import json,traceback
from hashlib import sha256
from pathlib import Path

PINS={
 "hepta/hia_core_upgrade.py":"550608c7b654c0af45cda8f122230188c1989069fda2dac4e05c285f7ce77570",
 "hepta/hia_program.py":"76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92",
 "hepta/hia_program_composite.py":"cc5ab4c8dc68214e8868aab30405820c3662572de63952dec5f1fd1aaf180951",
}
BYTES=8388608
NODES=262144
GROUPS={"exact-fields":9,"wrong-profile":7,"accepted-small":3,
        "renamed-byte-equal":1,"renamed-byte-over-one":1,"renamed-byte-over-two":1}

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")

def base():
    return {"schema":"hepta.hia.program.v2","module":"legacy_diagnostic",
        "types":[],"functions":[{"name":"f","params":[],"returns":[],"effects":[],
        "entry":"entry","blocks":[{"id":"entry","params":[],"ops":[],
                                  "term":{"op":"ret","values":[]}}]}]}

def stats(value):
    pending=[(value,0)];count=0;depth=0
    while pending:
        current,level=pending.pop();count+=1;depth=max(depth,level)
        if type(current) is dict:
            assert all(type(key) is str for key in current)
            pending.extend((child,level+1) for child in current.values())
        elif type(current) is list:
            pending.extend((child,level+1) for child in current)
        else:assert type(current) in (str,int,bool,type(None))
    return dict(nodes=count,depth=depth)

def valid_large_source(target):
    assert target in (BYTES-2,BYTES-1,BYTES)
    value=base();all_fields=[]
    for index in range(28):
        variants=[]
        for variant_index in range(32):
            fields=[{"name":"f"+format(i,"02d"),"type":"u8"} for i in range(64)]
            all_fields.extend(fields)
            variants.append({"name":"V"+format(variant_index,"02d"),"fields":fields})
        value["types"].append({"name":"E"+format(index,"02d"),
            "params":[],"kind":"enum","variants":variants})
    start=len(canonical(value));remaining=target-start
    assert 0<remaining<=125*len(all_fields),(start,target,len(all_fields))
    for field in all_fields:
        extra=min(125,remaining)
        field["name"]+="x"*extra
        remaining-=extra
    assert remaining==0
    raw=canonical(value);measured=stats(value)
    assert len(raw)==target and measured["nodes"]<=NODES and measured["depth"]<=64
    assert len(value["types"])==28 and len(all_fields)==28*32*64
    assert all(len(item["variants"])==32 and not item["params"] for item in value["types"])
    for item in value["types"]:
        for variant in item["variants"]:
            fields=variant["fields"]
            assert len(fields)==64 and len({field["name"] for field in fields})==64
            assert all(3<=len(field["name"])<=128 and field["type"]=="u8" for field in fields)
    return raw,measured

def prepare(reference,group,pin):
    assert group in GROUPS
    reference=Path(reference)
    for relative,expected in PINS.items():
        assert sha256(pin(reference/relative)).hexdigest()==expected,relative
    from hepta.hia_core_upgrade import import_legacy_composite_v2
    from hepta.hia_program import HIAProgramRejected,_decode,verify_program
    from hepta.hia_program_composite import elaborate_program
    plans=[];evidence=[]
    def add(label,value,*,raw=False,code=None,contains=None,accept=False):
        source=bytes(value) if raw else canonical(value)
        assert len(source)<=BYTES
        try:
            verified,report=import_legacy_composite_v2(source)
        except HIAProgramRejected as exc:
            assert not accept,(label,exc)
            full=str(exc)
            if code is not None:assert exc.code==code,(label,exc.code,full)
            if contains is not None:assert contains in full,(label,full)
            expected=dict(kind="rejection",code=exc.code,text=full.encode("utf-8"))
            frames=[dict(file=frame.filename,function=frame.name,line=frame.lineno)
                for frame in traceback.extract_tb(exc.__traceback__)]
        else:
            assert accept,(label,"unexpected original acceptance")
            assert verified.structured_bytes is not None
            core=verified.canonical_bytes;structured=verified.structured_bytes
            report_bytes=canonical(report)
            # The exact historical native success body has these three keys.
            combined=canonical({"core":json.loads(core),"report":report,
                                "structured":json.loads(structured)})
            expected=dict(kind="success",Core=core,structured=structured,
                          report=report_bytes,combined=combined)
            frames=[]
        plans.append(dict(label=label,source=source,expected=expected))
        evidence.append(dict(label=label,source_bytes=len(source),
            source_sha256=sha256(source).hexdigest(),original_public_trace=frames,
            expected_kind=expected["kind"],expected_code=expected.get("code"),
            expected_text_sha256=(sha256(expected["text"]).hexdigest()
                                  if expected["kind"]=="rejection" else None),
            exact_original_public_importer_called=True,
            reference_finished_before_native_interval=True))
    if group=="exact-fields":
        add("empty-dict",{},code="E_HIA_FORMAT",contains="legacy nominal program: expected exactly")
        for field in ("schema","module","types","functions"):
            value=base();del value[field]
            add("missing-"+field,value,code="E_HIA_FORMAT",contains="legacy nominal program: expected exactly")
        value=base();value["schema"]="wrong";value["extra"]=0
        add("extra-before-profile",value,code="E_HIA_FORMAT",contains="legacy nominal program: expected exactly")
        for label,value in (("root-list",[]),("root-null",None),("root-string","x")):
            add(label,value,code="E_HIA_FORMAT",contains="legacy nominal program: expected exactly")
    elif group=="wrong-profile":
        for label,schema in (("primitive-v1","hepta.hia.program.v1"),
            ("structured-v1","hepta.hia.composite.v1"),("empty",""),
            ("integer",1),("null",None),("list",[]),("map",{})):
            value=base();value["schema"]=schema;value["types"]=False;value["functions"]=None
            add(label,value,code="E_HIA_VERSION_COLLISION",
                contains="explicit nominal-v2 adapter requires nominal-v2 input")
    elif group=="accepted-small":
        add("minimal-legacy",base(),accept=True)
        value=base();value["types"]=[{"name":"Unused","params":[],"kind":"record",
                                     "fields":[{"name":"field","type":"u8"}]}]
        add("unused-record",value,accept=True)
        value=base();value["types"]=[{"name":"Unused","params":[],"kind":"enum",
            "variants":[{"name":"Yes","fields":[{"name":"field","type":"u8"}]},
                        {"name":"No","fields":[]}]}]
        add("unused-enum",value,accept=True)
    else:
        excess={"renamed-byte-equal":0,"renamed-byte-over-one":1,
                "renamed-byte-over-two":2}[group]
        raw,measured=valid_large_source(BYTES-2+excess)
        decoded,canonical_source=_decode(raw)
        assert canonical_source==raw
        renamed=dict(decoded);renamed["schema"]="hepta.hia.composite.v1"
        renamed_bytes=canonical(renamed)
        assert len(renamed_bytes)==len(raw)+2==BYTES+excess
        # Prove the entire old primitive gate succeeds, before claiming the
        # renamed target's snapshot-byte refusal is publicly reachable.
        old_payload=elaborate_program(renamed,legacy=True)
        old_payload["schema"]="hepta.hia.program.v1"
        old_core=verify_program(old_payload)
        assert canonical(decoded)==raw
        assert len(old_core.canonical_bytes)<4096
        if excess==0:
            add(group,raw,raw=True,accept=True)
        else:
            add(group,raw,raw=True,code="E_HIA_LIMIT",
                contains="program exceeds byte budget before encoding")
            assert plans[-1]["expected"]["text"]==b"E_HIA_LIMIT: program exceeds byte budget before encoding"
            frames=evidence[-1]["original_public_trace"]
            assert any(frame["function"]=="import_legacy_composite_v2" for frame in frames)
            assert any(frame["function"]=="_structure" for frame in frames)
        evidence[-1].update(original_source_stats=measured,
            original_canonical_bytes=len(raw),renamed_canonical_bytes=len(renamed_bytes),
            unused_type_count=28,variants_per_type=32,fields_per_variant=64,
            full_old_primitive_gate_passed_before_public_original_call=True,
            old_Core_bytes=len(old_core.canonical_bytes),
            old_Core_sha256=sha256(old_core.canonical_bytes).hexdigest(),
            renamed_source_sha256=sha256(renamed_bytes).hexdigest(),
            no_illegal_primitive_padding_field_used=True)
    assert len(plans)==GROUPS[group]
    assert all(sha256(pin(reference/relative)).hexdigest()==expected for relative,expected in PINS.items())
    return plans,dict(schema="hia-explicit-legacy-public-original-plans-r1",
        group=group,planned_cases=len(plans),evidence=evidence,
        code4_public_reachability_claimed=False,
        expected_error_text_from_native_catalog=False,
        actual_native_calls_during_preparation=0,
        original_caps_unchanged=dict(input_bytes=BYTES,nodes=NODES,depth=64,
            definitions=128,variants=32,fields=64,identifier_bytes=128))
