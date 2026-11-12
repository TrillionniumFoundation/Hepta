"""Exact explicit nominal importer group9 diagnostics continuation.

NEW SOURCE ONLY: not AST checked, generated, compiled or executed.
This extends only the historical explicit importer, never ordinary P16.
The original projection, old-Core admission, independent target admission,
complete comparison, hash/report and child-failure paths are retained.
A fixed executor must keep the actual private importer context and expose
the new readonly diagnostic slot; recognizing these bytes is not authority.
"""
from __future__ import annotations
import ast,copy,types
from hashlib import sha256

OWNER_SHA="53cdf4ce01c8f14ab4894062fdc321a124f0b2ed16e39e284876d7eb37f9968c"
LOWER_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
REFERENCE_UPGRADE_SHA="550608c7b654c0af45cda8f122230188c1989069fda2dac4e05c285f7ce77570"
REFERENCE_PROGRAM_SHA="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
MESSAGES={
 1:"E_HIA_FORMAT: legacy nominal program: expected exactly functions, module, schema, types",
 2:"E_HIA_VERSION_COLLISION: explicit nominal-v2 adapter requires nominal-v2 input",
 3:"E_HIA_LIMIT: program exceeds byte budget before encoding",
 4:"E_HIA_UPGRADE: nominal adapter changed primitive operations/CFG/effects",
}
CONSTANTS={
 "LG_DIAGNOSTIC":int.from_bytes(b"HIALDE01","little"),
 "LG_SLOT":57,"LG_ERROR":25000,"LG_TEXT_BYTES":25008,
 "LG_FRAME_BYTES":25016,"LG_SEQUENCE":25024,"LG_STATE":25032,
 "LG_ORIGINAL_PHASE":25040,
}
BEGIN_ANCHOR="""    phase = get(w, C_PHASE)
    if phase == 1:
"""
BEGIN_REPLACEMENT="""    phase = get(w, C_PHASE)
    if phase >= 90000 and phase < 90100:
        return legacy_group9_step(o, w, phase)
    if phase == 1:
"""
REPLACEMENTS=(
 (BEGIN_ANCHOR,BEGIN_REPLACEMENT),
 ("return finish(o, w, 9, error, 0)","return legacy_group9_begin(w, error)"),
 ("return finish(o, w, 9, 3, 0)","return legacy_group9_begin(w, 3)"),
 ("return finish(o, w, 9, 4, 0)","return legacy_group9_begin(w, 4)"),
)
BODY=r"""
def legacy_group9_begin(w:mutbuf,error:u64)->u64:
    if get(w,L_STATUS) != 1 or get(w,C_PENDING) != 0 or get(w,LG_STATE) != 0:
        return refuse(w,12800)
    if get(w,C_MAGIC) != IMPORT_STATE or get(w,L_DRIVER) != IMPORT_DRIVER:
        return refuse(w,12801)
    if cap(w,LG_SLOT) != 0 or error < 1 or error > 4:
        return refuse(w,12802)
    phase = get(w,C_PHASE)
    if error <= 2:
        if phase != 5:
            return refuse(w,12803)
    elif error == 3:
        if phase != 28:
            return refuse(w,12804)
    elif phase != 31:
        return refuse(w,12805)
    size = legacy_group9_length(error)
    if size == 0 or size > 192:
        return refuse(w,12806)
    put(w,LG_ERROR,error)
    put(w,LG_TEXT_BYTES,size)
    put(w,LG_FRAME_BYTES,64+size)
    put(w,LG_ORIGINAL_PHASE,phase)
    put(w,LG_STATE,1)
    put(w,C_PHASE,90000)
    return 0

def legacy_group9_step(o:mutbuf,w:mutbuf,phase:u64)->u64:
    error = get(w,LG_ERROR)
    size = get(w,LG_TEXT_BYTES)
    if get(w,LG_STATE) != 1 or get(w,C_MAGIC) != IMPORT_STATE or get(w,L_DRIVER) != IMPORT_DRIVER:
        return refuse(w,12810)
    if error < 1 or error > 4 or size != legacy_group9_length(error) or get(w,LG_FRAME_BYTES) != 64+size:
        return refuse(w,12811)
    if phase == 90000:
        if cap(w,LG_SLOT) != 0:
            return refuse(w,12812)
        return grow(o,w,LG_SLOT,get(w,LG_FRAME_BYTES),90001)
    if phase == 90001:
        if cap(w,LG_SLOT) != get(w,LG_FRAME_BYTES) or get(w,C_SEQUENCE) > MAX-2:
            return refuse(w,12813)
        # Only COPY and PROTECT issue later events. Original finish preserves
        # C_SEQUENCE rather than incrementing it.
        put(w,LG_SEQUENCE,get(w,C_SEQUENCE)+2)
        zero(w,WIRE,64)
        put(w,WIRE,LG_DIAGNOSTIC)
        put(w,WIRE+8,1)
        put(w,WIRE+16,9)
        put(w,WIRE+24,error)
        put(w,WIRE+32,get(w,C_LEASE))
        put(w,WIRE+40,get(w,LG_SEQUENCE))
        put(w,WIRE+48,get(w,LG_FRAME_BYTES))
        put(w,WIRE+56,size)
        if legacy_group9_message(w,error) != size:
            return refuse(w,12814)
        return copy(o,w,B_CONTROLLER,WIRE,LG_SLOT,0,get(w,LG_FRAME_BYTES),90002)
    if phase == 90002:
        return protect(o,w,LG_SLOT,1,90003)
    if phase == 90003:
        if cap(w,LG_SLOT) != get(w,LG_FRAME_BYTES) or get(w,C_SEQUENCE) != get(w,LG_SEQUENCE):
            return refuse(w,12815)
        put(w,LG_STATE,2)
        return finish(o,w,9,error,0)
    return refuse(w,12816)

def legacy_group9_message(w:mutbuf,error:u64)->u64:
    if error == 1:
        return legacy_group9_literal_1(w)
    if error == 2:
        return legacy_group9_literal_2(w)
    if error == 3:
        return legacy_group9_literal_3(w)
    if error == 4:
        return legacy_group9_literal_4(w)
    return 0
"""

def literal_functions():
    result="\ndef legacy_group9_length(error:u64)->u64:\n"
    for error,message in MESSAGES.items():
        raw=message.encode("utf-8")
        assert 0<len(raw)<=192
        result+=f"    if error == {error}:\n        return {len(raw)}\n"
    result+="    return 0\n"
    for error,message in MESSAGES.items():
        raw=message.encode("utf-8")
        result+=f"\ndef legacy_group9_literal_{error}(w:mutbuf)->u64:\n"
        full=(len(raw)//8)*8
        for offset in range(0,full,8):
            value=int.from_bytes(raw[offset:offset+8],"little")
            result+=f"    put(w,WIRE+{64+offset},{value})\n"
        for offset in range(full,len(raw)):
            result+=f"    store(w,WIRE+{64+offset},{raw[offset]})\n"
        result+=f"    return {len(raw)}\n"
    return result

def literal_assignment(raw,name):
    matches=[]
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id==name for target in node.targets):
            matches.append(ast.literal_eval(node.value))
    assert len(matches)==1,name
    return matches[0]

def function_map(source):
    body=ast.parse(source).body
    assert all(isinstance(node,ast.FunctionDef) for node in body)
    result={node.name:node for node in body}
    assert len(result)==len(body)
    return result

def extend(legacy,owner_raw,lower_raw,upgrade_raw,program_raw):
    """Author a separate image46; do not change a frozen module or namespace."""
    for raw,expected in ((owner_raw,OWNER_SHA),(lower_raw,LOWER_SHA),
            (upgrade_raw,REFERENCE_UPGRADE_SHA),(program_raw,REFERENCE_PROGRAM_SHA)):
        assert sha256(raw).hexdigest()==expected,(expected,sha256(raw).hexdigest())
    original_body=literal_assignment(owner_raw,"BODY")
    original_common=literal_assignment(lower_raw,"COMMON")
    assert legacy.BODY==original_body and legacy.COMMON==original_common
    assert legacy.CONSTANTS["IMPORT_DRIVER"]==46
    assert legacy.CONSTANTS["B_RESPONSE"]==45
    assert legacy.CONSTANTS["B_OLD_CORE"]==54 and legacy.CONSTANTS["B_NEW_CORE"]==55
    assert legacy.CONSTANTS["B_COMPARE"]==56 and legacy.CONSTANTS["M_TARGET_HASH"]+32<=CONSTANTS["LG_ERROR"]
    assert legacy.CONSTANTS["WIRE"]+256<=legacy.CONSTANTS["CAPS"]
    assert CONSTANTS["LG_ORIGINAL_PHASE"]+8<=legacy.CONSTANTS["MIN_WORK"]
    assert not (set(CONSTANTS)&set(legacy.CONSTANTS))
    before=legacy.source_program()
    changed=original_body
    inverse=[]
    for old,new in REPLACEMENTS:
        assert changed.count(old)==1,(old,changed.count(old))
        changed=changed.replace(old,new,1)
        inverse.append((old,new))
    restored=changed
    for old,new in reversed(inverse):
        assert restored.count(new)==1,new
        restored=restored.replace(new,old,1)
    assert restored==original_body
    # This exact owner calls source(BODY + literals + SERVICES + COMMON).
    # Rebind just its two globals in a copied development authoring namespace.
    namespace=dict(legacy.source_program.__globals__)
    namespace["CONSTANTS"]=dict(legacy.CONSTANTS,**CONSTANTS)
    namespace["BODY"]=changed+BODY+literal_functions()
    fn=legacy.source_program
    authored=types.FunctionType(fn.__code__,namespace,fn.__name__,fn.__defaults__,fn.__closure__)
    result=authored()
    assert legacy.BODY==original_body and legacy.COMMON==original_common
    assert legacy.source_program()==before
    old_functions=function_map(before);new_functions=function_map(result)
    untouched=set(old_functions)-{"import_step"}
    assert untouched<=set(new_functions)
    assert all(ast.dump(old_functions[name],include_attributes=False)==
               ast.dump(new_functions[name],include_attributes=False) for name in untouched)
    additions=set(new_functions)-set(old_functions)
    assert additions=={"legacy_group9_begin","legacy_group9_step","legacy_group9_message",
        "legacy_group9_length","legacy_group9_literal_1","legacy_group9_literal_2",
        "legacy_group9_literal_3","legacy_group9_literal_4"}
    proof=dict(schema="hia-explicit-legacy-group9-continuation-authoring-r1",
        status="AUTHORING_ONLY_NOT_NATIVE_QUALIFIED",original_owner_sha256=OWNER_SHA,
        original_source_sha256=sha256(before.encode()).hexdigest(),
        new_source_sha256=sha256(result.encode()).hexdigest(),
        body_four_unique_replacements_exact_inverse=True,
        unchanged_functions=sorted(untouched),added_functions=sorted(additions),
        original_finish_and_all_other_terminal_fields_unchanged=True,
        final_sequence_changes_only_by_new_real_mechanical_events=True,
        diagnostic_slot=57,diagnostic_magic="HIALDE01",header_bytes=64,
        complete_message_bytes={str(k):len(v.encode()) for k,v in MESSAGES.items()},
        original_semantic_error_points={"1":[5],"2":[5],"3":[28],"4":[31]},
        code4_public_reachability_not_claimed=True,
        actual_executor_integration_pending_exact_original_archive=True,
        ordinary_P16_unchanged=True,installed=False,whole_Worker_closed=False)
    return result,proof
