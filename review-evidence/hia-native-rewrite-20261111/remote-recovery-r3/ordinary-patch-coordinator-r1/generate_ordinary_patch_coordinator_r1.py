"""Actual ordinary patch native coordinator.

The HIA continuation owns original base admission, request decoding, preparation,
the dict-snapshot prefix, fresh candidate admission, interface policy and receipt.
The fixed executor transports bytes and actual native calls only. This source is
new and unqualified until the independent fixed-executable differential passes.
"""
from __future__ import annotations
import ast
from pathlib import Path
import program_service_root_reference as base

def magic(value):return int.from_bytes(value.encode("ascii"),"little")
CONSTANTS=dict(base.CONSTANTS)
CONSTANTS.update(EDIT_JSON_INIT=magic("HIAEJI01"),ORDINARY_STATE=magic("HIAOPS01"),
    PREPARE_EVENT=magic("HIAPPE01"),OBJECT_EVENT=magic("HIAOPE01"),
    RECEIPT_EVENT=magic("HIAPRC01"),NEED=0xfffffffe,
    O_INPUT_HASH=36400,O_SUFFIX=36500)
FIELDS=("MAGIC","ADMISSION","SOURCE","CORE_SLOT","BASE_BYTES","NEW_BYTES","REQUEST",
 "RELEASE","ENVELOPE_BYTES","CANDIDATE_BYTES","PREFIX_BYTES","VERSION","POLICY",
 "EDITS","NEED_OUTPUT","NEED_WORK","SUFFIX_BYTES","RECEIPT_BYTES")
CONSTANTS.update({"O_"+name:36000+i*8 for i,name in enumerate(FIELDS)})
BODY=r'''
def ordinary_patch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 6000)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if ordinary_begin(s, w) == 0:
            return refuse(w, 6001)
    elif get(w, C_MAGIC) != EDIT_STATE or get(w, O_MAGIC) != ORDINARY_STATE or acknowledge(s, w, MAIN) == 0:
        return refuse(w, 6002)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 45000 and phase < 45100:
            result = edit_publish_step(o, w)
        elif phase >= 1 and phase < 20:
            result = ordinary_admission_step(o, w)
        elif phase >= 20 and phase < 30:
            result = ordinary_request_step(o, w)
        elif phase >= 30 and phase < 50:
            result = ordinary_prepare_step(o, w)
        elif phase >= 50 and phase < 90:
            result = ordinary_object_step(o, w)
        elif phase >= 90 and phase < 120:
            result = ordinary_receipt_step(o, w)
        else:
            return refuse(w, 6003)
        if result != 0:
            return result
    return refuse(w, 6004)

def ordinary_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != EDIT_JSON_INIT or word(s, 56) != 0:
        return 0
    lease = word(s, 8)
    digits = word(s, 24)
    if lease == 0 or lease > MAX - 5 or word(s, 16) != 1:
        return 0
    if digits > 4294967295 or (digits != 0 and digits < 640):
        return 0
    if word(s, 32) != cap(w, B_PROGRAM) or word(s, 40) != cap(w, B_QUERY_GRAPH):
        return 0
    if word(s, 48) != 0 or cap(w, B_RESPONSE_GRAPH) != 0:
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != MIN_WORK:
        return 0
    slot = 3
    while slot < 64:
        if slot != B_QUERY_GRAPH and cap(w, slot) != 0:
            return 0
        slot = slot + 1
    at = 0
    while at < MIN_WORK:
        if at < CAPS or at >= CAPS + 512:
            if byte(w, at) != 0:
                return 0
        at = at + 1
    put(w, C_MAGIC, EDIT_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, MAIN)
    put(w, O_MAGIC, ORDINARY_STATE)
    put(w, O_ADMISSION, 0)
    put(w, O_SOURCE, B_PROGRAM)
    put(w, O_CORE_SLOT, B_CORE)
    put(w, E_MODE, 1)
    put(w, E_DIGITS, digits)
    put(w, E_REQUEST, 1)
    put(w, C_PHASE, 1)
    return 1

def ordinary_program_child(o:mutbuf, w:mutbuf, next:u64) -> u32:
    if cap(w, B_PROGRAM_FRAME) != 0 or get(w, C_LEASE) > MAX - 5:
        return refuse(w, 6010)
    generation = get(w, O_ADMISSION)
    source = get(w, O_SOURCE)
    if generation > 1:
        return refuse(w, 6011)
    if (generation == 0 and source != B_PROGRAM) or (generation == 1 and source != 25):
        return refuse(w, 6012)
    put(w, E_CHILD_LEASE, get(w, C_LEASE) + 1 + generation * 2)
    put(w, E_CHILD_TARGET, B_PROGRAM_FRAME)
    put(w, C_OBSERVE, 160)
    args(w, 2, source, 0, minimum(cap(w, source), INPUT_LIMIT + 1), B_PROGRAM_FRAME, get(w, E_CHILD_LEASE), get(w, E_DIGITS), 0, 0, 0, 0, 0)
    return event(o, w, 15, next)

def ordinary_admission_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1:
        return ordinary_program_child(o, w, 2)
    if phase == 2:
        state = program_child_frame(w)
        if state == 0:
            return refuse(w, 6013)
        if state == 2:
            return prefix_failure(w)
        if state == 3:
            return view(o, w, B_PROGRAM_FRAME, 0, 64, 15)
        return view(o, w, B_PROGRAM_FRAME, 0, 256, 3)
    if phase == 3:
        if program_receipt_header(w) == 0:
            return refuse(w, 6014)
        if get(w, O_ADMISSION) == 1 and (get(w, E_KIND) != 0 or get(w, E_INPUT_BYTES) != get(w, O_PREFIX_BYTES)):
            return refuse(w, 6015)
        return grow(o, w, get(w, O_CORE_SLOT), get(w, E_CORE_BYTES), 4)
    if phase == 4:
        return copy(o, w, B_PROGRAM_FRAME, 256, get(w, O_CORE_SLOT), 0, get(w, E_CORE_BYTES), 5)
    if phase == 5:
        return protect(o, w, get(w, O_CORE_SLOT), 1, 6)
    if phase == 6:
        return hash_start(w, get(w, O_CORE_SLOT), get(w, E_CORE_BYTES), E_ACTUAL_CORE_HASH, 7)
    if phase == 7:
        if same_digest(w, E_ACTUAL_CORE_HASH, E_CORE_HASH) == 0:
            return refuse(w, 6016)
        if get(w, O_ADMISSION) == 0:
            put(w, O_BASE_BYTES, get(w, E_CORE_BYTES))
            copy_digest(w, O_INPUT_HASH, E_INPUT_HASH)
        else:
            put(w, O_NEW_BYTES, get(w, E_CORE_BYTES))
        return release(o, w, B_PROGRAM_FRAME, 8)
    if phase == 8:
        if get(w, O_ADMISSION) == 0:
            put(w, C_PHASE, 20)
            return 0
        return release(o, w, 25, 90)
    if phase == 15:
        if get(w, OBS) != CORE_DIAGNOSTIC or get(w, OBS + 8) != 1:
            return refuse(w, 6017)
        if get(w, OBS + 16) != get(w, E_ERROR_CODE) or get(w, OBS + 24) == 0 or get(w, OBS + 24) > 92:
            return refuse(w, 6018)
        if get(w, OBS + 40) != get(w, E_ERROR_BYTES) or get(w, OBS + 32) != get(w, E_ERROR_BYTES) - 64:
            return refuse(w, 6019)
        if get(w, OBS + 48) == 0 or get(w, OBS + 48) > NODES or get(w, OBS + 56) != 0:
            return refuse(w, 6020)
        return edit_error_start(w, 2, 8, get(w, E_ERROR_CODE), B_PROGRAM_FRAME, 64, get(w, OBS + 32))
    return refuse(w, 6021)

def ordinary_request_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 20:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        put(w, O_REQUEST, request)
        wire8(w, DECODE_COMMAND, 41, request, 9, get(w, E_DIGITS), 0, 0, 0)
        result = edit_service_start(w, 2, B_QUERY_GRAPH, 0, cap(w, B_QUERY_GRAPH), B_CONTROLLER, WIRE, 64, 512, MAIN, 21)
        if result != 0:
            return result
        return switch(o, w, SERVICE, 50000)
    if phase == 21:
        if get(w, S_STATE) != 2 or get(w, S_KIND) != 2 or get(w, S_RESULT_CODE) != 128 or get(w, S_RESULT_EVENT_BYTES) != 128:
            return refuse(w, 6030)
        if get(w, S_RESULT_EVENT) != DECODE_EVENT or get(w, S_RESULT_EVENT + 16) != 41 or get(w, S_RESULT_EVENT + 24) != get(w, O_REQUEST):
            return refuse(w, 6031)
        if cap(w, get(w, S_RESULT_SLOT)) != get(w, S_RESULT_BYTES):
            return refuse(w, 6032)
        offset = get(w, S_RESULT_EVENT + 112)
        size = get(w, S_RESULT_EVENT + 120)
        error = get(w, S_RESULT_EVENT + 104)
        if inside(w, get(w, S_RESULT_SLOT), offset, size) == 0:
            return refuse(w, 6033)
        action = get(w, S_RESULT_EVENT + 8)
        if action == 3:
            if error == 0 or error == ABI or size == 0:
                return refuse(w, 6034)
            return edit_error_start(w, 1, 31, error, get(w, S_RESULT_SLOT), offset, size)
        if action != 0 or error != 0 or size < 128 or cap(w, B_QUERY_GRAPH) > INPUT_LIMIT:
            return refuse(w, 6035)
        put(w, O_RELEASE, 32)
        put(w, C_PHASE, 22)
        return 0
    if phase == 22:
        slot = get(w, O_RELEASE)
        if slot < 50:
            put(w, O_RELEASE, slot + 1)
            return release(o, w, slot, 22)
        put(w, S_STATE, 0)
        put(w, C_PHASE, 30)
        return 0
    return refuse(w, 6036)

def ordinary_leaf_header(w:mutbuf, magic:u64, output:u64, work:u64, zero_from:u64) -> u64:
    if get(w, OBS) != magic or get(w, OBS + 8) != 1 or get(w, OBS + 48) != 128:
        return 0
    action = get(w, OBS + 16)
    if action > 2:
        return 0
    at = zero_from
    while at < 128:
        if get(w, OBS + at) != 0:
            return 0
        at = at + 8
    need_o = get(w, OBS + 32)
    need_w = get(w, OBS + 40)
    if need_o < 128 or need_w < 128 or need_o > 4294967295 or need_w > 4294967295:
        return 0
    if action == 1:
        if get(w, C_RETURN) != NEED or get(w, OBS + 24) != 0 or get(w, OBS + 56) != 0:
            return 0
        if need_o <= cap(w, output) and need_w <= cap(w, work):
            return 0
        put(w, O_NEED_OUTPUT, need_o)
        put(w, O_NEED_WORK, need_w)
    else:
        if get(w, C_RETURN) != 128 or need_o > cap(w, output) or need_w > cap(w, work):
            return 0
        if inside(w, output, 128, get(w, OBS + 56)) == 0:
            return 0
    return 1

def ordinary_prepare_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 30:
        size = get(w, O_BASE_BYTES) + cap(w, B_QUERY_GRAPH) + 3
        if get(w, O_BASE_BYTES) == 0 or get(w, O_BASE_BYTES) > INPUT_LIMIT or cap(w, B_QUERY_GRAPH) > INPUT_LIMIT or size > 16777219:
            return refuse(w, 6040)
        put(w, O_ENVELOPE_BYTES, size)
        return grow(o, w, 20, size, 31)
    if phase == 31:
        store(w, WIRE, 91)
        store(w, WIRE + 1, 44)
        store(w, WIRE + 2, 93)
        return copy(o, w, B_CONTROLLER, WIRE, 20, 0, 1, 32)
    if phase == 32:
        return copy(o, w, B_CORE, 0, 20, 1, get(w, O_BASE_BYTES), 33)
    if phase == 33:
        return copy(o, w, B_CONTROLLER, WIRE + 1, 20, 1 + get(w, O_BASE_BYTES), 1, 34)
    if phase == 34:
        return copy(o, w, B_QUERY_GRAPH, 0, 20, 2 + get(w, O_BASE_BYTES), cap(w, B_QUERY_GRAPH), 35)
    if phase == 35:
        return copy(o, w, B_CONTROLLER, WIRE + 2, 20, get(w, O_ENVELOPE_BYTES) - 1, 1, 36)
    if phase == 36:
        return protect(o, w, 20, 1, 37)
    if phase == 37:
        return grow(o, w, 21, 128, 38)
    if phase == 38:
        return grow(o, w, 22, 128, 39)
    if phase == 39:
        return invoke(o, w, 57, 20, 0, get(w, O_ENVELOPE_BYTES), 21, cap(w, 21), 22, cap(w, 22), 21, 0, 128, 40)
    if phase == 40:
        if ordinary_leaf_header(w, PREPARE_EVENT, 21, 22, 96) == 0:
            return refuse(w, 6041)
        action = get(w, OBS + 16)
        reason = get(w, OBS + 24)
        size = get(w, OBS + 56)
        if action == 1:
            put(w, C_PHASE, 41)
            return 0
        if action == 2:
            if reason < 1 or reason > 22 or size == 0:
                return refuse(w, 6042)
            return edit_error_start(w, 3, 57, reason, 21, 128, size)
        if reason != 0 or size == 0:
            return refuse(w, 6043)
        version = get(w, OBS + 64)
        policy = get(w, OBS + 72)
        edits = get(w, OBS + 80)
        if version < 1 or version > 2 or policy > 1 or (version == 1 and policy != 0):
            return refuse(w, 6044)
        if edits < 1 or edits > 64 or get(w, OBS + 88) != edits:
            return refuse(w, 6045)
        put(w, O_CANDIDATE_BYTES, size)
        put(w, O_VERSION, version)
        put(w, O_POLICY, policy)
        put(w, O_EDITS, edits)
        return release(o, w, 20, 43)
    if phase == 41:
        return grow(o, w, 21, get(w, O_NEED_OUTPUT), 42)
    if phase == 42:
        return grow(o, w, 22, get(w, O_NEED_WORK), 39)
    if phase == 43:
        return release(o, w, 22, 44)
    if phase == 44:
        return protect(o, w, 21, 1, 50)
    return refuse(w, 6046)

def ordinary_object_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 50:
        return grow(o, w, 23, 128, 51)
    if phase == 51:
        return grow(o, w, 24, 128, 52)
    if phase == 52:
        return invoke(o, w, 63, 21, 128, get(w, O_CANDIDATE_BYTES), 23, cap(w, 23), 24, cap(w, 24), 23, 0, 128, 53)
    if phase == 53:
        if ordinary_leaf_header(w, OBJECT_EVENT, 23, 24, 80) == 0:
            return refuse(w, 6050)
        action = get(w, OBS + 16)
        reason = get(w, OBS + 24)
        size = get(w, OBS + 56)
        if action == 1:
            put(w, C_PHASE, 54)
            return 0
        if action == 2:
            if reason < 1 or reason > 5 or size != 0:
                return refuse(w, 6051)
            count = object_message(w, reason)
            if count == 0:
                return refuse(w, 6052)
            return edit_error_start(w, 2, 63, reason, B_CONTROLLER, PREFIX_TEXT, count)
        if reason != 0 or size == 0 or size > INPUT_LIMIT or get(w, OBS + 64) == 0 or get(w, OBS + 64) > NODES or get(w, OBS + 72) > DEPTH + 1:
            return refuse(w, 6053)
        put(w, O_PREFIX_BYTES, size)
        return grow(o, w, 25, size, 60)
    if phase == 54:
        return grow(o, w, 23, get(w, O_NEED_OUTPUT), 55)
    if phase == 55:
        return grow(o, w, 24, get(w, O_NEED_WORK), 52)
    if phase == 60:
        return copy(o, w, 23, 128, 25, 0, get(w, O_PREFIX_BYTES), 61)
    if phase == 61:
        return protect(o, w, 25, 1, 62)
    if phase == 62:
        return release(o, w, 21, 63)
    if phase == 63:
        return release(o, w, 23, 64)
    if phase == 64:
        return release(o, w, 24, 65)
    if phase == 65:
        put(w, O_ADMISSION, 1)
        put(w, O_SOURCE, 25)
        put(w, O_CORE_SLOT, 26)
        put(w, C_PHASE, 1)
        return 0
    return refuse(w, 6054)

def ordinary_suffix(w:mutbuf) -> u64:
    store(w, O_SUFFIX, 44)
    store(w, O_SUFFIX + 1, 34)
    hex_digest(w, O_INPUT_HASH, O_SUFFIX + 2)
    store(w, O_SUFFIX + 66, 34)
    store(w, O_SUFFIX + 67, 44)
    store(w, O_SUFFIX + 68, 48 + get(w, O_VERSION))
    store(w, O_SUFFIX + 69, 44)
    store(w, O_SUFFIX + 70, 48 + get(w, O_POLICY))
    store(w, O_SUFFIX + 71, 44)
    edits = get(w, O_EDITS)
    at = 72
    if edits >= 10:
        tens = 0
        while edits >= 10:
            edits = edits - 10
            tens = tens + 1
        store(w, O_SUFFIX + at, 48 + tens)
        at = at + 1
    store(w, O_SUFFIX + at, 48 + edits)
    store(w, O_SUFFIX + at + 1, 93)
    return at + 2

def ordinary_receipt_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 90:
        suffix = ordinary_suffix(w)
        if suffix < 74 or suffix > 75 or get(w, O_NEW_BYTES) == 0 or get(w, O_NEW_BYTES) > INPUT_LIMIT:
            return refuse(w, 6060)
        size = get(w, O_BASE_BYTES) + get(w, O_NEW_BYTES) + 2 + suffix
        if size > 16777472:
            return refuse(w, 6061)
        put(w, O_SUFFIX_BYTES, suffix)
        put(w, O_ENVELOPE_BYTES, size)
        return grow(o, w, 27, size, 91)
    if phase == 91:
        store(w, WIRE + 128, 91)
        store(w, WIRE + 129, 44)
        return copy(o, w, B_CONTROLLER, WIRE + 128, 27, 0, 1, 92)
    if phase == 92:
        return copy(o, w, B_CORE, 0, 27, 1, get(w, O_BASE_BYTES), 93)
    if phase == 93:
        return copy(o, w, B_CONTROLLER, WIRE + 129, 27, 1 + get(w, O_BASE_BYTES), 1, 94)
    if phase == 94:
        return copy(o, w, 26, 0, 27, 2 + get(w, O_BASE_BYTES), get(w, O_NEW_BYTES), 95)
    if phase == 95:
        return copy(o, w, B_CONTROLLER, O_SUFFIX, 27, 2 + get(w, O_BASE_BYTES) + get(w, O_NEW_BYTES), get(w, O_SUFFIX_BYTES), 96)
    if phase == 96:
        return protect(o, w, 27, 1, 97)
    if phase == 97:
        return grow(o, w, 28, 128, 98)
    if phase == 98:
        return grow(o, w, 29, 128, 99)
    if phase == 99:
        return invoke(o, w, 59, 27, 0, get(w, O_ENVELOPE_BYTES), 28, cap(w, 28), 29, cap(w, 29), 28, 0, 128, 100)
    if phase == 100:
        if ordinary_leaf_header(w, RECEIPT_EVENT, 28, 29, 64) == 0:
            return refuse(w, 6062)
        action = get(w, OBS + 16)
        reason = get(w, OBS + 24)
        size = get(w, OBS + 56)
        if action == 1:
            put(w, C_PHASE, 101)
            return 0
        if action == 2:
            if reason != 1 or size == 0:
                return refuse(w, 6063)
            return edit_error_start(w, 3, 59, reason, 28, 128, size)
        if reason != 0 or size == 0:
            return refuse(w, 6064)
        put(w, O_RECEIPT_BYTES, size)
        return edit_result_start(w, B_CORE, 0, get(w, O_BASE_BYTES), 26, 0, get(w, O_NEW_BYTES), 28, 128, size)
    if phase == 101:
        return grow(o, w, 28, get(w, O_NEED_OUTPUT), 102)
    if phase == 102:
        return grow(o, w, 29, get(w, O_NEED_WORK), 99)
    return refuse(w, 6065)
'''

def source_literal(path,name):
    tree=ast.parse(Path(path).read_bytes())
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))

def literal_source():
    prefix=base.PREFIX_MESSAGES
    objects=source_literal(Path(__file__).with_name("issued_object_prefix_reference.py"),"MESSAGES")
    result=[]
    for name,values in (("prefix_message",prefix),("object_message",objects)):
        result.append(f"def {name}(w:mutbuf, message:u64) -> u64:")
        for number,text in sorted(values.items()):
            raw=text.encode("utf-8") if isinstance(text,str) else text
            result.append(f"    if message == {number}:")
            result.extend(base.writes(raw,"PREFIX_TEXT","        "))
            result.append(f"        return {len(raw)}")
        result.append("    return 0")
    return "\n".join(result)+"\n"

def source_program():
    admissions=[n for n in ast.parse(base.ADMISSION).body if n.name!="program_child"]
    failures=[n for n in ast.parse(base.SOURCE).body if n.name=="prefix_failure"]
    assert len(admissions)==2 and len(failures)==1
    failure=ast.unparse(failures[0])
    old="return start_result(w, 4, 1, 2, 0, 0, 0, B_CONTROLLER, PREFIX_TEXT, size)"
    assert failure.count(old)==1
    failure=failure.replace(old,"return edit_error_start(w, 2, group, error, B_CONTROLLER, PREFIX_TEXT, size)")
    common=base.COMMON
    old="or (image >= 56 and image <= 59):"
    assert common.count(old)==1
    common=common.replace(old,"or image == 56 or image == 58:")
    source=(BODY+"\n"+ast.unparse(ast.Module(body=admissions,type_ignores=[]))+
        "\n"+failure+"\n"+base.HASH+"\n"+base.HEX+"\n"+base.HELPERS+
        "\n"+common+"\n"+literal_source())
    tree=ast.parse(source);functions={node.name:node for node in tree.body}
    assert len(functions)==len(tree.body)
    live={"ordinary_patch"};pending=["ordinary_patch"]
    while pending:
        for node in ast.walk(functions[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in functions and node.func.id not in live:
                live.add(node.func.id);pending.append(node.func.id)
    tree.body=[functions["ordinary_patch"]]+[n for n in tree.body if n.name!="ordinary_patch" and n.name in live]
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    for node in tree.body:
        if node.name!="ordinary_patch":
            assert node.returns.id in ("u32","u64")
            node.returns.id="u64"
    return ast.unparse(tree)+"\n"

def document():
    value=base.document(source_program());value["module"]="ordinary_patch_full_native_coordinator_r1"
    return value
