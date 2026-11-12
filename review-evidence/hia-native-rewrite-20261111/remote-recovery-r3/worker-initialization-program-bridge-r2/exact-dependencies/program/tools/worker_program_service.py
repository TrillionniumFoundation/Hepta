"""Worker program/assembly service values and continuation, development r1.

NEW SOURCE: no generated/native result is inherited. Input is an immutable
private byte lease; tree=1 additionally requires the issuer's complete
integer/UTF-8 insertion-order object transport. This is not an arbitrary
Python-object capture or a namespace/store authority.
"""
def magic(s):
    assert len(s)==8
    return int.from_bytes(s.encode("ascii"),"little")

CONSTANTS={
    "WP_INIT":magic("HIAWPI01"),"WP_STATE":magic("HIAWPS01"),
    "WP_RESULT":magic("HIAWPE01"),"WP_RECEIPT":77824,
    "WP_HEADER":78336,"WP_SAVED_CODE":78592,
}
FIELDS=("MAGIC","MODE","REQUEST","INPUT_BYTES","TREE","SELECTED_SLOT",
 "HAS_RECEIPT","CORE_SLOT","CORE_BYTES","RESULT_KIND","ERROR_DOMAIN","ERROR_PHASE",
 "ERROR_LINE","PAYLOAD_SLOT","PAYLOAD_AT","PAYLOAD_BYTES","FRAME_BYTES",
 "RECEIPT_AT","CORE_AT","PAYLOAD_OUT","CODE_BYTES","RELEASE")
CONSTANTS.update({"WP_"+name:73728+8*i for i,name in enumerate(FIELDS)})

BODY=r'''
def worker_program_service(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 12000)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if worker_program_begin(s, w) == 0:
            return refuse(w, 12001)
    elif get(w, C_MAGIC) != EDIT_STATE or get(w, A_MAGIC) != A_STATE_MAGIC or get(w, WP_MAGIC) != WP_STATE or acknowledge(s, w, MAIN) == 0:
        return refuse(w, 12002)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 71000 and phase < 71100:
            result = worker_object_step(o, w, phase)
        elif phase == 71500:
            result = worker_object_failure(w)
        elif phase == 87000:
            result = worker_assembly_finish(w)
        elif phase >= 88000 and phase < 88100:
            result = worker_result_step(o, w, phase)
        elif phase >= 60000 and phase < 64000:
            result = switch(o, w, ASSEMBLY_DRIVER, phase)
        else:
            result = worker_admission_step(o, w, phase)
        if result != 0:
            return result
    return refuse(w, 12003)

def worker_program_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != WP_INIT or word(s, 56) != 0:
        return 0
    lease = word(s, 8)
    request = word(s, 16)
    digits = word(s, 24)
    mode = word(s, 40)
    tree = word(s, 48)
    if lease == 0 or lease > MAX - 3 or request == 0 or mode < 1 or mode > 4:
        return 0
    if digits > 4294967295 or (digits != 0 and digits < 640):
        return 0
    if tree > 1 or (tree == 1 and mode > 2) or word(s, 32) != cap(w, B_PROGRAM):
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != MIN_WORK:
        return 0
    slot = 3
    while slot < 64:
        if cap(w, slot) != 0:
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
    put(w, A_MAGIC, A_STATE_MAGIC)
    put(w, WP_MAGIC, WP_STATE)
    put(w, WP_MODE, mode)
    put(w, WP_REQUEST, request)
    put(w, WP_INPUT_BYTES, word(s, 32))
    put(w, WP_TREE, tree)
    put(w, WP_SELECTED_SLOT, B_PROGRAM)
    put(w, E_DIGITS, digits)
    put(w, E_REQUEST, request)
    put(w, A_ACTION, 8)
    if mode == 2:
        put(w, A_ACTION, 4)
    elif mode == 3:
        put(w, A_ACTION, 3)
    elif mode == 4:
        put(w, A_ACTION, 5)
    if mode >= 3:
        put(w, C_PHASE, 60000)
    elif tree == 1:
        if assembly_initialize(w, 0) == 0:
            return 0
        put(w, AS_SOURCE_SLOT, B_PROGRAM)
        put(w, AS_SOURCE_AT, 0)
        put(w, AS_SOURCE_BYTES, cap(w, B_PROGRAM))
        put(w, AS_SYNTAX_AT, 0)
        put(w, AS_SYNTAX_BYTES, cap(w, B_PROGRAM))
        put(w, WP_SELECTED_SLOT, AS_CANONICAL)
        put(w, C_PHASE, 71000)
    else:
        put(w, C_PHASE, 1)
    return 1

def worker_save_receipt(w:mutbuf, slot:u64) -> u64:
    if get(w, WP_HAS_RECEIPT) != 0 or get(w, E_CORE_BYTES) == 0:
        return 0
    if slot != B_CORE and slot != AS_FINAL_CORE:
        return 0
    copy_local(w, WP_RECEIPT, OBS, 256)
    put(w, WP_HAS_RECEIPT, 1)
    put(w, WP_CORE_SLOT, slot)
    put(w, WP_CORE_BYTES, get(w, E_CORE_BYTES))
    return 1

def worker_admission_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return worker_program_child(o, w, 2)
    if phase == 2:
        state = program_child_frame(w)
        if state == 0:
            return refuse(w, 12010)
        if state == 2:
            return prefix_failure(w)
        if state == 3:
            return view(o, w, B_PROGRAM_FRAME, 0, 64, 20)
        return view(o, w, B_PROGRAM_FRAME, 0, 256, 3)
    if phase == 3:
        if program_receipt_header(w) == 0 or worker_save_receipt(w, B_CORE) == 0:
            return refuse(w, 12011)
        return grow(o, w, B_CORE, get(w, E_CORE_BYTES), 4)
    if phase == 4:
        return copy(o, w, B_PROGRAM_FRAME, 256, B_CORE, 0, get(w, E_CORE_BYTES), 5)
    if phase == 5:
        return protect(o, w, B_CORE, 1, 6)
    if phase == 6:
        return hash_start(w, B_CORE, get(w, E_CORE_BYTES), E_ACTUAL_CORE_HASH, 7)
    if phase == 7:
        if same_digest(w, E_ACTUAL_CORE_HASH, E_CORE_HASH) == 0:
            return refuse(w, 12012)
        if get(w, WP_TREE) == 1:
            put(w, WP_RELEASE, 51)
            put(w, C_PHASE, 10)
            return 0
        put(w, C_PHASE, 12)
        return 0
    if phase == 10:
        slot = get(w, WP_RELEASE)
        if slot == 59:
            zero(w, AS_MAGIC, 320)
            put(w, C_PHASE, 12)
            return 0
        if slot < 51 or slot > 58:
            return refuse(w, 12013)
        put(w, WP_RELEASE, slot + 1)
        return release(o, w, slot, 10)
    if phase == 12:
        if get(w, WP_MODE) == 1:
            return worker_result_begin(w, 1, 0, 0, 0, B_CORE, 0, get(w, WP_CORE_BYTES))
        if get(w, WP_MODE) != 2:
            return refuse(w, 12014)
        return switch(o, w, ASSEMBLY_DRIVER, 61000)
    if phase == 20:
        if get(w, OBS) != CORE_DIAGNOSTIC or get(w, OBS + 8) != 1:
            return refuse(w, 12015)
        if get(w, OBS + 16) != get(w, E_ERROR_CODE) or get(w, OBS + 24) == 0 or get(w, OBS + 24) > 92:
            return refuse(w, 12016)
        if get(w, E_ERROR_BYTES) < 65 or get(w, OBS + 40) != get(w, E_ERROR_BYTES) or get(w, OBS + 32) != get(w, E_ERROR_BYTES) - 64:
            return refuse(w, 12017)
        if get(w, OBS + 48) == 0 or get(w, OBS + 48) > NODES or get(w, OBS + 56) != 0:
            return refuse(w, 12018)
        return worker_result_begin(w, 4, 1, 0, 0, B_PROGRAM_FRAME, 64, get(w, OBS + 32))
    return refuse(w, 12019)

def start_result(w:mutbuf, kind:u64, domain:u64, exitcode:u64, field:u64, policy:u64, target:u64, source:u64, at:u64, size:u64) -> u64:
    if kind != 4 or domain != 1 or exitcode != 2 or field != 0 or policy != 0 or target != 0:
        return refuse(w, 12020)
    return worker_result_begin(w, 4, 1, 0, 0, source, at, size)

def worker_object_failure(w:mutbuf) -> u64:
    if get(w, WP_TREE) != 1 or get(w, AS_MAGIC) != AS_STATE_MAGIC or get(w, AS_ERROR_PHASE) != 1:
        return refuse(w, 12021)
    return worker_result_begin(w, 4, 1, 0, 0, get(w, AS_ERROR_SLOT), get(w, AS_ERROR_AT), get(w, AS_ERROR_BYTES))

def worker_assembly_decide_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 60300:
        if get(w, AS_MODE) != 0:
            return refuse(w, 12030)
        if get(w, A_ACTION) == 5:
            put(w, AS_ERROR_BYTES, 0)
            put(w, C_PHASE, 62000)
            return 0
        if get(w, A_ACTION) != 3:
            return refuse(w, 12031)
        return assembly_complete(o, w, 3, 0, 1, AS_FINAL_CORE, 0, get(w, AS_FINAL_BYTES))
    if phase == 60310:
        if get(w, A_ACTION) != 4 or get(w, AS_MODE) != 1:
            return refuse(w, 12032)
        return assembly_complete(o, w, 3, 0, 2, AS_RENDER_WORK, get(w, AS_TEXT_AT), get(w, AS_TEXT_BYTES))
    return refuse(w, 12033)

def worker_assembly_finish(w:mutbuf) -> u64:
    if get(w, AS_MAGIC) != AS_STATE_MAGIC:
        return refuse(w, 12040)
    kind = get(w, AS_RESULT_KIND)
    mode = get(w, WP_MODE)
    slot = get(w, AS_RESULT_SOURCE)
    at = get(w, AS_RESULT_AT)
    size = get(w, AS_RESULT_BYTES)
    if kind == 4:
        phase = get(w, AS_ERROR_PHASE)
        if phase > 2 or mode < 2 or mode > 3:
            return refuse(w, 12041)
        return worker_result_begin(w, 4, 2, phase + 1, get(w, AS_ERROR_LINE), slot, at, size)
    if kind != 3:
        return refuse(w, 12042)
    if mode == 2:
        if get(w, AS_MODE) != 1 or get(w, AS_RESULT_EXIT) != 0 or get(w, AS_RESULT_FORMAT) != 2:
            return refuse(w, 12043)
        return worker_result_begin(w, 2, 0, 0, 0, slot, at, size)
    if mode == 3:
        if get(w, AS_MODE) != 0 or get(w, AS_RESULT_EXIT) != 0 or get(w, AS_RESULT_FORMAT) != 1:
            return refuse(w, 12044)
        return worker_result_begin(w, 1, 0, 0, 0, slot, at, size)
    if mode == 4:
        if get(w, AS_MODE) != 0 or get(w, AS_RESULT_EXIT) > 1 or get(w, AS_RESULT_FORMAT) != 1:
            return refuse(w, 12045)
        if get(w, AS_RESULT_EXIT) == 0 and get(w, WP_HAS_RECEIPT) != 1:
            return refuse(w, 12046)
        if get(w, AS_RESULT_EXIT) == 1 and get(w, WP_HAS_RECEIPT) != 0:
            return refuse(w, 12047)
        return worker_result_begin(w, 3, 0, 0, 0, slot, at, size)
    return refuse(w, 12048)

def worker_result_begin(w:mutbuf, kind:u64, domain:u64, phase:u64, line:u64, slot:u64, at:u64, size:u64) -> u64:
    if get(w, WP_MAGIC) != WP_STATE or get(w, WP_RESULT_KIND) != 0 or cap(w, B_RESULT) != 0:
        return refuse(w, 12050)
    if kind < 1 or kind > 4 or size == 0 or inside(w, slot, at, size) == 0:
        return refuse(w, 12051)
    if kind == 4:
        if domain < 1 or domain > 2 or phase > 3 or (domain == 1 and (phase != 0 or line != 0)):
            return refuse(w, 12052)
        put(w, WP_HAS_RECEIPT, 0)
        put(w, WP_CORE_SLOT, 0)
        put(w, WP_CORE_BYTES, 0)
    else:
        if domain != 0 or phase != 0 or line != 0:
            return refuse(w, 12053)
        if kind != 3 and get(w, WP_HAS_RECEIPT) != 1:
            return refuse(w, 12054)
    if get(w, WP_HAS_RECEIPT) > 1:
        return refuse(w, 12055)
    if get(w, WP_HAS_RECEIPT) == 1:
        if get(w, WP_CORE_BYTES) == 0 or inside(w, get(w, WP_CORE_SLOT), 0, get(w, WP_CORE_BYTES)) == 0:
            return refuse(w, 12056)
    if kind == 1:
        if slot != get(w, WP_CORE_SLOT) or at != 0 or size != get(w, WP_CORE_BYTES):
            return refuse(w, 12057)
    put(w, WP_RESULT_KIND, kind)
    put(w, WP_ERROR_DOMAIN, domain)
    put(w, WP_ERROR_PHASE, phase)
    put(w, WP_ERROR_LINE, line)
    put(w, WP_PAYLOAD_SLOT, slot)
    put(w, WP_PAYLOAD_AT, at)
    put(w, WP_PAYLOAD_BYTES, size)
    put(w, C_PHASE, 88000)
    return 0

def worker_result_layout(w:mutbuf) -> u64:
    end = 256
    if get(w, WP_HAS_RECEIPT) == 1:
        if get(w, WP_CORE_BYTES) > MAX - 512:
            return 0
        put(w, WP_RECEIPT_AT, 256)
        put(w, WP_CORE_AT, 512)
        end = 512 + get(w, WP_CORE_BYTES)
    if get(w, WP_RESULT_KIND) == 1:
        put(w, WP_PAYLOAD_OUT, get(w, WP_CORE_AT))
    else:
        if get(w, WP_PAYLOAD_BYTES) > MAX - end:
            return 0
        put(w, WP_PAYLOAD_OUT, end)
        end = end + get(w, WP_PAYLOAD_BYTES)
    put(w, WP_FRAME_BYTES, end)
    zero(w, WP_HEADER, 256)
    put(w, WP_HEADER, WP_RESULT)
    put(w, WP_HEADER + 8, 1)
    put(w, WP_HEADER + 16, get(w, C_LEASE))
    put(w, WP_HEADER + 24, get(w, WP_REQUEST))
    put(w, WP_HEADER + 32, get(w, WP_MODE))
    put(w, WP_HEADER + 40, get(w, WP_RESULT_KIND))
    put(w, WP_HEADER + 48, get(w, WP_ERROR_DOMAIN))
    put(w, WP_HEADER + 56, get(w, WP_ERROR_PHASE))
    put(w, WP_HEADER + 64, get(w, WP_ERROR_LINE))
    put(w, WP_HEADER + 72, end)
    put(w, WP_HEADER + 80, get(w, WP_RECEIPT_AT))
    put(w, WP_HEADER + 88, get(w, WP_HAS_RECEIPT) * 256)
    put(w, WP_HEADER + 96, get(w, WP_CORE_AT))
    put(w, WP_HEADER + 104, get(w, WP_CORE_BYTES))
    put(w, WP_HEADER + 112, get(w, WP_PAYLOAD_OUT))
    put(w, WP_HEADER + 120, get(w, WP_PAYLOAD_BYTES))
    if get(w, WP_RESULT_KIND) == 4:
        put(w, WP_HEADER + 128, get(w, WP_PAYLOAD_OUT))
        put(w, WP_HEADER + 136, get(w, WP_CODE_BYTES))
    return 1

def worker_result_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 88000:
        if get(w, WP_RESULT_KIND) == 4:
            return view(o, w, get(w, WP_PAYLOAD_SLOT), get(w, WP_PAYLOAD_AT), minimum(get(w, WP_PAYLOAD_BYTES), 64), 88001)
        put(w, C_PHASE, 88002)
        return 0
    if phase == 88001:
        count = minimum(get(w, WP_PAYLOAD_BYTES), 64)
        index = 0
        while index < count and byte(w, OBS + index) != 58:
            part = byte(w, OBS + index)
            if (part < 65 or part > 90) and part != 95 and (part < 48 or part > 57):
                return refuse(w, 12060)
            index = index + 1
        if index < 6 or index + 1 >= count or byte(w, OBS + index + 1) != 32:
            return refuse(w, 12061)
        if byte(w, OBS) != 69 or byte(w, OBS + 1) != 95 or byte(w, OBS + 2) != 72 or byte(w, OBS + 3) != 73 or byte(w, OBS + 4) != 65 or byte(w, OBS + 5) != 95:
            return refuse(w, 12062)
        put(w, WP_CODE_BYTES, index)
        put(w, C_PHASE, 88002)
        return 0
    if phase == 88002:
        if worker_result_layout(w) == 0:
            return refuse(w, 12063)
        return grow(o, w, B_RESULT, get(w, WP_FRAME_BYTES), 88003)
    if phase == 88003:
        return copy(o, w, B_CONTROLLER, WP_HEADER, B_RESULT, 0, 256, 88004)
    if phase == 88004:
        if get(w, WP_HAS_RECEIPT) == 0:
            put(w, C_PHASE, 88006)
            return 0
        return copy(o, w, B_CONTROLLER, WP_RECEIPT, B_RESULT, get(w, WP_RECEIPT_AT), 256, 88005)
    if phase == 88005:
        return copy(o, w, get(w, WP_CORE_SLOT), 0, B_RESULT, get(w, WP_CORE_AT), get(w, WP_CORE_BYTES), 88006)
    if phase == 88006:
        if get(w, WP_RESULT_KIND) == 1:
            put(w, C_PHASE, 88007)
            return 0
        return copy(o, w, get(w, WP_PAYLOAD_SLOT), get(w, WP_PAYLOAD_AT), B_RESULT, get(w, WP_PAYLOAD_OUT), get(w, WP_PAYLOAD_BYTES), 88007)
    if phase == 88007:
        return protect(o, w, B_RESULT, 1, 88008)
    if phase == 88008:
        put(w, L_FN_SERIAL, 0)
        put(w, L_FN_SLOTS, get(w, WP_FRAME_BYTES))
        put(w, L_FN_COUNT, get(w, WP_RESULT_KIND))
        put(w, L_HELP_COUNT, get(w, WP_ERROR_DOMAIN))
        put(w, L_FINAL_BYTES, get(w, WP_FRAME_BYTES))
        zero(w, L_DIGEST0, 32)
        if get(w, WP_ERROR_DOMAIN) != 0:
            return finish(o, w, 1, get(w, WP_ERROR_DOMAIN), B_RESULT)
        return finish(o, w, 0, 0, B_RESULT)
    return refuse(w, 12064)
'''
