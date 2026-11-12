"""Complete assembly CLI service continuation; NEW authoring, zero execution.
This module extends service table 1 only. The E service table remains byte-for-
byte separate. The fixed carrier never interprets syntax, JSON or diagnostic
fields. The syntax/object/primitive sequence is decided here in HIA.
"""
import ast
from pathlib import Path
from hashlib import sha256
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
CONSTANTS={
 "ASSEMBLY_DRIVER":59,"ASSEMBLY_SYNTAX":61,"ASSEMBLY_RENDER":62,"ASSEMBLY_OBJECT":63,
 "AS_STATE_MAGIC":magic("HIASVS01"),"AS_SYNTAX_COMMAND":magic("HIAASC01"),
 "AS_SYNTAX_EVENT":magic("HIAASE01"),"AS_RENDER_COMMAND":magic("HIAARC01"),
 "AS_RENDER_EVENT":magic("HIAARE01"),"AS_OBJECT_EVENT":magic("HIAOPE01"),
 "AS_COMMAND":51,"AS_RENDER_WORK":52,"AS_SYNTAX_WORK":53,
 "AS_OBJECT_OUTPUT":54,"AS_OBJECT_WORK":55,"AS_CANONICAL":56,
 "AS_FINAL_CORE":57,"AS_JSON_OUTPUT":58,
 "AS_HASH_SOURCE":60928,"AS_HASH_TEXT":60960,
 "AS_COMPARE":61024,"AS_LITERAL_BASE":61440,"AS_LITERAL_LIMIT":65536,
 "AS_FRAGMENT":65536,"AS_CODE":67840,"AS_ERROR_LITERAL":68096,
}
FIELDS=("MAGIC","MODE","PREFIX","SOURCE_SLOT","SOURCE_AT","SOURCE_BYTES",
 "SYNTAX_AT","SYNTAX_BYTES","TEXT_AT","TEXT_BYTES","OBJECT_GROW_O","OBJECT_GROW_W",
 "CANONICAL_BYTES","FINAL_BYTES","ORIGINAL_BYTES","FIELD_INDEX","ERROR_SLOT",
 "ERROR_AT","ERROR_BYTES","ERROR_LINE","ERROR_CODE","ERROR_PHASE","NEXT",
 "RESULT_KIND","RESULT_EXIT","RESULT_FORMAT","RESULT_SOURCE","RESULT_AT","RESULT_BYTES",
 "COMPARE_POS","COMPARE_N","JSON_POS","JSON_SIZE","JSON_ERROR_POS","JSON_CHUNK",
 "JSON_CODE_BYTES","PUBLICATION_COMPLETE","DIGEST_DONE","RELEASE","CODE_PREFIX")
CONSTANTS.update({"AS_"+name:60000+8*i for i,name in enumerate(FIELDS)})
LITERALS={
 "object1":"E_HIA_LIMIT: caller-owned tree exceeds snapshot budget",
 "object2":"E_HIA_LIMIT: caller-owned tree exceeds queued-node budget",
 "object3":"E_HIA_LIMIT: program exceeds structural budget",
 "object4":"E_HIA_LIMIT: program exceeds queued-node budget",
 "object5":"E_HIA_LIMIT: program exceeds byte budget before encoding",
 "roundtrip":"E_HIA_ASSEMBLY_ROUNDTRIP: renderer changed canonical Core",
 "code_assembly":"E_HIA_ASSEMBLY","code_assembly_limit":"E_HIA_ASSEMBLY_LIMIT",
 "accepted":'{"accepted":true,"core_schema":"hepta.hia.program.v',
 "accepted_hash":'","core_sha256":"',
 "accepted_tail":'","deployment_authority":false,"diagnostic":null,"native_artifact_created":false,"safety_certificate":false,"schema":"hepta.hia.assembly-diagnostic.v1"',
 "rejected":'{"accepted":false,"deployment_authority":false,"diagnostic":{"code":"',
 "line":'","line":',"message":',"message":"',
 "phase_syntax":'","phase":"syntax"}',"phase_core":'","phase":"core_verification"}',
 "rejected_tail":',"native_artifact_created":false,"safety_certificate":false,"schema":"hepta.hia.assembly-diagnostic.v1"',
 "source_bytes":',"source_bytes":',"source_hash":',"source_sha256":"',
 "pub_first":'{"core_sha256":"',"pub_second":'","deployment_authority":false,"ok":true,"output":',
 "pub_third":',"publication":',"pub_last":',"schema":"hepta.hia.assembly-output.v1"}',
 "receipt_first":'{"bytes":',"receipt_second":',"sha256":"',
}
CONSTANTS.update(AS_PUB_TEXT1_BYTES=len(LITERALS["pub_first"])+64+len(LITERALS["pub_second"]),
 AS_PUB_TEXT2_BYTES=len(LITERALS["pub_third"]),AS_PUB_TEXT3_BYTES=len(LITERALS["pub_last"]))
BODY=r'''
def assembly_service(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128 or get(w, C_MAGIC) != EDIT_STATE or get(w, A_MAGIC) != A_STATE_MAGIC:
        return refuse(w, 7000)
    if get(w, A_ACTION) < 3 or get(w, A_ACTION) > 5 or acknowledge(s, w, ASSEMBLY_DRIVER) == 0:
        return refuse(w, 7001)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 60000 and phase < 60100:
            result = assembly_syntax_step(o, w, phase)
        elif phase >= 60100 and phase < 60200:
            result = assembly_object_step(o, w, phase)
        elif phase >= 60200 and phase < 60300:
            result = assembly_primitive_step(o, w, phase)
        elif phase >= 60300 and phase < 60400:
            result = assembly_decide_step(o, w, phase)
        elif phase >= 61000 and phase < 61100:
            result = assembly_render_step(o, w, phase)
        elif phase >= 62000 and phase < 62100:
            result = assembly_diagnostic_step(o, w, phase)
        elif phase >= 63000 and phase < 63100:
            result = assembly_compare_step(o, w, phase)
        else:
            return refuse(w, 7002)
        if result != 0:
            return result
    return refuse(w, 7003)

def assembly_initialize(w:mutbuf, mode:u64) -> u64:
    if get(w, AS_MAGIC) != 0 or mode > 1:
        return 0
    put(w, AS_MAGIC, AS_STATE_MAGIC)
    put(w, AS_MODE, mode)
    assembly_literals(w)
    return 1

def assembly_syntax_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 60000:
        if get(w, A_ACTION) != 3 and get(w, A_ACTION) != 5:
            return refuse(w, 7010)
        if assembly_initialize(w, 0) == 0:
            return refuse(w, 7011)
        put(w, AS_SOURCE_SLOT, B_PROGRAM)
        put(w, AS_SOURCE_AT, 0)
        put(w, AS_SOURCE_BYTES, cap(w, B_PROGRAM))
        put(w, C_PHASE, 60001)
        return 0
    if get(w, AS_MAGIC) != AS_STATE_MAGIC:
        return refuse(w, 7012)
    if phase == 60001:
        if inside(w, get(w, AS_SOURCE_SLOT), get(w, AS_SOURCE_AT), get(w, AS_SOURCE_BYTES)) == 0:
            return refuse(w, 7013)
        return grow(o, w, AS_COMMAND, 96, 60002)
    if phase == 60002:
        zero(w, WIRE, 96)
        wire8(w, AS_SYNTAX_COMMAND, 1, get(w, C_LEASE), 1, 2, get(w, E_DIGITS), get(w, AS_SOURCE_BYTES), 0)
        return copy(o, w, B_CONTROLLER, WIRE, AS_COMMAND, 0, 96, 60003)
    if phase == 60003:
        return protect(o, w, AS_COMMAND, 1, 60004)
    if phase == 60004:
        return grow(o, w, AS_SYNTAX_WORK, 163840, 60005)
    if phase == 60005:
        return invoke(o, w, ASSEMBLY_SYNTAX, get(w, AS_SOURCE_SLOT), get(w, AS_SOURCE_AT), get(w, AS_SOURCE_BYTES), AS_COMMAND, 96, AS_SYNTAX_WORK, cap(w, AS_SYNTAX_WORK), AS_SYNTAX_WORK, 256, 128, 60006)
    if phase == 60006:
        if get(w, OBS) != AS_SYNTAX_EVENT or get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != 1:
            return refuse(w, 7014)
        if get(w, OBS + 80) != get(w, AS_SOURCE_BYTES) or get(w, OBS + 72) > get(w, AS_SOURCE_BYTES):
            return refuse(w, 7015)
        if get(w, OBS + 48) > 1 or get(w, OBS + 96) > 1:
            return refuse(w, 7016)
        if get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return refuse(w, 7017)
        action = get(w, OBS + 8)
        if action == 1:
            if get(w, C_RETURN) != 4294967294 or get(w, OBS + 88) <= cap(w, AS_SYNTAX_WORK):
                return refuse(w, 7018)
            if get(w, OBS + 32) != 0 or get(w, OBS + 40) != 0 or get(w, OBS + 56) != 0 or get(w, OBS + 64) != 0:
                return refuse(w, 7019)
            return grow(o, w, AS_SYNTAX_WORK, get(w, OBS + 88), 60005)
        if get(w, C_RETURN) != 128 or (action != 0 and action != 2):
            return refuse(w, 7020)
        at = get(w, OBS + 56)
        size = get(w, OBS + 64)
        if size == 0 or inside(w, AS_SYNTAX_WORK, at, size) == 0:
            return refuse(w, 7021)
        put(w, AS_PREFIX, get(w, OBS + 48))
        if action == 2:
            if get(w, OBS + 32) == 0 or get(w, OBS + 32) > 28 or get(w, OBS + 40) > 16384:
                return refuse(w, 7022)
            put(w, AS_ERROR_SLOT, AS_SYNTAX_WORK)
            put(w, AS_ERROR_AT, at)
            put(w, AS_ERROR_BYTES, size)
            put(w, AS_ERROR_LINE, get(w, OBS + 40))
            put(w, AS_ERROR_CODE, 1 + get(w, OBS + 96))
            put(w, AS_ERROR_PHASE, 0)
            return protect(o, w, AS_SYNTAX_WORK, 1, 62000)
        if get(w, OBS + 32) != 0 or get(w, OBS + 40) != 0 or get(w, OBS + 96) != 0 or get(w, AS_PREFIX) != 1:
            return refuse(w, 7023)
        put(w, AS_SYNTAX_AT, at)
        put(w, AS_SYNTAX_BYTES, size)
        return protect(o, w, AS_SYNTAX_WORK, 1, 60100)
    return refuse(w, 7024)

def assembly_object_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if get(w, AS_MAGIC) != AS_STATE_MAGIC or get(w, AS_SYNTAX_BYTES) == 0:
        return refuse(w, 7030)
    if phase == 60100:
        return grow(o, w, AS_OBJECT_OUTPUT, 128, 60101)
    if phase == 60101:
        return grow(o, w, AS_OBJECT_WORK, 128, 60102)
    if phase == 60102:
        return invoke(o, w, ASSEMBLY_OBJECT, AS_SYNTAX_WORK, get(w, AS_SYNTAX_AT), get(w, AS_SYNTAX_BYTES), AS_OBJECT_OUTPUT, cap(w, AS_OBJECT_OUTPUT), AS_OBJECT_WORK, cap(w, AS_OBJECT_WORK), AS_OBJECT_OUTPUT, 0, 128, 60103)
    if phase == 60103:
        if get(w, OBS) != AS_OBJECT_EVENT or get(w, OBS + 8) != 1 or get(w, OBS + 48) != 128:
            return refuse(w, 7031)
        at = 80
        while at < 128:
            if get(w, OBS + at) != 0:
                return refuse(w, 7032)
            at = at + 8
        action = get(w, OBS + 16)
        if action == 1:
            out = get(w, OBS + 32)
            work = get(w, OBS + 40)
            if get(w, C_RETURN) != 4294967294 or get(w, OBS + 24) != 0 or get(w, OBS + 56) != 0 or out < 128 or work < 128:
                return refuse(w, 7033)
            if out <= cap(w, AS_OBJECT_OUTPUT) and work <= cap(w, AS_OBJECT_WORK):
                return refuse(w, 7034)
            put(w, AS_OBJECT_GROW_O, out)
            put(w, AS_OBJECT_GROW_W, work)
            return grow(o, w, AS_OBJECT_OUTPUT, out, 60104)
        if get(w, C_RETURN) != 128 or (action != 0 and action != 2):
            return refuse(w, 7035)
        if get(w, OBS + 32) > cap(w, AS_OBJECT_OUTPUT) or get(w, OBS + 40) > cap(w, AS_OBJECT_WORK):
            return refuse(w, 7036)
        if action == 2:
            reason = get(w, OBS + 24)
            if reason < 1 or reason > 5 or get(w, OBS + 56) != 0:
                return refuse(w, 7037)
            put(w, AS_ERROR_SLOT, B_CONTROLLER)
            put(w, AS_ERROR_AT, assembly_object_message_at(reason))
            put(w, AS_ERROR_BYTES, assembly_object_message_bytes(reason))
            put(w, AS_ERROR_LINE, 0)
            put(w, AS_ERROR_CODE, 0)
            put(w, AS_ERROR_PHASE, 1)
            put(w, C_PHASE, 62000)
            return 0
        size = get(w, OBS + 56)
        if get(w, OBS + 24) != 0 or size == 0 or size > 8388608 or inside(w, AS_OBJECT_OUTPUT, 128, size) == 0:
            return refuse(w, 7038)
        # These success checks only restate the prefix's completed gates.
        # They are not an early policy on the unadmitted syntax transport.
        # Transport depth counts containers; an empty container at value depth
        # 64 has stack peak 65 under the original root-at-zero rule.
        if get(w, OBS + 64) == 0 or get(w, OBS + 64) > 262144 or get(w, OBS + 72) > 65:
            return refuse(w, 7039)
        put(w, AS_CANONICAL_BYTES, size)
        return protect(o, w, AS_OBJECT_OUTPUT, 1, 60105)
    if phase == 60104:
        return grow(o, w, AS_OBJECT_WORK, get(w, AS_OBJECT_GROW_W), 60102)
    if phase == 60105:
        return grow(o, w, AS_CANONICAL, get(w, AS_CANONICAL_BYTES), 60106)
    if phase == 60106:
        return copy(o, w, AS_OBJECT_OUTPUT, 128, AS_CANONICAL, 0, get(w, AS_CANONICAL_BYTES), 60107)
    if phase == 60107:
        return protect(o, w, AS_CANONICAL, 1, 60200)
    return refuse(w, 7040)

def assembly_primitive_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 60200:
        if cap(w, B_PROGRAM_FRAME) != 0 or cap(w, AS_CANONICAL) != get(w, AS_CANONICAL_BYTES):
            return refuse(w, 7050)
        if get(w, C_LEASE) > MAX - 3 or get(w, AS_CANONICAL_BYTES) == 0 or get(w, AS_CANONICAL_BYTES) > 8388608:
            return refuse(w, 7051)
        put(w, E_CHILD_LEASE, get(w, C_LEASE) + 1)
        put(w, E_CHILD_TARGET, B_PROGRAM_FRAME)
        put(w, C_OBSERVE, 160)
        args(w, 2, AS_CANONICAL, 0, get(w, AS_CANONICAL_BYTES), B_PROGRAM_FRAME, get(w, E_CHILD_LEASE), get(w, E_DIGITS), 0, 0, 0, 0, 0)
        return event(o, w, 15, 60201)
    if phase == 60201:
        state = program_child_frame(w)
        if state == 0 or state == 2:
            # A raw/prefix failure here contradicts the actual syntax/object
            # successes. It is not relabelled as the public Core rejection.
            return refuse(w, 7052)
        if state == 3:
            return view(o, w, B_PROGRAM_FRAME, 0, 64, 60220)
        return view(o, w, B_PROGRAM_FRAME, 0, 256, 60202)
    if phase == 60202:
        if program_receipt_header(w) == 0 or get(w, E_KIND) != 0 or get(w, E_CORE_VERSION) < 6 or get(w, E_CORE_VERSION) > 8:
            return refuse(w, 7053)
        if get(w, E_CORE_BYTES) != get(w, AS_CANONICAL_BYTES) or get(w, E_INPUT_BYTES) != get(w, AS_CANONICAL_BYTES):
            return refuse(w, 7054)
        put(w, AS_FINAL_BYTES, get(w, E_CORE_BYTES))
        return grow(o, w, AS_FINAL_CORE, get(w, AS_FINAL_BYTES), 60203)
    if phase == 60203:
        return copy(o, w, B_PROGRAM_FRAME, 256, AS_FINAL_CORE, 0, get(w, AS_FINAL_BYTES), 60204)
    if phase == 60204:
        return protect(o, w, AS_FINAL_CORE, 1, 60205)
    if phase == 60205:
        return hash_start(w, AS_FINAL_CORE, get(w, AS_FINAL_BYTES), E_ACTUAL_CORE_HASH, 60206)
    if phase == 60206:
        if same_digest(w, E_ACTUAL_CORE_HASH, E_CORE_HASH) == 0:
            return refuse(w, 7055)
        if get(w, AS_MODE) == 1:
            put(w, AS_COMPARE_POS, 0)
            put(w, C_PHASE, 63000)
            return 0
        put(w, AS_FIELD_INDEX, 0)
        put(w, C_PHASE, 60300)
        return 0
    if phase == 60220:
        if get(w, OBS) != CORE_DIAGNOSTIC or get(w, OBS + 8) != 1:
            return refuse(w, 7056)
        if get(w, OBS + 16) != get(w, E_ERROR_CODE) or get(w, OBS + 24) == 0 or get(w, OBS + 24) > 92:
            return refuse(w, 7057)
        if get(w, OBS + 40) != get(w, E_ERROR_BYTES) or get(w, OBS + 32) != get(w, E_ERROR_BYTES) - 64:
            return refuse(w, 7058)
        if get(w, OBS + 48) == 0 or get(w, OBS + 48) > 262144 or get(w, OBS + 56) != 0:
            return refuse(w, 7059)
        put(w, AS_ERROR_SLOT, B_PROGRAM_FRAME)
        put(w, AS_ERROR_AT, 64)
        put(w, AS_ERROR_BYTES, get(w, OBS + 32))
        put(w, AS_ERROR_LINE, 0)
        put(w, AS_ERROR_CODE, 0)
        put(w, AS_ERROR_PHASE, 1)
        put(w, C_PHASE, 62000)
        return 0
    return refuse(w, 7060)

def assembly_decide_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 60300:
        index = get(w, AS_FIELD_INDEX)
        if index == 16:
            if get(w, A_ACTION) == 5:
                put(w, AS_ERROR_BYTES, 0)
                put(w, C_PHASE, 62000)
                return 0
            if get(w, A_ACTION) != 3:
                return refuse(w, 7070)
            if get(w, A_OUTPUT) == 1:
                return assembly_complete(o, w, 2, 0, 1, AS_FINAL_CORE, 0, get(w, AS_FINAL_BYTES))
            return assembly_complete(o, w, 3, 0, 1, AS_FINAL_CORE, 0, get(w, AS_FINAL_BYTES))
        put(w, A_FIELD_INDEX, index)
        return view(o, w, B_PARSER, 1024 + index * 32, 32, 60301)
    if phase == 60301:
        if parser_row(w) == 0:
            return refuse(w, 7071)
        put(w, AS_FIELD_INDEX, get(w, AS_FIELD_INDEX) + 1)
        put(w, C_PHASE, 60300)
        return 0
    if phase == 60310:
        if get(w, A_ACTION) != 4 or get(w, AS_MODE) != 1:
            return refuse(w, 7072)
        if get(w, A_OUTPUT) == 0:
            return assembly_complete(o, w, 3, 0, 2, AS_RENDER_WORK, get(w, AS_TEXT_AT), get(w, AS_TEXT_BYTES))
        return hash_view_start(w, AS_RENDER_WORK, get(w, AS_TEXT_AT), get(w, AS_TEXT_BYTES), AS_HASH_TEXT, 60311)
    if phase == 60311:
        put(w, AS_DIGEST_DONE, 1)
        return assembly_complete(o, w, 2, 0, 3, AS_RENDER_WORK, get(w, AS_TEXT_AT), get(w, AS_TEXT_BYTES))
    return refuse(w, 7073)

def assembly_render_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 61000:
        if get(w, A_ACTION) != 4 or assembly_initialize(w, 1) == 0:
            return refuse(w, 7080)
        put(w, AS_ORIGINAL_BYTES, get(w, E_CORE_BYTES))
        return release(o, w, B_PROGRAM_FRAME, 61001)
    if phase == 61001:
        return grow(o, w, AS_COMMAND, 96, 61002)
    if phase == 61002:
        zero(w, WIRE, 96)
        wire8(w, AS_RENDER_COMMAND, 1, get(w, C_LEASE), 1, get(w, AS_ORIGINAL_BYTES), get(w, E_KIND), 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, AS_COMMAND, 0, 96, 61003)
    if phase == 61003:
        return protect(o, w, AS_COMMAND, 1, 61004)
    if phase == 61004:
        return grow(o, w, AS_RENDER_WORK, 8192, 61005)
    if phase == 61005:
        return invoke(o, w, ASSEMBLY_RENDER, B_CORE, 0, get(w, AS_ORIGINAL_BYTES), AS_COMMAND, 96, AS_RENDER_WORK, cap(w, AS_RENDER_WORK), AS_RENDER_WORK, 256, 128, 61006)
    if phase == 61006:
        if get(w, OBS) != AS_RENDER_EVENT or get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != 1 or get(w, OBS + 80) != get(w, AS_ORIGINAL_BYTES):
            return refuse(w, 7081)
        if get(w, OBS + 40) != 0 or get(w, OBS + 48) != 0 or get(w, OBS + 72) != 0:
            return refuse(w, 7082)
        at = 96
        while at < 128:
            if get(w, OBS + at) != 0:
                return refuse(w, 7083)
            at = at + 8
        action = get(w, OBS + 8)
        if action == 1:
            if get(w, C_RETURN) != 4294967294 or get(w, OBS + 88) <= cap(w, AS_RENDER_WORK) or get(w, OBS + 32) != 0 or get(w, OBS + 56) != 0 or get(w, OBS + 64) != 0:
                return refuse(w, 7084)
            return grow(o, w, AS_RENDER_WORK, get(w, OBS + 88), 61005)
        if get(w, C_RETURN) != 128 or (action != 0 and action != 2):
            return refuse(w, 7085)
        start = get(w, OBS + 56)
        size = get(w, OBS + 64)
        if size == 0 or inside(w, AS_RENDER_WORK, start, size) == 0:
            return refuse(w, 7086)
        if action == 2:
            if get(w, OBS + 32) != 1:
                return refuse(w, 7087)
            put(w, AS_ERROR_SLOT, AS_RENDER_WORK)
            put(w, AS_ERROR_AT, start)
            put(w, AS_ERROR_BYTES, size)
            put(w, AS_ERROR_LINE, 0)
            put(w, AS_ERROR_CODE, 0)
            put(w, AS_ERROR_PHASE, 2)
            return protect(o, w, AS_RENDER_WORK, 1, 62000)
        if get(w, OBS + 32) != 0:
            return refuse(w, 7088)
        put(w, AS_TEXT_AT, start)
        put(w, AS_TEXT_BYTES, size)
        put(w, AS_SOURCE_SLOT, AS_RENDER_WORK)
        put(w, AS_SOURCE_AT, start)
        put(w, AS_SOURCE_BYTES, size)
        return protect(o, w, AS_RENDER_WORK, 1, 61007)
    if phase == 61007:
        return release(o, w, AS_COMMAND, 60001)
    return refuse(w, 7089)

def assembly_compare_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 63000:
        if get(w, AS_FINAL_BYTES) != get(w, AS_ORIGINAL_BYTES):
            return assembly_roundtrip_error(w)
        position = get(w, AS_COMPARE_POS)
        if position == get(w, AS_ORIGINAL_BYTES):
            put(w, C_PHASE, 60310)
            return 0
        if position > get(w, AS_ORIGINAL_BYTES):
            return refuse(w, 7090)
        count = minimum(get(w, AS_ORIGINAL_BYTES) - position, 256)
        put(w, AS_COMPARE_N, count)
        return view(o, w, B_CORE, position, count, 63001)
    if phase == 63001:
        copy_local(w, AS_COMPARE, OBS, get(w, AS_COMPARE_N))
        return view(o, w, AS_FINAL_CORE, get(w, AS_COMPARE_POS), get(w, AS_COMPARE_N), 63002)
    if phase == 63002:
        index = 0
        while index < get(w, AS_COMPARE_N):
            if byte(w, AS_COMPARE + index) != byte(w, OBS + index):
                return assembly_roundtrip_error(w)
            index = index + 1
        put(w, AS_COMPARE_POS, get(w, AS_COMPARE_POS) + get(w, AS_COMPARE_N))
        put(w, C_PHASE, 63000)
        return 0
    return refuse(w, 7091)

def assembly_roundtrip_error(w:mutbuf) -> u64:
    put(w, AS_ERROR_SLOT, B_CONTROLLER)
    put(w, AS_ERROR_AT, AS_L_roundtrip_AT)
    put(w, AS_ERROR_BYTES, AS_L_roundtrip_BYTES)
    put(w, AS_ERROR_LINE, 0)
    put(w, AS_ERROR_CODE, 0)
    put(w, AS_ERROR_PHASE, 2)
    put(w, C_PHASE, 62000)
    return 0

def assembly_complete(o:mutbuf, w:mutbuf, kind:u64, exitcode:u64, format:u64, slot:u64, at:u64, size:u64) -> u64:
    if get(w, AS_MAGIC) != AS_STATE_MAGIC or kind < 2 or kind > 4 or size == 0 or inside(w, slot, at, size) == 0:
        return refuse(w, 7100)
    put(w, AS_RESULT_KIND, kind)
    put(w, AS_RESULT_EXIT, exitcode)
    put(w, AS_RESULT_FORMAT, format)
    put(w, AS_RESULT_SOURCE, slot)
    put(w, AS_RESULT_AT, at)
    put(w, AS_RESULT_BYTES, size)
    return switch(o, w, MAIN, 87000)

def assembly_finish(w:mutbuf) -> u64:
    if get(w, AS_MAGIC) != AS_STATE_MAGIC or get(w, A_ACTION) < 3 or get(w, A_ACTION) > 5:
        return refuse(w, 7101)
    kind = get(w, AS_RESULT_KIND)
    if kind == 2:
        if get(w, A_REQUEST) != 0:
            return refuse(w, 7102)
        put(w, A_REQUEST, 1)
        return start_result(w, 2, 0, 0, 2, get(w, AS_RESULT_FORMAT), B_PUBLIC_RECEIPT, get(w, AS_RESULT_SOURCE), get(w, AS_RESULT_AT), get(w, AS_RESULT_BYTES))
    if kind == 4:
        return start_result(w, 4, 1, 2, 0, 0, 0, get(w, AS_RESULT_SOURCE), get(w, AS_RESULT_AT), get(w, AS_RESULT_BYTES))
    if kind == 3:
        return start_result(w, 3, 0, get(w, AS_RESULT_EXIT), 0, get(w, AS_RESULT_FORMAT), 0, get(w, AS_RESULT_SOURCE), get(w, AS_RESULT_AT), get(w, AS_RESULT_BYTES))
    return refuse(w, 7103)

def assembly_diagnostic_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 62000:
        if get(w, A_ACTION) != 5:
            if get(w, AS_ERROR_BYTES) == 0:
                return refuse(w, 7110)
            return assembly_complete(o, w, 4, 2, 0, get(w, AS_ERROR_SLOT), get(w, AS_ERROR_AT), get(w, AS_ERROR_BYTES))
        if get(w, AS_MODE) != 0 or get(w, AS_PREFIX) > 1:
            return refuse(w, 7111)
        if get(w, AS_PREFIX) == 1:
            return hash_start(w, B_PROGRAM, cap(w, B_PROGRAM), AS_HASH_SOURCE, 62001)
        put(w, C_PHASE, 62001)
        return 0
    if phase == 62001:
        if get(w, AS_ERROR_BYTES) > 3074457345618257920:
            return refuse(w, 7112)
        if get(w, AS_ERROR_BYTES) == 0:
            if get(w, AS_PREFIX) != 1 or get(w, E_CORE_VERSION) < 6 or get(w, E_CORE_VERSION) > 8:
                return refuse(w, 7113)
            size = assembly_success_json(w)
            put(w, AS_JSON_SIZE, size)
            return grow(o, w, AS_JSON_OUTPUT, size, 62002)
        put(w, AS_JSON_ERROR_POS, 0)
        return grow(o, w, AS_JSON_OUTPUT, get(w, AS_ERROR_BYTES) * 6 + 2048, 62010)
    if phase == 62002:
        return copy(o, w, B_CONTROLLER, AS_FRAGMENT, AS_JSON_OUTPUT, 0, get(w, AS_JSON_SIZE), 62003)
    if phase == 62003:
        return protect(o, w, AS_JSON_OUTPUT, 1, 62004)
    if phase == 62004:
        return assembly_complete(o, w, 3, 0, 1, AS_JSON_OUTPUT, 0, get(w, AS_JSON_SIZE))
    if phase == 62010:
        code = get(w, AS_ERROR_CODE)
        if code == 1:
            copy_local(w, AS_CODE, AS_L_code_assembly_AT, AS_L_code_assembly_BYTES)
            put(w, AS_JSON_CODE_BYTES, AS_L_code_assembly_BYTES)
        elif code == 2:
            copy_local(w, AS_CODE, AS_L_code_assembly_limit_AT, AS_L_code_assembly_limit_BYTES)
            put(w, AS_JSON_CODE_BYTES, AS_L_code_assembly_limit_BYTES)
        elif code == 0:
            return view(o, w, get(w, AS_ERROR_SLOT), get(w, AS_ERROR_AT), minimum(get(w, AS_ERROR_BYTES), 64), 62011)
        else:
            return refuse(w, 7114)
        put(w, C_PHASE, 62012)
        return 0
    if phase == 62011:
        count = minimum(get(w, AS_ERROR_BYTES), 64)
        index = 0
        while index < count and byte(w, OBS + index) != 58:
            part = byte(w, OBS + index)
            if (part < 65 or part > 90) and part != 95 and (part < 48 or part > 57):
                return refuse(w, 7115)
            store(w, AS_CODE + index, part)
            index = index + 1
        if index < 6 or index >= count or index + 1 >= count or byte(w, OBS + index + 1) != 32:
            return refuse(w, 7116)
        if byte(w, AS_CODE) != 69 or byte(w, AS_CODE + 1) != 95 or byte(w, AS_CODE + 2) != 72 or byte(w, AS_CODE + 3) != 73 or byte(w, AS_CODE + 4) != 65 or byte(w, AS_CODE + 5) != 95:
            return refuse(w, 7120)
        put(w, AS_JSON_CODE_BYTES, index)
        put(w, C_PHASE, 62012)
        return 0
    if phase == 62012:
        count = assembly_rejected_prefix(w)
        put(w, AS_JSON_POS, count)
        return copy(o, w, B_CONTROLLER, AS_FRAGMENT, AS_JSON_OUTPUT, 0, count, 62013)
    if phase == 62013:
        position = get(w, AS_JSON_ERROR_POS)
        if position == get(w, AS_ERROR_BYTES):
            count = assembly_rejected_suffix(w)
            put(w, AS_JSON_SIZE, get(w, AS_JSON_POS) + count)
            return copy(o, w, B_CONTROLLER, AS_FRAGMENT, AS_JSON_OUTPUT, get(w, AS_JSON_POS), count, 62016)
        if position > get(w, AS_ERROR_BYTES):
            return refuse(w, 7117)
        count = minimum(get(w, AS_ERROR_BYTES) - position, 256)
        put(w, AS_JSON_CHUNK, count)
        return view(o, w, get(w, AS_ERROR_SLOT), get(w, AS_ERROR_AT) + position, count, 62014)
    if phase == 62014:
        count = assembly_escape_chunk(w)
        if get(w, AS_JSON_POS) > cap(w, AS_JSON_OUTPUT) or count > cap(w, AS_JSON_OUTPUT) - get(w, AS_JSON_POS):
            return refuse(w, 7118)
        put(w, AS_NEXT, count)
        return copy(o, w, B_CONTROLLER, AS_FRAGMENT, AS_JSON_OUTPUT, get(w, AS_JSON_POS), count, 62015)
    if phase == 62015:
        put(w, AS_JSON_POS, get(w, AS_JSON_POS) + get(w, AS_NEXT))
        put(w, AS_JSON_ERROR_POS, get(w, AS_JSON_ERROR_POS) + get(w, AS_JSON_CHUNK))
        put(w, C_PHASE, 62013)
        return 0
    if phase == 62016:
        return protect(o, w, AS_JSON_OUTPUT, 1, 62017)
    if phase == 62017:
        return assembly_complete(o, w, 3, 1, 1, AS_JSON_OUTPUT, 0, get(w, AS_JSON_SIZE))
    return refuse(w, 7119)

def assembly_put_text(w:mutbuf, pos:u64, source:u64, count:u64) -> u64:
    copy_local(w, AS_FRAGMENT + pos, source, count)
    return pos + count

def assembly_source_suffix(w:mutbuf, pos:u64) -> u64:
    at = pos
    if get(w, AS_PREFIX) == 1:
        at = assembly_put_text(w, at, AS_L_source_bytes_AT, AS_L_source_bytes_BYTES)
        at = at + decimal_text(w, AS_FRAGMENT + at, cap(w, B_PROGRAM))
        at = assembly_put_text(w, at, AS_L_source_hash_AT, AS_L_source_hash_BYTES)
        hex_digest(w, AS_HASH_SOURCE, AS_FRAGMENT + at)
        at = at + 64
        store(w, AS_FRAGMENT + at, 34)
        at = at + 1
    store(w, AS_FRAGMENT + at, 125)
    return at + 1

def assembly_success_json(w:mutbuf) -> u64:
    at = assembly_put_text(w, 0, AS_L_accepted_AT, AS_L_accepted_BYTES)
    store(w, AS_FRAGMENT + at, 48 + get(w, E_CORE_VERSION))
    at = at + 1
    at = assembly_put_text(w, at, AS_L_accepted_hash_AT, AS_L_accepted_hash_BYTES)
    hex_digest(w, E_CORE_HASH, AS_FRAGMENT + at)
    at = at + 64
    at = assembly_put_text(w, at, AS_L_accepted_tail_AT, AS_L_accepted_tail_BYTES)
    return assembly_source_suffix(w, at)

def assembly_rejected_prefix(w:mutbuf) -> u64:
    at = assembly_put_text(w, 0, AS_L_rejected_AT, AS_L_rejected_BYTES)
    at = assembly_put_text(w, at, AS_CODE, get(w, AS_JSON_CODE_BYTES))
    at = assembly_put_text(w, at, AS_L_line_AT, AS_L_line_BYTES)
    if get(w, AS_ERROR_LINE) == 0:
        store(w, AS_FRAGMENT + at, 110)
        store(w, AS_FRAGMENT + at + 1, 117)
        store(w, AS_FRAGMENT + at + 2, 108)
        store(w, AS_FRAGMENT + at + 3, 108)
        at = at + 4
    else:
        at = at + decimal_text(w, AS_FRAGMENT + at, get(w, AS_ERROR_LINE))
    return assembly_put_text(w, at, AS_L_message_AT, AS_L_message_BYTES)

def assembly_rejected_suffix(w:mutbuf) -> u64:
    at = 0
    if get(w, AS_ERROR_PHASE) == 0:
        at = assembly_put_text(w, at, AS_L_phase_syntax_AT, AS_L_phase_syntax_BYTES)
    else:
        at = assembly_put_text(w, at, AS_L_phase_core_AT, AS_L_phase_core_BYTES)
    at = assembly_put_text(w, at, AS_L_rejected_tail_AT, AS_L_rejected_tail_BYTES)
    return assembly_source_suffix(w, at)

def assembly_escape_chunk(w:mutbuf) -> u64:
    at = 0
    index = 0
    while index < get(w, AS_JSON_CHUNK):
        part = byte(w, OBS + index)
        if part == 34 or part == 92:
            store(w, AS_FRAGMENT + at, 92)
            at = at + 1
        elif part < 32:
            store(w, AS_FRAGMENT + at, 92)
            at = at + 1
            short = 0
            if part == 8:
                short = 98
            elif part == 9:
                short = 116
            elif part == 10:
                short = 110
            elif part == 12:
                short = 102
            elif part == 13:
                short = 114
            if short != 0:
                store(w, AS_FRAGMENT + at, short)
                at = at + 1
            else:
                store(w, AS_FRAGMENT + at, 117)
                store(w, AS_FRAGMENT + at + 1, 48)
                store(w, AS_FRAGMENT + at + 2, 48)
                store(w, AS_FRAGMENT + at + 3, hex_digit(part >> 4))
                store(w, AS_FRAGMENT + at + 4, hex_digit(part & 15))
                at = at + 5
            part = 256
        if part != 256:
            store(w, AS_FRAGMENT + at, part)
            at = at + 1
        index = index + 1
    return at

def assembly_publication_literals(w:mutbuf) -> u64:
    if get(w, AS_MAGIC) != AS_STATE_MAGIC or get(w, AS_MODE) != 1 or get(w, AS_DIGEST_DONE) != 1 or get(w, A_ACTION) != 4:
        return 0
    copy_local(w, A_TEXT1, AS_L_pub_first_AT, AS_L_pub_first_BYTES)
    hex_digest(w, E_CORE_HASH, A_TEXT1 + AS_L_pub_first_BYTES)
    copy_local(w, A_TEXT1 + AS_L_pub_first_BYTES + 64, AS_L_pub_second_AT, AS_L_pub_second_BYTES)
    copy_local(w, A_TEXT2, AS_L_pub_third_AT, AS_L_pub_third_BYTES)
    copy_local(w, A_TEXT3, AS_L_pub_last_AT, AS_L_pub_last_BYTES)
    copy_local(w, A_EXPECT, AS_L_receipt_first_AT, AS_L_receipt_first_BYTES)
    count = AS_L_receipt_first_BYTES + decimal_text(w, A_EXPECT + AS_L_receipt_first_BYTES, get(w, AS_TEXT_BYTES))
    copy_local(w, A_EXPECT + count, AS_L_receipt_second_AT, AS_L_receipt_second_BYTES)
    count = count + AS_L_receipt_second_BYTES
    hex_digest(w, AS_HASH_TEXT, A_EXPECT + count)
    store(w, A_EXPECT + count + 64, 34)
    store(w, A_EXPECT + count + 65, 125)
    return count + 66

def publication_text_bytes(w:mutbuf, index:u64) -> u64:
    if get(w, A_ACTION) == 4:
        if index == 1:
            return AS_PUB_TEXT1_BYTES
        if index == 2:
            return AS_PUB_TEXT2_BYTES
        if index == 3:
            return AS_PUB_TEXT3_BYTES
    else:
        if index == 1:
            return A_TEXT1_BYTES
        if index == 2:
            return A_TEXT2_BYTES
        if index == 3:
            return A_TEXT3_BYTES
    return 0

'''
def literal_source():
    cursor=CONSTANTS["AS_LITERAL_BASE"];writes=[];constants=dict(CONSTANTS)
    for key,value in LITERALS.items():
        raw=value.encode("utf-8");constants["AS_L_"+key+"_AT"]=cursor
        constants["AS_L_"+key+"_BYTES"]=len(raw)
        for at in range(0,len(raw),8):
            part=raw[at:at+8]
            if len(part)==8:writes.append("put(w, %d, %d)"%(cursor+at,int.from_bytes(part,"little")))
            else:
                writes.extend("store(w, %d, %d)"%(cursor+at+i,v) for i,v in enumerate(part))
        cursor+=len(raw)+8;cursor=(cursor+7)&~7
    assert cursor<CONSTANTS["AS_LITERAL_LIMIT"]
    bodies=[];calls=[]
    for at in range(0,len(writes),16):
        name="asm_literals_"+str(at//16);calls.append("    "+name+"(w)")
        bodies.append("def "+name+"(w:mutbuf) -> u64:\n"+
            "\n".join("    "+line for line in writes[at:at+16])+"\n    return 0\n")
    bodies.append("def assembly_literals(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n")
    for suffix in ("at","bytes"):
        bodies.append("def assembly_object_message_"+suffix+"(reason:u64) -> u64:\n"+
            "\n".join("    if reason == %d:\n        return %d"%(i,constants["AS_L_object"+str(i)+"_"+suffix.upper()]) for i in range(1,6))+"\n    return 0\n")
    return BODY+"\n"+"\n".join(bodies),constants
