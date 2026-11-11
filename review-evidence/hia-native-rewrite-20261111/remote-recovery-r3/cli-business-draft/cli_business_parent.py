"""CLI business-parent continuation, new unexecuted HIA authoring source.

The base capture/parser/file/formatter owners remain source-bound. This module
extends only HIA orchestration after the original initial file gate. The carrier
does not parse these fields. Publication is an explicit open dependency; its
request retires the child and fails closed until a complete native publisher is
bound. No installed dispatch or whole-CLI claim follows from this source.
"""
import ast
from hashlib import sha256
from pathlib import Path
import cli_entry_owner as _base

BASE_SHA="d47f72eccb763bd4cc7ffb2a92aac7e96e3178c9f4df3c1bb60b9ccd68f0221c"
assert sha256(Path(_base.__file__).read_bytes()).hexdigest()==BASE_SHA
CONSTANTS=dict(_base.CONSTANTS)
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
CONSTANTS.update(BUSINESS_INIT=magic("HIACBI01"),BUSINESS_REPLY=magic("HIACBR01"),
    BUSINESS_EVENT=magic("HIACBE01"),BUSINESS_ACK=magic("HIACBA01"),
    BUSINESS_LEASES=magic("HIALSV01"))
_names=("ACTIVE","SERVICE","LEASE","SEQUENCE","REQUEST","FILES","PROGRAM_AT",
        "PROGRAM_BYTES","LIFECYCLE","VERB","KIND","FORMAT","PAYLOAD_AT","PAYLOAD_BYTES",
        "FIELD","TARGET","FILE_FIELD","FILE_LIMIT","FILE_SLOT","FILE_RETURN",
        "FILE_ERROR_RETURN","DIAG_POS","DIAG_OUT","DIAG_CHUNK")
CONSTANTS.update({"B_"+name:14000+i*8 for i,name in enumerate(_names)})
COMMON=_base.COMMON
literals=_base.literals

def one(text,before,after):
    assert text.count(before)==1,(before,text.count(before))
    return text.replace(before,after,1)

base_body=_base.BODY
base_body=one(base_body,
    "        put(w, S_FD, MAX)\n    else:",
    "        put(w, S_FD, MAX)\n"
    "        put(w, B_FILE_FIELD, 1)\n"
    "        put(w, B_FILE_LIMIT, 8388608)\n"
    "        put(w, B_FILE_SLOT, 11)\n"
    "        put(w, B_FILE_RETURN, 898)\n"
    "        put(w, B_FILE_ERROR_RETURN, 190)\n    else:")
base_body=one(base_body,
    "        elif phase == 900:\n            return business_handoff(o, w)\n",
    "        elif phase >= 900 and phase < 990:\n"
    "            result = business_step(o, w, phase)\n")

class FileSlots(ast.NodeTransformer):
    def visit_Constant(self,node):
        if type(node.value) is int and node.value==11:
            return ast.parse("get(w, B_FILE_SLOT)",mode="eval").body
        return node

nodes=[]
for node in ast.parse(base_body).body:
    if node.name=="business_handoff":
        continue
    if node.name in ("file_begin","file_request","file_response"):
        node=FileSlots().visit(node)
        text=ast.unparse(node)
        if node.name=="file_begin":
            text=one(text,"view(o, w, 6, 1056, 32, 101)",
                "view(o, w, 6, 1024 + get(w, B_FILE_FIELD) * 32, 32, 101)")
            text=one(text,
                "wire8(w, FILE_COMMAND, 1, 1, 1, 8388608,",
                "wire8(w, FILE_COMMAND, 1, 1, 1, get(w, B_FILE_LIMIT),")
            text=one(text,
                "protect(o, w, get(w, B_FILE_SLOT), 1, 898)",
                "protect(o, w, get(w, B_FILE_SLOT), 1, get(w, B_FILE_RETURN))")
            text=one(text,
                "get(w, OBS + 88), 190)",
                "get(w, OBS + 88), get(w, B_FILE_ERROR_RETURN))")
        node=ast.parse(text).body[0]
    nodes.append(ast.unparse(node))
BODY="\n".join(nodes)+"\n"

BODY+=r'''
def business_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase >= 900 and phase < 920:
        return business_begin_step(o, w, phase)
    if phase >= 920 and phase < 950:
        return business_file_step(o, w, phase)
    if phase >= 950 and phase < 960:
        return business_finish_step(o, w, phase)
    if phase >= 960 and phase < 970:
        return business_diagnostic_step(o, w, phase)
    if phase == 980:
        return business_retire(o, w, 981)
    if phase == 981:
        return refuse(w, 399)
    return refuse(w, 300)

def business_begin_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 900:
        if get(w, B_ACTIVE) != 0 or get(w, S_FD) != MAX:
            return refuse(w, 301)
        action = get(w, S_ACTION)
        service = 0
        if action >= 6 and action <= 8:
            service = 1
        elif action >= 12 and action <= 15:
            service = 2
        if service == 0:
            return refuse(w, 302)
        put(w, B_SERVICE, service)
        put(w, B_LEASE, 2)
        put(w, B_SEQUENCE, 0)
        put(w, B_REQUEST, 0)
        put(w, B_FILES, 0)
        put(w, B_PROGRAM_AT, get(w, S_RESULT_AT))
        put(w, B_PROGRAM_BYTES, get(w, S_RESULT_BYTES))
        return grow(o, w, 13, 128, 901)
    if phase == 901:
        return grow(o, w, 14, 128, 902)
    if phase == 902:
        zero(w, WIRE, 128)
        wire8(w, BUSINESS_LEASES, 1, 3, 128, 11, get(w, B_PROGRAM_AT), get(w, B_PROGRAM_BYTES), 1)
        put(w, WIRE + 64, 4)
        put(w, WIRE + 80, cap(w, 4))
        put(w, WIRE + 88, 4)
        put(w, WIRE + 96, 6)
        put(w, WIRE + 112, cap(w, 6))
        put(w, WIRE + 120, 5)
        return copy(o, w, 2, WIRE, 14, 0, 128, 903)
    if phase == 903:
        return protect(o, w, 14, 1, 904)
    if phase == 904:
        if get(w, C_SEQUENCE) > MAX - 3:
            return refuse(w, 303)
        zero(w, WIRE, 128)
        wire8(w, BUSINESS_INIT, 1, get(w, B_SERVICE), get(w, B_LEASE), get(w, C_LEASE), get(w, C_SEQUENCE) + 3, get(w, S_ACTION), 4300)
        put(w, WIRE + 64, get(w, B_PROGRAM_BYTES))
        put(w, WIRE + 72, cap(w, 4))
        put(w, WIRE + 80, cap(w, 6))
        put(w, WIRE + 88, 16)
        put(w, WIRE + 96, 1024)
        put(w, WIRE + 104, 32)
        return copy(o, w, 2, WIRE, 13, 0, 128, 905)
    if phase == 905:
        return protect(o, w, 13, 1, 906)
    if phase == 906:
        put(w, B_ACTIVE, 1)
        return business_call(o, w, 1, 128, 908)
    if phase == 908:
        if get(w, C_RETURN) != 0 or get(w, OBS) != BUSINESS_ACK or get(w, OBS + 8) != 1:
            return refuse(w, 304)
        if get(w, OBS + 16) != get(w, B_SERVICE) or get(w, OBS + 24) != get(w, B_LEASE) or get(w, OBS + 32) != get(w, B_LEASE):
            return refuse(w, 305)
        if get(w, OBS + 40) <= get(w, B_SEQUENCE) or get(w, OBS + 48) != 56 or get(w, OBS + 56) > 1:
            return refuse(w, 306)
        if get(w, OBS + 64) != 15 or get(w, OBS + 72) < 128 or get(w, OBS + 80) != get(w, B_VERB) or get(w, OBS + 88) != get(w, C_SEQUENCE):
            return refuse(w, 307)
        at = 96
        while at < 128:
            if get(w, OBS + at) != 0:
                return refuse(w, 308)
            at = at + 8
        put(w, B_SEQUENCE, get(w, OBS + 40))
        put(w, B_LIFECYCLE, get(w, OBS + 56))
        put(w, CAPS + 15 * 8, get(w, OBS + 72))
        return view(o, w, 15, 0, 128, 909)
    if phase == 909:
        return business_result(o, w)
    return refuse(w, 309)

def business_call(o:mutbuf, w:mutbuf, verb:u64, tablebytes:u64, nextphase:u64) -> u32:
    if get(w, C_PENDING) != 0 or get(w, S_FD) != MAX or cap(w, 15) != 0:
        return refuse(w, 310)
    if inside(w, 13, 0, 128) == 0 or inside(w, 14, 0, tablebytes) == 0 or verb < 1 or verb > 2:
        return refuse(w, 311)
    put(w, B_VERB, verb)
    put(w, C_OBSERVE, 128)
    args(w, verb, get(w, B_SERVICE), get(w, B_LEASE), 13, 0, 128, 14, 0, tablebytes, 15, get(w, B_SEQUENCE), 0)
    return event(o, w, 17, nextphase)

def business_result(o:mutbuf, w:mutbuf) -> u32:
    if get(w, OBS) != BUSINESS_EVENT or get(w, OBS + 8) != 1 or get(w, OBS + 16) != get(w, B_SERVICE) or get(w, OBS + 24) != get(w, B_LEASE):
        return refuse(w, 312)
    if get(w, OBS + 32) != get(w, B_SEQUENCE) or get(w, OBS + 120) != 0 or get(w, OBS + 112) != cap(w, 15):
        return refuse(w, 313)
    size = get(w, OBS + 104)
    at = get(w, OBS + 96)
    if size > MAX - 128 or cap(w, 15) != 128 + size:
        return refuse(w, 314)
    if size == 0:
        if at != 0:
            return refuse(w, 315)
    elif at != 128:
        return refuse(w, 316)
    put(w, B_KIND, get(w, OBS + 48))
    put(w, B_FORMAT, get(w, OBS + 80))
    put(w, B_PAYLOAD_AT, at)
    put(w, B_PAYLOAD_BYTES, size)
    kind = get(w, B_KIND)
    if kind == 1 or kind == 2:
        if get(w, B_LIFECYCLE) != 0 or get(w, OBS + 56) != 0 or get(w, OBS + 64) != 0:
            return refuse(w, 317)
        if get(w, B_REQUEST) == MAX or get(w, OBS + 40) != get(w, B_REQUEST) + 1 or get(w, OBS + 88) < 4 or get(w, OBS + 88) >= 64:
            return refuse(w, 318)
        put(w, B_REQUEST, get(w, OBS + 40))
        put(w, B_FIELD, get(w, OBS + 72))
        put(w, B_TARGET, get(w, OBS + 88))
        if kind == 2:
            if get(w, B_FIELD) != 2 or get(w, B_FORMAT) < 1 or get(w, B_FORMAT) > 3:
                return refuse(w, 319)
            # Publication's exact HIA filesystem owner is still an explicit open dependency.
            put(w, C_PHASE, 980)
            return 0
        if size != 0 or business_file_policy(w) == 0:
            return refuse(w, 320)
        put(w, C_PHASE, 920)
        return 0
    if get(w, B_LIFECYCLE) != 1 or get(w, OBS + 40) != 0 or get(w, OBS + 72) != 0 or get(w, OBS + 88) != 0:
        return refuse(w, 321)
    if kind == 3:
        if get(w, OBS + 56) != 0 or get(w, OBS + 64) > 1 or get(w, B_FORMAT) < 1 or get(w, B_FORMAT) > 2:
            return refuse(w, 322)
        put(w, S_EXIT, get(w, OBS + 64))
    elif kind == 4:
        if get(w, OBS + 56) < 1 or get(w, OBS + 56) > 4 or get(w, OBS + 64) != 2 or get(w, B_FORMAT) != 0:
            return refuse(w, 323)
        put(w, S_EXIT, 2)
    else:
        return refuse(w, 324)
    put(w, C_PHASE, 952)
    return 0

def business_file_policy(w:mutbuf) -> u64:
    action = get(w, S_ACTION)
    count = get(w, B_FILES)
    field = 0
    budget = 0
    if action == 13:
        if count == 0:
            field = 13
            budget = 8388608
        elif count == 1:
            field = 14
            budget = 16384
    elif action == 14:
        if count == 0:
            field = 12
            budget = 8388608
    elif action == 15:
        if count == 0:
            field = 13
            budget = 1048576
        elif count == 1:
            field = 14
            budget = 65536
    if field == 0 or get(w, B_FIELD) != field or get(w, B_FORMAT) != budget:
        return 0
    put(w, B_FILE_FIELD, field)
    put(w, B_FILE_LIMIT, budget)
    put(w, B_FILE_SLOT, 18 + count)
    put(w, B_FILE_RETURN, 935)
    put(w, B_FILE_ERROR_RETURN, 950)
    put(w, B_FILES, count + 1)
    return 1

def business_file_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 920:
        return protect(o, w, 8, 0, 100)
    if phase == 935:
        return protect(o, w, 13, 0, 936)
    if phase == 936:
        return protect(o, w, 14, 0, 937)
    if phase == 937:
        return release(o, w, 15, 938)
    if phase == 938:
        zero(w, WIRE, 64)
        wire8(w, BUSINESS_LEASES, 1, 1, 64, get(w, B_FILE_SLOT), get(w, S_RESULT_AT), get(w, S_RESULT_BYTES), get(w, B_TARGET))
        return copy(o, w, 2, WIRE, 14, 0, 64, 939)
    if phase == 939:
        return protect(o, w, 14, 1, 940)
    if phase == 940:
        if get(w, C_SEQUENCE) > MAX - 3:
            return refuse(w, 325)
        zero(w, WIRE, 128)
        wire8(w, BUSINESS_REPLY, 1, get(w, B_SERVICE), get(w, B_LEASE), get(w, B_SEQUENCE), get(w, B_REQUEST), 1, get(w, C_SEQUENCE) + 3)
        put(w, WIRE + 64, get(w, B_FIELD))
        put(w, WIRE + 72, get(w, B_TARGET))
        put(w, WIRE + 80, get(w, S_RESULT_BYTES))
        put(w, WIRE + 88, get(w, B_FORMAT))
        return copy(o, w, 2, WIRE, 13, 0, 128, 941)
    if phase == 941:
        return protect(o, w, 13, 1, 942)
    if phase == 942:
        return business_call(o, w, 2, 64, 908)
    return refuse(w, 326)

def business_retire(o:mutbuf, w:mutbuf, nextphase:u64) -> u32:
    if get(w, B_ACTIVE) != 1 or get(w, C_PENDING) != 0 or get(w, S_FD) != MAX:
        return refuse(w, 327)
    put(w, C_OBSERVE, 0)
    args(w, 3, get(w, B_SERVICE), get(w, B_LEASE), 0, 0, 0, 0, 0, 0, 0, get(w, B_SEQUENCE), 0)
    return event(o, w, 17, nextphase)

def business_finish_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 950:
        return business_retire(o, w, 951)
    if phase == 951:
        put(w, B_ACTIVE, 0)
        put(w, C_PHASE, 190)
        return 0
    if phase == 952:
        return business_retire(o, w, 953)
    if phase == 953:
        put(w, B_ACTIVE, 0)
        if get(w, B_KIND) == 4:
            put(w, C_PHASE, 960)
            return 0
        if get(w, B_KIND) != 3:
            return refuse(w, 328)
        if get(w, B_FORMAT) == 1:
            put(w, S_SOURCE_SLOT, 15)
            put(w, S_SOURCE_AT, get(w, B_PAYLOAD_AT))
            put(w, S_SOURCE_BYTES, get(w, B_PAYLOAD_BYTES))
            return protect(o, w, 8, 0, 70)
        put(w, S_STDOUT_SLOT, 15)
        put(w, S_STDOUT_AT, get(w, B_PAYLOAD_AT))
        put(w, S_STDOUT_BYTES, get(w, B_PAYLOAD_BYTES))
        put(w, S_STDERR_SLOT, 0)
        put(w, S_STDERR_AT, 0)
        put(w, S_STDERR_BYTES, 0)
        put(w, C_PHASE, 999)
        return 0
    return refuse(w, 329)

def business_diagnostic_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 960:
        if get(w, B_PAYLOAD_BYTES) > (MAX - 95) // 6:
            return refuse(w, 330)
        diagnostic_literals(w)
        store(w, 30045, 34)
        store(w, 30099, 34)
        put(w, B_DIAG_POS, 0)
        put(w, B_DIAG_OUT, 46)
        return grow(o, w, 16, get(w, B_PAYLOAD_BYTES) * 6 + 95, 961)
    if phase == 961:
        return copy(o, w, 2, 30000, 16, 0, 46, 962)
    if phase == 962:
        if get(w, B_DIAG_POS) == get(w, B_PAYLOAD_BYTES):
            return copy(o, w, 2, 30099, 16, get(w, B_DIAG_OUT), 49, 966)
        if get(w, B_DIAG_POS) > get(w, B_PAYLOAD_BYTES):
            return refuse(w, 331)
        count = get(w, B_PAYLOAD_BYTES) - get(w, B_DIAG_POS)
        if count > 256:
            count = 256
        put(w, B_DIAG_CHUNK, count)
        return view(o, w, 15, get(w, B_PAYLOAD_AT) + get(w, B_DIAG_POS), count, 963)
    if phase == 963:
        target = 32000
        i = 0
        while i < get(w, B_DIAG_CHUNK):
            part = byte(w, OBS + i)
            if part == 34 or part == 92:
                store(w, target, 92)
                target = target + 1
            elif part < 32:
                store(w, target, 92)
                store(w, target + 1, 117)
                store(w, target + 2, 48)
                store(w, target + 3, 48)
                store(w, target + 4, hex_digit(part >> 4))
                store(w, target + 5, hex_digit(part & 15))
                target = target + 6
                part = 256
            if part != 256:
                store(w, target, part)
                target = target + 1
            i = i + 1
        offset = get(w, B_DIAG_OUT)
        put(w, B_DIAG_OUT, offset + target - 32000)
        put(w, B_DIAG_POS, get(w, B_DIAG_POS) + get(w, B_DIAG_CHUNK))
        return copy(o, w, 2, 32000, 16, offset, target - 32000, 962)
    if phase == 966:
        put(w, B_DIAG_OUT, get(w, B_DIAG_OUT) + 49)
        put(w, S_SOURCE_SLOT, 16)
        put(w, S_SOURCE_AT, 0)
        put(w, S_SOURCE_BYTES, get(w, B_DIAG_OUT))
        put(w, S_EXIT, 2)
        return protect(o, w, 16, 1, 967)
    if phase == 967:
        return protect(o, w, 8, 0, 70)
    return refuse(w, 332)
'''
