"""Native publication-to-fixed-filesystem controller, new development.

Role 7 drives exact role-8 publish_verified and role-10 SHA256 images. The only
external operations are issued primitive 19 and the original buffer/call ABI.
The small private command-file entry is development transport, not public CLI
path parsing. Publication path/staging integration remains a separate owner.
"""
import ast,importlib.util
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
LOWER=ROOT/"reference/hia_composite_lowering_driver_common.py"
assert sha256(LOWER.read_bytes()).hexdigest()=="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
spec=importlib.util.spec_from_file_location("publication_fixed_common",LOWER)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
KEEP={"word","get","put","zero","refuse","args","event","acknowledge","cap","inside",
      "grow","release","copy","clear","protect","view","invoke"}
nodes=[n for n in ast.parse(common.COMMON).body if n.name in KEEP]
acks=[n for n in nodes if n.name=="acknowledge"];assert len(acks)==1
before=ast.parse("pending != 1 and pending != 14 and word(s, 40) != 0",mode="eval").body
after=ast.parse("pending != 1 and pending != 14 and pending != 19 and word(s, 40) != 0",mode="eval").body
matches=[n for n in ast.walk(acks[0]) if isinstance(n,ast.If) and ast.dump(n.test)==ast.dump(before)]
assert len(matches)==1;matches[0].test=after
COMMON="\n".join(ast.unparse(n) for n in nodes)+"\n"
def magic(s):return int.from_bytes(s.encode(),"little")
CONSTANTS=dict(common.CONSTANTS)
CONSTANTS.update(MIN_WORK=65536,LOWER_MAGIC=magic("HIAPFD01"),
    CLI_INIT=magic("HIACLI01"),CAPTURE=magic("HIACOS01"),
    PUB_COMMAND=magic("HIAPVC01"),PUB_EVENT=magic("HIAPVE01"),PUB_ACK=magic("HIAPVA01"),
    FIXED_OUTPUT=magic("HIAPFX01"),PE=16000,
    IN_BYTES=16200,IN_AT=16208,IN_REQUEST=16216,IN_PATH_AT=16224,IN_PATH_BYTES=16232,
    P_LEASE=16240,P_SEQ=16248,P_REPLY_BYTES=16256,P_RAW=16264,P_DATA=16272,
    P_DATA_SLOT=16280,P_VALUE_SLOT=16288,P_VALUE_AT=16296,P_VALUE_BYTES=16304,
    H_AT=16312,H_COUNT=16320,P_PUBLICATION_CALLS=16328,P_FS_CALLS=16336,
    P_HASH_CALLS=16344,P_GROWS=16352,P_INPUT_READS=16360,P_ERROR=16368)
BODY=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK or length(o) != 128:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 64 or word(s, 0) != CLI_INIT or word(s, 8) != 1:
            return refuse(w, 8800)
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, 7)
        put(w, C_LEASE, 1)
        put(w, C_PHASE, 1)
        put(w, CAPS + 8, word(s, 16))
        put(w, CAPS + 16, MIN_WORK)
        put(w, CAPS + 24, 128)
    elif acknowledge(s, w, 7) == 0:
        return refuse(w, 8801)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        result = 0
        if phase < 20:
            result = input_step(o, w, phase)
        elif phase < 40:
            result = publication_step(o, w, phase)
        elif phase < 80:
            result = hash_step(o, w, phase)
        else:
            result = final_step(o, w, phase)
        if result != 0:
            return result
    return ABI

def fs(o:mutbuf, w:mutbuf, kind:u64, token:u64, first:u64, at:u64, count:u64, a:u64, second:u64, to:u64, size:u64, b:u64, next:u64) -> u32:
    put(w, C_OBSERVE, 0)
    args(w, kind, token, first, at, count, a, second, to, size, b, 0, 0)
    put(w, P_FS_CALLS, get(w, P_FS_CALLS) + 1)
    return event(o, w, 19, next)

def raw_error(value:u64) -> u64:
    if value >= 18446744073709547521:
        return MAX - value + 1
    return 0

def input_step(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 1:
        return view(o, w, 1, 0, 96, 2)
    if phase == 2:
        if get(w, OBS) != CAPTURE or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 2:
            return refuse(w, 8802)
        if get(w, OBS + 32) != 96 or get(w, OBS + 48) != cap(w, 1):
            return refuse(w, 8803)
        return view(o, w, 1, 112, 16, 3)
    if phase == 3:
        at = get(w, OBS)
        count = get(w, OBS + 8)
        if count == 0 or count == MAX or inside(w, 1, at, count) == 0:
            return refuse(w, 8804)
        put(w, IN_PATH_AT, at)
        put(w, IN_PATH_BYTES, count)
        return grow(o, w, 12, count + 1, 4)
    if phase == 4:
        return copy(o, w, 1, get(w, IN_PATH_AT), 12, 0, get(w, IN_PATH_BYTES), 5)
    if phase == 5:
        return protect(o, w, 12, 1, 6)
    if phase == 6:
        return grow(o, w, 7, 65536, 7)
    if phase == 7:
        return fs(o, w, 1, 0, 12, 0, get(w, IN_PATH_BYTES) + 1, 657408, 0, 0, 0, 0, 8)
    if phase == 8:
        if raw_error(get(w, C_RETURN)) != 0:
            return refuse(w, 8805)
        return fs(o, w, 3, 0, 7, 0, 144, 0, 0, 0, 0, 0, 9)
    if phase == 9:
        if get(w, C_RETURN) != 0:
            return refuse(w, 8806)
        return view(o, w, 7, 0, 144, 10)
    if phase == 10:
        count = get(w, OBS + 48)
        if (get(w, OBS + 24) & 61440) != 32768 or count < 66 or count == MAX:
            return refuse(w, 8807)
        put(w, IN_BYTES, count)
        return grow(o, w, 4, count + 1, 11)
    if phase == 11:
        remain = get(w, IN_BYTES) + 1 - get(w, IN_AT)
        if remain > 65536:
            remain = 65536
        put(w, IN_REQUEST, remain)
        put(w, P_INPUT_READS, get(w, P_INPUT_READS) + 1)
        return fs(o, w, 4, 0, 4, get(w, IN_AT), remain, 0, 0, 0, 0, 0, 12)
    if phase == 12:
        count = get(w, C_RETURN)
        if raw_error(count) == 4:
            put(w, C_PHASE, 11)
            return 0
        if raw_error(count) != 0 or count > get(w, IN_REQUEST):
            return refuse(w, 8808)
        if count == 0:
            if get(w, IN_AT) != get(w, IN_BYTES):
                return refuse(w, 8809)
            return fs(o, w, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13)
        put(w, IN_AT, get(w, IN_AT) + count)
        if get(w, IN_AT) > get(w, IN_BYTES):
            return refuse(w, 8810)
        put(w, C_PHASE, 11)
        return 0
    if phase == 13:
        if get(w, C_RETURN) != 0:
            return refuse(w, 8811)
        return protect(o, w, 4, 1, 14)
    if phase == 14:
        return view(o, w, 4, 0, 64, 15)
    if phase == 15:
        if get(w, OBS) != PUB_COMMAND or get(w, OBS + 8) != 1 or get(w, OBS + 56) != get(w, IN_BYTES):
            return refuse(w, 8812)
        if get(w, OBS + 16) == 0 or get(w, OBS + 24) == 0:
            return refuse(w, 8813)
        put(w, P_LEASE, get(w, OBS + 16))
        put(w, P_SEQ, get(w, OBS + 24))
        return grow(o, w, 5, 65600, 16)
    if phase == 16:
        return protect(o, w, 5, 1, 17)
    if phase == 17:
        return grow(o, w, 6, 4096, 18)
    if phase == 18:
        return grow(o, w, 10, 1184, 20)
    return refuse(w, 8814)

def publication_call(o:mutbuf, w:mutbuf) -> u32:
    put(w, P_PUBLICATION_CALLS, get(w, P_PUBLICATION_CALLS) + 1)
    return invoke(o, w, 8, 4, 0, get(w, IN_BYTES), 5, get(w, P_REPLY_BYTES), 6, cap(w, 6), 6, 256, 128, 21)

def value_slot(w:mutbuf, source:u64) -> u64:
    if source == 0:
        return 4
    if source == 1:
        return 6
    return 0

def publication_step(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 20:
        return publication_call(o, w)
    if phase == 21:
        i = 0
        while i < 128:
            store(w, PE + i, byte(w, OBS + i))
            i = i + 1
        if get(w, PE) != PUB_EVENT or get(w, PE + 16) != get(w, P_LEASE):
            return refuse(w, 8815)
        action = get(w, PE + 8)
        if get(w, C_RETURN) == 4294967294:
            if action != 1 or get(w, PE + 24) != get(w, P_SEQ) or get(w, P_REPLY_BYTES) != 0 or get(w, PE + 112) <= cap(w, 6):
                return refuse(w, 8816)
            put(w, P_GROWS, get(w, P_GROWS) + 1)
            return grow(o, w, 6, get(w, PE + 112), 20)
        if get(w, C_RETURN) != 128:
            return refuse(w, 8817)
        if action == 0:
            if get(w, PE + 24) != get(w, P_SEQ) or get(w, PE + 40) > 2:
                return refuse(w, 8818)
            slot = value_slot(w, get(w, PE + 64))
            if slot == 0 or inside(w, slot, get(w, PE + 72), get(w, PE + 80)) == 0:
                return refuse(w, 8819)
            if get(w, PE + 80) > MAX - 192:
                return refuse(w, 8820)
            put(w, P_VALUE_SLOT, slot)
            put(w, P_VALUE_AT, get(w, PE + 72))
            put(w, P_VALUE_BYTES, get(w, PE + 80))
            return grow(o, w, 13, 192 + get(w, P_VALUE_BYTES), 80)
        if action != 2 and action != 3:
            return refuse(w, 8821)
        if get(w, P_SEQ) == MAX or get(w, PE + 24) != get(w, P_SEQ) + 1:
            return refuse(w, 8822)
        put(w, P_SEQ, get(w, PE + 24))
        if action == 3:
            if get(w, PE + 32) != 9 or get(w, PE + 64) != 0 or inside(w, 4, get(w, PE + 72), get(w, PE + 80)) == 0:
                return refuse(w, 8823)
            put(w, H_AT, 0)
            return grow(o, w, 9, 1, 40)
        return protect(o, w, 6, 1, 22)
    if phase == 22:
        return issue_publication_fs(o, w)
    if phase == 23:
        put(w, P_RAW, get(w, C_RETURN))
        return protect(o, w, 6, 0, 24)
    if phase == 24:
        if build_reply(w) == 0:
            return refuse(w, 8824)
        return protect(o, w, 5, 0, 25)
    if phase == 25:
        return grow(o, w, 5, get(w, P_REPLY_BYTES), 26)
    if phase == 26:
        return copy(o, w, 2, WIRE, 5, 0, 64, 27)
    if phase == 27:
        if get(w, P_DATA) != 0:
            return copy(o, w, get(w, P_DATA_SLOT), 0, 5, 64, get(w, P_DATA), 28)
        put(w, C_PHASE, 28)
        return 0
    if phase == 28:
        return protect(o, w, 5, 1, 20)
    return refuse(w, 8825)

def issue_publication_fs(o:mutbuf, w:mutbuf) -> u32:
    op = get(w, PE + 32)
    slot = value_slot(w, get(w, PE + 64))
    at = get(w, PE + 72)
    count = get(w, PE + 80)
    if op == 1 or op == 2 or op == 3 or op == 8 or op == 7:
        if slot == 0 or inside(w, slot, at, count) == 0:
            return refuse(w, 8826)
    if op == 1:
        return fs(o, w, 8, 0, slot, at, count, 0, 7, 0, 144, 0, 23)
    if op == 2:
        return fs(o, w, 7, 0, slot, at, count, 0, 7, 0, 144, 0, 23)
    if op == 3:
        return fs(o, w, 1, 0, slot, at, count, get(w, PE + 88), 0, 0, 0, 0, 23)
    if op == 4:
        return fs(o, w, 3, 0, 7, 0, 144, 0, 0, 0, 0, 0, 23)
    if op == 5:
        if count > 65536:
            return refuse(w, 8827)
        return fs(o, w, 4, 0, 7, 0, count, 0, 0, 0, 0, 0, 23)
    if op == 6:
        return fs(o, w, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23)
    if op == 7:
        second = value_slot(w, get(w, PE + 88))
        if second == 0 or inside(w, second, get(w, PE + 96), get(w, PE + 104)) == 0:
            return refuse(w, 8828)
        return fs(o, w, 9, 0, slot, at, count, 0, second, get(w, PE + 96), get(w, PE + 104), 0, 23)
    if op == 8:
        return fs(o, w, 10, 0, slot, at, count, 0, 0, 0, 0, 0, 23)
    return refuse(w, 8829)

def build_reply(w:mutbuf) -> u64:
    op = get(w, PE + 32)
    value = get(w, P_RAW)
    error = raw_error(value)
    result = 0
    size = 0
    slot = 7
    if error == 0:
        if op == 1 or op == 2 or op == 4:
            if value != 0:
                return 0
            size = 144
        elif op == 3:
            result = 1
        elif op == 5:
            if value > get(w, PE + 80):
                return 0
            result = value
            size = value
        elif op == 9:
            if value != 0:
                return 0
            size = 32
            slot = 3
        elif (op != 6 and op != 7 and op != 8) or value != 0:
            return 0
    zero(w, WIRE, 64)
    put(w, WIRE, PUB_ACK)
    put(w, WIRE + 8, get(w, P_LEASE))
    put(w, WIRE + 16, get(w, P_SEQ))
    put(w, WIRE + 24, op)
    if error != 0:
        put(w, WIRE + 32, 1)
    put(w, WIRE + 40, result)
    put(w, WIRE + 48, error)
    put(w, WIRE + 56, size)
    put(w, P_REPLY_BYTES, 64 + size)
    put(w, P_DATA, size)
    put(w, P_DATA_SLOT, slot)
    return 1

def hash_call(o:mutbuf, w:mutbuf, count:u64, phase:u64) -> u32:
    put(w, P_HASH_CALLS, get(w, P_HASH_CALLS) + 1)
    return invoke(o, w, 10, 9, 0, count, 3, 32, 10, 1184, 0, 0, 0, phase)

def hash_step(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 40:
        return protect(o, w, 9, 0, 41)
    if phase == 41:
        store(w, WIRE, 0)
        return copy(o, w, 2, WIRE, 9, 0, 1, 42)
    if phase == 42:
        return protect(o, w, 9, 1, 43)
    if phase == 43:
        return hash_call(o, w, 1, 44)
    if phase == 44:
        if get(w, C_RETURN) != 0:
            return refuse(w, 8830)
        put(w, C_PHASE, 45)
        return 0
    if phase == 45:
        if get(w, H_AT) == get(w, PE + 80):
            return protect(o, w, 9, 0, 54)
        if get(w, H_AT) > get(w, PE + 80):
            return refuse(w, 8831)
        count = get(w, PE + 80) - get(w, H_AT)
        if count > 8388608:
            count = 8388608
        put(w, H_COUNT, count)
        return protect(o, w, 9, 0, 46)
    if phase == 46:
        return grow(o, w, 9, get(w, H_COUNT) + 1, 47)
    if phase == 47:
        store(w, WIRE, 1)
        return copy(o, w, 2, WIRE, 9, 0, 1, 48)
    if phase == 48:
        return copy(o, w, 4, get(w, PE + 72) + get(w, H_AT), 9, 1, get(w, H_COUNT), 49)
    if phase == 49:
        return protect(o, w, 9, 1, 50)
    if phase == 50:
        return hash_call(o, w, get(w, H_COUNT) + 1, 51)
    if phase == 51:
        if get(w, C_RETURN) != 0:
            return refuse(w, 8832)
        put(w, H_AT, get(w, H_AT) + get(w, H_COUNT))
        put(w, C_PHASE, 45)
        return 0
    if phase == 54:
        store(w, WIRE, 2)
        return copy(o, w, 2, WIRE, 9, 0, 1, 55)
    if phase == 55:
        return protect(o, w, 9, 1, 56)
    if phase == 56:
        return hash_call(o, w, 1, 57)
    if phase == 57:
        if get(w, C_RETURN) != 32:
            return refuse(w, 8833)
        put(w, P_RAW, 0)
        put(w, C_PHASE, 24)
        return 0
    return refuse(w, 8834)

def final_step(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 80:
        zero(w, WIRE, 64)
        put(w, WIRE, FIXED_OUTPUT)
        put(w, WIRE + 8, 1)
        put(w, WIRE + 16, get(w, P_PUBLICATION_CALLS))
        put(w, WIRE + 24, get(w, P_FS_CALLS))
        put(w, WIRE + 32, get(w, P_HASH_CALLS))
        put(w, WIRE + 40, get(w, P_GROWS))
        put(w, WIRE + 48, get(w, P_INPUT_READS))
        put(w, WIRE + 56, 192 + get(w, P_VALUE_BYTES))
        return copy(o, w, 2, WIRE, 13, 0, 64, 81)
    if phase == 81:
        return copy(o, w, 2, PE, 13, 64, 128, 82)
    if phase == 82:
        if get(w, P_VALUE_BYTES) != 0:
            return copy(o, w, get(w, P_VALUE_SLOT), get(w, P_VALUE_AT), 13, 192, get(w, P_VALUE_BYTES), 83)
        put(w, C_PHASE, 83)
        return 0
    if phase == 83:
        return protect(o, w, 13, 1, 84)
    if phase == 84:
        zero(o, 0, 128)
        put(o, 0, EVENT_MAGIC)
        put(o, 8, 7)
        put(o, 16, get(w, C_LEASE))
        put(o, 24, get(w, C_SEQUENCE))
        if get(w, PE + 40) != 0:
            put(o, 32, 2)
        put(o, 40, 13)
        put(o, 56, 192 + get(w, P_VALUE_BYTES))
        put(w, L_STATUS, 2)
        return 128
    return refuse(w, 8835)
'''
def source():return BODY+COMMON,dict(CONSTANTS)
