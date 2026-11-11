"""New HIA CLI continuation owner: reconstructed development revision r5.
No activation or whole CLI closure is claimed. The fixed executor implements
only captured OS bytes, slots, primitive syscalls and HIA-selected output.
Successful file input currently produces an explicit unresolved service request.
This revision changes only the shared acknowledgement predicate for primitive
operation 16, by one asserted AST edit before unparse. Every other common check,
HIA phase, file owner and error presentation remains unchanged. The original
actual ENOENT rejection and its complete diagnostic frame remain preserved.
"""
from pathlib import Path
import ast,importlib.util
BASE=Path(__file__).resolve().parents[2]
_path=BASE/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py'
_spec=importlib.util.spec_from_file_location('cli_original_control_protocol',_path)
_shared=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_shared)
CONSTANTS=dict(_shared.CONSTANTS)
def magic(value):return int.from_bytes(value.encode(),'little')
CONSTANTS.update(MIN_WORK=65536,LOWER_MAGIC=magic('HIACLW01'),CLI_INIT=magic('HIACLI01'),
 CAP_EVENT=magic('HIACOE01'),ARG_EVENT=magic('HIACAE01'),FORMAT_EVENT=magic('HIACFO01'),
 META_EVENT=magic('HIAPME01'),META_COMMAND=magic('HIAPMC01'),PRETTY_EVENT=magic('HIAJPE01'),
 PRETTY_COMMAND=magic('HIAJPC01'),FILE_COMMAND=magic('HIAFRB01'),
 FILE_EVENT=magic('HIACRE01'),FILE_ACK=magic('HIAFRA01'),GROW=0xfffffffe)
_fields=('ACTION','EXIT','SOURCE_SLOT','SOURCE_AT','SOURCE_BYTES','RESULT_AT','RESULT_BYTES',
 'FILE_KIND','FILE_SEQ','FILE_REQUEST','FILE_REPLY','FD','TMP_AT','TMP_BYTES','COMMAND_BYTES',
 'META_EXPLICIT','STDOUT_SLOT','STDOUT_AT','STDOUT_BYTES','STDERR_SLOT','STDERR_AT','STDERR_BYTES',
 'READ_BYTES','FILE_ERROR')
CONSTANTS.update({'S_'+name:12288+i*8 for i,name in enumerate(_fields)})
_names={'word','get','put','zero','refuse','args','event','acknowledge','cap','inside',
 'grow','release','clear','copy','protect','invoke','view','wire8'}
# Adapt the one acknowledgement predicate in the AST before rendering it.
# ast.unparse may add parentheses; textual replacement after unparsing is not
# a semantic source edit and previously left raw ENOENT returns rejected.
_common_nodes=[n for n in ast.parse(_shared.COMMON).body if n.name in _names]
_ack_nodes=[n for n in _common_nodes if n.name == 'acknowledge']
assert len(_ack_nodes) == 1
_ack_before=ast.parse('pending != 1 and pending != 14 and word(s, 40) != 0',mode='eval').body
_ack_after=ast.parse('pending != 1 and pending != 14 and pending != 16 and word(s, 40) != 0',mode='eval').body
_ack_matches=[n for n in ast.walk(_ack_nodes[0]) if isinstance(n,ast.If)
              and ast.dump(n.test) == ast.dump(_ack_before)]
assert len(_ack_matches) == 1, ('exact acknowledgement predicate',len(_ack_matches))
_ack_matches[0].test=_ack_after
COMMON='\n'.join(ast.unparse(n) for n in _common_nodes)+'\n'
BODY=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK or length(o) != 128:
        return ABI
    if get(w, L_STATUS) == 3:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 64 or word(s, 0) != CLI_INIT or word(s, 8) != 1 or word(s, 16) < 96:
            return refuse(w, 100)
        i = 24
        while i < 64:
            if word(s, i) != 0:
                return refuse(w, 101)
            i = i + 8
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, DRIVER_MAIN)
        put(w, C_LEASE, 1)
        put(w, C_PHASE, 10)
        put(w, CAPS, 0)
        put(w, CAPS + 8, word(s, 16))
        put(w, CAPS + 16, MIN_WORK)
        put(w, CAPS + 24, 128)
        put(w, S_FD, MAX)
    else:
        if acknowledge(s, w, DRIVER_MAIN) == 0:
            return refuse(w, 102)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        result = ABI
        if phase >= 10 and phase < 20:
            result = capture_step(o, w, phase)
        elif phase >= 20 and phase < 40:
            result = arguments_step(o, w, phase)
        elif phase >= 40 and phase < 60:
            result = metadata_step(o, w, phase)
        elif phase >= 70 and phase < 80:
            result = pretty_step(o, w, phase)
        elif phase >= 100 and phase < 160:
            result = file_step(o, w, phase)
        elif phase >= 190 and phase < 200:
            result = diagnostic_step(o, w, phase)
        elif phase == 898:
            return protect(o, w, 6, 1, 900)
        elif phase == 900:
            return business_handoff(o, w)
        elif phase == 999:
            return terminal(o, w)
        else:
            return refuse(w, 103)
        if result != 0:
            return result
    return ABI

def capture_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 10:
        return grow(o, w, 5, 1024, 11)
    if phase == 11:
        return invoke(o, w, 1, 1, 0, cap(w, 1), 3, 128, 5, cap(w, 5), 5, 256, 128, 12)
    if phase == 12:
        if get(w, OBS) != CAP_EVENT:
            return refuse(w, 110)
        if get(w, OBS + 8) == 1:
            if get(w, C_RETURN) != GROW or get(w, OBS + 48) <= cap(w, 5):
                return refuse(w, 111)
            return grow(o, w, 5, get(w, OBS + 48), 11)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0 or get(w, OBS + 24) < 64:
            return refuse(w, 112)
        if inside(w, 5, get(w, OBS + 16), get(w, OBS + 24)) == 0:
            return refuse(w, 113)
        put(w, S_RESULT_AT, get(w, OBS + 16))
        put(w, S_RESULT_BYTES, get(w, OBS + 24))
        return grow(o, w, 4, get(w, S_RESULT_BYTES), 13)
    if phase == 13:
        return copy(o, w, 5, get(w, S_RESULT_AT), 4, 0, get(w, S_RESULT_BYTES), 14)
    if phase == 14:
        return protect(o, w, 4, 1, 15)
    if phase == 15:
        return release(o, w, 5, 20)
    return refuse(w, 114)

def arguments_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 20:
        return grow(o, w, 6, 1024, 21)
    if phase == 21:
        return invoke(o, w, 2, 4, 0, cap(w, 4), 3, 128, 6, cap(w, 6), 6, 256, 128, 22)
    if phase == 22:
        if get(w, OBS) != ARG_EVENT:
            return refuse(w, 120)
        if get(w, OBS + 8) == 1:
            if get(w, C_RETURN) != GROW or get(w, OBS + 112) <= cap(w, 6):
                return refuse(w, 121)
            return grow(o, w, 6, get(w, OBS + 112), 21)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) > 4:
            return refuse(w, 122)
        put(w, S_ACTION, get(w, OBS + 32))
        put(w, S_EXIT, get(w, OBS + 16))
        if get(w, OBS + 8) != 0:
            return grow(o, w, 7, 1024, 31)
        if get(w, S_ACTION) == 0 or get(w, S_ACTION) > 15 or get(w, S_EXIT) != 0 or get(w, OBS + 40) != 1024 or get(w, OBS + 48) != 16:
            return refuse(w, 123)
        if get(w, S_ACTION) <= 2:
            put(w, C_PHASE, 40)
        else:
            put(w, C_PHASE, 100)
        return 0
    if phase == 31:
        return invoke(o, w, 3, 4, 0, cap(w, 4), 6, cap(w, 6), 7, cap(w, 7), 7, 256, 128, 32)
    if phase == 32:
        if get(w, OBS) != FORMAT_EVENT:
            return refuse(w, 124)
        if get(w, OBS + 8) == 1:
            if get(w, C_RETURN) != GROW or get(w, OBS + 64) <= cap(w, 7):
                return refuse(w, 125)
            return grow(o, w, 7, get(w, OBS + 64), 31)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0 or get(w, OBS + 16) != get(w, S_EXIT) or get(w, OBS + 24) != get(w, S_ACTION):
            return refuse(w, 126)
        put(w, S_STDOUT_SLOT, 7)
        put(w, S_STDOUT_AT, get(w, OBS + 32))
        put(w, S_STDOUT_BYTES, get(w, OBS + 40))
        put(w, S_STDERR_SLOT, 7)
        put(w, S_STDERR_AT, get(w, OBS + 48))
        put(w, S_STDERR_BYTES, get(w, OBS + 56))
        return protect(o, w, 7, 1, 999)
    return refuse(w, 127)

def field_view(w:mutbuf) -> u64:
    if get(w, OBS) != 1:
        return 0
    owner = get(w, OBS + 8)
    if owner != 1 and owner != 2:
        return 0
    slot = 4
    if owner == 2:
        slot = 6
    if inside(w, slot, get(w, OBS + 16), get(w, OBS + 24)) == 0:
        return 0
    put(w, S_SOURCE_SLOT, slot)
    put(w, S_SOURCE_AT, get(w, OBS + 16))
    put(w, S_SOURCE_BYTES, get(w, OBS + 24))
    return 1

def metadata_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 40:
        if get(w, S_ACTION) == 2:
            return view(o, w, 6, 1024 + 3 * 32, 32, 41)
        put(w, S_SOURCE_SLOT, 0)
        put(w, S_SOURCE_AT, 0)
        put(w, S_SOURCE_BYTES, 0)
        put(w, S_META_EXPLICIT, 0)
        put(w, C_PHASE, 42)
        return 0
    if phase == 41:
        if field_view(w) == 0:
            return refuse(w, 130)
        put(w, S_META_EXPLICIT, 1)
        put(w, C_PHASE, 42)
        return 0
    if phase == 42:
        return grow(o, w, 8, 96, 43)
    if phase == 43:
        zero(w, WIRE, 96)
        wire8(w, META_COMMAND, 1, 1, 1, get(w, S_ACTION), get(w, S_META_EXPLICIT), get(w, S_SOURCE_BYTES), 0)
        return copy(o, w, 2, WIRE, 8, 0, 96, 44)
    if phase == 44:
        return protect(o, w, 8, 1, 45)
    if phase == 45:
        return grow(o, w, 9, 3072, 46)
    if phase == 46:
        return invoke(o, w, 4, get(w, S_SOURCE_SLOT), get(w, S_SOURCE_AT), get(w, S_SOURCE_BYTES), 8, 96, 9, cap(w, 9), 9, 2304, 128, 47)
    if phase == 47:
        if get(w, OBS) != META_EVENT or get(w, OBS + 16) != 1 or get(w, OBS + 24) != 1 or get(w, OBS + 32) != get(w, S_ACTION):
            return refuse(w, 131)
        if get(w, OBS + 8) == 1:
            if get(w, C_RETURN) != GROW or get(w, OBS + 56) <= cap(w, 9):
                return refuse(w, 132)
            return grow(o, w, 9, get(w, OBS + 56), 46)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0 or inside(w, 9, get(w, OBS + 40), get(w, OBS + 48)) == 0:
            return refuse(w, 133)
        put(w, S_SOURCE_SLOT, 9)
        put(w, S_SOURCE_AT, get(w, OBS + 40))
        put(w, S_SOURCE_BYTES, get(w, OBS + 48))
        put(w, S_EXIT, 0)
        return protect(o, w, 8, 0, 70)
    return refuse(w, 134)

def pretty_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 70:
        return grow(o, w, 8, 96, 71)
    if phase == 71:
        zero(w, WIRE, 96)
        wire8(w, PRETTY_COMMAND, 1, 1, 1, get(w, S_SOURCE_BYTES), 1, 0, 0)
        return copy(o, w, 2, WIRE, 8, 0, 96, 72)
    if phase == 72:
        return protect(o, w, 8, 1, 73)
    if phase == 73:
        return grow(o, w, 10, 1024, 74)
    if phase == 74:
        return invoke(o, w, 5, get(w, S_SOURCE_SLOT), get(w, S_SOURCE_AT), get(w, S_SOURCE_BYTES), 8, 96, 10, cap(w, 10), 10, 256, 128, 75)
    if phase == 75:
        if get(w, OBS) != PRETTY_EVENT or get(w, OBS + 16) != 1 or get(w, OBS + 24) != 1:
            return refuse(w, 140)
        if get(w, OBS + 8) == 1:
            if get(w, C_RETURN) != GROW or get(w, OBS + 48) <= cap(w, 10):
                return refuse(w, 141)
            return grow(o, w, 10, get(w, OBS + 48), 74)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0:
            return refuse(w, 142)
        put(w, S_STDOUT_SLOT, 10)
        put(w, S_STDOUT_AT, get(w, OBS + 32))
        put(w, S_STDOUT_BYTES, get(w, OBS + 40))
        put(w, S_STDERR_SLOT, 0)
        put(w, S_STDERR_AT, 0)
        put(w, S_STDERR_BYTES, 0)
        return protect(o, w, 10, 1, 999)
    return refuse(w, 143)

def file_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase < 120:
        return file_begin(o, w, phase)
    if phase < 140:
        return file_request(o, w, phase)
    return file_response(o, w, phase)

def file_begin(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 100:
        return view(o, w, 6, 1056, 32, 101)
    if phase == 101:
        if field_view(w) == 0 or get(w, S_SOURCE_BYTES) > MAX - 64:
            return refuse(w, 150)
        put(w, S_COMMAND_BYTES, 64 + get(w, S_SOURCE_BYTES))
        return grow(o, w, 8, get(w, S_COMMAND_BYTES), 102)
    if phase == 102:
        wire8(w, FILE_COMMAND, 1, 1, 1, 8388608, get(w, S_SOURCE_BYTES), 64, get(w, S_COMMAND_BYTES))
        return copy(o, w, 2, WIRE, 8, 0, 64, 103)
    if phase == 103:
        return copy(o, w, get(w, S_SOURCE_SLOT), get(w, S_SOURCE_AT), 8, 64, get(w, S_SOURCE_BYTES), 104)
    if phase == 104:
        return protect(o, w, 8, 1, 105)
    if phase == 105:
        return grow(o, w, 11, 1024, 106)
    if phase == 106:
        put(w, S_FILE_REPLY, 0)
        put(w, S_FILE_SEQ, 1)
        return grow(o, w, 12, 240, 110)
    if phase == 110:
        return invoke(o, w, 6, 8, 0, get(w, S_COMMAND_BYTES), 12, get(w, S_FILE_REPLY), 11, cap(w, 11), 11, 256, 128, 111)
    if phase == 111:
        if get(w, OBS) != FILE_EVENT or get(w, OBS + 16) != 1:
            return refuse(w, 151)
        action = get(w, OBS + 8)
        if action == 1:
            if get(w, C_RETURN) != GROW or get(w, OBS + 112) <= cap(w, 11) or get(w, OBS + 24) != get(w, S_FILE_SEQ):
                return refuse(w, 152)
            return grow(o, w, 11, get(w, OBS + 112), 110)
        if get(w, C_RETURN) != 128:
            return refuse(w, 153)
        if action == 0:
            if get(w, OBS + 24) != get(w, S_FILE_SEQ) or get(w, S_FD) != MAX:
                return refuse(w, 154)
            error = get(w, OBS + 72)
            put(w, S_FILE_ERROR, error)
            if error == 0:
                put(w, S_RESULT_AT, get(w, OBS + 96))
                put(w, S_RESULT_BYTES, get(w, OBS + 104))
                if inside(w, 11, get(w, S_RESULT_AT), get(w, S_RESULT_BYTES)) == 0:
                    return refuse(w, 155)
                return protect(o, w, 11, 1, 898)
            if error > 5 or get(w, OBS + 88) > 256 or inside(w, 11, get(w, OBS + 80), get(w, OBS + 88)) == 0:
                return refuse(w, 156)
            put(w, S_TMP_BYTES, get(w, OBS + 88))
            return view(o, w, 11, get(w, OBS + 80), get(w, OBS + 88), 190)
        if action < 2 or action > 5 or get(w, OBS + 32) != 1:
            return refuse(w, 157)
        sequence = get(w, OBS + 24)
        if sequence != get(w, S_FILE_SEQ):
            if get(w, S_FILE_SEQ) == MAX or sequence != get(w, S_FILE_SEQ) + 1:
                return refuse(w, 158)
        elif get(w, S_FILE_REPLY) != 0:
            return refuse(w, 159)
        put(w, S_FILE_SEQ, sequence)
        put(w, S_FILE_KIND, action)
        put(w, S_TMP_AT, get(w, OBS + 40))
        put(w, S_TMP_BYTES, get(w, OBS + 48))
        put(w, S_FILE_REQUEST, get(w, OBS + 56))
        put(w, S_READ_BYTES, get(w, OBS + 64))
        put(w, C_PHASE, 120)
        return 0
    return refuse(w, 160)

def primitive(o:mutbuf, w:mutbuf, kind:u64, fd:u64, slot:u64, at:u64, size:u64, flags:u64, observe:u64, offset:u64, count:u64, phase:u64) -> u32:
    if kind < 1 or kind > 4 or inside(w, slot, at, size) == 0 or inside(w, observe, offset, count) == 0 or count > 256:
        return refuse(w, 170)
    put(w, C_OBSERVE, count)
    args(w, kind, fd, slot, at, size, flags, observe, offset, count, 0, 0, 0)
    return event(o, w, 16, phase)

def file_request(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    kind = get(w, S_FILE_KIND)
    if phase == 120:
        if kind == 2:
            if get(w, S_FD) != MAX or get(w, S_TMP_BYTES) == MAX:
                return refuse(w, 171)
            return primitive(o, w, 1, 0, 11, get(w, S_TMP_AT), get(w, S_TMP_BYTES) + 1, get(w, S_FILE_REQUEST), 0, 0, 0, 140)
        if get(w, S_FD) == MAX:
            return refuse(w, 172)
        if kind == 3:
            return primitive(o, w, 2, get(w, S_FD), 12, 96, 144, 0, 12, 96, 56, 140)
        if kind == 4:
            if get(w, S_READ_BYTES) > MAX - 96:
                return refuse(w, 173)
            return grow(o, w, 12, 96 + get(w, S_READ_BYTES), 121)
        if kind == 5:
            return primitive(o, w, 4, get(w, S_FD), 0, 0, 0, 0, 0, 0, 0, 140)
        return refuse(w, 174)
    if phase == 121:
        return primitive(o, w, 3, get(w, S_FD), 12, 96, get(w, S_READ_BYTES), 0, 0, 0, 0, 140)
    return refuse(w, 175)

def file_response(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 140:
        kind = get(w, S_FILE_KIND)
        raw = get(w, C_RETURN)
        zero(w, WIRE, 96)
        put(w, WIRE, FILE_ACK)
        put(w, WIRE + 8, 1)
        put(w, WIRE + 16, get(w, S_FILE_SEQ))
        put(w, WIRE + 24, kind)
        size = 0
        if kind == 5:
            put(w, S_FD, MAX)
        if raw >= MAX - 4094:
            put(w, WIRE + 32, 1)
            put(w, WIRE + 56, MAX - raw + 1)
        else:
            if raw >= 9223372036854775808:
                return refuse(w, 185)
            if kind == 2:
                if raw > 2147483647:
                    return refuse(w, 186)
                put(w, S_FD, raw)
                put(w, WIRE + 40, 1)
            elif kind == 3:
                if raw != 0:
                    return refuse(w, 180)
                put(w, WIRE + 40, get(w, OBS + 24) & 4294967295)
                put(w, WIRE + 48, get(w, OBS + 48))
            elif kind == 4:
                if raw > get(w, S_READ_BYTES):
                    return refuse(w, 181)
                size = raw
                put(w, WIRE + 40, raw)
                put(w, WIRE + 64, raw)
            elif kind == 5:
                if raw != 0:
                    return refuse(w, 182)
            else:
                return refuse(w, 183)
        put(w, S_FILE_REPLY, 96 + size)
        put(w, WIRE + 72, 96 + size)
        return copy(o, w, 2, WIRE, 12, 0, 96, 110)
    return refuse(w, 184)

def diagnostic_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 190:
        diagnostic_literals(w)
        target = 20000
        i = 0
        while i < 45:
            store(w, target + i, byte(w, 30000 + i))
            i = i + 1
        target = target + 45
        store(w, target, 34)
        target = target + 1
        i = 0
        while i < get(w, S_TMP_BYTES):
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
        store(w, target, 34)
        target = target + 1
        i = 0
        while i < 48:
            store(w, target + i, byte(w, 30100 + i))
            i = i + 1
        target = target + 48
        put(w, S_SOURCE_SLOT, 2)
        put(w, S_SOURCE_AT, 20000)
        put(w, S_SOURCE_BYTES, target - 20000)
        put(w, S_EXIT, 2)
        return protect(o, w, 8, 0, 70)
    return refuse(w, 190)

def hex_digit(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def terminal(o:mutbuf, w:mutbuf) -> u32:
    if get(w, C_PENDING) != 0 or get(w, L_STATUS) != 1 or get(w, S_EXIT) > 255:
        return refuse(w, 200)
    if inside(w, get(w, S_STDOUT_SLOT), get(w, S_STDOUT_AT), get(w, S_STDOUT_BYTES)) == 0 or inside(w, get(w, S_STDERR_SLOT), get(w, S_STDERR_AT), get(w, S_STDERR_BYTES)) == 0:
        return refuse(w, 201)
    zero(o, 0, 128)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, 1)
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 32, get(w, S_EXIT))
    put(o, 40, get(w, S_STDOUT_SLOT))
    put(o, 48, get(w, S_STDOUT_AT))
    put(o, 56, get(w, S_STDOUT_BYTES))
    put(o, 64, get(w, S_STDERR_SLOT))
    put(o, 72, get(w, S_STDERR_AT))
    put(o, 80, get(w, S_STDERR_BYTES))
    put(w, L_STATUS, 2)
    return 128

def business_handoff(o:mutbuf, w:mutbuf) -> u32:
    if get(w, C_PENDING) != 0 or get(w, S_FD) != MAX:
        return refuse(w, 210)
    args(w, get(w, S_ACTION), 11, get(w, S_RESULT_AT), get(w, S_RESULT_BYTES), 4, cap(w, 4), 6, cap(w, 6), 0, 0, 0, 0)
    return event(o, w, 17, 901)
'''

def literals():
    prefix=b'{"diagnostics":[{"code":"E_DRIVER","message":'
    suffix=b',"phase":"driver"}],"ok":false,"status":"error"}'
    assert len(prefix)==45 and len(suffix)==48,(len(prefix),len(suffix))
    lines=['def diagnostic_literals(w:mutbuf) -> u64:']
    for base,raw in ((30000,prefix),(30100,suffix)):
        for pos in range(0,len(raw),8):
            lines.append(f'    put(w, {base+pos}, {int.from_bytes(raw[pos:pos+8],"little")})')
    lines.append('    return 0')
    return '\n'.join(lines)+'\n'
