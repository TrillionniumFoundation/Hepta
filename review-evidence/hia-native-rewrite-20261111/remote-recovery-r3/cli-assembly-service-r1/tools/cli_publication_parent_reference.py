"""New full CLI publication continuation authoring; no inherited execution.
Extends the exact public-A parent and retains the original two service tables.
HIA owns Path, payload format, temporary root, stage I/O, verified publication,
complete cleanup, error presentation and HIACPR. The carrier owns primitives.
"""
from hashlib import sha256
from pathlib import Path
import ast
import cli_business_parent as _base
assert sha256(Path(_base.__file__).read_bytes()).hexdigest()=="56680dca04f820cd23796f53d2f376a9604de03d79019316ad09d10c9dcc5809"
CONSTANTS=dict(_base.CONSTANTS)
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
for name,value in (
 ("PATH_COMMAND","HIAPPC01"),("PATH_EVENT","HIAPPE01"),("PATH_ACK","HIAPPA01"),
 ("TEMP_COMMAND","HIATDC01"),("TEMP_EVENT","HIATDE01"),("TEMP_ACK","HIATDA01"),
 ("WRITE_COMMAND","HIASWC01"),("WRITE_EVENT","HIASWE01"),("WRITE_ACK","HIASWA01"),
 ("PUB_COMMAND","HIAPVC01"),("PUB_EVENT","HIAPVE01"),("PUB_ACK","HIAPVA01"),
 ("CLEAN_COMMAND","HIATRC01"),("CLEAN_EVENT","HIATRE01"),("CLEAN_ACK","HIATRA01"),
 ("PRESENT_COMMAND","HIAPSC01"),("PRESENT_EVENT","HIAPSE01"),
 ("PUBLICATION_REPLY","HIACPR01")):
    CONSTANTS[name]=magic(value)
_names=("POLICY","CREATED","ERROR","ERROR_MODE","ERROR_NUMBER","ERROR_PATH",
 "ERROR_SLOT","ERROR_AT","ERROR_BYTES","DEST","DEST_N","PARENT","PARENT_N",
 "TEXT","TEXT_N","DIR","DIR_N","STAGE","STAGE_N","PAYLOAD_SLOT","PAYLOAD_AT",
 "PAYLOAD_N","QUOTE_N","RECEIPT_AT","RECEIPT_N","REPLY_N","ROLE","CMD","CMD_N",
 "WORK","EVENT","ACK","EVENT_N","SEQ","NEXT","RAW","DATA_N","DATA_SLOT",
 "HASH_POS","HASH_COUNT","PRESENT_KIND","PRESENT_NUMBER","PRESENT_PATH",
 "PRESENT_SLOT","PRESENT_AT","PRESENT_N","PRESENT_NEXT","PRESENT_OUT",
 "PRESENT_OUT_N","RESUME_N","RESUME_SEQ","GROW_N","FS_KIND","FS_TOKEN",
 "FS_FIRST","FS_AT","FS_N","FS_A","FS_SECOND","FS_TO","FS_SIZE","FS_B")
CONSTANTS.update({"PP_"+name:16000+i*8 for i,name in enumerate(_names)})
CONSTANTS.update(PP_EVENT_COPY=17408,PP_PRESENT_COPY=17728,
    PP_CODEC_DONE=17856,PP_CODEC_ERROR=17864,PP_PRESENT_ERROR=17872)
def one(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
body=one(_base.BODY,
 "        elif phase == 999:\n            return terminal(o, w)",
 "        elif phase == 999:\n            result = publication_output_start(o, w)\n"
 "        elif phase >= 1000 and phase < 1900:\n            result = publication_step(o, w, phase)")
body=one(body,
 "            # Publication's exact HIA filesystem owner is still an explicit open dependency.\n"
 "            put(w, C_PHASE, 980)",
 "            if get(w, B_FORMAT) > 2:\n                put(w, C_PHASE, 980)\n"
 "            else:\n                put(w, C_PHASE, 1000)")
COMMON=_base.COMMON
nodes=ast.parse(COMMON).body
ack=[n for n in nodes if n.name=="acknowledge"];assert len(ack)==1
before=ast.parse("pending != 1 and pending != 14 and pending != 16 and word(s, 40) != 0",mode="eval").body
after=ast.parse("pending != 1 and pending != 14 and pending != 16 and pending != 19 and word(s, 40) != 0",mode="eval").body
matches=[n for n in ast.walk(ack[0]) if isinstance(n,ast.If) and ast.dump(n.test)==ast.dump(before)]
assert len(matches)==1;matches[0].test=after
COMMON="\n".join(ast.unparse(n) for n in nodes)+"\n"
literals=_base.literals
BODY=body+r'''
def publication_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase < 1020:
        return publication_path(o, w, phase)
    if phase < 1040:
        return publication_temp(o, w, phase)
    if phase < 1070:
        return publication_write_publish(o, w, phase)
    if phase < 1160:
        return publication_cleanup_resume(o, w, phase)
    if phase >= 1200 and phase < 1210:
        return publication_pretty(o, w, phase)
    if phase >= 1400 and phase < 1430:
        return publication_output_step(o, w, phase)
    if phase >= 1600 and phase < 1630:
        return publication_peer_step(o, w, phase)
    if phase >= 1700 and phase < 1730:
        return publication_hash_step(o, w, phase)
    if phase >= 1800 and phase < 1820:
        return publication_presentation_step(o, w, phase)
    return refuse(w, 9100)

def publication_path(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1000:
        if get(w, B_ACTIVE) != 1 or get(w, B_KIND) != 2 or get(w, B_FIELD) != 2 or get(w, S_FD) != MAX:
            return refuse(w, 9101)
        if get(w, B_FORMAT) < 1 or get(w, B_FORMAT) > 2 or get(w, B_PAYLOAD_BYTES) == 0:
            return refuse(w, 9102)
        zero(w, 16000, 1024)
        put(w, PP_POLICY, get(w, B_FORMAT))
        put(w, PP_PAYLOAD_SLOT, 15)
        put(w, PP_PAYLOAD_AT, get(w, B_PAYLOAD_AT))
        put(w, PP_PAYLOAD_N, get(w, B_PAYLOAD_BYTES))
        return view(o, w, 6, 1088, 32, 1001)
    if phase == 1001:
        if field_view(w) == 0 or get(w, S_SOURCE_BYTES) > MAX - 64:
            return refuse(w, 9103)
        return grow(o, w, 20, 64 + get(w, S_SOURCE_BYTES), 1002)
    if phase == 1002:
        wire8(w, PATH_COMMAND, 1, 1, 1, get(w, S_SOURCE_BYTES), 64 + get(w, S_SOURCE_BYTES), 0, 0)
        return copy(o, w, 2, WIRE, 20, 0, 64, 1003)
    if phase == 1003:
        return copy(o, w, get(w, S_SOURCE_SLOT), get(w, S_SOURCE_AT), 20, 64, get(w, S_SOURCE_BYTES), 1004)
    if phase == 1004:
        return protect(o, w, 20, 1, 1005)
    if phase == 1005:
        return grow(o, w, 21, 65600, 1006)
    if phase == 1006:
        return protect(o, w, 21, 1, 1007)
    if phase == 1007:
        return grow(o, w, 27, 65536, 1008)
    if phase == 1008:
        return grow(o, w, 22, 4096, 1009)
    if phase == 1009:
        return publication_peer_start(o, w, 9, 20, cap(w, 20), 22, 1010)
    if phase == 1010:
        domain = get(w, PP_EVENT_COPY + 40)
        if domain == 0:
            put(w, PP_DEST, get(w, PP_EVENT_COPY + 64))
            put(w, PP_DEST_N, get(w, PP_EVENT_COPY + 72))
            put(w, PP_PARENT, get(w, PP_EVENT_COPY + 80))
            put(w, PP_PARENT_N, get(w, PP_EVENT_COPY + 88))
            put(w, PP_TEXT, get(w, PP_EVENT_COPY + 96))
            put(w, PP_TEXT_N, get(w, PP_EVENT_COPY + 104))
            if inside(w, 22, get(w, PP_DEST), get(w, PP_DEST_N) + 1) == 0 or inside(w, 22, get(w, PP_PARENT), get(w, PP_PARENT_N) + 1) == 0:
                return refuse(w, 9104)
            if get(w, PP_DEST_N) == 0 or get(w, PP_PARENT_N) == 0 or inside(w, 22, get(w, PP_TEXT), get(w, PP_TEXT_N)) == 0:
                return refuse(w, 9105)
            if get(w, PP_POLICY) == 2:
                put(w, C_PHASE, 1200)
                return 0
            put(w, C_PHASE, 1011)
            return 0
        if domain == 1:
            code = get(w, PP_EVENT_COPY + 48)
            if code < 1 or code > 2:
                return refuse(w, 9106)
            code = code + (get(w, PP_POLICY) - 1) * 2
            publication_error(w, 4, code, 0, 0, 0, 0)
        elif domain == 2:
            publication_error(w, 2, get(w, PP_EVENT_COPY + 56), choose_nonempty(get(w, PP_EVENT_COPY + 72)), 22, get(w, PP_EVENT_COPY + 64), get(w, PP_EVENT_COPY + 72))
        else:
            # Path.resolve's unhandled RuntimeError traceback is a separate CLI
            # compatibility boundary; never forge it as an E_DRIVER response.
            return refuse(w, 9399)
        put(w, C_PHASE, 1120)
        return 0
    if phase == 1011:
        return publication_present_start(o, w, 1, 0, 0, 22, get(w, PP_TEXT), get(w, PP_TEXT_N), 1020)
    return refuse(w, 9107)

def publication_temp(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1020:
        put(w, PP_QUOTE_N, get(w, PP_PRESENT_OUT_N))
        return grow(o, w, 31, get(w, PP_QUOTE_N), 1021)
    if phase == 1021:
        return copy(o, w, 39, get(w, PP_PRESENT_OUT), 31, 0, get(w, PP_QUOTE_N), 1022)
    if phase == 1022:
        return protect(o, w, 31, 1, 1030)
    if phase == 1030:
        if get(w, PP_PARENT_N) > MAX - 65:
            return refuse(w, 9110)
        return grow(o, w, 32, 65 + get(w, PP_PARENT_N), 1031)
    if phase == 1031:
        wire8(w, TEMP_COMMAND, 1, 1, 1, get(w, PP_PARENT_N), 65 + get(w, PP_PARENT_N), get(w, PP_POLICY), 0)
        return copy(o, w, 2, WIRE, 32, 0, 64, 1032)
    if phase == 1032:
        return copy(o, w, 22, get(w, PP_PARENT), 32, 64, get(w, PP_PARENT_N) + 1, 1033)
    if phase == 1033:
        return protect(o, w, 32, 1, 1034)
    if phase == 1034:
        return grow(o, w, 23, 1024, 1035)
    if phase == 1035:
        return publication_peer_start(o, w, 12, 32, cap(w, 32), 23, 1040)
    return refuse(w, 9111)

def publication_write_publish(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1040:
        code = get(w, PP_EVENT_COPY + 40)
        if code != 0:
            if get(w, PP_EVENT_COPY + 56) != 0:
                return refuse(w, 9112)
            if code == 1:
                publication_error(w, 2, get(w, PP_EVENT_COPY + 48), 1, 23, get(w, PP_EVENT_COPY + 64), get(w, PP_EVENT_COPY + 72))
            elif code == 2:
                publication_error(w, 4, 5, 0, 0, 0, 0)
            else:
                return refuse(w, 9113)
            put(w, C_PHASE, 1120)
            return 0
        if get(w, PP_EVENT_COPY + 56) != 1:
            return refuse(w, 9114)
        put(w, PP_CREATED, 1)
        put(w, PP_DIR, get(w, PP_EVENT_COPY + 64))
        put(w, PP_DIR_N, get(w, PP_EVENT_COPY + 72))
        put(w, PP_STAGE, get(w, PP_EVENT_COPY + 80))
        put(w, PP_STAGE_N, get(w, PP_EVENT_COPY + 88))
        if inside(w, 23, get(w, PP_DIR), get(w, PP_DIR_N) + 1) == 0 or inside(w, 23, get(w, PP_STAGE), get(w, PP_STAGE_N) + 1) == 0:
            return refuse(w, 9115)
        if get(w, PP_STAGE_N) > MAX - 65 or get(w, PP_PAYLOAD_N) > MAX - 65 - get(w, PP_STAGE_N):
            return refuse(w, 9116)
        return grow(o, w, 33, 65 + get(w, PP_STAGE_N) + get(w, PP_PAYLOAD_N), 1041)
    if phase == 1041:
        wire8(w, WRITE_COMMAND, 1, 1, 1, get(w, PP_STAGE_N), get(w, PP_PAYLOAD_N), cap(w, 33), 0)
        return copy(o, w, 2, WIRE, 33, 0, 64, 1042)
    if phase == 1042:
        return copy(o, w, 23, get(w, PP_STAGE), 33, 64, get(w, PP_STAGE_N) + 1, 1043)
    if phase == 1043:
        return copy(o, w, get(w, PP_PAYLOAD_SLOT), get(w, PP_PAYLOAD_AT), 33, 65 + get(w, PP_STAGE_N), get(w, PP_PAYLOAD_N), 1044)
    if phase == 1044:
        return protect(o, w, 33, 1, 1045)
    if phase == 1045:
        return grow(o, w, 24, 1024, 1046)
    if phase == 1046:
        return publication_peer_start(o, w, 11, 33, cap(w, 33), 24, 1050)
    if phase == 1050:
        if get(w, PP_EVENT_COPY + 112) != 0:
            return refuse(w, 9117)
        kind = get(w, PP_EVENT_COPY + 40)
        if kind != 0:
            if kind == 1:
                publication_error(w, 2, get(w, PP_EVENT_COPY + 48), choose_nonempty(get(w, PP_EVENT_COPY + 80)), 33, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80))
            elif kind == 2:
                publication_error(w, 3, get(w, PP_EVENT_COPY + 48), 0, 0, 0, 0)
            elif kind == 3:
                publication_error(w, 4, 6, 0, 0, 0, 0)
            else:
                return refuse(w, 9118)
            put(w, C_PHASE, 1100)
            return 0
        if get(w, PP_STAGE_N) > MAX - 66 or get(w, PP_DEST_N) > MAX - 66 - get(w, PP_STAGE_N):
            return refuse(w, 9119)
        size = 66 + get(w, PP_STAGE_N) + get(w, PP_DEST_N)
        if get(w, PP_PAYLOAD_N) > MAX - size:
            return refuse(w, 9120)
        return grow(o, w, 34, size + get(w, PP_PAYLOAD_N), 1051)
    if phase == 1051:
        wire8(w, PUB_COMMAND, 1, 1, 1, get(w, PP_STAGE_N), get(w, PP_DEST_N), get(w, PP_PAYLOAD_N), cap(w, 34))
        return copy(o, w, 2, WIRE, 34, 0, 64, 1052)
    if phase == 1052:
        return copy(o, w, 23, get(w, PP_STAGE), 34, 64, get(w, PP_STAGE_N) + 1, 1053)
    if phase == 1053:
        return copy(o, w, 22, get(w, PP_DEST), 34, 65 + get(w, PP_STAGE_N), get(w, PP_DEST_N) + 1, 1054)
    if phase == 1054:
        return copy(o, w, get(w, PP_PAYLOAD_SLOT), get(w, PP_PAYLOAD_AT), 34, 66 + get(w, PP_STAGE_N) + get(w, PP_DEST_N), get(w, PP_PAYLOAD_N), 1055)
    if phase == 1055:
        return protect(o, w, 34, 1, 1056)
    if phase == 1056:
        return grow(o, w, 25, 4096, 1057)
    if phase == 1057:
        return publication_peer_start(o, w, 8, 34, cap(w, 34), 25, 1060)
    if phase == 1060:
        kind = get(w, PP_EVENT_COPY + 40)
        source = publication_pub_value(w, get(w, PP_EVENT_COPY + 64))
        if source == 0 or inside(w, source, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80)) == 0:
            return refuse(w, 9121)
        if kind == 0:
            if source != 25 or get(w, PP_EVENT_COPY + 80) == 0:
                return refuse(w, 9122)
            put(w, PP_RECEIPT_AT, get(w, PP_EVENT_COPY + 72))
            put(w, PP_RECEIPT_N, get(w, PP_EVENT_COPY + 80))
        elif kind == 1:
            publication_error(w, 0, 0, 0, source, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80))
        elif kind == 2:
            publication_error(w, 2, get(w, PP_EVENT_COPY + 56), choose_nonempty(get(w, PP_EVENT_COPY + 80)), source, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80))
        else:
            return refuse(w, 9123)
        put(w, C_PHASE, 1100)
        return 0
    return refuse(w, 9124)

def choose_nonempty(n:u64) -> u64:
    if n == 0:
        return 0
    return 1

def publication_pub_value(w:mutbuf, source:u64) -> u64:
    if source == 0:
        return 34
    if source == 1:
        return 25
    return 0

def publication_error(w:mutbuf, mode:u64, number:u64, path:u64, slot:u64, at:u64, n:u64) -> u64:
    put(w, PP_ERROR, 1)
    put(w, PP_ERROR_MODE, mode)
    put(w, PP_ERROR_NUMBER, number)
    put(w, PP_ERROR_PATH, path)
    put(w, PP_ERROR_SLOT, slot)
    put(w, PP_ERROR_AT, at)
    put(w, PP_ERROR_BYTES, n)
    return 0
'''


BODY+=r'''
def publication_cleanup_resume(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase >= 1100 and phase < 1120:
        return publication_cleanup(o, w, phase)
    if phase >= 1120 and phase < 1140:
        return publication_failure(o, w, phase)
    if phase >= 1140 and phase < 1160:
        return publication_resume(o, w, phase)
    return refuse(w, 9130)

def publication_cleanup(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1100:
        if get(w, PP_CREATED) != 1 or get(w, PP_DIR_N) > MAX - 65:
            return refuse(w, 9131)
        return grow(o, w, 35, 65 + get(w, PP_DIR_N), 1101)
    if phase == 1101:
        wire8(w, CLEAN_COMMAND, 1, 1, 1, get(w, PP_DIR_N), 65 + get(w, PP_DIR_N), 0, 0)
        return copy(o, w, 2, WIRE, 35, 0, 64, 1102)
    if phase == 1102:
        return copy(o, w, 23, get(w, PP_DIR), 35, 64, get(w, PP_DIR_N) + 1, 1103)
    if phase == 1103:
        return protect(o, w, 35, 1, 1104)
    if phase == 1104:
        return grow(o, w, 26, 4096, 1105)
    if phase == 1105:
        return publication_peer_start(o, w, 13, 35, cap(w, 35), 26, 1110)
    if phase == 1110:
        if get(w, PP_EVENT_COPY + 128) != 0:
            return refuse(w, 9132)
        kind = get(w, PP_EVENT_COPY + 40)
        if kind == 1:
            publication_error(w, 2, get(w, PP_EVENT_COPY + 48), 1, 26, get(w, PP_EVENT_COPY + 64), get(w, PP_EVENT_COPY + 72))
        elif kind == 2:
            publication_error(w, 4, 7, 0, 0, 0, 0)
        elif kind != 0:
            return refuse(w, 9133)
        put(w, PP_CREATED, 0)
        if get(w, PP_ERROR) != 0:
            put(w, C_PHASE, 1120)
        else:
            put(w, C_PHASE, 1140)
        return 0
    return refuse(w, 9134)

def publication_failure(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1120:
        if get(w, PP_CREATED) != 0 or get(w, PP_ERROR) != 1:
            return refuse(w, 9135)
        if inside(w, get(w, PP_ERROR_SLOT), get(w, PP_ERROR_AT), get(w, PP_ERROR_BYTES)) == 0:
            return refuse(w, 9136)
        if get(w, PP_ERROR_MODE) == 0:
            put(w, PP_PRESENT_OUT, get(w, PP_ERROR_AT))
            put(w, PP_PRESENT_OUT_N, get(w, PP_ERROR_BYTES))
            put(w, PP_PRESENT_SLOT, get(w, PP_ERROR_SLOT))
            put(w, C_PHASE, 1121)
            return 0
        return publication_present_start(o, w, get(w, PP_ERROR_MODE), get(w, PP_ERROR_NUMBER), get(w, PP_ERROR_PATH), get(w, PP_ERROR_SLOT), get(w, PP_ERROR_AT), get(w, PP_ERROR_BYTES), 1121)
    if phase == 1121:
        if get(w, PP_ERROR_MODE) != 0:
            put(w, PP_PRESENT_SLOT, 39)
        if get(w, PP_PRESENT_OUT_N) == 0:
            return refuse(w, 9137)
        return business_retire(o, w, 1122)
    if phase == 1122:
        put(w, B_ACTIVE, 0)
        return release(o, w, 15, 1123)
    if phase == 1123:
        return grow(o, w, 15, get(w, PP_PRESENT_OUT_N), 1124)
    if phase == 1124:
        return copy(o, w, get(w, PP_PRESENT_SLOT), get(w, PP_PRESENT_OUT), 15, 0, get(w, PP_PRESENT_OUT_N), 1125)
    if phase == 1125:
        put(w, B_PAYLOAD_AT, 0)
        put(w, B_PAYLOAD_BYTES, get(w, PP_PRESENT_OUT_N))
        put(w, S_EXIT, 2)
        return protect(o, w, 15, 1, 960)
    return refuse(w, 9138)

def publication_resume(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1140:
        if get(w, PP_CREATED) != 0 or get(w, PP_ERROR) != 0 or get(w, PP_QUOTE_N) < 2 or get(w, PP_RECEIPT_N) == 0:
            return refuse(w, 9140)
        if get(w, PP_QUOTE_N) > MAX - 128 or get(w, PP_RECEIPT_N) > MAX - 128 - get(w, PP_QUOTE_N):
            return refuse(w, 9141)
        put(w, PP_RESUME_N, 128 + get(w, PP_QUOTE_N) + get(w, PP_RECEIPT_N))
        return grow(o, w, 36, get(w, PP_RESUME_N), 1141)
    if phase == 1141:
        return copy(o, w, 31, 0, 36, 128, get(w, PP_QUOTE_N), 1142)
    if phase == 1142:
        return copy(o, w, 25, get(w, PP_RECEIPT_AT), 36, 128 + get(w, PP_QUOTE_N), get(w, PP_RECEIPT_N), 1143)
    if phase == 1143:
        return protect(o, w, 14, 0, 1144)
    if phase == 1144:
        wire8(w, BUSINESS_LEASES, 1, 1, 64, 36, 0, get(w, PP_RESUME_N), get(w, B_TARGET))
        return copy(o, w, 2, WIRE, 14, 0, 64, 1145)
    if phase == 1145:
        return protect(o, w, 14, 1, 1146)
    if phase == 1146:
        return protect(o, w, 13, 0, 1147)
    if phase == 1147:
        return release(o, w, 15, 1148)
    if phase == 1148:
        if get(w, C_SEQUENCE) > MAX - 5:
            return refuse(w, 9142)
        put(w, PP_RESUME_SEQ, get(w, C_SEQUENCE) + 5)
        zero(w, WIRE, 128)
        wire8(w, PUBLICATION_REPLY, 1, get(w, B_SERVICE), get(w, B_LEASE), get(w, B_SEQUENCE), get(w, B_REQUEST), get(w, PP_RESUME_SEQ), get(w, PP_POLICY))
        put(w, WIRE + 64, 128)
        put(w, WIRE + 72, get(w, PP_QUOTE_N))
        put(w, WIRE + 80, 128 + get(w, PP_QUOTE_N))
        put(w, WIRE + 88, get(w, PP_RECEIPT_N))
        put(w, WIRE + 96, get(w, PP_RESUME_N))
        return copy(o, w, 2, WIRE, 36, 0, 128, 1149)
    if phase == 1149:
        return protect(o, w, 36, 1, 1150)
    if phase == 1150:
        zero(w, WIRE, 128)
        wire8(w, BUSINESS_REPLY, 1, get(w, B_SERVICE), get(w, B_LEASE), get(w, B_SEQUENCE), get(w, B_REQUEST), 2, get(w, PP_RESUME_SEQ))
        put(w, WIRE + 64, 2)
        put(w, WIRE + 72, get(w, B_TARGET))
        put(w, WIRE + 80, get(w, PP_RESUME_N))
        put(w, WIRE + 88, get(w, PP_POLICY))
        return copy(o, w, 2, WIRE, 13, 0, 128, 1151)
    if phase == 1151:
        return protect(o, w, 13, 1, 1152)
    if phase == 1152:
        if get(w, C_SEQUENCE) + 1 != get(w, PP_RESUME_SEQ):
            return refuse(w, 9143)
        return business_call(o, w, 2, 64, 908)
    return refuse(w, 9144)

def publication_pretty(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1200:
        return grow(o, w, 37, 96, 1201)
    if phase == 1201:
        zero(w, WIRE, 96)
        wire8(w, PRETTY_COMMAND, 1, 1, 1, get(w, PP_PAYLOAD_N), 1, 1, 0)
        return copy(o, w, 2, WIRE, 37, 0, 96, 1202)
    if phase == 1202:
        return protect(o, w, 37, 1, 1203)
    if phase == 1203:
        return grow(o, w, 38, 1024, 1204)
    if phase == 1204:
        return invoke(o, w, 5, get(w, PP_PAYLOAD_SLOT), get(w, PP_PAYLOAD_AT), get(w, PP_PAYLOAD_N), 37, 96, 38, cap(w, 38), 38, 256, 128, 1205)
    if phase == 1205:
        if get(w, OBS) != PRETTY_EVENT or get(w, OBS + 16) != 1 or get(w, OBS + 24) != 1:
            return refuse(w, 9150)
        if get(w, C_RETURN) == GROW:
            if get(w, OBS + 8) != 1 or get(w, OBS + 48) <= cap(w, 38):
                return refuse(w, 9151)
            return grow(o, w, 38, get(w, OBS + 48), 1204)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0 or inside(w, 38, get(w, OBS + 32), get(w, OBS + 40)) == 0:
            return refuse(w, 9152)
        put(w, PP_PAYLOAD_SLOT, 38)
        put(w, PP_PAYLOAD_AT, get(w, OBS + 32))
        put(w, PP_PAYLOAD_N, get(w, OBS + 40))
        return protect(o, w, 38, 1, 1011)
    return refuse(w, 9153)

def publication_present_start(o:mutbuf, w:mutbuf, kind:u64, number:u64, path:u64, slot:u64, at:u64, n:u64, next:u64) -> u64:
    if inside(w, slot, at, n) == 0:
        return refuse(w, 9160)
    put(w, PP_PRESENT_KIND, kind)
    put(w, PP_PRESENT_NUMBER, number)
    put(w, PP_PRESENT_PATH, path)
    put(w, PP_PRESENT_SLOT, slot)
    put(w, PP_PRESENT_AT, at)
    put(w, PP_PRESENT_N, n)
    put(w, PP_PRESENT_NEXT, next)
    if cap(w, 40) != 0:
        return protect(o, w, 40, 0, 1800)
    put(w, C_PHASE, 1800)
    return 0

def publication_presentation_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1800:
        return grow(o, w, 40, 96, 1801)
    if phase == 1801:
        zero(w, WIRE, 96)
        wire8(w, PRESENT_COMMAND, 1, 1, 1, get(w, PP_PRESENT_KIND), get(w, PP_PRESENT_NUMBER), get(w, PP_PRESENT_PATH), get(w, PP_PRESENT_N))
        return copy(o, w, 2, WIRE, 40, 0, 96, 1802)
    if phase == 1802:
        return protect(o, w, 40, 1, 1803)
    if phase == 1803:
        return release(o, w, 39, 1804)
    if phase == 1804:
        return grow(o, w, 39, 65536, 1805)
    if phase == 1805:
        return invoke(o, w, 14, get(w, PP_PRESENT_SLOT), get(w, PP_PRESENT_AT), get(w, PP_PRESENT_N), 40, 96, 39, cap(w, 39), 39, 256, 128, 1806)
    if phase == 1806:
        if get(w, OBS) != PRESENT_EVENT or get(w, OBS + 16) != 1 or get(w, OBS + 24) != 1 or get(w, OBS + 32) != get(w, PP_PRESENT_KIND):
            return refuse(w, 9161)
        if get(w, C_RETURN) == GROW:
            if get(w, OBS + 8) != 1 or get(w, OBS + 56) <= cap(w, 39):
                return refuse(w, 9162)
            return grow(o, w, 39, get(w, OBS + 56), 1805)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0 or inside(w, 39, get(w, OBS + 40), get(w, OBS + 48)) == 0:
            return refuse(w, 9163)
        if get(w, OBS + 64) > 1 or (get(w, PP_PRESENT_KIND) != 6 and get(w, OBS + 64) != 0):
            return refuse(w, 9165)
        put(w, PP_PRESENT_ERROR, get(w, OBS + 64))
        put(w, PP_PRESENT_OUT, get(w, OBS + 40))
        put(w, PP_PRESENT_OUT_N, get(w, OBS + 48))
        return protect(o, w, 39, 1, get(w, PP_PRESENT_NEXT))
    return refuse(w, 9164)
'''


BODY+=r'''
def publication_peer_start(o:mutbuf, w:mutbuf, role:u64, command:u64, n:u64, work:u64, next:u64) -> u64:
    event_magic = 0
    ack_magic = 0
    size = 128
    if role == 8:
        event_magic = PUB_EVENT
        ack_magic = PUB_ACK
    elif role == 9:
        event_magic = PATH_EVENT
        ack_magic = PATH_ACK
    elif role == 11:
        event_magic = WRITE_EVENT
        ack_magic = WRITE_ACK
    elif role == 12:
        event_magic = TEMP_EVENT
        ack_magic = TEMP_ACK
    elif role == 13:
        event_magic = CLEAN_EVENT
        ack_magic = CLEAN_ACK
        size = 256
    else:
        return refuse(w, 9170)
    if inside(w, command, 0, n) == 0 or cap(w, work) < 1024 or cap(w, 21) < 64:
        return refuse(w, 9171)
    put(w, PP_ROLE, role)
    put(w, PP_CMD, command)
    put(w, PP_CMD_N, n)
    put(w, PP_WORK, work)
    put(w, PP_EVENT, event_magic)
    put(w, PP_ACK, ack_magic)
    put(w, PP_EVENT_N, size)
    put(w, PP_SEQ, 1)
    put(w, PP_REPLY_N, 0)
    put(w, PP_NEXT, next)
    put(w, C_PHASE, 1600)
    return 0

def publication_peer_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1600:
        return invoke(o, w, get(w, PP_ROLE), get(w, PP_CMD), 0, get(w, PP_CMD_N), 21, get(w, PP_REPLY_N), get(w, PP_WORK), cap(w, get(w, PP_WORK)), get(w, PP_WORK), 256, get(w, PP_EVENT_N), 1601)
    if phase == 1601:
        i = 0
        while i < get(w, PP_EVENT_N):
            store(w, PP_EVENT_COPY + i, byte(w, OBS + i))
            i = i + 1
        if get(w, PP_EVENT_COPY) != get(w, PP_EVENT) or get(w, PP_EVENT_COPY + 16) != 1:
            return refuse(w, 9172)
        action = get(w, PP_EVENT_COPY + 8)
        if get(w, C_RETURN) == GROW:
            if action != 1 or get(w, PP_EVENT_COPY + 24) != get(w, PP_SEQ) or get(w, PP_EVENT_COPY + 112) <= cap(w, get(w, PP_WORK)):
                return refuse(w, 9173)
            return grow(o, w, get(w, PP_WORK), get(w, PP_EVENT_COPY + 112), 1600)
        if get(w, C_RETURN) != get(w, PP_EVENT_N):
            return refuse(w, 9174)
        if action == 0:
            if get(w, PP_EVENT_COPY + 24) != get(w, PP_SEQ):
                return refuse(w, 9175)
            return protect(o, w, get(w, PP_WORK), 1, get(w, PP_NEXT))
        if action != 2 and (get(w, PP_ROLE) != 8 or action != 3):
            return refuse(w, 9176)
        if get(w, PP_SEQ) == MAX or get(w, PP_EVENT_COPY + 24) != get(w, PP_SEQ) + 1:
            return refuse(w, 9177)
        put(w, PP_SEQ, get(w, PP_EVENT_COPY + 24))
        if action == 3:
            if get(w, PP_EVENT_COPY + 32) != 9 or get(w, PP_EVENT_COPY + 64) != 0 or inside(w, 34, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80)) == 0:
                return refuse(w, 9178)
            put(w, PP_HASH_POS, 0)
            return protect(o, w, get(w, PP_WORK), 1, 1700)
        return protect(o, w, get(w, PP_WORK), 1, 1602)
    if phase == 1602:
        if publication_fs_select(w) == 0:
            return refuse(w, 9179)
        need = 144
        if get(w, PP_FS_FIRST) == 27 and get(w, PP_FS_N) > need:
            need = get(w, PP_FS_N)
        if get(w, PP_FS_SECOND) == 27 and get(w, PP_FS_SIZE) > need:
            need = get(w, PP_FS_SIZE)
        return grow(o, w, 27, need, 1603)
    if phase == 1603:
        return publication_fs(o, w)
    if phase == 1604:
        put(w, PP_RAW, get(w, C_RETURN))
        return protect(o, w, get(w, PP_WORK), 0, 1610)
    if phase == 1610:
        if publication_reply(w) == 0:
            return refuse(w, 9180)
        return protect(o, w, 21, 0, 1611)
    if phase == 1611:
        return grow(o, w, 21, get(w, PP_REPLY_N), 1612)
    if phase == 1612:
        return copy(o, w, 2, WIRE, 21, 0, 64, 1613)
    if phase == 1613:
        if get(w, PP_DATA_N) != 0:
            return copy(o, w, get(w, PP_DATA_SLOT), 0, 21, 64, get(w, PP_DATA_N), 1614)
        put(w, C_PHASE, 1614)
        return 0
    if phase == 1614:
        return protect(o, w, 21, 1, 1600)
    return refuse(w, 9181)

def publication_fs_fields(w:mutbuf, kind:u64, token:u64, first:u64, at:u64, n:u64, a:u64, second:u64, to:u64, size:u64, b:u64) -> u64:
    put(w, PP_FS_KIND, kind)
    put(w, PP_FS_TOKEN, token)
    put(w, PP_FS_FIRST, first)
    put(w, PP_FS_AT, at)
    put(w, PP_FS_N, n)
    put(w, PP_FS_A, a)
    put(w, PP_FS_SECOND, second)
    put(w, PP_FS_TO, to)
    put(w, PP_FS_SIZE, size)
    put(w, PP_FS_B, b)
    return 1

def publication_fs_select(w:mutbuf) -> u64:
    if get(w, PP_ROLE) == 8:
        return publication_pub_fs(w)
    if get(w, PP_ROLE) == 9:
        return publication_path_fs(w)
    if get(w, PP_ROLE) == 11:
        return publication_write_fs(w)
    if get(w, PP_ROLE) == 12:
        return publication_temp_fs(w)
    if get(w, PP_ROLE) == 13:
        return publication_clean_fs(w)
    return 0

def publication_path_fs(w:mutbuf) -> u64:
    op = get(w, PP_EVENT_COPY + 32)
    at = get(w, PP_EVENT_COPY + 64)
    n = get(w, PP_EVENT_COPY + 72)
    if op == 7 or op == 8:
        return publication_fs_fields(w, op, 0, 22, at, n, 0, 27, 0, 144, 0)
    if op == 11:
        return publication_fs_fields(w, 11, 0, 22, at, n, 0, 0, 0, 0, get(w, PP_EVENT_COPY + 88))
    if op == 13:
        return publication_fs_fields(w, 13, 0, 22, at, n, 0, 27, 0, get(w, PP_EVENT_COPY + 80), 0)
    if op == 14:
        return publication_fs_fields(w, 14, 0, 27, 0, get(w, PP_EVENT_COPY + 80), 0, 0, 0, 0, 0)
    return 0

def publication_temp_fs(w:mutbuf) -> u64:
    op = get(w, PP_EVENT_COPY + 32)
    if op == 11:
        return publication_fs_fields(w, 11, 0, 23, get(w, PP_EVENT_COPY + 64), get(w, PP_EVENT_COPY + 72), 0, 0, 0, 0, get(w, PP_EVENT_COPY + 88))
    if op == 15:
        return publication_fs_fields(w, 15, 0, 27, 0, get(w, PP_EVENT_COPY + 80), get(w, PP_EVENT_COPY + 88), 0, 0, 0, 0)
    if op == 24:
        return publication_fs_fields(w, 24, 0, 27, 0, 16, get(w, PP_EVENT_COPY + 88), 0, 0, 0, 0)
    if op == 25:
        return publication_fs_fields(w, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return 0

def publication_write_fs(w:mutbuf) -> u64:
    op = get(w, PP_EVENT_COPY + 32)
    if op == 1:
        return publication_fs_fields(w, 1, 0, 33, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80), get(w, PP_EVENT_COPY + 88), 0, 0, 0, get(w, PP_EVENT_COPY + 96))
    if op == 3:
        return publication_fs_fields(w, 3, 0, 27, 0, 144, 0, 0, 0, 0, 0)
    if op == 5:
        return publication_fs_fields(w, 5, 0, 33, get(w, PP_EVENT_COPY + 72), get(w, PP_EVENT_COPY + 80), 0, 0, 0, 0, 0)
    if op == 2 or op == 6:
        return publication_fs_fields(w, op, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return 0

def publication_pub_fs(w:mutbuf) -> u64:
    op = get(w, PP_EVENT_COPY + 32)
    source = publication_pub_value(w, get(w, PP_EVENT_COPY + 64))
    at = get(w, PP_EVENT_COPY + 72)
    n = get(w, PP_EVENT_COPY + 80)
    if op == 1 or op == 2:
        kind = 8
        if op == 2:
            kind = 7
        return publication_fs_fields(w, kind, 0, source, at, n, 0, 27, 0, 144, 0)
    if op == 3:
        return publication_fs_fields(w, 1, 0, source, at, n, get(w, PP_EVENT_COPY + 88), 0, 0, 0, 0)
    if op == 4:
        return publication_fs_fields(w, 3, 0, 27, 0, 144, 0, 0, 0, 0, 0)
    if op == 5:
        return publication_fs_fields(w, 4, 0, 27, 0, n, 0, 0, 0, 0, 0)
    if op == 6:
        return publication_fs_fields(w, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    if op == 7:
        other = publication_pub_value(w, get(w, PP_EVENT_COPY + 88))
        return publication_fs_fields(w, 9, 0, source, at, n, 0, other, get(w, PP_EVENT_COPY + 96), get(w, PP_EVENT_COPY + 104), 0)
    if op == 8:
        return publication_fs_fields(w, 10, 0, source, at, n, 0, 0, 0, 0, 0)
    return 0

def publication_clean_fs(w:mutbuf) -> u64:
    op = get(w, PP_EVENT_COPY + 32)
    token = get(w, PP_EVENT_COPY + 80)
    at = get(w, PP_EVENT_COPY + 64)
    n = get(w, PP_EVENT_COPY + 72)
    a = get(w, PP_EVENT_COPY + 96)
    b = get(w, PP_EVENT_COPY + 104)
    if op == 1:
        return publication_fs_fields(w, 1, token, 26, at, n, a, 0, 0, 0, b)
    if op == 16:
        return publication_fs_fields(w, 16, token, 26, at, n, a, get(w, PP_EVENT_COPY + 144), 0, 0, b)
    if op == 23:
        return publication_fs_fields(w, 23, token, 0, 0, 0, 0, get(w, PP_EVENT_COPY + 144), 0, 0, 0)
    if op == 2:
        return publication_fs_fields(w, 2, token, 0, 0, 0, 0, 0, 0, 0, 0)
    if op == 3:
        return publication_fs_fields(w, 3, token, 27, 0, 144, 0, 0, 0, 0, 0)
    if op == 7 or op == 8:
        return publication_fs_fields(w, op, 0, 26, at, n, 0, 27, 0, 144, 0)
    if op == 17:
        return publication_fs_fields(w, 17, token, 26, at, n, a, 27, 0, 144, 0)
    if op == 18:
        return publication_fs_fields(w, 18, token, 27, 0, get(w, PP_EVENT_COPY + 88), 0, 0, 0, 0, 0)
    if op == 10 or op == 12:
        return publication_fs_fields(w, op, 0, 26, at, n, 0, 0, 0, 0, 0)
    if op == 20:
        return publication_fs_fields(w, 20, 0, 26, at, n, 0, 0, 0, 0, b)
    if op == 21:
        return publication_fs_fields(w, 21, token, 26, at, n, a, 0, 0, 0, 0)
    return 0

def publication_fs(o:mutbuf, w:mutbuf) -> u32:
    kind = get(w, PP_FS_KIND)
    if kind != 16 and kind != 23:
        if inside(w, get(w, PP_FS_SECOND), get(w, PP_FS_TO), get(w, PP_FS_SIZE)) == 0:
            return refuse(w, 9182)
    if inside(w, get(w, PP_FS_FIRST), get(w, PP_FS_AT), get(w, PP_FS_N)) == 0:
        return refuse(w, 9183)
    put(w, C_OBSERVE, 0)
    args(w, kind, get(w, PP_FS_TOKEN), get(w, PP_FS_FIRST), get(w, PP_FS_AT), get(w, PP_FS_N), get(w, PP_FS_A), get(w, PP_FS_SECOND), get(w, PP_FS_TO), get(w, PP_FS_SIZE), get(w, PP_FS_B), 0, 0)
    return event(o, w, 19, 1604)

def publication_raw_error(raw:u64) -> u64:
    if raw >= 18446744073709547521:
        return MAX - raw + 1
    return 0

def publication_reply(w:mutbuf) -> u64:
    role = get(w, PP_ROLE)
    op = get(w, PP_EVENT_COPY + 32)
    raw = get(w, PP_RAW)
    err = publication_raw_error(raw)
    result = 0
    size = 0
    source = 27
    if err == 0:
        if raw >= 9223372036854775808:
            return 0
        kind = get(w, PP_FS_KIND)
        if role == 8 and op == 9:
            if raw != 0:
                return 0
            size = 32
            source = 3
        elif kind == 1 or kind == 16 or kind == 23:
            if raw > 2147483647:
                return 0
            result = 1
            if role == 13:
                result = get(w, PP_FS_TOKEN)
        elif kind == 3 or kind == 7 or kind == 8 or kind == 17:
            if raw != 0:
                return 0
            size = 144
        elif kind == 4 or kind == 5 or kind == 14 or kind == 15 or kind == 18:
            if raw > get(w, PP_FS_N):
                return 0
            result = raw
            if kind != 5:
                size = raw
        elif kind == 13:
            if raw > get(w, PP_FS_SIZE):
                return 0
            result = raw
            size = raw
        elif kind == 24:
            if raw != 0:
                return 0
            size = 16
        elif kind == 25:
            if raw == 0 or raw > 2147483647:
                return 0
            result = raw
        elif raw != 0:
            return 0
    zero(w, WIRE, 64)
    put(w, WIRE, get(w, PP_ACK))
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, PP_SEQ))
    put(w, WIRE + 24, op)
    put(w, WIRE + 32, choose_nonempty(err))
    put(w, WIRE + 40, result)
    put(w, WIRE + 48, err)
    put(w, WIRE + 56, size)
    if size > MAX - 64:
        return 0
    put(w, PP_REPLY_N, 64 + size)
    put(w, PP_DATA_N, size)
    put(w, PP_DATA_SLOT, source)
    return 1
'''


BODY+=r'''
def publication_hash_call(o:mutbuf, w:mutbuf, n:u64, next:u64) -> u32:
    return invoke(o, w, 10, 28, 0, n, 3, 32, 29, 1184, 0, 0, 0, next)

def publication_hash_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1700:
        return grow(o, w, 28, 1, 1701)
    if phase == 1701:
        return grow(o, w, 29, 1184, 1702)
    if phase == 1702:
        store(w, WIRE, 0)
        return copy(o, w, 2, WIRE, 28, 0, 1, 1703)
    if phase == 1703:
        return protect(o, w, 28, 1, 1704)
    if phase == 1704:
        return publication_hash_call(o, w, 1, 1705)
    if phase == 1705:
        if get(w, C_RETURN) != 0:
            return refuse(w, 9190)
        put(w, C_PHASE, 1706)
        return 0
    if phase == 1706:
        if get(w, PP_HASH_POS) == get(w, PP_EVENT_COPY + 80):
            return protect(o, w, 28, 0, 1715)
        if get(w, PP_HASH_POS) > get(w, PP_EVENT_COPY + 80):
            return refuse(w, 9191)
        count = get(w, PP_EVENT_COPY + 80) - get(w, PP_HASH_POS)
        if count > 8388608:
            count = 8388608
        put(w, PP_HASH_COUNT, count)
        return protect(o, w, 28, 0, 1707)
    if phase == 1707:
        return grow(o, w, 28, get(w, PP_HASH_COUNT) + 1, 1708)
    if phase == 1708:
        store(w, WIRE, 1)
        return copy(o, w, 2, WIRE, 28, 0, 1, 1709)
    if phase == 1709:
        return copy(o, w, 34, get(w, PP_EVENT_COPY + 72) + get(w, PP_HASH_POS), 28, 1, get(w, PP_HASH_COUNT), 1710)
    if phase == 1710:
        return protect(o, w, 28, 1, 1711)
    if phase == 1711:
        return publication_hash_call(o, w, get(w, PP_HASH_COUNT) + 1, 1712)
    if phase == 1712:
        if get(w, C_RETURN) != 0:
            return refuse(w, 9192)
        put(w, PP_HASH_POS, get(w, PP_HASH_POS) + get(w, PP_HASH_COUNT))
        put(w, C_PHASE, 1706)
        return 0
    if phase == 1715:
        store(w, WIRE, 2)
        return copy(o, w, 2, WIRE, 28, 0, 1, 1716)
    if phase == 1716:
        return protect(o, w, 28, 1, 1717)
    if phase == 1717:
        return publication_hash_call(o, w, 1, 1718)
    if phase == 1718:
        if get(w, C_RETURN) != 32:
            return refuse(w, 9193)
        put(w, PP_RAW, 0)
        return protect(o, w, get(w, PP_WORK), 0, 1610)
    return refuse(w, 9194)
'''

BODY+=r'''
def publication_output_start(o:mutbuf, w:mutbuf) -> u64:
    if get(w, B_ACTIVE) != 0 or get(w, PP_CREATED) != 0:
        return refuse(w, 9200)
    if get(w, PP_CODEC_DONE) == 2:
        return terminal(o, w)
    if get(w, PP_CODEC_DONE) == 0:
        if get(w, S_STDOUT_BYTES) != 0:
            return publication_present_start(o, w, 6, 0, 0, get(w, S_STDOUT_SLOT), get(w, S_STDOUT_AT), get(w, S_STDOUT_BYTES), 1400)
        put(w, PP_CODEC_DONE, 1)
    if get(w, PP_CODEC_DONE) == 1:
        if get(w, S_STDERR_BYTES) != 0:
            return publication_present_start(o, w, 7, 0, 0, get(w, S_STDERR_SLOT), get(w, S_STDERR_AT), get(w, S_STDERR_BYTES), 1410)
        put(w, PP_CODEC_DONE, 2)
        return terminal(o, w)
    return refuse(w, 9201)

def publication_output_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1400:
        if get(w, PP_CODEC_DONE) != 0:
            return refuse(w, 9202)
        if get(w, PP_PRESENT_ERROR) != 0:
            if get(w, PP_CODEC_ERROR) != 0 or get(w, PP_PRESENT_OUT_N) == 0:
                return refuse(w, 9203)
            put(w, PP_CODEC_ERROR, 1)
            return release(o, w, 15, 1420)
        return grow(o, w, 41, get(w, PP_PRESENT_OUT_N), 1401)
    if phase == 1401:
        return copy(o, w, 39, get(w, PP_PRESENT_OUT), 41, 0, get(w, PP_PRESENT_OUT_N), 1402)
    if phase == 1402:
        put(w, S_STDOUT_SLOT, 41)
        put(w, S_STDOUT_AT, 0)
        put(w, S_STDOUT_BYTES, get(w, PP_PRESENT_OUT_N))
        put(w, PP_CODEC_DONE, 1)
        return protect(o, w, 41, 1, 999)
    if phase == 1410:
        if get(w, PP_CODEC_DONE) != 1 or get(w, PP_PRESENT_ERROR) != 0:
            return refuse(w, 9204)
        return grow(o, w, 42, get(w, PP_PRESENT_OUT_N), 1411)
    if phase == 1411:
        return copy(o, w, 39, get(w, PP_PRESENT_OUT), 42, 0, get(w, PP_PRESENT_OUT_N), 1412)
    if phase == 1412:
        put(w, S_STDERR_SLOT, 42)
        put(w, S_STDERR_AT, 0)
        put(w, S_STDERR_BYTES, get(w, PP_PRESENT_OUT_N))
        put(w, PP_CODEC_DONE, 2)
        return protect(o, w, 42, 1, 999)
    if phase == 1420:
        return grow(o, w, 15, get(w, PP_PRESENT_OUT_N), 1421)
    if phase == 1421:
        return copy(o, w, 39, get(w, PP_PRESENT_OUT), 15, 0, get(w, PP_PRESENT_OUT_N), 1422)
    if phase == 1422:
        return protect(o, w, 15, 1, 1423)
    if phase == 1423:
        put(w, B_PAYLOAD_AT, 0)
        put(w, B_PAYLOAD_BYTES, get(w, PP_PRESENT_OUT_N))
        put(w, S_EXIT, 2)
        put(w, S_STDOUT_BYTES, 0)
        put(w, S_STDERR_BYTES, 0)
        return release(o, w, 10, 1424)
    if phase == 1424:
        return protect(o, w, 8, 0, 960)
    return refuse(w, 9205)
'''
