"""Author ordinary AgentStore reference/profile authority and routing in HIA.

SQL, immutable-file publication and codecs are explicit foreign owners. The
legacy Python field-shape admission is retained separately, not called native.
"""
from __future__ import annotations

import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools import generate_hia_worker_report as equality_source

SOURCE_PATH = 'examples/hia_bootstrap/agent_store_authority.hiaasm'
MAGIC = int.from_bytes(b'HIASTA02', 'little')
HIGH = 1 << 63
LITERALS = {
    'ID': 'id', 'SHA': 'sha256', 'URI': 'uri', 'KIND': 'kind',
    'METADATA': 'metadata', 'ARTIFACT': 'artifact', 'PROFILE': 'profile', 'HEX': 'hex',
    'ID_PREFIX': 'a-', 'URI_PREFIX': 'hia://artifacts/',
    'STORE_HASH': 'store-hash', 'STORE_PUT': 'store-put', 'STORE_GET': 'store-get',
    'SELECT_ID': 'SELECT * FROM artifacts WHERE id=?',
    'SELECT_URI': 'SELECT * FROM artifacts WHERE uri=?',
    'SELECT_CONTENT': 'SELECT * FROM artifacts WHERE content_key=?',
    'SELECT_PROFILE': 'SELECT artifact FROM profiles WHERE id=? AND sha256=?',
    'INSERT_ARTIFACT': 'INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)',
    'INSERT_PROFILE': 'INSERT OR IGNORE INTO profiles VALUES (?,?,?)',
    'IDENTITY_CODE': 'E_HIA_ARTIFACT_IDENTITY',
    'IDENTITY_MESSAGE': 'artifact reference was not issued in this runtime namespace',
    'URI_MESSAGE': 'resource URI was not issued in this runtime namespace',
    'AUTHORITY_CODE': 'E_HIA_ARTIFACT_AUTHORITY',
    'AUTHORITY_PREFIX': 'input bytes cannot impersonate a retained ',
    'CORRUPT_CODE': 'E_HIA_ARTIFACT_CORRUPT',
    'CORRUPT_MESSAGE': 'artifact bytes no longer match their recorded digest',
    'PUBLICATION_MESSAGE': 'native artifact hash and durable file receipt differ',
    'LIMIT_CODE': 'E_HIA_ARTIFACT_LIMIT',
    'LIMIT_MESSAGE': 'artifact exceeds the 64 MiB store limit',
    'PROFILE_STALE_CODE': 'E_HIA_PROFILE_STALE',
    'PROFILE_STALE_MESSAGE': 'profile is unavailable or differs from the installed implementation',
    'PROFILE_AUTHORITY_CODE': 'E_HIA_PROFILE_AUTHORITY',
    'PROFILE_AUTHORITY_MESSAGE': 'profile does not resolve to a retained server record',
}
FIELDS = {key: value for key, value in equality_source.FIELDS.items()
          if key.startswith(('EQ_', 'EL_', 'ER_'))}
FIELDS.update({
    'MAGIC': MAGIC, 'HIGH': HIGH, 'AWAIT': 8, 'SEQ': 16, 'PHASE': 24,
    'MODE': 48, 'STORE': 56, 'ARG0': 64, 'ARG1': 72, 'ARG2': 80, 'NONE': 88,
    'RESULT': 96, 'ROW': 104, 'REF': 112, 'DATA': 120, 'META': 128,
    'CONTENT_HASH': 136, 'CONTENT_KEY': 144, 'NATIVE_ADMISSION': 152,
    'NATIVE_HASH': 160, 'TEMP': 168, 'TEMP2': 176, 'INDEX': 184,
    'REQ_A': 200, 'REQ_B': 208, 'REQ_C': 216, 'REQ_D': 224,
    'ISSUE_ID': 240, 'ISSUE_URI': 248,
    'SQL_CALLABLE': 256, 'FILE_CONTEXT': 264, 'DECODE_CALLABLE': 272,
    'REJECT_CALLABLE': 280, 'GET_JSON_CALLABLE': 288,
    'NEXT_NODE': 328, 'NEXT_DATA': 336, 'NODE_BASE': 32768, 'DATA_BASE': 65536,
    'FIRST_DYNAMIC': len(LITERALS) + 1,
})
FIELDS.update({'L_' + name: HIGH + index for index, name in enumerate(LITERALS, 1)})

SOURCE = r'''
def store_authority(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 262144 or length(o) < 8:
        return 199
    if get(w, 0) == 0:
        if length(s) != 88 or read64(s, 0) != MAGIC or read64(s, 8) != 0 or read64(s, 16) != 0:
            return 199
        mode = read64(s, 24)
        if mode > 5 or read64(s, 80) != 0:
            return 199
        put(w, 0, MAGIC)
        put(w, MODE, mode)
        put(w, STORE, read64(s, 32))
        put(w, ARG0, read64(s, 40))
        put(w, ARG1, read64(s, 48))
        put(w, ARG2, read64(s, 56))
        put(w, NONE, read64(s, 64))
        if read64(s, 72) != 0:
            return 199
        put(w, NATIVE_HASH, read64(s, 64))
        put(w, NEXT_NODE, FIRST_DYNAMIC)
        put(w, NEXT_DATA, DATA_BASE)
        constants(w)
        phase = 10
        if mode == 1:
            phase = 30
        elif mode == 2:
            phase = 60
        elif mode == 3:
            phase = 80
        elif mode == 4:
            phase = 110
        elif mode == 5:
            phase = 300
        put(w, PHASE, phase)
    else:
        if get(w, 0) != MAGIC or get(w, AWAIT) == 0 or length(s) < 64:
            return 199
        opcode = get(w, AWAIT)
        if read64(s, 0) != MAGIC or read64(s, 8) != get(w, SEQ) or read64(s, 16) != opcode or read64(s, 24) != 0:
            return 199
        size = 64
        if opcode == 3 or opcode == 4:
            if read64(s, 32) != get(w, REQ_C) or read64(s, 32) > 1024:
                return 199
            size = size + read64(s, 32) * 4
        if opcode == 34:
            size = 72
        if length(s) != size:
            return 199
        put(w, AWAIT, 0)
    while True:
        phase = get(w, PHASE)
        result = 199
        if phase >= 10 and phase < 30:
            result = project_ref(s, w, phase)
        elif phase >= 30 and phase < 60:
            result = read_artifact(s, w, phase)
        elif phase >= 60 and phase < 80:
            result = resolve_uri(s, w, phase)
        elif phase >= 80 and phase < 110:
            result = issue_profile(s, w, phase)
        elif phase >= 110 and phase < 130:
            result = check_profile(s, w, phase)
        elif phase >= 200 and phase < 240:
            result = equality(s, w, phase)
        elif phase >= 300 and phase < 340:
            result = put_artifact(s, w, phase)
        if result != 0:
            if result != 1:
                put(w, PHASE, 4294967295)
            return result
    return 199

def ask(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    put(w, AWAIT, opcode)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, REQ_A, a)
    put(w, REQ_B, b)
    put(w, REQ_C, c)
    put(w, REQ_D, d)
    put(w, PHASE, phase)
    return 1

def finish(w:mutbuf, result:u64) -> u64:
    put(w, RESULT, result)
    return 2

def refusal(w:mutbuf, code:u64, message:u64) -> u64:
    return ask(w, 16, code, message, 0, 0, 4294967295)

def ref_field(index:u64) -> u64:
    if index == 0:
        return L_ID
    if index == 1:
        return L_SHA
    return L_URI

def project_ref(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 10:
        return ask(w, 40, 0, 0, 0, 0, 11)
    if phase == 11:
        put(w, REF, read64(s, 32))
        put(w, INDEX, 0)
        put(w, PHASE, 12)
        return 0
    if phase == 12:
        if get(w, INDEX) == 3:
            return finish(w, get(w, REF))
        return ask(w, 5, get(w, ARG0), ref_field(get(w, INDEX)), 0, 0, 13)
    if phase == 13:
        return ask(w, 41, get(w, REF), ref_field(get(w, INDEX)), read64(s, 32), 0, 14)
    if phase == 14:
        put(w, INDEX, get(w, INDEX) + 1)
        put(w, PHASE, 12)
        return 0
    return 199

def read_artifact(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 30:
        return ask(w, 42, get(w, ARG0), 0, 0, 0, 31)
    if phase == 31:
        return ask(w, 63, 0, 0, 0, 0, 55)
    if phase == 55:
        put(w, SQL_CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, ARG0), L_ID, 0, 0, 32)
    if phase == 32:
        return ask(w, 43, L_SELECT_ID, tuple1(w, read64(s, 32)), get(w, SQL_CALLABLE), 0, 33)
    if phase == 33:
        put(w, ROW, read64(s, 32))
        if get(w, ROW) == get(w, NONE):
            return refusal(w, L_IDENTITY_CODE, L_IDENTITY_MESSAGE)
        return ask(w, 44, get(w, ROW), 0, 0, 0, 34)
    if phase == 34:
        return equal_begin(w, read64(s, 32), get(w, ARG0), 35)
    if phase == 35:
        if get(w, EQ_RESULT) == 0:
            return refusal(w, L_IDENTITY_CODE, L_IDENTITY_MESSAGE)
        if get(w, ARG1) == get(w, NONE):
            put(w, PHASE, 40)
            return 0
        return ask(w, 5, get(w, ROW), L_KIND, 0, 0, 36)
    if phase == 36:
        return equal_begin(w, read64(s, 32), get(w, ARG1), 37)
    if phase == 37:
        if get(w, EQ_RESULT) == 0:
            return ask(w, 67, 0, 0, 0, 0, 56)
        put(w, PHASE, 40)
        return 0
    if phase == 56:
        put(w, REJECT_CALLABLE, read64(s, 32))
        return ask(w, 33, L_AUTHORITY_PREFIX, get(w, ARG1), 0, 0, 38)
    if phase == 38:
        return ask(w, 16, L_AUTHORITY_CODE, read64(s, 32), get(w, REJECT_CALLABLE), 0, 4294967295)
    if phase == 39:
        return ask(w, 46, read64(s, 32), get(w, FILE_CONTEXT), 0, 0, 43)
    if phase == 40:
        return ask(w, 64, 0, 0, 0, 0, 52)
    if phase == 52:
        put(w, FILE_CONTEXT, tuple2(w, read64(s, 32), read64(s, 40)))
        return ask(w, 5, get(w, ROW), L_SHA, 0, 0, 41)
    if phase == 41:
        put(w, CONTENT_HASH, read64(s, 32))
        return ask(w, 45, L_STORE_GET, read64(s, 32), get(w, NONE), get(w, FILE_CONTEXT), 42)
    if phase == 42:
        if read64(s, 32) == get(w, NONE):
            return ask(w, 65, 0, 0, 0, 0, 53)
        put(w, DATA, read64(s, 32))
        put(w, PHASE, 49)
        return 0
    if phase == 53:
        put(w, FILE_CONTEXT, tuple2(w, read64(s, 32), read64(s, 40)))
        return ask(w, 5, get(w, ROW), L_SHA, 0, 0, 39)
    if phase == 43:
        put(w, DATA, read64(s, 32))
        return ask(w, 47, read64(s, 32), 0, 0, 0, 44)
    if phase == 44:
        put(w, TEMP, read64(s, 32))
        return ask(w, 5, get(w, ROW), L_SHA, 0, 0, 45)
    if phase == 45:
        return equal_begin(w, get(w, TEMP), read64(s, 32), 46)
    if phase == 46:
        if get(w, EQ_RESULT) == 0:
            return refusal(w, L_CORRUPT_CODE, L_CORRUPT_MESSAGE)
        put(w, PHASE, 49)
        return 0
    if phase == 49:
        return ask(w, 66, 0, 0, 0, 0, 54)
    if phase == 54:
        put(w, DECODE_CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, ROW), L_METADATA, 0, 0, 50)
    if phase == 50:
        return ask(w, 48, read64(s, 32), get(w, DECODE_CALLABLE), 0, 0, 51)
    if phase == 51:
        return finish(w, tuple2(w, get(w, DATA), read64(s, 32)))
    return 199

def resolve_uri(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 60:
        return ask(w, 43, L_SELECT_URI, tuple1(w, get(w, ARG0)), 0, 0, 61)
    if phase == 61:
        if read64(s, 32) == get(w, NONE):
            return refusal(w, L_IDENTITY_CODE, L_URI_MESSAGE)
        return ask(w, 44, read64(s, 32), 0, 0, 0, 62)
    if phase == 62:
        put(w, REF, read64(s, 32))
        return ask(w, 49, read64(s, 32), 0, 0, 0, 63)
    if phase == 63:
        return finish(w, get(w, REF))
    return 199

def issue_profile(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 80:
        return ask(w, 50, get(w, ARG1), L_PROFILE, 0, 0, 81)
    if phase == 81:
        put(w, REF, read64(s, 32))
        return ask(w, 5, read64(s, 32), L_SHA, 0, 0, 82)
    if phase == 82:
        result = object(w, 2)
        pair(w, result, 0, L_ID, get(w, ARG0))
        pair(w, result, 1, L_SHA, read64(s, 32))
        return ask(w, 51, result, 0, 0, 0, 83)
    if phase == 83:
        put(w, TEMP, read64(s, 32))
        return ask(w, 63, 0, 0, 0, 0, 88)
    if phase == 88:
        put(w, SQL_CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, REF), L_SHA, 0, 0, 84)
    if phase == 84:
        put(w, TEMP2, read64(s, 32))
        return ask(w, 52, get(w, REF), 0, 0, 0, 85)
    if phase == 85:
        return ask(w, 53, read64(s, 32), 0, 0, 0, 86)
    if phase == 86:
        params = tuple3(w, get(w, ARG0), get(w, TEMP2), read64(s, 32))
        return ask(w, 54, L_INSERT_PROFILE, params, get(w, SQL_CALLABLE), 0, 87)
    if phase == 87:
        return finish(w, tuple2(w, get(w, TEMP), get(w, REF)))
    return 199

def check_profile(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 110:
        return equal_begin(w, get(w, ARG0), get(w, ARG1), 111)
    if phase == 111:
        if get(w, EQ_RESULT) == 0:
            return refusal(w, L_PROFILE_STALE_CODE, L_PROFILE_STALE_MESSAGE)
        return ask(w, 63, 0, 0, 0, 0, 119)
    if phase == 119:
        put(w, SQL_CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, ARG0), L_ID, 0, 0, 112)
    if phase == 112:
        put(w, TEMP, read64(s, 32))
        return ask(w, 5, get(w, ARG0), L_SHA, 0, 0, 113)
    if phase == 113:
        return ask(w, 43, L_SELECT_PROFILE, tuple2(w, get(w, TEMP), read64(s, 32)), get(w, SQL_CALLABLE), 0, 114)
    if phase == 114:
        if read64(s, 32) == get(w, NONE):
            return refusal(w, L_PROFILE_AUTHORITY_CODE, L_PROFILE_AUTHORITY_MESSAGE)
        put(w, ROW, read64(s, 32))
        return ask(w, 68, 0, 0, 0, 0, 121)
    if phase == 121:
        put(w, GET_JSON_CALLABLE, read64(s, 32))
        return ask(w, 66, 0, 0, 0, 0, 120)
    if phase == 120:
        put(w, DECODE_CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, ROW), L_ARTIFACT, 0, 0, 115)
    if phase == 115:
        return ask(w, 48, read64(s, 32), get(w, DECODE_CALLABLE), 0, 0, 116)
    if phase == 116:
        return ask(w, 55, read64(s, 32), L_PROFILE, get(w, GET_JSON_CALLABLE), 0, 117)
    if phase == 117:
        return ask(w, 56, read64(s, 32), 0, 0, 0, 118)
    if phase == 118:
        return finish(w, read64(s, 32))
    return 199

def put_artifact(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 300:
        return ask(w, 57, get(w, ARG0), 0, 0, 0, 301)
    if phase == 301:
        if read64(s, 32) > 1:
            return 199
        if read64(s, 32) == 0 or read64(s, 40) > 67108864:
            return refusal(w, L_LIMIT_CODE, L_LIMIT_MESSAGE)
        put(w, META, get(w, ARG2))
        if get(w, META) == get(w, NONE):
            return ask(w, 40, 0, 0, 0, 0, 302)
        put(w, PHASE, 303)
        return 0
    if phase == 302:
        put(w, META, read64(s, 32))
        put(w, PHASE, 303)
        return 0
    if phase == 303:
        return ask(w, 58, 0, 0, 0, 0, 304)
    if phase == 304:
        put(w, NATIVE_ADMISSION, read64(s, 32))
        if read64(s, 32) == get(w, NONE):
            return ask(w, 47, get(w, ARG0), 0, 0, 0, 307)
        return ask(w, 45, L_STORE_HASH, get(w, ARG0), read64(s, 32), 0, 305)
    if phase == 305:
        put(w, NATIVE_HASH, read64(s, 32))
        if read64(s, 32) == get(w, NONE):
            return ask(w, 47, get(w, ARG0), 0, 0, 0, 307)
        return ask(w, 5, read64(s, 32), L_SHA, 0, 0, 307)
    if phase == 307:
        put(w, CONTENT_HASH, read64(s, 32))
        content = object(w, 3)
        pair(w, content, 0, L_SHA, read64(s, 32))
        pair(w, content, 1, L_KIND, get(w, ARG1))
        pair(w, content, 2, L_METADATA, get(w, META))
        return ask(w, 59, content, 0, 0, 0, 308)
    if phase == 308:
        put(w, CONTENT_KEY, read64(s, 32))
        return ask(w, 43, L_SELECT_CONTENT, tuple1(w, read64(s, 32)), 0, 0, 309)
    if phase == 309:
        if read64(s, 32) != get(w, NONE):
            return ask(w, 44, read64(s, 32), 0, 0, 0, 310)
        if get(w, NATIVE_HASH) != get(w, NONE):
            return ask(w, 45, L_STORE_PUT, get(w, ARG0), get(w, NATIVE_ADMISSION), 0, 312)
        return ask(w, 60, get(w, CONTENT_HASH), get(w, ARG0), 0, 0, 315)
    if phase == 310:
        put(w, REF, read64(s, 32))
        return ask(w, 61, read64(s, 32), get(w, ARG1), 0, 0, 311)
    if phase == 311:
        return finish(w, get(w, REF))
    if phase == 312:
        return equal_begin(w, read64(s, 32), get(w, NATIVE_HASH), 313)
    if phase == 313:
        if get(w, EQ_RESULT) == 0:
            return refusal(w, L_CORRUPT_CODE, L_PUBLICATION_MESSAGE)
        put(w, PHASE, 315)
        return 0
    if phase == 315:
        return ask(w, 62, 0, 0, 0, 0, 316)
    if phase == 316:
        return ask(w, 7, read64(s, 32), L_HEX, 0, 0, 317)
    if phase == 317:
        put(w, TEMP, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 318)
    if phase == 318:
        if read64(s, 32) == 4:
            put(w, ISSUE_ID, concat(w, L_ID_PREFIX, get(w, TEMP), 2, read64(s, 40)))
            put(w, PHASE, 320)
            return 0
        return ask(w, 33, L_ID_PREFIX, get(w, TEMP), 0, 0, 319)
    if phase == 319:
        put(w, ISSUE_ID, read64(s, 32))
        put(w, PHASE, 320)
        return 0
    if phase == 320:
        return ask(w, 62, 0, 0, 0, 0, 321)
    if phase == 321:
        return ask(w, 7, read64(s, 32), L_HEX, 0, 0, 322)
    if phase == 322:
        put(w, TEMP, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 323)
    if phase == 323:
        if read64(s, 32) == 4:
            put(w, ISSUE_URI, concat(w, L_URI_PREFIX, get(w, TEMP), 16, read64(s, 40)))
            put(w, PHASE, 325)
            return 0
        return ask(w, 33, L_URI_PREFIX, get(w, TEMP), 0, 0, 324)
    if phase == 324:
        put(w, ISSUE_URI, read64(s, 32))
        put(w, PHASE, 325)
        return 0
    if phase == 325:
        ref = object(w, 3)
        pair(w, ref, 0, L_ID, get(w, ISSUE_ID))
        pair(w, ref, 1, L_SHA, get(w, CONTENT_HASH))
        pair(w, ref, 2, L_URI, get(w, ISSUE_URI))
        return ask(w, 51, ref, 0, 0, 0, 326)
    if phase == 326:
        put(w, REF, read64(s, 32))
        return ask(w, 63, 0, 0, 0, 0, 334)
    if phase == 334:
        put(w, SQL_CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, REF), L_ID, 0, 0, 327)
    if phase == 327:
        put(w, ISSUE_ID, read64(s, 32))
        return ask(w, 5, get(w, REF), L_URI, 0, 0, 328)
    if phase == 328:
        put(w, ISSUE_URI, read64(s, 32))
        return ask(w, 52, get(w, META), 0, 0, 0, 329)
    if phase == 329:
        return ask(w, 53, read64(s, 32), 0, 0, 0, 330)
    if phase == 330:
        params = tuple6(w, get(w, ISSUE_ID), get(w, CONTENT_HASH), get(w, ISSUE_URI), get(w, ARG1), read64(s, 32), get(w, CONTENT_KEY))
        return ask(w, 54, L_INSERT_ARTIFACT, params, get(w, SQL_CALLABLE), 0, 331)
    if phase == 331:
        return ask(w, 43, L_SELECT_CONTENT, tuple1(w, get(w, CONTENT_KEY)), 0, 0, 332)
    if phase == 332:
        return ask(w, 44, read64(s, 32), 0, 0, 0, 333)
    if phase == 333:
        return finish(w, read64(s, 32))
    return 199

def tuple_node(w:mutbuf, size:u64) -> u64:
    data = get(w, NEXT_DATA)
    put(w, NEXT_DATA, data + size * 8)
    return node(w, 6, size, 0, data, 0, 0)

def tuple_item(w:mutbuf, handle:u64, index:u64, value:u64) -> u64:
    at = NODE_BASE + (handle - HIGH) * 48
    return put(w, get(w, at + 24) + index * 8, value)

def tuple1(w:mutbuf, a:u64) -> u64:
    result = tuple_node(w, 1)
    tuple_item(w, result, 0, a)
    return result

def tuple2(w:mutbuf, a:u64, b:u64) -> u64:
    result = tuple_node(w, 2)
    tuple_item(w, result, 0, a)
    tuple_item(w, result, 1, b)
    return result

def tuple3(w:mutbuf, a:u64, b:u64, c:u64) -> u64:
    result = tuple_node(w, 3)
    tuple_item(w, result, 0, a)
    tuple_item(w, result, 1, b)
    tuple_item(w, result, 2, c)
    return result

def tuple6(w:mutbuf, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u64:
    result = tuple_node(w, 6)
    tuple_item(w, result, 0, a)
    tuple_item(w, result, 1, b)
    tuple_item(w, result, 2, c)
    tuple_item(w, result, 3, d)
    tuple_item(w, result, 4, e)
    tuple_item(w, result, 5, f)
    return result
'''


def helper_program():
    names = {'node', 'slice', 'concat', 'object', 'pair', 'read64', 'read32',
             'get', 'put', 'get32', 'put32'}
    helpers = [node for node in ast.parse(equality_source.SOURCE).body if node.name in names]
    if {node.name for node in helpers} != names:
        raise ValueError('worker equality/virtual-node helpers changed')
    return ast.unparse(ast.Module(body=helpers, type_ignores=[])) + '\n'


def constant_program():
    lines = []
    offset = 49152
    for index, text in enumerate(LITERALS.values(), 1):
        at = 32768 + index * 48
        lines += [f'    put(w, {at}, 4)', f'    put(w, {at + 8}, {len(text)})',
                  f'    put(w, {at + 24}, {offset})']
        for point in map(ord, text):
            lines.append(f'    put32(w, {offset}, {point})')
            offset += 4
    if offset >= 65536:
        raise ValueError('AgentStore literals crossed their private extent')
    # Keep each ordinary Core function below the unchanged native compiler's
    # 2048 value-slot bound. The initial single literal function was genuinely
    # refused; splitting only preserves the original ordered stores/calls.
    chunks = [lines[index:index + 240] for index in range(0, len(lines), 240)]
    functions = []
    for index, chunk in enumerate(chunks):
        functions += [f'def constant_part_{index}(w:mutbuf) -> u64:', *chunk, '    return 0', '']
    functions += ['def constants(w:mutbuf) -> u64:']
    functions += [f'    constant_part_{index}(w)' for index in range(len(chunks))]
    return '\n'.join(functions + ['    return 0', ''])


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node
    tree = Constants().visit(ast.parse(SOURCE + helper_program() + equality_source.EQUALITY + constant_program()))
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([arg.annotation.id for arg in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for n in nodes:
        b = Builder(n, names, signatures, total)
        b.statements(n.body)
        functions.append({'name': names[n.name], 'params': [b.param(v) for v in b.params],
                          'returns': [b.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_store_authority', 'functions': functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
