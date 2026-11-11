"""Author the ordinary worker control/report owner and virtual graph in HIA.

Request admission remains the independently selected existing owner. The host
performs only HIA-requested effects and foreign object/runtime observations.
"""
from __future__ import annotations

import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/worker_report.hiaasm'
MAGIC = int.from_bytes(b'HIAWKR02', 'little')
HIGH = 1 << 63
LITERALS = {
    'SCHEMA_KEY': 'schema', 'REPORT_SCHEMA': 'hia-agent-worker-report-v1',
    'TOOL': 'tool', 'REQUEST_SHA': 'request_sha256', 'PROFILE_SHA': 'profile_sha256',
    'CATALOG_SHA': 'catalog_sha256', 'BACKEND_SHA': 'backend_sha256', 'WORKER_SHA': 'worker_sha256',
    'COMPLETE': 'complete', 'RESPONSE': 'response', 'ARGUMENTS': 'arguments', 'VERSION_KEY': 'contract_version',
    'REQUEST_ID': 'request_id', 'STATUS': 'status', 'REJECTED': 'rejected', 'ERROR': 'error',
    'CODE': 'code', 'PHASE_KEY': 'phase', 'ADMISSION': 'admission', 'MESSAGE': 'message',
    'RETRY': 'retry_action', 'DETAILS': 'details_artifact', 'CORRECT': 'correct_input',
    'DEFAULT_CODE': 'E_HIA_WORKER', 'PIN_CODE': 'E_HIA_WORKER_PIN',
    'PIN_MESSAGE': 'administrator source pin differs before execution', 'STOP': 'stop',
    'STALE_CODE': 'E_HIA_IMPLEMENTATION_STALE',
    'STALE_MESSAGE': 'installed source changed during operation; observe original job',
    'OBSERVE': 'observe_original', 'UNKNOWN_CODE': 'E_HIA_REQUEST_UNKNOWN',
    'UNKNOWN_MESSAGE': 'worker could not attest the terminal result after entering the service; observe the original job',
    'PREFIX_TEXT': 'worker-', 'NEWLINE': '\n', 'CALL': 'call', 'CLOSE': 'close', 'HEX': 'hex', 'ADMIT': 'admit',
    'REQUEST_SELECTOR': 'HEPTA_HIA_WORKER_REQUEST_MANIFEST',
    'FORMAT_SELECTOR': 'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST',
    'MODE_ERROR': 'manifest read and request execution are distinct modes',
    'ARG_ERROR': 'request execution requires --state-root and --request-json-stdin',
}
CONSTANTS = {name: HIGH + i for i, name in enumerate(LITERALS, 1)}
FIELDS = {
    'MAGIC': MAGIC, 'HIGH': HIGH,
    'AWAIT': 8, 'SEQ': 16, 'PHASE': 24, 'EXC': 32, 'EXC_DOMAIN': 40,
    'ENTERED': 48, 'REQUEST': 56, 'IDENTITIES': 64, 'AFTER': 72, 'REPLY': 80,
    'SERVICE': 88, 'PENDING_EXC': 96, 'PENDING_DOMAIN': 104, 'CATCH': 112,
    'CALL_REGION': 120, 'CLOSE_REGION': 128, 'RAW': 136, 'SELECTED': 144,
    'CALLABLE': 152, 'ARG_ONE': 160, 'ARG_TWO': 168, 'PIN_INDEX': 176,
    'EXPECTED': 184, 'RETURN_CODE': 192,
    'REQ_A': 200, 'REQ_B': 208, 'REQ_C': 216, 'REQ_D': 224,
    'MANIFEST_MODE': 256, 'REQUEST_MODE': 264, 'STATE_ROOT': 272, 'ARTIFACT_ROOTS': 280,
    'PIN_WORKER': 288, 'PIN_BACKEND': 296, 'PIN_CATALOG': 304,
    'VERSION': 312, 'NONE': 320, 'NEXT_NODE': 328, 'NEXT_DATA': 336,
    'ERROR_ID': 344, 'ERROR_CODE': 352, 'ERROR_MESSAGE': 360, 'ERROR_RETRY': 368,
    'TEMP': 376, 'REPORT': 384, 'REPORT_INDEX': 392, 'WIRE_ROOT': 400,
    'FORMAT_IMAGE': 408,
    'HANDLED_EXC': 416, 'REQ_CONTEXT': 424,
    'EQ_LEFT': 512, 'EQ_RIGHT': 520, 'EQ_NEXT': 528, 'EQ_RESULT': 536,
    'EQ_DEPTH': 544, 'EQ_LIMIT': 552, 'EQ_CHILD': 560,
    'EL_KIND': 568, 'EL_SIZE': 576, 'EL_A': 584, 'EL_B': 592,
    'ER_KIND': 600, 'ER_SIZE': 608, 'ER_A': 616, 'ER_B': 624,
    'EQ_INDEX': 632, 'EQ_COUNT': 640, 'EQ_RECORD': 648,
    'EQ_LEAF_NE': 656, 'EQ_OPAQUE_RESULT': 664,
    'EQ_TOTAL': 672,
    'NODE_BASE': 32768, 'DATA_BASE': 65536, 'EQ_BASE': 131072,
    'EQ_CHUNK_A': 8192, 'EQ_CHUNK_B': 12288,
}
FIELDS.update({'L_' + key: value for key, value in CONSTANTS.items()})
FIELDS['FIRST_DYNAMIC'] = len(LITERALS) + 3
FIELDS['TRUE_NODE'] = HIGH + len(LITERALS) + 1
FIELDS['FALSE_NODE'] = HIGH + len(LITERALS) + 2

SOURCE = r'''
def worker_report(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 262144 or length(o) < 8:
        return 199
    if get(w, 0) == 0:
        if length(s) != 112 or read64(s, 0) != MAGIC or read64(s, 8) != 0 or read64(s, 16) != 0:
            return 199
        if read64(s, 24) > 1 or read64(s, 32) > 1 or read64(s, 104) != 0:
            return 199
        put(w, 0, MAGIC)
        put(w, MANIFEST_MODE, read64(s, 24))
        put(w, REQUEST_MODE, read64(s, 32))
        put(w, STATE_ROOT, read64(s, 40))
        put(w, ARTIFACT_ROOTS, read64(s, 48))
        put(w, PIN_WORKER, read64(s, 56))
        put(w, PIN_BACKEND, read64(s, 64))
        put(w, PIN_CATALOG, read64(s, 72))
        put(w, IDENTITIES, read64(s, 80))
        put(w, VERSION, read64(s, 88))
        put(w, NONE, read64(s, 96))
        put(w, REQUEST, read64(s, 96))
        put(w, NEXT_NODE, FIRST_DYNAMIC)
        put(w, NEXT_DATA, DATA_BASE)
        constants(w)
        put(w, PHASE, 1)
    else:
        if get(w, 0) != MAGIC or get(w, AWAIT) == 0 or length(s) < 64:
            return 199
        opcode = get(w, AWAIT)
        if read64(s, 0) != MAGIC or read64(s, 8) != get(w, SEQ) or read64(s, 16) != opcode or read64(s, 24) > 1:
            return 199
        size = 64
        if read64(s, 24) == 0 and (opcode == 3 or opcode == 4):
            if read64(s, 32) != get(w, REQ_C) or read64(s, 32) > 1024:
                return 199
            size = size + read64(s, 32) * 4
        if read64(s, 24) == 0 and opcode == 34:
            size = 72
        if length(s) != size:
            return 199
        put(w, AWAIT, 0)
        if read64(s, 24) != 0:
            if (opcode == 15 or opcode == 30) and read64(s, 48) != 0:
                put(w, REQUEST, read64(s, 48))
            exception = read64(s, 32)
            domain = read64(s, 40)
            if exception == 0 or domain > 1:
                return 199
            if get(w, CALL_REGION) != 0:
                put(w, CALL_REGION, 0)
                put(w, PENDING_EXC, exception)
                put(w, PENDING_DOMAIN, domain)
                put(w, PHASE, 23)
            elif get(w, CLOSE_REGION) != 0:
                put(w, CLOSE_REGION, 0)
                put(w, PENDING_EXC, exception)
                put(w, PENDING_DOMAIN, domain)
                put(w, PHASE, 29)
            else:
                result = caught(w, exception, domain)
                if result != 0:
                    return result
    while True:
        phase = get(w, PHASE)
        result = 199
        if phase < 50:
            result = control(s, w, phase)
        elif phase < 100:
            result = reporting(s, w, phase)
        elif phase >= 200 and phase < 240:
            result = equality(s, w, phase)
        if result != 0:
            if result != 1:
                put(w, PHASE, 4294967295)
            return result
    return 199

def ask(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    active = get(w, HANDLED_EXC)
    if get(w, CLOSE_REGION) != 0 and get(w, PENDING_EXC) != 0:
        active = get(w, PENDING_EXC)
    put(w, REQ_CONTEXT, active)
    put(w, AWAIT, opcode)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, REQ_A, a)
    put(w, REQ_B, b)
    put(w, REQ_C, c)
    put(w, REQ_D, d)
    put(w, PHASE, phase)
    return 1

def caught(w:mutbuf, exception:u64, domain:u64) -> u64:
    put(w, EXC, exception)
    put(w, EXC_DOMAIN, domain)
    if get(w, CATCH) == 0 or domain == 0:
        return 3
    put(w, HANDLED_EXC, exception)
    put(w, CATCH, 0)
    put(w, PHASE, 50)
    return 0

def control(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        if get(w, MANIFEST_MODE) != 0:
            put(w, WIRE_ROOT, get(w, IDENTITIES))
            if get(w, REQUEST_MODE) != 0:
                return ask(w, 22, L_MODE_ERROR, 0, 0, 0, 90)
            put(w, PHASE, 90)
            return 0
        return ask(w, 1, get(w, STATE_ROOT), 0, 0, 0, 2)
    if phase == 2:
        if read64(s, 32) == 0 or (read64(s, 32) == 4 and read64(s, 40) == 0) or get(w, REQUEST_MODE) == 0:
            return ask(w, 22, L_ARG_ERROR, 0, 0, 0, 3)
        put(w, PHASE, 3)
        return 0
    if phase == 3:
        put(w, CATCH, 1)
        index = get(w, PIN_INDEX)
        if index == 3:
            return ask(w, 11, 8388609, 0, 0, 0, 10)
        expected = get(w, PIN_WORKER + index * 8)
        put(w, EXPECTED, expected)
        return ask(w, 1, expected, 0, 0, 0, 4)
    if phase == 4:
        if read64(s, 32) == 0:
            put(w, PIN_INDEX, get(w, PIN_INDEX) + 1)
            put(w, PHASE, 3)
            return 0
        return ask(w, 5, get(w, IDENTITIES), pin_field(get(w, PIN_INDEX)), 0, 0, 5)
    if phase == 5:
        return equal_begin(w, get(w, EXPECTED), read64(s, 32), 7)
    if phase == 7:
        if get(w, EQ_RESULT) == 0:
            return ask(w, 16, L_PIN_CODE, L_PIN_MESSAGE, L_STOP, 1, 3)
        put(w, PIN_INDEX, get(w, PIN_INDEX) + 1)
        put(w, PHASE, 3)
        return 0
    if phase == 10:
        put(w, RAW, read64(s, 32))
        return ask(w, 13, L_REQUEST_SELECTOR, 0, 0, 0, 11)
    if phase == 11:
        put(w, SELECTED, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 12)
    if phase == 12:
        if read64(s, 32) == 0 or (read64(s, 32) == 4 and read64(s, 40) == 0):
            return ask(w, 15, get(w, RAW), get(w, IDENTITIES), 0, 0, 17)
        return ask(w, 14, get(w, SELECTED), 0, 0, 0, 13)
    if phase == 13:
        return ask(w, 7, read64(s, 32), L_ADMIT, 0, 0, 14)
    if phase == 14:
        put(w, CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, IDENTITIES), L_CATALOG_SHA, 0, 0, 15)
    if phase == 15:
        return ask(w, 30, get(w, CALLABLE), get(w, RAW), read64(s, 32), 0, 16)
    if phase == 16 or phase == 17:
        put(w, REQUEST, read64(s, 32))
        return ask(w, 10, get(w, STATE_ROOT), get(w, ARTIFACT_ROOTS), 0, 0, 18)
    if phase == 18:
        put(w, SERVICE, read64(s, 32))
        put(w, ENTERED, 1)
        put(w, CALL_REGION, 1)
        return ask(w, 7, get(w, SERVICE), L_CALL, 0, 0, 19)
    if phase == 19:
        put(w, CALLABLE, read64(s, 32))
        return ask(w, 5, get(w, REQUEST), L_TOOL, 0, 0, 20)
    if phase == 20:
        put(w, ARG_ONE, read64(s, 32))
        return ask(w, 5, get(w, REQUEST), L_ARGUMENTS, 0, 0, 21)
    if phase == 21:
        return ask(w, 9, get(w, CALLABLE), get(w, ARG_ONE), read64(s, 32), 0, 22)
    if phase == 22:
        put(w, REPLY, read64(s, 32))
        put(w, CALL_REGION, 0)
        put(w, PENDING_EXC, 0)
        put(w, PHASE, 23)
        return 0
    if phase == 23:
        put(w, CLOSE_REGION, 1)
        return ask(w, 7, get(w, SERVICE), L_CLOSE, 0, 0, 24)
    if phase == 24:
        return ask(w, 8, read64(s, 32), 0, 0, 0, 25)
    if phase == 25:
        put(w, CLOSE_REGION, 0)
        put(w, PHASE, 29)
        return 0
    if phase == 29:
        if get(w, PENDING_EXC) != 0:
            return caught(w, get(w, PENDING_EXC), get(w, PENDING_DOMAIN))
        return ask(w, 12, 0, 0, 0, 0, 26)
    if phase == 26:
        put(w, AFTER, read64(s, 32))
        return equal_begin(w, read64(s, 32), get(w, IDENTITIES), 28)
    if phase == 28:
        if get(w, EQ_RESULT) == 0:
            put(w, IDENTITIES, get(w, AFTER))
            return ask(w, 16, L_STALE_CODE, L_STALE_MESSAGE, L_OBSERVE, 1, 80)
        put(w, CATCH, 0)
        put(w, PHASE, 80)
        return 0
    return 199

def pin_field(index:u64) -> u64:
    if index == 0:
        return L_WORKER_SHA
    return choose(index == 1, L_BACKEND_SHA, L_CATALOG_SHA)

def request_field(index:u64) -> u64:
    if index == 0:
        return L_TOOL
    if index == 1:
        return L_REQUEST_SHA
    return choose(index == 2, L_PROFILE_SHA, L_CATALOG_SHA)

def reporting(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 50:
        put(w, REPORT_INDEX, 0)
        return ask(w, 1, get(w, REQUEST), 0, 0, 0, 51)
    if phase == 51:
        if read64(s, 32) != 7:
            return ask(w, 18, get(w, EXC), 0, 0, 0, 55)
        return ask(w, 6, get(w, REQUEST), request_field(0), 0, 0, 52)
    if phase == 52:
        if read64(s, 32) == 0:
            return ask(w, 18, get(w, EXC), 0, 0, 0, 55)
        index = get(w, REPORT_INDEX) + 1
        put(w, REPORT_INDEX, index)
        if index < 4:
            return ask(w, 6, get(w, REQUEST), request_field(index), 0, 0, 52)
        if get(w, ENTERED) != 0:
            return ask(w, 16, L_UNKNOWN_CODE, L_UNKNOWN_MESSAGE, L_OBSERVE, 0, 54)
        put(w, PHASE, 60)
        return 0
    if phase == 54:
        put(w, EXC, read64(s, 32))
        put(w, PHASE, 60)
        return 0
    if phase == 55:
        put(w, TEMP, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 56)
    if phase == 56:
        if read64(s, 32) == 4:
            count = choose(read64(s, 40) < 4096, read64(s, 40), 4096)
            text = slice(w, get(w, TEMP), 0, count)
            line = concat(w, text, L_NEWLINE, count, 1)
            return ask(w, 26, line, 0, 0, 0, 57)
        return ask(w, 32, get(w, TEMP), 4096, 0, 0, 58)
    if phase == 58:
        return ask(w, 33, read64(s, 32), L_NEWLINE, 0, 0, 59)
    if phase == 59:
        return ask(w, 26, read64(s, 32), 0, 0, 0, 57)
    if phase == 57:
        put(w, RETURN_CODE, 2)
        return 2
    if phase == 60:
        return ask(w, 17, 0, 0, 0, 0, 61)
    if phase == 61:
        return ask(w, 7, read64(s, 32), L_HEX, 0, 0, 62)
    if phase == 62:
        put(w, TEMP, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 63)
    if phase == 63:
        if read64(s, 32) == 4:
            put(w, ERROR_ID, concat(w, L_PREFIX_TEXT, get(w, TEMP), 7, read64(s, 40)))
            return ask(w, 7, get(w, EXC), L_CODE, L_DEFAULT_CODE, 1, 65)
        return ask(w, 33, L_PREFIX_TEXT, get(w, TEMP), 0, 0, 64)
    if phase == 64:
        put(w, ERROR_ID, read64(s, 32))
        return ask(w, 7, get(w, EXC), L_CODE, L_DEFAULT_CODE, 1, 65)
    if phase == 65:
        put(w, ERROR_CODE, read64(s, 32))
        return ask(w, 18, get(w, EXC), 0, 0, 0, 66)
    if phase == 66:
        put(w, TEMP, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 67)
    if phase == 67:
        if read64(s, 32) == 4:
            size = read64(s, 40)
            if size == 0:
                return ask(w, 19, get(w, EXC), 0, 0, 0, 70)
            put(w, ERROR_MESSAGE, slice(w, get(w, TEMP), 0, choose(size < 4096, size, 4096)))
            return ask(w, 7, get(w, EXC), L_RETRY, L_CORRECT, 1, 71)
        return ask(w, 32, get(w, TEMP), 4096, 0, 0, 68)
    if phase == 68:
        put(w, ERROR_MESSAGE, read64(s, 32))
        return ask(w, 21, read64(s, 32), 0, 0, 0, 69)
    if phase == 69:
        if read64(s, 32) == 0:
            return ask(w, 19, get(w, EXC), 0, 0, 0, 70)
        return ask(w, 7, get(w, EXC), L_RETRY, L_CORRECT, 1, 71)
    if phase == 70:
        put(w, ERROR_MESSAGE, read64(s, 32))
        return ask(w, 7, get(w, EXC), L_RETRY, L_CORRECT, 1, 71)
    if phase == 71:
        put(w, ERROR_RETRY, read64(s, 32))
        error = object(w, 5)
        pair(w, error, 0, L_CODE, get(w, ERROR_CODE))
        pair(w, error, 1, L_PHASE_KEY, L_ADMISSION)
        pair(w, error, 2, L_MESSAGE, get(w, ERROR_MESSAGE))
        pair(w, error, 3, L_RETRY, get(w, ERROR_RETRY))
        pair(w, error, 4, L_DETAILS, get(w, NONE))
        response = object(w, 4)
        pair(w, response, 0, L_VERSION_KEY, get(w, VERSION))
        pair(w, response, 1, L_REQUEST_ID, get(w, ERROR_ID))
        pair(w, response, 2, L_STATUS, L_REJECTED)
        pair(w, response, 3, L_ERROR, error)
        put(w, REPLY, response)
        put(w, PHASE, 80)
        return 0
    if phase == 80:
        put(w, CATCH, 0)
        put(w, HANDLED_EXC, 0)
        report = object(w, 9)
        put(w, REPORT, report)
        pair(w, report, 0, L_SCHEMA_KEY, L_REPORT_SCHEMA)
        put(w, REPORT_INDEX, 0)
        return ask(w, 5, get(w, REQUEST), request_field(0), 0, 0, 81)
    if phase == 81:
        index = get(w, REPORT_INDEX)
        pair(w, get(w, REPORT), index + 1, request_field(index), read64(s, 32))
        index = index + 1
        put(w, REPORT_INDEX, index)
        if index < 4:
            return ask(w, 5, get(w, REQUEST), request_field(index), 0, 0, 81)
        return ask(w, 5, get(w, IDENTITIES), L_BACKEND_SHA, 0, 0, 82)
    if phase == 82:
        pair(w, get(w, REPORT), 5, L_BACKEND_SHA, read64(s, 32))
        return ask(w, 5, get(w, IDENTITIES), L_WORKER_SHA, 0, 0, 83)
    if phase == 83:
        pair(w, get(w, REPORT), 6, L_WORKER_SHA, read64(s, 32))
        pair(w, get(w, REPORT), 7, L_COMPLETE, TRUE_NODE)
        pair(w, get(w, REPORT), 8, L_RESPONSE, get(w, REPLY))
        put(w, WIRE_ROOT, get(w, REPORT))
        put(w, PHASE, 90)
        return 0
    if phase == 90:
        return ask(w, 13, L_FORMAT_SELECTOR, 0, 0, 0, 91)
    if phase == 91:
        put(w, SELECTED, read64(s, 32))
        return ask(w, 1, read64(s, 32), 0, 0, 0, 92)
    if phase == 92:
        if read64(s, 32) == 0 or (read64(s, 32) == 4 and read64(s, 40) == 0):
            return ask(w, 24, get(w, WIRE_ROOT), 0, 0, 0, 94)
        return ask(w, 23, get(w, SELECTED), 0, 0, 0, 93)
    if phase == 93:
        return ask(w, 24, get(w, WIRE_ROOT), read64(s, 32), 0, 0, 94)
    if phase == 94:
        return ask(w, 25, read64(s, 32), L_NEWLINE, 0, 0, 95)
    if phase == 95:
        put(w, RETURN_CODE, 0)
        return 2
    return 199

def node(w:mutbuf, kind:u64, size:u64, subtype:u64, a:u64, b:u64, c:u64) -> u64:
    index = get(w, NEXT_NODE)
    at = NODE_BASE + index * 48
    put(w, at, kind)
    put(w, at + 8, size)
    put(w, at + 16, subtype)
    put(w, at + 24, a)
    put(w, at + 32, b)
    put(w, at + 40, c)
    put(w, NEXT_NODE, index + 1)
    return HIGH | index

def slice(w:mutbuf, source:u64, start:u64, size:u64) -> u64:
    return node(w, 4, size, 1, source, start, 0)

def concat(w:mutbuf, left:u64, right:u64, a:u64, b:u64) -> u64:
    return node(w, 4, a + b, 2, left, right, a)

def object(w:mutbuf, size:u64) -> u64:
    at = get(w, NEXT_DATA)
    put(w, NEXT_DATA, at + size * 16)
    return node(w, 7, size, 0, at, 0, 0)

def pair(w:mutbuf, handle:u64, index:u64, key:u64, value:u64) -> u64:
    at = get(w, NODE_BASE + (handle - HIGH) * 48 + 24) + index * 16
    put(w, at, key)
    put(w, at + 8, value)
    return 0

def read64(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def read32(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def get32(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put32(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''

EQUALITY = r'''
def equal_begin(w:mutbuf, left:u64, right:u64, next:u64) -> u64:
    put(w, EQ_LEFT, left)
    put(w, EQ_RIGHT, right)
    put(w, EQ_NEXT, next)
    put(w, EQ_DEPTH, 0)
    put(w, EQ_CHILD, 0)
    return ask(w, 35, 0, 0, 0, 0, 200)

def eq_done(w:mutbuf, equal:u64) -> u64:
    if equal == 0 or get(w, EQ_DEPTH) == 0:
        put(w, EQ_RESULT, equal)
        put(w, EQ_DEPTH, 0)
        put(w, PHASE, get(w, EQ_NEXT))
    else:
        put(w, PHASE, 205)
    return 0

def eq_pop(w:mutbuf, equal:u64) -> u64:
    put(w, EQ_DEPTH, get(w, EQ_DEPTH) - 1)
    return eq_done(w, equal)

def eq_child(w:mutbuf, left:u64, right:u64) -> u64:
    put(w, EQ_LEFT, left)
    put(w, EQ_RIGHT, right)
    put(w, EQ_CHILD, 1)
    put(w, PHASE, 201)
    return 0

def eq_frame(w:mutbuf) -> u64:
    return EQ_BASE + (get(w, EQ_DEPTH) - 1) * 64

def equality(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 200:
        if read64(s, 32) == 0:
            return 199
        put(w, EQ_LIMIT, read64(s, 32))
        put(w, PHASE, 201)
        return 0
    if phase == 201:
        return ask(w, 1, get(w, EQ_LEFT), 0, 0, 0, 202)
    if phase == 202:
        index = 0
        while index < 4:
            put(w, EL_KIND + index * 8, read64(s, 32 + index * 8))
            index = index + 1
        kind = get(w, EL_KIND)
        if get(w, EQ_LEFT) == get(w, EQ_RIGHT):
            if get(w, EQ_CHILD) != 0 or (kind >= 5 and kind <= 7):
                return eq_done(w, 1)
        return ask(w, 1, get(w, EQ_RIGHT), 0, 0, 0, 203)
    if phase == 203:
        index = 0
        while index < 4:
            put(w, ER_KIND + index * 8, read64(s, 32 + index * 8))
            index = index + 1
        a = get(w, EL_KIND)
        b = get(w, ER_KIND)
        if a == 8 or b == 8:
            put(w, EQ_LEAF_NE, choose(get(w, EQ_CHILD) == 0, 1, 0))
            return ask(w, 20, get(w, EQ_LEFT), get(w, EQ_RIGHT), get(w, EQ_LEAF_NE), 0, 220)
        if a >= 1 and a <= 3 and b >= 1 and b <= 3:
            put(w, PHASE, 212)
            return 0
        if a != b:
            return eq_done(w, 0)
        if a == 0:
            return eq_done(w, 1)
        if get(w, EL_SIZE) != get(w, ER_SIZE):
            return eq_done(w, 0)
        if a == 4:
            put(w, EQ_INDEX, 0)
            put(w, PHASE, 206)
            return 0
        if a >= 5 and a <= 7:
            if get(w, EL_SIZE) == 0:
                return eq_done(w, 1)
            put(w, PHASE, 204)
            return 0
        return 199
    if phase == 204:
        depth = get(w, EQ_DEPTH)
        if depth >= get(w, EQ_LIMIT):
            return ask(w, 37, 0, 0, 0, 0, 204)
        if EQ_BASE + (depth + 1) * 64 > length(w):
            return ask(w, 36, length(w) * 2, 0, 0, 0, 204)
        frame = EQ_BASE + depth * 64
        put(w, frame, get(w, EQ_LEFT))
        put(w, frame + 8, get(w, EQ_RIGHT))
        put(w, frame + 16, get(w, EL_KIND))
        put(w, frame + 24, get(w, EL_SIZE))
        put(w, frame + 32, 0)
        put(w, frame + 40, 0)
        put(w, EQ_DEPTH, depth + 1)
        put(w, PHASE, 205)
        return 0
    if phase == 205:
        frame = eq_frame(w)
        kind = get(w, frame + 16)
        if kind == 7:
            return ask(w, 34, get(w, frame), get(w, frame + 40), 0, 0, 224)
        if kind == 5:
            return ask(w, 1, get(w, frame), 0, 0, 0, 228)
        if get(w, frame + 32) == get(w, frame + 24):
            return eq_pop(w, 1)
        return ask(w, 2, get(w, frame), get(w, frame + 32), 0, 0, 226)
    if phase == 206:
        remaining = get(w, EL_SIZE) - get(w, EQ_INDEX)
        if remaining == 0:
            return eq_done(w, 1)
        count = choose(remaining < 1024, remaining, 1024)
        put(w, EQ_COUNT, count)
        return ask(w, 3, get(w, EQ_LEFT), get(w, EQ_INDEX), count, 0, 207)
    if phase == 207:
        index = 0
        while index < get(w, EQ_COUNT):
            put32(w, EQ_CHUNK_A + index * 4, read32(s, 64 + index * 4))
            index = index + 1
        return ask(w, 3, get(w, EQ_RIGHT), get(w, EQ_INDEX), get(w, EQ_COUNT), 0, 208)
    if phase == 208:
        index = 0
        while index < get(w, EQ_COUNT):
            if get32(w, EQ_CHUNK_A + index * 4) != read32(s, 64 + index * 4):
                return eq_done(w, 0)
            index = index + 1
        put(w, EQ_INDEX, get(w, EQ_INDEX) + index)
        put(w, PHASE, 206)
        return 0
    if phase == 212:
        left = get(w, EL_KIND)
        right = get(w, ER_KIND)
        a = get(w, EL_A)
        b = get(w, ER_A)
        if left == 3 and right == 3:
            if (((a >> 52) & 2047) == 2047 and (a & 4503599627370495) != 0) or (((b >> 52) & 2047) == 2047 and (b & 4503599627370495) != 0):
                return eq_done(w, 0)
            same = a == b or ((a & 9223372036854775807) == 0 and (b & 9223372036854775807) == 0)
            return eq_done(w, choose(same, 1, 0))
        bits_a = integer_bits(left, get(w, EL_SIZE), a)
        bits_b = integer_bits(right, get(w, ER_SIZE), b)
        if bits_a == 18446744073709551615 or bits_b == 18446744073709551615 or bits_a != bits_b:
            return eq_done(w, 0)
        if bits_a == 0:
            return eq_done(w, 1)
        sign_a = choose(left == 3, a >> 63, choose(left == 2, a, 0))
        sign_b = choose(right == 3, b >> 63, choose(right == 2, b, 0))
        if sign_a != sign_b:
            return eq_done(w, 0)
        put(w, EQ_TOTAL, (bits_a + 31) >> 5)
        put(w, EQ_INDEX, 0)
        put(w, PHASE, 213)
        return 0
    if phase == 213:
        remaining = get(w, EQ_TOTAL) - get(w, EQ_INDEX)
        if remaining == 0:
            return eq_done(w, 1)
        count = choose(remaining < 1024, remaining, 1024)
        put(w, EQ_COUNT, count)
        if get(w, EL_KIND) == 2:
            return ask(w, 4, get(w, EQ_LEFT), get(w, EQ_INDEX), count, 0, 214)
        index = 0
        while index < count:
            put32(w, EQ_CHUNK_A + index * 4, numeric_word(get(w, EL_KIND), get(w, EL_A), get(w, EQ_INDEX) + index))
            index = index + 1
        put(w, PHASE, 215)
        return 0
    if phase == 214:
        index = 0
        while index < get(w, EQ_COUNT):
            put32(w, EQ_CHUNK_A + index * 4, read32(s, 64 + index * 4))
            index = index + 1
        put(w, PHASE, 215)
        return 0
    if phase == 215:
        if get(w, ER_KIND) == 2:
            return ask(w, 4, get(w, EQ_RIGHT), get(w, EQ_INDEX), get(w, EQ_COUNT), 0, 216)
        index = 0
        while index < get(w, EQ_COUNT):
            put32(w, EQ_CHUNK_B + index * 4, numeric_word(get(w, ER_KIND), get(w, ER_A), get(w, EQ_INDEX) + index))
            index = index + 1
        put(w, PHASE, 217)
        return 0
    if phase == 216:
        index = 0
        while index < get(w, EQ_COUNT):
            put32(w, EQ_CHUNK_B + index * 4, read32(s, 64 + index * 4))
            index = index + 1
        put(w, PHASE, 217)
        return 0
    if phase == 217:
        index = 0
        while index < get(w, EQ_COUNT):
            if get32(w, EQ_CHUNK_A + index * 4) != get32(w, EQ_CHUNK_B + index * 4):
                return eq_done(w, 0)
            index = index + 1
        put(w, EQ_INDEX, get(w, EQ_INDEX) + index)
        put(w, PHASE, 213)
        return 0
    if phase == 220:
        return ask(w, 21, read64(s, 32), 0, 0, 0, 221)
    if phase == 221:
        value = read64(s, 32)
        if value > 1:
            return 199
        return eq_done(w, choose(get(w, EQ_LEAF_NE) == 0, value, 1 - value))
    if phase == 224:
        if read64(s, 32) == 0:
            return eq_pop(w, 1)
        frame = eq_frame(w)
        put(w, frame + 40, read64(s, 56))
        put(w, frame + 48, read64(s, 48))
        return ask(w, 31, get(w, frame + 8), read64(s, 40), read64(s, 64), 0, 225)
    if phase == 225:
        if read64(s, 32) == 0:
            return eq_done(w, 0)
        frame = eq_frame(w)
        return eq_child(w, get(w, frame + 48), read64(s, 40))
    if phase == 226:
        frame = eq_frame(w)
        put(w, frame + 48, read64(s, 32))
        return ask(w, 2, get(w, frame + 8), get(w, frame + 32), 0, 0, 227)
    if phase == 227:
        frame = eq_frame(w)
        put(w, frame + 32, get(w, frame + 32) + 1)
        return eq_child(w, get(w, frame + 48), read64(s, 32))
    if phase == 228:
        frame = eq_frame(w)
        put(w, frame + 24, read64(s, 40))
        return ask(w, 1, get(w, frame + 8), 0, 0, 0, 229)
    if phase == 229:
        frame = eq_frame(w)
        index = get(w, frame + 32)
        left_size = get(w, frame + 24)
        right_size = read64(s, 40)
        if index >= left_size or index >= right_size:
            return eq_pop(w, choose(left_size == right_size, 1, 0))
        return ask(w, 2, get(w, frame), index, 0, 0, 226)
    return 199

def integer_bits(kind:u64, size:u64, value:u64) -> u64:
    if kind == 1:
        return value
    if kind == 2:
        return size
    magnitude = value & 9223372036854775807
    if magnitude == 0:
        return 0
    exponent = (value >> 52) & 2047
    if exponent == 2047 or exponent < 1023:
        return 18446744073709551615
    mantissa = (value & 4503599627370495) | 4503599627370496
    if exponent < 1075:
        shift = 1075 - exponent
        if (mantissa & ((1 << shift) - 1)) != 0:
            return 18446744073709551615
    return exponent - 1022

def numeric_word(kind:u64, value:u64, index:u64) -> u64:
    if kind == 1:
        return choose(index == 0, value, 0)
    exponent = (value >> 52) & 2047
    mantissa = (value & 4503599627370495) | 4503599627370496
    result = 0
    bit = 0
    while bit < 32:
        position = index * 32 + bit
        in_range = True
        source = 0
        if exponent >= 1075:
            shift = exponent - 1075
            if position < shift:
                in_range = False
            else:
                source = position - shift
        else:
            source = position + 1075 - exponent
        if in_range and source < 53:
            result = result | (((mantissa >> source) & 1) << bit)
        bit = bit + 1
    return result
'''


def constant_program():
    lines = ['def constants(w:mutbuf) -> u64:']
    offset = 49152
    for index, text in enumerate(LITERALS.values(), 1):
        at = 32768 + index * 48
        lines += [f'    put(w, {at}, 4)', f'    put(w, {at + 8}, {len(text)})',
                  f'    put(w, {at + 24}, {offset})']
        for point in map(ord, text):
            lines.append(f'    put32(w, {offset}, {point})')
            offset += 4
    if offset >= 65536:
        raise ValueError('worker literal data crossed its private extent')
    for offset_index, boolean in ((len(LITERALS) + 1, 1), (len(LITERALS) + 2, 0)):
        at = 32768 + offset_index * 48
        lines += [f'    put(w, {at}, 1)', f'    put(w, {at + 24}, {boolean})']
    return '\n'.join(lines + ['    return 0', ''])


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node
    tree = Constants().visit(ast.parse(SOURCE + EQUALITY + constant_program()))
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'worker_report', 'functions': functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
