"""Author native MCP replies and deterministic typed admission failures."""
from tools.generate_hia_mcp_service_owner_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        at = text_id(w, PURE_INPUT)
        at = cp(w, S_REQUEST_ID, at)
        at = text_kind(w, at)
        at = decimal(w, at, get(w, 280))
        at = text_modern(w, at)
        if get(w, 272) == 1:
            at = text_true(w, at)
        else:
            at = text_false(w, at)
        at = text_payload(w, at)
        at = cp(w, S_RESPONSE, at)
        at = text_uri(w, at)
        if get(w, 280) == 4:
            at = cp(w, S_URI, at)
        else:
            at = text_null(w, at)
        at = text_close(w, at)
        if at - PURE_INPUT > 9437184:
            return 0
        return pure(o, w, 1, P_REPLY, PURE_INPUT, at - PURE_INPUT, SESSION_OUT, 8389120, PURE_WORK, W_REPLY)
    if phase == 1:
        if result == 0 or result > 8389120:
            return 0
        put(w, 232, SESSION_OUT)
        put(w, 240, result)
        put(w, 248, 0)
        return enter(w, 2, 19)
    if phase == 100:
        return decode(o, w, 101, get(w, S_ORIGINAL), get(w, S_ORIGINAL + 8))
    if phase == 101:
        if result >= 4294967292:
            return 0
        changed = 0
        if get(w, 264) != 1 and get(w, 264) != 12 and string_eq(w, field(w, F_CATALOG_SHA256), S_CATALOG_PIN) == False:
            changed = 1
        put(w, 296, changed)
        at = text_hash_prefix(w, PURE_INPUT)
        at = cp(w, S_ORIGINAL, at)
        at = text_hash_tool(w, at)
        at = cp(w, S_TOOL, at)
        at = text_close(w, at)
        put(w, 1480, PURE_INPUT)
        put(w, 1488, at - PURE_INPUT)
        put(w, 1496, 0)
        return sha(o, w, 102, 0, 1)
    if phase == 102 or phase == 103:
        if result != 0:
            return 0
        if get(w, 1496) == get(w, 1488):
            return sha(o, w, 104, 2, 1)
        size = get(w, 1488) - get(w, 1496)
        if size > 65536:
            size = 65536
        copy_state(w, get(w, 1480) + get(w, 1496), SHA_INPUT + 1, size)
        put(w, 1496, get(w, 1496) + size)
        return sha(o, w, 103, 1, size + 1)
    if phase == 104:
        if result != 32:
            return 0
        at = rejection(w)
        bind(w, S_RESPONSE, PURE_OUTPUT, at - PURE_OUTPUT)
        put(w, 280, 2)
        put(w, PURE_WORK, choose(get(w, 264) == 12, 3, get(w, 264)))
        cp(w, S_CATALOG_PIN, PURE_WORK + 8)
        return pure(o, w, 105, P_OUTPUT_SCHEMA, PURE_OUTPUT, at - PURE_OUTPUT, PURE_INPUT, 1048576, PURE_WORK, 33554432)
    if phase == 105:
        if result != 0:
            return 0
        return enter(w, 5, 0)
    return 0

def rejection(w:mutbuf) -> u64:
    at = text_reject_prefix(w, PURE_OUTPUT)
    if get(w, 296) != 0:
        at = text_changed_code(w, at)
    else:
        at = text_refused_code(w, at)
    at = text_message_prefix(w, at)
    reason = get(w, 288)
    if reason == 2:
        at = text_catalog_message(w, at)
    elif reason == 3:
        at = text_capture_message(w, at)
    elif reason == 4:
        at = text_size_message(w, at)
    else:
        at = text_schema_message(w, at)
    at = text_retry_prefix(w, at)
    if get(w, 296) != 0:
        at = text_refresh(w, at)
    else:
        at = text_correct(w, at)
    at = text_request_prefix(w, at)
    at = encode_hex(w, SHA_OUTPUT, at)
    return text_reject_suffix(w, at)
'''


def source():
    return authored(SOURCE, text={
        'id': '{"id":', 'kind': ',"kind":', 'modern': ',"modern":',
        'payload': ',"payload":', 'uri': ',"uri":',
        'hash_prefix': '{"arguments":', 'hash_tool': ',"tool":',
        'reject_prefix': '{"contract_version":"hepta.hia.agent-native.v1","error":{"code":',
        'changed_code': '"HIA_CATALOG_CHANGED"', 'refused_code': '"HIA_ADMISSION_REFUSED"',
        'message_prefix': ',"details_artifact":null,"message":',
        'catalog_message': '"HIA catalog changed; discover the current contract before creating a request"',
        'capture_message': '"HIA artifact capture path is outside the admitted host and path policy"',
        'size_message': '"HIA arguments exceed the admitted serialized bound"',
        'schema_message': '"Native HIA input schema refused the request"',
        'retry_prefix': ',"phase":"runtime_admission","retry_action":',
        'refresh': '"refresh_context"', 'correct': '"correct_input"',
        'request_prefix': '},"request_id":"hia_',
        'reject_suffix': '","status":"rejected"}',
    })
