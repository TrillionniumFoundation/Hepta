"""Author MCP discovery, request admission and the exact native bridge frame."""
from tools.generate_hia_mcp_service_owner_common import authored
from tools.generate_hia_mcp_request import tool_names
from tools.generate_hia_mcp_history_diagnostic import source_program as diagnostic_source, TEXT as DIAGNOSTIC_TEXT

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if descriptor(w) == False:
            return 0
        action = get(w, 256)
        if action == 1:
            return history_catalog(w)
        if action == 3 or action == 4:
            if action == 3:
                end = text_resources(w, PURE_OUTPUT)
            else:
                end = text_templates(w, PURE_OUTPUT)
            return control_reply(w, PURE_OUTPUT, end - PURE_OUTPUT)
        if action != 2 and action != 5:
            return 0
        if action == 2:
            if get(w, 264) == 13 or get(w, 264) == 14:
                if get(w, 296) == 0:
                    end = text_empty_object(w, PURE_INPUT)
                    return pure(o, w, 30, P_CANONICAL, PURE_INPUT, end - PURE_INPUT, PURE_OUTPUT, 8388608, PURE_WORK, W_CANONICAL)
                return pure(o, w, 30, P_CANONICAL, get(w, 288), get(w, 296), PURE_OUTPUT, 8388608, PURE_WORK, W_CANONICAL)
            return audit(w, 3, 10, 1)
        return enter(w, 3, 10)
    if phase == 30:
        if result == 0 or result > 8388608:
            return rpc_error(w, 1)
        return decode(o, w, 31, PURE_OUTPUT, result)
    if phase == 31:
        if result < 128 or result > ARENA_BYTES:
            return rpc_error(w, 1)
        status = history_params(w)
        if status == 1:
            return enter(w, 5, 0)
        if status == 2:
            return history_unavailable(w)
        return audit(w, 3, 32, choose(get(w,264) == 14,4,3))
    if phase == 32:
        if get(w, 2016) != 0:
            return history_unavailable(w)
        return history_reply(w, HISTORY_REPLY + 64, get(w, HISTORY_REPLY_BYTES) - 64, get(w, HISTORY_STATUS))
    if phase == 10:
        action = get(w, 256)
        if action == 2 and get(w, 2016) != 0:
            return rpc_error(w, 4)
        if action == 5:
            at = text_resource_prefix(w, PURE_INPUT)
            at = cp(w, S_URI, at)
            at = text_resource_suffix(w, at)
            return pure(o, w, 1, P_CANONICAL, PURE_INPUT, at - PURE_INPUT, PURE_OUTPUT, 8388608, PURE_WORK, W_CANONICAL)
        put(w, PURE_WORK, 4294967296 + get(w, 264))
        cp(w, S_CATALOG_PIN, PURE_WORK + 8)
        if get(w, 296) == 0:
            end = text_empty_object(w, PURE_INPUT)
            return pure(o, w, 2, P_INPUT_SCHEMA, PURE_INPUT, end - PURE_INPUT, PURE_OUTPUT, 8389120, PURE_WORK, 33554432)
        return pure(o, w, 2, P_INPUT_SCHEMA, get(w, 288), get(w, 296), PURE_OUTPUT, 8389120, PURE_WORK, 33554432)
    if phase == 2:
        if result != 0:
            if result > 8389120:
                return rpc_error(w, 1)
            bind(w, S_RESPONSE, PURE_OUTPUT, result)
            put(w, 280, 3)
            return enter(w, 5, 0)
        if get(w, 296) == 0:
            end = text_empty_object(w, PURE_INPUT)
            return pure(o, w, 1, P_CANONICAL, PURE_INPUT, end - PURE_INPUT, PURE_OUTPUT, 8388608, PURE_WORK, W_CANONICAL)
        return pure(o, w, 1, P_CANONICAL, get(w, 288), get(w, 296), PURE_OUTPUT, 8388608, PURE_WORK, W_CANONICAL)
    if phase == 1:
        if result == 0:
            return rpc_error(w, 1)
        if get(w, 264) == 12:
            if result > 524288:
                return rpc_error(w, 2)
        elif result > 524288:
            put(w, 288, 4)
            return enter(w, 5, 100)
        copy_state(w, PURE_OUTPUT, ORIGINAL_ARGS, result)
        bind(w, S_ORIGINAL, ORIGINAL_ARGS, result)
        return admission(o, w)
    if phase == 3:
        if result == 0 or result > 524288:
            if get(w, 264) == 12:
                return rpc_error(w, 2)
            put(w, 288, choose(result == 4294967265, 2, choose(result == 4294967266, 3, 1)))
            return enter(w, 5, 100)
        copy_state(w, PURE_OUTPUT, NORMAL_ARGS, result)
        bind(w, S_ARGUMENTS, NORMAL_ARGS, result)
        if get(w, 264) == 12:
            return audit(w, 3, 6, 1)
        return enter(w, 3, 7)
    if phase == 6:
        if get(w, 2016) != 0:
            return rpc_error(w, 5)
        return enter(w, 3, 7)
    if phase == 7:
        size = bridge_frame(w)
        if size == 0:
            return 0
        return child(w, 3, 4, 20, size, 524288, 262144, 0, NONE)
    if phase == 4:
        if child_ok(w) == False or get(w, 616) != 0 or get(w, 624) == 0:
            return rpc_error(w, 3)
        return pure(o, w, 5, P_CANONICAL, CHILD_OUT, get(w, 624), PURE_OUTPUT, 8388608, PURE_WORK, W_CANONICAL)
    if phase == 5:
        if result == 0 or result > 524288:
            return rpc_error(w, 3)
        bind(w, S_RESPONSE, PURE_OUTPUT, result)
        put(w, 280, choose(get(w, 264) == 12, 4, 2))
        return enter(w, 5, 0)
    return 0

def descriptor(w:mutbuf) -> bool:
    if get(w, SESSION_OUT + 88) < 1 or get(w, SESSION_OUT + 88) > 2 or get(w, SESSION_OUT + 56) > 1:
        return False
    at = get(w, SESSION_OUT + 16)
    size = get(w, SESSION_OUT + 24)
    if at > get(w, 200) or size > get(w, 200) - at or size == 0:
        return False
    if get(w, SESSION_OUT + 88) == 1:
        start = get(w, 64)
        end = signed_decimal(w, start, get(w, SESSION_OUT + 80))
        bind(w, S_REQUEST_ID, start, end - start)
        put(w, 64, end)
    else:
        if get(w, SESSION_OUT + 80) != 0:
            return False
        bind(w, S_REQUEST_ID, REQUEST + at, size)
    put(w, 256, get(w, SESSION_OUT + 8))
    put(w, 264, get(w, SESSION_OUT + 32))
    put(w, 272, get(w, SESSION_OUT + 56))
    at = get(w, SESSION_OUT + 40)
    size = get(w, SESSION_OUT + 48)
    if at > get(w, 200) or size > get(w, 200) - at:
        return False
    put(w, 288, REQUEST + at)
    put(w, 296, size)
    bind(w, S_URI, REQUEST + at, choose(get(w, 256) == 5, size, 0))
    if get(w, 256) == 2 or get(w, 256) == 5:
        if get(w, 264) < 1 or get(w, 264) > 14 or (get(w, 256) == 5 and get(w, 264) != 12):
            return False
        start = get(w, 64)
        end = tool_json(w, get(w, 264), start)
        bind(w, S_TOOL, start, end - start)
        put(w, 64, end)
    return True

def history_catalog(w:mutbuf) -> u32:
    source = get(w, S_CATALOG_RESULT)
    size = get(w, S_CATALOG_RESULT + 8)
    if size < 12 or size > 1048576 or byte(w, source + size - 2) != 93 or byte(w, source + size - 1) != 125:
        return 0
    at = copy_state(w, source, PURE_OUTPUT, size - 2)
    at = text_history_catalog(w, at)
    return control_reply(w, PURE_OUTPUT, at - PURE_OUTPUT)

def history_params(w:mutbuf) -> u64:
    root = ARENA + 64
    if get(w, root) != 6:
        return history_parameter_fallback(w)
    put(w, HISTORY_LIMIT, 32)
    bind(w, S_HISTORY_AFTER, 0, 0)
    child = get(w, root + 24)
    while child != NONE:
        row = ARENA + 64 + child * 72
        key = key_id(w, ARENA + get(w, row + 40), get(w, row + 48))
        if key != F_AFTER_ID and key != F_LIMIT:
            return history_unknown_parameter(w, row)
        if key == F_LIMIT and is_null(w, row) == False:
            selected = number(w, row)
            if selected > 65535:
                return history_type_error(w, row, 1)
            put(w, HISTORY_LIMIT, selected)
        if key == F_AFTER_ID and is_null(w, row) == False:
            if get(w, row) != 4:
                return history_type_error(w, row, 2)
            bind(w, S_HISTORY_AFTER, ARENA + get(w, row + 24), get(w, row + 32))
        child = get(w, row + 16)
    after = field(w, F_AFTER_ID)
    if after != NONE and is_null(w, after) == False:
        if get(w, S_HISTORY_AFTER + 8) != 64 or lowerhex(w, get(w, S_HISTORY_AFTER), 64) == False:
            return 2
    if get(w, HISTORY_LIMIT) == 0 or get(w, HISTORY_LIMIT) > 32:
        return 2
    return 0

def history_unavailable(w:mutbuf) -> u32:
    if get(w,264) == 14:
        end = text_archive_unavailable(w, PURE_OUTPUT)
    else:
        end = text_history_unavailable(w, PURE_OUTPUT)
    return history_reply(w, PURE_OUTPUT, end - PURE_OUTPUT, 1)

def history_reply(w:mutbuf, source:u64, size:u64, error:u64) -> u32:
    if size > 65536 or error > 1:
        return 0
    at = text_control_prefix(w, SESSION_OUT)
    at = cp(w, S_REQUEST_ID, at)
    at = text_history_result(w, at)
    at = quoted(w, at, source, size)
    at = text_history_error(w, at)
    if error == 0:
        at = text_false(w, at)
    else:
        at = text_true(w, at)
    if get(w, 272) == 1:
        at = text_history_modern(w, at)
    at = text_control_close(w, at)
    put(w, 232, SESSION_OUT)
    put(w, 240, at - SESSION_OUT)
    put(w, 248, 0)
    return enter(w, 2, 19)

def control_reply(w:mutbuf, source:u64, size:u64) -> u32:
    if size < 2 or size > 1048576 or byte(w, source) != 123 or byte(w, source + size - 1) != 125:
        return 0
    at = text_control_prefix(w, SESSION_OUT)
    at = cp(w, S_REQUEST_ID, at)
    at = text_control_result(w, at)
    at = copy_state(w, source, at, size - 1)
    if get(w, 272) == 1:
        if size > 2:
            store(w, at, 44)
            at = at + 1
        if get(w, 256) == 1:
            at = text_control_public(w, at)
        else:
            at = text_control_private(w, at)
        at = text_control_modern(w, at)
    at = text_control_close(w, at)
    if at - SESSION_OUT > 17826304:
        return 0
    put(w, 232, SESSION_OUT)
    put(w, 240, at - SESSION_OUT)
    put(w, 248, 0)
    return enter(w, 2, 19)

def admission(o:mutbuf, w:mutbuf) -> u32:
    at = text_context(w, PURE_INPUT)
    at = cp(w, S_CONTEXT, at)
    at = text_arguments(w, at)
    at = cp(w, S_ORIGINAL, at)
    at = text_tool(w, at)
    at = decimal(w, at, get(w, 264))
    at = text_close(w, at)
    return pure(o, w, 3, P_ADMISSION, PURE_INPUT, at - PURE_INPUT, PURE_OUTPUT, 524288, PURE_WORK, W_ADMISSION)

def bridge_frame(w:mutbuf) -> u64:
    start = CHILD_IN
    put(w, start, BRIDGE_MAGIC)
    put(w, start + 16, get(w, 32))
    put(w, start + 24, get(w, 48))
    put(w, start + 32, 12)
    put(w, start + 40, get(w, S_FENCE_ROOT + 8))
    put(w, start + 48, get(w, S_SELF_OWNER + 8))
    put(w, start + 56, get(w, 136) | 6)
    index = 0
    while index < 12:
        row = start + 64 + index * 64
        role = role_record(bridge_role(index))
        put(w, row, index + 1)
        put(w, row + 8, get(w, role))
        put(w, row + 16, get(w, role + 8))
        copy_state(w, role + 16, row + 24, 32)
        put(w, row + 56, 0)
        index = index + 1
    put(w, start + 832, LEASE_MAGIC)
    put(w, start + 840, get(w, 384))
    put(w, start + 848, get(w, 392))
    put(w, start + 856, get(w, 400))
    put(w, start + 864, get(w, 408))
    at = cp(w, S_FENCE_ROOT, start + 872)
    at = cp(w, S_SELF_OWNER, at)
    body = at
    put(w, body, BUSINESS_MAGIC)
    put(w, body + 8, get(w, S_PROFILE + 8))
    put(w, body + 16, get(w, S_HOST_CONFIG + 8))
    put(w, body + 24, get(w, S_ORIGINAL + 8))
    put(w, body + 32, get(w, S_ARGUMENTS + 8))
    put(w, body + 40, get(w, S_TOOL + 8))
    put(w, body + 48, get(w, S_STATE_ROOT + 8))
    put(w, body + 56, 64)
    put(w, body + 64, 0)
    at = cp(w, S_PROFILE, body + 72)
    at = cp(w, S_HOST_CONFIG, at)
    at = cp(w, S_ORIGINAL, at)
    at = cp(w, S_ARGUMENTS, at)
    at = cp(w, S_TOOL, at)
    at = cp(w, S_STATE_ROOT, at)
    at = cp(w, S_CATALOG_PIN, at)
    put(w, start + 8, at - body)
    if at - start > 4194304:
        return 0
    return at - start

def rpc_error(w:mutbuf, kind:u64) -> u32:
    if kind == 1:
        end = text_invalid_params(w, PURE_OUTPUT)
    elif kind == 2:
        end = text_invalid_uri(w, PURE_OUTPUT)
    elif kind == 4:
        end = text_audit_error(w, PURE_OUTPUT)
    elif kind == 5:
        end = text_resource_audit_error(w, PURE_OUTPUT)
    else:
        end = text_bridge_error(w, PURE_OUTPUT)
    bind(w, S_RESPONSE, PURE_OUTPUT, end - PURE_OUTPUT)
    put(w, 280, 3)
    return enter(w, 5, 0)
'''


def source():
    import json
    history_tool = {
        'name': 'request_history',
        'title': 'Read Native Session Request History',
        'description': 'Read bounded redacted dispatch metadata owned by this native MCP session. Independent retained-record cursors; server request identity, canonical tool name, timing and observed status only. Unknown effects must never be replayed automatically. Records prove neither delivery nor business success. Transport-invalid requests and facade-local refusals are outside native dispatch history.',
        'inputSchema': {'title': 'RequestHistoryParams', 'type': 'object', 'properties': {
            'after_id': {'description': 'Last returned request id. Expired and other-owner cursors are refused.',
                         'type': ['string', 'null'], 'default': None},
            'limit': {'description': 'At most 32 metadata records; default 32. No parameters or output are returned.',
                      'type': ['integer', 'null'], 'format': 'uint16', 'minimum': 0,
                      'maximum': 65535, 'default': None}}, 'additionalProperties': False},
        'annotations': {'readOnlyHint': True, 'destructiveHint': False,
                        'idempotentHint': True, 'openWorldHint': False}}
    archive_tool = dict(history_tool, name='request_archive', title='Page Retained Request Metadata Archive', description='Page private dispatch metadata retained at archive introduction and all subsequent admitted native requests. This archive is not automatically evicted with the hot request_history cache. At most 32 records per page, independent after_id cursors; no parameters or output are stored. Uses the same native stdio session ownership. History is live, and observed completion proves neither delivery nor business success. No dispatch or replay occurs.')
    text = {'control_prefix': '{"jsonrpc":"2.0","id":', 'control_result': ',"result":',
        'control_close': '}}\n',
        'control_public': '"cacheScope":"public",', 'control_private': '"cacheScope":"private",',
        'control_modern': '"ttlMs":0,"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"hepta-hia","version":"1"}}',
        'resources': '{"resources":[]}', 'templates': '{"resourceTemplates":[]}',
        'resource_prefix': '{"max_bytes":65536,"uri":', 'resource_suffix': '}',
        'empty_object': '{}', 'context': '{"context":', 'arguments': ',"arguments":',
        'tool': ',"tool":', 'invalid_params': '{"code":-32602,"message":"Invalid params"}',
        'invalid_uri': '{"code":-32602,"message":"Invalid HIA artifact URI"}',
        'audit_error': '{"code":-32603,"message":"request audit unavailable; dispatch refused"}',
        'resource_audit_error': '{"code":-32603,"message":"HIA resource audit unavailable; dispatch refused"}',
        'bridge_error': '{"code":-32603,"message":"HIA native job bridge unavailable; repeat the identical request to observe its original binding"}',
        'history_catalog': ',' + json.dumps(history_tool, separators=(',', ':')) + ',' + json.dumps(archive_tool, separators=(',', ':')) + ']}',
        'archive_unavailable': 'archive index preparing or validation unavailable; repeat only this metadata query',
        'history_unavailable': 'request history unavailable to this session or private metadata refused',
        'history_result': ',"result":{"content":[{"type":"text","text":',
        'history_error': '}],"isError":',
        'history_modern': ',"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"hepta-hia","version":"1"}}'}
    text.update(DIAGNOSTIC_TEXT)
    code = SOURCE + diagnostic_source() + '\ndef tool_json(w:mutbuf, role:u64, at:u64) -> u64:\n'
    for index, name in enumerate((*tool_names(), 'hia_resource_read', 'request_history', 'request_archive'), 1):
        text['tool_' + str(index)] = '"' + name + '"'
        code += f'    if role == {index}:\n        return text_tool_{index}(w, at)\n'
    code += '    return at\n\ndef bridge_role(index:u64) -> u64:\n'
    for i, role in enumerate((16,17,0,1,2,3,4,18,9,14,19,15)):
        code += f'    if index == {i}:\n        return {role}\n'
    code += '    return NONE\n'
    return authored(code, text=text, extra={
        'BRIDGE_MAGIC': int.from_bytes(b'HIAMBI01', 'little'),
        'BUSINESS_MAGIC': int.from_bytes(b'HIAMJB01', 'little'),
        'LEASE_MAGIC': int.from_bytes(b'HIAOWN02', 'little'),
    })
