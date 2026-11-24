"""Author HIA MCP framing for already authenticated catalog and domain results.

Input is an exact five-field private JSON object: id, kind, modern, payload,
uri. Kind 1 frames a result, 2 frames a typed tool result, 3 frames an error,
and 4 frames a completed HIA resource read. Authentication remains with the
provider owner and its terminal/schema gates, not this byte renderer.
"""
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import ROOT, WIRE_HELPERS, comparison_table

SOURCE = 'examples/hia_bootstrap/mcp_service_reply.hepta'
INPUT_BYTES = 9 << 20
RESPONSE_BYTES = (8 << 20) + 512
WORKSPACE_BYTES = 64 + 262144 * 72 + INPUT_BYTES
KEYS = ('id', 'kind', 'modern', 'payload', 'uri', 'status', 'result', 'code', 'message')

POLICY = r'''
def service_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > INPUT_CAP or length(o) != OUTPUT_CAP or length(w) != WORKSPACE_CAP:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    status = widen(decode_json(s, w, o))
    if status >= 4294967292:
        return status
    if get(w, 64) != 6 or get(w, 96) != 5:
        return 4294967280
    id = lookup(w, 64, 1)
    kind = lookup(w, 64, 2)
    modern = lookup(w, 64, 3)
    payload = lookup(w, 64, 4)
    uri = lookup(w, 64, 5)
    if id == NONE or kind == NONE or modern == NONE or payload == NONE or uri == NONE:
        return 4294967280
    if get(w, kind) != 3 or get(w, kind + 32) != 1 or get(w, payload) != 6:
        return 4294967280
    selected = byte(s, get(w, kind + 24))
    if selected < 49 or selected > 52 or (get(w, modern) != 1 and get(w, modern) != 2):
        return 4294967280
    modern = choose(get(w, modern) == 2, 1, 0)
    selected = selected - 48
    if valid_id(s, w, id, selected) == 0:
        return 4294967280
    if selected == 3 and valid_error(s, w, payload) == 0:
        return 4294967280
    if selected == 4:
        if get(w, uri) != 4:
            return 4294967280
    elif get(w, uri) != 0:
        return 4294967280
    put(w, 48, 0)
    put(w, 56, 0)
    prefix(o, w)
    emit_node(s, o, w, id)
    if selected == 3:
        error_prefix(o, w)
        emit_node(s, o, w, payload)
    elif selected == 4:
        if resource_result(s, o, w, payload, uri, modern) == 0:
            return 4294967280
    else:
        result_prefix(o, w)
        if selected == 2:
            if tool_result(s, o, w, payload) == 0:
                return 4294967280
        else:
            begin_object(s, o, w, payload)
            if modern == 1:
                if get(w, payload + 32) != 0:
                    emit_byte(o, w, 44)
                cache_fields(o, w)
        if modern == 1:
            if selected == 2 or get(w, payload + 32) != 0 or selected == 1:
                emit_byte(o, w, 44)
            modern_fields(o, w)
        emit_byte(o, w, 125)
    emit_byte(o, w, 125)
    emit_byte(o, w, 10)
    if get(w, 48) != 0:
        return 4294967293
    return get(w, 56)

def valid_id(s:readbuf, w:mutbuf, id:u64, selected:u64) -> u64:
    kind = get(w, id)
    if kind == 4:
        return 1
    if kind == 0:
        return choose(selected == 3, 1, 0)
    if kind != 3:
        return 0
    return signed_id(s, get(w, id + 24), get(w, id + 32))

def valid_error(s:readbuf, w:mutbuf, payload:u64) -> u64:
    code = lookup(w, payload, 8)
    message = lookup(w, payload, 9)
    if code == NONE or message == NONE or get(w, code) != 3 or get(w, message) != 4:
        return 0
    return signed_id(s, get(w, code + 24), get(w, code + 32))

def tool_result(s:readbuf, o:mutbuf, w:mutbuf, payload:u64) -> u64:
    status = lookup(w, payload, 6)
    if status == NONE or get(w, status) != 4:
        return 0
    outcome = status_id(w, get(w, status + 24), get(w, status + 32))
    if outcome == 0:
        return 0
    tool_prefix(o, w)
    quote_wire(s, o, w, get(w, payload + 56), get(w, payload + 64))
    tool_middle(o, w)
    if outcome == 1 or outcome == 2:
        true_literal(o, w)
    else:
        false_literal(o, w)
    structured_prefix(o, w)
    emit_node(s, o, w, payload)
    return 1

def resource_result(s:readbuf, o:mutbuf, w:mutbuf, payload:u64, uri:u64, modern:u64) -> u64:
    status = lookup(w, payload, 6)
    if status == NONE or get(w, status) != 4:
        return 0
    outcome = status_id(w, get(w, status + 24), get(w, status + 32))
    if outcome == 0:
        return 0
    if outcome != 3:
        resource_error(o, w)
        emit_node(s, o, w, payload)
        emit_byte(o, w, 125)
        return 1
    result = lookup(w, payload, 7)
    if result == NONE:
        return 0
    resource_prefix(o, w)
    emit_node(s, o, w, uri)
    resource_text(o, w)
    quote_node(s, o, w, result)
    resource_tail(o, w)
    if modern == 1:
        emit_byte(o, w, 44)
        cache_fields(o, w)
        emit_byte(o, w, 44)
        modern_fields(o, w)
    emit_byte(o, w, 125)
    return 1

def begin_object(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    return copy_wire(s, o, w, get(w, node + 56), get(w, node + 64) - 1)

def emit_node(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    if get(w, node) == 0 or get(w, node) == 1 or get(w, node) == 2 or get(w, node) == 3:
        return copy_wire(s, o, w, get(w, node + 24), get(w, node + 32))
    return copy_wire(s, o, w, get(w, node + 56), get(w, node + 64))

def quote_node(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    if get(w, node) == 0 or get(w, node) == 1 or get(w, node) == 2 or get(w, node) == 3:
        return quote_wire(s, o, w, get(w, node + 24), get(w, node + 32))
    return quote_wire(s, o, w, get(w, node + 56), get(w, node + 64))

def copy_wire(s:readbuf, o:mutbuf, w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        emit_byte(o, w, byte(s, at + i))
        i = i + 1
    return 0

def quote_wire(s:readbuf, o:mutbuf, w:mutbuf, at:u64, size:u64) -> u64:
    emit_byte(o, w, 34)
    i = 0
    while i < size:
        value = byte(s, at + i)
        if value == 34 or value == 92:
            emit_byte(o, w, 92)
            emit_byte(o, w, value)
        elif value < 32:
            emit_byte(o, w, 92)
            replacement = 0
            if value == 8:
                replacement = 98
            elif value == 9:
                replacement = 116
            elif value == 10:
                replacement = 110
            elif value == 12:
                replacement = 102
            elif value == 13:
                replacement = 114
            if replacement != 0:
                emit_byte(o, w, replacement)
            else:
                emit_byte(o, w, 117)
                emit_byte(o, w, 48)
                emit_byte(o, w, 48)
                emit_byte(o, w, hex_digit(value >> 4))
                emit_byte(o, w, hex_digit(value & 15))
        else:
            emit_byte(o, w, value)
        i = i + 1
    emit_byte(o, w, 34)
    return 0

def emit_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, 56)
    if at < length(o):
        store(o, at, value)
    else:
        put(w, 48, 1)
    put(w, 56, at + 1)
    return 0

def hex_digit(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)
'''


def writer(name, raw):
    return ('def ' + name + '(o:mutbuf, w:mutbuf) -> u64:\n'
            + ''.join('    emit_byte(o, w, ' + str(value) + ')\n' for value in raw)
            + '    return 0\n')


def render():
    literals = {
        'prefix': b'{"jsonrpc":"2.0","id":',
        'result_prefix': b',"result":', 'error_prefix': b',"error":',
        'tool_prefix': b'{"content":[{"type":"text","text":',
        'tool_middle': b'}],"isError":',
        'structured_prefix': b',"structuredContent":',
        'true_literal': b'true', 'false_literal': b'false',
        'cache_fields': b'"cacheScope":"private","ttlMs":0',
        'modern_fields': b'"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"hepta-hia","version":"1"}}',
        'resource_prefix': b',"result":{"contents":[{"uri":',
        'resource_text': b',"mimeType":"text/plain","text":', 'resource_tail': b'}]',
        'resource_error': b',"error":{"code":-32603,"message":"HIA resource read is pending or unavailable; repeat the same URI, or use hia_read with its original artifact reference","data":',
    }
    decoder = json_decoder(wire_spans=True)
    if decoder.count('length(s) > 8388608') != 2:
        raise ValueError('JSON decoder input bound changed')
    decoder = decoder.replace('length(s) > 8388608', 'length(s) > ' + str(INPUT_BYTES))
    policy = POLICY + WIRE_HELPERS
    for name, value in {'INPUT_CAP': INPUT_BYTES, 'OUTPUT_CAP': RESPONSE_BYTES,
                        'WORKSPACE_CAP': WORKSPACE_BYTES, 'NONE': (1 << 64) - 1}.items():
        policy = policy.replace(name, str(value))
    source = '\n'.join((policy, *(writer(name, raw) for name, raw in literals.items()),
                        comparison_table('key_id', KEYS),
                        comparison_table('status_id', ('rejected', 'unknown', 'completed', 'accepted')),
                        decoder))
    return render_assembly(document(source, 'mcp_service_reply'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
