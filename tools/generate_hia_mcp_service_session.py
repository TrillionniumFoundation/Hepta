"""Author the native HIA service lifecycle after the independent SDK projection."""
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_negotiation import (
    DESCRIPTOR, LEGACY_FALLBACK, METHODS_WITH_DISCOVERY, NONE,
    POLICY as NEGOTIATION, VERSIONS, _EXTRA_KEYS,
)
from tools.generate_hia_mcp_reply import PREFIX, literal_writes
from tools.generate_hia_mcp_request import KEYS, LIMIT, ROOT, comparison_table, source_program

SOURCE = 'examples/hia_bootstrap/mcp_service_session.hepta'
STATE_OFFSET = 64 + 262144 * 72 + LIMIT
SDK_OFFSET = STATE_OFFSET + 16
WORKSPACE_BYTES = STATE_OFFSET + 256
RESPONSE_BYTES = (16 << 20) + 512
DISPATCH = 0xffffffeb
CLOSE = 0xffffffea
DISPATCH_MAGIC = int.from_bytes(b'HIAMSQ01', 'little')
SDK_MAGIC = int.from_bytes(b'HIASDK01', 'little')

POLICY = r'''
def service_session(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORKSPACE or length(o) != RESPONSE_CAPACITY:
        return 4294967293
    phase = get(w, SESSION_OFFSET)
    if phase > 3:
        return 4294967293
    if get(w, SESSION_OFFSET + 8) == 1:
        return invalid_request(o, 0)
    if get(w, SESSION_OFFSET + 8) != 160 or session_get(w, 0) != SDK_MAGIC:
        return 4294967293
    kind = session_get(w, 8)
    role = session_get(w, 16)
    if kind != 1:
        if phase == 0:
            return SESSION_CLOSE
        if kind == 2 and role == 9 and session_get(w, 120) != 0:
            return session_dispatch(o, w, 6, 0)
        return 0
    if phase == 0 and role == 3:
        return empty_result(o, session_id(s, o, w))
    if role == 1:
        return session_initialize(s, o, w, phase)
    missing = session_get(w, 104)
    inline_version = session_get(w, 112)
    if phase == 0 and missing != 0:
        return session_missing(s, o, w, missing)
    if (missing & 1) == 0 and inline_version == 0:
        return session_unsupported(s, o, w)
    required = 0
    if phase == 2 or role == 10 or inline_version == 5:
        required = 1
    if required == 1 and missing != 0:
        return session_missing(s, o, w, missing)
    if phase == 0 and role != 10:
        put(w, SESSION_OFFSET, 2)
        phase = 2
        required = 1
    modern = get(w, SESSION_OFFSET + 184)
    if (missing & 1) == 0:
        modern = choose(inline_version == 5, 1, 0)
    if role == 3:
        if required == 1 or modern == 1:
            return session_method(s, o, w)
        return empty_result(o, session_id(s, o, w))
    if role == 10:
        return discovery(o, session_id(s, o, w))
    if role == 4 or role == 6 or role == 7:
        return session_dispatch(o, w, choose(role == 4, 1, choose(role == 6, 3, 4)), modern)
    if role == 11:
        if modern == 1:
            return prompts_modern(o, session_id(s, o, w))
        return prompts_legacy(o, session_id(s, o, w))
    if role == 12 or role == 13:
        if modern == 1:
            return session_method(s, o, w)
        return empty_result(o, session_id(s, o, w))
    if role == 14:
        if modern == 1:
            return completion_modern(o, session_id(s, o, w))
        return completion_legacy(o, session_id(s, o, w))
    if role == 5:
        if session_get(w, 56) == 0:
            return tool_missing(o, session_id(s, o, w))
        if session_get(w, 56) == 12 or session_get(w, 56) == 13:
            return session_dispatch(o, w, 2, modern)
        status = widen(route(s, o, w))
        if status != 88:
            return tool_wire(o, session_id(s, o, w))
        if get(o, 8) != 5 or get(o, 56) != session_get(w, 56) or get(o, 80) != 0:
            return tool_wire(o, session_id(s, o, w))
        return session_dispatch(o, w, 2, modern)
    if role == 8:
        uri = session_get(w, 48)
        if session_hia_uri(s, span_at(uri)) == 0:
            return session_nonhia(s, o, w, modern)
        status = widen(route(s, o, w))
        if status != 88:
            return resource_wire(o, session_id(s, o, w))
        if get(o, 8) != 8 or get(o, 80) != 0 or get(o, 72) == 0:
            return resource_wire(o, session_id(s, o, w))
        return session_dispatch(o, w, 5, modern)
    return session_method(s, o, w)

def session_initialize(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u32:
    status = widen(negotiation(s, o, w))
    if status != 112:
        if phase == 0:
            put(w, SESSION_OFFSET, 3)
        return initialize_wire(o, session_id(s, o, w))
    if get(o, 8) != 1 or get(o, 80) != 0 or get(o, 88) != 1:
        if phase == 0:
            put(w, SESSION_OFFSET, 3)
        return initialize_wire(o, session_id(s, o, w))
    version = get(o, 104)
    if phase == 0:
        put(w, SESSION_OFFSET, 1)
        put(w, SESSION_OFFSET + 184, 0)
    else:
        params = lookup(w, 64, 4)
        requested = lookup(w, params, 7)
        put(w, SESSION_OFFSET + 184, session_future(w, requested))
    at = result_prefix(o, session_id(s, o, w))
    at = version_text(o, at, version)
    return server_info(o, at)

def session_future(w:mutbuf, node:u64) -> u64:
    at = get(w, node + 24)
    size = get(w, node + 32)
    index = 0
    while index < size and index < 10:
        ch = byte(w, at + index)
        expected = future_byte(index)
        if ch != expected:
            return choose(ch > expected, 1, 0)
        index = index + 1
    return choose(size >= 10, 1, 0)

def session_dispatch(o:mutbuf, w:mutbuf, action:u64, modern:u64) -> u32:
    id = session_get(w, 24)
    idkind = session_get(w, 64)
    idnumber = session_get(w, 72)
    if action == 6:
        id = session_get(w, 120)
        idkind = session_get(w, 128)
        idnumber = session_get(w, 136)
    args = session_get(w, 48)
    params = session_get(w, 40)
    put(o, 0, SERVICE_MAGIC)
    put(o, 8, action)
    put(o, 16, span_at(id))
    put(o, 24, span_size(id))
    tool = session_get(w, 56)
    if action == 2 and tool >= 12:
        tool = tool+1
    put(o, 32, choose(action == 5, 12, tool))
    put(o, 40, choose(args == 0, 0, span_at(args)))
    put(o, 48, span_size(args))
    put(o, 56, modern)
    put(o, 64, choose(params == 0, 0, span_at(params)))
    put(o, 72, span_size(params))
    put(o, 80, idnumber)
    put(o, 88, idkind)
    return SERVICE_DISPATCH

def session_get(w:mutbuf, field:u64) -> u64:
    return get(w, SDK_OFFSET + field)

def span_at(span:u64) -> u64:
    return (span & 16777215) - 1

def span_size(span:u64) -> u64:
    if span == 0:
        return 0
    return ((span >> 24) & 16777215) - span_at(span)

def session_copy(s:readbuf, o:mutbuf, span:u64, at:u64) -> u64:
    start = span_at(span)
    size = span_size(span)
    index = 0
    while index < size:
        store(o, at + index, byte(s, start + index))
        index = index + 1
    return at + size

def session_id(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = prefix(o)
    if session_get(w, 64) == 1:
        return session_integer(o, at, session_get(w, 72))
    return session_copy(s, o, session_get(w, 24), at)

def session_integer(o:mutbuf, at:u64, value:u64) -> u64:
    if value >> 63 == 1:
        store(o, at, 45)
        at = at + 1
        value = 0 - value
    digits = 1
    copy = value
    while copy >= 10:
        digits = digits + 1
        copy = session_divide_ten(copy)
    end = at + digits
    index = end
    while index > at:
        index = index - 1
        quotient = session_divide_ten(value)
        store(o, index, value - quotient * 10 + 48)
        value = quotient
    return end

def session_divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = remainder * 2 + ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def session_method(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = method_prefix(o, session_id(s, o, w))
    at = session_copy(s, o, session_get(w, 32), at)
    return error_close(o, at)

def session_missing(s:readbuf, o:mutbuf, w:mutbuf, missing:u64) -> u32:
    at = missing_prefix(o, session_id(s, o, w))
    if (missing & 1) != 0:
        at = missing_protocol(o, at)
    if missing == 3:
        at = missing_comma(o, at)
    if (missing & 2) != 0:
        at = missing_capabilities(o, at)
    return string_error_close(o, at)

def session_unsupported(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = unsupported_prefix(o, session_id(s, o, w))
    at = session_copy(s, o, session_get(w, 88), at)
    return unsupported_suffix(o, at)

def session_nonhia(s:readbuf, o:mutbuf, w:mutbuf, modern:u64) -> u32:
    at = session_id(s, o, w)
    span = session_get(w, 48)
    if session_job_uri(s, span_at(span)) == 1:
        if modern == 1:
            at = job_missing_modern(o, at)
        else:
            at = job_missing_legacy(o, at)
    elif modern == 1:
        at = nonhia_modern(o, at)
    else:
        at = nonhia_legacy(o, at)
    start = span_at(span) + 1
    size = span_size(span) - 2
    index = 0
    while index < size:
        store(o, at + index, byte(s, start + index))
        index = index + 1
    return string_error_close(o, at + size)
'''


def _writer(name, value):
    lines=[f'def {name}(o:mutbuf, at:u64) -> u64:']
    for index in range(0,len(value),8):
        chunk=value[index:index+8]
        if len(chunk)==8:
            lines.append(f'    word_store(o, at + {index}, {int.from_bytes(chunk,"little")})')
        else:
            lines.extend(f'    store(o, at + {index+j}, {b})' for j,b in enumerate(chunk))
    lines.append(f'    return at + {len(value)}')
    return '\n'.join(lines)+'\n'


def render():
    import json
    versions = json.dumps(list(VERSIONS), separators=(',', ':')).encode()
    writes = (
        ('result_prefix', b',"result":{"protocolVersion":"'),
        ('server_info', b'","capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"hepta-hia","version":"1"}}}\n'),
        ('empty_result', b',"result":{}}\n'),
        ('prompts_legacy', b',"result":{"prompts":[]}}\n'),
        ('prompts_modern', b',"result":{"resultType":"complete","ttlMs":0,"cacheScope":"private","prompts":[]}}\n'),
        ('completion_legacy', b',"result":{"completion":{"values":[]}}}\n'),
        ('completion_modern', b',"result":{"resultType":"complete","completion":{"values":[]}}}\n'),
        ('invalid_request', b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid request"}}\n'),
        ('method_prefix', b',"error":{"code":-32601,"message":'),
        ('error_close', b'}}\n'), ('string_error_close', b'"}}\n'),
        ('tool_missing', b',"error":{"code":-32602,"message":"tool not found in this runtime mode"}}\n'),
        ('tool_wire', b',"error":{"code":-32602,"message":"HIA native wire admission refused"}}\n'),
        ('resource_wire', b',"error":{"code":-32602,"message":"HIA resource wire admission refused"}}\n'),
        ('initialize_wire', b',"error":{"code":-32602,"message":"HIA wire negotiation refused"}}\n'),
        ('missing_prefix', b',"error":{"code":-32602,"message":"request _meta is missing or has malformed required fields: '),
        ('missing_protocol', b'io.modelcontextprotocol/protocolVersion'),
        ('missing_capabilities', b'io.modelcontextprotocol/clientCapabilities'),
        ('missing_comma', b', '),
        ('unsupported_prefix', b',"error":{"code":-32022,"message":"Unsupported protocol version","data":{"requested":'),
        ('unsupported_suffix', b',"supported":' + versions + b'}}}\n'),
        ('job_missing_legacy', b',"error":{"code":-32002,"message":"No such background job: '),
        ('job_missing_modern', b',"error":{"code":-32602,"message":"No such background job: '),
        ('nonhia_legacy', b',"error":{"code":-32002,"message":"Not a job URI: '),
        ('nonhia_modern', b',"error":{"code":-32602,"message":"Not a job URI: '),
        ('discovery', b',"result":{"resultType":"complete","supportedVersions":' + versions
         + b',"capabilities":{"tools":{},"resources":{}},"ttlMs":0,"cacheScope":"private",'
           b'"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"hepta-hia","version":"1"}}}}\n'),
    )
    helpers = [_writer(name, value) for name, value in writes]
    static_prefix = ('def prefix(o:mutbuf) -> u64:\n' + literal_writes(PREFIX, offset='0')
                     + f'\n    return {len(PREFIX)}\n')
    policy = POLICY
    constants = {'WORKSPACE': WORKSPACE_BYTES, 'RESPONSE_CAPACITY': RESPONSE_BYTES,
                 'SESSION_OFFSET': STATE_OFFSET, 'SDK_OFFSET': SDK_OFFSET,
                 'SDK_MAGIC': SDK_MAGIC, 'SESSION_CLOSE': CLOSE,
                 'SERVICE_MAGIC': DISPATCH_MAGIC, 'SERVICE_DISPATCH': DISPATCH}
    import re
    for name,value in constants.items():policy=re.sub(r'\b'+name+r'\b',str(value),policy)
    version = ['def version_text(o:mutbuf, at:u64, version:u64) -> u64:']
    for index,literal in enumerate(VERSIONS[:VERSIONS.index(LEGACY_FALLBACK)],1):
        version.extend((f'    if version == {index}:',f'        return version_{index}(o, at)'))
        helpers.append(_writer(f'version_{index}',literal.encode()))
    version.append('    return fallback_version(o, at)')
    helpers.append(_writer('fallback_version',LEGACY_FALLBACK.encode()))
    future=['def future_byte(index:u64) -> u64:']
    for index,ch in enumerate(b'2026-07-28'):
        future.extend((f'    if index == {index}:',f'        return {ch}'))
    future.append('    return 0')
    hia=['def session_hia_uri(s:readbuf, at:u64) -> u64:', '    at = at + 1']
    for ch in b'hia://':
        hia.extend(('    unit = decoded(s, at)',f'    if (unit & 4294967295) != {ch}:','        return 0','    at = unit >> 32'))
    hia.append('    return 1')
    job=['def session_job_uri(s:readbuf, at:u64) -> u64:', '    at = at + 1']
    for ch in b'octofs://jobs/':
        job.extend(('    unit = decoded(s, at)',f'    if (unit & 4294967295) != {ch}:','        return 0','    at = unit >> 32'))
    job.append('    return 1')
    negotiation=(NEGOTIATION.replace('NONE',str(NONE)).replace('FALLBACK',str(VERSIONS.index(LEGACY_FALLBACK)+1)).replace('DESCRIPTOR',str(DESCRIPTOR)))
    source='\n'.join((policy,static_prefix,'\n'.join(version),'\n'.join(future),'\n'.join(hia),'\n'.join(job),*helpers,negotiation,
        comparison_table('protocol_version',VERSIONS),source_program(methods=METHODS_WITH_DISCOVERY,
        keys=(*KEYS,*_EXTRA_KEYS,'cursor','requestId'),capture_resource_uri=True)))
    return render_assembly(document(source,'mcp_service_session'))


if __name__=='__main__':
    (ROOT/SOURCE).write_text(render(),encoding='utf-8')
