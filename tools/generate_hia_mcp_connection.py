"""Author the stateful, capability-free HIA MCP stdio connection owner."""

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_mcp_negotiation import (
    DESCRIPTOR, LEGACY_FALLBACK, METHODS_WITH_DISCOVERY, NONE, POLICY as NEGOTIATION,
    VERSIONS, _EXTRA_KEYS,
)
from tools.generate_hia_mcp_reply import PREFIX, literal_writes
from tools.generate_hia_mcp_request import (
    INVALID_ENVELOPE, KEYS, LIMIT, ROOT, comparison_table, source_program,
)

SOURCE = 'examples/hia_bootstrap/mcp_connection.hepta'
STATE_OFFSET = 64 + 262144 * 72 + LIMIT
WORKSPACE_BYTES = STATE_OFFSET + 8
RESPONSE_BYTES = LIMIT + 256

POLICY = r'''
def connection(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORKSPACE or length(o) != RESPONSE_CAPACITY:
        return 4294967293
    phase = get(w, SESSION_OFFSET)
    if phase > 2:
        return 4294967293
    status = widen(negotiation(s, o, w))
    if status != 112:
        if status == INVALID_REQUEST:
            return emit(o, null_id(o, prefix(o)), 7, 0)
        return emit(o, null_id(o, prefix(o)), 8, 0)
    role = get(o, 8)
    kind = get(o, 16)
    if kind == 0:
        if role == 2 and phase == 1 and get(o, 80) == 0:
            put(w, SESSION_OFFSET, 2)
        return 0
    start = get(o, 24)
    size = get(o, 32)
    decision = get(o, 80)
    action = get(o, 88)
    version = get(o, 104)
    response = 5
    if decision == 2:
        response = 6
    elif role == 3:
        response = 2
    elif role == 1:
        if action != 1:
            response = 6
        elif phase == 0:
            response = 1
            put(w, SESSION_OFFSET, 1)
        else:
            response = 9
    elif phase != 2:
        response = 9
    elif role == 4:
        response = 3
    if start > length(s) or size > length(s) - start or size + 256 > length(o):
        return 4294967293
    offset = prefix(o)
    index = 0
    while index < size:
        store(o, offset + index, byte(s, start + index))
        index = index + 1
    return emit(o, offset + size, response, version)

def emit(o:mutbuf, at:u64, response:u64, version:u64) -> u32:
    if response == 1:
        cursor = result_prefix(o, at)
        cursor = version_text(o, cursor, version)
        return server_info(o, cursor)
    if response == 2:
        return empty_result(o, at)
    if response == 3:
        return tools_result(o, at)
    if response == 5:
        return method_error(o, at)
    if response == 6:
        return params_error(o, at)
    if response == 7:
        return request_error(o, at)
    if response == 8:
        return parse_error(o, at)
    return phase_error(o, at)
'''


def _writer(name, value):
    source = literal_writes(value)
    return (f'def {name}(o:mutbuf, at:u64) -> u64:\n'
            + source + f'\n    return at + {len(value)}\n')


def render():
    policy = (POLICY.replace('WORKSPACE', str(WORKSPACE_BYTES))
              .replace('RESPONSE_CAPACITY', str(RESPONSE_BYTES))
              .replace('SESSION_OFFSET', str(STATE_OFFSET))
              .replace('INVALID_REQUEST', str(INVALID_ENVELOPE)))
    # Prefix is needed before copying the exact request ID, including escaping.
    static_prefix = ('def prefix(o:mutbuf) -> u64:\n'
                     + literal_writes(PREFIX, offset='0') + f'\n    return {len(PREFIX)}\n')
    writes = (
        ('null_id', b'null'),
        ('result_prefix', b',"result":{"protocolVersion":"'),
        ('server_info', b'","capabilities":{},"serverInfo":{"name":"hepta-hia","version":"1"}}}\n'),
        ('empty_result', b',"result":{}}\n'),
        ('tools_result', b',"result":{"tools":[]}}\n'),
        ('method_error', b',"error":{"code":-32601,"message":"Method not found"}}\n'),
        ('params_error', b',"error":{"code":-32602,"message":"Invalid params"}}\n'),
        ('request_error', b',"error":{"code":-32600,"message":"Invalid Request"}}\n'),
        ('parse_error', b',"error":{"code":-32700,"message":"Parse error"}}\n'),
        ('phase_error', b',"error":{"code":-32002,"message":"Connection is not ready for this request"}}\n'),
    )
    helpers = [_writer(name, value) for name, value in writes]
    version = ['def version_text(o:mutbuf, at:u64, version:u64) -> u64:']
    for index, literal in enumerate(VERSIONS[:VERSIONS.index(LEGACY_FALLBACK)], 1):
        version.extend((f'    if version == {index}:', f'        return send_version_{index}(o, at)'))
        helpers.append(_writer(f'send_version_{index}', literal.encode('ascii')))
    version.append('    return fallback_version(o, at)')
    helpers.append(_writer('fallback_version', LEGACY_FALLBACK.encode('ascii')))
    negotiation = (NEGOTIATION.replace('NONE', str(NONE))
                   .replace('FALLBACK', str(VERSIONS.index(LEGACY_FALLBACK) + 1))
                   .replace('DESCRIPTOR', str(DESCRIPTOR)))
    source = '\n'.join((policy, static_prefix, '\n'.join(version), *helpers, negotiation,
                        comparison_table('protocol_version', VERSIONS),
                        source_program(methods=METHODS_WITH_DISCOVERY, keys=(*KEYS, *_EXTRA_KEYS))))
    return render_assembly(document(source, 'mcp_connection'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
