"""Author the lossless, side-effect-free HIA MCP request classifier.

The 88-byte little-endian result contains a magic, request role, ID type,
three raw spans (ID, params, arguments), tool ordinal and route decision.
Span offsets always refer to the unchanged input. No span confers authority.
"""
from __future__ import annotations

import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'
SOURCE = 'examples/hia_bootstrap/mcp_request_route.hepta'
MAGIC = b'HIAMCP01'
LIMIT = 8 << 20
OUTPUT_BYTES = 8192  # Includes scratch used before exporting the descriptor.
WIRE_FORMAT = '<8s10Q'
INVALID_ENVELOPE = 0xfffffff0
ACCEPT, METHOD_NOT_FOUND, INVALID_PARAMS = range(3)

METHODS = (
    'initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call',
    'resources/list', 'resources/templates/list', 'resources/read', 'notifications/cancelled',
)
POLICY = r'''
# Request wire observation: no tool effect occurs before the owner spends a role.
# Output is private workspace until a complete descriptor is returned.
def route(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > WIRE_LIMIT or length(o) < OUTPUT_LIMIT or length(w) < 128:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    if get(w, 64) != 6:
        return BAD_ENVELOPE
    version = lookup(w, 64, 1)
    method = lookup(w, 64, 2)
    id = lookup(w, 64, 3)
    params = lookup(w, 64, 4)
    if version == NONE or method == NONE:
        return BAD_ENVELOPE
    if get(w, version) != 4 or get(w, version + 32) != 3 or get(w, method) != 4:
        return BAD_ENVELOPE
    start = get(w, version + 24)
    if byte(w, start) != 50 or byte(w, start + 1) != 46 or byte(w, start + 2) != 48:
        return BAD_ENVELOPE
    kind = 0
    id_at = 0
    id_bytes = 0
    if id != NONE:
        kind = get(w, id)
        id_at = get(w, id + 56)
        id_bytes = get(w, id + 64)
        if kind == 3:
            id_at = get(w, id + 24)
            id_bytes = get(w, id + 32)
        if kind != 3 and kind != 4:
            return BAD_ENVELOPE
        if kind == 3 and signed_id(s, id_at, id_bytes) == 0:
            return BAD_ENVELOPE
    params_at = 0
    params_bytes = 0
    decision = 0
    if params != NONE:
        shape = get(w, params)
        if shape != 5 and shape != 6:
            decision = 2
        else:
            params_at = get(w, params + 56)
            params_bytes = get(w, params + 64)
    role = method_id(w, get(w, method + 24), get(w, method + 32))
    tool = 0
    argument_at = 0
    argument_bytes = 0
    if id == NONE:
        if role != 2 and role != 9:
            role = 0
    elif role == 2 or role == 9:
        return BAD_ENVELOPE
    elif role == 0:
        decision = 1
    elif role == 5 and decision == 0:
        if params == NONE or get(w, params) != 6:
            decision = 2
        else:
            name = lookup(w, params, 5)
            arguments = lookup(w, params, 6)
            if name == NONE or get(w, name) != 4:
                decision = 2
            else:
                tool = tool_id(w, get(w, name + 24), get(w, name + 32))
                if tool == 0:
                    decision = 1
                elif arguments != NONE and get(w, arguments) != 0:
                    if get(w, arguments) != 6:
                        decision = 2
                    else:
                        argument_at = get(w, arguments + 56)
                        argument_bytes = get(w, arguments + 64)
    put(o, 0, ROUTE_MAGIC)
    put(o, 8, role)
    put(o, 16, kind)
    put(o, 24, id_at)
    put(o, 32, id_bytes)
    put(o, 40, params_at)
    put(o, 48, params_bytes)
    put(o, 56, tool)
    put(o, 64, argument_at)
    put(o, 72, argument_bytes)
    put(o, 80, decision)
    return 88

def lookup(w:mutbuf, parent:u64, field:u64) -> u64:
    children = get(w, parent + 24)
    while children != NONE:
        record = 64 + children * 72
        if key_id(w, get(w, record + 40), get(w, record + 48)) == field:
            return record
        children = get(w, record + 16)
    return NONE

def match_word(w:mutbuf, at:u64, width:u64) -> u64:
    value = 0
    index = 0
    while index < width:
        value = value | (byte(w, at + index) << (8 * index))
        index = index + 1
    return value

def signed_id(s:readbuf, at:u64, extent:u64) -> u64:
    end = at + extent
    maximum = 7
    if byte(s, at) == 45:
        at = at + 1
        maximum = 8
    accumulator = 0
    while at < end:
        point = byte(s, at)
        if point < 48 or point > 57:
            return 0
        digit = point - 48
        if accumulator > 922337203685477580:
            return 0
        if accumulator == 922337203685477580 and digit > maximum:
            return 0
        accumulator = accumulator * 10 + digit
        at = at + 1
    return 1
'''

def tool_names():
    tools = json.loads(CATALOG.read_bytes())['tools']
    names = tuple(tool['name'] for tool in tools)
    if not names or len(set(names)) != len(names):
        raise ValueError('incomplete or duplicate HIA MCP tool list')
    return names


def comparison_table(name, values):
    lines = [f'def {name}(w:mutbuf, at:u64, extent:u64) -> u64:']
    for index, value in enumerate(values, 1):
        raw = value.encode('ascii')
        pieces = [f'extent == {len(raw)}']
        for offset in range(0, len(raw), 8):
            part = raw[offset:offset + 8]
            word = int.from_bytes(part, 'little')
            pieces.append(f'match_word(w, at + {offset}, {len(part)}) == {word}')
        lines.append('    if ' + ' and '.join(pieces) + ':')
        lines.append(f'        return {index}')
    lines.append('    return 0')
    return '\n'.join(lines)


def render():
    policy = (POLICY.replace('ROUTE_MAGIC', str(int.from_bytes(MAGIC, 'little')))
              .replace('NONE', '18446744073709551615')
              .replace('WIRE_LIMIT', str(LIMIT))
              .replace('OUTPUT_LIMIT', str(OUTPUT_BYTES))
              .replace('BAD_ENVELOPE', str(INVALID_ENVELOPE)))
    source = '\n'.join((policy, comparison_table('tool_id', tool_names()),
                       comparison_table('method_id', METHODS),
                       comparison_table('key_id', ('jsonrpc', 'method', 'id', 'params',
                                                   'name', 'arguments')),
                       json_decoder(wire_spans=True)))
    return render_assembly(document(source, 'mcp_request_route'))


def main():
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
