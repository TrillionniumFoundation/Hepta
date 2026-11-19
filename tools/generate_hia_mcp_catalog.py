"""Project the installed HIA tool catalog into a native MCP list result.

Runtime input is the package's separately pinned catalog. The projection
checks the catalog profile, complete entry layout and ordered tool identities,
then emits only MCP tool rows, preserving schemas and annotation values.
"""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_reply import literal_writes
from tools.generate_hia_mcp_request import (
    INVALID_ENVELOPE, LIMIT, OUTPUT_BYTES, ROOT, WIRE_HELPERS, comparison_table, tool_names,
)

SOURCE = 'examples/hia_bootstrap/mcp_catalog_wire.hepta'
PROFILE = 'hepta.hia.agent-native-tool-catalog.v1'
FIELDS = ('schema', 'tools', 'name', 'description', 'inputSchema', 'outputSchema', 'annotations')
PREFIX = b'{"tools":['
TITLE = b'{"title":"'

POLICY = r'''
def catalog(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > WIRE_LIMIT or length(o) < OUTPUT_LIMIT or length(w) < 128:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    status = widen(decode_json(s, w, o))
    if status >= 4294967292:
        return status
    if get(w, 64) != 6:
        return BAD_CATALOG
    profile = lookup(w, 64, 1)
    tools = lookup(w, 64, 2)
    if kind_is(w, profile, 4) == 0 or kind_is(w, tools, 5) == 0:
        return BAD_CATALOG
    if profile_id(w, get(w, profile + 24), get(w, profile + 32)) != 1:
        return BAD_CATALOG
    if get(w, tools + 32) != TOOL_COUNT:
        return BAD_CATALOG
    offset = get(w, tools + 24)
    total = PREFIX_SIZE + 3
    ordinal = 1
    while ordinal <= TOOL_COUNT:
        row = 64 + offset * 72
        if entry_valid(w, row, ordinal) == 0:
            return BAD_CATALOG
        body = get(w, row + 56)
        end = body + get(w, row + 64)
        name = lookup(w, row, 3)
        total = compact(s, o, total, body + 1, end, False) + TITLE_SIZE + get(w, name + 32) + 2
        if ordinal > 1:
            total = total + 1
        offset = get(w, row + 16)
        ordinal = ordinal + 1
    if total > length(o):
        return 4294967293
    prefix(o)
    target = PREFIX_SIZE
    offset = get(w, tools + 24)
    ordinal = 1
    while ordinal <= TOOL_COUNT:
        if ordinal > 1:
            store(o, target, 44)
            target = target + 1
        row = 64 + offset * 72
        body = get(w, row + 56)
        end = body + get(w, row + 64)
        target = emit_title(o, w, target, lookup(w, row, 3))
        target = compact(s, o, target, body + 1, end, True)
        offset = get(w, row + 16)
        ordinal = ordinal + 1
    store(o, target, 93)
    store(o, target + 1, 125)
    store(o, target + 2, 10)
    return target + 3

def kind_is(w:mutbuf, field:u64, kind:u64) -> u64:
    if field == NONE:
        return 0
    return choose(get(w, field) == kind, 1, 0)

def entry_valid(w:mutbuf, row:u64, ordinal:u64) -> u64:
    if get(w, row) != 6 or get(w, row + 32) != 5:
        return 0
    name = lookup(w, row, 3)
    if kind_is(w, name, 4) == 0 or kind_is(w, lookup(w, row, 4), 4) == 0:
        return 0
    if kind_is(w, lookup(w, row, 5), 6) == 0 or kind_is(w, lookup(w, row, 6), 6) == 0:
        return 0
    if kind_is(w, lookup(w, row, 7), 6) == 0:
        return 0
    return choose(tool_id(w, get(w, name + 24), get(w, name + 32)) == ordinal, 1, 0)

def compact(s:readbuf, o:mutbuf, target:u64, begin:u64, end:u64, emit:bool) -> u64:
    quoted = False
    escaped = False
    while begin < end:
        value = byte(s, begin)
        keep = True
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value == 9 or value == 10 or value == 13 or value == 32:
            keep = False
        if keep:
            if emit:
                store(o, target, value)
            target = target + 1
        begin = begin + 1
    return target

def emit_title(o:mutbuf, w:mutbuf, at:u64, name:u64) -> u64:
    start = get(w, name + 24)
    width = get(w, name + 32)
    at = title_prefix(o, at)
    index = 0
    while index < width:
        letter = byte(w, start + index)
        if letter == 95:
            letter = 32
        elif letter >= 97 and letter <= 122:
            letter = letter - 32
        store(o, at + index, letter)
        index = index + 1
    at = at + width
    store(o, at, 34)
    store(o, at + 1, 44)
    return at + 2
'''


def render():
    names = tool_names()
    constants = {
        'WIRE_LIMIT': LIMIT, 'OUTPUT_LIMIT': OUTPUT_BYTES,
        'PREFIX_SIZE': len(PREFIX), 'TITLE_SIZE': len(TITLE),
        'BAD_CATALOG': INVALID_ENVELOPE, 'TOOL_COUNT': len(names), 'NONE': (1 << 64) - 1,
    }
    helpers = WIRE_HELPERS[:WIRE_HELPERS.index('def signed_id(')]
    policy = POLICY + helpers
    for name, value in constants.items():
        policy = policy.replace(name, str(value))
    prefix = ('def prefix(o:mutbuf) -> u64:\n' + literal_writes(PREFIX, offset='0') + '\n    return 0\n')
    title = ('def title_prefix(o:mutbuf, at:u64) -> u64:\n' + literal_writes(TITLE) +
             f'\n    return at + {len(TITLE)}\n')
    source = '\n'.join((policy, prefix, title, comparison_table('key_id', FIELDS),
                       comparison_table('profile_id', (PROFILE,)), comparison_table('tool_id', names),
                       json_decoder(wire_spans=True)))
    return render_assembly(document(source, 'mcp_catalog_wire'))


def main():
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
