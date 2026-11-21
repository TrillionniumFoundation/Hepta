"""Author the native typed commands for a durable Worker request key."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

SOURCE = 'examples/hia_bootstrap/worker_journal_records.hepta'
RESPONSE_LIMIT = 8 << 20

POLICY = r'''
def journal_records(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 72 or length(o) < 512 or valid_hex(s, 8) == False:
        return 4294967293
    operation = word(s, 0)
    if operation == LOOKUP:
        if length(s) != 72:
            return 4294967293
        return lookup(s, o)
    if operation == RESERVE:
        if length(s) < 137 or length(s) > 156 or valid_hex(s, 72) == False:
            return 4294967293
        return reserve(s, o)
    if operation == COMPLETE:
        if length(s) < 74 or length(s) - 72 > RESPONSE_LIMIT or length(o) < length(s) + 80:
            return 4294967293
        if byte(s, 72) != 123 or byte(s, length(s) - 1) != 125:
            return 4294967293
        return complete(s, o)
    return 4294967293

def lookup(s:readbuf, o:mutbuf) -> u64:
    put(o, 0, QUERY)
    put(o, 8, 1)
    put(o, 16, 1)
    put(o, 24, 120)
    cell(o, 32, 3, 56, 64)
    return copy(s, o, 8, 56, 64)

def reserve(s:readbuf, o:mutbuf) -> u64:
    width = length(s) - 136
    if canonical_time(s, 136, width) == False:
        return 4294967293
    put(o, 0, INSERT)
    put(o, 8, 1)
    put(o, 16, 6)
    put(o, 24, 0)
    put(o, 32, 6)
    cell(o, 40, 3, 184, 64)
    cell(o, 64, 3, 248, 64)
    cell(o, 88, 3, 312, TOOL_BYTES)
    cell(o, 112, 3, 312 + TOOL_BYTES, 7)
    cell(o, 136, 0, 319 + TOOL_BYTES, 0)
    cell(o, 160, 3, 319 + TOOL_BYTES, width)
    at = copy(s, o, 8, 184, 128)
    at = tool(o, at)
    at = running(o, at)
    return copy(s, o, 136, at, width)

def complete(s:readbuf, o:mutbuf) -> u64:
    response = length(s) - 72
    put(o, 0, UPDATE)
    put(o, 8, 1)
    put(o, 16, 1)
    put(o, 24, 0)
    put(o, 32, 2)
    cell(o, 40, 3, 88, response)
    cell(o, 64, 3, 88 + response, 64)
    past = copy(s, o, 72, 88, response)
    return copy(s, o, 8, past, 64)

def canonical_time(s:readbuf, at:u64, size:u64) -> bool:
    if size > 1 and byte(s, at) == 48:
        return False
    index = 0
    value = 0
    while index < size:
        ch = byte(s, at + index)
        if ch < 48 or ch > 57:
            return False
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return False
        value = value * 10 + digit
        index = index + 1
    return True

def valid_hex(s:readbuf, at:u64) -> bool:
    index = 0
    while index < 64:
        ch = byte(s, at + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        index = index + 1
    return True

def cell(o:mutbuf, at:u64, kind:u64, offset:u64, size:u64) -> u64:
    put(o, at, kind)
    put(o, at + 8, offset)
    put(o, at + 16, size)
    return 0

def copy(s:readbuf, o:mutbuf, at:u64, target:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, target + index, byte(s, at + index))
        index = index + 1
    return target + size

def word(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(o, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0
'''


def source_program():
    tags = {'LOOKUP': b'HIARJL01', 'RESERVE': b'HIARJR01', 'COMPLETE': b'HIARJC01',
            'QUERY': b'HIAQPA01', 'INSERT': b'HIAINS01', 'UPDATE': b'HIAUPB01'}
    tool = b'hia_artifact'
    constants = {name: int.from_bytes(raw, 'little') for name, raw in tags.items()}
    constants.update(RESPONSE_LIMIT=RESPONSE_LIMIT, TOOL_BYTES=len(tool))
    source = POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    for name, raw in (('tool', tool), ('running', b'running')):
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for index, value in enumerate(raw):
            source += f'    store(o, at + {index}, {value})\n'
        source += f'    return at + {len(raw)}\n'
    return source


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'journal_records')), encoding='utf-8')
