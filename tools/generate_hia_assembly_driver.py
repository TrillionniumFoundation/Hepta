"""Project the shared native assembly diagnostic into the public driver report."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document


SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_cli/assembly_driver.hepta'

BODY = r'''
def driver(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) == 16 and word(s, 0, 8) == OUTPUT_PROBE:
        # A successful no-follow stat observes an existing directory entry,
        # including a dangling symlink. Leave other observations to the
        # established HIA publisher and its no-replace link.
        if word(s, 8, 8) != 0 or length(o) < ENVELOPE_SIZE + EXISTS_SIZE:
            return 0
        prefix(o, 0)
        output_exists(o, PREFIX_SIZE)
        suffix(o, PREFIX_SIZE + EXISTS_SIZE)
        return ENVELOPE_SIZE + EXISTS_SIZE
    if length(s) > 8192 or length(s) < 98:
        return 0
    # Read exactly the existing presenter's quoted JSON string. Its
    # bytes already include the required JSON escaping and UTF-8.
    if word(s, 0, 8) != REJECT_ROOT or word(s, 8, 8) != REJECT_STATUS or word(s, 16, 8) != REJECT_FALSE:
        return 0
    marker = 0
    while marker + MARKER_SIZE <= length(s):
        if word(s, marker, 8) == MARKER_A and word(s, marker + 8, 8) == MARKER_B and byte(s, marker + 16) == 34:
            begin = marker + MARKER_SIZE - 1
            return copy_message(s, o, begin)
        marker = marker + 1
    return 0

def copy_message(s:readbuf, o:mutbuf, begin:u64) -> u32:
    cursor = begin + 1
    escaped = False
    while cursor < length(s):
        next_char = byte(s, cursor)
        if escaped:
            escaped = False
        elif next_char == 34:
            return assemble(s, o, begin, cursor + 1)
        elif next_char == 92:
            escaped = True
        cursor = cursor + 1
    return 0

def assemble(s:readbuf, o:mutbuf, begin:u64, stop:u64) -> u32:
    if length(s) - stop < 15 or word(s, stop, 8) != AFTER_A or word(s, stop + 8, 7) != AFTER_B:
        return 0
    span = stop - begin
    if ENVELOPE_SIZE + span > length(o):
        return 0
    prefix(o, 0)
    i = 0
    while i < span:
        store(o, PREFIX_SIZE + i, byte(s, begin + i))
        i = i + 1
    suffix(o, PREFIX_SIZE + span)
    return ENVELOPE_SIZE + span

def word(s:readbuf, at:u64, width:u64) -> u64:
    value = 0
    index = 0
    while index < width:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def write_word(o:mutbuf, at:u64, width:u64, value:u64) -> u64:
    index = 0
    while index < width:
        store(o, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''

PREFIX = b'{\n  "diagnostics": [\n    {\n      "code": "E_DRIVER",\n      "message": '
SUFFIX = b',\n      "phase": "driver"\n    }\n  ],\n  "ok": false,\n  "status": "error"\n}\n'
EXISTS = b'"E_HIA_EDIT: destination must be a new file"'


def put_literal(name, literal):
    lines = [f'def {name}(o:mutbuf, at:u64) -> u64:']
    for start in range(0, len(literal), 8):
        chunk = literal[start:start + 8]
        lines.append(f'    write_word(o, at + {start}, {len(chunk)}, {int.from_bytes(chunk, "little")})')
    return '\n'.join(lines + ['    return 0', ''])


def source_program():
    marker = b'\n    "message": "'
    after = b',\n    "phase": '
    constants = {
        'REJECT_ROOT': int.from_bytes(b'{\n  "acc', 'little'),
        'REJECT_STATUS': int.from_bytes(b'epted": ', 'little'),
        'REJECT_FALSE': int.from_bytes(b'false,\n ', 'little'),
        'MARKER_SIZE': len(marker),
        'MARKER_A': int.from_bytes(marker[:8], 'little'),
        'MARKER_B': int.from_bytes(marker[8:16], 'little'),
        'AFTER_A': int.from_bytes(after[:8], 'little'),
        'AFTER_B': int.from_bytes(after[8:], 'little'),
        'PREFIX_SIZE': len(PREFIX), 'ENVELOPE_SIZE': len(PREFIX + SUFFIX),
        'OUTPUT_PROBE': int.from_bytes(b'HIAPEX01', 'little'), 'EXISTS_SIZE': len(EXISTS),
    }
    # The marker spans two words and one opening quote.
    assert len(marker) == 17 and len(after) == 15
    source = BODY
    for name, value in constants.items():
        source = source.replace(name, str(value))
    return (source + '\n' + put_literal('prefix', PREFIX) + '\n' + put_literal('suffix', SUFFIX)
            + '\n' + put_literal('output_exists', EXISTS))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), 'assembly_driver')))
