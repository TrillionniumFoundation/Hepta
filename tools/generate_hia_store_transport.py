"""Author HIA's native Store command and response-header protocol."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/agent_store_transport.hepta'

WIRE = {
    'BUILD_COMMAND': b'HIASTCM1',
    'READ_ACK': b'HIASTAK1',
    'READ_ROW': b'HIASTRW1',
    'COMMAND': b'HIATCM01',
    'ACK': b'HIATXR01',
    'ROW': b'HIAQRF01',
}

POLICY = '''
def store_transport(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8:
        return 0
    role = read_word(s, 0)
    if role == BUILD_COMMAND:
        if length(s) != 40 or length(o) != 48 or read_word(s, 8) == 0:
            return 0
        write_word(o, 0, COMMAND)
        write_word(o, 8, 1)
        copy_fields(s, o, 8, 16, 32)
        return 48
    if role == READ_ACK:
        if length(s) != 104 or length(o) != 48:
            return 0
        if read_word(s, 24) != ACK or read_word(s, 32) != 1:
            return 0
        if read_word(s, 40) != read_word(s, 8) or read_word(s, 48) != read_word(s, 16):
            return 0
        copy_fields(s, o, 56, 0, 48)
        return 48
    if role == READ_ROW:
        if length(s) != 88 or length(o) != 56:
            return 0
        if read_word(s, 24) != ROW or read_word(s, 40) != read_word(s, 8):
            return 0
        if read_word(s, 64) > read_word(s, 16) or read_word(s, 80) != 0:
            return 0
        copy_fields(s, o, 32, 0, 56)
        return 56
    return 0

def read_word(s:readbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(s, at + count) << (count * 8))
        count = count + 1
    return value

def write_word(o:mutbuf, at:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(o, at + count, (value >> (count * 8)) & 255)
        count = count + 1
    return 0

def copy_fields(s:readbuf, o:mutbuf, start:u64, end:u64, extent:u64) -> u64:
    index = 0
    while index < extent:
        store(o, end + index, byte(s, start + index))
        index = index + 1
    return 0
'''


def source_program():
    import re

    return re.sub(r'\b(' + '|'.join(WIRE) + r')\b',
        lambda name: str(int.from_bytes(WIRE[name.group()], 'little')), POLICY)


if __name__ == '__main__':
    program = document(source_program(), module='agent_store_transport')
    SOURCE.write_text(render_assembly(program))
