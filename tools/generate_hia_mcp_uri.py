"""Author sealed HIA resource URI admission; it never grants read authority."""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_mcp_request import INVALID_ENVELOPE, ROOT

SOURCE = 'examples/hia_bootstrap/mcp_resource_uri.hepta'
PREFIX = b'hia://artifacts/'
MAGIC = b'HIAMURI1'
SUFFIX_LIMIT = 192
DESCRIPTOR_BYTES = 24

POLICY = r'''
def check_uri(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if size <= PREFIX_SIZE or size > PREFIX_SIZE + SUFFIX_LIMIT or length(o) < DESCRIPTOR_BYTES:
        return INVALID
    if uri_word(s, 0, 8) != PREFIX_FIRST or uri_word(s, 8, 8) != PREFIX_SECOND:
        return INVALID
    offset = PREFIX_SIZE
    if ascii_alphanum(byte(s, offset)) == 0:
        return INVALID
    while offset < size:
        value = byte(s, offset)
        if ascii_alphanum(value) == 0 and value != 46 and value != 95 and value != 126 and value != 45:
            return INVALID
        offset = offset + 1
    put(o, 0, MAGIC)
    put(o, 8, size)
    put(o, 16, size - PREFIX_SIZE)
    return DESCRIPTOR_BYTES

def ascii_alphanum(value:u64) -> u64:
    return choose((value >= 48 and value <= 57) or (value >= 65 and value <= 90) or (value >= 97 and value <= 122), 1, 0)

def uri_word(s:readbuf, at:u64, width:u64) -> u64:
    value = 0
    index = 0
    while index < width:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def put(o:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(o, index + count, (value >> (8 * count)) & 255)
        count = count + 1
    return 0
'''


def render():
    words = {
        'PREFIX_SIZE': len(PREFIX), 'SUFFIX_LIMIT': SUFFIX_LIMIT, 'DESCRIPTOR_BYTES': DESCRIPTOR_BYTES,
        'PREFIX_FIRST': int.from_bytes(PREFIX[:8], 'little'),
        'PREFIX_SECOND': int.from_bytes(PREFIX[8:], 'little'),
        'MAGIC': int.from_bytes(MAGIC, 'little'), 'INVALID': INVALID_ENVELOPE,
    }
    source = POLICY
    for marker, value in words.items():
        source = source.replace(marker, str(value))
    return render_assembly(document(source, 'mcp_resource_uri'))


def main():
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
