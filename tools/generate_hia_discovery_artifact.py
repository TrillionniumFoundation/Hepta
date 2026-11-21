"""Author native key derivation and immutable Store rows for discovery."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sha256 import source_program as sha256_program

SOURCE = 'examples/hia_bootstrap/discovery_artifact.hepta'
POLICY = r'''
def discovery_artifact(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 80 and length(s) != 112:
        return 4294967293
    if length(o) < 1024 or length(w) < 1152:
        return 4294967294
    operation = word(s, 0)
    lookup = length(s) == 80
    if (lookup and operation != LOOKUP) or (lookup == False and operation != ISSUE):
        return 4294967293
    kind = word(s, 8)
    if kind != 1 and kind != 2:
        return 4294967293
    at = 16
    while at < 80:
        ch = byte(s, at)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 4294967293
        at = at + 1
    at = key_open(o, 0)
    at = kind_text(o, at, kind)
    at = key_middle(o, at)
    at = copy_input(s, o, 16, at, 64)
    at = json_close(o, at)
    if widen(sha256_in_place(o, at, w)) != 32:
        return 4294967293
    index = 0
    while index < 32:
        value = byte(o, index)
        store(w, 1088 + index * 2, hex_digit(value >> 4))
        store(w, 1089 + index * 2, hex_digit(value & 15))
        index = index + 1
    if lookup:
        put(o, 0, QUERY)
        put(o, 8, 1)
        put(o, 16, 1)
        put(o, 24, 120)
        put(o, 32, 3)
        put(o, 40, 56)
        put(o, 48, 64)
        return key_bytes(o, w, 56)
    return artifact_record(s, o, w, kind)

def artifact_record(s:readbuf, o:mutbuf, w:mutbuf, kind:u64) -> u64:
    name = choose(kind == 1, 7, 9)
    typed = 396 + name
    put(o, 0, RESULT)
    put(o, 8, typed)
    put(o, 16, 176)
    put(o, 24, INSERT)
    put(o, 32, 1)
    put(o, 40, 9)
    put(o, 48, 0)
    put(o, 56, 6)
    offset = 184
    field = 0
    while field < 6:
        size = choose(field == 0, 34, choose(field == 2, 48, choose(field == 3, name, choose(field == 4, 2, 64))))
        at = 64 + field * 24
        put(o, at, 3)
        put(o, at + 8, offset)
        put(o, at + 16, size)
        offset = offset + size
        field = field + 1
    at = artifact_id(o, 208)
    at = nonce_hex(s, o, 80, at)
    at = copy_input(s, o, 16, at, 64)
    at = artifact_uri(o, at)
    at = nonce_hex(s, o, 96, at)
    at = kind_text(o, at, kind)
    at = empty_metadata(o, at)
    at = key_bytes(o, w, at)
    at = ref_open(o, at)
    at = artifact_id(o, at)
    at = nonce_hex(s, o, 80, at)
    at = ref_sha(o, at)
    at = copy_input(s, o, 16, at, 64)
    at = ref_uri(o, at)
    at = artifact_uri(o, at)
    at = nonce_hex(s, o, 96, at)
    return json_close(o, at)

def key_bytes(o:mutbuf, w:mutbuf, at:u64) -> u64:
    index = 0
    while index < 64:
        store(o, at + index, byte(w, 1088 + index))
        index = index + 1
    return at + 64

def hex_digit(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def nonce_hex(s:readbuf, o:mutbuf, source:u64, at:u64) -> u64:
    index = 0
    while index < 16:
        value = byte(s, source + index)
        if index == 6:
            value = (value & 15) | 64
        elif index == 8:
            value = (value & 63) | 128
        store(o, at + index * 2, hex_digit(value >> 4))
        store(o, at + index * 2 + 1, hex_digit(value & 15))
        index = index + 1
    return at + 32

def kind_text(o:mutbuf, at:u64, kind:u64) -> u64:
    if kind == 1:
        return profile_name(o, at)
    return discovery_name(o, at)

def copy_input(s:readbuf, o:mutbuf, source:u64, at:u64, extent:u64) -> u64:
    index = 0
    while index < extent:
        store(o, at + index, byte(s, source + index))
        index = index + 1
    return at + extent

def word(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def widen(value:u32) -> u64:
    return value
'''

LITERALS = {
    'key_open': b'{"kind":"', 'key_middle': b'","metadata":{},"sha256":"',
    'json_close': b'"}', 'artifact_id': b'a-', 'artifact_uri': b'hia://artifacts/',
    'empty_metadata': b'{}', 'ref_open': b'{"id":"', 'ref_sha': b'","sha256":"',
    'ref_uri': b'","uri":"', 'profile_name': b'profile', 'discovery_name': b'discovery',
}


def source_program():
    tags = {'LOOKUP': b'HIADAL01', 'ISSUE': b'HIADAI01', 'RESULT': b'HIADAR01',
            'QUERY': b'HIAQPA01', 'INSERT': b'HIAINS01'}
    source = POLICY
    for name, value in tags.items():
        source = re.sub(rf'\b{name}\b', str(int.from_bytes(value, 'little')), source)
    for name, raw in LITERALS.items():
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for index, value in enumerate(raw):
            source += f'    store(o, at + {index}, {value})\n'
        source += f'    return at + {len(raw)}\n'
    # All message bytes are consumed before digest serialization, so hashing
    # the private key material in place needs no aliased buffer capabilities.
    hash_source = (sha256_program()
                   .replace('sha256(s:readbuf, o:mutbuf, w:mutbuf)', 'sha256_in_place(s:mutbuf, extent:u64, w:mutbuf)')
                   .replace('padded_byte(s:readbuf,', 'padded_byte(s:mutbuf, extent:u64,')
                   .replace('padded_byte(s,', 'padded_byte(s, extent,')
                   .replace('length(s)', 'extent').replace('length(o)', 'length(s)')
                   .replace('store(o, i * 4 + j,', 'store(s, i * 4 + j,'))
    return source + '\n' + hash_source


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'discovery_artifact')),
                            encoding='utf-8')
