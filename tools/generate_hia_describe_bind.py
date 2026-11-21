"""Bind the discovered language artifact to the canonical describe answer."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_describe_answer_native import BASE_FIELDS, REFERENCE_COUNT
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_artifact import sha256_in_place_program

SOURCE = 'examples/hia_bootstrap/describe_bind.hepta'
FIELDS = BASE_FIELDS + REFERENCE_COUNT
METADATA_FIELDS = 8 + FIELDS * 8
ANSWER_FIELDS = 16 + FIELDS * 8

POLICY = r'''
def describe_bind(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(o) < 65536 or length(w) < 1088:
        return 4294967293
    if word(s, 0) != BIND:
        return 4294967293
    metadata = word(s, 8)
    discovery = word(s, 16)
    retained = word(s, 24)
    if metadata < METADATA_FIELDS or metadata > 32768 or metadata > length(s) - 32:
        return 4294967293
    if discovery <= 32 or discovery > 65568 or discovery > length(s) - 32 - metadata:
        return 4294967293
    if retained != 305 or retained != length(s) - 32 - metadata - discovery:
        return 4294967293
    if word(s, 32) != METADATA:
        return 4294967293
    found = 32 + metadata
    doc = found + discovery
    version = word(s, found)
    roles = word(s, found + 8)
    recipe = word(s, found + 16)
    if version < 1 or version > 9 or roles < 1 or roles > 10 or recipe >> (roles * 5) != 0:
        return 4294967293
    if word(s, found + 24) != discovery - 32:
        return 4294967293
    if word(s, doc) != DOCUMENT or word(s, doc + 8) != 176 or word(s, doc + 16) != 105:
        return 4294967293
    reference = doc + 24
    if ref_id(s, reference) == False or profile_sha(s, reference + 41) == False or ref_uri(s, reference + 117) == False:
        return 4294967293
    if byte(s, reference + 174) != 34 or byte(s, reference + 175) != 125:
        return 4294967293
    if hex_text(s, reference + 9) == False or hex_text(s, reference + 142) == False:
        return 4294967293
    profile = doc + 200
    if schema_prefix(s, profile) == False or byte(s, profile + 26) != 48 + version:
        return 4294967293
    if profile_sha(s, profile + 27) == False or byte(s, profile + 103) != 34 or byte(s, profile + 104) != 125:
        return 4294967293
    copy_value(s, o, found + 32, 0, discovery - 32)
    if widen(sha256_in_place(o, discovery - 32, w)) != 32:
        return 4294967293
    index = 0
    while index < 64:
        datum = byte(o, index >> 1)
        digit = choose(index & 1 == 0, datum >> 4, datum & 15)
        encoded = choose(digit < 10, digit + 48, digit + 87)
        if byte(s, doc + 77 + index) != encoded or byte(s, profile + 39 + index) != encoded:
            return 4294967293
        index = index + 1
    return answer_packet(s, o, metadata, doc, roles | (recipe << 4))

def hex_text(s:readbuf, at:u64) -> bool:
    end = at + 32
    while at < end:
        value = byte(s, at)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return False
        at = at + 1
    return True

def answer_packet(s:readbuf, o:mutbuf, metadata:u64, doc:u64, recipe:u64) -> u64:
    put(o, 0, ANSWER)
    put(o, 8, recipe)
    source = 32 + METADATA_FIELDS
    end = 32 + metadata
    out = ANSWER_FIELDS
    index = 0
    while index < FIELD_COUNT:
        count = word(s, 40 + index * 8)
        at = source
        if index == 3 or index == 9:
            if count != 0:
                return 4294967293
            count = choose(index == 3, 105, 176)
            at = doc + choose(index == 3, 200, 24)
        else:
            if count == 0 or count > 4096 or count > end - source:
                return 4294967293
            source = source + count
        if count > length(o) - out:
            return 4294967294
        put(o, 16 + index * 8, count)
        out = copy_value(s, o, at, out, count)
        index = index + 1
    if source != end:
        return 4294967293
    return out

def copy_value(s:readbuf, o:mutbuf, at:u64, out:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, out + index, byte(s, at + index))
        index = index + 1
    return out + size

def word(s:readbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(s, at + count) << (count * 8))
        count = count + 1
    return value

def widen(value:u32) -> u64:
    return value
'''


def source_program():
    tags = {'BIND': b'HIADBD01', 'METADATA': b'HIADMT01', 'DOCUMENT': b'HIADOC01',
            'ANSWER': b'HIADISAN'}
    constants = {name: int.from_bytes(value, 'little') for name, value in tags.items()}
    constants.update(METADATA_FIELDS=METADATA_FIELDS, ANSWER_FIELDS=ANSWER_FIELDS, FIELD_COUNT=FIELDS)
    source = POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    for name, raw in (('schema_prefix', b'{"id":"hepta.hia.program.v'), ('profile_sha', b'","sha256":"'),
                      ('ref_id', b'{"id":"a-'), ('ref_uri', b'","uri":"hia://artifacts/')):
        source += f'\ndef {name}(s:readbuf, at:u64) -> bool:\n'
        source += '    return ' + ' and '.join(
            f'byte(s, at + {index}) == {value}' for index, value in enumerate(raw)) + '\n'
    return source + '\n' + sha256_in_place_program()


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'describe_bind')),
                            encoding='utf-8')
