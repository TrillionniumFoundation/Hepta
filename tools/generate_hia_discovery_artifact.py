"""Author native key derivation and immutable Store rows for Agent artifacts."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_discovery_native import PROFILE_NAMES
from hepta.hia_schema import PRIMITIVE_PROFILES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sha256 import source_program as sha256_program
from tools.hia_emit_metadata_layout import EMIT_DOCUMENT_KINDS, METADATA_LIMIT, emit_metadata_source

SOURCE = 'examples/hia_bootstrap/discovery_artifact.hepta'
DOCUMENT_KINDS = (b'profile', b'discovery', b'input', b'context',
                  b'inspection', b'edit-query', b'lowering-object',
                  b'core', b'candidate-diagnostics', b'rollback-receipt', b'slot-snapshot',
                  *EMIT_DOCUMENT_KINDS)

CANDIDATE_CONTEXT = '''
def candidate_context(s:readbuf, at:u64) -> bool:
    if at > length(s) or length(s) - at < 121:
        return False
    if candidate_context_open(s, at) == False or candidate_context_sha(s, at + 43) == False:
        return False
    if byte(s, at + 119) != 34 or byte(s, at + 120) != 125:
        return False
    index = 11
    while index < 119:
        if index == 43:
            index = 55
        ch = byte(s, at + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        index = index + 1
    return True
'''


def candidate_context_source():
    parts = (('open', b'{"id":"ctx-'), ('sha', b'","sha256":"'), ('metadata', b'{"context":'))
    source = CANDIDATE_CONTEXT
    for name, raw in parts:
        tests = ' and '.join(f'byte(s, at + {index}) == {value}' for index, value in enumerate(raw))
        source += f'\ndef candidate_context_{name}(s:readbuf, at:u64) -> bool:\n    return {tests}\n'
    return source


def kind_width_source():
    source = '\ndef document_kind_width(kind:u64) -> u64:\n'
    for index, name in enumerate(DOCUMENT_KINDS, 1):
        source += f'    if kind == {index}:\n        return {len(name)}\n'
    return source + '    return 0\n'


def kind_match_source():
    source = '\ndef document_kind_matches(s:readbuf, at:u64, kind:u64) -> bool:\n'
    for index, name in enumerate(DOCUMENT_KINDS, 1):
        fields = ('kind_word(s, at + %d, %d) == %d' % (at, len(chunk), int.from_bytes(chunk, 'little'))
                  for at in range(0, len(name), 8) if (chunk := name[at:at + 8]))
        source += f'    if kind == {index}:\n        return ' + ' and '.join(fields) + '\n'
    return source + '''    return False

def kind_word(s:readbuf, at:u64, width:u64) -> u64:
    value = 0
    index = 0
    while index < width:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value
'''


POLICY = r'''
def discovery_artifact(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 80:
        return 4294967293
    if length(o) < 1024 or length(w) < 1152:
        return 4294967294
    operation = word(s, 0)
    if operation == PROFILE:
        if length(s) != 192:
            return 4294967293
        return profile_record(s, o)
    lookup = operation == LOOKUP
    if lookup == False and operation != ISSUE:
        return 4294967293
    kind = word(s, 8)
    if document_kind_width(kind) == 0 or valid_digest(s, 16, 64) == False:
        return 4294967293
    nonce = choose(lookup, 0, 32)
    if length(s) < 80 + nonce:
        return 4294967293
    supplied = length(s) - 80 - nonce
    if kind >= 12:
        if supplied > @META_LIMIT@ or length(o) < supplied + 640:
            return 4294967293
        if emit_metadata(s, 80, supplied, kind) == False:
            return 4294967293
    else:
        if supplied != choose(kind == 8, 121, 0):
            return 4294967293
        if kind == 8 and candidate_context(s, 80) == False:
            return 4294967293
    at = key_open(o, 0)
    at = kind_text(o, at, kind)
    at = key_metadata(o, at)
    at = metadata(s, o, at, kind, supplied)
    at = key_sha(o, at)
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
    return artifact_record(s, o, w, kind, supplied)

def artifact_record(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, supplied:u64) -> u64:
    name = document_kind_width(kind)
    meta_size = choose(kind >= 12, supplied, choose(kind == 8, 133, 2))
    typed = 394 + name + meta_size
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
        size = choose(field == 0, 34, choose(field == 2, 48, choose(field == 3, name, choose(field == 4, meta_size, 64))))
        at = 64 + field * 24
        put(o, at, 3)
        put(o, at + 8, offset)
        put(o, at + 16, size)
        offset = offset + size
        field = field + 1
    at = artifact_id(o, 208)
    at = nonce_hex(s, o, 80 + supplied, at)
    at = copy_input(s, o, 16, at, 64)
    at = artifact_uri(o, at)
    at = nonce_hex(s, o, 96 + supplied, at)
    at = kind_text(o, at, kind)
    at = metadata(s, o, at, kind, supplied)
    at = key_bytes(o, w, at)
    at = ref_open(o, at)
    at = artifact_id(o, at)
    at = nonce_hex(s, o, 80 + supplied, at)
    at = ref_sha(o, at)
    at = copy_input(s, o, 16, at, 64)
    at = ref_uri(o, at)
    at = artifact_uri(o, at)
    at = nonce_hex(s, o, 96 + supplied, at)
    return json_close(o, at)

def metadata(s:readbuf, o:mutbuf, at:u64, kind:u64, supplied:u64) -> u64:
    if kind >= 12:
        return copy_input(s, o, 80, at, supplied)
    if supplied == 0:
        return empty_metadata(o, at)
    at = metadata_context(o, at)
    at = copy_input(s, o, 80, at, supplied)
    store(o, at, 125)
    return at + 1

# The selected version is the native discovery receipt ordinal, not a
# caller-supplied profile ID. Retain the exact canonical issued reference.
def profile_record(s:readbuf, o:mutbuf) -> u64:
    version = word(s, 8)
    if version == 0 or version > VERSIONS:
        return 4294967293
    if same_id(s, 16) == False or same_sha(s, 57) == False or same_uri(s, 133) == False:
        return 4294967293
    if byte(s, 190) != 34 or byte(s, 191) != 125:
        return 4294967293
    if valid_digest(s, 25, 32) == False or valid_digest(s, 69, 64) == False or valid_digest(s, 158, 32) == False:
        return 4294967293
    put(o, 0, PROFILE_RESULT)
    name = profile_id_bytes(version)
    put(o, 8, 352 + name)
    put(o, 16, 85 + name)
    put(o, 24, INSERT)
    put(o, 32, 1)
    put(o, 40, 11)
    put(o, 48, 0)
    put(o, 56, 3)
    put(o, 64, 3)
    put(o, 72, 112)
    put(o, 80, name)
    put(o, 88, 3)
    put(o, 96, 112 + name)
    put(o, 104, 64)
    put(o, 112, 3)
    put(o, 120, 176 + name)
    put(o, 128, 176)
    at = profile_id(o, 136, version)
    at = copy_input(s, o, 69, at, 64)
    at = copy_input(s, o, 16, at, 176)
    at = ref_open(o, at)
    at = profile_id(o, at, version)
    at = ref_sha(o, at)
    at = copy_input(s, o, 69, at, 64)
    return json_close(o, at)

def valid_digest(s:readbuf, start:u64, count:u64) -> bool:
    at = start
    while at < start + count:
        ch = byte(s, at)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        at = at + 1
    return True

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
    'key_open': b'{"kind":"', 'key_metadata': b'","metadata":', 'key_sha': b',"sha256":"',
    'json_close': b'"}', 'artifact_id': b'a-', 'artifact_uri': b'hia://artifacts/',
    'empty_metadata': b'{}', 'ref_open': b'{"id":"', 'ref_sha': b'","sha256":"',
    'ref_uri': b'","uri":"', 'schema_version': b'hepta.hia.program.v',
    'metadata_context': b'{"context":',
}


def source_program():
    tags = {'LOOKUP': b'HIADAL01', 'ISSUE': b'HIADAI01', 'RESULT': b'HIADAR01',
            'PROFILE': b'HIADPR01', 'PROFILE_RESULT': b'HIADPS01',
            'QUERY': b'HIAQPA01', 'INSERT': b'HIAINS01'}
    assert tuple(PRIMITIVE_PROFILES) == tuple(f'hepta.hia.program.v{n}' for n in range(1, 10))
    source = POLICY.replace('@META_LIMIT@', str(METADATA_LIMIT))
    source += kind_width_source() + candidate_context_source() + emit_metadata_source()
    for name, value in tags.items():
        source = re.sub(rf'\b{name}\b', str(int.from_bytes(value, 'little')), source)
    qualified = {key: ('hia-' + key + '-v1').encode('ascii') for key in PROFILE_NAMES}
    source = source.replace('VERSIONS', str(len(PRIMITIVE_PROFILES) + len(qualified)))
    source += '\ndef profile_id(o:mutbuf, at:u64, version:u64) -> u64:\n'
    source += '    if version <= 9:\n        at = schema_version(o, at)\n'
    source += '        store(o, at, 48 + version)\n        return at + 1\n'
    for ordinal, name in enumerate(qualified, 10):
        source += f'    if version == {ordinal}:\n        return installed_{name}(o, at)\n'
    source += '    return at\n'
    source += '\ndef profile_id_bytes(version:u64) -> u64:\n    if version <= 9:\n        return 20\n'
    for ordinal, raw in enumerate(qualified.values(), 10):
        source += f'    if version == {ordinal}:\n        return {len(raw)}\n'
    source += '    return 0\n'
    names = dict(LITERALS)
    source += '\ndef kind_text(o:mutbuf, at:u64, kind:u64) -> u64:\n'
    for ordinal, name in enumerate(DOCUMENT_KINDS, 1):
        label = name.decode('ascii').replace('-', '_') + '_name'
        names[label] = name
        source += f'    if kind == {ordinal}:\n        return {label}(o, at)\n'
    source += '    return at\n'
    names.update((f'installed_{name}', raw) for name, raw in qualified.items())
    for name, raw in names.items():
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for index, value in enumerate(raw):
            source += f'    store(o, at + {index}, {value})\n'
        source += f'    return at + {len(raw)}\n'
    for name, raw in (('same_id', b'{"id":"a-'), ('same_sha', LITERALS['ref_sha']),
                      ('same_uri', LITERALS['ref_uri'] + LITERALS['artifact_uri'])):
        source += f'\ndef {name}(s:readbuf, at:u64) -> bool:\n'
        source += '    return ' + ' and '.join(
            f'byte(s, at + {index}) == {value}' for index, value in enumerate(raw)) + '\n'
    return source + '\n' + sha256_in_place_program()


def sha256_in_place_program():
    # All message bytes are consumed before digest serialization, so hashing
    # private canonical bytes needs no aliased buffer capabilities.
    return (sha256_program()
                   .replace('sha256(s:readbuf, o:mutbuf, w:mutbuf)', 'sha256_in_place(s:mutbuf, extent:u64, w:mutbuf)')
                   .replace('padded_byte(s:readbuf,', 'padded_byte(s:mutbuf, extent:u64,')
                   .replace('padded_byte(s,', 'padded_byte(s, extent,')
                   .replace('length(s)', 'extent').replace('length(o)', 'length(s)')
                   .replace('store(o, i * 4 + j,', 'store(s, i * 4 + j,'))


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'discovery_artifact')),
                            encoding='utf-8')
