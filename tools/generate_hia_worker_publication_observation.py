"""Check the real Store row before reusing an immutable Worker publication."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_artifact import (
    EVALUATE_FIRST_KIND, EVALUATE_LAST_KIND, VERIFY_FIRST_KIND, VERIFY_LAST_KIND, kind_match_source, kind_width_source,
)
from tools.generate_hia_discovery_effect import source_program as discovery_policy
from tools.generate_hia_sha256 import source_program as sha256_policy
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_publication_observation.hepta')

POLICY = r'''
# The authorization header is derived from HIA's separately admitted bytes:
# [kind, content hash, content key, metadata hash, metadata extent].
# No existing row may bypass the exact metadata or object hash comparison.
def publication_observation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < HEADER + 48 or length(w) < 1088 or length(o) < 200:
        return INVALID
    if input_word(s, 0) != EXPECTED or valid_hex(s, 16, 192) == False:
        return INVALID
    kind = input_word(s, 8)
    extent = input_word(s, 208)
    if (kind >= VERIFY_FIRST and kind <= VERIFY_LAST) or (kind >= EVALUATE_FIRST and kind <= EVALUATE_LAST):
        if extent != 2:
            return INVALID
    elif kind < 12 or kind > 14 or extent < 2 or extent > 8388608:
        return INVALID
    row = length(s) - HEADER - 48
    trailer = HEADER + row
    if input_word(s, trailer) != 5 or input_word(s, trailer + 8) != row or input_word(s, trailer + 24) != 0:
        return INVALID
    found = input_word(s, trailer + 16)
    if row == 0:
        if found != 0:
            return INVALID
        state_put(o, 0, MISSING)
        state_put(o, 8, 0)
        return 16
    if found != 1 or valid_document_row(s, kind, extent, row) == False:
        return INVALID
    start = HEADER + 322 + document_kind_width(kind)
    if metadata_digest(s, start, extent, o, w) == False:
        return INVALID
    state_put(o, 0, DOCUMENT)
    state_put(o, 8, 176)
    state_put(o, 16, 0)
    at = ref_prefix(o, 24)
    at = copy_input(s, o, HEADER + 176, at, 34)
    at = ref_sha(o, at)
    at = copy_input(s, o, HEADER + 210, at, 64)
    at = ref_uri(o, at)
    at = copy_input(s, o, HEADER + 274, at, 48)
    return ref_end(o, at)

def valid_document_row(s:readbuf, kind:u64, extent:u64, size:u64) -> bool:
    name = document_kind_width(kind)
    if size != 386 + name + extent or input_word(s, HEADER) != ROW:
        return False
    if input_word(s, HEADER + 8) != 1 or input_word(s, HEADER + 16) != 1 or input_word(s, HEADER + 24) != 6:
        return False
    cursor = 176
    field = 0
    while field < 6:
        cell = HEADER + 32 + field * 24
        width = choose(field == 0, 34, choose(field == 2, 48, choose(field == 3, name, choose(field == 4, extent, 64))))
        if input_word(s, cell) != 3 or input_word(s, cell + 8) != cursor or input_word(s, cell + 16) != width:
            return False
        cursor = cursor + width
        field = field + 1
    if byte(s, HEADER + 176) != 97 or byte(s, HEADER + 177) != 45 or valid_hex(s, HEADER + 178, 32) == False:
        return False
    if uri_prefix(s, HEADER + 274) == False or valid_hex(s, HEADER + 290, 32) == False:
        return False
    if document_kind_matches(s, HEADER + 322, kind) == False:
        return False
    return compare(s, 16, HEADER + 210, 64) and compare(s, 80, HEADER + 322 + name + extent, 64)

def metadata_digest(s:readbuf, at:u64, extent:u64, o:mutbuf, w:mutbuf) -> bool:
    if widen(sha256_range(s, at, extent, o, w)) != 32:
        return False
    index = 0
    while index < 32:
        unit = byte(o, index)
        if byte(s, 144 + index * 2) != hex(unit >> 4) or byte(s, 145 + index * 2) != hex(unit & 15):
            return False
        index = index + 1
    return True

def widen(value:u32) -> u64:
    return value

def hex(point:u64) -> u64:
    return choose(point < 10, 48 + point, 87 + point)

def compare(s:readbuf, first:u64, second:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, first + index) != byte(s, second + index):
            return False
        index = index + 1
    return True
'''


def sha256_range():
    return (sha256_policy()
            .replace('sha256(s:readbuf, o:mutbuf, w:mutbuf)',
                     'sha256_range(s:readbuf, start:u64, extent:u64, o:mutbuf, w:mutbuf)')
            .replace('padded_byte(s:readbuf, index', 'padded_byte(s:readbuf, start:u64, extent:u64, index')
            .replace('padded_byte(s, block', 'padded_byte(s, start, extent, block')
            .replace('length(s)', 'extent').replace('byte(s, index)', 'byte(s, start + index)'))


def program():
    constants = {'HEADER': 216, 'INVALID': 4294967293,
                 'VERIFY_FIRST': VERIFY_FIRST_KIND, 'VERIFY_LAST': VERIFY_LAST_KIND,
                 'EVALUATE_FIRST': EVALUATE_FIRST_KIND, 'EVALUATE_LAST': EVALUATE_LAST_KIND}
    for name, value in (('EXPECTED', b'HIAEPO01'), ('ROW', b'HIAROW01'),
                        ('DOCUMENT', b'HIADOC01'), ('MISSING', b'HIAEPB01')):
        constants[name] = int.from_bytes(value, 'little')
    policy = re.sub(r'\b('+'|'.join(constants)+r')\b', lambda m: str(constants[m[0]]), POLICY)
    discovery = discovery_policy()
    return '\n'.join((policy, kind_match_source(), kind_width_source(), sha256_range(),
                      *(function(discovery, name) for name in
                        ('input_word', 'state_put', 'valid_hex', 'uri_prefix', 'copy_input',
                         'ref_prefix', 'ref_sha', 'ref_uri', 'ref_end'))))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
