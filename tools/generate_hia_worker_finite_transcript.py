"""Render exact retained finite-domain transcripts from HIA reference results."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import EXECUTION_CHAIN_FIELDS, EXECUTION_RESOURCE_FIELDS, WIDTHS
from hepta.hia_scalar_reference_wire import PROGRAM_RESULT, TRAPS, TYPES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_finite_batch import POLICY as BATCH, RESPONSE as BATCH_RESPONSE
from tools.generate_hia_worker_finite_reference import EVIDENCE, INVALID, NONE
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_finite_transcript.hepta')
REQUEST = int.from_bytes(b'HIAVFT01', 'little')
RESPONSE = int.from_bytes(b'HIAVFJ01', 'little')

POLICY = r'''
# [request, ledger flags, result type, name bytes, two batch sizes,
#  padded kind bytes, quoted public name, base batch, candidate batch].
# Output is exact successive canonical transcript JSON records, without a
# delimiter; stop only at the first semantic difference, not a tick change.
def finite_transcript(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 147 or length(w) < 64 or input_word(s, 0) != REQUEST_TAG:
        return BAD
    name = input_word(s, 24)
    left_size = input_word(s, 32)
    right_size = input_word(s, 40)
    if name < 3 or name > 130 or public_name(s, name) == False:
        return BAD
    start = 64 + name
    if start > length(s) or left_size > length(s) - start or right_size != length(s) - start - left_size:
        return BAD
    if left_size != right_size or left_size < 80:
        return BAD
    shape = input_word(s, 8)
    typ = input_word(s, 16)
    if shape > 3 or (typ != NONE and typ >= TYPE_COUNT):
        return BAD
    count = input_word(s, start + 24)
    if count > 12 or input_word(s, 56) >> 32 != 0:
        return BAD
    total = domain_count(s, 48, count)
    if total == 0 or length(o) < 64 + total * 1536:
        return BAD
    if batch_header(s, start, left_size, total, count, typ) == False:
        return BAD
    if batch_header(s, start + left_size, right_size, total, count, typ) == False:
        return BAD
    put(w, 0, count)
    put(w, 8, name)
    put(w, 16, shape)
    put(w, 24, typ)
    put(w, 32, start + 40)
    put(w, 40, start + left_size + 40)
    return render_transcript(s, o, w, total)

def batch_header(s:readbuf, at:u64, size:u64, total:u64, count:u64, typ:u64) -> bool:
    return size == 40 + total * 40 and input_word(s, at) == BATCH_TAG and input_word(s, at + 8) == 0 and input_word(s, at + 16) == total and input_word(s, at + 24) == count and input_word(s, at + 32) == choose(typ == NONE, 0, 1)

def render_transcript(s:readbuf, o:mutbuf, w:mutbuf, total:u64) -> u64:
    typ = get(w, 24)
    shape = get(w, 16)
    index = 0
    at = 64
    first_difference = NONE
    start = 0
    while index < total and first_difference == NONE:
        left = get(w, 32) + index * 40
        right = get(w, 40) + index * 40
        before = terminal(s, left, typ)
        after = terminal(s, right, typ)
        if before == NONE or after == NONE:
            return BAD
        values = paired_values(s, left, right, typ, before)
        if before != after or values == False or (shape & 1) != (shape >> 1):
            first_difference = index
        start = at
        at = after_prefix(o, at)
        at = observation(o, at, after, input_word(s, right + 32), typ, shape >> 1)
        at = before_prefix(o, at)
        at = observation(o, at, before, input_word(s, left + 32), typ, shape & 1)
        at = case_prefix(o, at)
        at = arguments(s, o, at, get(w, 0), index)
        at = function_prefix(o, at)
        at = append_name(s, o, at, get(w, 8))
        at = append(o, at, 32125, 2)
        index = index + 1
    put(o, 0, RESPONSE_TAG)
    put(o, 8, 0)
    put(o, 16, index)
    put(o, 24, total)
    put(o, 32, first_difference)
    put(o, 40, start)
    put(o, 48, at - start)
    put(o, 56, at - 64)
    return at

def terminal(s:readbuf, at:u64, typ:u64) -> u64:
    if input_word(s, at) != PROGRAM_REPLY:
        return NONE
    status = input_word(s, at + 8)
    steps = input_word(s, at + 16)
    detail = input_word(s, at + 24)
    value = input_word(s, at + 32)
    if steps == 0 or steps > 10000:
        return NONE
    if status == 0:
        if detail == 0 and scalar_bits(value, typ):
            return 0
        return NONE
    if value != 0:
        return NONE
    trap = first_trap(status, detail)
    if trap == NONE:
        return NONE
    return trap + 1

def paired_values(s:readbuf, left:u64, right:u64, typ:u64, status:u64) -> bool:
    return status != 0 or typ == NONE or input_word(s, left + 32) == input_word(s, right + 32)

def scalar_bits(value:u64, typ:u64) -> bool:
    if typ == NONE or typ == UNIT_TYPE:
        return value == 0
    if typ == BOOL_TYPE:
        return value < 2
    bits = width(typ)
    if bits == 64:
        return True
    if signed(typ):
        mask = 18446744073709551615 << bits
        return (value & mask) == choose((value >> (bits - 1)) & 1 == 0, 0, mask)
    return value < 1 << bits

def observation(o:mutbuf, at:u64, status:u64, value:u64, typ:u64, chain:u64) -> u64:
    at = observation_prefix(o, at)
    if status == 0:
        at = null_value(o, at)
    else:
        at = trap_text(o, at, status - 1)
    at = resource_prefix(o, at)
    if chain == 1:
        at = chain_resources(o, at)
    else:
        at = plain_resources(o, at)
    if status != 0:
        return trapped_tail(o, at)
    at = returned_prefix(o, at)
    if typ == BOOL_TYPE:
        at = boolean(o, at, value)
    elif typ == UNIT_TYPE:
        at = null_value(o, at)
    elif typ != NONE:
        at = number(o, at, value, signed(typ))
    return returned_tail(o, at)

def number(o:mutbuf, at:u64, value:u64, negative_allowed:bool) -> u64:
    if negative_allowed and value >> 63 != 0:
        at = append(o, at, 45, 1)
        value = 0 - value
    return decimal(o, at, value)

def arguments(s:readbuf, o:mutbuf, at:u64, count:u64, ordinal:u64) -> u64:
    index = 0
    bits = 0
    while index < count:
        bits = bits + (byte(s, 48 + index) & 127)
        index = index + 1
    index = 0
    while index < count:
        if index != 0:
            at = append(o, at, 44, 1)
        kind = byte(s, 48 + index)
        dimension = kind & 127
        bits = bits - dimension
        digit = (ordinal >> bits) & ((1 << dimension) - 1)
        if kind == 1:
            at = boolean(o, at, digit)
        elif kind == 136:
            at = number(o, at, digit - 128, True)
        else:
            at = number(o, at, digit, False)
        index = index + 1
    return at

def public_name(s:readbuf, size:u64) -> bool:
    if 64 + size > length(s) or byte(s, 64) != 34 or byte(s, 63 + size) != 34:
        return False
    index = 1
    while index + 1 < size:
        ch = byte(s, 64 + index)
        if ch != 95 and (ch < 65 or ch > 90) and (ch < 97 or ch > 122):
            if index == 1 or ch < 48 or ch > 57:
                return False
        index = index + 1
    return True

def append_name(s:readbuf, o:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, at + index, byte(s, 64 + index))
        index = index + 1
    return at + size

def append(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, at + index, value >> (index * 8))
        index = index + 1
    return at + size

def boolean(o:mutbuf, at:u64, value:u64) -> u64:
    if value == 0:
        return false_value(o, at)
    return true_value(o, at)
'''


def writer_body(raw):
    lines = []
    for offset in range(0, len(raw), 8):
        word = raw[offset:offset + 8]
        lines.append(f'at = append(o, at, {int.from_bytes(word, "little")}, {len(word)})')
    return lines


def writer(name, text):
    lines = [*writer_body(text.encode('ascii')), 'return at']
    return '\n'.join((f'def {name}(o:mutbuf, at:u64) -> u64:',
                      *('    ' + line for line in lines)))


def program():
    values = dict(BAD=INVALID, NONE=NONE, REQUEST_TAG=REQUEST, RESPONSE_TAG=RESPONSE,
                  BATCH_TAG=BATCH_RESPONSE, PROGRAM_REPLY=PROGRAM_RESULT,
                  TYPE_COUNT=len(TYPES), TRAP_COUNT=len(TRAPS),
                  BOOL_TYPE=TYPES.index('bool'), UNIT_TYPE=TYPES.index('unit'),
                  DIV_ZERO=TRAPS.index('division_by_zero'), OVERFLOW=TRAPS.index('overflow'))
    policy = '\n'.join((POLICY, function(BATCH, 'domain_count'), function(EVIDENCE, 'first_trap')))
    policy = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), policy)
    literals = {
        'after_prefix': '{"after":', 'before_prefix': ',"before":',
        'case_prefix': ',"case":{"arguments":[', 'function_prefix': '],"function":',
        'observation_prefix': '{"first_trap":', 'resource_prefix': ',"resources":',
        'returned_prefix': ',"status":"returned","values":[', 'returned_tail': ']}',
        'trapped_tail': ',"status":"trapped","values":null}',
        'false_value': 'false', 'true_value': 'true', 'null_value': 'null',
    }
    for name, fields in (('plain_resources', EXECUTION_RESOURCE_FIELDS),
                         ('chain_resources', EXECUTION_RESOURCE_FIELDS | EXECUTION_CHAIN_FIELDS)):
        literals[name] = '{' + ','.join(f'"{key}":0' for key in sorted(fields)) + '}'
    kinds = ['def width(typ:u64) -> u64:']
    for size in (8, 16, 32):
        tests = ' or '.join(f'typ == {index}' for index, name in enumerate(TYPES) if WIDTHS.get(name) == size)
        kinds.extend((f'    if {tests}:', f'        return {size}'))
    kinds.extend(('    return 64', 'def signed(typ:u64) -> bool:',
                  '    return ' + ' or '.join(f'typ == {i}' for i, name in enumerate(TYPES) if name.startswith('i'))))
    traps = ['def trap_text(o:mutbuf, at:u64, code:u64) -> u64:']
    for code, trap in enumerate(TRAPS):
        name = 'trap_' + trap
        literals[name] = '"' + trap + '"'
        traps.extend((f'    if code == {code}:', f'        return {name}(o, at)'))
    traps.append('    return at')
    return '\n'.join((
        policy, function(authority(), 'input_word'),
        *(function(RELEASE_WRITER, name) for name in ('put', 'get', 'write', 'decimal', 'divide10')),
        '\n'.join(kinds), '\n'.join(traps),
        *(writer(name, text) for name, text in literals.items()),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
