"""Author native retained-context queries and atomic creation bindings."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY
from tools.generate_hia_worker_artifact_authority import source_program as artifact_policy

SOURCE = Path('examples/hia_bootstrap/worker_context_store.hepta')

POLICY = r'''
def context_store(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 640:
        return 4294967293
    mode = input_word(s, 0)
    if mode == LOOKUP:
        return context_lookup(s, o)
    if mode == OBSERVE:
        return context_observe(s, o)
    if mode != CREATE or length(s) != 208:
        return 4294967293
    if artifact_reference(s, 32) == False:
        return 4294967293
    put(o, 0, BINDINGS)
    put(o, 16, 100)
    put(o, 24, 36)
    context_name(s, o, 32)

    # Exact old INSERT_CONTEXT bindings, including its actual timestamp.
    at = 68
    insert(o, at, 1, 4)
    field(o, at + 40, 136, 36)
    field(o, at + 64, 172, 64)
    field(o, at + 88, 236, 176)
    context_name(s, o, at + 136)
    copy_input(s, o, 85, at + 172, 64)
    copy_input(s, o, 32, at + 236, 176)
    end = decimal(o, at + 412, input_word(s, 8))
    field(o, at + 112, 412, end - at - 412)
    put(o, 8, end - at)

    # The budget's initial used='0' and owner=NULL belong to native INSERT 3.
    insert(o, end, 3, 1)
    field(o, end + 40, 64, 36)
    context_name(s, o, end + 64)
    return end + 100

# Query the original five-column context row by server-generated ID.
def context_lookup(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 44 or is_context_name(s, 8) == False:
        return 4294967293
    query_header(o, 0, 1, 92)
    query_field(o, 32, 56, 36)
    return copy_input(s, o, 8, 56, 36)

# Compare the requested reference to a correlated sealed Store observation.
# Distinguish an unknown ID from a mismatched digest as the controller does,
# without yielding a usable artifact reference on either path.
def context_observe(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 184 or input_word(s, 32) & 4294967295 != 0 or is_context_name(s, 36) == False or valid_hex(s, 72, 64) == False:
        return 4294967293
    size = input_word(s, 8)
    if size != length(s) - 184 or unique_summary(s, 136 + size, size) == False:
        return 4294967293
    put(o, 0, RESOLVED)
    if size == 0:
        put(o, 8, 1)
        return 16
    row = 136
    if size < 437 or size > 456 or row_header(s, row, 3, 5) == False:
        return 4294967293
    if row_text(s, row + 32, 152, 36) == False or row_text(s, row + 56, 188, 64) == False:
        return 4294967293
    if row_text(s, row + 80, 252, 176) == False or row_text(s, row + 104, 428, size - 436) == False:
        return 4294967293
    if input_word(s, row + 128) != 1 or input_word(s, row + 136) != size - 8 or input_word(s, row + 144) != 8:
        return 4294967293
    if matches(s, row + 152, 36, 36) == False or valid_hex(s, row + 188, 64) == False:
        return 4294967293
    if matches(s, row + 188, 72, 64) == False:
        put(o, 8, 2)
        return 16
    if artifact_reference(s, row + 252) == False or matches(s, row + 305, 72, 64) == False:
        return 4294967293
    attempts = input_word(s, row + size - 8)
    if attempts > 9223372036854775807 or decimal_time(s, row + 428, size - 436) == False:
        return 4294967293
    put(o, 8, 0)
    put(o, 16, attempts)
    put(o, 24, size - 436)
    copy_input(s, o, row + 252, 32, 176)
    return copy_input(s, o, row + 428, 208, size - 436)

def decimal_time(s:readbuf, at:u64, width:u64) -> bool:
    if width > 1 and byte(s, at) == 48:
        return False
    value = 0
    index = 0
    while index < width:
        digit = byte(s, at + index)
        if digit < 48 or digit > 57:
            return False
        digit = digit - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return False
        value = value * 10 + digit
        index = index + 1
    return True

def is_context_name(s:readbuf, at:u64) -> bool:
    return byte(s, at) == 99 and byte(s, at + 1) == 116 and byte(s, at + 2) == 120 and byte(s, at + 3) == 45 and valid_hex(s, at + 4, 32)

def insert(o:mutbuf, at:u64, ordinal:u64, count:u64) -> u64:
    put(o, at, INSERT)
    put(o, at + 8, 1)
    put(o, at + 16, ordinal)
    put(o, at + 24, 0)
    return put(o, at + 32, count)

def field(o:mutbuf, at:u64, offset:u64, size:u64) -> u64:
    put(o, at, 3)
    put(o, at + 8, offset)
    return put(o, at + 16, size)

def context_name(s:readbuf, o:mutbuf, at:u64) -> u64:
    store(o, at, 99)
    store(o, at + 1, 116)
    store(o, at + 2, 120)
    store(o, at + 3, 45)
    index = 0
    while index < 16:
        c = byte(s, 16 + index)
        store(o, at + 4 + index * 2, nibble(c >> 4))
        store(o, at + 5 + index * 2, nibble(c & 15))
        index = index + 1
    return at + 36

def nibble(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)
'''


def program():
    constants = {'CREATE': b'HIACTS01', 'BINDINGS': b'HIACTB01', 'INSERT': b'HIAINS01', 'LOOKUP': b'HIACTL01', 'OBSERVE': b'HIACTO01',
                 'RESOLVED': b'HIACTO02'}
    code = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(int.from_bytes(constants[match.group()], 'little')), POLICY)
    shared = artifact_policy()
    for name in ('artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri',
                 'input_word', 'valid_hex', 'put', 'copy_input', 'query_header', 'query_field',
                 'unique_summary', 'row_header', 'row_text', 'matches'):
        signature = '\ndef ' + name + '('
        start = shared.index(signature)
        end = shared.find('\ndef ', start + len(signature))
        code += shared[start:end if end != -1 else len(shared)] + '\n'
    return code + RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')]


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
