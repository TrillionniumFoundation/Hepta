"""Author the native immutable-input profile binding and artifact result."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_effect import source_program as document_effect
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY

SOURCE = 'examples/hia_bootstrap/worker_artifact_authority.hepta'

POLICY = r'''
def artifact_authority(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 512:
        return 4294967293
    mode = input_word(s, 0)
    if mode == PROFILE_QUERY:
        if length(s) != 72 or valid_hex(s, 8, 64) == False:
            return 4294967293
        return profile_query(s, o)
    if mode == PROFILE_OBSERVE:
        return profile_observation(s, o)
    if mode == ARTIFACT_OBSERVE:
        return artifact_observation(s, o)
    if mode == INPUT_RESULT:
        return receipt(s, o)
    return 4294967293

def profile_query(s:readbuf, o:mutbuf) -> u64:
    query_header(o, 0, 2, 159)
    query_field(o, 32, 80, 15)
    query_field(o, 56, 95, 64)
    put(o, 80, PROFILE_HEAD)
    put(o, 88, PROFILE_END)
    return copy_input(s, o, 8, 95, 64)

def profile_observation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 144 or valid_hex(s, 32, 64) == False:
        return 4294967293
    size = input_word(s, 8)
    if size != length(s) - 144 or unique_summary(s, 96 + size, size) == False:
        return 4294967293
    if size == 0:
        return 4294967289
    if size != 359 or row_header(s, 96, 2, 3) == False:
        return 4294967293
    if row_text(s, 128, 104, 15) == False or row_text(s, 152, 119, 64) == False:
        return 4294967293
    if row_text(s, 176, 183, 176) == False or artifact_reference(s, 279) == False:
        return 4294967293
    if input_word(s, 200) != PROFILE_HEAD or (input_word(s, 208) & 72057594037927935) != PROFILE_END:
        return 4294967293
    if matches(s, 215, 32, 64) == False or matches(s, 332, 32, 64) == False:
        return 4294967293
    put(o, 0, PROFILE_REF)
    put(o, 8, 176)
    copy_input(s, o, 279, 16, 176)
    query_header(o, 192, 1, 90)
    query_field(o, 224, 56, 34)
    return copy_input(s, o, 286, 248, 34)

def artifact_observation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 256 or artifact_reference(s, 32) == False:
        return 4294967293
    size = input_word(s, 8)
    if size != length(s) - 256 or unique_summary(s, 208 + size, size) == False:
        return 4294967293
    if size == 0:
        return 4294967288
    if size < 393 or size > 16777216 or row_header(s, 208, 1, 6) == False:
        return 4294967293
    if row_text(s, 240, 176, 34) == False or row_text(s, 264, 210, 64) == False:
        return 4294967293
    if row_text(s, 288, 274, 48) == False or row_text(s, 312, 322, 7) == False:
        return 4294967293
    metadata = size - 393
    if row_text(s, 336, 329, metadata) == False or row_text(s, 360, 329 + metadata, 64) == False:
        return 4294967293
    if profile_text(s, 530) == False or valid_hex(s, 208 + size - 64, 64) == False:
        return 4294967293
    if matches(s, 384, 39, 34) == False or matches(s, 418, 85, 64) == False or matches(s, 482, 158, 48) == False:
        return 4294967288
    put(o, 0, PROFILE_READ)
    return copy_input(s, o, 85, 8, 64)

def unique_summary(s:readbuf, at:u64, size:u64) -> bool:
    if input_word(s, at) != 5 or input_word(s, at + 8) != size or input_word(s, at + 24) != 0:
        return False
    if input_word(s, at + 16) != choose(size == 0, 0, 1):
        return False
    return input_word(s, at + 32) == input_word(s, 16) and input_word(s, at + 40) == input_word(s, 24)

def row_header(s:readbuf, at:u64, table:u64, count:u64) -> bool:
    return input_word(s, at) == ROW and input_word(s, at + 8) == 1 and input_word(s, at + 16) == table and input_word(s, at + 24) == count

def row_text(s:readbuf, at:u64, offset:u64, size:u64) -> bool:
    return input_word(s, at) == 3 and input_word(s, at + 8) == offset and input_word(s, at + 16) == size

def artifact_reference(s:readbuf, at:u64) -> bool:
    if artifact_start(s, at) == False or artifact_digest(s, at + 41) == False or artifact_uri(s, at + 117) == False:
        return False
    if valid_hex(s, at + 9, 32) == False or valid_hex(s, at + 53, 64) == False:
        return False
    return valid_hex(s, at + 142, 32) and byte(s, at + 174) == 34 and byte(s, at + 175) == 125

def matches(s:readbuf, left:u64, right:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, left + index) != byte(s, right + index):
            return False
        index = index + 1
    return True

def query_header(o:mutbuf, at:u64, count:u64, size:u64) -> u64:
    put(o, at, QUERY)
    put(o, at + 8, 1)
    put(o, at + 16, count)
    return put(o, at + 24, size)

def query_field(o:mutbuf, at:u64, offset:u64, size:u64) -> u64:
    put(o, at, 3)
    put(o, at + 8, offset)
    return put(o, at + 16, size)

def receipt(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 216 or input_word(s, 16) != DOCUMENT or input_word(s, 24) != 176 or input_word(s, 32) != 0:
        return 4294967293
    size = input_word(s, 8)
    if size > 8388608 or artifact_reference(s, 40) == False:
        return 4294967293
    at = result_open(o, 0)
    at = copy_input(s, o, 40, at, 176)
    at = result_size(o, at)
    at = decimal(o, at, size)
    return result_end(o, at)
'''


def source_program():
    tags = {
        'PROFILE_QUERY': b'HIARPF01', 'PROFILE_OBSERVE': b'HIARPF02',
        'ARTIFACT_OBSERVE': b'HIARPF03', 'INPUT_RESULT': b'HIARPF04',
        'PROFILE_REF': b'HIARPO01', 'PROFILE_READ': b'HIARPO02',
        'QUERY': b'HIAQPA01', 'ROW': b'HIAROW01', 'DOCUMENT': b'HIADOC01',
        'PROFILE_HEAD': b'hia-arti', 'PROFILE_END': b'fact-v1',
    }
    program = re.sub(r'\b(' + '|'.join(tags) + r')\b',
                     lambda match: str(int.from_bytes(tags[match.group()], 'little')), POLICY)
    shared = document_effect()
    for name in ('copy_input', 'valid_hex', 'input_word', 'state_put', 'profile_text'):
        definition = '\ndef ' + name + '('
        start = shared.index(definition)
        end = shared.find('\ndef ', start + len(definition))
        program += shared[start:end if end != -1 else len(shared)] + '\n'
    program += RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')]
    program = program.replace('state_put(', 'put(')
    for name, raw in (
        ('artifact_start', b'{"id":"a-'), ('artifact_digest', b'","sha256":"'),
        ('artifact_uri', b'","uri":"hia://artifacts/'),
    ):
        program += f'\ndef {name}(s:readbuf, at:u64) -> bool:\n'
        program += '    return ' + ' and '.join(
            f'byte(s, at + {offset}) == {byte}' for offset, byte in enumerate(raw)) + '\n'
    for name, raw in (
        ('result_open', b'{"artifact":'), ('result_size', b',"byte_length":"'),
        ('result_end', b'","content_admitted_as_program":false,"execution_authority_granted":false}'),
    ):
        program += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for offset, byte in enumerate(raw):
            program += f'    store(o, at + {offset}, {byte})\n'
        program += f'    return at + {len(raw)}\n'
    return program


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'worker_artifact_authority')),
                            encoding='utf-8')
