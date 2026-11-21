"""Author atomic context and execution-budget Store bindings."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY
from tools.generate_hia_worker_artifact_authority import source_program as artifact_policy

SOURCE = Path('examples/hia_bootstrap/worker_context_store.hepta')

POLICY = r'''
def context_store(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 208 or length(o) < 640 or input_word(s, 0) != CREATE:
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
    constants = {'CREATE': b'HIACTS01', 'BINDINGS': b'HIACTB01', 'INSERT': b'HIAINS01'}
    code = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(int.from_bytes(constants[match.group()], 'little')), POLICY)
    shared = artifact_policy()
    for name in ('artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri',
                 'input_word', 'valid_hex', 'put', 'copy_input'):
        signature = '\ndef ' + name + '('
        start = shared.index(signature)
        end = shared.find('\ndef ', start + len(signature))
        code += shared[start:end if end != -1 else len(shared)] + '\n'
    return code + RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')]


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
