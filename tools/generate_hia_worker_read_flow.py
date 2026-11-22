"""Author Read's ordinary Worker entry using the shared HIA descriptor actions."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_read_capsule import ROLES
from tools.generate_hia_worker_describe_flow import POLICY, program as worker_program
from tools.generate_hia_worker_describe_reactor import POLICY as ENTRY_POLICY
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_read_flow.hepta')

ENTRY = r'''
def admit_entry(s:readbuf, o:mutbuf) -> u64:
    if length(s) != ENTRY_HEAD + DOSSIER_HEAD + ROLE_COUNT * DESCRIPTOR_BYTES:
        return BAD
    size = input_word(s, 8)
    dossier = input_word(s, 16)
    dossier_fd = input_word(s, 32)
    if size < 2 or size > 8388608 or dossier < DOSSIER_HEAD or dossier > 1048576:
        return BAD
    if input_word(s, 24) != 0 or input_word(s, 40) != 0 or input_word(s, 56) != 0:
        return BAD
    if valid_fd(dossier_fd) == False or input_word(s, 48) != 15:
        return BAD
    if dossier_identity(s, dossier) == False or trusted_descriptors(s, dossier_fd, 0) == False:
        return BAD
    put(o, 32, input_word(s, ENTRY_HEAD + 24))
    put(o, 40, input_word(s, ENTRY_HEAD + 32))
    put(o, 48, input_word(s, ENTRY_HEAD + 40))
    put(o, 56, input_word(s, ENTRY_HEAD + 8))
    put(o, 64, input_word(s, ENTRY_HEAD + 16))
    copy_span(s, o, ENTRY_HEAD + 56, 88, 256)
    return 344
'''

READ = r'''
def discovery_flow(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == AFTER_PLAN:
        size = input_word(s, 40)
        if size < 128 or size > 8192 or length(s) < 72 or input_word(s, 64) != PLAN_MAGIC:
            return BAD
        observe_slot(s, w, PLAN_FD)
        return read_span(o, w, AFTER_PLAN_PIN, slot_fd(w, PLAN_FD), 64, 64)
    if state == AFTER_PLAN_PIN:
        if length(s) != 128 or input_word(s, 40) != slot_bytes(w, PLAN_FD):
            return BAD
        copy_span(s, w, 64, PLAN_PIN, 64)
        return next_journal(o, w, 11)
    if state == AFTER_QUERY:
        size = input_word(s, 40)
        if size < 48 or length(s) < 112 or input_word(s, 64) != EFFECT_MAGIC:
            return BAD
        if input_word(s, 104) != size - 48:
            return BAD
        if input_word(s, 72) == 0:
            observe_slot(s, w, EFFECT_FD)
            put(w, 96, 1)
            return next_journal(o, w, 13)
        put(o, HEADER, READ_ERROR)
        fragment(o, 0, input_word(s, 32), 0, size)
        return issue(o, w, AFTER_REFUSAL, RUN, 4, 0, 1, 8)
    if state == AFTER_REFUSAL:
        observe_slot(s, w, EFFECT_FD)
        put(w, 96, 2)
        return next_journal(o, w, 14)
    return BAD

def journal_binding(o:mutbuf, w:mutbuf, at:u64) -> u64:
    put(o, at, 66)
    put(o, at + 8, 66)
    put(o, at + 16, 0)
    store(o, at + 24, 34)
    copy_private(w, o, PLAN_PIN, at + 25, 64)
    store(o, at + 89, 34)
    store(o, at + 90, 34)
    copy_private(w, o, TRUST, at + 91, 64)
    store(o, at + 155, 34)
    return 156

def launch_effect(o:mutbuf, w:mutbuf) -> u64:
    whole_slot(w, o, PLAN_FD, 0)
    put(o, 160, OWN_STORE_PREFIX)
    put(o, 168, OWN_STORE_SUFFIX)
    argv(o, 0, LITERAL_ARG, 160)
    launch_directory(w, o, 1)
    role = 0
    while role < 8:
        role_argument(w, o, 3 + role, 7 + role)
        role = role + 1
    return issue(o, w, AFTER_QUERY, RUN, 6, 11, 1, 0)
'''


def program():
    variants = {name: int.from_bytes(value, 'little') for name, value in {
        'PLAN_MAGIC': b'HIAARD01', 'EFFECT_MAGIC': b'HIAFDO01', 'READ_ERROR': b'HIAJWE01',
        'OWN_STORE_PREFIX': b'--own-st', 'OWN_STORE_SUFFIX': b'ore',
    }.items()}
    variants.update(ROLE_COUNT=len(ROLES), DESCRIPTOR_BYTES=40, ELF_MAGIC=0x464c457f,
                    PLAN_PIN=768, AFTER_PLAN_PIN=7, SCHEMA_ROLE=3, EFFECT_PREFIX=48)
    read_functions = {'discovery_flow', 'journal_binding', 'launch_effect'}
    retained = re.split(r'(?=\ndef )', POLICY)
    policy = '\n'.join(block for block in retained
                       if not any(block.startswith('\ndef ' + name + '(')
                                  for name in (*read_functions, 'observe_discovery'))) + READ
    return worker_program(policy=policy, variants=variants, control_overrides={
        'admit_entry': ENTRY,
        'trusted_descriptors': function(ENTRY_POLICY, 'trusted_descriptors'),
    })


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
