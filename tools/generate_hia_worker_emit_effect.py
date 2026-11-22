"""Author native Emit ordering, publication custody and terminal authority."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_effect import source_program as discovery_policy
from tools.generate_hia_worker_artifact_authority import source_program as authority_policy
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_emit_effect.hepta')
# Action/feedback ordinals are fixed for the sealed descriptor relay.
STAGES = (
    'CONTEXT', 'BUDGET', 'BACKEND', 'PROGRAM', 'VERIFICATION', 'CODEGEN',
    'PLAN', 'PLAN_VERIFICATION', 'PLAN_BINDING', 'WINDOW', 'OBJECT', 'LINK',
    'BUILD_OBSERVATION', 'OBJECT_ARTIFACT', 'NATIVE_ARTIFACT', 'BUILD_RECORD',
    'BUILD_RECEIPT', 'RESULT', 'TERMINAL',
)

POLICY = r'''
# The relay may invoke only the phase authorized here and must report its
# matching sequence. It holds immutable descriptors, not phase policy.
def emit_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or length(o) < 2048 or length(w) != 32768:
        return INVALID
    event = input_word(s, 8)
    seq = input_word(s, 16)
    status = input_word(s, 24)
    size = input_word(s, 32)
    if input_word(s, 0) != EVENT or size != length(s) - 40 or seq != state_word(w, 8) + 1:
        return INVALID
    stage = state_word(w, 0)
    if stage == 0:
        if event != 1 or status != 0:
            return INVALID
        return begin(s, o, w)
    if event != stage or stage < CONTEXT or stage >= TERMINAL:
        return INVALID
    if status != 0:
        if status != 1 or stage >= OBJECT_ARTIFACT:
            return INVALID
        return terminal(s, o, w, 2, size)
    if stage == CONTEXT:
        return after_context(s, o, w, size)
    if stage == VERIFICATION:
        if size != 0:
            return INVALID
        return next_verification(o, w)
    if stage >= OBJECT:
        return after_build(s, o, w, stage, size)
    if size != 0:
        return INVALID
    if stage == PROGRAM:
        return next_verification(o, w)
    if stage == CODEGEN and state_word(w, 24) == 1:
        return action(o, w, WINDOW, 0, 0, 48)
    return action(o, w, stage + 1, 0, 0, 48)

# Only the prefix and exact Context reference are needed for the reactor.
# The full HIA-projected request remains a sealed relay descriptor.
def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 82 or input_word(s, 40) != REQUEST:
        return INVALID
    output = input_word(s, 48)
    codegen = input_word(s, 56)
    receipts = input_word(s, 64)
    extent = input_word(s, 72)
    if output < 1 or output > 2 or codegen < 1 or codegen > 2 or receipts > 16:
        return INVALID
    if extent < 2 or extent > 320 or extent != length(s) - 80:
        return INVALID
    state_put(w, 16, output)
    state_put(w, 24, codegen)
    state_put(w, 32, receipts)
    state_put(w, 40, 0)
    state_put(w, 48, extent)
    copy_input(s, w, 80, 512, extent)
    return action(o, w, CONTEXT, 0, 0, 48)

def after_context(s:readbuf, o:mutbuf, w:mutbuf, size:u64) -> u64:
    if size != 121 or state_word(w, 48) != 121 or input_word(s, 47) & 4294967295 != CONTEXT_PREFIX:
        return INVALID
    index = 0
    while index < 121:
        if byte(s, 40 + index) != byte(w, 512 + index):
            return INVALID
        index = index + 1
    index = 4
    while index < 36:
        digit = byte(s, 47 + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return INVALID
        index = index + 1
    state_put(w, 56, 36)
    return action(o, w, BUDGET, 0, 0, 48)

def next_verification(o:mutbuf, w:mutbuf) -> u64:
    index = state_word(w, 40)
    if index == state_word(w, 32):
        return action(o, w, CODEGEN, state_word(w, 24), 0, 48)
    state_put(w, 40, index + 1)
    return action(o, w, VERIFICATION, index, 0, 48)

def after_build(s:readbuf, o:mutbuf, w:mutbuf, stage:u64, size:u64) -> u64:
    if stage == OBJECT or stage == LINK or stage == BUILD_RECORD:
        return observe_digest(s, o, w, stage, size)
    if stage == BUILD_OBSERVATION:
        if size != 16 or input_word(s, 40) != VERIFIED or input_word(s, 48) != 0:
            return INVALID
        return publication_action(o, w, OBJECT_ARTIFACT, 128)
    if stage == OBJECT_ARTIFACT:
        if retained(s, w, size, 128) == False:
            return INVALID
        return publication_action(o, w, NATIVE_ARTIFACT, 192)
    if stage == NATIVE_ARTIFACT:
        if retained(s, w, size, 192) == False:
            return INVALID
        return action(o, w, BUILD_RECORD, state_word(w, 16), 0, 48)
    if stage == BUILD_RECEIPT:
        if retained(s, w, size, 256) == False:
            return INVALID
        return action(o, w, RESULT, state_word(w, 16), 0, 48)
    if stage == RESULT:
        return terminal(s, o, w, 1, size)
    return INVALID

def observe_digest(s:readbuf, o:mutbuf, w:mutbuf, stage:u64, size:u64) -> u64:
    if size != 64 or valid_hex(s, 40, 64) == False:
        return INVALID
    if stage == BUILD_RECORD:
        copy_input(s, w, 40, 256, 64)
        return publication_action(o, w, BUILD_RECEIPT, 256)
    if stage == OBJECT:
        copy_input(s, w, 40, 128, 64)
        if state_word(w, 16) == 2:
            return action(o, w, LINK, 0, 0, 48)
    copy_input(s, w, 40, 192, 64)
    return action(o, w, BUILD_OBSERVATION, state_word(w, 16), 0, 48)

def publication_action(o:mutbuf, w:mutbuf, stage:u64, digest:u64) -> u64:
    action(o, w, stage, 0, 64, 48)
    return copy_state(w, o, digest, 48, 64)

def retained(s:readbuf, w:mutbuf, size:u64, digest:u64) -> bool:
    if size != 200 or input_word(s, 40) != DOCUMENT or input_word(s, 48) != 176 or input_word(s, 56) != 0:
        return False
    if artifact_reference(s, 64) == False:
        return False
    index = 0
    while index < 64:
        if byte(s, 117 + index) != byte(w, digest + index):
            return False
        index = index + 1
    return True

def terminal(s:readbuf, o:mutbuf, w:mutbuf, status:u64, size:u64) -> u64:
    if size < 2 or size > length(o) - 116 or byte(s, 40) != 123 or byte(s, length(s) - 1) != 125:
        return INVALID
    context = state_word(w, 56)
    if status == 1 and context != 36:
        return INVALID
    action(o, w, TERMINAL, status, 68 + size, 48)
    state_put(o, 48, OUTCOME)
    state_put(o, 56, status)
    state_put(o, 64, context)
    state_put(o, 72, size)
    index = 0
    while index < 36:
        unit = 0
        if context == 36:
            unit = byte(w, 519 + index)
        store(o, 80 + index, unit)
        index = index + 1
    return copy_input(s, o, 40, 116, size)

def action(o:mutbuf, w:mutbuf, stage:u64, role:u64, size:u64, at:u64) -> u64:
    seq = state_word(w, 8) + 1
    state_put(w, 0, stage)
    state_put(w, 8, seq)
    state_put(o, 0, ACTION)
    state_put(o, 8, stage)
    state_put(o, 16, seq)
    state_put(o, 24, role)
    state_put(o, 32, 0)
    state_put(o, 40, size)
    return at
'''


def program():
    words = {name: ordinal for ordinal, name in enumerate(STAGES, 2)}
    tags = {'EVENT': b'HIAFDE01', 'REQUEST': b'HIAERQ01', 'ACTION': b'HIAEMA01',
            'DOCUMENT': b'HIADOC01', 'OUTCOME': b'HIAIND01', 'VERIFIED': b'HIABOR01',
            'CONTEXT_PREFIX': b'ctx-'}
    words.update((tag, int.from_bytes(raw, 'little')) for tag, raw in tags.items())
    words['INVALID'] = 4294967295
    policy = re.sub(r'\b('+'|'.join(words)+r')\b', lambda m: str(words[m[0]]), POLICY)
    existing = discovery_policy()
    authority = authority_policy()
    return '\n'.join((
        policy,
        *(function(existing, helper) for helper in ('state_word', 'state_put', 'input_word', 'copy_state', 'copy_input')),
        *(function(authority, helper) for helper in
          ('artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri', 'valid_hex')),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
