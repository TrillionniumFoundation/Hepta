"""Author the HIA continuation for public immutable program inspection."""
import json
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_effect import source_program as discovery_policy
from tools.generate_hia_worker_artifact_authority import source_program as authority_policy

SOURCE = Path('examples/hia_bootstrap/worker_inspection_effect.hepta')

POLICY = r'''
# Adapt the existing Linux event pipe; all view/publish order stays here.
# Event1=admitted request, 2=Context authority, 3=program authority,
# 4=rendered document/object, 5=intermediate publication, 6=lowering
# metadata rendered, 7=final immutable inspection publication.
# Action1=resolve context, 2=resolve program, 3=render, 4=publish
# typed document, 5=render lowering view, 6=return, 7=reject.
def inspection_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or length(w) != 32768 or length(o) < 2048:
        return INVALID
    seq = input_word(s, 16)
    body = input_word(s, 32)
    if input_word(s, 0) != EVENT or seq != state_word(w, 8) + 1 or body != length(s) - 40:
        return INVALID
    event = input_word(s, 8)
    status = input_word(s, 24)
    phase = state_word(w, 0)
    if phase == 0:
        if event != 1 or status != 0:
            return INVALID
        return begin(s, o, w, body)
    if event != phase:
        return INVALID
    if event == 2:
        return after_context(o, w, status, body)
    if event == 3:
        return after_program(o, w, status, body)
    if event == 4:
        return after_view(s, o, w, status, body)
    if event == 5:
        return after_intermediate(s, o, w, status, body)
    if event == 6:
        if status != 0 or body != 64 or valid_hex(s, 40, 64) == False:
            return INVALID
        return publish(s, o, w, 5, 7)
    if event == 7:
        if status != 5 or valid_receipt(s, w, body) == False:
            return INVALID
        return result(s, o, w)
    return INVALID

def begin(s:readbuf, o:mutbuf, w:mutbuf, body:u64) -> u64:
    if body < 42 or body > 2600 or input_word(s, 40) != REQUEST:
        return INVALID
    view = input_word(s, 48)
    reason = input_word(s, 56)
    if view < 1 or view > 5 or reason > 2 or (reason == 2 and view != 4):
        return INVALID
    context_bytes = input_word(s, 64)
    if context_bytes < 2 or context_bytes > 320 or 40 + context_bytes > body:
        return INVALID
    program_size_at = 72 + context_bytes
    program_bytes = input_word(s, program_size_at)
    if program_bytes < 2 or program_bytes > 512 or 40 + context_bytes + program_bytes > body:
        return INVALID
    selectors_at = program_size_at + 8 + program_bytes
    selector_bytes = length(s) - selectors_at
    selector_count = choose(reason != 0 or view == 1 or view == 5, 0, choose(view == 4, 3, 2))
    if valid_selectors(s, selectors_at, selector_count, view == 4) == False:
        return INVALID
    state_put(w, 16, view)
    state_put(w, 24, reason)
    state_put(w, 32, program_bytes)
    state_put(w, 40, selector_bytes)
    state_put(w, 304, context_bytes)
    copy_input(s, w, 72, 3072, context_bytes)
    copy_input(s, w, program_size_at + 8, 512, program_bytes)
    copy_input(s, w, selectors_at, 1024, selector_bytes)
    action(o, w, 1, 2, 0, context_bytes)
    return copy_input(s, o, 72, 48, context_bytes)

def valid_selectors(s:readbuf, at:u64, count:u64, required:bool) -> bool:
    index = 0
    while index < count:
        if length(s) - at < 8:
            return False
        size = input_word(s, at)
        if size > 512 or size > length(s) - at - 8 or (required and size == 0):
            return False
        at = at + 8 + size
        index = index + 1
    return at == length(s)

def after_context(o:mutbuf, w:mutbuf, status:u64, size:u64) -> u64:
    if size != 0 or status > 6:
        return INVALID
    if status != 0:
        return refuse(o, w, status)
    # The lookup port admitted this exact canonical reference. A successful
    # Context observation is the only authority for its cost ledger column.
    if state_word(w, 304) != 121 or state_word(w, 3072 + 7) & 4294967295 != CONTEXT_PREFIX:
        return INVALID
    index = 4
    while index < 36:
        digit = byte(w, 3072 + 7 + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return INVALID
        index = index + 1
    state_put(w, 312, 36)
    width = state_word(w, 32)
    action(o, w, 2, 3, 0, width)
    return copy_state(w, o, 512, 48, width)

def after_program(o:mutbuf, w:mutbuf, status:u64, size:u64) -> u64:
    if size != 0 or status > 2:
        return INVALID
    if status == 1:
        return refuse(o, w, 5)
    if status == 2:
        return refuse(o, w, 7)
    # Cursor refusal follows actual Context lookup and Core admission even
    # when the saved selectors also lack required keys.
    reason = state_word(w, 24)
    if reason != 0:
        return refuse(o, w, 7 + reason)
    width = state_word(w, 40)
    action(o, w, 3, 4, state_word(w, 16), width)
    return copy_state(w, o, 1024, 48, width)

def after_view(s:readbuf, o:mutbuf, w:mutbuf, status:u64, body:u64) -> u64:
    view = state_word(w, 16)
    if status != 0:
        if body != 0:
            return INVALID
        if (view == 2 or view == 3) and status >= 4294967288 and status <= 4294967290:
            if view == 2 and status == 4294967290:
                return INVALID
            return refuse(o, w, 10 + status - 4294967288)
        if view == 4 and status >= 1 and status <= 3:
            return refuse(o, w, 12 + status)
        return INVALID
    if body != 64 or valid_hex(s, 40, 64) == False:
        return INVALID
    if view == 4 or view == 5:
        return publish(s, o, w, view + 2, 5)
    return publish(s, o, w, 5, 7)

def publish(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, phase:u64) -> u64:
    copy_input(s, w, 40, 48, 64)
    action(o, w, 4, phase, kind, 64)
    return copy_state(w, o, 48, 48, 64)

def after_intermediate(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, body:u64) -> u64:
    view = state_word(w, 16)
    if kind != view + 2 or valid_receipt(s, w, body) == False:
        return INVALID
    if view == 4:
        copy_input(s, w, 64, 128, 176)
        action(o, w, 4, 7, 5, 64)
        return copy_state(w, o, 48, 48, 64)
    action(o, w, 5, 6, 0, 176)
    return copy_input(s, o, 64, 48, 176)

def valid_receipt(s:readbuf, w:mutbuf, body:u64) -> bool:
    if body != 200 or input_word(s, 40) != DOCUMENT or input_word(s, 48) != 176 or input_word(s, 56) != 0:
        return False
    if artifact_reference(s, 64) == False:
        return False
    index = 0
    while index < 64:
        if byte(s, 117 + index) != byte(w, 48 + index):
            return False
        index = index + 1
    return True

def result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    program_bytes = state_word(w, 32)
    if program_bytes != 176:
        return INVALID
    at = result_open(o, 116)
    at = copy_state(w, o, 512, at, program_bytes)
    at = result_query(o, at)
    if state_word(w, 16) == 4:
        at = copy_state(w, o, 128, at, 176)
    else:
        at = result_null(o, at)
    at = result_view(o, at)
    at = copy_input(s, o, 64, at, 176)
    store(o, at, 125)
    return outcome(o, w, 6, 0, at + 1)

def refuse(o:mutbuf, w:mutbuf, code:u64) -> u64:
    end = rejection(o, code)
    if end == 0:
        return INVALID
    return outcome(o, w, 7, code, end)

# The body supplied to the existing response projector begins at byte 116.
# The preceding private bytes are a receipt for the cost projection only.
def outcome(o:mutbuf, w:mutbuf, role:u64, kind:u64, end:u64) -> u64:
    context = state_word(w, 312)
    state_put(o, 48, OUTCOME)
    state_put(o, 56, role - 5)
    state_put(o, 64, context)
    state_put(o, 72, end - 116)
    index = 0
    while index < 36:
        unit = 0
        if context == 36:
            unit = byte(w, 3072 + 7 + index)
        store(o, 80 + index, unit)
        index = index + 1
    action(o, w, role, 8, kind, end - 48)
    return end

def action(o:mutbuf, w:mutbuf, role:u64, phase:u64, kind:u64, size:u64) -> u64:
    seq = state_word(w, 8) + 1
    state_put(w, 0, phase)
    state_put(w, 8, seq)
    state_put(o, 0, ACTION)
    state_put(o, 8, role)
    state_put(o, 16, seq)
    state_put(o, 24, kind)
    state_put(o, 32, 0)
    return state_put(o, 40, size)
'''

ERRORS = (
    ('E_HIA_CONTEXT_IDENTITY', 'context is not a retained server record', 'context'),
    ('E_HIA_CONTEXT_STALE', 'context binds a different installed implementation', 'context'),
    ('E_HIA_PROFILE_STALE', 'profile is unavailable or differs from the installed implementation', 'admission'),
    ('E_HIA_PROFILE_AUTHORITY', 'profile does not resolve to a retained server record', 'admission'),
    ('E_HIA_ARTIFACT_IDENTITY', 'artifact reference was not issued in this runtime namespace', 'admission'),
    ('E_HIA_ARTIFACT_AUTHORITY', 'input bytes cannot impersonate a retained context', 'admission'),
    ('E_HIA_ARTIFACT_CORRUPT', 'artifact bytes no longer match their recorded digest', 'admission'),
    ('E_HIA_CURSOR', 'inspection returns an immutable artifact; paginate it through hia_read', 'admission'),
    ('E_HIA_SELECTOR', 'dependencies require function, block and output', 'admission'),
    ('E_HIA_SELECTOR', 'function view requires an exact function', 'admission'),
    ('E_HIA_SELECTOR', 'function is not in this program', 'admission'),
    ('E_HIA_SELECTOR', 'block is not in this function', 'admission'),
    ('E_HIA_REJECTED', 'E_HIA_QUERY: function not found', 'admission'),
    ('E_HIA_REJECTED', 'E_HIA_QUERY: block not found', 'admission'),
    ('E_HIA_REJECTED', 'E_HIA_QUERY: SSA output does not identify one instruction', 'admission'),
)


def literal(name, raw, *, fixed=None):
    # Compact long diagnostic literals into the same little-endian words as
    # the other Worker error producers.
    arg = ', at:u64' if fixed is None else ''
    base = 'at' if fixed is None else str(fixed)
    lines = [f'def {name}(o:mutbuf{arg}) -> u64:']
    for offset in range(0, len(raw), 8):
        chunk = raw[offset:offset+8]
        if len(chunk) == 8:
            lines.append(f'    state_put(o, {base} + {offset}, {int.from_bytes(chunk, "little")})')
        else:
            lines.extend(f'    store(o, {base} + {offset+i}, {byte})' for i, byte in enumerate(chunk))
    lines.append(f'    return {base} + {len(raw)}')
    return '\n'.join(lines)


def function(source, name):
    declaration = '\ndef ' + name + '('
    begin = source.index(declaration)
    end = source.find('\ndef ', begin + len(declaration))
    return source[begin:] if end == -1 else source[begin:end]


def source_program():
    tags = {'EVENT': b'HIAFDE01', 'ACTION': b'HIAINA01', 'REQUEST': b'HIAINR01', 'DOCUMENT': b'HIADOC01',
            'OUTCOME': b'HIAIND01', 'CONTEXT_PREFIX': b'ctx-'}
    constants = {name: int.from_bytes(value, 'little') for name, value in tags.items()}
    constants['INVALID'] = 4294967295
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    shared = discovery_policy()
    authority = authority_policy()
    dispatch = ['def rejection(o:mutbuf, code:u64) -> u64:']
    diagnostics = []
    for index, (code, message, phase) in enumerate(ERRORS, 1):
        dispatch.extend((f'    if code == {index}:', f'        return error_{index}(o)'))
        raw = json.dumps({'code': code, 'details_artifact': None, 'message': message, 'phase': phase,
                          'retry_action': 'correct_input'}, sort_keys=True, separators=(',', ':')).encode('ascii')
        diagnostics.append(literal(f'error_{index}', raw, fixed=116))
    dispatch.append('    return 0')
    parts = {'result_open': b'{"next_cursor":null,"program":', 'result_query': b',"query_artifact":',
             'result_null': b'null', 'result_view': b',"view_artifact":'}
    return '\n'.join((policy, *(function(shared, name) for name in (
        'input_word', 'state_word', 'state_put', 'copy_input', 'copy_state', 'valid_hex')),
        *(function(authority, name) for name in (
            'artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri')),
        *(literal(name, raw) for name, raw in parts.items()), '\n'.join(dispatch), *diagnostics))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
