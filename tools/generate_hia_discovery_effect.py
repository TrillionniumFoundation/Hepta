"""Author the native observation/commit reactor for immutable Agent artifacts."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_discovery_native import PROFILE_NAMES, VERSIONS
from tools.generate_hia_artifact_publication import document

SOURCE = 'examples/hia_bootstrap/discovery_effect.hepta'
POLICY = r'''
def discovery_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or length(w) != 32768 or length(o) < 512:
        return 4294967295
    if input_word(s, 0) != EVENT or input_word(s, 16) != state_word(w, 8) + 1:
        return 4294967295
    body = input_word(s, 32)
    if body != length(s) - 40:
        return 4294967295
    event = input_word(s, 8)
    extent = input_word(s, 24)
    phase = state_word(w, 0)
    if phase == 0:
        if event != 1 or body != 16:
            return 4294967295
        return start_document(s, o, w, extent)
    if phase != event:
        return 4294967295
    if event == 2 or event == 4:
        if extent != 0 or valid_hash_receipt(s, state_word(w, 24)) == False:
            return 4294967295
        if event == 2:
            copy_input(s, w, 51, 64, 64)
            return artifact_operation(o, w, 2, 3, LOOKUP)
        if equal_saved_digest(s, w, 51) == False:
            return 4294967295
        return artifact_operation(o, w, 4, 5, ISSUE)
    if event == 3:
        if extent != 0:
            return 4294967295
        return observe_lookup(s, o, w, body)
    if event == 5 or event == 7:
        if extent != 0 or valid_commit(s, body) == False:
            return 4294967295
        if event == 5:
            state_put(w, 48, input_word(s, 64))
            return artifact_operation(o, w, 2, 3, LOOKUP)
        return finish_document(o, w)
    if event == 6:
        if body != 0 or extent != state_word(w, 24):
            return 4294967295
        if state_word(w, 16) != 1:
            return finish_document(o, w)
        next_action(o, w, 6, 7, 0, 192)
        state_put(o, 48, PROFILE_PLAN)
        state_put(o, 56, state_word(w, 32))
        copy_state(w, o, 128, 64, 176)
        return 240
    return 4294967295

def start_document(s:readbuf, o:mutbuf, w:mutbuf, extent:u64) -> u64:
    kind = input_word(s, 40)
    version = input_word(s, 48)
    if kind < 1 or kind > 3 or extent > choose(kind == 3, 8388608, 1048576):
        return 4294967295
    if kind == 1:
        if version == 0 or version > MAX_PROFILE:
            return 4294967295
    elif version != 0:
        return 4294967295
    state_put(w, 16, kind)
    state_put(w, 24, extent)
    state_put(w, 32, version)
    return next_action(o, w, 1, 2, extent, 0)

def valid_hash_receipt(s:readbuf, extent:u64) -> bool:
    if length(s) < 128 or length(s) > 134:
        return False
    if hash_prefix(s, 40) == False or hash_count(s, 115) == False:
        return False
    if valid_hex(s, 51, 64) == False:
        return False
    end = length(s) - 2
    if byte(s, end) != 125 or byte(s, end + 1) != 10:
        return False
    at = 125
    if end - at > 1 and byte(s, at) == 48:
        return False
    value = 0
    while at < end:
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return False
        value = value * 10 + ch - 48
        at = at + 1
    return value == extent

def observe_lookup(s:readbuf, o:mutbuf, w:mutbuf, body:u64) -> u64:
    if body < 48:
        return 4294967295
    row = body - 48
    end = 40 + row
    if input_word(s, end) != 5 or input_word(s, end + 8) != row or input_word(s, end + 24) != 0:
        return 4294967295
    found = input_word(s, end + 16)
    if row == 0:
        attempts = state_word(w, 40)
        if found != 0 or attempts >= 3 or state_word(w, 48) != 0:
            return 4294967295
        state_put(w, 40, attempts + 1)
        return next_action(o, w, 3, 4, state_word(w, 24), 0)
    kind = state_word(w, 16)
    if found != 1 or valid_row(s, w, row, kind) == False:
        return 4294967295
    at = ref_prefix(w, 128)
    at = copy_input(s, w, 216, at, 34)
    at = ref_sha(w, at)
    at = copy_input(s, w, 250, at, 64)
    at = ref_uri(w, at)
    at = copy_input(s, w, 314, at, 48)
    ref_end(w, at)
    next_action(o, w, 5, 6, state_word(w, 24), 64)
    copy_state(w, o, 64, 48, 64)
    return 112

def valid_row(s:readbuf, w:mutbuf, size:u64, kind:u64) -> bool:
    name = choose(kind == 1, 7, choose(kind == 2, 9, 5))
    if size != 388 + name or input_word(s, 40) != ROW:
        return False
    if input_word(s, 48) != 1 or input_word(s, 56) != 1 or input_word(s, 64) != 6:
        return False
    offset = 176
    field = 0
    while field < 6:
        extent = choose(field == 0, 34, choose(field == 2, 48, choose(field == 3, name, choose(field == 4, 2, 64))))
        at = 72 + field * 24
        if input_word(s, at) != 3 or input_word(s, at + 8) != offset or input_word(s, at + 16) != extent:
            return False
        offset = offset + extent
        field = field + 1
    if byte(s, 216) != 97 or byte(s, 217) != 45 or valid_hex(s, 218, 32) == False:
        return False
    if equal_saved_digest(s, w, 250) == False:
        return False
    if uri_prefix(s, 314) == False or valid_hex(s, 330, 32) == False:
        return False
    if kind == 1:
        if profile_text(s, 362) == False:
            return False
    elif kind == 2:
        if discovery_text(s, 362) == False:
            return False
    elif input_text(s, 362) == False:
        return False
    if byte(s, 362 + name) != 123 or byte(s, 363 + name) != 125:
        return False
    return valid_hex(s, 364 + name, 64)

def valid_commit(s:readbuf, size:u64) -> bool:
    if size != 56 or input_word(s, 40) != COMMIT:
        return False
    if input_word(s, 48) != 5 or input_word(s, 56) != 8:
        return False
    return input_word(s, 64) <= 1 and input_word(s, 72) == 0 and input_word(s, 80) >= 2

def finish_document(o:mutbuf, w:mutbuf) -> u64:
    next_action(o, w, 7, 255, state_word(w, 32), 176)
    return copy_state(w, o, 128, 48, 176)

def artifact_operation(o:mutbuf, w:mutbuf, role:u64, phase:u64, tag:u64) -> u64:
    next_action(o, w, role, phase, 0, 80)
    state_put(o, 48, tag)
    state_put(o, 56, state_word(w, 16))
    return copy_state(w, o, 64, 64, 64)

def next_action(o:mutbuf, w:mutbuf, role:u64, phase:u64, extent:u64, tail:u64) -> u64:
    sequence = state_word(w, 8) + 1
    state_put(w, 0, phase)
    state_put(w, 8, sequence)
    state_put(o, 0, ACTION)
    state_put(o, 8, role)
    state_put(o, 16, sequence)
    state_put(o, 24, 0)
    state_put(o, 32, tail)
    state_put(o, 40, extent)
    return 48 + tail

def valid_hex(s:readbuf, at:u64, count:u64) -> bool:
    end = at + count
    while at < end:
        ch = byte(s, at)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        at = at + 1
    return True

def equal_saved_digest(s:readbuf, w:mutbuf, at:u64) -> bool:
    index = 0
    while index < 64:
        if byte(s, at + index) != byte(w, 64 + index):
            return False
        index = index + 1
    return True

def copy_input(s:readbuf, o:mutbuf, at:u64, out:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, out + index, byte(s, at + index))
        index = index + 1
    return out + size

def copy_state(w:mutbuf, o:mutbuf, at:u64, out:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, out + index, byte(w, at + index))
        index = index + 1
    return out + size

def input_word(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def state_word(w:mutbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(w, at + index) << (8 * index))
        index = index + 1
    return value

def state_put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0
'''


def source_program():
    tags = {
        'EVENT': b'HIAFDE01', 'ACTION': b'HIAFDA01', 'LOOKUP': b'HIADAL01', 'ISSUE': b'HIADAI01',
        'ROW': b'HIAROW01', 'COMMIT': b'HIASTCP1', 'PROFILE_PLAN': b'HIADPR01',
    }
    source = POLICY.replace('MAX_PROFILE', str(len(VERSIONS) + len(PROFILE_NAMES)))
    for name, tag in tags.items():
        source = source.replace(name, str(int.from_bytes(tag, 'little')))
    for name, raw in (
            ('hash_prefix', b'{"sha256":"'), ('hash_count', b'","bytes":'),
            ('uri_prefix', b'hia://artifacts/'), ('profile_text', b'profile'),
            ('discovery_text', b'discovery'), ('input_text', b'input')):
        source += f'\ndef {name}(s:readbuf, at:u64) -> bool:\n'
        source += '    return ' + ' and '.join(
            f'byte(s, at + {index}) == {value}' for index, value in enumerate(raw)) + '\n'
    for name, raw in (
            ('ref_prefix', b'{"id":"'), ('ref_sha', b'","sha256":"'), ('ref_uri', b'","uri":"'),
            ('ref_end', b'"}')):
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for index, value in enumerate(raw):
            source += f'    store(o, at + {index}, {value})\n'
        source += f'    return at + {len(raw)}\n'
    return source


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'discovery_effect')),
                            encoding='utf-8')
