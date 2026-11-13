"""Author the retained HIA slot/version/lease ledger, not SQL or proof adapters."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIASLQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIASLT01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLR01', 'little')
PREFIX = 4096
MAX_ABI = 8 << 20

CORE = r'''
def ledger_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 256 or length(s) > 8392960 or length(w) < 4096 or length(w) > 8392704 or length(o) < 32:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or valid_frame(s) == 0:
        return invalid(o, 16)
    if read_word(s, 120) >= 8 and read_word(s, 120) <= 11:
        return direct_main(s, o, w)
    if read_word(s, 8) == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0 or binding_matches(s, w) == 0:
        return invalid(o, 16)
    event = read_word(s, 8)
    if read_word(s, 144) != 0 or read_word(s, 152) != 0:
        return answer(o, w, 16)
    if event == 90:
        if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 136) != 0:
            return answer(o, w, 16)
        return answer(o, w, 0)
    if read_word(s, 16) != get(w, 2) or get(w, 2) == 18446744073709551615:
        return answer(o, w, 18)
    if event == 4:
        return commit_ack(s, o, w)
    if event == 5:
        if get(w, 3) != 2 or read_word(s, 24) == 0 or read_word(s, 24) != get(w, 6) or read_word(s, 136) != 0 or read_word(s, 128) > 1:
            return answer(o, w, 16)
        if read_word(s, 128) == 1 and get(w, 5) == 4 and get(w, 37) == 0:
            return refusal(o, w, 21)
        return refusal(o, w, 17)
    if read_word(s, 24) == 0 or read_word(s, 24) != get(w, 6):
        return answer(o, w, 16)
    if event == 2:
        if get(w, 3) != 1 or read_word(s, 128) != 0 or read_word(s, 136) != 0:
            return answer(o, w, 16)
        set(w, 3, 2)
        set(w, 36, get(w, 36) + 1)
        action = get(w, 5)
        if action == 6 or action == 7 or action == 8 or action == 9 or action == 14 or action == 15:
            set(w, 37, get(w, 37) + 1)
        return advance(o, w, 0)
    if event == 3:
        if get(w, 3) != 2 or read_word(s, 128) > 1:
            return answer(o, w, 16)
        return outcome(s, o, w)
    return answer(o, w, 16)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 136) != 11 or read_word(s, 128) != 0:
        return invalid(o, 16)
    if read_word(s, 120) < 1 or read_word(s, 120) > 7 or scope_valid(s) == 0:
        return invalid(o, 16)
    if read_word(s, 32) == 0 and read_word(s, 40) == 0:
        return invalid(o, 16)
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return invalid(o, 16)
    if read_word(s, 160) == 0 and read_word(s, 168) == 0:
        return invalid(o, 16)
    if field_size(s, 10) > 8388608 or field_size(s, 10) > length(w) - 4096:
        return invalid(o, 18)
    i = 0
    while i < 4096:
        if byte(w, i) != 0:
            return invalid(o, 16)
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, 1)
    set(w, 4, read_word(s, 120))
    i = 4
    while i < 15:
        set(w, i + 4, read_word(s, i * 8))
        i = i + 1
    set(w, 43, read_word(s, 160))
    set(w, 44, read_word(s, 168))
    set(w, 55, 4096)
    return admit_inputs(s, o, w)

def scope_valid(s:readbuf) -> u64:
    kind = read_word(s, 80)
    operation = read_word(s, 120)
    if kind > 3:
        return 0
    if kind == 0:
        if read_word(s, 64) != read_word(s, 48) or read_word(s, 72) != read_word(s, 56):
            return 0
        if read_word(s, 88) != 0 or read_word(s, 96) != 0 or read_word(s, 104) != 0 or read_word(s, 112) != 0:
            return 0
    else:
        if read_word(s, 88) == 0 or (read_word(s, 96) == 0 and read_word(s, 104) == 0):
            return 0
        if kind == 1:
            if read_word(s, 64) != read_word(s, 48) or read_word(s, 72) != read_word(s, 56) or read_word(s, 112) != 0:
                return 0
        elif read_word(s, 112) == 0:
            return 0
    if (operation == 2 or operation == 3) and kind != 2:
        return 0
    if (operation == 4 or operation == 6 or operation == 9 or operation == 11) and kind != 1:
        return 0
    return 1

def binding_matches(s:readbuf, w:mutbuf) -> u64:
    i = 4
    while i < 15:
        if read_word(s, i * 8) != get(w, i + 4):
            return 0
        i = i + 1
    if read_word(s, 120) != get(w, 4) or read_word(s, 160) != get(w, 43) or read_word(s, 168) != get(w, 44):
        return 0
    return 1

def admit_inputs(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    operation = get(w, 4)
    mask = 1
    if operation == 2:
        mask = 1087
    elif operation == 3:
        mask = 79
    elif operation == 5 or operation == 6:
        mask = 897
    elif operation == 7:
        mask = 13
    index = 0
    while index < 11:
        if ((mask >> index) & 1) == 0 and field_tag(s, index) != 0:
            return refusal(o, w, 16)
        index = index + 1
    if operation == 3:
        if string_field(s, 6, 20) == 0 or decimal_valid(s, field_data(s, 6), field_size(s, 6)) == 0:
            return refusal(o, w, 3)
        set(w, 28, decimal_value(s, field_data(s, 6), field_size(s, 6)))
    if operation == 5 or operation == 6:
        if read_word(s, 144) != 31 or read_word(s, 152) != 4:
            return refusal(o, w, 11)
        if string_field(s, 7, 192) == 0 or string_field(s, 8, 20) == 0 or reference_field(s, 9) == 0:
            return refusal(o, w, 10)
        if decimal_valid(s, field_data(s, 8), field_size(s, 8)) == 0:
            return refusal(o, w, 10)
        set(w, 35, decimal_value(s, field_data(s, 8), field_size(s, 8)))
        copy_field(s, 9, w, 1440)
    if string_field(s, 0, 192) == 0:
        if operation == 5 or operation == 6:
            return refusal(o, w, 10)
        return refusal(o, w, 12)
    set(w, 24, copy_field(s, 0, w, 512))
    if operation == 2 or operation == 3 or operation == 7:
        if string_field(s, 2, 20) == 0 or decimal_valid(s, field_data(s, 2), field_size(s, 2)) == 0:
            return refusal(o, w, 1)
        if string_field(s, 3, 20) == 0 or decimal_valid(s, field_data(s, 3), field_size(s, 3)) == 0:
            return refusal(o, w, 2)
        set(w, 26, decimal_value(s, field_data(s, 2), field_size(s, 2)))
        set(w, 27, decimal_value(s, field_data(s, 3), field_size(s, 3)))
        if read_word(s, 144) == 7 and read_word(s, 152) == 2:
            set(w, 57, 1)
    if operation == 2 or operation == 3:
        if string_field(s, 1, 192) == 0 or field_size(s, 1) == 0:
            return refusal(o, w, 20)
        set(w, 25, copy_field(s, 1, w, 704))
    if operation == 2:
        if reference_field(s, 4) == 0 or reference_field(s, 5) == 0 or field_tag(s, 10) != 4 or field_size(s, 10) == 0:
            return refusal(o, w, 20)
        copy_field(s, 4, w, 896)
        copy_field(s, 5, w, 1072)
        set(w, 56, copy_field(s, 10, w, 4096))
        set(w, 55, 4096 + get(w, 56))
    if operation == 5 or operation == 6:
        if string_field(s, 7, 192) == 0 or field_size(s, 7) == 0:
            return refusal(o, w, 10)
        set(w, 34, copy_field(s, 7, w, 1248))
    if operation == 5 or operation == 6:
        return stage(o, w, 13)
    return stage(o, w, 1)

def outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 5)
    if action == 1 or action == 10 or action == 18:
        return slot_outcome(s, o, w)
    if action == 2 or action == 11 or action == 12:
        return version_outcome(s, o, w)
    if action == 3:
        if read_word(s, 128) != 1 or read_word(s, 136) != 1 or integer_field(s, 0) == 0:
            return refusal(o, w, 20)
        set(w, 33, decimal_value(s, field_data(s, 0), field_size(s, 0)))
        return snapshot_ready(o, w)
    if action == 4:
        return native_outcome(s, o, w)
    if action == 5:
        return generation_outcome(s, o, w)
    if action == 13 or action == 16:
        return lease_outcome(s, o, w)
    if action == 17:
        return hash_outcome(s, o, w)
    return mutation_outcome(s, o, w)

def slot_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 5)
    if action == 1 and read_word(s, 128) == 0 and read_word(s, 136) == 0:
        return snapshot_ready(o, w)
    if read_word(s, 128) != 1 or read_word(s, 136) != 5 or valid_slot_row(s) == 0:
        return refusal(o, w, 20)
    if same_field(s, 0, w, 512, get(w, 24)) == 0:
        return refusal(o, w, 20)
    if action == 1:
        set(w, 20, 1)
        set(w, 23, copy_field(s, 1, w, 1616))
        set(w, 21, decimal_value(s, field_data(s, 2), field_size(s, 2)))
        set(w, 22, decimal_value(s, field_data(s, 3), field_size(s, 3)))
        copy_field(s, 4, w, 1808)
        return stage(o, w, 2)
    if action == 18:
        if slot_matches(s, w, get(w, 21), get(w, 22), 1616, get(w, 23), 1808) == 0:
            return refusal(o, w, 20)
        if get(w, 4) == 3:
            return stage(o, w, 17)
        if same_state(w, 1808, 2400, 64) == 0:
            return refusal(o, w, 7)
        return stage(o, w, 4)
    if get(w, 39) == 1:
        if slot_matches(s, w, 0, 0, 704, get(w, 25), 2400) == 0:
            return refusal(o, w, 20)
        return stage(o, w, 7)
    if get(w, 39) != 2 or slot_matches(s, w, get(w, 29), get(w, 30), 704, get(w, 25), 2400) == 0:
        return refusal(o, w, 20)
    return finish(o, w)

def valid_slot_row(s:readbuf) -> u64:
    if string_field(s, 0, 192) == 0 or string_field(s, 1, 192) == 0 or field_size(s, 1) == 0:
        return 0
    if string_field(s, 2, 20) == 0 or decimal_valid(s, field_data(s, 2), field_size(s, 2)) == 0:
        return 0
    if string_field(s, 3, 20) == 0 or decimal_valid(s, field_data(s, 3), field_size(s, 3)) == 0:
        return 0
    return digest_field(s, 4)

def slot_matches(s:readbuf, w:mutbuf, generation:u64, epoch:u64, context_at:u64, context_size:u64, abi_at:u64) -> u64:
    if decimal_value(s, field_data(s, 2), field_size(s, 2)) != generation or decimal_value(s, field_data(s, 3), field_size(s, 3)) != epoch:
        return 0
    if same_field(s, 1, w, context_at, context_size) == 0 or same_field(s, 4, w, abi_at, 64) == 0:
        return 0
    return 1

def snapshot_ready(o:mutbuf, w:mutbuf) -> u32:
    operation = get(w, 4)
    if operation == 1:
        return finish(o, w)
    if operation == 2 or operation == 3 or operation == 7:
        if get(w, 57) == 0 or get(w, 26) != get(w, 21) or get(w, 27) != get(w, 22):
            return refusal(o, w, 4)
    if operation == 7:
        return finish(o, w)
    if operation == 2:
        return stage(o, w, 17)
    if get(w, 20) == 0:
        return refusal(o, w, 5)
    if operation == 3:
        return stage(o, w, 12)
    if operation == 4:
        return stage(o, w, 4)
    return refusal(o, w, 16)

def version_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 5)
    if action == 12 and read_word(s, 128) == 0 and read_word(s, 136) == 0:
        return refusal(o, w, 6)
    if read_word(s, 128) != 1 or read_word(s, 136) != 1 or reference_field(s, 0) == 0:
        return refusal(o, w, 20)
    if action == 2:
        copy_field(s, 0, w, 1872)
        return stage(o, w, 3)
    if action == 12:
        copy_field(s, 0, w, 2048)
        return stage(o, w, 4)
    if get(w, 39) == 3:
        if same_field(s, 0, w, 1072, 176) == 0:
            return refusal(o, w, 20)
        return stage(o, w, 5)
    if get(w, 39) != 4 or same_field(s, 0, w, 896, 176) == 0:
        return refusal(o, w, 20)
    return stage(o, w, 9)

def native_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 128) != 1:
        return refusal(o, w, 20)
    operation = get(w, 4)
    if operation == 3:
        if read_word(s, 136) != 1 or field_tag(s, 0) != 4 or field_size(s, 0) == 0 or field_size(s, 0) > 8388608 or field_size(s, 0) > length(w) - 4096:
            return refusal(o, w, 20)
        set(w, 56, copy_field(s, 0, w, 4096))
        set(w, 55, 4096 + get(w, 56))
        return stage(o, w, 18)
    if operation == 2:
        if read_word(s, 136) != 0:
            return refusal(o, w, 16)
        if same_state(w, 1872 + 53, 1072 + 53, 64) == 0:
            return refusal(o, w, 8)
        return stage(o, w, 5)
    if operation == 4:
        if read_word(s, 136) != 1 or field_tag(s, 0) != 4 or field_size(s, 0) != 16:
            return refusal(o, w, 16)
        lease_identifier(s, field_data(s, 0), w)
        set(w, 29, get(w, 21))
        copy_state(w, 1872, 2224, 176)
        return stage(o, w, 14)
    return refusal(o, w, 16)

def hash_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 128) != 1 or read_word(s, 136) != 2 or digest_field(s, 0) == 0 or integer_field(s, 1) == 0:
        return refusal(o, w, 20)
    if decimal_value(s, field_data(s, 1), field_size(s, 1)) != get(w, 56):
        return refusal(o, w, 20)
    copy_field(s, 0, w, 2400)
    if get(w, 4) == 3:
        if same_state(w, 1808, 2400, 64) == 0:
            return refusal(o, w, 7)
        if get(w, 22) == 18446744073709551615:
            return refusal(o, w, 9)
        set(w, 29, get(w, 28))
        set(w, 30, get(w, 22) + 1)
        return stage(o, w, 9)
    if get(w, 20) == 0:
        set(w, 23, get(w, 25))
        copy_state(w, 704, 1616, get(w, 25))
        copy_state(w, 2400, 1808, 64)
        return stage(o, w, 6)
    return stage(o, w, 18)

def generation_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 128) == 1:
        if read_word(s, 136) != 1 or string_field(s, 0, 20) == 0 or decimal_valid(s, field_data(s, 0), field_size(s, 0)) == 0:
            return refusal(o, w, 20)
        if get(w, 32) == 18446744073709551615:
            return refusal(o, w, 18)
        value = decimal_value(s, field_data(s, 0), field_size(s, 0))
        if value > get(w, 31):
            set(w, 31, value)
        set(w, 32, get(w, 32) + 1)
        return advance(o, w, 0)
    if read_word(s, 136) != 0 or get(w, 32) == 0:
        return refusal(o, w, 20)
    if get(w, 31) == 18446744073709551615 or get(w, 22) == 18446744073709551615:
        return refusal(o, w, 9)
    set(w, 29, get(w, 31) + 1)
    set(w, 30, get(w, 22) + 1)
    return stage(o, w, 8)

def mutation_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 128) != 1 or read_word(s, 136) != 1 or integer_field(s, 0) == 0 or decimal_value(s, field_data(s, 0), field_size(s, 0)) != 1:
        return refusal(o, w, 20)
    action = get(w, 5)
    if action == 6:
        set(w, 39, 1)
        return stage(o, w, 10)
    if action == 7:
        set(w, 39, 3)
        return stage(o, w, 11)
    if action == 8:
        set(w, 39, 4)
        return stage(o, w, 11)
    if action == 9:
        set(w, 39, 2)
        return stage(o, w, 10)
    if action == 14 or action == 15:
        return stage(o, w, 16)
    return refusal(o, w, 16)

def lease_outcome(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 5) == 13 and read_word(s, 128) == 0 and read_word(s, 136) == 0:
        return refusal(o, w, 10)
    if read_word(s, 128) != 1 or read_word(s, 136) != 5 or string_field(s, 0, 192) == 0 or string_field(s, 1, 192) == 0 or string_field(s, 2, 20) == 0:
        return refusal(o, w, 20)
    if decimal_valid(s, field_data(s, 2), field_size(s, 2)) == 0 or reference_field(s, 3) == 0 or integer_field(s, 4) == 0:
        return refusal(o, w, 20)
    active = 1
    generation = get(w, 35)
    artifact = 1440
    if get(w, 4) == 4:
        generation = get(w, 29)
        artifact = 2224
    if get(w, 5) == 16 and get(w, 4) == 6:
        active = 0
    if same_field(s, 0, w, 1248, get(w, 34)) == 0 or same_field(s, 1, w, 512, get(w, 24)) == 0 or decimal_value(s, field_data(s, 2), field_size(s, 2)) != generation or decimal_value(s, field_data(s, 4), field_size(s, 4)) != active or same_field(s, 3, w, artifact, 176) == 0:
        if get(w, 5) == 13:
            return refusal(o, w, 10)
        return refusal(o, w, 20)
    set(w, 29, generation)
    copy_field(s, 3, w, 2224)
    if get(w, 4) == 6 and get(w, 5) == 13:
        return stage(o, w, 15)
    return finish(o, w)

def commit_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 3) != 3 or get(w, 14) != 1 or (get(w, 4) != 4 and get(w, 4) != 6):
        return answer(o, w, 16)
    if read_word(s, 24) != 0 or read_word(s, 128) != 1 or read_word(s, 136) != 1 or field_tag(s, 0) != 4 or field_size(s, 0) != 96:
        return answer(o, w, 16)
    at = field_data(s, 0)
    if read_word(s, at) != get(w, 43) or read_word(s, at + 8) != get(w, 44) or read_word(s, at + 16) != get(w, 15) or read_word(s, at + 24) != get(w, 16) or read_word(s, at + 32) != get(w, 17):
        return answer(o, w, 16)
    if read_word(s, at + 40) != 0 or read_word(s, at + 48) != 0 or read_word(s, at + 56) != 0 or read_word(s, at + 64) == get(w, 15) or read_word(s, at + 72) != 0 or read_word(s, at + 80) != 0 or read_word(s, at + 88) == 0:
        return answer(o, w, 16)
    set(w, 41, read_word(s, at + 88))
    set(w, 3, 4)
    return advance(o, w, 0)

def stage(o:mutbuf, w:mutbuf, action:u64) -> u32:
    set(w, 3, 1)
    set(w, 5, action)
    set(w, 6, get(w, 2) + 1)
    return advance(o, w, 0)

def finish(o:mutbuf, w:mutbuf) -> u32:
    phase = 4
    if get(w, 4) == 2 or get(w, 4) == 3 or get(w, 4) == 4 or get(w, 4) == 6:
        phase = 3
    set(w, 3, phase)
    set(w, 5, 0)
    set(w, 6, 0)
    return advance(o, w, 0)

def refusal(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 7, status)
    if status >= 16 and status <= 20:
        set(w, 3, 6)
    else:
        set(w, 3, 5)
        set(w, 5, 0)
        set(w, 6, 0)
    return advance(o, w, status)
'''

# Direct consumers retain original Python/SQLite objects as opaque handles. The
# finite number of handles bounds the protocol, not the length/type of a slot,
# row or lease field. Every branch and effect order below is executed by HIA.
DIRECT = r'''
def direct_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    event = read_word(s, 8)
    if event == 0:
        return direct_initialize(s, o, w)
    if direct_valid_state(w) == 0 or binding_matches(s, w) == 0:
        return invalid(o, 16)
    if read_word(s, 144) != 0 or read_word(s, 152) != 0:
        return answer(o, w, 16)
    if event == 90:
        if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 128) != 0 or read_word(s, 136) != 0:
            return answer(o, w, 16)
        return answer(o, w, 0)
    if read_word(s, 16) != get(w, 2) or get(w, 2) == 18446744073709551615:
        return answer(o, w, 18)
    if event == 4:
        return direct_commit(s, o, w)
    if read_word(s, 24) == 0 or read_word(s, 24) != get(w, 6):
        return answer(o, w, 16)
    if event == 2:
        if get(w, 3) != 1 or read_word(s, 128) != 0 or read_word(s, 136) != 0:
            return answer(o, w, 16)
        set(w, 3, 2)
        set(w, 36, get(w, 36) + 1)
        if get(w, 5) == 124 or get(w, 5) == 231:
            set(w, 37, get(w, 37) + 1)
        return advance(o, w, 0)
    if get(w, 3) != 2:
        return answer(o, w, 16)
    if event == 5:
        if read_word(s, 128) != 1 or read_word(s, 136) != 0:
            return answer(o, w, 16)
        direct_consumed(w)
        return refusal(o, w, 22)
    if event != 3 or read_word(s, 128) != 1 or read_word(s, 136) != 1 or field_tag(s, 0) != 4:
        return answer(o, w, 16)
    if get(w, 5) == 121:
        if field_size(s, 0) != 16:
            return answer(o, w, 16)
        lease_identifier(s, field_data(s, 0), w)
        set(w, 34, 0)
        return direct_stage(o, w, 122)
    if field_size(s, 0) != 8:
        return answer(o, w, 16)
    value = read_word(s, field_data(s, 0))
    action = get(w, 5)
    if action == 120 or action == 124 or action == 231 or action == 240 or action == 241:
        if value != 0:
            return answer(o, w, 16)
        direct_consumed(w)
        return direct_void(o, w)
    if action == 102 or action == 114 or action == 200 or action == 202 or action == 205 or action == 209 or action == 211 or action == 215 or action == 219 or action == 224:
        if value > 1:
            return answer(o, w, 16)
        direct_consumed(w)
        return direct_predicate(o, w, value)
    if value == 0 or get(w, 20) == 64 or value != get(w, 20) + 1:
        return answer(o, w, 16)
    direct_consumed(w)
    set(w, 21, get(w, 21) | (1 << (value - 1)))
    if action < 200:
        return direct_snapshot_outcome(o, w, value)
    return direct_lease_outcome(o, w, value)

def direct_initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 128) != 0 or read_word(s, 136) != 0 or read_word(s, 144) != 0 or read_word(s, 152) != 0 or scope_valid(s) == 0:
        return invalid(o, 16)
    if (read_word(s, 32) == 0 and read_word(s, 40) == 0) or (read_word(s, 48) == 0 and read_word(s, 56) == 0) or (read_word(s, 160) == 0 and read_word(s, 168) == 0):
        return invalid(o, 16)
    i = 0
    while i < 4096:
        if byte(w, i) != 0:
            return invalid(o, 16)
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 3)
    set(w, 2, 1)
    set(w, 4, read_word(s, 120))
    i = 4
    while i < 15:
        set(w, i + 4, read_word(s, i * 8))
        i = i + 1
    set(w, 43, read_word(s, 160))
    set(w, 44, read_word(s, 168))
    set(w, 55, 4096)
    set(w, 20, 1)
    set(w, 21, 1)
    if get(w, 4) == 8 or get(w, 4) == 9:
        return direct_stage(o, w, 100)
    return direct_stage(o, w, 200)

def direct_valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 3 or get(w, 2) == 0 or get(w, 3) < 1 or get(w, 3) > 6 or get(w, 4) < 8 or get(w, 4) > 11 or get(w, 7) > 22 or get(w, 55) != 4096 or get(w, 20) == 0 or get(w, 20) > 64:
        return 0
    if (get(w, 21) & 1) != 1 or (get(w, 20) < 64 and (get(w, 21) >> get(w, 20)) != 0):
        return 0
    if get(w, 6) > get(w, 2) or get(w, 36) > get(w, 2) or get(w, 37) > get(w, 36) or get(w, 14) > 3:
        return 0
    if get(w, 3) == 1 or get(w, 3) == 2:
        if get(w, 6) == 0 or get(w, 7) != 0:
            return 0
        action = get(w, 5)
        if action < 100 or action > 241 or (action > 114 and action < 120) or (action > 124 and action < 200) or (action > 231 and action < 240) or action == 212 or action == 216 or action == 220 or action == 225:
            return 0
        if get(w, 45) != direct_consume_mask(w, action) or (get(w, 45) & get(w, 21)) != get(w, 45):
            return 0
    elif get(w, 3) < 6:
        if get(w, 5) != 0 or get(w, 6) != 0 or get(w, 45) != 0:
            return 0
    i = 22
    while i < 36:
        if get(w, i) > get(w, 20):
            return 0
        if get(w, i) != 0 and (get(w, 21) & (1 << (get(w, i) - 1))) == 0:
            return 0
        i = i + 1
    if get(w, 19) != 0 or get(w, 38) != 0 or get(w, 39) != 0 or get(w, 40) > 3 or get(w, 42) != 0:
        return 0
    i = 46
    while i < 63:
        if i != 55 and get(w, i) != 0:
            return 0
        i = i + 1
    if checksum(w) != get(w, 63):
        return 0
    return 1

def direct_handle_bit(w:mutbuf, word:u64) -> u64:
    handle = get(w, word)
    if handle == 0 or handle > 64:
        return 0
    return 1 << (handle - 1)

def direct_consume_mask(w:mutbuf, action:u64) -> u64:
    if action == 101 or action == 105 or action == 107 or action == 208:
        return direct_handle_bit(w, 35)
    if action == 104 or action == 108 or action == 112 or action == 124 or action == 202 or action == 204 or action == 205 or action == 207 or action == 211 or action == 222 or action == 230:
        return direct_handle_bit(w, 33)
    if action == 215 or action == 219 or action == 224:
        return direct_handle_bit(w, 33) | direct_handle_bit(w, 34)
    if action == 240:
        return direct_handle_bit(w, 22) | direct_handle_bit(w, 23)
    if action == 241:
        return direct_handle_bit(w, 22)
    return 0

def direct_stage(o:mutbuf, w:mutbuf, action:u64) -> u32:
    set(w, 45, direct_consume_mask(w, action))
    return stage(o, w, action)

def direct_consumed(w:mutbuf) -> u64:
    mask = get(w, 45)
    set(w, 21, get(w, 21) ^ mask)
    i = 22
    while i < 36:
        if (direct_handle_bit(w, i) & mask) != 0:
            set(w, i, 0)
        i = i + 1
    set(w, 45, 0)
    return 0

def direct_capture(o:mutbuf, w:mutbuf, value:u64, target:u64, action:u64) -> u32:
    set(w, 20, value)
    set(w, target, value)
    return direct_stage(o, w, action)

def direct_done(o:mutbuf, w:mutbuf) -> u32:
    phase = 4
    if get(w, 4) == 9 or get(w, 4) == 11:
        phase = 3
    set(w, 3, phase)
    set(w, 5, 0)
    set(w, 6, 0)
    set(w, 45, 0)
    return advance(o, w, 0)

def direct_predicate(o:mutbuf, w:mutbuf, value:u64) -> u32:
    action = get(w, 5)
    if action == 102:
        if value == 1:
            if get(w, 4) == 9:
                return refusal(o, w, 5)
            set(w, 40, 1)
            return direct_done(o, w)
        return direct_stage(o, w, 103)
    if action == 114:
        if value == 1:
            return refusal(o, w, 5)
        return direct_stage(o, w, 120)
    if action == 200 or action == 202:
        if value == 0:
            return refusal(o, w, 11)
        return direct_stage(o, w, action + 1)
    if action == 205:
        if value == 1:
            return refusal(o, w, 11)
        return direct_stage(o, w, 206)
    if action == 209:
        if value == 1:
            return refusal(o, w, 10)
        return direct_stage(o, w, 210)
    if action == 211 or action == 215 or action == 219:
        if value == 1:
            return refusal(o, w, 10)
        return direct_stage(o, w, action + 2)
    if action == 224:
        if value == 1:
            return refusal(o, w, 10)
        return direct_stage(o, w, 226)
    return answer(o, w, 16)

def direct_snapshot_outcome(o:mutbuf, w:mutbuf, value:u64) -> u32:
    action = get(w, 5)
    if action == 100 or action == 104 or action == 106:
        return direct_capture(o, w, value, 35, action + 1)
    if action == 101:
        return direct_capture(o, w, value, 22, 102)
    if action == 103:
        return direct_capture(o, w, value, 33, 104)
    if action == 105:
        return direct_capture(o, w, value, 23, 106)
    if action == 107:
        return direct_capture(o, w, value, 33, 108)
    if action == 108:
        return direct_capture(o, w, value, 24, 109)
    if action == 109:
        return direct_capture(o, w, value, 25, 110)
    if action == 110:
        return direct_capture(o, w, value, 26, 111)
    if action == 111:
        return direct_capture(o, w, value, 33, 112)
    if action == 112:
        return direct_capture(o, w, value, 28, 113)
    if action == 113:
        set(w, 20, value)
        set(w, 27, value)
        set(w, 40, 2)
        return direct_stage(o, w, 240)
    if action == 122:
        return direct_capture(o, w, value, 29, 123)
    if action == 123:
        return direct_capture(o, w, value, 33, 124)
    return answer(o, w, 16)

def direct_lease_outcome(o:mutbuf, w:mutbuf, value:u64) -> u32:
    action = get(w, 5)
    if action == 201 or action == 203 or action == 204 or action == 206 or action == 210 or action == 213 or action == 217 or action == 221 or action == 222 or action == 229:
        return direct_capture(o, w, value, 33, action + 1)
    if action == 214 or action == 218 or action == 223:
        return direct_capture(o, w, value, 34, action + 1)
    if action == 207:
        return direct_capture(o, w, value, 35, 208)
    if action == 208:
        return direct_capture(o, w, value, 22, 209)
    if action == 226:
        return direct_capture(o, w, value, 29, 227)
    if action == 227:
        return direct_capture(o, w, value, 30, 228)
    if action == 228:
        return direct_capture(o, w, value, 31, 229)
    if action == 230:
        set(w, 20, value)
        set(w, 32, value)
        set(w, 40, 3)
        return direct_stage(o, w, 241)
    return answer(o, w, 16)

def direct_void(o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 5)
    if action == 120:
        return direct_stage(o, w, 121)
    if action == 124:
        set(w, 30, 1)
        set(w, 31, get(w, 25))
        set(w, 32, get(w, 28))
        set(w, 40, 3)
        return direct_done(o, w)
    if action == 240:
        if get(w, 4) == 9:
            return direct_stage(o, w, 114)
        return direct_done(o, w)
    if action == 241:
        if get(w, 4) == 11:
            return direct_stage(o, w, 231)
        return direct_done(o, w)
    if action == 231:
        return direct_done(o, w)
    return answer(o, w, 16)

def direct_commit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 3) != 3 or get(w, 14) != 1 or (get(w, 4) != 9 and get(w, 4) != 11):
        return answer(o, w, 16)
    if read_word(s, 24) != 0 or read_word(s, 128) != 1 or read_word(s, 136) != 1 or field_tag(s, 0) != 4 or field_size(s, 0) != 96:
        return answer(o, w, 16)
    at = field_data(s, 0)
    if read_word(s, at) != get(w, 43) or read_word(s, at + 8) != get(w, 44) or read_word(s, at + 16) != get(w, 15) or read_word(s, at + 24) != get(w, 16) or read_word(s, at + 32) != get(w, 17):
        return answer(o, w, 16)
    if read_word(s, at + 40) != 0 or read_word(s, at + 48) != 0 or read_word(s, at + 56) != 0 or read_word(s, at + 64) == get(w, 15) or read_word(s, at + 72) != 0 or read_word(s, at + 80) != 0 or read_word(s, at + 88) == 0:
        return answer(o, w, 16)
    set(w, 41, read_word(s, at + 88))
    set(w, 3, 4)
    return advance(o, w, 0)
'''

HELPERS = r'''
def valid_frame(s:readbuf) -> u64:
    count = read_word(s, 136)
    if count > 11:
        return 0
    i = 22
    while i < 32:
        if read_word(s, i * 8) != 0:
            return 0
        i = i + 1
    at = 256
    i = 0
    while i < count:
        if at > length(s) or length(s) - at < 16:
            return 0
        size = read_word(s, at + 8)
        if read_word(s, at) > 4 or size > length(s) - at - 16 or (read_word(s, at) == 0 and size != 0):
            return 0
        at = at + 16 + size
        i = i + 1
    if at != length(s):
        return 0
    return 1

def field_at(s:readbuf, field:u64) -> u64:
    at = 256
    i = 0
    while i < field:
        at = at + 16 + read_word(s, at + 8)
        i = i + 1
    return at

def field_tag(s:readbuf, field:u64) -> u64:
    return read_word(s, field_at(s, field))

def field_size(s:readbuf, field:u64) -> u64:
    return read_word(s, field_at(s, field) + 8)

def field_data(s:readbuf, field:u64) -> u64:
    return field_at(s, field) + 16

def string_field(s:readbuf, field:u64, maximum:u64) -> u64:
    if field_tag(s, field) != 1 or field_size(s, field) > maximum:
        return 0
    return 1

def integer_field(s:readbuf, field:u64) -> u64:
    if field_tag(s, field) != 3:
        return 0
    return decimal_valid(s, field_data(s, field), field_size(s, field))

def decimal_valid(s:readbuf, at:u64, size:u64) -> u64:
    if size == 0 or size > 20 or (size > 1 and byte(s, at) == 48):
        return 0
    value = 0
    i = 0
    while i < size:
        digit = byte(s, at + i)
        if digit < 48 or digit > 57:
            return 0
        digit = digit - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 0
        value = value * 10 + digit
        i = i + 1
    return 1

def decimal_value(s:readbuf, at:u64, size:u64) -> u64:
    value = 0
    i = 0
    while i < size:
        value = value * 10 + byte(s, at + i) - 48
        i = i + 1
    return value

def digest_field(s:readbuf, field:u64) -> u64:
    if field_tag(s, field) != 1 or field_size(s, field) != 64:
        return 0
    return hex_bytes(s, field_data(s, field), 64)

def hex_bytes(s:readbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        value = byte(s, at + i)
        if value < 48 or value > 102 or (value > 57 and value < 97):
            return 0
        i = i + 1
    return 1

def lease_identifier(s:readbuf, at:u64, w:mutbuf) -> u64:
    prefix = @LEASE_PREFIX_LOW@
    i = 0
    while i < 6:
        store(w, 1248 + i, prefix >> (i * 8))
        i = i + 1
    i = 0
    while i < 16:
        value = byte(s, at + i)
        if i == 6:
            value = (value & 15) | 64
        elif i == 8:
            value = (value & 63) | 128
        store(w, 1254 + i * 2, hex_digit(value >> 4))
        store(w, 1255 + i * 2, hex_digit(value & 15))
        i = i + 1
    set(w, 34, 38)
    return 0

def hex_digit(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87

def reference_field(s:readbuf, field:u64) -> u64:
    if field_tag(s, field) != 2 or field_size(s, field) != 176:
        return 0
    at = field_data(s, field)
    if literal(s, at, 7, @REF_ID_LOW@, 0) == 0 or byte(s, at + 7) != 97 or byte(s, at + 8) != 45 or hex_bytes(s, at + 9, 32) == 0:
        return 0
    if literal(s, at + 41, 12, @REF_HASH_LOW@, @REF_HASH_HIGH@) == 0 or hex_bytes(s, at + 53, 64) == 0:
        return 0
    if literal(s, at + 117, 9, @REF_URI_LOW@, @REF_URI_HIGH@) == 0 or literal(s, at + 126, 16, @URI_PREFIX_LOW@, @URI_PREFIX_HIGH@) == 0 or hex_bytes(s, at + 142, 32) == 0:
        return 0
    if byte(s, at + 174) != 34 or byte(s, at + 175) != 125:
        return 0
    return 1

def literal(s:readbuf, at:u64, size:u64, low:u64, high:u64) -> u64:
    i = 0
    while i < size:
        value = low
        shift = i
        if i >= 8:
            value = high
            shift = i - 8
        if byte(s, at + i) != ((value >> (shift * 8)) & 255):
            return 0
        i = i + 1
    return 1

def copy_field(s:readbuf, field:u64, w:mutbuf, target:u64) -> u64:
    at = field_data(s, field)
    size = field_size(s, field)
    i = 0
    while i < size:
        store(w, target + i, byte(s, at + i))
        i = i + 1
    return size

def same_field(s:readbuf, field:u64, w:mutbuf, target:u64, size:u64) -> u64:
    if field_size(s, field) != size:
        return 0
    at = field_data(s, field)
    i = 0
    while i < size:
        if byte(s, at + i) != byte(w, target + i):
            return 0
        i = i + 1
    return 1

def same_state(w:mutbuf, first:u64, second:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(w, first + i) != byte(w, second + i):
            return 0
        i = i + 1
    return 1

def copy_state(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return size

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) == 0 or get(w, 3) < 1 or get(w, 3) > 6 or get(w, 4) < 1 or get(w, 4) > 7 or get(w, 5) > 18 or get(w, 7) > 21:
        return 0
    if get(w, 55) < 4096 or get(w, 55) > length(w) or get(w, 56) > 8388608 or get(w, 55) != 4096 + get(w, 56):
        return 0
    if get(w, 6) > get(w, 2) or get(w, 36) > get(w, 2) or get(w, 37) > get(w, 36) or get(w, 14) > 3 or get(w, 20) > 1:
        return 0
    if get(w, 23) > 192 or get(w, 24) > 192 or get(w, 25) > 192 or get(w, 34) > 192:
        return 0
    if get(w, 3) == 1 or get(w, 3) == 2:
        if get(w, 5) == 0 or get(w, 6) == 0 or get(w, 7) != 0:
            return 0
    elif get(w, 3) < 6:
        if get(w, 5) != 0 or get(w, 6) != 0:
            return 0
    if get(w, 19) != 0 or get(w, 38) != 0 or get(w, 40) != 0 or get(w, 42) != 0 or get(w, 57) > 1:
        return 0
    i = 45
    while i < 63:
        if (i < 55 or i > 57) and get(w, i) != 0:
            return 0
        i = i + 1
    if checksum(w) != get(w, 63):
        return 0
    return 1

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 63:
        value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    extent = get(w, 55)
    i = 512
    while i < extent:
        value = ((value << 7) | (value >> 57)) ^ byte(w, i)
        i = i + 1
    return value

def advance(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 2, get(w, 2) + 1)
    set(w, 63, checksum(w))
    return answer(o, w, status)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    size = get(w, 55)
    if length(o) < size + 32:
        return invalid(o, 16)
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 2))
    set(o, 3, size)
    i = 0
    while i < size:
        store(o, 32 + i, byte(w, i))
        i = i + 1
    return size + 32

def invalid(o:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, 0)
    set(o, 3, 0)
    return 32

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''


def source_program():
    values = {'REQUEST_MAGIC': REQUEST_MAGIC, 'STATE_MAGIC': STATE_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC}
    for name, raw in (('REF_ID', b'{"id":"'), ('REF_HASH', b'","sha256":"'),
                      ('REF_URI', b'","uri":"'), ('URI_PREFIX', b'hia://artifacts/'),
                      ('LEASE_PREFIX', b'lease-')):
        values[name + '_LOW'] = int.from_bytes(raw[:8], 'little')
        values[name + '_HIGH'] = int.from_bytes(raw[8:], 'little')
    source = CORE + DIRECT + HELPERS
    for name, value in values.items():
        source = source.replace('@' + name + '@', str(value))
    return source


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'slot_ledger', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/slot_ledger.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
