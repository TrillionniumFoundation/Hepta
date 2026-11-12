"""Author the bounded foreign-object JSON wire owner in HIA.

Python composes source; the executable requests each foreign observation and
owns graph admission, numeric/key policy, ordering, escaping and byte budgets.
The observer protocol is deliberately lazy, not a pre-serialized graph packet.
"""
from __future__ import annotations

import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import format_program

SOURCE_PATH = 'examples/hia_bootstrap/json_wire.hiaasm'
MAGIC = int.from_bytes(b'HIAWIR02', 'little')
CACHED_MAGIC = int.from_bytes(b'HIAWIR03', 'little')
KEY_SUMMARY_MAGIC = int.from_bytes(b'HIAWIR04', 'little')
# Header slots are part of the versioned continuation protocol. Arrays follow
# the fixed header; the last 8192 bytes are the independently authored printer.
FIELDS = {
    'MAGIC': MAGIC, 'CACHED_MAGIC': CACHED_MAGIC,
    'KEY_SUMMARY_MAGIC': KEY_SUMMARY_MAGIC, 'AWAIT': 8, 'SEQ': 16, 'PHASE': 24,
    'MAX': 32, 'BUDGET': 40, 'ASCII': 48, 'SORT': 56, 'RENDERER': 64,
    'ROOT': 72, 'NODES': 80, 'QUEUED': 88, 'SP': 96, 'ACTIVE': 104,
    'OUT': 112, 'H': 120, 'DEPTH': 128, 'KIND': 136, 'SIZE': 144,
    'A': 152, 'B': 160, 'INDEX': 168, 'KEY_COUNT': 176, 'HASH_SLOTS': 184,
    'REQ_H': 200, 'REQ_INDEX': 208, 'REQ_COUNT': 216, 'REQ_PART': 224,
    'STACK': 232, 'RECORDS': 240, 'TABLE': 248, 'TEMP_A': 256,
    'TEMP_B': 264, 'LIMB_BASE': 272, 'KEY_H': 280, 'KEY_KIND': 288,
    'KEY_HASH': 296, 'KEY_LEN': 304, 'PROBE': 312, 'KEY_TEXT': 320,
    'N_H': 328, 'N_KIND': 336, 'N_SIZE': 344, 'N_A': 352, 'N_B': 360,
    'N_ROLE': 368, 'N_TARGET': 376, 'N_RETURN': 384, 'N_COUNT': 392,
    'N_LIMBS': 400, 'N_INDEX': 408, 'N_LIMIT': 416, 'N_TEXT': 424,
    'T_H': 432, 'T_SIZE': 440, 'T_MODE': 448, 'T_POS': 456,
    'T_WIDTH': 464, 'T_COUNT': 472, 'T_TARGET': 480, 'T_RETURN': 488,
    'FRAMES': 496, 'FRAME_COUNT': 504, 'ENTRIES': 512, 'PREFIX': 520,
    'SORT_HEAD': 528, 'SORT_WIDTH': 536, 'SORT_P': 544, 'SORT_Q': 552,
    'SORT_PN': 560, 'SORT_QN': 568, 'SORT_TAIL': 576, 'SORT_NEW': 584,
    'SORT_MERGES': 592, 'CMP_LEFT': 600, 'CMP_RIGHT': 608, 'CMP_SIDE': 616,
    'CMP_INDEX': 624, 'CMP_LESS': 632, 'CMP_LEN': 640,
    'CACHE_BASE': 648, 'CACHE_HITS': 656, 'CACHE_MISSES': 664,
    'CACHE_STORES': 672, 'CACHE_BYTES': 163840,
    'KEY_SUMMARY_READY': 680, 'KEY_SUMMARY_SIZE': 688,
    'KEY_SUMMARY_HITS': 696, 'KEY_SUMMARY_MISSES': 704,
    'ACTIVE_BASE': 1024, 'FRAME_BASE': 4096,
}

SOURCE = r'''
def json_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 32768 + 8192:
        return 199
    if get(w, 0) == 0:
        if length(s) != 104 and length(s) != 112:
            return 199
        if read64(s, 0) == MAGIC:
            if length(s) != 104:
                return 199
        elif read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC:
            if length(s) != 112 or read64(s, 104) != 1:
                return 199
        else:
            return 199
        if read64(s, 8) != 0 or read64(s, 16) != 0:
            return 199
        if read64(s, 32) != 2 or read64(s, 40) != 0 or read64(s, 48) > 24 or read64(s, 56) > 8388608:
            return 100
        maximum = read64(s, 56)
        if read64(s, 64) > 5 or read64(s, 80) > 5 or read64(s, 96) > 2 or read64(s, 24) == 0:
            return 199
        if (read64(s, 64) == 0 and read64(s, 72) != 0) or (read64(s, 64) == 1 and read64(s, 72) > 1):
            return 199
        if (read64(s, 80) == 0 and read64(s, 88) != 0) or (read64(s, 80) == 1 and read64(s, 88) > 1):
            return 199
        ascii_flag = flag_truth(read64(s, 64), read64(s, 72))
        sort_flag = flag_truth(read64(s, 80), read64(s, 88))
        if ascii_flag == 2:
            return 117
        if sort_flag == 2:
            return 118
        if read64(s, 96) == 2:
            return 119
        if (read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC) and read64(s, 96) != 0:
            return 199
        budget = choose(maximum < 262144, maximum, 262144)
        slots = 2
        while slots < budget * 2:
            slots = slots << 1
        stack = 32768
        records = stack + (budget + 130) * 24
        table = records + budget * 64
        temp_a = table + slots * 8
        temp_b = temp_a + maximum + 64
        limbs = temp_b + maximum + 64
        required = limbs + ((maximum * 4 + 31) >> 5) * 4 + 64 + 8192 + choose(read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC, CACHE_BYTES, 0)
        if length(w) != required or length(o) < maximum:
            return 199
        put(w, 0, read64(s, 0))
        put(w, CACHE_BASE, 0)
        if read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC:
            put(w, CACHE_BASE, required - 8192 - CACHE_BYTES)
        put(w, MAX, maximum)
        put(w, BUDGET, budget)
        put(w, ASCII, ascii_flag)
        put(w, SORT, sort_flag)
        put(w, RENDERER, read64(s, 96))
        put(w, ROOT, read64(s, 24))
        put(w, HASH_SLOTS, slots)
        put(w, STACK, stack)
        put(w, RECORDS, records)
        put(w, TABLE, table)
        put(w, TEMP_A, temp_a)
        put(w, TEMP_B, temp_b)
        put(w, LIMB_BASE, limbs)
        put(w, QUEUED, 1)
        push(w, read64(s, 24), 0, 0)
        put(w, PHASE, 1)
    else:
        if (get(w, 0) != MAGIC and get(w, 0) != CACHED_MAGIC and get(w, 0) != KEY_SUMMARY_MAGIC) or get(w, AWAIT) == 0 or length(s) < 56:
            return 199
        opcode = get(w, AWAIT)
        if read64(s, 0) != get(w, 0) or read64(s, 8) != get(w, SEQ) or read64(s, 16) != opcode:
            return 199
        expected = 56
        if opcode == 3 or opcode == 4:
            if read64(s, 24) != get(w, REQ_COUNT) or read64(s, 24) > 1024:
                return 199
            expected = expected + read64(s, 24) * 4
        if opcode == 6:
            if read64(s, 24) == 0 or read64(s, 24) > 32:
                return 199
            expected = expected + read64(s, 24)
        if length(s) != expected:
            return 199
        put(w, AWAIT, 0)
    while True:
        phase = get(w, PHASE)
        result = 199
        if phase < 20:
            result = preflight(s, w, phase)
        elif phase < 40:
            result = normalize(s, o, w, phase)
        elif phase >= 100 and phase < 150:
            result = encode(s, o, w, phase)
        if result != 0:
            if result != 1:
                put(w, PHASE, 4294967295)
            return result
    return 199

def flag_truth(kind:u64, value:u64) -> u64:
    if kind == 0:
        return 0
    if kind == 1:
        return value
    if kind == 2 or kind == 4:
        return choose(value == 0, 0, 1)
    if kind == 3:
        return choose((value & 9223372036854775807) == 0, 0, 1)
    return 2

def ask(w:mutbuf, opcode:u64, handle:u64, index:u64, count:u64, part:u64, phase:u64) -> u64:
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, AWAIT, opcode)
    put(w, REQ_H, handle)
    put(w, REQ_INDEX, index)
    put(w, REQ_COUNT, count)
    put(w, REQ_PART, part)
    put(w, PHASE, phase)
    return 1

def key_summary(w:mutbuf, handle:u64, next:u64) -> u64:
    # Only protocol 04 may omit a SUMMARY, and only for the exact string
    # whose immutable-key preflight already completed in this workspace.
    # Legacy 02/03 retain even their unused header bytes and request order.
    if get(w, 0) == KEY_SUMMARY_MAGIC:
        put(w, KEY_SUMMARY_READY, 0)
        base = get(w, CACHE_BASE)
        if base != 0 and handle != 0:
            slot = base + (handle & 1023) * 160
            if get(w, slot) == handle:
                size = get(w, slot + 8)
                count = get(w, slot + 16)
                width = get(w, slot + 24)
                if size <= 32 and count <= 128 and width >= 2 and width <= get(w, MAX):
                    put(w, KEY_SUMMARY_SIZE, size)
                    put(w, KEY_SUMMARY_READY, 1)
                    put(w, KEY_SUMMARY_HITS, get(w, KEY_SUMMARY_HITS) + 1)
                    put(w, PHASE, next)
                    return 0
        put(w, KEY_SUMMARY_MISSES, get(w, KEY_SUMMARY_MISSES) + 1)
    return ask(w, 1, handle, 0, 0, 0, next)

def key_fact(s:readbuf, w:mutbuf, offset:u64) -> u64:
    if get(w, 0) == KEY_SUMMARY_MAGIC and get(w, KEY_SUMMARY_READY) != 0:
        if offset == 24:
            return 4
        if offset == 32:
            return get(w, KEY_SUMMARY_SIZE)
        return 0
    return read64(s, offset)

def key_norm_begin(s:readbuf, w:mutbuf, handle:u64, role:u64, target:u64, next:u64) -> u64:
    if get(w, 0) != KEY_SUMMARY_MAGIC or get(w, KEY_SUMMARY_READY) == 0:
        return norm_begin(s, w, handle, role, target, next)
    put(w, N_H, handle)
    put(w, N_KIND, 4)
    put(w, N_SIZE, get(w, KEY_SUMMARY_SIZE))
    put(w, N_A, 0)
    put(w, N_B, 0)
    put(w, N_ROLE, role)
    put(w, N_TARGET, target)
    put(w, N_RETURN, next)
    put(w, N_COUNT, 0)
    put(w, N_TEXT, 0)
    put(w, PHASE, 20)
    return 0

def push(w:mutbuf, handle:u64, depth:u64, leaving:u64) -> u64:
    index = get(w, SP)
    if handle == 0 or index >= get(w, BUDGET) + 130:
        return 199
    at = get(w, STACK) + index * 24
    put(w, at, handle)
    put(w, at + 8, depth)
    put(w, at + 16, leaving)
    put(w, SP, index + 1)
    return 0

def preflight(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        if get(w, SP) == 0:
            put(w, PHASE, 100)
            return 0
        index = get(w, SP) - 1
        at = get(w, STACK) + index * 24
        handle = get(w, at)
        depth = get(w, at + 8)
        put(w, SP, index)
        if depth > 128:
            return 101
        if get(w, at + 16) != 0:
            count = get(w, ACTIVE)
            if count == 0 or get(w, ACTIVE_BASE + (count - 1) * 8) != handle:
                return 199
            put(w, ACTIVE, count - 1)
            return 0
        if get(w, QUEUED) == 0:
            return 199
        put(w, QUEUED, get(w, QUEUED) - 1)
        put(w, NODES, get(w, NODES) + 1)
        if get(w, NODES) > get(w, BUDGET):
            return 102
        put(w, H, handle)
        put(w, DEPTH, depth)
        return ask(w, 1, handle, 0, 0, 0, 2)
    if phase == 2:
        kind = read64(s, 24)
        size = read64(s, 32)
        put(w, KIND, kind)
        put(w, SIZE, size)
        put(w, A, read64(s, 40))
        put(w, B, read64(s, 48))
        if kind >= 5 and kind <= 7:
            if size > get(w, BUDGET) - get(w, NODES) - get(w, QUEUED):
                return 103
            put(w, QUEUED, get(w, QUEUED) + size)
            index = 0
            while index < get(w, ACTIVE):
                if get(w, ACTIVE_BASE + index * 8) == get(w, H):
                    return 104
                index = index + 1
            if index >= 129:
                return 199
            put(w, ACTIVE_BASE + index * 8, get(w, H))
            put(w, ACTIVE, index + 1)
            result = push(w, get(w, H), get(w, DEPTH), 1)
            if result != 0:
                return result
            put(w, INDEX, 0)
            if kind == 7:
                index = 0
                while index < get(w, KEY_COUNT):
                    record = get(w, RECORDS) + index * 64
                    put(w, get(w, TABLE) + get(w, record + 40) * 8, 0)
                    index = index + 1
                put(w, KEY_COUNT, 0)
                put(w, PHASE, 10)
            else:
                put(w, PHASE, 3)
            return 0
        if kind == 4:
            return text_begin(w, get(w, H), size, 0, 0, 1)
        if kind == 2:
            if size > get(w, MAX) * 4:
                return 105
        elif kind > 3:
            return 106
        put(w, PHASE, 1)
        return 0
    if phase == 3 or phase == 10:
        if get(w, INDEX) == get(w, SIZE):
            put(w, PHASE, 1)
            return 0
        return ask(w, 2, get(w, H), get(w, INDEX), 0, 0, choose(phase == 3, 4, 11))
    if phase == 4 or phase == 18:
        result = push(w, read64(s, 24), get(w, DEPTH) + 1, 0)
        if result != 0:
            return result
        put(w, INDEX, get(w, INDEX) + 1)
        put(w, PHASE, choose(phase == 4, 3, 10))
        return 0
    if phase == 11:
        if read64(s, 24) == 0:
            return 199
        put(w, KEY_H, read64(s, 24))
        return key_summary(w, read64(s, 24), 12)
    if phase == 12:
        put(w, KEY_KIND, key_fact(s, w, 24))
        return key_norm_begin(s, w, get(w, KEY_H), 0, get(w, TEMP_A), 13)
    if phase == 13:
        put(w, KEY_LEN, get(w, N_COUNT))
        put(w, KEY_TEXT, get(w, N_TEXT))
        hash = 1469598103934665603
        index = 0
        while index < get(w, N_COUNT):
            hash = (hash ^ byte(w, get(w, TEMP_A) + index)) * 1099511628211
            index = index + 1
        put(w, KEY_HASH, hash)
        put(w, PROBE, hash & (get(w, HASH_SLOTS) - 1))
        put(w, PHASE, 14)
        return 0
    if phase == 14:
        slot = get(w, PROBE)
        value = get(w, get(w, TABLE) + slot * 8)
        if value == 0:
            index = get(w, KEY_COUNT)
            if index >= get(w, BUDGET):
                return 199
            record = get(w, RECORDS) + index * 64
            put(w, record, get(w, KEY_HASH))
            put(w, record + 8, get(w, KEY_H))
            put(w, record + 16, get(w, KEY_KIND))
            put(w, record + 24, get(w, KEY_TEXT))
            put(w, record + 32, get(w, KEY_LEN))
            put(w, record + 40, slot)
            put(w, get(w, TABLE) + slot * 8, index + 1)
            put(w, KEY_COUNT, index + 1)
            return ask(w, 2, get(w, H), get(w, INDEX), 0, 1, 18)
        if value > get(w, KEY_COUNT):
            return 199
        record = get(w, RECORDS) + (value - 1) * 64
        if get(w, record) == get(w, KEY_HASH) and get(w, record + 32) == get(w, KEY_LEN):
            handle = get(w, record + 8)
            if get(w, record + 24) != 0:
                handle = get(w, record + 24)
            put(w, N_H, handle)
            return key_summary(w, handle, 15)
        put(w, PROBE, (slot + 1) & (get(w, HASH_SLOTS) - 1))
        return 0
    if phase == 15:
        return key_norm_begin(s, w, get(w, N_H), 1, get(w, TEMP_B), 16)
    if phase == 16:
        if get(w, N_COUNT) == get(w, KEY_LEN):
            index = 0
            equal = True
            while index < get(w, KEY_LEN) and equal:
                equal = byte(w, get(w, TEMP_A) + index) == byte(w, get(w, TEMP_B) + index)
                index = index + 1
            if equal:
                return 107
        put(w, PROBE, (get(w, PROBE) + 1) & (get(w, HASH_SLOTS) - 1))
        put(w, PHASE, 14)
        return 0
    return 199

def norm_begin(s:readbuf, w:mutbuf, handle:u64, role:u64, target:u64, next:u64) -> u64:
    put(w, N_H, handle)
    put(w, N_KIND, read64(s, 24))
    put(w, N_SIZE, read64(s, 32))
    put(w, N_A, read64(s, 40))
    put(w, N_B, read64(s, 48))
    put(w, N_ROLE, role)
    put(w, N_TARGET, target)
    put(w, N_RETURN, next)
    put(w, N_COUNT, 0)
    put(w, N_TEXT, 0)
    put(w, PHASE, 20)
    return 0

def text_begin(w:mutbuf, handle:u64, size:u64, mode:u64, target:u64, next:u64) -> u64:
    if (mode == 0 or mode == 1) and size > get(w, MAX) - choose(get(w, MAX) >= 2, 2, 0):
        return 108
    if (mode == 0 or mode == 1) and get(w, MAX) < 2:
        return 108
    put(w, T_H, handle)
    put(w, T_SIZE, size)
    put(w, T_MODE, mode)
    put(w, T_POS, 0)
    put(w, T_WIDTH, 2)
    put(w, T_COUNT, 0)
    put(w, T_TARGET, target)
    put(w, T_RETURN, next)
    put(w, PHASE, 30)
    if get(w, CACHE_BASE) != 0 and (mode == 1 or mode == 2) and size <= 32:
        return key_cache_restore(w)
    return 0

def key_cache_restore(w:mutbuf) -> u64:
    # This capability applies only to stable exact-builtin observations. A
    # cache entry is created after the original key preflight has succeeded.
    # Aliases keep a strong reference and a session-unique nonzero handle.
    slot = get(w, CACHE_BASE) + (get(w, T_H) & 1023) * 160
    if get(w, slot) == get(w, T_H) and get(w, slot + 8) == get(w, T_SIZE):
        count = get(w, slot + 16)
        if count > 128:
            return 199
        index = 0
        target = get(w, T_TARGET)
        while index < count:
            store(w, target + index, byte(w, slot + 32 + index))
            index = index + 1
        put(w, T_POS, get(w, T_SIZE))
        put(w, T_COUNT, count)
        if get(w, T_MODE) == 1:
            put(w, T_WIDTH, get(w, slot + 24))
        put(w, N_COUNT, count)
        put(w, PHASE, get(w, T_RETURN))
        put(w, CACHE_HITS, get(w, CACHE_HITS) + 1)
    else:
        put(w, CACHE_MISSES, get(w, CACHE_MISSES) + 1)
    return 0

def key_cache_save(w:mutbuf) -> u64:
    # Occupied/colliding slots are a miss, never a new admission refusal.
    slot = get(w, CACHE_BASE) + (get(w, T_H) & 1023) * 160
    if get(w, slot) != 0:
        return 0
    count = get(w, T_COUNT)
    if count > 128:
        return 199
    index = 0
    source = get(w, T_TARGET)
    while index < count:
        store(w, slot + 32 + index, byte(w, source + index))
        index = index + 1
    put(w, slot + 8, get(w, T_SIZE))
    put(w, slot + 16, count)
    put(w, slot + 24, get(w, T_WIDTH))
    put(w, slot, get(w, T_H))
    put(w, CACHE_STORES, get(w, CACHE_STORES) + 1)
    return 0

def normalize(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 20:
        kind = get(w, N_KIND)
        role = get(w, N_ROLE)
        target = get(w, N_TARGET)
        if kind == 4:
            return text_begin(w, get(w, N_H), get(w, N_SIZE), choose(role == 0, 1, 2), target, 29)
        if kind == 0 or kind == 1:
            literal(w, target, choose(kind == 0, 0, choose(get(w, N_A) == 0, 1, 2)))
            put(w, N_COUNT, choose(kind == 0, 4, choose(get(w, N_A) == 0, 5, 4)))
            put(w, PHASE, 29)
            return 0
        if kind == 2:
            if get(w, N_SIZE) > get(w, MAX) * 4:
                return choose(role == 0, 109, 199)
            put(w, N_LIMBS, (get(w, N_SIZE) + 31) >> 5)
            put(w, N_INDEX, 0)
            put(w, N_LIMIT, 0)
            if role == 1:
                put(w, PHASE, 22)
                return 0
            return ask(w, 5, 0, 0, 0, 0, 21)
        if kind == 3:
            bits = get(w, N_A)
            if ((bits >> 52) & 2047) == 2047:
                if role == 0:
                    return 110
                return choose(get(w, RENDERER) != 0, 111, 112)
            if get(w, RENDERER) != 0 and role != 1:
                return ask(w, 6, get(w, N_H), bits, 0, 0, 25)
            put(w, length(w) - 192, bits)
            count = widen(format_render_binary64(w))
            if count > 32:
                return 199
            index = 0
            while index < count:
                store(w, target + index, byte(w, length(w) - 2048 + index))
                index = index + 1
            put(w, N_COUNT, count)
            put(w, PHASE, 29)
            return 0
        return choose(role == 0, 113, 199)
    if phase == 21:
        limit = read64(s, 24)
        if limit > 2147483647:
            return 199
        put(w, N_LIMIT, limit)
        if limit != 0 and get(w, N_SIZE) > limit * 4:
            return 112
        put(w, PHASE, 22)
        return 0
    if phase == 22:
        remaining = get(w, N_LIMBS) - get(w, N_INDEX)
        if remaining == 0:
            return integer_decimal(w)
        return ask(w, 4, get(w, N_H), get(w, N_INDEX), choose(remaining < 1024, remaining, 1024), 0, 23)
    if phase == 23:
        index = 0
        reply_count = read64(s, 24)
        while index < reply_count:
            put32(w, get(w, LIMB_BASE) + (get(w, N_INDEX) + index) * 4, read32(s, 56 + index * 4))
            index = index + 1
        put(w, N_INDEX, get(w, N_INDEX) + index)
        put(w, PHASE, 22)
        return 0
    if phase == 25:
        # This seam is the existing finite native binary64 formatter, whose
        # contract returns ASCII JSON-number text of at most 32 characters.
        index = 0
        reply_count = read64(s, 24)
        while index < reply_count:
            value = byte(s, 56 + index)
            if value > 127:
                return 199
            store(w, get(w, N_TARGET) + index, value)
            index = index + 1
        put(w, N_COUNT, index)
        put(w, PHASE, 29)
        return 0
    if phase == 29:
        if get(w, N_ROLE) == 0 and get(w, N_KIND) != 4 and get(w, N_COUNT) + 2 > get(w, MAX):
            return 114
        put(w, PHASE, get(w, N_RETURN))
        return 0
    if phase == 30:
        remaining = get(w, T_SIZE) - get(w, T_POS)
        if remaining == 0:
            if get(w, CACHE_BASE) != 0 and get(w, T_MODE) == 1 and get(w, T_SIZE) <= 32:
                saved = key_cache_save(w)
                if saved != 0:
                    return saved
            put(w, N_COUNT, get(w, T_COUNT))
            put(w, PHASE, get(w, T_RETURN))
            return 0
        return ask(w, 3, get(w, T_H), get(w, T_POS), choose(remaining < 1024, remaining, 1024), 0, 31)
    if phase == 31:
        index = 0
        mode = get(w, T_MODE)
        reply_count = read64(s, 24)
        while index < reply_count:
            point = read32(s, 56 + index * 4)
            if point > 1114111 or (mode == 4 and point > 127):
                return 199
            if mode == 0 or mode == 1:
                if point >= 55296 and point <= 57343:
                    return 115
                put(w, T_WIDTH, get(w, T_WIDTH) + width(point, get(w, ASCII)))
                if get(w, T_WIDTH) > get(w, MAX):
                    return 108
            if mode == 3:
                result = escaped(o, w, point)
                if result != 0:
                    return result
            elif mode != 0:
                text_utf8(w, point)
            index = index + 1
        put(w, T_POS, get(w, T_POS) + index)
        put(w, PHASE, 30)
        return 0
    return 199

def integer_decimal(w:mutbuf) -> u64:
    words = get(w, N_LIMBS)
    count = 0
    target = get(w, N_TARGET) + get(w, N_A)
    while words > 0:
        carry = 0
        index = words
        while index > 0:
            index = index - 1
            value = get32(w, get(w, LIMB_BASE) + index * 4)
            quotient = 0
            bit = 32
            while bit > 0:
                bit = bit - 1
                carry = (carry << 1) | ((value >> bit) & 1)
                if carry >= 1000000000:
                    carry = carry - 1000000000
                    quotient = quotient | (1 << bit)
            put32(w, get(w, LIMB_BASE) + index * 4, quotient)
        while words > 0 and get32(w, get(w, LIMB_BASE) + (words - 1) * 4) == 0:
            words = words - 1
        digits = 0
        while digits < 9 and (words != 0 or carry != 0 or digits == 0):
            quotient = (carry * 3435973837) >> 35
            if count < get(w, MAX):
                store(w, target + count, carry - quotient * 10 + 48)
            carry = quotient
            count = count + 1
            digits = digits + 1
    if count == 0:
        store(w, target, 48)
        count = 1
    if get(w, N_LIMIT) != 0 and count > get(w, N_LIMIT):
        return 112
    if count <= get(w, MAX):
        index = 0
        while index < count >> 1:
            value = byte(w, target + index)
            store(w, target + index, byte(w, target + count - 1 - index))
            store(w, target + count - 1 - index, value)
            index = index + 1
    if get(w, N_A) != 0:
        store(w, get(w, N_TARGET), 45)
    put(w, N_COUNT, count + get(w, N_A))
    put(w, PHASE, 29)
    return 0

def width(point:u64, ascii:u64) -> u64:
    if point < 32:
        if point == 8 or point == 9 or point == 10 or point == 12 or point == 13:
            return 2
        return 6
    if point == 34 or point == 92:
        return 2
    if point < 128:
        return choose(point == 127 and ascii != 0, 6, 1)
    if ascii != 0:
        return choose(point <= 65535, 6, 12)
    if point < 2048:
        return 2
    return choose(point < 65536, 3, 4)

def text_byte(w:mutbuf, value:u64) -> u64:
    count = get(w, T_COUNT)
    if count < get(w, MAX):
        store(w, get(w, T_TARGET) + count, value)
    put(w, T_COUNT, count + 1)
    return 0

def text_utf8(w:mutbuf, point:u64) -> u64:
    if point < 128:
        text_byte(w, point)
    else:
        if point < 2048:
            text_byte(w, 192 | (point >> 6))
        else:
            if point < 65536:
                text_byte(w, 224 | (point >> 12))
            else:
                text_byte(w, 240 | (point >> 18))
                text_byte(w, 128 | ((point >> 12) & 63))
            text_byte(w, 128 | ((point >> 6) & 63))
        text_byte(w, 128 | (point & 63))
    return 0

def literal(w:mutbuf, at:u64, kind:u64) -> u64:
    if kind == 0:
        store(w, at, 110)
        store(w, at + 1, 117)
        store(w, at + 2, 108)
        store(w, at + 3, 108)
    elif kind == 1:
        store(w, at, 102)
        store(w, at + 1, 97)
        store(w, at + 2, 108)
        store(w, at + 3, 115)
        store(w, at + 4, 101)
    else:
        store(w, at, 116)
        store(w, at + 1, 114)
        store(w, at + 2, 117)
        store(w, at + 3, 101)
    return 0

def emit(o:mutbuf, w:mutbuf, value:u64) -> u64:
    count = get(w, OUT)
    if count < get(w, MAX):
        store(o, count, value)
    put(w, OUT, count + 1)
    return 0

def commit_fragment(w:mutbuf) -> u64:
    return choose(get(w, OUT) > get(w, MAX), 116, 0)

def escaped(o:mutbuf, w:mutbuf, point:u64) -> u64:
    if point < 32:
        emit(o, w, 92)
        ch = 0
        if point == 8:
            ch = 98
        elif point == 9:
            ch = 116
        elif point == 10:
            ch = 110
        elif point == 12:
            ch = 102
        elif point == 13:
            ch = 114
        if ch != 0:
            emit(o, w, ch)
        else:
            emit(o, w, 117)
            hex4(o, w, point)
    elif point == 34 or point == 92:
        emit(o, w, 92)
        emit(o, w, point)
    elif get(w, ASCII) != 0 and point >= 127:
        if point <= 65535:
            emit(o, w, 92)
            emit(o, w, 117)
            hex4(o, w, point)
        else:
            emit(o, w, 92)
            emit(o, w, 117)
            hex4(o, w, 55296 + ((point - 65536) >> 10))
            emit(o, w, 92)
            emit(o, w, 117)
            hex4(o, w, 56320 + ((point - 65536) & 1023))
    else:
        if point >= 55296 and point <= 57343:
            return 112
        if point < 128:
            emit(o, w, point)
        else:
            if point < 2048:
                emit(o, w, 192 | (point >> 6))
            else:
                if point < 65536:
                    emit(o, w, 224 | (point >> 12))
                else:
                    emit(o, w, 240 | (point >> 18))
                    emit(o, w, 128 | ((point >> 12) & 63))
                emit(o, w, 128 | ((point >> 6) & 63))
            emit(o, w, 128 | (point & 63))
    return 0

def hex4(o:mutbuf, w:mutbuf, value:u64) -> u64:
    index = 4
    while index > 0:
        index = index - 1
        digit = (value >> (index * 4)) & 15
        emit(o, w, digit + choose(digit < 10, 48, 87))
    return 0

def read64(s:readbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(s, at + 0) << 0)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    value = value | (byte(s, at + 4) << 32)
    value = value | (byte(s, at + 5) << 40)
    value = value | (byte(s, at + 6) << 48)
    value = value | (byte(s, at + 7) << 56)
    return value

def read32(s:readbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(s, at + 0) << 0)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(w, at + 0) << 0)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    value = value | (byte(w, at + 7) << 56)
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at + 0, (value >> 0) & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0

def get32(w:mutbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(w, at + 0) << 0)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    return value

def put32(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at + 0, (value >> 0) & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    return 0

def widen(value:u32) -> u64:
    return value
'''

ENCODER = r'''
def encode(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 100:
        put(w, FRAME_COUNT, 0)
        put(w, ENTRIES, 0)
        put(w, OUT, 0)
        put(w, PREFIX, 0)
        put(w, H, get(w, ROOT))
        return ask(w, 1, get(w, H), 0, 0, 0, 101)
    if phase == 101:
        kind = read64(s, 24)
        size = read64(s, 32)
        if kind < 5:
            if kind == 4:
                if get(w, PREFIX) != 0:
                    emit(o, w, get(w, PREFIX))
                emit(o, w, 34)
                return text_begin(w, get(w, H), size, 3, 0, 109)
            return norm_begin(s, w, get(w, H), 2, get(w, TEMP_A), 108)
        if kind > 7:
            return 112
        if get(w, PREFIX) != 0:
            emit(o, w, get(w, PREFIX))
            result = commit_fragment(w)
            if result != 0:
                return result
        if size == 0:
            emit(o, w, choose(kind == 7, 123, 91))
            emit(o, w, choose(kind == 7, 125, 93))
            result = commit_fragment(w)
            if result != 0:
                return result
            put(w, PHASE, 110)
            return 0
        index = 0
        while index < get(w, FRAME_COUNT):
            if get(w, FRAME_BASE + index * 96) == get(w, H):
                return 112
            index = index + 1
        if index >= 129 or size > get(w, BUDGET):
            return 199
        frame = FRAME_BASE + index * 96
        put(w, frame, get(w, H))
        put(w, frame + 8, kind)
        put(w, frame + 16, size)
        put(w, frame + 24, 0)
        put(w, frame + 32, get(w, ENTRIES))
        put(w, frame + 40, 0)
        put(w, frame + 64, 0)
        put(w, FRAME_COUNT, index + 1)
        if kind != 7:
            put(w, PHASE, 110)
            return 0
        emit(o, w, 123)
        result = commit_fragment(w)
        if result != 0:
            return result
        if get(w, SORT) != 0:
            if get(w, ENTRIES) + size > get(w, BUDGET):
                return 199
            put(w, ENTRIES, get(w, ENTRIES) + size)
            put(w, PHASE, 111)
        else:
            put(w, PHASE, 140)
        return 0
    if phase == 102:
        if read64(s, 24) == 0:
            return 199
        put(w, H, read64(s, 24))
        return ask(w, 1, get(w, H), 0, 0, 0, 101)
    if phase == 108:
        if get(w, N_COUNT) > get(w, MAX):
            return 116
        if get(w, PREFIX) != 0:
            emit(o, w, get(w, PREFIX))
        index = 0
        while index < get(w, N_COUNT):
            emit(o, w, byte(w, get(w, TEMP_A) + index))
            index = index + 1
        result = commit_fragment(w)
        if result != 0:
            return result
        put(w, PHASE, 110)
        return 0
    if phase == 109:
        emit(o, w, 34)
        result = commit_fragment(w)
        if result != 0:
            return result
        put(w, PHASE, 110)
        return 0
    if phase == 110:
        if get(w, FRAME_COUNT) == 0:
            return 2
        frame = frame_at(w)
        if get(w, frame + 8) == 7:
            put(w, PHASE, 140)
            return 0
        index = get(w, frame + 24)
        if index == get(w, frame + 16):
            emit(o, w, 93)
            result = commit_fragment(w)
            if result != 0:
                return result
            pop_frame(w)
            return 0
        put(w, PREFIX, choose(index == 0, 91, 44))
        put(w, frame + 24, index + 1)
        return ask(w, 2, get(w, frame), index, 0, 0, 102)
    if phase >= 111 and phase <= 114:
        frame = frame_at(w)
        index = get(w, frame + 24)
        record = get(w, RECORDS) + (get(w, frame + 32) + index) * 64
        if phase == 111:
            if index == get(w, frame + 16):
                head = get(w, RECORDS) + get(w, frame + 32) * 64
                put(w, frame + 64, head)
                put(w, SORT_HEAD, head)
                put(w, SORT_WIDTH, 1)
                put(w, PHASE, 120)
                return 0
            return ask(w, 2, get(w, frame), index, 0, 0, 112)
        if phase == 112:
            if read64(s, 24) == 0:
                return 199
            put(w, record, read64(s, 24))
            return ask(w, 2, get(w, frame), index, 0, 1, 113)
        if phase == 113:
            if read64(s, 24) == 0:
                return 199
            put(w, record + 8, read64(s, 24))
            return key_summary(w, get(w, record), 114)
        put(w, record + 16, key_fact(s, w, 24))
        put(w, record + 24, key_fact(s, w, 32))
        put(w, record + 32, key_fact(s, w, 40))
        put(w, record + 40, key_fact(s, w, 48))
        put(w, record + 48, choose(index + 1 == get(w, frame + 16), 0, record + 64))
        put(w, frame + 24, index + 1)
        put(w, PHASE, 111)
        return 0
    if phase >= 120 and phase <= 139:
        return sort_step(s, w, phase)
    if phase == 140:
        frame = frame_at(w)
        index = get(w, frame + 24)
        if index == get(w, frame + 16):
            emit(o, w, 125)
            result = commit_fragment(w)
            if result != 0:
                return result
            pop_frame(w)
            put(w, PHASE, 110)
            return 0
        if get(w, SORT) != 0:
            record = get(w, frame + 40)
            if record == 0:
                return 199
            put(w, frame + 48, get(w, record))
            put(w, frame + 56, get(w, record + 8))
            put(w, frame + 40, get(w, record + 48))
            return key_summary(w, get(w, record), 143)
        return ask(w, 2, get(w, frame), index, 0, 0, 141)
    if phase == 141:
        frame = frame_at(w)
        put(w, frame + 48, read64(s, 24))
        return ask(w, 2, get(w, frame), get(w, frame + 24), 0, 1, 142)
    if phase == 142:
        frame = frame_at(w)
        put(w, frame + 56, read64(s, 24))
        return key_summary(w, get(w, frame + 48), 143)
    if phase == 143:
        frame = frame_at(w)
        return key_norm_begin(s, w, get(w, frame + 48), 3, get(w, TEMP_A), 144)
    if phase == 144:
        frame = frame_at(w)
        if get(w, frame + 24) != 0:
            emit(o, w, 44)
            result = commit_fragment(w)
            if result != 0:
                return result
        if get(w, N_COUNT) > get(w, MAX):
            return 116
        emit(o, w, 34)
        result = quoted_buffer(o, w, get(w, TEMP_A), get(w, N_COUNT))
        if result != 0:
            return result
        emit(o, w, 34)
        result = commit_fragment(w)
        if result != 0:
            return result
        emit(o, w, 58)
        result = commit_fragment(w)
        if result != 0:
            return result
        put(w, PREFIX, 0)
        put(w, H, get(w, frame + 56))
        put(w, frame + 24, get(w, frame + 24) + 1)
        return ask(w, 1, get(w, H), 0, 0, 0, 101)
    return 199

def frame_at(w:mutbuf) -> u64:
    return FRAME_BASE + (get(w, FRAME_COUNT) - 1) * 96

def pop_frame(w:mutbuf) -> u64:
    frame = frame_at(w)
    put(w, ENTRIES, get(w, frame + 32))
    put(w, FRAME_COUNT, get(w, FRAME_COUNT) - 1)
    return 0

def quoted_buffer(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        point = byte(w, at + index)
        index = index + 1
        count = 0
        if point >= 240:
            count = 3
            point = point & 7
        elif point >= 224:
            count = 2
            point = point & 15
        elif point >= 192:
            count = 1
            point = point & 31
        if count > size - index:
            return 199
        while count > 0:
            point = (point << 6) | (byte(w, at + index) & 63)
            index = index + 1
            count = count - 1
        result = escaped(o, w, point)
        if result != 0:
            return result
    return 0

def sort_step(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 120:
        put(w, SORT_P, get(w, SORT_HEAD))
        put(w, SORT_TAIL, 0)
        put(w, SORT_NEW, 0)
        put(w, SORT_MERGES, 0)
        put(w, PHASE, 121)
        return 0
    if phase == 121:
        p = get(w, SORT_P)
        if p == 0:
            put(w, get(w, SORT_TAIL) + 48, 0)
            put(w, SORT_HEAD, get(w, SORT_NEW))
            if get(w, SORT_MERGES) <= 1:
                frame = frame_at(w)
                put(w, frame + 40, get(w, SORT_NEW))
                put(w, frame + 24, 0)
                put(w, PHASE, 140)
            else:
                put(w, SORT_WIDTH, get(w, SORT_WIDTH) << 1)
                put(w, PHASE, 120)
            return 0
        put(w, SORT_MERGES, get(w, SORT_MERGES) + 1)
        count = 0
        q = p
        while count < get(w, SORT_WIDTH) and q != 0:
            count = count + 1
            q = get(w, q + 48)
        put(w, SORT_Q, q)
        put(w, SORT_PN, count)
        put(w, SORT_QN, get(w, SORT_WIDTH))
        put(w, PHASE, 122)
        return 0
    if phase == 122:
        if get(w, SORT_PN) == 0 and (get(w, SORT_QN) == 0 or get(w, SORT_Q) == 0):
            put(w, SORT_P, get(w, SORT_Q))
            put(w, PHASE, 121)
            return 0
        if get(w, SORT_PN) == 0:
            put(w, CMP_LESS, 0)
            put(w, PHASE, 129)
            return 0
        if get(w, SORT_QN) == 0 or get(w, SORT_Q) == 0:
            put(w, CMP_LESS, 1)
            put(w, PHASE, 129)
            return 0
        left = get(w, SORT_P)
        right = get(w, SORT_Q)
        put(w, CMP_LEFT, left)
        put(w, CMP_RIGHT, right)
        a = get(w, left + 16)
        b = get(w, right + 16)
        if a == 4 and b == 4:
            return text_begin(w, get(w, left), get(w, left + 24), 2, get(w, TEMP_A), 130)
        if a >= 1 and a <= 3 and b >= 1 and b <= 3:
            put(w, CMP_SIDE, 0)
            put(w, CMP_INDEX, 0)
            put(w, PHASE, 132)
            return 0
        return 112
    if phase == 129:
        take = get(w, SORT_P)
        if get(w, CMP_LESS) != 0:
            put(w, SORT_P, get(w, take + 48))
            put(w, SORT_PN, get(w, SORT_PN) - 1)
        else:
            take = get(w, SORT_Q)
            put(w, SORT_Q, get(w, take + 48))
            put(w, SORT_QN, get(w, SORT_QN) - 1)
        if get(w, SORT_TAIL) == 0:
            put(w, SORT_NEW, take)
        else:
            put(w, get(w, SORT_TAIL) + 48, take)
        put(w, SORT_TAIL, take)
        put(w, PHASE, 122)
        return 0
    if phase == 130:
        put(w, CMP_LEN, get(w, N_COUNT))
        right = get(w, CMP_RIGHT)
        return text_begin(w, get(w, right), get(w, right + 24), 2, get(w, TEMP_B), 131)
    if phase == 131:
        a = get(w, CMP_LEN)
        b = get(w, N_COUNT)
        if a > get(w, MAX) or b > get(w, MAX):
            return 199
        index = 0
        equal = True
        less = a <= b
        while index < a and index < b and equal:
            left = byte(w, get(w, TEMP_A) + index)
            right = byte(w, get(w, TEMP_B) + index)
            if left != right:
                equal = False
                less = left < right
            index = index + 1
        put(w, CMP_LESS, choose(less, 1, 0))
        put(w, PHASE, 129)
        return 0
    if phase == 132:
        side = get(w, CMP_SIDE)
        if side == 2:
            put(w, CMP_LESS, numeric_less(w, get(w, CMP_LEFT), get(w, CMP_RIGHT)))
            put(w, PHASE, 129)
            return 0
        record = choose(side == 0, get(w, CMP_LEFT), get(w, CMP_RIGHT))
        kind = get(w, record + 16)
        if kind == 2:
            words = (get(w, record + 24) + 31) >> 5
            if words * 4 > get(w, MAX) + 64:
                return 199
            remaining = words - get(w, CMP_INDEX)
            if remaining != 0:
                return ask(w, 4, get(w, record), get(w, CMP_INDEX), choose(remaining < 1024, remaining, 1024), 0, 133)
        put(w, CMP_SIDE, side + 1)
        put(w, CMP_INDEX, 0)
        return 0
    if phase == 133:
        target = choose(get(w, CMP_SIDE) == 0, get(w, TEMP_A), get(w, TEMP_B))
        index = 0
        reply_count = read64(s, 24)
        while index < reply_count:
            put32(w, target + (get(w, CMP_INDEX) + index) * 4, read32(s, 56 + index * 4))
            index = index + 1
        put(w, CMP_INDEX, get(w, CMP_INDEX) + index)
        put(w, PHASE, 132)
        return 0
    return 199

def number_top(w:mutbuf, record:u64) -> u64:
    kind = get(w, record + 16)
    value = get(w, record + 32)
    if kind == 1:
        return choose(value == 0, 0, 2048)
    if kind == 2:
        size = get(w, record + 24)
        return choose(size == 0, 0, size + 2047)
    magnitude = value & 9223372036854775807
    if magnitude == 0:
        return 0
    exponent = (magnitude >> 52) & 2047
    if exponent != 0:
        return exponent + 1025
    count = 0
    while magnitude != 0:
        magnitude = magnitude >> 1
        count = count + 1
    return count + 973

def number_sign(w:mutbuf, record:u64) -> u64:
    if number_top(w, record) == 0:
        return 0
    kind = get(w, record + 16)
    if kind == 3:
        return get(w, record + 32) >> 63
    return choose(kind == 2, get(w, record + 32), 0)

def number_bit(w:mutbuf, record:u64, base:u64, exponent:u64) -> u64:
    kind = get(w, record + 16)
    if kind == 1:
        return choose(exponent == 2048, get(w, record + 32), 0)
    if kind == 2:
        if exponent < 2048 or exponent - 2048 >= get(w, record + 24):
            return 0
        bit = exponent - 2048
        return (get32(w, base + (bit >> 5) * 4) >> (bit & 31)) & 1
    bits = get(w, record + 32)
    order = (bits >> 52) & 2047
    low = choose(order == 0, 974, order + 973)
    if exponent < low or exponent - low >= 53:
        return 0
    mantissa = bits & 4503599627370495
    if order != 0:
        mantissa = mantissa | 4503599627370496
    return (mantissa >> (exponent - low)) & 1

def numeric_less(w:mutbuf, left:u64, right:u64) -> u64:
    a = number_top(w, left)
    b = number_top(w, right)
    sa = number_sign(w, left)
    sb = number_sign(w, right)
    if sa != sb:
        return choose(sa != 0, 1, 0)
    if a != b:
        return choose(choose(sa == 0, a < b, a > b), 1, 0)
    if a == 0:
        return 1
    if get(w, left + 16) == 2 and get(w, right + 16) == 2:
        index = (get(w, left + 24) + 31) >> 5
        while index > 0:
            index = index - 1
            x = get32(w, get(w, TEMP_A) + index * 4)
            y = get32(w, get(w, TEMP_B) + index * 4)
            if x != y:
                return choose(choose(sa == 0, x < y, x > y), 1, 0)
        return 1
    exponent = a + 1
    while exponent > 974:
        exponent = exponent - 1
        x = number_bit(w, left, get(w, TEMP_A), exponent)
        y = number_bit(w, right, get(w, TEMP_B), exponent)
        if x != y:
            return choose(choose(sa == 0, x < y, x > y), 1, 0)
    return 1
'''


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node

    class FixedWordReads(ast.NodeTransformer):
        """Expand hot buffer-name/literal-address reads in place.

        Dynamic addresses retain their helpers. No read moves out of its
        expression or short-circuit branch, and bytes keep their original
        low-to-high order and individual bounds traps. Restrict this to the
        continuation receive/dispatch and observed string processing. Whole
        program expansion exceeds the unchanged assembly line budget, and
        expanding the one-time initialization as well exceeds the unchanged
        native compiler's per-function value-slot budget.
        """
        def visit_FunctionDef(self, node):
            if node.name in {'text_begin', 'text_byte', 'emit', 'commit_fragment', 'escaped'}:
                return self.generic_visit(node)
            if node.name == 'normalize':
                # The actual continuation profile identifies string replies
                # as the hot path. Keep all other normalization branches
                # byte-for-byte at the authoring-AST level.
                for statement in node.body:
                    if (isinstance(statement, ast.If)
                            and isinstance(statement.test, ast.Compare)
                            and ast.dump(statement.test, include_attributes=False) in {
                                ast.dump(ast.parse('phase == 30', mode='eval').body, include_attributes=False),
                                ast.dump(ast.parse('phase == 31', mode='eval').body, include_attributes=False),
                            }):
                        self.generic_visit(statement)
                return node
            if node.name != 'json_wire':
                return node
            initialization = None
            for statement in node.body:
                if (isinstance(statement, ast.If)
                        and ast.dump(statement.test, include_attributes=False) == ast.dump(
                            ast.parse('get(w, 0) == 0', mode='eval').body, include_attributes=False)):
                    if initialization is not None:
                        raise ValueError('ambiguous JSON wire initialization branch')
                    initialization = statement
            if initialization is None:
                raise ValueError('missing JSON wire initialization branch')
            body = []
            for statement in node.body:
                if statement is initialization:
                    statement.test = self.visit(statement.test)
                    statement.orelse = [self.visit(child) for child in statement.orelse]
                    body.append(statement)
                else:
                    body.append(self.visit(statement))
            node.body = body
            return node

        def visit_Call(self, node):
            node = self.generic_visit(node)
            widths = {'get': 8, 'read64': 8, 'get32': 4, 'read32': 4}
            if (not isinstance(node.func, ast.Name) or node.func.id not in widths
                    or len(node.args) != 2 or node.keywords
                    or not isinstance(node.args[0], ast.Name)
                    or not isinstance(node.args[1], ast.Constant)
                    or type(node.args[1].value) is not int):
                return node
            width = widths[node.func.id]
            offset = node.args[1].value
            if not 0 <= offset <= (1 << 64) - width:
                return node
            value = ast.Constant(0)
            for index in range(width):
                address = ast.Constant(offset + index)
                byte = ast.Call(ast.Name('byte', ast.Load()),
                                [ast.Name(node.args[0].id, ast.Load()), address], [])
                shifted = ast.BinOp(byte, ast.LShift(), ast.Constant(index * 8))
                value = ast.BinOp(value, ast.BitOr(), shifted)
            return ast.copy_location(value, node)

    class FixedWordStores(ast.NodeTransformer):
        """Inline ignored fixed-field stores in the observed hot helpers.

        Evaluate the value once before the first byte, as the original call
        does, then keep all eight byte writes and their partial-store traps
        in low-to-high order. Dynamic addresses and value-returning calls
        retain the original helper. This is a call expansion, not a state
        cache or a combined foreign observation.
        """
        def visit_FunctionDef(self, node):
            if node.name not in {'ask', 'text_byte', 'emit'}:
                return node
            self.names = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
            self.counter = 0
            return self.generic_visit(node)

        def visit_Expr(self, node):
            node = self.generic_visit(node)
            call = node.value
            if (not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name)
                    or call.func.id != 'put' or len(call.args) != 3 or call.keywords
                    or not isinstance(call.args[0], ast.Name)
                    or not isinstance(call.args[1], ast.Constant)
                    or type(call.args[1].value) is not int
                    or not 0 <= call.args[1].value <= (1 << 64) - 8):
                return node
            while True:
                name = 'wire_store_value_' + str(self.counter)
                self.counter += 1
                if name not in self.names:
                    self.names.add(name)
                    break
            result = [ast.Assign([ast.Name(name, ast.Store())], call.args[2])]
            for index in range(8):
                shifted = ast.BinOp(ast.Name(name, ast.Load()), ast.RShift(), ast.Constant(index * 8))
                value = ast.BinOp(shifted, ast.BitAnd(), ast.Constant(255))
                result.append(ast.Expr(ast.Call(ast.Name('store', ast.Load()),
                    [ast.Name(call.args[0].id, ast.Load()), ast.Constant(call.args[1].value + index), value], [])))
            return [ast.copy_location(statement, node) for statement in result]

    tree = Constants().visit(ast.parse(SOURCE + ENCODER))
    tree = FixedWordReads().visit(tree)
    tree = FixedWordStores().visit(tree)
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n' + format_program()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate HIA wire authoring symbol')
    signatures = {n.name: ([arg.annotation.id for arg in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        b = Builder(node, names, signatures, total)
        b.statements(node.body)
        functions.append({'name': names[node.name], 'params': [b.param(v) for v in b.params],
                          'returns': [b.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'json_wire', 'functions': functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
