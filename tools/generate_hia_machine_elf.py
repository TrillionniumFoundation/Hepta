"""HIA ELF ET_REL validation, stable sort, layout and byte construction.

Reconstructed from fixed peer inputs and independently revised. HIA owns every
policy branch and physical-operation claim. CPython-specific object primitives
remain explicit; the HIA Powersort kernel follows version-tagged original run
and merge schedules. Development evidence is not whole-source qualification.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.hia_machine_elf_sort import BODY as SORT_BODY, FIELDS as SORT_FIELDS
from tools.hia_exception_delivery import BODY as EXCEPTION_DELIVERY_BODY
from tools.generate_hia_selfhost import (
    Builder, compact_authoring_cfg, total_scalar_functions)

CONSTANTS = {
    'MAGIC': 3544410200133945672,
    'INIT_MAGIC': 3616471092706756936,
    'CLAIM_MAGIC': 3616464495636990280,
    'NONCE': 680,
    'CONSUME': 688,
    'DEAD': 696,
    'FOREIGN_ERROR': 720,
    'ABI': 4294967293,
    'BAD': 2147483648,
    'MAX_BYTES': 67108864,
    'PHASE': 8,
    'SEQ': 16,
    'PENDING': 24,
    'REQ': 32,
    'ACK': 72,
    'NEED': 80,
    'RESULT': 88,
    'ALIGN': 104,
    'CODELEN': 112,
    'SYMARG': 120,
    'RELARG': 128,
    'ITER': 136,
    'ROW': 144,
    'NAME': 152,
    'DEFS': 160,
    'DEFTAIL': 168,
    'NDEF': 176,
    'RELS': 184,
    'RELTAIL': 192,
    'NREL': 200,
    'NUNDEF': 208,
    'NNAMES': 216,
    'NAMES': 224,
    'NAMETAIL': 232,
    'ARENA': 240,
    'SORT_KIND': 248,
    'SORT_RET': 256,
    'SORT_ARRAY': 264,
    'SORT_TMP': 272,
    'SORT_N': 280,
    'SORT_WIDTH': 288,
    'SORT_LEFT': 296,
    'SORT_I': 304,
    'SORT_J': 312,
    'SORT_MID': 320,
    'SORT_END': 328,
    'SORT_K': 336,
    'SORT_WAIT': 344,
    'ARRAY': 352,
    'INDEX': 360,
    'CURRENT': 368,
    'LOCAL_ARRAY': 376,
    'LOCAL_N': 384,
    'PUBLIC_ARRAY': 392,
    'PUBLIC_N': 400,
    'NAME_ARRAY': 408,
    'STRTAB': 416,
    'STRSIZE': 424,
    'SYMTAB': 432,
    'SYMSIZE': 440,
    'RELATAB': 448,
    'RELASIZE': 456,
    'INFO': 464,
    'VIS': 472,
    'VALUE': 480,
    'TMP': 488,
    'NODE': 496,
    'FACT': 512,
    'S0': 768,
    'S1': 1600,
    'S2': 2432,
    'BUCKETS': 4096,
    'POOL': 528384,
    'ELF_IDENT': 282584257676671,
    'SECTION_NAMES_LENGTH': 60,
    'TEXT_NAME': 1,
    'RELA_NAME': 7,
    'SYM_NAME': 18,
    'STR_NAME': 26,
    'SHSTR_NAME': 34,
    'STACK_NAME': 44,
}

CONSTANTS.update(SORT_FIELDS)

SOURCE = r'''

def machine_elf(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) == 128:
        return emit_exception_delivery(s, o, w)
    if length(w) < 4096 or length(o) < 64:
        return ABI
    if get(w, 0) == 0:
        if length(s) != 24 or read_small(s, 0, 8) != INIT_MAGIC or read_small(s, 8, 8) == 0:
            put(w, DEAD, 1)
            return ABI
        version = read_small(s, 16, 8)
        if version != 312 and version != 313 and version != 314:
            put(w, DEAD, 1)
            return ABI
        put(w, SORT_VERSION, version)
        put(w, NONCE, read_small(s, 8, 8))
        put(w, 0, MAGIC)
        put(w, PHASE, 1)
    if get(w, 0) != MAGIC or get(w, DEAD) != 0:
        return ABI
    if get(w, PENDING) == 1:
        valid = length(s) == 72
        if valid:
            valid = read_small(s, 0, 8) == CLAIM_MAGIC and read_small(s, 8, 8) == get(w, NONCE) and read_small(s, 16, 8) == get(w, SEQ)
        index = 0
        while valid and index < 5:
            valid = read_small(s, 24 + index * 8, 8) == get(w, REQ + index * 8)
            index = index + 1
        if valid:
            valid = read_small(s, 64, 8) == get(w, CONSUME)
        if valid == False:
            put(w, DEAD, 1)
            return ABI
        put(w, PENDING, 2)
        return 5
    if get(w, PENDING) == 2:
        if get(w, ACK) != get(w, SEQ):
            put(w, DEAD, 1)
            return ABI
        put(w, PENDING, 0)
        if get(w, FOREIGN_ERROR) != 0:
            put(w, DEAD, 1)
            if get(w, FOREIGN_ERROR) == 1:
                return 6
            return ABI
    elif get(w, ACK) != get(w, SEQ) or get(w, PENDING) != 0:
        put(w, DEAD, 1)
        return ABI
    status = 4
    while status == 4:
        phase = get(w, PHASE)
        if phase < 30:
            status = admission(s, w, phase)
        elif phase < 40:
            status = spans(s, w, phase)
        elif phase < 100:
            status = relocations(s, w, phase)
        elif phase < 150:
            status = filter_symbols(s, w, phase)
        elif phase < 210:
            status = tables(s, w, phase)
        elif phase < 220:
            status = output(s, o, w, phase)
        elif phase == 900:
            status = sorting(s, w)
        else:
            status = ABI
    if status != 1 and status != 2 and status != 3:
        put(w, DEAD, 1)
    return status

def request(w:mutbuf, op:u64, a:u64, b:u64, c:u64, d:u64, next_phase:u64) -> u64:
    if get(w, SEQ) == 18446744073709551615:
        return ABI
    put(w, CONSUME, choose(op == 5, 1, 0))
    put(w, REQ, op)
    put(w, REQ + 8, a)
    put(w, REQ + 16, b)
    put(w, REQ + 24, c)
    put(w, REQ + 32, d)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, PENDING, 1)
    put(w, PHASE, next_phase)
    return 1

def advance(w:mutbuf, next_phase:u64) -> u64:
    put(w, PHASE, next_phase)
    return 4

def reserve(w:mutbuf, n:u64) -> u64:
    at = get(w, ARENA)
    end = at + n
    if end < at:
        put(w, NEED, 18446744073709551615)
        return 0
    if end > length(w):
        put(w, NEED, end)
        return 0
    put(w, ARENA, end)
    return at

def fact(w:mutbuf, index:u64, offset:u64) -> u64:
    return get(w, FACT + index * 56 + offset)

def exact(w:mutbuf, index:u64, lower:u64, upper:u64) -> u64:
    return choose(fact(w, index, 0) == 1 and fact(w, index, 16) == 0 and fact(w, index, 8) >= lower and fact(w, index, 8) < upper, 1, 0)

def stash(s:readbuf, w:mutbuf, index:u64, at:u64) -> u64:
    kind = fact(w, index, 0)
    n = fact(w, index, 48)
    start = fact(w, index, 40)
    if kind == 0 or kind > 9 or n > 193 or start > length(s) or n * 4 > length(s) - start:
        return 0
    put(w, at, kind)
    put(w, at + 8, fact(w, index, 8))
    put(w, at + 16, choose(kind == 3, n, fact(w, index, 16)))
    put(w, at + 24, fact(w, index, 24))
    put(w, at + 32, fact(w, index, 32))
    put(w, at + 40, at + 48)
    if n != 0:
        copy_read(w, at + 48, s, start, n * 4)
    return 1

def atom_size(w:mutbuf, at:u64) -> u64:
    return 48 + choose(get(w, at) == 3, get(w, at + 16) * 4, 0)

def copy_atom(w:mutbuf, dest:u64, src:u64) -> u64:
    copy_work(w, dest, w, src, atom_size(w, src))
    put(w, dest + 40, dest + 48)
    return 0

def number(w:mutbuf, at:u64, value:u64) -> u64:
    fill_range(w, at, 48, 0)
    put(w, at, 1)
    put(w, at + 8, value)
    return 0

def truth(w:mutbuf, at:u64) -> u64:
    kind = get(w, at)
    if kind == 1 or kind == 2:
        return choose(get(w, at + 8) != 0 or (get(w, at + 16) & 2) != 0, 1, 0)
    if kind >= 3 and kind <= 6:
        return choose(get(w, at + 24) != 0, 1, 0)
    return 2

def compare_atom(w:mutbuf, a:u64, b:u64) -> u64:
    ka = get(w, a)
    kb = get(w, b)
    if (ka == 1 or ka == 2) and (kb == 1 or kb == 2):
        fa = get(w, a + 16)
        fb = get(w, b + 16)
        if (fa & 2) != 0 or (fb & 2) != 0:
            return 2
        if (fa & 1) != (fb & 1):
            return fa & 1
        va = get(w, a + 8)
        vb = get(w, b + 8)
        return choose((fa & 1) == 0, choose(va < vb, 1, 0), choose(va > vb, 1, 0))
    if ka == 3 and kb == 3:
        na = get(w, a + 24)
        nb = get(w, b + 24)
        if get(w, a + 16) != na or get(w, b + 16) != nb:
            return 2
        i = 0
        while i < na and i < nb:
            va = small(w, a + 48 + i * 4, 4)
            vb = small(w, b + 48 + i * 4, 4)
            if va != vb:
                return choose(va < vb, 1, 0)
            i = i + 1
        return choose(na < nb, 1, 0)
    return 2

def sum_atoms(w:mutbuf, a:u64, b:u64, dest:u64) -> u64:
    if get(w, a) != 1 or get(w, b) != 1 or get(w, a + 16) != 0 or get(w, b + 16) != 0:
        return 0
    left = get(w, a + 8)
    right = get(w, b + 8)
    if left + right < left:
        return 0
    number(w, dest, left + right)
    return 1

def name_valid(s:readbuf, w:mutbuf) -> u64:
    n = fact(w, 0, 24)
    at = fact(w, 0, 40)
    if fact(w, 0, 0) != 3 or n == 0 or n > 192 or fact(w, 0, 48) != n or at > length(s) or n * 4 > length(s) - at:
        return 0
    i = 0
    while i < n:
        ch = read_small(s, at + i * 4, 4)
        letter = (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95
        if i == 0 and letter == False:
            return 0
        if letter == False and (ch < 48 or ch > 57):
            return 0
        i = i + 1
    return 1

def name_intern(s:readbuf, w:mutbuf) -> u64:
    n = fact(w, 0, 24)
    start = fact(w, 0, 40)
    hash_value = 14695981039346656037
    i = 0
    while i < n:
        hash_value = (hash_value ^ byte(s, start + i * 4)) * 1099511628211
        i = i + 1
    slot = BUCKETS + (hash_value & 65535) * 8
    node = get(w, slot)
    while node != 0:
        same = get(w, node + 24) == n and get(w, node + 32) == hash_value
        i = 0
        while same and i < n:
            same = byte(w, node + 64 + i) == byte(s, start + i * 4)
            i = i + 1
        if same:
            return node
        node = get(w, node + 8)
    size = (64 + n + 8) & 18446744073709551608
    node = reserve(w, size)
    if node == 0:
        return 0
    fill_range(w, node, size, 0)
    put(w, node + 8, get(w, slot))
    put(w, slot, node)
    put(w, node + 24, n)
    put(w, node + 32, hash_value)
    put(w, node + 56, fact(w, 0, 32))
    i = 0
    while i < n:
        store(w, node + 64 + i, byte(s, start + i * 4))
        i = i + 1
    if get(w, NAMES) == 0:
        put(w, NAMES, node)
    else:
        put(w, get(w, NAMETAIL), node)
    put(w, NAMETAIL, node)
    put(w, NNAMES, get(w, NNAMES) + 1)
    put(w, STRSIZE, get(w, STRSIZE) + n + 1)
    return node

def name_atom(w:mutbuf, node:u64, at:u64) -> u64:
    fill_range(w, at, 48, 0)
    put(w, at, 3)
    put(w, at + 24, get(w, node + 24))
    put(w, at + 32, get(w, node + 56))
    return 0

def record_keys(s:readbuf, w:mutbuf, relocation:u64) -> u64:
    if fact(w, 0, 0) != 9 or fact(w, 0, 24) != 4:
        return 0
    seen = 0
    i = 0
    at = 0
    foreign = 0
    invalid = 0
    while i < 4:
        if at > length(s) or 24 > length(s) - at:
            return 0
        kind = read_word(s, at)
        n = read_word(s, at + 8)
        count = read_word(s, at + 16)
        at = at + 24
        if count > 8 or count * 4 > length(s) - at:
            return 0
        if kind != 3:
            foreign = 1
        else:
            key = key_id(s, at, n, count)
            if key == 0:
                invalid = 1
            else:
                seen = seen | (1 << key)
        at = at + count * 4
        i = i + 1
    if foreign != 0:
        return 2
    return choose(invalid == 0 and seen == choose(relocation == 0, 30, 228), 1, 0)

def key_id(s:readbuf, at:u64, n:u64, count:u64) -> u64:
    if n != count:
        return 0
    value = 0
    i = 0
    while i < n:
        ch = read_small(s, at + i * 4, 4)
        if ch > 127:
            return 0
        value = value | (ch << (i * 8))
        i = i + 1
    if n == 4 and value == 1701667182:
        return 1
    if n == 6 and value == 127979076609647:
        return 2
    if n == 4 and value == 1702521203:
        return 3
    if n == 6 and value == 119165519096935:
        return 4
    if n == 6 and value == 119225648511347:
        return 5
    if n == 4 and value == 1701869940:
        return 6
    if n == 6 and value == 110425310258273:
        return 7
    return 0

def admission(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return request(w, 1, 1, 0, 0, 0, 2)
    if phase == 2:
        n = fact(w, 0, 8)
        if fact(w, 0, 0) != 1 or fact(w, 0, 16) != 0 or (n != 16 and n != 32 and n != 64):
            return BAD + 1
        put(w, ALIGN, n)
        return request(w, 1, 2, 0, 0, 0, 3)
    if phase == 3:
        n = fact(w, 0, 24)
        if fact(w, 0, 0) != 4 or n == 0 or n > MAX_BYTES:
            return BAD + 2
        put(w, CODELEN, n)
        return request(w, 1, 3, 0, 0, 0, 4)
    if phase == 4:
        n = fact(w, 0, 24)
        if fact(w, 0, 0) != 5 or n == 0 or n >= 65536:
            return BAD + 3
        put(w, SYMARG, fact(w, 0, 32))
        return request(w, 1, 4, 0, 0, 0, 5)
    if phase == 5:
        if fact(w, 0, 0) != 5 or fact(w, 0, 24) > div5(get(w, CODELEN)):
            return BAD + 3
        put(w, RELARG, fact(w, 0, 32))
        return advance(w, 6)
    if phase == 6:
        if length(w) < POOL:
            put(w, NEED, POOL)
            return 2
        fill_range(w, BUCKETS, POOL - BUCKETS, 0)
        put(w, ARENA, POOL)
        put(w, STRSIZE, 1)
        return request(w, 2, get(w, SYMARG), 0, 0, 0, 10)
    if phase == 10:
        put(w, ITER, fact(w, 0, 32))
        return request(w, 3, get(w, ITER), 0, 0, 0, 11)
    if phase == 11:
        if fact(w, 0, 0) == 0:
            put(w, CURRENT, get(w, DEFS))
            return advance(w, 30)
        if fact(w, 0, 0) != 6:
            return BAD + 4
        put(w, ROW, fact(w, 0, 32))
        return request(w, 4, get(w, ROW), 0, 0, 0, 12)
    if phase == 12:
        keys = record_keys(s, w, 0)
        if keys == 0:
            return BAD + 4
        if keys == 2:
            return request(w, 5, fact(w, 0, 32), 0, 0, 0, 13)
        return request(w, 6, get(w, ROW), 1, 0, 0, 14)
    if phase == 13:
        if fact(w, 0, 8) != 0:
            return BAD + 4
        return request(w, 6, get(w, ROW), 1, 0, 0, 14)
    if phase == 14:
        if name_valid(s, w) == 0:
            return BAD + 5
        node = name_intern(s, w)
        if node == 0:
            return 2
        if (get(w, node + 16) & 1) != 0:
            return BAD + 6
        put(w, NAME, node)
        return request(w, 6, get(w, ROW), 4, 0, 0, 15)
    if phase == 15:
        if fact(w, 0, 0) != 2:
            return BAD + 6
        return request(w, 6, get(w, ROW), 2, 0, 0, 16)
    if phase == 16:
        if exact(w, 0, 0, get(w, CODELEN)) == 0:
            return BAD + 6
        return request(w, 6, get(w, ROW), 3, 0, 0, 17)
    if phase == 17:
        if exact(w, 0, 1, get(w, CODELEN) + 1) == 0:
            return BAD + 6
        return request(w, 6, get(w, ROW), 2, 3, 0, 18)
    if phase == 18:
        if stash(s, w, 0, S0) == 0 or stash(s, w, 1, S1) == 0:
            return ABI
        if sum_atoms(w, S0, S1, S2) == 0:
            return request(w, 9, S0, S1, 0, 0, 19)
        return advance(w, 21)
    if phase == 19:
        if stash(s, w, 0, S2) == 0:
            return ABI
        return advance(w, 21)
    if phase == 21:
        number(w, S1, get(w, CODELEN))
        comparison = compare_atom(w, S1, S2)
        if comparison == 2:
            return request(w, 10, S2, S1, 1, 0, 22)
        if comparison == 1:
            return BAD + 6
        return advance(w, 23)
    if phase == 22:
        if fact(w, 0, 8) != 0:
            return BAD + 6
        return advance(w, 23)
    if phase == 23:
        node = get(w, NAME)
        put(w, node + 16, get(w, node + 16) | 1)
        return request(w, 7, get(w, ROW), 0, 0, 0, 20)
    if phase == 20:
        node = reserve(w, 64)
        if node == 0:
            return 2
        fill_range(w, node, 64, 0)
        put(w, node + 8, fact(w, 0, 32))
        put(w, node + 16, get(w, NAME))
        if get(w, DEFS) == 0:
            put(w, DEFS, node)
        else:
            put(w, get(w, DEFTAIL), node)
        put(w, DEFTAIL, node)
        put(w, NDEF, get(w, NDEF) + 1)
        return request(w, 3, get(w, ITER), 0, 0, 0, 11)
    return ABI


def spans(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 30:
        node = get(w, CURRENT)
        if node == 0:
            return sort_list(w, get(w, DEFS), get(w, NDEF), 1, 35)
        return request(w, 6, get(w, node + 8), 2, 2, 3, 31)
    if phase == 31:
        if stash(s, w, 0, S0) == 0 or stash(s, w, 1, S1) == 0 or stash(s, w, 2, S2) == 0:
            return ABI
        if sum_atoms(w, S1, S2, S1) == 0:
            return request(w, 9, S1, S2, 0, 0, 32)
        return advance(w, 33)
    if phase == 32:
        if stash(s, w, 0, S1) == 0:
            return ABI
        return advance(w, 33)
    if phase == 33:
        na = atom_size(w, S0)
        nb = atom_size(w, S1)
        area = reserve(w, na + nb)
        if area == 0:
            return 2
        copy_atom(w, area, S0)
        copy_atom(w, area + na, S1)
        node = get(w, CURRENT)
        put(w, node + 24, area)
        put(w, node + 32, area + na)
        put(w, CURRENT, get(w, node))
        return advance(w, 30)
    if phase == 35:
        put(w, ARRAY, get(w, SORT_ARRAY))
        put(w, INDEX, 1)
        return advance(w, 36)
    if phase == 36:
        i = get(w, INDEX)
        if i >= get(w, NDEF):
            return request(w, 2, get(w, RELARG), 0, 0, 0, 40)
        left = get(w, get(w, ARRAY) + (i - 1) * 8)
        right = get(w, get(w, ARRAY) + i * 8)
        a = get(w, right + 24)
        b = get(w, left + 32)
        comparison = compare_atom(w, a, b)
        if comparison == 2:
            return request(w, 10, a, b, 0, 0, 37)
        if comparison != 0:
            return BAD + 7
        put(w, INDEX, i + 1)
        return 4
    if phase == 37:
        if fact(w, 0, 8) != 0:
            return BAD + 7
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 36)
    return ABI

def relocations(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 40:
        put(w, ITER, fact(w, 0, 32))
        return request(w, 3, get(w, ITER), 0, 0, 0, 41)
    if phase == 41:
        if fact(w, 0, 0) == 0:
            put(w, CURRENT, get(w, RELS))
            return advance(w, 70)
        if fact(w, 0, 0) != 6:
            return BAD + 8
        put(w, ROW, fact(w, 0, 32))
        return request(w, 4, get(w, ROW), 0, 0, 0, 42)
    if phase == 42:
        keys = record_keys(s, w, 1)
        if keys == 0:
            return BAD + 8
        if keys == 2:
            return request(w, 5, fact(w, 0, 32), 1, 0, 0, 43)
        return request(w, 6, get(w, ROW), 2, 0, 0, 44)
    if phase == 43:
        if fact(w, 0, 8) != 0:
            return BAD + 8
        return request(w, 6, get(w, ROW), 2, 0, 0, 44)
    if phase == 44:
        if get(w, CODELEN) <= 4 or exact(w, 0, 1, get(w, CODELEN) - 3) == 0:
            return BAD + 8
        return request(w, 6, get(w, ROW), 6, 0, 0, 45)
    if phase == 45:
        if fact(w, 0, 0) != 1:
            return BAD + 8
        return request(w, 6, get(w, ROW), 6, 0, 0, 46)
    if phase == 46:
        if fact(w, 0, 0) == 1:
            if fact(w, 0, 16) != 0 or fact(w, 0, 8) != 4:
                return BAD + 8
            return request(w, 6, get(w, ROW), 7, 0, 0, 48)
        if stash(s, w, 0, S0) == 0:
            return ABI
        number(w, S1, 4)
        return request(w, 10, S0, S1, 4, 0, 47)
    if phase == 47:
        if fact(w, 0, 8) != 0:
            return BAD + 8
        return request(w, 6, get(w, ROW), 7, 0, 0, 48)
    if phase == 48:
        if fact(w, 0, 0) != 1:
            return BAD + 8
        return request(w, 6, get(w, ROW), 7, 0, 0, 49)
    if phase == 49:
        if fact(w, 0, 0) == 1:
            if fact(w, 0, 16) != 1 or fact(w, 0, 8) != 4:
                return BAD + 8
            return request(w, 6, get(w, ROW), 5, 0, 0, 51)
        if stash(s, w, 0, S0) == 0:
            return ABI
        number(w, S1, 4)
        put(w, S1 + 16, 1)
        return request(w, 10, S0, S1, 4, 0, 50)
    if phase == 50:
        if fact(w, 0, 8) != 0:
            return BAD + 8
        return request(w, 6, get(w, ROW), 5, 0, 0, 51)
    if phase == 51:
        if name_valid(s, w) == 0:
            return BAD + 5
        node = name_intern(s, w)
        if node == 0:
            return 2
        put(w, NAME, node)
        return request(w, 6, get(w, ROW), 2, 0, 0, 52)
    if phase == 52:
        if stash(s, w, 0, S0) == 0:
            return ABI
        if get(w, S0) == 1 and get(w, S0 + 16) == 0 and get(w, S0 + 8) != 0:
            number(w, S1, get(w, S0 + 8) - 1)
            return request(w, 13, S1, 0, 0, 0, 54)
        number(w, S1, 1)
        return request(w, 9, S0, S1, 1, 0, 53)
    if phase == 53:
        if stash(s, w, 0, S1) == 0:
            return ABI
        return request(w, 13, S1, 0, 0, 0, 54)
    if phase == 54:
        if fact(w, 0, 0) != 1 or fact(w, 0, 8) != 232:
            return BAD + 9
        number(w, S1, 4)
        if sum_atoms(w, S0, S1, S1) != 0:
            return request(w, 14, S0, S1, 0, 0, 56)
        return request(w, 9, S0, S1, 0, 0, 55)
    if phase == 55:
        if stash(s, w, 0, S1) == 0:
            return ABI
        return request(w, 14, S0, S1, 0, 0, 56)
    if phase == 56:
        if fact(w, 0, 0) != 4 or fact(w, 0, 24) != 4 or length(s) != 4:
            return BAD + 9
        if read_small(s, 0, 4) != 0:
            return BAD + 9
        return request(w, 7, get(w, ROW), 0, 0, 0, 57)
    if phase == 57:
        node = reserve(w, 64)
        if node == 0:
            return 2
        fill_range(w, node, 64, 0)
        put(w, node + 8, fact(w, 0, 32))
        if get(w, RELS) == 0:
            put(w, RELS, node)
        else:
            put(w, get(w, RELTAIL), node)
        put(w, RELTAIL, node)
        put(w, NREL, get(w, NREL) + 1)
        name = get(w, NAME)
        flags = get(w, name + 16)
        if flags == 0:
            put(w, name + 16, 2)
            put(w, NUNDEF, get(w, NUNDEF) + 1)
        return request(w, 3, get(w, ITER), 0, 0, 0, 41)
    if phase == 70:
        node = get(w, CURRENT)
        if node == 0:
            return sort_list(w, get(w, RELS), get(w, NREL), 2, 72)
        return request(w, 6, get(w, node + 8), 2, 0, 0, 71)
    if phase == 71:
        if stash(s, w, 0, S0) == 0:
            return ABI
        area = reserve(w, atom_size(w, S0))
        if area == 0:
            return 2
        copy_atom(w, area, S0)
        node = get(w, CURRENT)
        put(w, node + 24, area)
        put(w, CURRENT, get(w, node))
        return advance(w, 70)
    if phase == 72:
        put(w, ARRAY, get(w, SORT_ARRAY))
        put(w, INDEX, 1)
        return advance(w, 73)
    if phase == 73:
        i = get(w, INDEX)
        if i >= get(w, NREL):
            if get(w, NNAMES) + 2 > 65536:
                return BAD + 11
            put(w, RELS, get(w, ARRAY))
            return advance(w, 100)
        node = get(w, get(w, ARRAY) + i * 8)
        return request(w, 6, get(w, node + 8), 2, 0, 0, 74)
    if phase == 74:
        if stash(s, w, 0, S0) == 0:
            return ABI
        node = get(w, get(w, ARRAY) + (get(w, INDEX) - 1) * 8)
        return request(w, 6, get(w, node + 8), 2, 0, 0, 75)
    if phase == 75:
        if stash(s, w, 0, S1) == 0:
            return ABI
        if get(w, S0) == 1 and get(w, S1) == 1 and get(w, S0 + 16) == 0 and get(w, S1 + 16) == 0:
            right = get(w, S0 + 8)
            left = get(w, S1 + 8)
            if right < left or right - left < 5:
                return BAD + 10
            put(w, INDEX, get(w, INDEX) + 1)
            return advance(w, 73)
        return request(w, 9, S0, S1, 1, 0, 76)
    if phase == 76:
        if stash(s, w, 0, S0) == 0:
            return ABI
        number(w, S1, 5)
        comparison = compare_atom(w, S0, S1)
        if comparison == 2:
            return request(w, 10, S0, S1, 0, 0, 77)
        if comparison != 0:
            return BAD + 10
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 73)
    if phase == 77:
        if fact(w, 0, 8) != 0:
            return BAD + 10
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 73)
    return ABI

def sort_list(w:mutbuf, head:u64, n:u64, kind:u64, ret:u64) -> u64:
    area = reserve(w, n * 16 + 2048)
    if area == 0:
        return 2
    i = 0
    node = head
    while i < n:
        if node == 0:
            return ABI
        put(w, area + i * 8, node)
        node = get(w, node)
        i = i + 1
    if node != 0:
        return ABI
    return sort_start(w, area, area + n * 8, n, kind, ret)

def sort_compare(w:mutbuf, a:u64, b:u64, kind:u64) -> u64:
    if kind == 4:
        na = get(w, a + 24)
        nb = get(w, b + 24)
        i = 0
        while i < na and i < nb:
            ca = byte(w, a + 64 + i)
            cb = byte(w, b + 64 + i)
            if ca != cb:
                return choose(ca < cb, 1, 0)
            i = i + 1
        return choose(na < nb, 1, 0)
    if kind != 1:
        offset = choose(kind == 2, 24, 40)
        return compare_atom(w, get(w, a + offset), get(w, b + offset))
    aa = get(w, a + 24)
    ba = get(w, b + 24)
    if get(w, aa + 32) != 0 and get(w, aa + 32) == get(w, ba + 32):
        return compare_atom(w, get(w, a + 32), get(w, b + 32))
    first = compare_atom(w, aa, ba)
    if first != 0:
        return first
    other = compare_atom(w, ba, aa)
    if other == 2:
        return 2
    if other != 0:
        return 0
    return compare_atom(w, get(w, a + 32), get(w, b + 32))

def filter_symbols(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 100 or phase == 106:
        area = reserve(w, get(w, NDEF) * 16 + 2048)
        if area == 0:
            return 2
        if phase == 106:
            put(w, LOCAL_ARRAY, get(w, SORT_ARRAY))
            put(w, LOCAL_N, get(w, SORT_N))
        put(w, VIS, choose(phase == 100, 0, 1))
        put(w, ARRAY, area)
        put(w, TMP, 0)
        put(w, CURRENT, get(w, DEFS))
        return advance(w, 101)
    if phase == 101:
        node = get(w, CURRENT)
        if node == 0:
            put(w, INDEX, 0)
            return advance(w, 108)
        return request(w, 6, get(w, node + 8), 4, 0, 0, 102)
    if phase == 102:
        if stash(s, w, 0, S0) == 0:
            return ABI
        value = truth(w, S0)
        if value == 2:
            return request(w, 8, S0, 0, 0, 0, 103)
        put(w, INFO, value)
        return advance(w, 104)
    if phase == 103:
        put(w, INFO, fact(w, 0, 8))
        return advance(w, 104)
    if phase == 104:
        node = get(w, CURRENT)
        if get(w, INFO) == get(w, VIS):
            put(w, get(w, ARRAY) + get(w, TMP) * 8, node)
            put(w, TMP, get(w, TMP) + 1)
        put(w, CURRENT, get(w, node))
        return advance(w, 101)
    if phase == 108:
        index = get(w, INDEX)
        if index >= get(w, TMP):
            ret = choose(get(w, VIS) == 0, 106, 107)
            return sort_start(w, get(w, ARRAY), get(w, ARRAY) + get(w, NDEF) * 8, get(w, TMP), 3, ret)
        node = get(w, get(w, ARRAY) + index * 8)
        put(w, CURRENT, node)
        return request(w, 6, get(w, node + 8), 1, 0, 0, 109)
    if phase == 109:
        if stash(s, w, 0, S0) == 0:
            return ABI
        area = reserve(w, atom_size(w, S0))
        if area == 0:
            return 2
        copy_atom(w, area, S0)
        node = get(w, CURRENT)
        put(w, node + 40, area)
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 108)
    if phase == 107:
        put(w, PUBLIC_ARRAY, get(w, SORT_ARRAY))
        put(w, PUBLIC_N, get(w, SORT_N))
        return sort_list(w, get(w, NAMES), get(w, NNAMES), 4, 150)
    return ABI

def tables(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 150:
        string_size = (get(w, STRSIZE) + 7) & 18446744073709551608
        symbol_size = (get(w, LOCAL_N) + get(w, PUBLIC_N) + get(w, NUNDEF) + 2) * 24
        rela_size = get(w, NREL) * 24
        area = reserve(w, string_size + symbol_size + rela_size)
        if area == 0:
            return 2
        fill_range(w, area, string_size + symbol_size + rela_size, 0)
        put(w, NAME_ARRAY, get(w, SORT_ARRAY))
        put(w, STRTAB, area)
        put(w, SYMTAB, area + string_size)
        put(w, SYMSIZE, symbol_size)
        put(w, RELATAB, area + string_size + symbol_size)
        put(w, RELASIZE, rela_size)
        store(w, area + string_size + 28, 3)
        little(w, area + string_size + 30, 1, 2)
        put(w, INDEX, 0)
        put(w, TMP, 1)
        return advance(w, 151)
    if phase == 151:
        index = get(w, INDEX)
        if index >= get(w, NNAMES):
            if get(w, TMP) != get(w, STRSIZE):
                return ABI
            put(w, INDEX, 0)
            put(w, VALUE, 2)
            return advance(w, 160)
        node = get(w, get(w, NAME_ARRAY) + index * 8)
        put(w, NODE, node)
        put(w, node + 40, get(w, TMP))
        name_atom(w, node, S0)
        return request(w, 11, 0, S0, get(w, TMP), 0, 152)
    if phase == 152:
        node = get(w, NODE)
        n = get(w, node + 24)
        copy_work(w, get(w, STRTAB) + get(w, TMP), w, node + 64, n)
        put(w, TMP, get(w, TMP) + n + 1)
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 151)
    if phase >= 160 and phase < 180:
        return defined_symbols(s, w, phase)
    if phase == 180:
        index = get(w, INDEX)
        if index >= get(w, NNAMES):
            if get(w, VALUE) * 24 != get(w, SYMSIZE):
                return ABI
            put(w, INDEX, 0)
            return advance(w, 190)
        node = get(w, get(w, NAME_ARRAY) + index * 8)
        if (get(w, node + 16) & 2) == 0:
            put(w, INDEX, index + 1)
            return 4
        put(w, NODE, node)
        name_atom(w, node, S0)
        return request(w, 11, 1, S0, get(w, VALUE), 0, 181)
    if phase == 181:
        at = get(w, SYMTAB) + get(w, VALUE) * 24
        little(w, at, get(w, get(w, NODE) + 40), 4)
        store(w, at + 4, 16)
        put(w, VALUE, get(w, VALUE) + 1)
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 180)
    if phase >= 190 and phase < 200:
        return relocation_table(s, w, phase)
    return ABI

def defined_symbols(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 160:
        index = get(w, INDEX)
        local_count = get(w, LOCAL_N)
        if index >= local_count + get(w, PUBLIC_N):
            put(w, INDEX, 0)
            return advance(w, 180)
        if index < local_count:
            node = get(w, get(w, LOCAL_ARRAY) + index * 8)
        else:
            node = get(w, get(w, PUBLIC_ARRAY) + (index - local_count) * 8)
        put(w, ROW, get(w, node + 8))
        return request(w, 6, get(w, ROW), 1, 0, 0, 161)
    if phase == 161:
        if stash(s, w, 0, S0) == 0:
            return ABI
        return request(w, 11, 1, S0, get(w, VALUE), 0, 162)
    if phase == 162:
        return request(w, 6, get(w, ROW), 4, 0, 0, 163)
    if phase == 163:
        if stash(s, w, 0, S0) == 0:
            return ABI
        value = truth(w, S0)
        if value == 2:
            return request(w, 8, S0, 0, 0, 0, 164)
        put(w, INFO, (value << 4) | 2)
        return request(w, 6, get(w, ROW), 4, 0, 0, 165)
    if phase == 164:
        put(w, INFO, (fact(w, 0, 8) << 4) | 2)
        return request(w, 6, get(w, ROW), 4, 0, 0, 165)
    if phase == 165:
        if stash(s, w, 0, S0) == 0:
            return ABI
        value = truth(w, S0)
        if value == 2:
            return request(w, 8, S0, 0, 0, 0, 167)
        put(w, VIS, choose(value != 0, 0, 2))
        return request(w, 6, get(w, ROW), 1, 0, 0, 166)
    if phase == 167:
        put(w, VIS, choose(fact(w, 0, 8) != 0, 0, 2))
        return request(w, 6, get(w, ROW), 1, 0, 0, 166)
    if phase == 166:
        if stash(s, w, 0, S0) == 0:
            return ABI
        return request(w, 12, 0, S0, 0, 0, 168)
    if phase == 168:
        if exact(w, 0, 0, 4294967296) == 0:
            return ABI
        put(w, NAME, fact(w, 0, 8))
        return request(w, 6, get(w, ROW), 2, 3, 0, 169)
    if phase == 169:
        if stash(s, w, 0, S0) == 0 or stash(s, w, 1, S1) == 0:
            return ABI
        kind = get(w, S0)
        if kind == 1 or kind == 2:
            if get(w, S0 + 16) != 0:
                return 1879048193
            number(w, S2, get(w, S0 + 8))
            return advance(w, 171)
        return request(w, 16, S0, 0, 0, 0, 170)
    if phase == 170:
        if stash(s, w, 0, S2) == 0:
            return ABI
        return advance(w, 171)
    if phase == 171:
        kind = get(w, S1)
        if kind == 1 or kind == 2:
            if get(w, S1 + 16) != 0:
                return 1879048193
            put(w, TMP, get(w, S1 + 8))
            return advance(w, 172)
        return request(w, 16, S1, 0, 0, 0, 173)
    if phase == 173:
        put(w, TMP, fact(w, 0, 8))
        return advance(w, 172)
    if phase == 172:
        at = get(w, SYMTAB) + get(w, VALUE) * 24
        little(w, at, get(w, NAME), 4)
        store(w, at + 4, get(w, INFO))
        store(w, at + 5, get(w, VIS))
        little(w, at + 6, 1, 2)
        put(w, at + 8, get(w, S2 + 8))
        put(w, at + 16, get(w, TMP))
        put(w, VALUE, get(w, VALUE) + 1)
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 160)
    return ABI

def relocation_table(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 190:
        index = get(w, INDEX)
        if index >= get(w, NREL):
            return advance(w, 210)
        node = get(w, get(w, RELS) + index * 8)
        put(w, NODE, node)
        put(w, ROW, get(w, node + 8))
        return request(w, 6, get(w, ROW), 2, 0, 0, 191)
    if phase == 191:
        if stash(s, w, 0, S0) == 0:
            return ABI
        return request(w, 6, get(w, ROW), 5, 0, 0, 192)
    if phase == 192:
        if stash(s, w, 0, S1) == 0:
            return ABI
        return request(w, 12, 1, S1, 0, 0, 193)
    if phase == 193:
        if fact(w, 0, 0) != 1 or fact(w, 0, 16) != 0:
            return ABI
        put(w, NAME, fact(w, 0, 8))
        kind = get(w, S0)
        if kind == 1 or kind == 2:
            if get(w, S0 + 16) != 0:
                return 1879048193
            number(w, S2, get(w, S0 + 8))
            return advance(w, 195)
        return request(w, 16, S0, 0, 0, 0, 194)
    if phase == 194:
        if stash(s, w, 0, S2) == 0:
            return ABI
        return advance(w, 195)
    if phase == 195:
        symbol = get(w, NAME)
        if symbol > 4294967295:
            return 1879048193
        at = get(w, RELATAB) + get(w, INDEX) * 24
        put(w, at, get(w, S2 + 8))
        put(w, at + 8, (symbol << 32) | 4)
        put(w, at + 16, 18446744073709551612)
        put(w, INDEX, get(w, INDEX) + 1)
        return advance(w, 190)
    return ABI

def copy_other(o:mutbuf, dest:u64, w:mutbuf, src:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, dest + i, byte(w, src + i))
        i = i + 1
    return 0

def section(o:mutbuf, at:u64, name:u64, typ:u64, flags:u64, offset:u64, size:u64, link:u64, info:u64, alignment:u64, entry_size:u64) -> u64:
    little(o, at, name, 4)
    little(o, at + 4, typ, 4)
    put(o, at + 8, flags)
    put(o, at + 24, offset)
    put(o, at + 32, size)
    little(o, at + 40, link, 4)
    little(o, at + 44, info, 4)
    put(o, at + 48, alignment)
    put(o, at + 56, entry_size)
    return 0

def output(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    alignment = get(w, ALIGN)
    text = (64 + alignment - 1) & (0 - alignment)
    rela = (text + get(w, CODELEN) + 7) & 18446744073709551608
    sym = rela + get(w, RELASIZE)
    strings = sym + get(w, SYMSIZE)
    shstrings = strings + get(w, STRSIZE)
    stack = shstrings + SECTION_NAMES_LENGTH
    shoff = (stack + 7) & 18446744073709551608
    size = shoff + 448
    if phase == 210:
        if size > MAX_BYTES:
            return BAD + 12
        put(w, RESULT, size)
        if length(o) < size:
            put(w, NEED, size)
            return 3
        return request(w, 15, 0, 0, 0, 0, 211)
    if phase != 211 or get(w, RESULT) != size or length(s) != get(w, CODELEN) or size > length(o):
        return ABI
    fill_range(o, 0, size, 0)
    copy_read(o, text, s, 0, get(w, CODELEN))
    copy_other(o, rela, w, get(w, RELATAB), get(w, RELASIZE))
    copy_other(o, sym, w, get(w, SYMTAB), get(w, SYMSIZE))
    copy_other(o, strings, w, get(w, STRTAB), get(w, STRSIZE))
    section_names(o, shstrings)
    section(o, shoff + 64, TEXT_NAME, 1, 6, text, get(w, CODELEN), 0, 0, alignment, 0)
    section(o, shoff + 128, RELA_NAME, 4, 0, rela, get(w, RELASIZE), 3, 1, 8, 24)
    section(o, shoff + 192, SYM_NAME, 2, 0, sym, get(w, SYMSIZE), 4, get(w, LOCAL_N) + 2, 8, 24)
    section(o, shoff + 256, STR_NAME, 3, 0, strings, get(w, STRSIZE), 0, 0, 1, 0)
    section(o, shoff + 320, SHSTR_NAME, 3, 0, shstrings, SECTION_NAMES_LENGTH, 0, 0, 1, 0)
    section(o, shoff + 384, STACK_NAME, 1, 0, stack, 0, 0, 0, 1, 0)
    put(o, 0, ELF_IDENT)
    little(o, 16, 1, 2)
    little(o, 18, 62, 2)
    little(o, 20, 1, 4)
    put(o, 40, shoff)
    little(o, 52, 64, 2)
    little(o, 58, 64, 2)
    little(o, 60, 7, 2)
    little(o, 62, 5, 2)
    put(w, PHASE, 220)
    return 0


def section_names(o:mutbuf, at:u64) -> u64:
    store(o, at + 0, 0)
    store(o, at + 1, 46)
    store(o, at + 2, 116)
    store(o, at + 3, 101)
    store(o, at + 4, 120)
    store(o, at + 5, 116)
    store(o, at + 6, 0)
    store(o, at + 7, 46)
    store(o, at + 8, 114)
    store(o, at + 9, 101)
    store(o, at + 10, 108)
    store(o, at + 11, 97)
    store(o, at + 12, 46)
    store(o, at + 13, 116)
    store(o, at + 14, 101)
    store(o, at + 15, 120)
    store(o, at + 16, 116)
    store(o, at + 17, 0)
    store(o, at + 18, 46)
    store(o, at + 19, 115)
    store(o, at + 20, 121)
    store(o, at + 21, 109)
    store(o, at + 22, 116)
    store(o, at + 23, 97)
    store(o, at + 24, 98)
    store(o, at + 25, 0)
    store(o, at + 26, 46)
    store(o, at + 27, 115)
    store(o, at + 28, 116)
    store(o, at + 29, 114)
    store(o, at + 30, 116)
    store(o, at + 31, 97)
    store(o, at + 32, 98)
    store(o, at + 33, 0)
    store(o, at + 34, 46)
    store(o, at + 35, 115)
    store(o, at + 36, 104)
    store(o, at + 37, 115)
    store(o, at + 38, 116)
    store(o, at + 39, 114)
    store(o, at + 40, 116)
    store(o, at + 41, 97)
    store(o, at + 42, 98)
    store(o, at + 43, 0)
    store(o, at + 44, 46)
    store(o, at + 45, 110)
    store(o, at + 46, 111)
    store(o, at + 47, 116)
    store(o, at + 48, 101)
    store(o, at + 49, 46)
    store(o, at + 50, 71)
    store(o, at + 51, 78)
    store(o, at + 52, 85)
    store(o, at + 53, 45)
    store(o, at + 54, 115)
    store(o, at + 55, 116)
    store(o, at + 56, 97)
    store(o, at + 57, 99)
    store(o, at + 58, 107)
    store(o, at + 59, 0)
    return 0


def div5(value:u64) -> u64:
    quotient = 0
    remainder = 0
    index = 64
    while index != 0:
        index = index - 1
        remainder = (remainder << 1) | ((value >> index) & 1)
        if remainder >= 5:
            remainder = remainder - 5
            quotient = quotient | (1 << index)
    return quotient

def read_word(s:readbuf, at:u64) -> u64:
    return read_small(s, at, 8)

def read_small(s:readbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return small(w, at, 8)

def small(w:mutbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    little(w, at, value, 8)
    return 0

def little(w:mutbuf, at:u64, value:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


class ElfBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == 'copy_read':
                assert len(node.args) == 5 and not node.keywords
                args = [self.expr(value) for value in node.args]
                return self.op('buffer.copy_range', [
                    args[0], args[2], self.cast(args[1], 'usize'),
                    self.cast(args[3], 'usize'), self.cast(args[4], 'usize')])
            if node.func.id == 'copy_work':
                assert len(node.args) == 5 and not node.keywords
                assert ast.dump(node.args[0]) == ast.dump(node.args[2])
                args = [self.expr(value) for value in node.args]
                return self.op('buffer.move_within', [
                    args[0], self.cast(args[1], 'usize'),
                    self.cast(args[3], 'usize'), self.cast(args[4], 'usize')])
        return super().expr(node)


def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
    parsed = Expand().visit(ast.parse(SOURCE + "\n" + SORT_BODY + "\n" + EXCEPTION_DELIVERY_BODY))
    return ast.unparse(ast.fix_missing_locations(parsed)) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {
        node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
        for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ElfBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({
            'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({
        'schema': 'hepta.hia.program.v8', 'module': 'machine_elf',
        'functions': functions})


if __name__ == '__main__':
    path = (Path(sys.argv[1]) if len(sys.argv) > 1
            else ROOT / 'examples/hia_bootstrap/machine_elf.hiaasm')
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
