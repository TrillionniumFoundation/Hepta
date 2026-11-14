"""Author complete enum-match lowering in ordinary HIA.

The private packet carries admitted nominal descriptors and the existing block
environment. HIA performs case admission, exact nominal/primitive identity
comparison, linear transfer, alias-aware carry construction, inactive-slot
cleanup, name allocation and complete Core CFG construction. No host-generated
lowering plan or semantic predicate is consumed.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES

MAGIC = int.from_bytes(b'HIAMAT01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 64 << 20
WORKSPACE_BYTES = 32 << 20
CONSTANTS = {
    'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192,
    'EV': 2105344, 'EH': 4202496, 'MARK': 8396800,
    'SG': 10493952, 'CN': 10526720, 'CT': 10788864,
    'CH': 11051008, 'B': 11575296, 'CM': 11583616,
    'HEAP': 11616256, 'G': 1 << 63, 'N': (1 << 64) - 1,
    'ABI': 0xfffffff1,
}

# The public source has at most 262,144 JSON value nodes and 32,768 flattened
# elaborated slots. Nominal descriptors are already interned (at most 128);
# primitive descriptor copies are bounded by those source nodes. This packet
# never expands a nominal display key or traverses a record DAG recursively.
# The 256-MiB private input allowance exceeds the conservative sum of all
# descriptor, source-term, environment, signature and primitive-name envelopes.
# It does not replace the original 8-MiB public document limit.
#
# At most 32 arms can each forward 32,768 primitive slots. These repeated
# aliases do not all allocate fresh names, so the output must allow >20 MiB,
# independently of the unchanged 8,192 fresh-name quota. 64 MiB includes every
# forwarding list, generated parameter, decision and padding-drop instruction.
# Scratch uses fixed tables below 12 MiB; the largest case hash is 4 MiB,
# edge vectors total at most 8 MiB, and fresh-name/CFG records fit below 4 MiB.

BODY = r'''
def enum_match(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(w) < W_BYTES or length(o) < O_BYTES:
        return ABI
    if validate(s, w) == 0:
        return ABI
    if tag(s, 0) != 5 or total(s, 0) != 5:
        return ABI
    i = 0
    while i < 256:
        put(w, S + i, 0)
        i = i + 8
    put(w, S + 16, HEAP)
    if admit(s, w) == 0:
        return ABI
    lower(s, w)
    if get(w, S + 32) != 0:
        return ABI
    put(w, S + 24, 64)
    emit_text(o, w, '{"first":')
    if get(w, S + 8) != 0:
        emit_text(o, w, 'null,"blocks":null}')
    else:
        render_first(s, o, w)
        emit_text(o, w, ',"blocks":[')
        i = 1
        while i < get(w, S + 40):
            if i != 1:
                append_byte(o, w, 44)
            render_block(s, o, w, B + i * 128)
            i = i + 1
        emit_text(o, w, ']}')
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, S + 8))
    put(o, 16, get(w, S))
    put(o, 24, get(w, S + 24) - 64)
    put(o, 32, 0)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return get(w, S + 24)

def unsigned(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 2 or size_of(s, node) == 0 or size_of(s, node) > 6:
        return N
    value = 0
    i = 0
    while i < size_of(s, node):
        digit = byte(s, node + 16 + i)
        if digit < 48 or digit > 57:
            return N
        value = value * 10 + digit - 48
        i = i + 1
    if value > 262144:
        return N
    return value

def truth(s:readbuf, node:u64) -> u64:
    return byte(s, node + 16)

def prefix(s:readbuf, node:u64, n:u64, a:u64, b:u64) -> u64:
    if tag(s, node) != 4 or size_of(s, node) < n:
        return 0
    i = 0
    while i < n:
        value = a
        if i >= 8:
            value = b
        if byte(s, node + 16 + i) != ((value >> ((i & 7) * 8)) & 255):
            return 0
        i = i + 1
    return 1

def name_status(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 4 or size_of(s, node) < 1 or size_of(s, node) > 128:
        return 1
    i = 0
    while i < size_of(s, node):
        ch = byte(s, node + 16 + i)
        valid = (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95
        if i != 0:
            valid = valid or (ch >= 48 and ch <= 57)
        if valid == False:
            return 1
        i = i + 1
    if prefix(s, node, 6, 104871984914271, 0) != 0:
        return 1
    if prefix(s, node, 11, 7958535042260087400, 6253665) != 0:
        return 2
    return 0

def name_check(s:readbuf, w:mutbuf, node:u64, first:u64) -> u64:
    status = name_status(s, node)
    if status != 0:
        refuse(w, first + status - 1)
        return 0
    return 1

def hash_name(s:readbuf, node:u64) -> u64:
    value = 14695981039346656037
    i = 0
    while i < size_of(s, node):
        value = (value ^ byte(s, node + 16 + i)) * 1099511628211
        i = i + 1
    return value

def field(s:readbuf, node:u64, ident:u64) -> u64:
    if tag(s, node) != 6:
        return N
    at = node + 24
    i = 0
    while i < total(s, node):
        key = field_id(s, at)
        value = end(s, at)
        if key == ident:
            return value
        at = end(s, value)
        i = i + 1
    return N

def keys(s:readbuf, node:u64, mask:u64) -> u64:
    if tag(s, node) != 6 or total(s, node) != 3:
        return 0
    at = node + 24
    seen = 0
    i = 0
    while i < 3:
        ident = field_id(s, at)
        if ident == 0 or (seen & ident) != 0:
            return 0
        seen = seen | ident
        at = end(s, end(s, at))
        i = i + 1
    return choose(seen == mask, 1, 0)

def typename(s:readbuf, w:mutbuf, ident:u64) -> u64:
    return get(w, T + ident * 8)

def flat_node(s:readbuf, descriptor:u64) -> u64:
    return element(s, descriptor, 1)

def type_width(s:readbuf, descriptor:u64) -> u64:
    return total(s, flat_node(s, descriptor))

def linear(s:readbuf, descriptor:u64) -> u64:
    return truth(s, element(s, descriptor, 2))

def type_equal(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    if left == right:
        return 1
    a = typename(s, w, left)
    b = typename(s, w, right)
    if kind_id(s, element(s, a, 0)) != 1 or kind_id(s, element(s, b, 0)) != 1:
        return 0
    return same_text(s, element(s, flat_node(s, a), 0), element(s, flat_node(s, b), 0))

def env_type(s:readbuf, w:mutbuf, index:u64) -> u64:
    return unsigned(s, element(s, get(w, EV + index * 8), 1))

def env_values(s:readbuf, w:mutbuf, index:u64) -> u64:
    return element(s, get(w, EV + index * 8), 2)

def env_lookup(s:readbuf, w:mutbuf, name:u64) -> u64:
    mask = get(w, S + 64) - 1
    slot = hash_name(s, name) & mask
    while True:
        value = get(w, EH + slot * 8)
        if value == 0:
            return N
        node = get(w, EV + (value - 1) * 8)
        if same_text(s, name, element(s, node, 0)) != 0:
            return value - 1
        slot = (slot + 1) & mask
    return N

def admitted_value(s:readbuf, w:mutbuf, name:u64) -> u64:
    if name_check(s, w, name, 3) == 0:
        return N
    index = env_lookup(s, w, name)
    if index == N:
        refuse(w, 5)
        return N
    if truth(s, element(s, get(w, EV + index * 8), 4)) != 0:
        refuse(w, 6)
        return N
    return index

def admit(s:readbuf, w:mutbuf) -> u64:
    serial = unsigned(s, element(s, 0, 0))
    if serial > 8192:
        return 0
    put(w, S, serial)
    types = element(s, 0, 2)
    values = element(s, 0, 3)
    signatures = element(s, 0, 4)
    if tag(s, types) != 5 or tag(s, values) != 5 or tag(s, signatures) != 5:
        return 0
    tc = total(s, types)
    ec = total(s, values)
    sc = total(s, signatures)
    if tc > 262144 or ec > 262144 or sc > 4096:
        return 0
    put(w, S + 48, tc)
    put(w, S + 56, ec)
    put(w, S + 72, sc)
    node = types + 24
    i = 0
    while i < tc:
        put(w, T + i * 8, node)
        if tag(s, node) != 5 or total(s, node) != 4:
            return 0
        kind = kind_id(s, element(s, node, 0))
        flat = flat_node(s, node)
        variants = element(s, node, 3)
        if kind == 0 or tag(s, flat) != 5 or total(s, flat) > 512:
            return 0
        if tag(s, element(s, node, 2)) != 1 or tag(s, variants) != 5:
            return 0
        if total(s, variants) > 32:
            return 0
        if kind == 1 and total(s, flat) != 1:
            return 0
        if kind == 3 and total(s, variants) == 0:
            return 0
        if kind != 3 and total(s, variants) != 0:
            return 0
        at = flat + 24
        j = 0
        while j < total(s, flat):
            if type_id(s, at) == 0:
                return 0
            at = end(s, at)
            j = j + 1
        variant = variants + 24
        j = 0
        while j < total(s, variants):
            if tag(s, variant) != 5 or total(s, variant) != 2:
                return 0
            if name_status(s, element(s, variant, 0)) != 0:
                return 0
            fields = element(s, variant, 1)
            if tag(s, fields) != 5 or total(s, fields) > 64:
                return 0
            at = fields + 24
            k = 0
            while k < total(s, fields):
                if unsigned(s, at) >= tc:
                    return 0
                at = end(s, at)
                k = k + 1
            variant = end(s, variant)
            j = j + 1
        node = end(s, node)
        i = i + 1
    i = 0
    while i < tc:
        descriptor = get(w, T + i * 8)
        if kind_id(s, element(s, descriptor, 0)) == 3:
            if enum_shape(s, w, descriptor) == 0:
                return 0
        i = i + 1
    capacity = 1
    while capacity < ec * 2:
        capacity = capacity * 2
    put(w, S + 64, capacity)
    i = 0
    while i < capacity:
        put(w, EH + i * 8, 0)
        i = i + 1
    node = values + 24
    slots = 0
    i = 0
    while i < ec:
        if tag(s, node) != 5 or total(s, node) != 5:
            return 0
        name = element(s, node, 0)
        ident = unsigned(s, element(s, node, 1))
        names = element(s, node, 2)
        if name_status(s, name) != 0 or ident >= tc or tag(s, names) != 5:
            return 0
        if tag(s, element(s, node, 3)) != 1 or tag(s, element(s, node, 4)) != 1:
            return 0
        if total(s, names) != type_width(s, get(w, T + ident * 8)):
            return 0
        slots = slots + total(s, names)
        if slots > 32768:
            return 0
        at = names + 24
        j = 0
        while j < total(s, names):
            if name_status(s, at) == 1:
                return 0
            at = end(s, at)
            j = j + 1
        put(w, EV + i * 8, node)
        put(w, MARK + i * 8, 0)
        slot = hash_name(s, name) & (capacity - 1)
        while get(w, EH + slot * 8) != 0:
            previous = get(w, EV + (get(w, EH + slot * 8) - 1) * 8)
            if same_text(s, name, element(s, previous, 0)) != 0:
                return 0
            slot = (slot + 1) & (capacity - 1)
        put(w, EH + slot * 8, i + 1)
        node = end(s, node)
        i = i + 1
    capacity = 1
    while capacity < slots * 2:
        capacity = capacity * 2
    put(w, S + 152, capacity)
    i = 0
    while i < capacity:
        put(w, CH + i * 8, 0)
        i = i + 1
    node = signatures + 24
    i = 0
    while i < sc:
        if tag(s, node) != 5 or total(s, node) != 2:
            return 0
        if name_status(s, element(s, node, 0)) != 0:
            return 0
        parameters = element(s, node, 1)
        if tag(s, parameters) != 5 or total(s, parameters) > 262144:
            return 0
        at = parameters + 24
        j = 0
        while j < total(s, parameters):
            if unsigned(s, at) >= tc:
                return 0
            at = end(s, at)
            j = j + 1
        put(w, SG + i * 8, node)
        node = end(s, node)
        i = i + 1
    return 1

def enum_shape(s:readbuf, w:mutbuf, descriptor:u64) -> u64:
    flat = flat_node(s, descriptor)
    if total(s, flat) == 0 or type_id(s, element(s, flat, 0)) != 9:
        return 0
    expected = end(s, flat + 24)
    width = 1
    variants = element(s, descriptor, 3)
    variant = variants + 24
    i = 0
    while i < total(s, variants):
        fields = element(s, variant, 1)
        at = fields + 24
        j = 0
        while j < total(s, fields):
            nested = flat_node(s, typename(s, w, unsigned(s, at)))
            source = nested + 24
            k = 0
            while k < total(s, nested):
                if width >= total(s, flat) or same_text(s, source, expected) == 0:
                    return 0
                width = width + 1
                expected = end(s, expected)
                source = end(s, source)
                k = k + 1
            at = end(s, at)
            j = j + 1
        variant = end(s, variant)
        i = i + 1
    return choose(width == total(s, flat), 1, 0)

def case_slot(s:readbuf, w:mutbuf, name:u64) -> u64:
    mask = get(w, S + 136) - 1
    slot = hash_name(s, name) & mask
    table = get(w, S + 128)
    while True:
        value = get(w, table + slot * 8)
        if value == 0 or same_text(s, name, field(s, value, 8)) != 0:
            return table + slot * 8
        slot = (slot + 1) & mask
    return table

def lower(s:readbuf, w:mutbuf) -> u64:
    term = element(s, 0, 1)
    if keys(s, term, 7) == 0:
        return refuse(w, 2)
    matched_name = field(s, term, 2)
    matched = admitted_value(s, w, matched_name)
    if get(w, S + 8) != 0:
        return 0
    descriptor = typename(s, w, env_type(s, w, matched))
    if kind_id(s, element(s, descriptor, 0)) != 3:
        return refuse(w, 7)
    put(w, S + 80, matched)
    put(w, S + 88, descriptor)
    cases = field(s, term, 4)
    if tag(s, cases) != 5:
        return refuse(w, 8)
    count = total(s, cases)
    capacity = 1
    while capacity < count * 2:
        capacity = capacity * 2
    table = allocate(w, capacity * 8)
    if get(w, S + 32) != 0:
        return 0
    put(w, S + 128, table)
    put(w, S + 136, capacity)
    i = 0
    while i < capacity:
        put(w, table + i * 8, 0)
        i = i + 1
    case = cases + 24
    i = 0
    while i < count:
        if keys(s, case, 56) == 0:
            return refuse(w, 9)
        variant = field(s, case, 8)
        if name_check(s, w, variant, 10) == 0:
            return 0
        args = field(s, case, 32)
        if tag(s, args) != 5:
            return refuse(w, 12)
        name = args + 24
        j = 0
        while j < total(s, args):
            if name_status(s, name) == 1:
                return refuse(w, 13)
            name = end(s, name)
            j = j + 1
        slot = case_slot(s, w, variant)
        if get(w, slot) != 0:
            return refuse(w, 14)
        put(w, slot, case)
        if linear(s, descriptor) != 0:
            name = args + 24
            j = 0
            while j < total(s, args):
                if same_text(s, name, matched_name) != 0:
                    return refuse(w, 15)
                name = end(s, name)
                j = j + 1
        case = end(s, case)
        i = i + 1
    variants = element(s, descriptor, 3)
    if count != total(s, variants):
        return refuse(w, 16)
    variant = variants + 24
    i = 0
    while i < count:
        case = get(w, case_slot(s, w, element(s, variant, 0)))
        if case == 0:
            return refuse(w, 16)
        put(w, CM + i * 8, case)
        variant = end(s, variant)
        i = i + 1
    make_carry(s, w)
    clear_block(w, B)
    put(w, S + 40, 1)
    current = B
    mapping = CN
    cursor = 1
    variant = variants + 24
    i = 0
    while i < count:
        case = get(w, CM + i * 8)
        fields = element(s, variant, 1)
        width = payload_width(s, w, fields)
        edge_args = admit_edge(s, w, case, fields, cursor, width)
        if get(w, S + 8) != 0 or get(w, S + 32) != 0:
            return 0
        arm = make_block(w)
        if get(w, S + 8) != 0:
            return 0
        cleanup(s, w, arm, cursor, width)
        if get(w, S + 8) != 0:
            return 0
        remap(s, w, edge_args, get(w, S + 176), get(w, arm + 8))
        put(w, arm + 48, 1)
        put(w, arm + 72, field(s, case, 16))
        put(w, arm + 80, edge_args)
        put(w, arm + 88, get(w, S + 176))
        expected = constant(w, current, i)
        matches = fresh(w)
        tag_name = element(s, env_values(s, w, get(w, S + 80)), 0)
        tag_index = carry_index(s, w, tag_name)
        if tag_index == N:
            put(w, S + 32, 1)
            return 0
        instruction(w, current, 2, pair(w, get(w, mapping + tag_index * 8), expected), 2,
                    singleton(w, matches), singleton(w, 1), 1, 0)
        next_block = make_block(w)
        if get(w, S + 8) != 0:
            return 0
        put(w, current + 48, 3)
        put(w, current + 56, matches)
        put(w, current + 72, get(w, arm))
        put(w, current + 80, mapping)
        put(w, current + 88, get(w, S + 112))
        put(w, current + 96, get(w, next_block))
        put(w, current + 104, mapping)
        put(w, current + 112, get(w, S + 112))
        if i + 1 == count:
            put(w, next_block + 48, 2)
        else:
            current = next_block
            mapping = get(w, current + 8)
        cursor = cursor + width
        variant = end(s, variant)
        i = i + 1
    return 0

def payload_width(s:readbuf, w:mutbuf, fields:u64) -> u64:
    at = fields + 24
    width = 0
    i = 0
    while i < total(s, fields):
        width = width + type_width(s, typename(s, w, unsigned(s, at)))
        at = end(s, at)
        i = i + 1
    return width

def carry_index(s:readbuf, w:mutbuf, name:u64) -> u64:
    mask = get(w, S + 152) - 1
    slot = hash_name(s, name) & mask
    while True:
        value = get(w, CH + slot * 8)
        if value == 0:
            return N
        if same_text(s, name, get(w, CN + (value - 1) * 8)) != 0:
            return value - 1
        slot = (slot + 1) & mask
    return N

def make_carry(s:readbuf, w:mutbuf) -> u64:
    count = 0
    i = 0
    while i < get(w, S + 56):
        entry = get(w, EV + i * 8)
        if truth(s, element(s, entry, 4)) == 0:
            names = element(s, entry, 2)
            flat = flat_node(s, typename(s, w, env_type(s, w, i)))
            name = names + 24
            typ = flat + 24
            j = 0
            while j < total(s, names):
                slot = hash_name(s, name) & (get(w, S + 152) - 1)
                found = False
                while get(w, CH + slot * 8) != 0 and found == False:
                    previous = get(w, CH + slot * 8) - 1
                    if same_text(s, name, get(w, CN + previous * 8)) != 0:
                        found = True
                    else:
                        slot = (slot + 1) & (get(w, S + 152) - 1)
                if found == False:
                    put(w, CN + count * 8, name)
                    put(w, CT + count * 8, type_id(s, typ))
                    put(w, CH + slot * 8, count + 1)
                    count = count + 1
                name = end(s, name)
                typ = end(s, typ)
                j = j + 1
        i = i + 1
    put(w, S + 112, count)
    return 0

def admit_edge(s:readbuf, w:mutbuf, case:u64, fields:u64, cursor:u64, width:u64) -> u64:
    target = field(s, case, 16)
    if name_check(s, w, target, 17) == 0:
        return 0
    signature = N
    i = 0
    while i < get(w, S + 72):
        entry = get(w, SG + i * 8)
        if same_text(s, target, element(s, entry, 0)) != 0:
            signature = element(s, entry, 1)
        i = i + 1
    if signature == N:
        return refuse(w, 19)
    epoch = get(w, S + 160) + 1
    put(w, S + 160, epoch)
    args = field(s, case, 32)
    at = args + 24
    i = 0
    count = width
    while i < total(s, args):
        index = admitted_value(s, w, at)
        if get(w, S + 8) != 0:
            return 0
        descriptor = typename(s, w, env_type(s, w, index))
        if linear(s, descriptor) != 0:
            if get(w, MARK + index * 8) == epoch:
                return refuse(w, 20)
            put(w, MARK + index * 8, epoch)
        count = count + type_width(s, descriptor)
        at = end(s, at)
        i = i + 1
    i = 0
    while i < get(w, S + 56):
        entry = get(w, EV + i * 8)
        descriptor = typename(s, w, env_type(s, w, i))
        if linear(s, descriptor) != 0 and truth(s, element(s, entry, 4)) == 0:
            if truth(s, element(s, entry, 3)) == 0 and i != get(w, S + 80):
                if get(w, MARK + i * 8) != epoch:
                    return refuse(w, 21)
        i = i + 1
    if total(s, fields) + total(s, args) != total(s, signature):
        return refuse(w, 22)
    expected = signature + 24
    at = fields + 24
    i = 0
    while i < total(s, fields):
        if type_equal(s, w, unsigned(s, at), unsigned(s, expected)) == 0:
            return refuse(w, 22)
        at = end(s, at)
        expected = end(s, expected)
        i = i + 1
    at = args + 24
    i = 0
    while i < total(s, args):
        index = env_lookup(s, w, at)
        if type_equal(s, w, env_type(s, w, index), unsigned(s, expected)) == 0:
            return refuse(w, 22)
        at = end(s, at)
        expected = end(s, expected)
        i = i + 1
    if count > 32768:
        put(w, S + 32, 1)
        return 0
    result = allocate(w, count * 8)
    copied = 0
    names = env_values(s, w, get(w, S + 80))
    at = element(s, names, cursor)
    i = 0
    while i < width:
        put(w, result + copied * 8, at)
        at = end(s, at)
        copied = copied + 1
        i = i + 1
    at = args + 24
    i = 0
    while i < total(s, args):
        index = env_lookup(s, w, at)
        names = env_values(s, w, index)
        name = names + 24
        j = 0
        while j < total(s, names):
            put(w, result + copied * 8, name)
            name = end(s, name)
            copied = copied + 1
            j = j + 1
        at = end(s, at)
        i = i + 1
    put(w, S + 176, count)
    return result

def cleanup(s:readbuf, w:mutbuf, arm:u64, cursor:u64, width:u64) -> u64:
    names = env_values(s, w, get(w, S + 80))
    flat = flat_node(s, get(w, S + 88))
    name = end(s, names + 24)
    typ = end(s, flat + 24)
    i = 1
    while i < total(s, names):
        selected = False
        other = element(s, names, cursor)
        j = 0
        while j < width:
            if same_text(s, name, other) != 0:
                selected = True
            other = end(s, other)
            j = j + 1
        if selected == False:
            primitive = type_id(s, typ)
            if primitive == 13 or primitive == 16:
                index = carry_index(s, w, name)
                if index == N:
                    put(w, S + 32, 1)
                    return 0
                mapped = get(w, get(w, arm + 8) + index * 8)
                instruction(w, arm, 3, singleton(w, mapped), 1, 0, 0, 0, 0)
            elif primitive == 14 or primitive == 15:
                return refuse(w, 23)
        name = end(s, name)
        typ = end(s, typ)
        i = i + 1
    return 0

def remap(s:readbuf, w:mutbuf, values:u64, count:u64, mapping:u64) -> u64:
    i = 0
    while i < count:
        index = carry_index(s, w, get(w, values + i * 8))
        if index == N:
            put(w, S + 32, 1)
            return 0
        put(w, values + i * 8, get(w, mapping + index * 8))
        i = i + 1
    return 0

def refuse(w:mutbuf, code:u64) -> u64:
    if get(w, S + 8) == 0:
        put(w, S + 8, code)
    return 0

def fresh(w:mutbuf) -> u64:
    if get(w, S + 8) != 0:
        return 0
    serial = get(w, S)
    if serial >= 8192:
        return refuse(w, 1)
    put(w, S, serial + 1)
    return G | (serial + 1)

def allocate(w:mutbuf, size:u64) -> u64:
    start = get(w, S + 16)
    if start > W_BYTES or size > W_BYTES - start:
        put(w, S + 32, 1)
        return 0
    put(w, S + 16, start + size)
    return start

def singleton(w:mutbuf, value:u64) -> u64:
    at = allocate(w, 8)
    put(w, at, value)
    return at

def pair(w:mutbuf, left:u64, right:u64) -> u64:
    at = allocate(w, 16)
    put(w, at, left)
    put(w, at + 8, right)
    return at

def clear_block(w:mutbuf, at:u64) -> u64:
    i = 0
    while i < 128:
        put(w, at + i, 0)
        i = i + 8
    return 0

def make_block(w:mutbuf) -> u64:
    index = get(w, S + 40)
    if index >= 65:
        put(w, S + 32, 1)
        return B
    at = B + index * 128
    put(w, S + 40, index + 1)
    clear_block(w, at)
    count = get(w, S + 112)
    names = allocate(w, count * 8)
    i = 0
    while i < count:
        put(w, names + i * 8, fresh(w))
        i = i + 1
    put(w, at, fresh(w))
    put(w, at + 8, names)
    put(w, at + 16, CT)
    put(w, at + 24, count)
    return at

def instruction(w:mutbuf, target:u64, code:u64, args:u64, argc:u64, results:u64, types:u64, count:u64, attribute:u64) -> u64:
    at = allocate(w, 64)
    put(w, at, code)
    put(w, at + 8, args)
    put(w, at + 16, argc)
    put(w, at + 24, results)
    put(w, at + 32, types)
    put(w, at + 40, count)
    put(w, at + 48, attribute)
    put(w, at + 56, 0)
    previous = get(w, target + 40)
    if previous == 0:
        put(w, target + 32, at)
    else:
        put(w, previous + 56, at)
    put(w, target + 40, at)
    return 0

def constant(w:mutbuf, target:u64, value:u64) -> u64:
    ident = fresh(w)
    instruction(w, target, 1, 0, 0, singleton(w, ident), singleton(w, 9), 1, value)
    return ident

def render_name(s:readbuf, o:mutbuf, w:mutbuf, value:u64) -> u64:
    if value >= G:
        emit_text(o, w, '"h2internal_')
        number(o, w, value - G)
        append_byte(o, w, 34)
    else:
        source_name(s, o, w, value)
    return 0

def render_names(s:readbuf, o:mutbuf, w:mutbuf, values:u64, count:u64) -> u64:
    append_byte(o, w, 91)
    i = 0
    while i < count:
        if i != 0:
            append_byte(o, w, 44)
        render_name(s, o, w, get(w, values + i * 8))
        i = i + 1
    append_byte(o, w, 93)
    return 0

def render_params(s:readbuf, o:mutbuf, w:mutbuf, values:u64, types:u64, count:u64) -> u64:
    append_byte(o, w, 91)
    i = 0
    while i < count:
        if i != 0:
            append_byte(o, w, 44)
        emit_text(o, w, '{"name":')
        render_name(s, o, w, get(w, values + i * 8))
        emit_text(o, w, ',"type":"')
        type_name(o, w, get(w, types + i * 8))
        emit_text(o, w, '"}')
        i = i + 1
    append_byte(o, w, 93)
    return 0

def render_ops(s:readbuf, o:mutbuf, w:mutbuf, block:u64) -> u64:
    append_byte(o, w, 91)
    at = get(w, block + 32)
    previous = 0
    while at != 0:
        if previous != 0:
            append_byte(o, w, 44)
        code = get(w, at)
        emit_text(o, w, '{"op":"')
        instruction_name(o, w, code)
        emit_text(o, w, '","args":')
        render_names(s, o, w, get(w, at + 8), get(w, at + 16))
        emit_text(o, w, ',"out":')
        render_params(s, o, w, get(w, at + 24), get(w, at + 32), get(w, at + 40))
        emit_text(o, w, ',"attrs":{')
        if code == 1:
            emit_text(o, w, '"value":')
            number(o, w, get(w, at + 48))
        emit_text(o, w, '}}')
        previous = 1
        at = get(w, at + 56)
    append_byte(o, w, 93)
    return 0

def render_edge(s:readbuf, o:mutbuf, w:mutbuf, target:u64, args:u64, count:u64) -> u64:
    emit_text(o, w, '{"target":')
    render_name(s, o, w, target)
    emit_text(o, w, ',"args":')
    render_names(s, o, w, args, count)
    append_byte(o, w, 125)
    return 0

def render_term(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    kind = get(w, at + 48)
    if kind == 1:
        emit_text(o, w, '{"op":"jump","target":')
        render_name(s, o, w, get(w, at + 72))
        emit_text(o, w, ',"args":')
        render_names(s, o, w, get(w, at + 80), get(w, at + 88))
        append_byte(o, w, 125)
    elif kind == 2:
        emit_text(o, w, '{"op":"trap","code":"user"}')
    else:
        emit_text(o, w, '{"op":"branch","cond":')
        render_name(s, o, w, get(w, at + 56))
        emit_text(o, w, ',"then":')
        render_edge(s, o, w, get(w, at + 72), get(w, at + 80), get(w, at + 88))
        emit_text(o, w, ',"else":')
        render_edge(s, o, w, get(w, at + 96), get(w, at + 104), get(w, at + 112))
        append_byte(o, w, 125)
    return 0

def render_first(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    emit_text(o, w, '{"ops":')
    render_ops(s, o, w, B)
    emit_text(o, w, ',"term":')
    render_term(s, o, w, B)
    append_byte(o, w, 125)
    return 0

def render_block(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    emit_text(o, w, '{"id":')
    render_name(s, o, w, get(w, at))
    emit_text(o, w, ',"params":')
    render_params(s, o, w, get(w, at + 8), get(w, at + 16), get(w, at + 24))
    emit_text(o, w, ',"ops":')
    render_ops(s, o, w, at)
    emit_text(o, w, ',"term":')
    render_term(s, o, w, at)
    append_byte(o, w, 125)
    return 0
'''


def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'emit_text'):
                output, workspace, literal = node.value.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str
                return [ast.Expr(ast.Call(ast.Name('emit', ast.Load()),
                    [output, workspace, *(ast.Constant(value) for value in packed(literal.value[i:i + 24]))], []))
                    for i in range(0, len(literal.value), 24)]
            return self.generic_visit(node)

        def visit_Name(self, node):
            return ast.Constant(CONSTANTS[node.id]) if node.id in CONSTANTS else node

    own = ast.parse(BODY)
    common_names = {'validate', 'word', 'put', 'get', 'tag', 'size_of', 'end', 'total',
                    'element', 'text_is', 'same_text'}
    common_source = TRANSPORT_SOURCE.replace('    DISPATCH', '    pass').replace('1048576', '8388608')
    common = [node for node in ast.parse(common_source).body
              if isinstance(node, ast.FunctionDef) and node.name in common_names]
    utility_names = {'append_byte', 'emit', 'number', 'source_name'}
    utilities = [node for node in ast.parse(HELPER_BODY).body
                 if isinstance(node, ast.FunctionDef) and node.name in utility_names]
    own.body.extend(common + utilities)
    own = Expand().visit(own)
    suffix = []
    for function, values in [
        ('type_id', enumerate(PRIMITIVES, 1)),
        ('kind_id', enumerate(('primitive', 'record', 'enum', 'task', 'partial_record'), 1)),
        ('field_id', zip((1, 2, 4, 8, 16, 32), ('op', 'value', 'cases', 'variant', 'target', 'args'))),
    ]:
        suffix.append('def ' + function + '(s:readbuf, node:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if text_is(s, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                       '        return ' + str(identifier)]
        suffix += ['    return 0']
    for function, values in [('type_name', PRIMITIVES),
                             ('instruction_name', ('const', 'compare.eq', 'owner.drop'))]:
        suffix.append('def ' + function + '(o:mutbuf, w:mutbuf, identifier:u64) -> u64:')
        for identifier, value in enumerate(values, 1):
            suffix += ['    if identifier == ' + str(identifier) + ':',
                       '        return emit(o, w, ' + ', '.join(map(str, packed(value))) + ')']
        suffix += ['    return 0']
    return ast.unparse(ast.fix_missing_locations(own)) + '\n' + '\n'.join(suffix) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'enum_match', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/enum_match.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
