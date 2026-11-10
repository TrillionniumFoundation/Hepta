"""Author native nominal/generic capability and stored-borrow graph queries.

Dependency stage of semantic type/ownership migration, not the complete checker.
Generic substitutions use native contextual references, not host instantiation.
"""
from __future__ import annotations
import ast
import copy
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

SOURCE=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    code = validate(s, w)
    if code != 0:
        return code
    code = prepare(s, w)
    if code != 0:
        return code
    if word(s, 8) >= 4:
        code = validate_type_walk(s, w)
        if code != 0:
            return code
        return type_result(s, o, w)
    if word(s, 8) == 3:
        code = owned_walk(s, w)
        if code != 0:
            return code
        return owned_result(s, o, w)
    answer = query(s, w)
    if answer > 1:
        return answer
    if length(o) < 32:
        return 4294967294
    put(o, 0, 3549479791681612109)
    put(o, 8, answer)
    put(o, 16, word(s, 8))
    put(o, 24, 0)
    return 32

def validate(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or length(s) > 1048576 or length(w) < 680256:
        return 4294967293
    if word(s, 0) != 3549479791681612108 or word(s, 8) < 1 or word(s, 8) > 5:
        return 4294967293
    if word(s, 8) == 3 and (length(w) < 4932240 or word(s, 72) != 0):
        return 4294967293
    if word(s, 8) >= 4 and length(w) < 6374032:
        return 4294967293
    if word(s, 16) == 0 or word(s, 16) > 8192 or word(s, 24) > 512 or word(s, 32) > 32768 or word(s, 40) == 0 or word(s, 40) > 8192 or word(s, 48) > 4096 or word(s, 56) > 8192 or word(s, 64) > 8192 or word(s, 72) > 8192 or word(s, 80) >= word(s, 16):
        return 4294967293
    if word(s, 88) != 128 or word(s, 96) != 128 + word(s, 16) * 64 or word(s, 104) != word(s, 96) + word(s, 24) * 48:
        return 4294967293
    if word(s, 112) != word(s, 104) + (word(s, 32) + word(s, 48) + word(s, 56) + word(s, 64) + word(s, 72)) * 8 or word(s, 120) != word(s, 112) + word(s, 40) * 16 or word(s, 120) > length(s):
        return 4294967293
    cursor = 0
    i = 0
    while i < word(s, 16):
        at = 128 + i * 64
        if word(s, at) >= word(s, 40) or word(s, at + 8) != cursor or word(s, at + 16) > word(s, 32) - cursor:
            return 4294967293
        count = word(s, at + 16)
        j = 0
        while j < count:
            if word(s, word(s, 104) + (cursor + j) * 8) >= i:
                return 4294967293
            j = j + 1
        cursor = cursor + count
        if word(s, at + 24) != cursor or word(s, at + 32) > word(s, 32) - cursor:
            return 4294967293
        count = word(s, at + 32)
        j = 0
        while j < count:
            if word(s, word(s, 104) + (cursor + j) * 8) >= word(s, 40):
                return 4294967293
            j = j + 1
        cursor = cursor + count
        if word(s, at + 40) > 2 or word(s, at + 56) != 0:
            return 4294967293
        if word(s, at + 40) == 0:
            if word(s, at + 48) != 0:
                return 4294967293
        else:
            if word(s, at + 48) >= word(s, 40):
                return 4294967293
        i = i + 1
    if cursor != word(s, 32):
        return 4294967293
    if word(s, 8) >= 4 and validate_config(s) != 0:
        return 4294967293
    if validate_declarations(s) != 0:
        return 4294967293
    cursor = 0
    i = 0
    while i < word(s, 40):
        at = word(s, 112) + i * 16
        if word(s, at) != cursor or word(s, at + 8) < cursor or word(s, at + 8) > length(s) - word(s, 120):
            return 4294967293
        cursor = word(s, at + 8)
        i = i + 1
    if cursor != length(s) - word(s, 120):
        return 4294967293
    return 0

def validate_declarations(s:readbuf) -> u64:
    pc = 0
    mc = 0
    i = 0
    while i < word(s, 24):
        at = word(s, 96) + i * 48
        if word(s, at) >= word(s, 40) or word(s, at + 8) != pc or word(s, at + 16) > word(s, 48) - pc or word(s, at + 24) != mc or word(s, at + 32) > word(s, 56) - mc:
            return 1
        pc = pc + word(s, at + 16)
        mc = mc + word(s, at + 32)
        i = i + 1
    if pc != word(s, 48) or mc != word(s, 56):
        return 1
    i = 0
    while i < word(s, 48) + word(s, 56) + word(s, 64) + word(s, 72):
        limit = word(s, 40)
        if i >= word(s, 48) and i < word(s, 48) + word(s, 56):
            limit = word(s, 16)
        if word(s, 8) >= 4 and i >= word(s, 48) + word(s, 56) + word(s, 64):
            return 0
        if word(s, word(s, 104) + (word(s, 32) + i) * 8) >= limit:
            return 1
        i = i + 1
    return 0

def prepare(s:readbuf, w:mutbuf) -> u64:
    put(w, 0, 1)
    put(w, 8, 0)
    put(w, 16, 0)
    put(w, 32, 0)
    put(w, 256, word(s, 80))
    i = 0
    while i < word(s, 40):
        store(w, 524544 + i, 0)
        store(w, 532736 + i, 0)
        put(w, 614720 + i * 8, 0)
        i = i + 1
    i = 0
    while i < word(s, 24):
        name = word(s, word(s, 96) + i * 48)
        if get(w, 614720 + name * 8) != 0:
            return 4294967293
        put(w, 614720 + name * 8, i + 1)
        i = i + 1
    at = word(s, 104) + (word(s, 32) + word(s, 48) + word(s, 56)) * 8
    i = 0
    while i < word(s, 64):
        name = word(s, at + i * 8)
        store(w, 532736 + name, 1)
        if same_word(s, name, W_REF_MUT, 7) == 1:
            put(w, 32, 1)
        i = i + 1
    at = at + word(s, 64) * 8
    i = 0
    while word(s, 8) <= 2 and i < word(s, 72):
        store(w, 524544 + word(s, at + i * 8), 1)
        i = i + 1
    return 0

def query(s:readbuf, w:mutbuf) -> u64:
    mode = word(s, 8)
    while get(w, 0) != 0:
        put(w, 0, get(w, 0) - 1)
        ref = resolve(s, w, get(w, 256 + get(w, 0) * 8))
        if ref == 18446744073709551615:
            return 4294967292
        at = 128 + (ref & 65535) * 64
        name = word(s, at)
        opaque = 0
        if mode == 1:
            if byte(w, 532736 + name) != 0:
                return 1
            if get(w, 32) == 1 and is_reference(s, name) == 1:
                opaque = 1
        else:
            if is_reference(s, name) == 1 or word(s, at + 32) != 0:
                return 1
        if opaque == 0:
            if push_args(s, w, ref) != 0:
                return 4294967292
            if byte(w, 524544 + name) == 0:
                store(w, 524544 + name, 1)
                declaration = get(w, 614720 + name * 8)
                if declaration != 0:
                    declaration = declaration - 1
                    if mode == 2 and word(s, word(s, 96) + declaration * 48 + 40) != 0:
                        return 1
                    env = 0
                    if mode == 1:
                        env = new_env(s, w, ref, declaration)
                    if env == 18446744073709551615 or push_members(s, w, declaration, env) != 0:
                        return 4294967292
    return 0

def push_args(s:readbuf, w:mutbuf, ref:u64) -> u64:
    at = 128 + (ref & 65535) * 64
    first = word(s, at + 8)
    count = word(s, at + 16)
    top = get(w, 0)
    if count > 65536 - top:
        return 1
    i = 0
    while i < count:
        value = word(s, word(s, 104) + (first + i) * 8) | (ref & 18446744073709486080)
        put(w, 256 + (top + i) * 8, value)
        i = i + 1
    put(w, 0, top + count)
    return 0

def push_members(s:readbuf, w:mutbuf, declaration:u64, env:u64) -> u64:
    at = word(s, 96) + declaration * 48
    first = word(s, at + 24)
    count = word(s, at + 32)
    top = get(w, 0)
    if count > 65536 - top:
        return 1
    base = word(s, 104) + (word(s, 32) + word(s, 48)) * 8
    i = 0
    while i < count:
        value = word(s, base + (first + i) * 8) | (env << 16)
        put(w, 256 + (top + i) * 8, value)
        i = i + 1
    put(w, 0, top + count)
    return 0

def new_env(s:readbuf, w:mutbuf, ref:u64, declaration:u64) -> u64:
    at = word(s, 96) + declaration * 48
    count = word(s, at + 16)
    args = word(s, 128 + (ref & 65535) * 64 + 16)
    if count > args:
        count = args
    if count == 0:
        return 0
    env = get(w, 8) + 1
    first = get(w, 16)
    if env > environment_limit(s) or count > binding_limit(s) - first:
        return 18446744073709551615
    put(w, environment_base(s) + env * 16, count)
    put(w, environment_base(s) + env * 16 + 8, first)
    params = word(s, word(s, 96) + declaration * 48 + 8)
    args = word(s, 128 + (ref & 65535) * 64 + 8)
    i = 0
    while i < count:
        name = word(s, word(s, 104) + (word(s, 32) + params + i) * 8)
        target = word(s, word(s, 104) + (args + i) * 8) | (ref & 18446744073709486080)
        put(w, binding_base(s) + (first + i) * 16, name)
        put(w, binding_base(s) + (first + i) * 16 + 8, target)
        i = i + 1
    put(w, 8, env)
    put(w, 16, first + count)
    return env

def resolve(s:readbuf, w:mutbuf, ref:u64) -> u64:
    step = 0
    while step < environment_limit(s) + 1:
        env = ref >> 16
        at = 128 + (ref & 65535) * 64
        if env == 0 or word(s, at + 16) != 0 or word(s, at + 40) != 0:
            return ref
        first = get(w, environment_base(s) + env * 16 + 8)
        i = get(w, environment_base(s) + env * 16)
        found = 0
        target = ref
        while i > 0 and found == 0:
            i = i - 1
            at = binding_base(s) + (first + i) * 16
            if get(w, at) == word(s, 128 + (ref & 65535) * 64):
                target = get(w, at + 8)
                found = 1
        if found == 0:
            return ref
        ref = target
        step = step + 1
    return 18446744073709551615

def is_reference(s:readbuf, name:u64) -> u64:
    if same_word(s, name, W_REF_READ, 8) == 1 or same_word(s, name, W_REF_MUT, 7) == 1:
        return 1
    return 0

def same_word(s:readbuf, symbol:u64, value:u64, size:u64) -> u64:
    row = word(s, 112) + symbol * 16
    begin = word(s, row)
    if word(s, row + 8) - begin != size:
        return 0
    at = word(s, 120) + begin
    i = 0
    while i < size:
        if byte(s, at + i) != ((value >> (i * 8)) & 255):
            return 0
        i = i + 1
    return 1
'''

# Owned-shape traversal uses persistent primary contexts. Temporary linear
# queries have a disjoint pending/visited arena and checkpoint their contexts.
# Native diagnostic cloning emits a postorder type graph, not environments for
# a host-side substitution interpreter.
SOURCE+=r'''
def environment_base(s:readbuf) -> u64:
    if word(s, 8) >= 3:
        return 1360512
    return 540928

def binding_base(s:readbuf) -> u64:
    if word(s, 8) >= 3:
        return 1491600
    return 549136

def environment_limit(s:readbuf) -> u64:
    if word(s, 8) >= 3:
        return 8192
    return 512

def binding_limit(s:readbuf) -> u64:
    if word(s, 8) >= 3:
        return 65536
    return 4096

def get_query(w:mutbuf, at:u64) -> u64:
    return get(w, 680256 + at)

def put_query(w:mutbuf, at:u64, value:u64) -> u64:
    return put(w, 680256 + at, value)

def linear_query(s:readbuf, w:mutbuf, ref:u64) -> u64:
    ref = resolve(s, w, ref)
    if ref == 18446744073709551615:
        return 4294967292
    name = word(s, 128 + (ref & 65535) * 64)
    if byte(w, 532736 + name) != 0:
        return 1
    if get(w, 32) == 1 and is_reference(s, name) == 1:
        return 0
    if word(s, 128 + (ref & 65535) * 64 + 16) == 0 and get(w, 614720 + name * 8) == 0:
        return 0
    env = get(w, 8)
    bindings = get(w, 16)
    code = prepare_query(s, w)
    if code == 0:
        put_query(w, 256, ref)
        code = query_query(s, w, 1)
    put(w, 8, env)
    put(w, 16, bindings)
    return code

def is_owned_container(s:readbuf, name:u64) -> u64:
    if same_word(s, name, W_ARRAY, 5) == 1 or same_word(s, name, W_SLICE, 5) == 1 or same_word(s, name, W_BUFFER, 6) == 1 or same_word(s, name, W_RAW_MUT, 7) == 1:
        return 1
    row = word(s, 112) + name * 16
    if word(s, row + 8) - word(s, row) == 9:
        at = word(s, 120) + word(s, row)
        if word(s, at) == W_RAW_CONS and byte(s, at + 8) == 116:
            return 1
    return 0

def owned_walk(s:readbuf, w:mutbuf) -> u64:
    put(w, 40, 0)
    put(w, 48, 0)
    put(w, 56, 0)
    while get(w, 0) != 0:
        put(w, 0, get(w, 0) - 1)
        ref = resolve(s, w, get(w, 256 + get(w, 0) * 8))
        if ref == 18446744073709551615:
            return 4294967292
        name = word(s, 128 + (ref & 65535) * 64)
        code = 0
        if is_owned_container(s, name) == 1:
            code = owned_container(s, w, ref)
        else:
            code = owned_nominal(s, w, ref)
        if code != 0:
            return code
    return 0

def owned_container(s:readbuf, w:mutbuf, ref:u64) -> u64:
    at = 128 + (ref & 65535) * 64
    first = word(s, at + 8)
    count = word(s, at + 16)
    i = 0
    while i < count:
        child = word(s, word(s, 104) + (first + i) * 8) | (ref & 18446744073709486080)
        code = linear_query(s, w, child)
        if code > 1:
            return code
        if code == 1:
            if get(w, 56) >= 8192:
                return 4294967292
            put(w, 2900624 + get(w, 56) * 8, ref)
            put(w, 56, get(w, 56) + 1)
            return 0
        i = i + 1
    return 0

def owned_nominal(s:readbuf, w:mutbuf, ref:u64) -> u64:
    name = word(s, 128 + (ref & 65535) * 64)
    declaration = get(w, 614720 + name * 8)
    if declaration == 0:
        return 0
    code = owned_seen(s, w, ref)
    if code == 1:
        return 0
    if code != 0:
        return code
    env = new_env(s, w, ref, declaration - 1)
    if env == 18446744073709551615 or push_members(s, w, declaration - 1, env) != 0:
        return 4294967292
    return 0

def owned_mask(s:readbuf, w:mutbuf, ref:u64) -> u64:
    at = 128 + (ref & 65535) * 64
    count = word(s, at + 16)
    size = (count + 7) >> 3
    first = get(w, 48)
    if size > 262144 - first:
        return 4294967292
    i = 0
    while i < size:
        store(w, 2638480 + first + i, 0)
        i = i + 1
    i = 0
    while i < count:
        child = word(s, word(s, 104) + (word(s, at + 8) + i) * 8) | (ref & 18446744073709486080)
        code = linear_query(s, w, child)
        if code > 1:
            return code
        if code == 1:
            offset = 2638480 + first + (i >> 3)
            store(w, offset, byte(w, offset) | (1 << (i & 7)))
        i = i + 1
    return 0

def owned_seen(s:readbuf, w:mutbuf, ref:u64) -> u64:
    code = owned_mask(s, w, ref)
    if code != 0:
        return code
    name = word(s, 128 + (ref & 65535) * 64)
    count = word(s, 128 + (ref & 65535) * 64 + 16)
    size = (count + 7) >> 3
    i = 0
    while i < get(w, 40):
        row = 2540176 + i * 24
        if get(w, row) == name and get(w, row + 8) == count:
            j = 0
            same = 1
            while j < size:
                if byte(w, 2638480 + get(w, row + 16) + j) != byte(w, 2638480 + get(w, 48) + j):
                    same = 0
                j = j + 1
            if same == 1:
                return 1
        i = i + 1
    if get(w, 40) >= 4096:
        return 4294967292
    row = 2540176 + get(w, 40) * 24
    put(w, row, name)
    put(w, row + 8, count)
    put(w, row + 16, get(w, 48))
    put(w, 40, get(w, 40) + 1)
    put(w, 48, get(w, 48) + size)
    return 0

def clone_type(s:readbuf, w:mutbuf, root:u64) -> u64:
    put(w, 96, 1)
    put(w, 104, 0)
    root = resolve(s, w, root)
    if root == 18446744073709551615:
        return 18446744073709551615
    put(w, 2966160, root)
    put(w, 2966168, 0)
    while get(w, 96) != 0:
        row = 2966160 + (get(w, 96) - 1) * 16
        ref = get(w, row)
        at = 128 + (ref & 65535) * 64
        index = get(w, row + 8)
        if index < word(s, at + 16):
            if get(w, 96) >= 8192:
                return 18446744073709551615
            child = word(s, word(s, 104) + (word(s, at + 8) + index) * 8) | (ref & 18446744073709486080)
            child = resolve(s, w, child)
            if child == 18446744073709551615:
                return 18446744073709551615
            put(w, row + 8, index + 1)
            put(w, 2966160 + get(w, 96) * 16, child)
            put(w, 2966160 + get(w, 96) * 16 + 8, 0)
            put(w, 96, get(w, 96) + 1)
        else:
            if clone_finish(s, w, ref) != 0:
                return 18446744073709551615
            put(w, 96, get(w, 96) - 1)
    if get(w, 104) != 1:
        return 18446744073709551615
    return get(w, 3097232)

def clone_finish(s:readbuf, w:mutbuf, ref:u64) -> u64:
    count = word(s, 128 + (ref & 65535) * 64 + 16)
    if get(w, 80) >= 32768 or count > get(w, 104) or count > 65536 - get(w, 88):
        return 1
    first = get(w, 104) - count
    if first >= 65536:
        return 1
    i = 0
    while i < count:
        put(w, 4407952 + (get(w, 88) + i) * 8, get(w, 3097232 + (first + i) * 8))
        i = i + 1
    row = 3621520 + get(w, 80) * 24
    put(w, row, ref & 65535)
    put(w, row + 8, get(w, 88))
    put(w, row + 16, count)
    put(w, 88, get(w, 88) + count)
    put(w, 3097232 + first * 8, get(w, 80))
    put(w, 104, first + 1)
    put(w, 80, get(w, 80) + 1)
    return 0

def owned_result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 80, 0)
    put(w, 88, 0)
    i = 0
    while i < get(w, 56):
        value = clone_type(s, w, get(w, 2900624 + i * 8))
        if value == 18446744073709551615:
            return 4294967292
        put(w, 2900624 + i * 8, value)
        i = i + 1
    size = 32 + get(w, 56) * 8 + get(w, 80) * 24 + get(w, 88) * 8
    if length(o) < size:
        return 4294967294
    put(o, 0, 3549479791681612110)
    put(o, 8, get(w, 56))
    put(o, 16, get(w, 80))
    put(o, 24, get(w, 88))
    i = 0
    while i < get(w, 56):
        put(o, 32 + i * 8, get(w, 2900624 + i * 8))
        i = i + 1
    at = 32 + get(w, 56) * 8
    i = 0
    while i < get(w, 80) * 3:
        put(o, at + i * 8, get(w, 3621520 + i * 8))
        i = i + 1
    at = at + get(w, 80) * 24
    i = 0
    while i < get(w, 88):
        put(o, at + i * 8, get(w, 4407952 + i * 8))
        i = i + 1
    return size
'''
from tools.generate_hia_type_validation import SOURCE as TYPE_VALIDATION_SOURCE
SOURCE+=TYPE_VALIDATION_SOURCE

for name,read,annotation in (('word',True,'readbuf'),('get',True,'mutbuf'),('put',False,'mutbuf')):
    SOURCE+='\ndef '+name+'(s:'+annotation+', at:u64'+('' if read else ', value:u64')+') -> u64:\n'
    if read:
        SOURCE+='    value = 0\n'+''.join(f'    value = value | (byte(s, at + {i}) << {8*i})\n' for i in range(8))+'    return value\n'
    else:SOURCE+=''.join(f'    store(s, at + {i}, (value >> {8*i}) & 255)\n' for i in range(8))+'    return 0\n'

def document():
    source=SOURCE
    for name in ('ref_mut','ref_read','array','slice','Buffer','raw_mut','raw_cons'):
        source=source.replace('W_'+name.upper(),str(int.from_bytes(name.encode(),'little')))
    nodes=ast.parse(source).body
    cloned={'prepare','query','push_args','push_members'}
    class QueryArena(ast.NodeTransformer):
        def visit_Call(self,node):
            self.generic_visit(node)
            if node.func.id in cloned or node.func.id in {'get','put'}:
                node.func.id+='_query'
            elif node.func.id in {'byte','store'} and isinstance(node.args[0],ast.Name) and node.args[0].id=='w':
                node.args[1]=ast.BinOp(left=ast.Constant(value=680256),op=ast.Add(),right=node.args[1])
            return node
        def visit_Assign(self,node):
            self.generic_visit(node)
            if isinstance(node.targets[0],ast.Name) and node.targets[0].id=='mode':node.value=ast.Name(id='native_mode',ctx=ast.Load())
            return node
    for node in list(nodes):
        if node.name in cloned:
            other=QueryArena().visit(copy.deepcopy(node));other.name+='_query'
            if node.name=='query':other.args.args.append(ast.arg(arg='native_mode',annotation=ast.Name(id='u64',ctx=ast.Load())))
            nodes.append(other)
    ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]))
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'type_graph','functions':functions})

def main():
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/type_graph.hiaasm';d=document()
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']))
if __name__=='__main__':main()
