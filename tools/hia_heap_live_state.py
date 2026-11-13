"""HIA owner inventories, scalar joins and edge remapping for live heap analysis.

Pending analysis authoring, with no public/native selection of its own.
Known scalar values use five words: kind, lo-sign, lo-magnitude, hi-sign,
hi-magnitude. Kinds 0/1/2/3 are unknown/bool/exact-int/closed-span. Kind 4 is
reserved for a finite invocation's borrowed-extent memo argument and is never
accepted as an arithmetic interval. Workspace 768 holds the immutable unknown
value. Owner map N means external caller storage; map presence is separate.
An analysis state is four map pointers: owners, known, loans and extents.
"""

BODY = r'''
def live_bound(w:mutbuf, kind:u64, ls:u64, lm:u64, hs:u64, hm:u64) -> u64:
    result = heap_alloc(w, 40)
    if result == 0:
        return 0
    put(w, result, kind)
    put(w, result + 8, ls)
    put(w, result + 16, lm)
    put(w, result + 24, hs)
    put(w, result + 32, hm)
    return result

def live_combine(w:mutbuf, left:u64, right:u64) -> u64:
    result = heap_alloc(w, 40)
    if result == 0:
        return 0
    if heap_combine(w, left, right, result) != 0:
        put(w, 80, 2)
        return 0
    return result

def live_scalar(w:mutbuf, node:u64) -> u64:
    if tag(w, node) == 1:
        value = byte(w, node + 16)
        return live_bound(w, 1, 0, value, 0, value)
    if tag(w, node) == 2:
        at = node + 16
        negative = 0
        if byte(w, at) == 45:
            negative = 1
            at = at + 1
        value = 0
        while at < end(w, node):
            value = value * 10 + byte(w, at) - 48
            at = at + 1
        return live_bound(w, 2, negative, value, negative, value)
    return UNKNOWN

def live_intrinsic(w:mutbuf, typ:u64) -> u64:
    result = heap_alloc(w, 40)
    if result == 0:
        return 0
    if heap_entry_value(w, typ, result) != 0:
        put(w, 80, 2)
        return 0
    return result

def live_known(w:mutbuf, table:u64, name:u64) -> u64:
    value = heap_map_get(w, table, name)
    return choose(value == N, UNKNOWN, value)

def live_remember(w:mutbuf, table:u64, name:u64, value:u64) -> u64:
    if value == 0:
        return 0
    if get(w, value) == 0:
        return 1
    return heap_map_put(w, table, name, value)

def live_has_root(w:mutbuf, loans:u64, root:u64) -> u64:
    entry = get(w, loans)
    while entry != 0:
        if same_text(w, get(w, entry + 16), root) != 0:
            return 1
        entry = get(w, entry)
    return 0

def live_big(w:mutbuf, value:u64) -> u64:
    result = heap_alloc(w, 40)
    if result == 0:
        return 0
    big_init(w, result, 2)
    big_set_u64(w, result, 0, value)
    return result

def live_add(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left + 8)
    b = get(w, right + 8)
    capacity = choose(a > b, a, b) + 1
    result = heap_alloc(w, 24 + capacity * 8)
    if result == 0:
        return 0
    big_init(w, result, capacity)
    if big_add(w, result, left, right) == 0:
        put(w, 80, 4)
        return 0
    return result

def live_payload(w:mutbuf, owners:u64) -> u64:
    result = live_big(w, 0)
    if result == 0:
        return 0
    entry = get(w, owners)
    while entry != 0:
        amount = get(w, entry + 16)
        if amount != N:
            value = live_big(w, amount)
            if value == 0:
                return 0
            result = live_add(w, result, value)
            if result == 0:
                return 0
        entry = get(w, entry)
    return result

def live_state(w:mutbuf) -> u64:
    state = heap_alloc(w, 32)
    if state == 0:
        return 0
    index = 0
    while index < 4:
        table = heap_map(w)
        if table == 0:
            return 0
        put(w, state + index * 8, table)
        index = index + 1
    return state

def live_copy_state(w:mutbuf, state:u64) -> u64:
    result = heap_alloc(w, 32)
    if result == 0:
        return 0
    index = 0
    while index < 4:
        table = heap_map_copy(w, get(w, state + index * 8))
        if table == 0:
            return 0
        put(w, result + index * 8, table)
        index = index + 1
    return result

def live_join_error(w:mutbuf, code:u64) -> u64:
    put(w, 88, code)
    return 0

def live_join(w:mutbuf, previous:u64, proposed:u64) -> u64:
    old_owners = get(w, previous)
    new_owners = get(w, proposed)
    if get(w, old_owners + 8) != get(w, new_owners + 8):
        return live_join_error(w, 1)
    entry = get(w, old_owners)
    while entry != 0:
        if heap_map_entry(w, new_owners, get(w, entry + 8)) == 0:
            return live_join_error(w, 1)
        entry = get(w, entry)
    old_loans = get(w, previous + 16)
    new_loans = get(w, proposed + 16)
    if get(w, old_loans + 8) != get(w, new_loans + 8):
        return live_join_error(w, 2)
    entry = get(w, old_loans)
    while entry != 0:
        other = heap_map_get(w, new_loans, get(w, entry + 8))
        if other == N or same_text(w, other, get(w, entry + 16)) == 0:
            return live_join_error(w, 2)
        entry = get(w, entry)
    result = live_state(w)
    if result == 0:
        return 0
    entry = get(w, old_owners)
    while entry != 0:
        name = get(w, entry + 8)
        old = get(w, entry + 16)
        new = heap_map_get(w, new_owners, name)
        if (old == N) != (new == N):
            return live_join_error(w, 3)
        value = choose(old > new, old, new)
        if heap_map_put(w, get(w, result), name, value) == 0:
            return 0
        entry = get(w, entry)
    entry = get(w, get(w, previous + 8))
    while entry != 0:
        name = get(w, entry + 8)
        other = heap_map_get(w, get(w, proposed + 8), name)
        if other != N:
            combined = live_combine(w, get(w, entry + 16), other)
            if live_remember(w, get(w, result + 8), name, combined) == 0:
                return 0
        entry = get(w, entry)
    copied = heap_map_copy(w, old_loans)
    if copied == 0:
        return 0
    put(w, result + 16, copied)
    entry = get(w, get(w, previous + 24))
    while entry != 0:
        name = get(w, entry + 8)
        other = heap_map_get(w, get(w, proposed + 24), name)
        if other != N:
            value = get(w, entry + 16)
            value = choose(value > other, value, other)
            if heap_map_put(w, get(w, result + 24), name, value) == 0:
                return 0
        entry = get(w, entry)
    return result

def live_forward(w:mutbuf, state:u64, args:u64, parameters:u64) -> u64:
    result = live_state(w)
    remap = heap_map(w)
    if result == 0 or remap == 0:
        return 0
    index = 0
    while index < total(w, parameters):
        param = element(w, parameters, index)
        typ = type_id(w, field(w, param, 19))
        if typ == 13 or typ == 14 or typ == 15:
            if heap_map_put(w, remap, element(w, args, index), field(w, param, 5)) == 0:
                return 0
        index = index + 1
    index = 0
    while index < total(w, parameters):
        source = element(w, args, index)
        param = element(w, parameters, index)
        name = field(w, param, 5)
        typ = type_id(w, field(w, param, 19))
        if typ == 13:
            value = heap_map_get(w, get(w, state), source)
            if value == N:
                return live_join_error(w, 4)
            if heap_map_put(w, get(w, result), name, value) == 0:
                return 0
        elif typ == 14 or typ == 15:
            root = heap_map_get(w, get(w, state + 16), source)
            target = N
            if root != N:
                target = heap_map_get(w, remap, root)
            if target == N:
                return live_join_error(w, 5)
            if heap_map_put(w, get(w, result + 16), name, target) == 0:
                return 0
            if heap_map_entry(w, get(w, state), root) == 0:
                put(w, 80, 2)
                return 0
            if heap_map_get(w, get(w, state), root) == N:
                if heap_map_put(w, get(w, result), target, N) == 0:
                    return 0
                extent = heap_map_get(w, get(w, state + 24), root)
                if extent != N:
                    if heap_map_put(w, get(w, result + 24), target, extent) == 0:
                        return 0
        elif typ >= 1 and typ <= 12:
            value = live_known(w, get(w, state + 8), source)
            if live_remember(w, get(w, result + 8), name, value) == 0:
                return 0
        index = index + 1
    return result
'''
