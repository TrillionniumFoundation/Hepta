"""HIA local instruction transfers for the pending live-heap owner.

Frame words at 72/80 hold the four-map state and immutable bigint peak.
The caller pins current function/block names in workspace 96/104. Return 1
means an ordinary completed transfer, 2 is a proved allocation-stop prefix,
and 0 is storage/ABI/semantic failure. Calls are handled by the enclosing
explicit invocation frames. No public selector is installed by this module.
"""

BODY = r'''
def live_error(w:mutbuf, code:u64) -> u64:
    if get(w, 88) == 0:
        put(w, 88, code)
    return 0

def live_peak(w:mutbuf, frame:u64, extra:u64) -> u64:
    amount = live_payload(w, get(w, get(w, frame + 72)))
    if amount == 0:
        return 0
    if extra != 0:
        amount = live_add(w, amount, extra)
        if amount == 0:
            return 0
    if big_cmp(w, amount, get(w, frame + 80)) == 2:
        put(w, frame + 80, amount)
    return 1

def live_root(w:mutbuf, state:u64, source:u64) -> u64:
    owners = get(w, state)
    root = source
    if heap_map_entry(w, owners, source) == 0:
        root = heap_map_get(w, get(w, state + 16), source)
    if root == N:
        return N
    if heap_map_entry(w, owners, root) == 0:
        return N
    return root

def live_free_owner(w:mutbuf, state:u64, name:u64) -> u64:
    if heap_map_get(w, get(w, state), name) == N:
        return 0
    return choose(live_has_root(w, get(w, state + 16), name) == 0, 1, 0)

def live_known_arg(w:mutbuf, known:u64, args:u64, index:u64) -> u64:
    if index >= total(w, args):
        return UNKNOWN
    return live_known(w, known, element(w, args, index))

def live_fold_ins(w:mutbuf, state:u64, ins:u64, op:u64) -> u64:
    known = get(w, state + 8)
    args = field(w, ins, 16)
    result = element(w, field(w, ins, 17), 0)
    attrs = field(w, ins, 18)
    if op == OP_CONST:
        value = live_scalar(w, field(w, attrs, 20))
        return live_remember(w, known, field(w, result, 5), value)
    value = heap_alloc(w, 40)
    if value == 0:
        return 0
    mode = 0
    if op == OP_CAST:
        token = field(w, attrs, 21)
        if text_is(w, token, 7, CHECKED_WORD, 0, 0) != 0:
            mode = 1
        elif text_is(w, token, 4, WRAP_WORD, 0, 0) != 0:
            mode = 2
    status = heap_fold(w, op, type_id(w, field(w, result, 19)), mode, live_known_arg(w, known, args, 0), live_known_arg(w, known, args, 1), live_known_arg(w, known, args, 2), value)
    if status == 16:
        put(w, 80, 2)
        return 0
    if status != 0:
        return live_error(w, 100 + status)
    return live_remember(w, known, field(w, result, 5), value)

def live_allocation(w:mutbuf, frame:u64, mode:u64, ins:u64, op:u64) -> u64:
    state = get(w, frame + 72)
    args = field(w, ins, 16)
    outputs = field(w, ins, 17)
    value = live_known_arg(w, get(w, state + 8), args, 0)
    kind = get(w, value)
    bounded = kind == 2 or kind == 3
    if mode >= 2 and bounded and get(w, value + 8) == 0 and get(w, value + 16) > MAX_REQUEST:
        if op == OP_NEW:
            return 2
        if heap_map_put(w, get(w, state), field(w, element(w, outputs, 0), 5), 0) == 0:
            return 0
        false_value = live_bound(w, 1, 0, 0, 0, 0)
        return live_remember(w, get(w, state + 8), field(w, element(w, outputs, 1), 5), false_value)
    if bounded == False or get(w, value + 8) != 0 or get(w, value + 24) != 0 or get(w, value + 32) > MAX_REQUEST:
        return live_error(w, 20)
    if heap_map_put(w, get(w, state), field(w, element(w, outputs, 0), 5), get(w, value + 32)) == 0:
        return 0
    return live_peak(w, frame, 0)

def live_local(w:mutbuf, frame:u64, mode:u64, ins:u64) -> u64:
    state = get(w, frame + 72)
    op = opcode_id(w, field(w, ins, 15))
    if op < 64 and ((ZERO_SCALARS >> op) & 1) != 0:
        return live_fold_ins(w, state, ins, op)
    if op == OP_NEW or op == OP_TRY:
        return live_allocation(w, frame, mode, ins, op)
    args = field(w, ins, 16)
    outputs = field(w, ins, 17)
    if op == OP_READ or op == OP_MUT:
        root = live_root(w, state, element(w, args, 0))
        if root == N:
            return live_error(w, 21)
        return heap_map_put(w, get(w, state + 16), field(w, element(w, outputs, 0), 5), root)
    if op == OP_END:
        if heap_map_drop(w, get(w, state + 16), element(w, args, 0)) == 0:
            return live_error(w, 22)
        return 1
    if op == OP_MOVE or op == OP_DROP:
        name = element(w, args, 0)
        if live_free_owner(w, state, name) == 0:
            return live_error(w, choose(op == OP_MOVE, 23, 24))
        value = heap_map_get(w, get(w, state), name)
        heap_map_drop(w, get(w, state), name)
        if op == OP_MOVE:
            return heap_map_put(w, get(w, state), field(w, element(w, outputs, 0), 5), value)
        return 1
    if op == OP_LEN:
        root = live_root(w, state, element(w, args, 0))
        if root == N:
            return live_error(w, 25)
        extent = heap_map_get(w, get(w, state), root)
        if extent == N:
            extent = heap_map_get(w, get(w, state + 24), root)
        if extent != N:
            value = live_bound(w, 3, 0, 0, 0, extent)
            return live_remember(w, get(w, state + 8), field(w, element(w, outputs, 0), 5), value)
        return 1
    if op < 64 and ((NO_ALLOCATION >> op) & 1) != 0:
        return 1
    put(w, 112, field(w, ins, 15))
    return live_error(w, 26)
'''
