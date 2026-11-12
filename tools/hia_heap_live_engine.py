"""Pending HIA CFG and finite invocation engine for live payload analysis.

All abstract states, work limits, memo keys, call transfers and branch joins
are native HIA decisions. This private kernel expects the same reverified
canonical Core supplied by its eventual public controller; it does not confer
Core verification or public admission itself. Mode 0 is legacy all-function,
1 is borrowed local peaks, and 2/3/4 are the original three finite profiles.

The analysis record stores functions/mode/current frame/context count/steps/
depth/peak depth/memo/result in consecutive words. A 144-byte frame stores
parent/function/arguments/CFG/order/states/order index/block/op index/state/
peak/returns/phase/waiting instruction. Offset 120 retains the next instruction
node, so sequential execution never rescans a block prefix. Values and bigint
results are immutable.
"""

BODY = r'''
def heap_live_kernel(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < BASE or length(s) > length(w) - BASE or length(o) < 32:
        return ABI
    if src_validate(s, w) == 0:
        return ABI
    fill_range(w, 0, BASE, 0)
    live_literals(w)
    copy_in(w, s, BASE, 0, length(s))
    put(w, 64, (BASE + length(s) + 7) & 18446744073709551608)
    if tag(w, BASE) != 5 or total(w, BASE) != 4:
        return ABI
    mode = decimal(w, element(w, BASE, 0))
    if mode > 4:
        return ABI
    analysis = heap_alloc(w, 80)
    graph = live_call_graph(w, element(w, BASE, 1))
    if analysis == 0 or graph == 0:
        return live_status(w)
    put(w, analysis, graph)
    put(w, analysis + 8, mode)
    selected = N
    if mode < 2:
        order = heap_topological(w, graph)
        if order == N:
            put(w, 80, 0)
            live_error(w, 41)
            return 3
        if order == 0:
            return live_status(w)
        index = get(w, order)
        while index != 0:
            index = index - 1
            node = heap_node(w, graph, get(w, order + 8 + index * 8))
            if live_push(w, analysis, get(w, node + 8), 0) == 0:
                return live_status(w)
            if live_drive(w, analysis) == 0:
                return live_status(w)
            put(w, node + 32, get(w, get(w, analysis + 64)))
    else:
        selected = heap_named(w, graph, element(w, BASE, 2))
        if selected == N:
            return ABI
        args = element(w, BASE, 3)
        values = live_values(w, total(w, args))
        if values == 0:
            return live_status(w)
        index = 0
        while index < total(w, args):
            value = live_scalar(w, element(w, args, index))
            if value == 0:
                return live_status(w)
            put(w, values + 8 + index * 8, value)
            index = index + 1
        if live_push(w, analysis, get(w, heap_node(w, graph, selected) + 8), values) == 0:
            return live_status(w)
        if live_drive(w, analysis) == 0:
            return live_status(w)
    put(o, 0, analysis)
    put(o, 8, graph)
    put(o, 16, selected)
    put(o, 24, mode)
    return 0

def live_status(w:mutbuf) -> u32:
    if get(w, 88) != 0:
        return 3
    if get(w, 80) != 0:
        return ABI
    return 1

def live_graph(w:mutbuf, items:u64, functions:u64) -> u64:
    graph = heap_graph(w, total(w, items))
    if graph == 0:
        return 0
    index = 0
    while index < total(w, items):
        item = element(w, items, index)
        node = heap_node(w, graph, index)
        put(w, node, field(w, item, choose(functions != 0, 5, 12)))
        put(w, node + 8, item)
        index = index + 1
    return graph

def live_link(w:mutbuf, graph:u64, source:u64, name:u64) -> u64:
    target = heap_named(w, graph, name)
    if target == N:
        return live_error(w, 40)
    return heap_edge(w, graph, source, target)

def live_call_graph(w:mutbuf, document:u64) -> u64:
    functions = field(w, document, 3)
    graph = live_graph(w, functions, 1)
    if graph == 0:
        return 0
    index = 0
    while index < total(w, functions):
        blocks = field(w, element(w, functions, index), 10)
        block_index = 0
        while block_index < total(w, blocks):
            ops = field(w, element(w, blocks, block_index), 13)
            op_index = 0
            ins = ops + 24
            while op_index < total(w, ops):
                if opcode_id(w, field(w, ins, 15)) == OP_CALL:
                    if live_link(w, graph, index, field(w, field(w, ins, 18), 22)) == 0:
                        return 0
                ins = end(w, ins)
                op_index = op_index + 1
            block_index = block_index + 1
        index = index + 1
    return graph

def live_cfg(w:mutbuf, fn:u64) -> u64:
    blocks = field(w, fn, 10)
    graph = live_graph(w, blocks, 0)
    if graph == 0:
        return 0
    index = 0
    while index < total(w, blocks):
        term = field(w, element(w, blocks, index), 14)
        kind = term_id(w, field(w, term, 15))
        if kind == 2:
            if live_link(w, graph, index, field(w, term, 24)) == 0:
                return 0
        elif kind == 3:
            if live_link(w, graph, index, field(w, field(w, term, 25), 24)) == 0:
                return 0
            if live_link(w, graph, index, field(w, field(w, term, 26), 24)) == 0:
                return 0
        index = index + 1
    return graph

def live_boundary(w:mutbuf, fn:u64, mode:u64) -> u64:
    if mode >= 2:
        return 1
    part = 0
    while part < 2:
        values = field(w, fn, choose(part == 0, 6, 7))
        index = 0
        while index < total(w, values):
            typ = element(w, values, index)
            if part == 0:
                typ = field(w, typ, 19)
            kind = type_id(w, typ)
            if kind == 13 or (mode == 0 and (kind == 14 or kind == 15)):
                return live_error(w, 10 + part)
            index = index + 1
        part = part + 1
    return 1

def live_zero(w:mutbuf, fn:u64) -> u64:
    blocks = field(w, fn, 10)
    block_index = 0
    while block_index < total(w, blocks):
        ops = field(w, element(w, blocks, block_index), 13)
        index = 0
        while index < total(w, ops):
            op = opcode_id(w, field(w, element(w, ops, index), 15))
            if op >= 64 or ((ZERO_SCALARS >> op) & 1) == 0:
                return 0
            index = index + 1
        block_index = block_index + 1
    return 1

def live_values(w:mutbuf, count:u64) -> u64:
    values = heap_alloc(w, 8 + count * 8)
    if values != 0:
        put(w, values, count)
    return values

def live_initial(w:mutbuf, fn:u64, args:u64, mode:u64) -> u64:
    params = field(w, fn, 6)
    if mode >= 2:
        if args == 0 or get(w, args) != total(w, params):
            return live_error(w, 13)
    state = live_state(w)
    if state == 0:
        return 0
    index = 0
    while index < total(w, params):
        param = element(w, params, index)
        name = field(w, param, 5)
        typ = type_id(w, field(w, param, 19))
        value = live_intrinsic(w, typ)
        if value == 0:
            return 0
        bound = UNKNOWN
        if mode >= 2:
            bound = get(w, args + 8 + index * 8)
        if typ == 13 and mode >= 2:
            if get(w, bound) != 2 or get(w, bound + 8) != 0 or get(w, bound + 16) > MAX_REQUEST:
                return live_error(w, 14)
            if heap_map_put(w, get(w, state), name, get(w, bound + 16)) == 0:
                return 0
        elif typ == 14 or typ == 15:
            if heap_map_put(w, get(w, state), name, N) == 0 or heap_map_put(w, get(w, state + 16), name, name) == 0:
                return 0
            if get(w, bound) != 0:
                if mode != 4 or get(w, bound) != 4 or get(w, bound + 8) != 0 or get(w, bound + 16) > MAX_REQUEST:
                    return live_error(w, 15)
                if heap_map_put(w, get(w, state + 24), name, get(w, bound + 16)) == 0:
                    return 0
        elif get(w, bound) != 0:
            value = bound
        if live_remember(w, get(w, state + 8), name, value) == 0:
            return 0
        index = index + 1
    return state

def live_same_values(w:mutbuf, left:u64, right:u64) -> u64:
    if get(w, left) != get(w, right):
        return 0
    index = 0
    while index < get(w, left):
        a = get(w, left + 8 + index * 8)
        b = get(w, right + 8 + index * 8)
        word_index = 0
        while word_index < 5:
            if get(w, a + word_index * 8) != get(w, b + word_index * 8):
                return 0
            word_index = word_index + 1
        index = index + 1
    return 1

def live_push(w:mutbuf, analysis:u64, fn:u64, args:u64) -> u64:
    mode = get(w, analysis + 8)
    if mode >= 2:
        memo = get(w, analysis + 56)
        while memo != 0:
            if get(w, memo + 8) == fn and live_same_values(w, get(w, memo + 16), args) != 0:
                put(w, analysis + 64, get(w, memo + 24))
                return 2
            memo = get(w, memo)
        if get(w, analysis + 24) >= 1024 or get(w, analysis + 40) >= 64:
            return live_error(w, 50)
        put(w, analysis + 24, get(w, analysis + 24) + 1)
        depth = get(w, analysis + 40) + 1
        put(w, analysis + 40, depth)
        if depth > get(w, analysis + 48):
            put(w, analysis + 48, depth)
    frame = heap_alloc(w, 144)
    peak = live_big(w, 0)
    if frame == 0 or peak == 0:
        return 0
    put(w, frame, get(w, analysis + 16))
    put(w, frame + 8, fn)
    put(w, frame + 16, args)
    put(w, frame + 80, peak)
    put(w, 96, field(w, fn, 5))
    put(w, 104, 0)
    if live_boundary(w, fn, mode) == 0:
        return 0
    put(w, analysis + 16, frame)
    if mode < 2 and live_zero(w, fn) != 0:
        put(w, frame + 96, 4)
        return 1
    cfg = live_cfg(w, fn)
    if cfg == 0:
        return 0
    put(w, frame + 24, cfg)
    order = heap_topological(w, cfg)
    if order == N:
        put(w, 80, 0)
        if mode >= 2:
            return live_error(w, 41)
        scoped = cycle_peak(w, fn)
        if scoped == N:
            return live_error(w, 41)
        if scoped == 0:
            if get(w, 88) != 0:
                put(w, 88, 100 + get(w, 88))
            return 0
        put(w, frame + 80, scoped)
        put(w, frame + 96, 4)
        return 1
    if order == 0:
        return 0
    states = heap_alloc(w, get(w, cfg) * 8)
    initial = live_initial(w, fn, args, mode)
    if states == 0 or initial == 0:
        return 0
    entry = heap_named(w, cfg, field(w, fn, 9))
    if entry == N:
        return live_error(w, 40)
    put(w, states + entry * 8, initial)
    put(w, frame + 32, order)
    put(w, frame + 40, states)
    return 1

def live_step_count(w:mutbuf, analysis:u64) -> u64:
    if get(w, analysis + 8) < 2:
        return 1
    steps = get(w, analysis + 32) + 1
    put(w, analysis + 32, steps)
    if steps > 32768:
        return live_error(w, 51)
    return 1

def live_next_block(w:mutbuf, frame:u64) -> u64:
    put(w, frame + 48, get(w, frame + 48) + 1)
    put(w, frame + 96, 0)
    put(w, frame + 56, 0)
    put(w, frame + 64, 0)
    put(w, frame + 120, 0)
    return 1

def live_enter_block(w:mutbuf, analysis:u64, frame:u64) -> u64:
    order = get(w, frame + 32)
    if get(w, frame + 48) == get(w, order):
        put(w, frame + 96, 4)
        return 1
    if live_step_count(w, analysis) == 0:
        return 0
    ident = get(w, order + 8 + get(w, frame + 48) * 8)
    block = get(w, heap_node(w, get(w, frame + 24), ident) + 8)
    put(w, frame + 56, block)
    put(w, 104, field(w, block, 12))
    state = get(w, get(w, frame + 40) + ident * 8)
    if state == 0:
        if get(w, analysis + 8) >= 2:
            return live_next_block(w, frame)
        return live_error(w, 12)
    state = live_copy_state(w, state)
    if state == 0:
        return 0
    put(w, frame + 72, state)
    put(w, frame + 96, 1)
    put(w, frame + 120, field(w, block, 13) + 24)
    return live_peak(w, frame, 0)

def live_child_bounds(w:mutbuf, frame:u64, child:u64, ins:u64, mode:u64) -> u64:
    params = field(w, child, 6)
    actuals = field(w, ins, 16)
    values = live_values(w, total(w, params))
    moved = heap_map(w)
    if values == 0 or moved == 0:
        return 0
    state = get(w, frame + 72)
    index = 0
    while index < total(w, params):
        actual = element(w, actuals, index)
        typ = type_id(w, field(w, element(w, params, index), 19))
        value = UNKNOWN
        if typ == 13:
            if live_free_owner(w, state, actual) == 0 or heap_map_entry(w, moved, actual) != 0:
                return live_error(w, 27)
            if heap_map_put(w, moved, actual, 1) == 0:
                return 0
            amount = heap_map_get(w, get(w, state), actual)
            value = live_bound(w, 2, 0, amount, 0, amount)
        elif typ == 14 or typ == 15:
            root = heap_map_get(w, get(w, state + 16), actual)
            if root == N:
                return live_error(w, 28)
            if heap_map_entry(w, get(w, state), root) == 0:
                return live_error(w, 28)
            extent = heap_map_get(w, get(w, state), root)
            if extent == N:
                extent = heap_map_get(w, get(w, state + 24), root)
            if mode == 4 and extent != N:
                value = live_bound(w, 4, 0, extent, 0, extent)
        else:
            value = live_known(w, get(w, state + 8), actual)
        if value == 0:
            return 0
        put(w, values + 8 + index * 8, value)
        index = index + 1
    entry = get(w, moved)
    while entry != 0:
        heap_map_drop(w, get(w, state), get(w, entry + 8))
        entry = get(w, entry)
    return values

def live_loan_returns(w:mutbuf, state:u64, child:u64, ins:u64) -> u64:
    outputs = field(w, ins, 17)
    origins = field(w, child, 11)
    params = field(w, child, 6)
    args = field(w, ins, 16)
    index = 0
    while index < total(w, outputs):
        output = element(w, outputs, index)
        typ = type_id(w, field(w, output, 19))
        if typ == 14 or typ == 15:
            source = N
            if origins != N:
                origin = element(w, origins, index)
                param_index = 0
                while param_index < total(w, params):
                    if same_text(w, origin, field(w, element(w, params, param_index), 5)) != 0:
                        source = element(w, args, param_index)
                    param_index = param_index + 1
            if source == N:
                return live_error(w, 34)
            root = heap_map_get(w, get(w, state + 16), source)
            if root == N:
                return live_error(w, 34)
            if heap_map_entry(w, get(w, state), root) == 0:
                return live_error(w, 34)
            if heap_map_put(w, get(w, state + 16), field(w, output, 5), root) == 0:
                return 0
        index = index + 1
    return 1

def live_apply_child(w:mutbuf, analysis:u64, frame:u64, ins:u64, child:u64) -> u64:
    result = get(w, analysis + 64)
    if live_peak(w, frame, get(w, result)) == 0:
        return 0
    values = get(w, result + 8)
    if values == 0:
        return 2
    outputs = field(w, ins, 17)
    if get(w, values) != total(w, outputs):
        return live_error(w, 29)
    state = get(w, frame + 72)
    index = 0
    while index < total(w, outputs):
        output = element(w, outputs, index)
        name = field(w, output, 5)
        typ = type_id(w, field(w, output, 19))
        value = get(w, values + 8 + index * 8)
        if typ == 13:
            if get(w, value) != 2 or get(w, value + 8) != 0 or get(w, value + 16) > MAX_REQUEST:
                return live_error(w, 30)
            if heap_map_put(w, get(w, state), name, get(w, value + 16)) == 0:
                return 0
        elif typ == 14 or typ == 15:
            if get(w, analysis + 8) < 3 or get(w, value) != 0:
                return live_error(w, 31)
        elif live_remember(w, get(w, state + 8), name, value) == 0:
            return 0
        index = index + 1
    if live_peak(w, frame, 0) == 0:
        return 0
    if get(w, analysis + 8) >= 3:
        return live_loan_returns(w, state, child, ins)
    return 1

def live_call(w:mutbuf, analysis:u64, frame:u64, ins:u64) -> u64:
    graph = get(w, analysis)
    child_id = heap_named(w, graph, field(w, field(w, ins, 18), 22))
    if child_id == N:
        return live_error(w, 40)
    node = heap_node(w, graph, child_id)
    child = get(w, node + 8)
    mode = get(w, analysis + 8)
    if mode >= 2:
        values = live_child_bounds(w, frame, child, ins, mode)
        if values == 0:
            return 0
        put(w, frame + 104, ins)
        put(w, frame + 112, child)
        put(w, frame + 96, 2)
        pushed = live_push(w, analysis, child, values)
        if pushed == 0:
            return 0
        return 3
    if live_boundary(w, child, mode) == 0:
        put(w, 88, 32)
        return 0
    bound = get(w, node + 32)
    if bound == 0:
        return live_error(w, 33)
    if live_peak(w, frame, bound) == 0:
        return 0
    if mode == 1:
        return live_loan_returns(w, get(w, frame + 72), child, ins)
    return 1

def live_returns(w:mutbuf, analysis:u64, frame:u64, term:u64) -> u64:
    types = field(w, get(w, frame + 8), 7)
    sources = field(w, term, 23)
    values = live_values(w, total(w, types))
    if values == 0:
        return 0
    state = get(w, frame + 72)
    previous = get(w, frame + 88)
    index = 0
    while index < total(w, types):
        typ = type_id(w, element(w, types, index))
        source = element(w, sources, index)
        value = UNKNOWN
        if typ == 13:
            amount = heap_map_get(w, get(w, state), source)
            if amount == N:
                return live_error(w, 35)
            if previous != 0:
                old = get(w, get(w, previous + 8 + index * 8) + 16)
                amount = choose(amount > old, amount, old)
            value = live_bound(w, 2, 0, amount, 0, amount)
        elif typ == 14 or typ == 15:
            root = heap_map_get(w, get(w, state + 16), source)
            if get(w, analysis + 8) < 3 or root == N:
                return live_error(w, 36)
            if heap_map_entry(w, get(w, state), root) == 0 or heap_map_get(w, get(w, state), root) != N:
                return live_error(w, 36)
        else:
            value = live_known(w, get(w, state + 8), source)
            if previous != 0:
                value = live_combine(w, get(w, previous + 8 + index * 8), value)
        if value == 0:
            return 0
        put(w, values + 8 + index * 8, value)
        index = index + 1
    put(w, frame + 88, values)
    return 1

def live_edge(w:mutbuf, frame:u64, edge:u64) -> u64:
    put(w, 104, field(w, get(w, frame + 56), 12))
    cfg = get(w, frame + 24)
    ident = heap_named(w, cfg, field(w, edge, 24))
    if ident == N:
        return live_error(w, 40)
    node = heap_node(w, cfg, ident)
    proposed = live_forward(w, get(w, frame + 72), field(w, edge, 16), field(w, get(w, node + 8), 6))
    if proposed == 0:
        return 0
    previous = get(w, get(w, frame + 40) + ident * 8)
    if previous != 0:
        put(w, 104, get(w, node))
        proposed = live_join(w, previous, proposed)
        if proposed == 0:
            return 0
    put(w, get(w, frame + 40) + ident * 8, proposed)
    return 1

def live_terminate_block(w:mutbuf, analysis:u64, frame:u64) -> u64:
    if live_step_count(w, analysis) == 0:
        return 0
    term = field(w, get(w, frame + 56), 14)
    kind = term_id(w, field(w, term, 15))
    if get(w, analysis + 8) >= 2 and kind == 1:
        if live_returns(w, analysis, frame, term) == 0:
            return 0
    if kind == 2:
        if live_edge(w, frame, term) == 0:
            return 0
    elif kind == 3:
        if live_edge(w, frame, field(w, term, 25)) == 0:
            return 0
        if live_edge(w, frame, field(w, term, 26)) == 0:
            return 0
    return live_next_block(w, frame)

def live_complete(w:mutbuf, analysis:u64, frame:u64) -> u64:
    result = heap_alloc(w, 16)
    if result == 0:
        return 0
    put(w, result, get(w, frame + 80))
    put(w, result + 8, get(w, frame + 88))
    if get(w, analysis + 8) >= 2:
        memo = heap_alloc(w, 32)
        if memo == 0:
            return 0
        put(w, memo, get(w, analysis + 56))
        put(w, memo + 8, get(w, frame + 8))
        put(w, memo + 16, get(w, frame + 16))
        put(w, memo + 24, result)
        put(w, analysis + 56, memo)
        put(w, analysis + 40, get(w, analysis + 40) - 1)
    put(w, analysis + 64, result)
    put(w, analysis + 16, get(w, frame))
    return 1

def live_drive(w:mutbuf, analysis:u64) -> u64:
    while get(w, analysis + 16) != 0:
        frame = get(w, analysis + 16)
        put(w, 96, field(w, get(w, frame + 8), 5))
        if get(w, frame + 56) != 0:
            put(w, 104, field(w, get(w, frame + 56), 12))
        phase = get(w, frame + 96)
        status = 1
        if phase == 0:
            status = live_enter_block(w, analysis, frame)
        elif phase == 2:
            status = live_apply_child(w, analysis, frame, get(w, frame + 104), get(w, frame + 112))
            put(w, frame + 96, 1)
            put(w, frame + 64, get(w, frame + 64) + 1)
            put(w, frame + 120, end(w, get(w, frame + 104)))
        elif phase == 4:
            status = live_complete(w, analysis, frame)
        else:
            ops = field(w, get(w, frame + 56), 13)
            index = get(w, frame + 64)
            if index == total(w, ops):
                status = live_terminate_block(w, analysis, frame)
            else:
                if live_step_count(w, analysis) == 0:
                    return 0
                ins = get(w, frame + 120)
                if opcode_id(w, field(w, ins, 15)) == OP_CALL:
                    status = live_call(w, analysis, frame, ins)
                else:
                    status = live_local(w, frame, get(w, analysis + 8), ins)
                if status == 1:
                    put(w, frame + 64, index + 1)
                    put(w, frame + 120, end(w, ins))
        if status == 0:
            return 0
        if status == 2:
            live_next_block(w, frame)
    return 1
'''


ERROR_DETAILS = {
    1: 'incompatible owner inventory at a CFG join',
    2: 'incompatible borrowed owner roots',
    3: 'local owner and external loan roots disagree',
    4: 'missing bounded owner at edge',
    5: 'loan edge lacks its bounded owner',
    10: 'resource arguments have unbounded external extent',
    11: 'owned return needs a caller-size invariant',
    12: 'missing reachable CFG input',
    13: 'finite invocation argument inventory differs',
    14: 'owned argument needs a proved finite extent',
    15: 'external borrowed extent promises are not admitted',
    20: 'allocator extent lacks a finite verified bound',
    21: 'borrowed extent lacks a bounded owner root',
    22: 'ending a loan without a bounded root',
    23: 'owner move lacks a free bounded source',
    24: 'drop lacks a free bounded source',
    25: 'buffer.len lacks a bounded root',
    26: 'unreviewed opcode {extra} has no heap accounting',
    27: 'call lacks a free bounded owned argument',
    28: 'borrowed call lacks its retained caller root',
    29: 'callee return inventory differs',
    30: 'returned owner lacks a bounded extent',
    31: 'invocation cannot return this loan',
    32: 'interprocedural resource transfer requires a separate proof',
    33: 'callee heap bound not available',
    34: 'returned loan lacks its caller root',
    35: 'returned owner has no bounded root',
    36: 'returned loan lacks an external formal root',
    50: 'finite invocation context/depth analysis limit exceeded',
    51: 'finite invocation abstract-transfer work limit exceeded',
    101: 'checked constant arithmetic may trap',
    102: 'unreviewed integer cast mode cannot qualify a heap budget',
    103: 'checked constant shift count traps',
    104: 'checked constant division or remainder traps',
    105: 'checked constant negation may trap',
}


def source_program():
    import ast
    from tools.generate_hia_program_execution import source_program as common, OP_IDS, FIELDS, TYPES
    from tools.hia_heap_bound_graphs import BODY as GRAPHS
    from tools.hia_heap_live_state import BODY as STATE
    from tools.hia_heap_live_transfers import BODY as TRANSFERS
    from tools.hia_heap_scoped_cycle import BODY as SCOPED
    from tools.hia_native_bigints import BODY as BIGINTS
    from tools.hia_native_heap_intervals import BODY as INTERVALS
    zero = ('const int.cast int.neg.checked select bool.not bool.and bool.or '
            'bit.and bit.or bit.xor bit.not compare.eq compare.ne compare.lt compare.le compare.gt compare.ge '
            'int.add.checked int.sub.checked int.mul.checked int.add.wrap int.sub.wrap int.mul.wrap '
            'int.div.checked int.rem.checked int.shl.checked int.shr.checked').split()
    no_allocation = [name for name in zero if name != 'const'] + (
        'buffer.len borrow.read borrow.mut loan.end buffer.load buffer.store buffer.fill buffer.copy '
        'buffer.move_within buffer.fill_range buffer.copy_range buffer.swap').split()
    constants = {'BASE': 8192, 'ABI': 0xfffffff1, 'N': (1 << 64) - 1, 'UNKNOWN': 768,
        'MAX_REQUEST': (1 << 63) - 1, 'ZERO_SCALARS': sum(1 << OP_IDS[name] for name in zero),
        'NO_ALLOCATION': sum(1 << OP_IDS[name] for name in no_allocation),
        'CHECKED_WORD': int.from_bytes(b'checked', 'little'), 'WRAP_WORD': int.from_bytes(b'wrap', 'little')}
    constants.update({'OP_' + name: OP_IDS[op] for name, op in (
        ('CONST', 'const'), ('CAST', 'int.cast'), ('NEW', 'buffer.new'), ('TRY', 'buffer.try_new'),
        ('READ', 'borrow.read'), ('MUT', 'borrow.mut'), ('END', 'loan.end'), ('MOVE', 'owner.move'),
        ('DROP', 'owner.drop'), ('LEN', 'buffer.len'), ('CALL', 'call'))})
    nodes = ast.parse(BODY + STATE + TRANSFERS + SCOPED + GRAPHS + BIGINTS + INTERVALS).body
    shared = {'get', 'put', 'word', 'tag', 'size_of', 'end', 'total', 'element', 'same_text', 'text_is',
              'src_validate', 'src_word', 'decimal', 'field', 'field_id', 'type_id', 'opcode_id', 'term_id', 'cast_id'}
    nodes += [node for node in ast.parse(common()).body if node.name in shared]
    # Literal tables are immutable native data in the private header. The one
    # HIA lookup loop replaces five repeated chains of exact text comparisons.
    # Every ID and every byte is still fixed by the original closed catalog.
    catalogs = {'field_id': FIELDS, 'opcode_id': tuple(OP_IDS), 'type_id': TYPES,
                'term_id': ('ret', 'jump', 'branch', 'trap'), 'cast_id': ('checked', 'wrap')}
    table = 4096
    locations = {}
    lines = ['def live_literals(w:mutbuf) -> u64:']
    for name, values in catalogs.items():
        locations[name] = (table, len(values))
        for value in values:
            raw = value.encode('ascii')
            assert len(raw) <= 24
            lines.append(f'    put(w, {table}, {len(raw)})')
            for index in range(3):
                word = int.from_bytes(raw[index * 8:index * 8 + 8], 'little')
                if word:
                    lines.append(f'    put(w, {table + 8 + index * 8}, {word})')
            table += 32
    assert table <= 8192
    lines += ['    return 0', 'def live_token(w:mutbuf, node:u64, table:u64, count:u64) -> u64:',
              '    if node == N:', '        return 0', '    index = 0', '    while index < count:',
              '        row = table + index * 32',
              '        if text_is(w, node, get(w, row), get(w, row + 8), get(w, row + 16), get(w, row + 24)) != 0:',
              '            return index + 1', '        index = index + 1', '    return 0']
    nodes = [node for node in nodes if node.name not in catalogs] + ast.parse('\n'.join(lines)).body
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in locations:
                offset, count = locations[node.func.id]
                assert len(node.args) == 2
                node.func.id = 'live_token'
                node.args += [ast.Constant(offset), ast.Constant(count)]
            return node
    nodes = [Expand().visit(node) for node in nodes]
    by_name = {node.name: node for node in nodes}
    assert len(by_name) == len(nodes)
    used, pending = set(), ['heap_live_kernel']
    while pending:
        name = pending.pop()
        if name in used:
            continue
        used.add(name)
        pending.extend(node.func.id for node in ast.walk(by_name[name])
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in by_name)
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=[node for node in nodes if node.name in used], type_ignores=[]))) + '\n'


def document():
    import ast
    import copy
    from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
    from tools.hia_program_execution_scalars import ScalarBuilder
    nodes = ast.parse(source_program()).body
    # Inline only single-expression wrappers, evaluating each argument once
    # into SSA before substitution. This removes duplicate wrapper functions
    # without changing the original bootstrap limits or evaluation order.
    inline_names = {'heap_node', 'heap_name', 'heap_map', 'big_add', 'heap_signed',
        'heap_small', 'heap_overlap', 'heap_unknown', 'heap_value_copy', 'tag',
        'size_of', 'end', 'total'}
    inlines = {node.name: node for node in nodes if node.name in inline_names}
    assert len(inlines) == 13 and all(len(node.body) == 1 and isinstance(node.body[0], ast.Return)
                                    for node in inlines.values())
    all_nodes = nodes
    nodes = [node for node in nodes if node.name not in inlines]
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    totals = total_scalar_functions(all_nodes)
    class LiveBuilder(ScalarBuilder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in inlines:
                fn = inlines[node.func.id]
                assert len(fn.args.args) == len(node.args)
                self.inline_serial = getattr(self, 'inline_serial', 0) + 1
                invocation_id = self.inline_serial
                substitutions = {}
                for param, actual in zip(fn.args.args, node.args):
                    value = self.expr(actual)
                    name = 'inline_argument_' + str(invocation_id) + '_' + str(len(substitutions))
                    assert name not in self.env
                    self.env[name] = self.cast(value, param.annotation.id)
                    substitutions[param.arg] = name
                class Bind(ast.NodeTransformer):
                    def visit_Name(self, item):
                        if item.id in substitutions:
                            return ast.copy_location(ast.Name(id=substitutions[item.id], ctx=ast.Load()), item)
                        return item
                result = self.expr(Bind().visit(copy.deepcopy(fn.body[0].value)))
                for name in substitutions.values():
                    self.env.pop(name)
                return self.cast(result, fn.returns.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_in':
                args = [self.expr(arg) for arg in node.args]
                return self.op('buffer.copy_range', [args[0], args[1], *[self.cast(v, 'usize') for v in args[2:]]])
            return super().expr(node)
    functions = []
    for node in nodes:
        builder = LiveBuilder(node, names, signatures, totals)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'heap_live_engine', 'functions': functions})
