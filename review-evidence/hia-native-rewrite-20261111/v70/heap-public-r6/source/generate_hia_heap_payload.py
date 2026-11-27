"""Pure HIA primitive-v1 payload analysis; reconstructed from the retained API.

The native kernel audits the whole module, preserves stable graph/SCC order,
and builds the complete structural summaries using arbitrary-precision sums.
No caller-supplied receipt or hosted payload policy is used.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_heap_bound import _selected
from tools.generate_hia_static_budget import BODY as STATIC_BODY, WRITERS as STATIC_WRITERS
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_program_execution_scalars import ScalarBuilder
from tools.hia_heap_bound_graphs import BODY as GRAPH_BODY
from tools.hia_native_bigints import BODY as BIG_BODY

ABI=0xfffffff1
BASE=8192
N=(1<<64)-1
FIELDS=('schema','functions','name','params','returns','blocks','id','term','op',
        'ops','out','type','attrs','function','entry','target','then','else','args','value')
TYPES=('i8','i16','i32','i64','isize','u8','u16','u32','u64','usize','bool','unit',
       'buffer','readbuf','mutbuf')
OPS=tuple(('const int.cast int.neg.checked select bool.not bool.and bool.or '
 'bit.and bit.or bit.xor bit.not compare.eq compare.ne compare.lt compare.le compare.gt compare.ge '
 'int.add.checked int.sub.checked int.mul.checked int.add.wrap int.sub.wrap int.mul.wrap '
 'int.div.checked int.rem.checked int.shl.checked int.shr.checked buffer.new buffer.try_new '
 'buffer.len borrow.read borrow.mut loan.end owner.move owner.drop buffer.load buffer.store call').split())

BODY=r'''
def heap_payload_kernel(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < BASE or length(s) > length(w) - BASE:
        return ABI
    if src_validate(s, w) == 0:
        return ABI
    fill_range(w, 0, BASE, 0)
    copy_in(w, s, BASE, 0, length(s))
    put(w, 64, (BASE + length(s) + 7) & (N - 7))
    if tag(w, BASE) != 5 or total(w, BASE) != 5:
        return ABI
    document = element(w, BASE, 1)
    name = element(w, BASE, 2)
    if tag(w, document) != 6 or tag(w, name) != 4:
        return ABI
    if payload_bindings(w) == 0:
        return payload_status(w)
    constants = heap_alloc(w, 24)
    if constants == 0:
        return payload_status(w)
    put(w, 176, constants)
    functions = field(w, document, F_functions)
    graph = payload_graph(w, functions, F_name)
    if graph == 0:
        return payload_status(w)
    put(w, 128, graph)
    selected = heap_named(w, graph, name)
    if selected == N:
        payload_error(w, 1000, 0, 0, 0)
    else:
        fn = get(w, heap_node(w, graph, selected) + 8)
        if payload_declared(w, field(w, fn, F_params), 1, 12) == 0 or payload_declared(w, field(w, fn, F_returns), 0, 12) == 0:
            payload_error(w, 1000, 0, 0, 0)
        else:
            if payload_audit(w, graph) != 0:
                order = heap_topological(w, graph)
                if order == N:
                    put(w, 80, 0)
                    payload_error(w, 41, 0, 0, 0)
                elif order == 0:
                    return payload_status(w)
                else:
                    if payload_order_sources(w, graph, order) == 0:
                        return payload_status(w)
                    put(w, 136, order)
                    cursor = get(w, order)
                    while cursor != 0 and get(w, 88) == 0:
                        cursor = cursor - 1
                        ident = get(w, order + 8 + cursor * 8)
                        if payload_function(w, graph, ident) == 0:
                            if get(w, 88) == 0:
                                return payload_status(w)
                    if get(w, 88) == 0:
                        if payload_render(w, o, graph, order) == 0:
                            return payload_status(w)
    if get(w, 88) != 0:
        payload_error_graph(w, o)
    if get(w, 80) != 0:
        return ABI
    if get(w, 72) != 0:
        return 1
    put(w, 104, get(w, 152))
    if get(w, 160) != 0:
        return 2
    return 0

def payload_binding_number(w:mutbuf, node:u64) -> u64:
    if tag(w, node) != 2 or size_of(w, node) == 0:
        put(w, 80, 1)
        return 0
    number = 0
    index = 0
    while index < size_of(w, node):
        digit = byte(w, node + 16 + index)
        if digit < 48 or digit > 57 or (index == 0 and digit == 48 and size_of(w, node) != 1):
            put(w, 80, 1)
            return 0
        digit = digit - 48
        if number > N // 10 or (number == N // 10 and digit > N % 10):
            put(w, 80, 1)
            return 0
        number = number * 10 + digit
        index = index + 1
    return number

def payload_bindings(w:mutbuf) -> u64:
    rows = element(w, BASE, 4)
    if tag(w, rows) != 5 or total(w, rows) > (N - 8) // 16:
        put(w, 80, 1)
        return 0
    count = total(w, rows)
    table = heap_alloc(w, 8 + count * 16)
    if table == 0:
        return 0
    put(w, table, count)
    source = BASE + 24
    row = rows + 24
    index = 0
    while source < rows:
        kind = tag(w, source)
        if kind == 5 or kind == 6:
            source = source + 24
        else:
            if kind > 4 or index >= count or tag(w, row) != 5 or total(w, row) != 2:
                put(w, 80, 1)
                return 0
            offset = payload_binding_number(w, element(w, row, 0))
            ident = payload_binding_number(w, element(w, row, 1))
            if get(w, 80) != 0 or offset != source - BASE:
                put(w, 80, 1)
                return 0
            put(w, table + 8 + index * 16, source)
            put(w, table + 16 + index * 16, ident)
            index = index + 1
            source = end(w, source)
            row = end(w, row)
    if source != rows or index != count or row != end(w, rows):
        put(w, 80, 1)
        return 0
    put(w, 168, table)
    return 1

def payload_object(w:mutbuf, o:mutbuf, source:u64) -> u64:
    table = get(w, 168)
    lower = 0
    upper = get(w, table)
    while lower < upper:
        middle = lower + (upper - lower) // 2
        node = get(w, table + 8 + middle * 16)
        if node < source:
            lower = middle + 1
        else:
            upper = middle
    if lower == get(w, table) or get(w, table + 8 + lower * 16) != source:
        put(w, 80, 1)
        return 0
    graph_word(w, o, 13)
    graph_word(w, o, 8)
    graph_word(w, o, get(w, table + 16 + lower * 16))
    return 0

def payload_reference(w:mutbuf, o:mutbuf, offset:u64) -> u64:
    graph_word(w, o, 8)
    graph_word(w, o, 8)
    graph_word(w, o, offset)
    return 0

def payload_output_begin(w:mutbuf, o:mutbuf) -> u64:
    graph_reset(w)
    graph_word(w, o, PAYLOAD_MAGIC)
    graph_word(w, o, 0)
    graph_word(w, o, 0)
    graph_word(w, o, 0)
    rows = get(w, 176)
    pool = graph_begin(w, o, 5, get(w, rows))
    constant = get(w, rows + 8)
    while constant != 0:
        put(w, constant + 16, get(w, 152) - 32)
        graph_u64(w, o, get(w, constant))
        constant = get(w, constant + 24)
    graph_end(w, o, pool)
    put(w, 184, get(w, 152) - 32)
    put(w, 192, get(w, 152))
    return 0

def payload_output_end(w:mutbuf, o:mutbuf) -> u64:
    if get(w, 160) == 0:
        put(o, 8, get(w, 184))
        put(o, 16, get(w, 152) - get(w, 192))
    return 0

def payload_edge(w:mutbuf, graph:u64, source:u64, target:u64, name:u64) -> u64:
    if source >= get(w, graph) or target >= get(w, graph):
        put(w, 80, 2)
        return 0
    if heap_has_edge(w, graph, source, target) != 0:
        return 1
    if heap_edge(w, graph, source, target) == 0:
        return 0
    alias = heap_alloc(w, 24)
    if alias == 0:
        return 0
    origins = get(w, heap_node(w, graph, source) + 40)
    put(w, alias, get(w, origins + 8))
    put(w, alias + 8, target)
    put(w, alias + 16, name)
    put(w, origins + 8, alias)
    return 1

def payload_edge_source(w:mutbuf, graph:u64, source:u64, target:u64) -> u64:
    origins = get(w, heap_node(w, graph, source) + 40)
    edge = get(w, origins + 8)
    while edge != 0:
        if get(w, edge + 8) == target:
            return get(w, edge + 16)
        edge = get(w, edge)
    put(w, 80, 1)
    return 0

def payload_order_sources(w:mutbuf, graph:u64, order:u64) -> u64:
    count = get(w, graph)
    degrees = heap_alloc(w, count * 8)
    if degrees == 0:
        return 0
    index = 0
    while index < count:
        put(w, degrees + index * 8, get(w, heap_node(w, graph, index) + 24))
        index = index + 1
    index = 0
    while index < count:
        source = get(w, order + 8 + index * 8)
        neighbors = heap_neighbors(w, graph, source)
        if neighbors == 0:
            return 0
        cursor = 0
        while cursor < get(w, neighbors):
            target = get(w, neighbors + 8 + cursor * 8)
            degree = get(w, degrees + target * 8) - 1
            put(w, degrees + target * 8, degree)
            if degree == 0:
                put(w, get(w, heap_node(w, graph, target) + 40), payload_edge_source(w, graph, source, target))
            cursor = cursor + 1
        index = index + 1
    return 1

def payload_successors(w:mutbuf, o:mutbuf, graph:u64, source:u64, ids:u64) -> u64:
    root = graph_begin(w, o, 5, get(w, ids))
    index = 0
    while index < get(w, ids):
        payload_object(w, o, payload_edge_source(w, graph, source, get(w, ids + 8 + index * 8)))
        index = index + 1
    graph_end(w, o, root)
    return 0

def payload_finish_order(w:mutbuf, graph:u64) -> u64:
    count = get(w, graph)
    names = heap_alloc(w, count * 8)
    seen = heap_alloc(w, count * 8)
    stack = heap_alloc(w, count * 24)
    finished = heap_alloc(w, 8 + count * 8)
    if names == 0 or seen == 0 or stack == 0 or finished == 0:
        return 0
    index = 0
    while index < count:
        put(w, names + index * 8, index)
        index = index + 1
    heap_sort_ids(w, graph, names, count)
    used = 0
    index = 0
    while index < count:
        start = get(w, names + index * 8)
        if get(w, seen + start * 8) == 0:
            neighbors = heap_neighbors(w, graph, start)
            if neighbors == 0:
                return 0
            put(w, seen + start * 8, 1)
            put(w, stack, start)
            put(w, stack + 8, neighbors)
            put(w, stack + 16, 0)
            depth = 1
            while depth != 0:
                frame = stack + (depth - 1) * 24
                node = get(w, frame)
                targets = get(w, frame + 8)
                cursor = get(w, frame + 16)
                if cursor == get(w, targets):
                    put(w, finished + 8 + used * 8, node)
                    used = used + 1
                    depth = depth - 1
                else:
                    target = get(w, targets + 8 + cursor * 8)
                    put(w, frame + 16, cursor + 1)
                    if get(w, seen + target * 8) == 0:
                        neighbors = heap_neighbors(w, graph, target)
                        if neighbors == 0:
                            return 0
                        put(w, get(w, heap_node(w, graph, target) + 40), payload_edge_source(w, graph, node, target))
                        put(w, seen + target * 8, 1)
                        frame = stack + depth * 24
                        put(w, frame, target)
                        put(w, frame + 8, neighbors)
                        put(w, frame + 16, 0)
                        depth = depth + 1
        index = index + 1
    put(w, finished, used)
    return finished


def payload_components(w:mutbuf, graph:u64) -> u64:
    count = get(w, graph)
    reverse = heap_reverse_graph(w, graph)
    finished = payload_finish_order(w, graph)
    seen = heap_alloc(w, count * 8)
    pending = heap_alloc(w, count * 8)
    members = heap_alloc(w, count * 8)
    components = heap_alloc(w, 8 + count * 8)
    if reverse == 0 or finished == 0 or seen == 0 or pending == 0 or members == 0 or components == 0:
        return 0
    cursor = get(w, finished)
    used = 0
    while cursor != 0:
        cursor = cursor - 1
        start = get(w, finished + 8 + cursor * 8)
        if get(w, seen + start * 8) == 0:
            put(w, seen + start * 8, 1)
            put(w, pending, start)
            tail = 1
            size = 0
            while tail != 0:
                tail = tail - 1
                node = get(w, pending + tail * 8)
                put(w, members + size * 8, node)
                size = size + 1
                neighbors = heap_neighbors(w, reverse, node)
                if neighbors == 0:
                    return 0
                index = 0
                while index < get(w, neighbors):
                    source = get(w, neighbors + 8 + index * 8)
                    if get(w, seen + source * 8) == 0:
                        put(w, get(w, heap_node(w, graph, source) + 40), heap_name(w, graph, source))
                        put(w, seen + source * 8, 1)
                        put(w, pending + tail * 8, source)
                        tail = tail + 1
                    index = index + 1
            component = heap_alloc(w, 8 + size * 8)
            if component == 0:
                return 0
            put(w, component, size)
            heap_copy(w, component + 8, members, size * 8)
            heap_sort_ids(w, graph, component + 8, size)
            put(w, components + 8 + used * 8, component)
            used = used + 1
    put(w, components, used)
    index = 1
    while index < used:
        value = get(w, components + 8 + index * 8)
        at = index
        going = True
        while going and at != 0:
            previous = get(w, components + at * 8)
            first = heap_name(w, graph, get(w, value + 8))
            second = heap_name(w, graph, get(w, previous + 8))
            if heap_text_cmp(w, first, second) != 1:
                going = False
            else:
                put(w, components + 8 + at * 8, previous)
                at = at - 1
        put(w, components + 8 + at * 8, value)
        index = index + 1
    return components


def payload_status(w:mutbuf) -> u32:
    if get(w, 80) != 0:
        return ABI
    if get(w, 72) != 0:
        return 1
    return ABI

def payload_error(w:mutbuf, code:u64, fn:u64, block:u64, extra:u64) -> u64:
    if get(w, 88) == 0:
        put(w, 88, code)
        put(w, 96, fn)
        put(w, 104, block)
        put(w, 112, extra)
    return 0

def payload_graph(w:mutbuf, rows:u64, name_field:u64) -> u64:
    graph = heap_graph(w, total(w, rows))
    if graph == 0:
        return 0
    index = 0
    while index < total(w, rows):
        row = element(w, rows, index)
        node = heap_node(w, graph, index)
        put(w, node, field(w, row, name_field))
        put(w, node + 8, row)
        origins = heap_alloc(w, 24)
        if origins == 0:
            return 0
        put(w, origins, get(w, node))
        put(w, node + 40, origins)
        index = index + 1
    return graph

def payload_declared(w:mutbuf, items:u64, mapped:u64, maximum:u64) -> u64:
    index = 0
    valid = 1
    while index < total(w, items):
        item = element(w, items, index)
        if mapped != 0:
            item = field(w, item, F_type)
        ident = type_id(w, item)
        if ident == 0 or ident > maximum:
            valid = 0
        index = index + 1
    return valid

def payload_audit(w:mutbuf, graph:u64) -> u64:
    fi = 0
    while fi < get(w, graph):
        fn = get(w, heap_node(w, graph, fi) + 8)
        name = heap_name(w, graph, fi)
        valid = payload_declared(w, field(w, fn, F_params), 1, 15)
        if payload_declared(w, field(w, fn, F_returns), 0, 15) == 0:
            valid = 0
        blocks = field(w, fn, F_blocks)
        bi = 0
        while bi < total(w, blocks):
            block = element(w, blocks, bi)
            if payload_declared(w, field(w, block, F_params), 1, 15) == 0:
                valid = 0
            if term_id(w, field(w, field(w, block, F_term), F_op)) == 0:
                return payload_error(w, 1001, name, 0, 0)
            ops = field(w, block, F_ops)
            oi = 0
            while oi < total(w, ops):
                ins = element(w, ops, oi)
                opcode = opcode_id(w, field(w, ins, F_op))
                if opcode == 0:
                    return payload_error(w, 1002, name, 0, 0)
                if payload_declared(w, field(w, ins, F_out), 1, 15) == 0:
                    valid = 0
                if opcode == OP_CALL:
                    target = heap_named(w, graph, field(w, field(w, ins, F_attrs), F_function))
                    if target == N:
                        return payload_error(w, 40, 0, 0, 0)
                    if payload_edge(w, graph, fi, target, field(w, field(w, ins, F_attrs), F_function)) == 0:
                        return 0
                oi = oi + 1
            bi = bi + 1
        if valid == 0:
            return payload_error(w, 1003, name, 0, 0)
        fi = fi + 1
    return 1

def payload_cfg(w:mutbuf, fn:u64) -> u64:
    blocks = field(w, fn, F_blocks)
    graph = payload_graph(w, blocks, F_id)
    if graph == 0:
        return 0
    index = 0
    while index < total(w, blocks):
        term = field(w, element(w, blocks, index), F_term)
        opcode = term_id(w, field(w, term, F_op))
        if opcode == 2:
            target = heap_named(w, graph, field(w, term, F_target))
            if payload_edge(w, graph, index, target, field(w, term, F_target)) == 0:
                return 0
        elif opcode == 3:
            target = heap_named(w, graph, field(w, field(w, term, F_then), F_target))
            if payload_edge(w, graph, index, target, field(w, field(w, term, F_then), F_target)) == 0:
                return 0
            target = heap_named(w, graph, field(w, field(w, term, F_else), F_target))
            if payload_edge(w, graph, index, target, field(w, field(w, term, F_else), F_target)) == 0:
                return 0
        index = index + 1
    return graph

def payload_small(w:mutbuf, value:u64) -> u64:
    result = heap_alloc(w, 40)
    if result == 0:
        return 0
    if big_init(w, result, 2) == 0 or big_set_u64(w, result, 0, value) == 0:
        put(w, 80, 1)
        return 0
    return result

def payload_sum(w:mutbuf, left:u64, right:u64) -> u64:
    capacity = get(w, left + 8) + 1
    if get(w, right + 8) >= capacity:
        capacity = get(w, right + 8) + 1
    if capacity > (N - 24) // 8:
        put(w, 80, 1)
        return 0
    result = heap_alloc(w, 24 + capacity * 8)
    if result == 0:
        return 0
    if big_init(w, result, capacity) == 0 or big_add(w, result, left, right) == 0:
        put(w, 80, 1)
        return 0
    return result

def payload_add_field(w:mutbuf, summary:u64, offset:u64, value:u64) -> u64:
    result = payload_sum(w, get(w, summary + offset), value)
    if result == 0:
        return 0
    put(w, summary + offset, result)
    return 1

def payload_append(w:mutbuf, rows:u64, row:u64) -> u64:
    tail = get(w, rows + 16)
    if tail == 0:
        put(w, rows + 8, row)
    else:
        put(w, tail, row)
    put(w, rows + 16, row)
    put(w, rows, get(w, rows) + 1)
    return 0

def payload_allocation(w:mutbuf, fn_node:u64, summary:u64, record:u64, constants:u64, ins:u64, oi:u64) -> u64:
    block = get(w, record)
    allocation_sites = get(w, record + 24)
    if get(w, record + 16) != 0:
        return payload_error(w, 1005, get(w, fn_node), field(w, block, F_id), 0)
    arg = element(w, field(w, ins, F_args), 0)
    constant = heap_map_get(w, constants, arg)
    if constant == N:
        return payload_error(w, 1006, get(w, fn_node), field(w, block, F_id), 0)
    node = get(w, constant + 8)
    if tag(w, node) != 2 or size_of(w, node) == 0 or byte(w, node + 16) == 45:
        return payload_error(w, 1006, get(w, fn_node), field(w, block, F_id), 0)
    amount = decimal(w, node)
    if amount > 9223372036854775807:
        return payload_error(w, 1006, get(w, fn_node), field(w, block, F_id), 0)
    one = payload_small(w, 1)
    requested = payload_small(w, choose(amount > 0, 1, 0))
    size = payload_small(w, amount)
    if one == 0 or requested == 0 or size == 0:
        return 0
    if payload_add_field(w, summary, 40, one) == 0 or payload_add_field(w, summary, 48, requested) == 0 or payload_add_field(w, summary, 56, size) == 0:
        return 0
    put(w, summary + 32, 1)
    site = heap_alloc(w, 40)
    if site == 0:
        return 0
    put(w, site + 8, oi)
    put(w, site + 16, ins)
    put(w, site + 24, constant)
    put(w, site + 32, node)
    payload_append(w, allocation_sites, site)
    return 1

def payload_call(w:mutbuf, functions:u64, fn_node:u64, summary:u64, record:u64, ins:u64, oi:u64) -> u64:
    block = get(w, record)
    call_sites = get(w, record + 32)
    callee = field(w, field(w, ins, F_attrs), F_function)
    target = heap_named(w, functions, callee)
    child = get(w, heap_node(w, functions, target) + 32)
    if child == 0:
        put(w, 80, 1)
        return 0
    if get(w, record + 16) != 0 and get(w, child + 32) != 0:
        return payload_error(w, 1007, get(w, fn_node), field(w, block, F_id), callee)
    put(w, summary + 32, get(w, summary + 32) | get(w, child + 32))
    offset = 40
    while offset <= 56:
        bound = get(w, child + offset)
        if get(w, record + 16) != 0 and get(w, bound + 8) != 0:
            return payload_error(w, 1008, get(w, fn_node), field(w, block, F_id), 0)
        if payload_add_field(w, summary, offset, bound) == 0:
            return 0
        offset = offset + 8
    site = heap_alloc(w, 24)
    if site == 0:
        return 0
    put(w, site + 8, oi)
    put(w, site + 16, callee)
    payload_append(w, call_sites, site)
    return 1

def payload_operations(w:mutbuf, functions:u64, fn_node:u64, summary:u64, record:u64, constants:u64) -> u64:
    block = get(w, record)
    ops = field(w, block, F_ops)
    oi = 0
    while oi < total(w, ops):
        ins = element(w, ops, oi)
        opcode = opcode_id(w, field(w, ins, F_op))
        if opcode == OP_CONST and type_id(w, field(w, element(w, field(w, ins, F_out), 0), F_type)) == 10:
            constant = heap_alloc(w, 32)
            if constant == 0:
                return 0
            put(w, constant, oi)
            put(w, constant + 8, field(w, field(w, ins, F_attrs), F_value))
            rows = get(w, 176)
            tail = get(w, rows + 16)
            if tail == 0:
                put(w, rows + 8, constant)
            else:
                put(w, tail + 24, constant)
            put(w, rows + 16, constant)
            put(w, rows, get(w, rows) + 1)
            if heap_map_put(w, constants, field(w, element(w, field(w, ins, F_out), 0), F_name), constant) == 0:
                return 0
        elif opcode == OP_NEW or opcode == OP_TRY:
            if payload_allocation(w, fn_node, summary, record, constants, ins, oi) == 0:
                return 0
        elif opcode == OP_CALL:
            if payload_call(w, functions, fn_node, summary, record, ins, oi) == 0:
                return 0
        oi = oi + 1
    return 1

def payload_function(w:mutbuf, functions:u64, ident:u64) -> u64:
    fn_node = heap_node(w, functions, ident)
    fn = get(w, fn_node + 8)
    blocks = payload_cfg(w, fn)
    if blocks == 0:
        return 0
    components = payload_components(w, blocks)
    cyclic = heap_alloc(w, get(w, blocks) * 8)
    summary = heap_alloc(w, 72)
    rows = heap_alloc(w, 8 + get(w, blocks) * 8)
    zero = payload_small(w, 0)
    if components == 0 or cyclic == 0 or summary == 0 or rows == 0 or zero == 0:
        return 0
    put(w, summary, fn)
    put(w, summary + 8, blocks)
    put(w, summary + 16, components)
    put(w, summary + 24, cyclic)
    put(w, summary + 40, zero)
    put(w, summary + 48, zero)
    put(w, summary + 56, zero)
    put(w, summary + 64, rows)
    put(w, rows, get(w, blocks))
    index = 0
    while index < get(w, components):
        component = get(w, components + 8 + index * 8)
        first = get(w, component + 8)
        is_cycle = get(w, component) > 1 or heap_has_edge(w, blocks, first, first) != 0
        if is_cycle:
            j = 0
            while j < get(w, component):
                put(w, cyclic + get(w, component + 8 + j * 8) * 8, 1)
                j = j + 1
        index = index + 1
    bi = 0
    while bi < get(w, blocks):
        block = get(w, heap_node(w, blocks, bi) + 8)
        neighbors = heap_neighbors(w, blocks, bi)
        allocation_sites = heap_alloc(w, 24)
        call_sites = heap_alloc(w, 24)
        record = heap_alloc(w, 40)
        constants = heap_map(w)
        if neighbors == 0 or allocation_sites == 0 or call_sites == 0 or record == 0 or constants == 0:
            return 0
        put(w, record, block)
        put(w, record + 8, neighbors)
        put(w, record + 16, get(w, cyclic + bi * 8))
        put(w, record + 24, allocation_sites)
        put(w, record + 32, call_sites)
        put(w, rows + 8 + bi * 8, record)
        if payload_operations(w, functions, fn_node, summary, record, constants) == 0:
            return 0
        bi = bi + 1
    put(w, fn_node + 32, summary)
    return 1

def payload_name_array(w:mutbuf, o:mutbuf, graph:u64, ids:u64) -> u64:
    root = graph_begin(w, o, 5, get(w, ids))
    index = 0
    while index < get(w, ids):
        node = heap_node(w, graph, get(w, ids + 8 + index * 8))
        payload_object(w, o, get(w, get(w, node + 40)))
        index = index + 1
    graph_end(w, o, root)
    return 0

def payload_allocation_sites(w:mutbuf, o:mutbuf, rows:u64) -> u64:
    root = graph_begin(w, o, 5, get(w, rows))
    item = get(w, rows + 8)
    while item != 0:
        ins = get(w, item + 16)
        row = graph_begin(w, o, 6, 5)
        graph_literal(w, o, lit('op_index'))
        graph_u64(w, o, get(w, item + 8))
        graph_literal(w, o, lit('opcode'))
        payload_object(w, o, field(w, ins, F_op))
        graph_literal(w, o, lit('size_value'))
        payload_object(w, o, element(w, field(w, ins, F_args), 0))
        graph_literal(w, o, lit('const_op_index'))
        payload_reference(w, o, get(w, get(w, item + 24) + 16))
        graph_literal(w, o, lit('constant_bytes'))
        payload_object(w, o, get(w, item + 32))
        graph_end(w, o, row)
        item = get(w, item)
    graph_end(w, o, root)
    return 0

def payload_call_sites(w:mutbuf, o:mutbuf, rows:u64) -> u64:
    root = graph_begin(w, o, 5, get(w, rows))
    item = get(w, rows + 8)
    while item != 0:
        row = graph_begin(w, o, 6, 2)
        graph_literal(w, o, lit('op_index'))
        graph_u64(w, o, get(w, item + 8))
        graph_literal(w, o, lit('function'))
        payload_object(w, o, get(w, item + 16))
        graph_end(w, o, row)
        item = get(w, item)
    graph_end(w, o, root)
    return 0

def payload_summary_graph(w:mutbuf, o:mutbuf, node:u64) -> u64:
    summary = get(w, node + 32)
    graph = get(w, summary + 8)
    components = get(w, summary + 16)
    cyclic = get(w, summary + 24)
    root = graph_begin(w, o, 6, 6)
    graph_literal(w, o, lit('function'))
    payload_object(w, o, get(w, get(w, node + 40)))
    graph_literal(w, o, lit('entry_block'))
    payload_object(w, o, field(w, get(w, node + 8), F_entry))
    graph_literal(w, o, lit('contains_allocator_opcode'))
    graph_bool(w, o, get(w, summary + 32) != 0)
    graph_literal(w, o, lit('bounds'))
    bounds = graph_begin(w, o, 6, 3)
    graph_literal(w, o, lit('max_allocation_op_executions'))
    graph_binary(w, o, get(w, summary + 40))
    graph_literal(w, o, lit('max_nonzero_allocation_requests'))
    graph_binary(w, o, get(w, summary + 48))
    graph_literal(w, o, lit('max_cumulative_requested_payload_bytes'))
    graph_binary(w, o, get(w, summary + 56))
    graph_end(w, o, bounds)
    graph_literal(w, o, lit('cyclic_components'))
    count = 0
    index = 0
    while index < get(w, components):
        component = get(w, components + 8 + index * 8)
        if get(w, cyclic + get(w, component + 8) * 8) != 0:
            count = count + 1
        index = index + 1
    groups = graph_begin(w, o, 5, count)
    index = 0
    while index < get(w, components):
        component = get(w, components + 8 + index * 8)
        if get(w, cyclic + get(w, component + 8) * 8) != 0:
            payload_name_array(w, o, graph, component)
        index = index + 1
    graph_end(w, o, groups)
    graph_literal(w, o, lit('blocks'))
    records = get(w, summary + 64)
    blocks = graph_begin(w, o, 5, get(w, records))
    index = 0
    while index < get(w, records):
        item = get(w, records + 8 + index * 8)
        block = graph_begin(w, o, 6, 5)
        graph_literal(w, o, lit('block'))
        payload_object(w, o, field(w, get(w, item), F_id))
        graph_literal(w, o, lit('successors'))
        payload_successors(w, o, graph, index, get(w, item + 8))
        graph_literal(w, o, lit('cyclic'))
        graph_bool(w, o, get(w, item + 16) != 0)
        graph_literal(w, o, lit('allocation_sites'))
        payload_allocation_sites(w, o, get(w, item + 24))
        graph_literal(w, o, lit('call_sites'))
        payload_call_sites(w, o, get(w, item + 32))
        graph_end(w, o, block)
        index = index + 1
    graph_end(w, o, blocks)
    graph_end(w, o, root)
    return 0

def payload_render(w:mutbuf, o:mutbuf, graph:u64, order:u64) -> u64:
    count = get(w, graph)
    sorted_ids = heap_alloc(w, count * 8)
    if sorted_ids == 0:
        return 0
    index = 0
    while index < count:
        put(w, sorted_ids + index * 8, index)
        index = index + 1
    heap_sort_ids(w, graph, sorted_ids, count)
    payload_output_begin(w, o)
    root = graph_begin(w, o, 5, 4)
    graph_u64(w, o, 0)
    calls = graph_begin(w, o, 6, count)
    index = 0
    while index < count:
        ident = get(w, sorted_ids + index * 8)
        payload_object(w, o, heap_name(w, graph, ident))
        targets = heap_neighbors(w, graph, ident)
        if targets == 0:
            return 0
        payload_successors(w, o, graph, ident, targets)
        index = index + 1
    graph_end(w, o, calls)
    names = graph_begin(w, o, 5, count)
    index = count
    while index != 0:
        index = index - 1
        node = heap_node(w, graph, get(w, order + 8 + index * 8))
        payload_object(w, o, get(w, get(w, node + 40)))
    graph_end(w, o, names)
    summaries = graph_begin(w, o, 5, count)
    index = 0
    while index < count:
        payload_summary_graph(w, o, heap_node(w, graph, get(w, sorted_ids + index * 8)))
        index = index + 1
    graph_end(w, o, summaries)
    graph_end(w, o, root)
    payload_output_end(w, o)
    return 1

def payload_error_graph(w:mutbuf, o:mutbuf) -> u64:
    payload_output_begin(w, o)
    root = graph_begin(w, o, 5, 5)
    graph_u64(w, o, 1)
    graph_u64(w, o, get(w, 88))
    offset = 96
    while offset <= 112:
        node = get(w, offset)
        if node == 0 or node == N:
            graph_null(w, o)
        else:
            graph_copy(w, o, node)
        offset = offset + 8
    graph_end(w, o, root)
    payload_output_end(w, o)
    return 0
'''

def source_program():
    own=ast.parse(BODY+GRAPH_BODY+BIG_BODY)
    own.body += _selected(STATIC_BODY,{'field','decimal'})
    own.body += _selected(STATIC_WRITERS,{
       'graph_reset','append_byte','graph_word','graph_begin','graph_end','graph_null',
       'graph_bool','graph_u64','graph_binary','graph_copy','emit','graph_literal'})
    raw=TRANSPORT_SOURCE.replace('    DISPATCH','    pass')
    for n in _selected(raw,{'word','put','get','tag','size_of','end','total','element','same_text'}):
        for a in n.args.args:
            if a.annotation.id=='readbuf':a.annotation.id='mutbuf'
        own.body.append(n)
    class Reader(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            n.name='src_'+n.name
            return self.generic_visit(n)
        def visit_Name(self,n):
            return ast.copy_location(ast.Name(id='src_word',ctx=n.ctx),n) if n.id=='word' else n
        def visit_Constant(self,n):
            if type(n.value) is int and n.value in (128,136):
                return ast.copy_location(ast.Constant(n.value+3968),n)
            return n
        def visit_Compare(self,n):
            if isinstance(n.left,ast.Name) and n.left.id in {'nodes','children'} and len(n.comparators)==1 and isinstance(n.comparators[0],ast.Constant) and n.comparators[0].value==1048576:
                n.comparators[0]=ast.parse('length(s) // 16' if n.left.id=='nodes' else '(size - 8) // 16',mode='eval').body
            return self.generic_visit(n)
    for n in _selected(raw,{'validate','word'}):
        n=Reader().visit(n)
        for item in ast.walk(n):
            if isinstance(item,ast.Compare) and isinstance(item.left,ast.Name) and item.left.id=='depth' and isinstance(item.comparators[0],ast.Constant) and item.comparators[0].value==4096:item.comparators[0].value=128
        own.body.append(n)
    for name,values in {'field_id':FIELDS,'type_id':TYPES,'opcode_id':OPS,
                       'term_id':('ret','jump','branch','trap')}.items():
        lines=[f'def {name}(w:mutbuf, node:u64) -> u64:',
               '    if node == N or tag(w, node) != 4:','        return 0']
        for index,value in enumerate(values,1):
            data=value.encode();checks=[f'size_of(w, node) == {len(data)}']
            for start in range(0,len(data),8):
                part=data[start:start+8];mask=(1<<(8*len(part)))-1
                checks.append(f'(word(w, node + {16+start}) & {mask}) == {int.from_bytes(part,"little")}')
            lines += ['    if '+' and '.join(checks)+':',f'        return {index}']
        lines.append('    return 0');own.body+=ast.parse('\n'.join(lines)).body
    literals=[]
    class Literals(ast.NodeTransformer):
        def visit_Call(self,n):
            if isinstance(n.func,ast.Name) and n.func.id=='lit':
                value=n.args[0].value
                if value not in literals:literals.append(value)
                return ast.copy_location(ast.Constant(literals.index(value)+1),n)
            return self.generic_visit(n)
    own=Literals().visit(own)
    lines=['def literal_bytes(w:mutbuf, o:mutbuf, ident:u64) -> u64:']
    for index,value in enumerate(literals,1):
        lines.append(f'    if ident == {index}:');data=value.encode()
        for at in range(0,len(data),24):
            part=data[at:at+24];padded=part+b'\0'*(24-len(part))
            values=[len(part),*(int.from_bytes(padded[k:k+8],'little') for k in (0,8,16))]
            lines.append('        emit(w, o, '+', '.join(map(str,values))+')')
        lines.append('        return 0')
    lines.append('    return 0');own.body+=ast.parse('\n'.join(lines)).body
    constants={'BASE':BASE,'ABI':ABI,'N':N,'PAYLOAD_MAGIC':int.from_bytes(b'HIAPAL01','little'),**{'F_'+n:i for i,n in enumerate(FIELDS,1)},
               **{'OP_'+label:OPS.index(op)+1 for label,op in (('CONST','const'),('NEW','buffer.new'),('TRY','buffer.try_new'),('CALL','call'))}}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,n):
            return ast.copy_location(ast.Constant(constants[n.id]),n) if n.id in constants else n
    own=ast.fix_missing_locations(Expand().visit(own))
    names={n.name:n for n in own.body};used={'heap_payload_kernel'};todo=['heap_payload_kernel']
    while todo:
        for call in ast.walk(names[todo.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id in names and call.func.id not in used:
                used.add(call.func.id);todo.append(call.func.id)
    own.body=[n for n in own.body if n.name in used]
    return ast.unparse(own)+'\n'

def document():
    class PayloadBuilder(ScalarBuilder):
        def expr(self,node):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_in':
                args=[self.expr(a) for a in node.args]
                return self.op('buffer.copy_range',[args[0],args[1],*[self.cast(v,'usize') for v in args[2:]]])
            return super().expr(node)
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    totals=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=PayloadBuilder(node,names,signatures,totals);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
                          'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'heap_payload','functions':functions})

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    target=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/heap_payload.hiaasm'
    generated=render_assembly(document()).encode('utf-8')
    if args.check:
        if target.read_bytes()!=generated:raise SystemExit('native heap payload source differs')
    else:target.write_bytes(generated)
