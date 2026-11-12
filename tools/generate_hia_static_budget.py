"""Author the native structural-resource owner; no installed Python policy.

The HIA controller owns admission order, complete-module profile audit, stable
DAG traversal, arbitrary-precision event bounds, limits and complete receipts.
Only requested Core verification, Python object operations, existing heap
owners and final canonical JSON/hash remain foreign continuations.
"""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_program_execution_scalars import ScalarBuilder
from tools.hia_native_bigints import BODY as BIG_BODY
from tools.hia_heap_bound_graphs import BODY as GRAPH_BODY

MAGIC = int.from_bytes(b'HIABUD01', 'little')
ABI = 0xfffffff1
BASE = 8192
N = (1 << 64) - 1
FIELDS = ('schema','functions','name','params','returns','blocks','id','term','op',
          'ops','out','type','attrs','function','entry','target','then','else','exports')
OPS = ('const','int.cast','int.neg.checked','select','bool.not','bool.and','bool.or',
       'bit.and','bit.or','bit.xor','bit.not','compare.eq','compare.ne','compare.lt',
       'compare.le','compare.gt','compare.ge','int.add.checked','int.sub.checked',
       'int.mul.checked','int.add.wrap','int.sub.wrap','int.mul.wrap','int.div.checked',
       'int.rem.checked','int.shl.checked','int.shr.checked','buffer.new','buffer.try_new',
       'buffer.len','borrow.read','borrow.mut','loan.end','owner.move','owner.drop',
       'buffer.load','buffer.store','buffer.fill','buffer.copy','buffer.move_within',
       'buffer.swap','buffer.copy_range','buffer.fill_range','call','chain.empty',
       'chain.try_push','chain.pop','chain.is_empty','chain.head_read','chain.head_mut')
TYPES = ('i8','i16','i32','i64','isize','u8','u16','u32','u64','usize','bool','unit',
         'buffer','readbuf','mutbuf','chain')

# Header 0..120 is fixed framing. 64/72/80 are shared graph-arena used/need/error.
# graph cursor/error use 152/160. Limits: four 48-byte records at 256.
# Each limit record: opaque id, exact kind, magnitude bits, low64, binary node,
# negative flag. Functions use 48-byte graph nodes plus 24-byte extras.
BODY = r'''
def static_budget(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return ABI
    if get(w, 0) == 0:
        if initialize(s, w) == 0:
            return ABI
    else:
        if get(w, 0) != MAGIC or get(w, 96) != 0 or get(w, 24) == 0:
            return ABI
        if get(w, 88) != get(w, 16):
            return ABI
        request = get(w, 24)
        if request != 100 and request != 101:
            if capture(s, w) == 0:
                return ABI
        put(w, 24, 0)
        put(w, 88, 0)
    going = True
    while going:
        phase = get(w, 8)
        if phase < 100:
            admission(w, o, phase)
        elif phase < 200:
            analysis(w, o, phase)
        elif phase < 300:
            composition(w, o, phase)
        elif phase < 400:
            reporting(w, o, phase)
        else:
            return ABI
        if get(w, 24) != 0 or get(w, 96) != 0:
            going = False
    if get(w, 96) != 0:
        put(w, 16, get(w, 16) + 1)
        put(w, 24, 0)
        return 0
    return get(w, 24)

def initialize(s:readbuf, w:mutbuf) -> u64:
    if src_validate(s, w) == 0 or length(s) > length(w) - BASE:
        return 0
    fill_range(w, 0, 4096, 0)
    copy_in(w, s, BASE, 0, length(s))
    put(w, 64, (BASE + length(s) + 7) & (N - 7))
    if tag(w, BASE) != 5 or total(w, BASE) != 10:
        return 0
    mode = decimal(w, element(w, BASE, 0))
    if mode < 1 or mode > 4:
        return 0
    put(w, 0, MAGIC)
    put(w, 8, 1)
    put(w, 120, mode)
    put(w, 176, BASE)
    put(w, 504, decimal(w, element(w, BASE, 1)))
    limits = element(w, BASE, 2)
    if tag(w, limits) != 5 or total(w, limits) != 4:
        return 0
    index = 0
    while index < 4:
        put(w, 256 + index * 48, decimal(w, element(w, limits, index)))
        index = index + 1
    put(w, 480, decimal(w, element(w, BASE, 3)))
    put(w, 488, decimal(w, element(w, BASE, 4)))
    put(w, 496, decimal(w, element(w, BASE, 5)))
    put(w, 688, element(w, BASE, 6))
    put(w, 696, decimal(w, element(w, BASE, 7)))
    put(w, 192, element(w, BASE, 8))
    keys = element(w, BASE, 9)
    if tag(w, keys) != 5 or total(w, keys) != 4:
        return 0
    put(w, 856, keys)
    return 1

def capture(s:readbuf, w:mutbuf) -> u64:
    if src_validate(s, w) == 0:
        return 0
    at = get(w, 64)
    if at > length(w) or length(s) > length(w) - at:
        return 0
    copy_in(w, s, at, 0, length(s))
    put(w, 112, at)
    put(w, 64, (at + length(s) + 7) & (N - 7))
    return 1

def issue(w:mutbuf, request:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    put(w, 16, get(w, 16) + 1)
    put(w, 24, request)
    put(w, 32, a)
    put(w, 40, b)
    put(w, 48, c)
    put(w, 56, d)
    put(w, 8, phase)
    put(w, 104, 0)
    return 0

def need_arena(w:mutbuf, mark:u64) -> u64:
    put(w, 64, mark)
    if get(w, 80) != 0:
        put(w, 96, 3)
        return 0
    return issue(w, 100, get(w, 72), 0, 0, 0, get(w, 8))

def fail(w:mutbuf, kind:u64, fn:u64, arg:u64) -> u64:
    put(w, 560, kind)
    put(w, 568, fn)
    put(w, 576, arg)
    put(w, 8, 390)
    return 0

def field(w:mutbuf, node:u64, ident:u64) -> u64:
    if node == N or tag(w, node) != 6:
        return N
    at = node + 24
    index = 0
    while index < total(w, node):
        value = end(w, at)
        if field_id(w, at) == ident:
            return value
        at = end(w, value)
        index = index + 1
    return N

def decimal(w:mutbuf, node:u64) -> u64:
    value = 0
    index = 0
    while index < size_of(w, node):
        value = value * 10 + byte(w, node + 16 + index) - 48
        index = index + 1
    return value

def bit_length(value:u64) -> u64:
    bits = 0
    while value != 0:
        bits = bits + 1
        value = value >> 1
    return bits

def profile_types(w:mutbuf, values:u64, parameters:bool, chain:u64) -> u64:
    at = values + 24
    index = 0
    while index < total(w, values):
        typ = at
        if parameters:
            typ = field(w, at, F_type)
        ident = type_id(w, typ)
        if ident == 0 or ident > 15 + chain:
            return 0
        at = end(w, at)
        index = index + 1
    return 1

def audit(w:mutbuf, document:u64, expected:u64, chain:u64) -> u64:
    if same_text(w, field(w, document, F_schema), expected) == 0:
        return fail(w, 5, N, expected)
    functions = field(w, document, F_functions)
    fn = functions + 24
    fi = 0
    while fi < total(w, functions):
        bad = profile_types(w, field(w, fn, F_params), True, chain) == 0
        if profile_types(w, field(w, fn, F_returns), False, chain) == 0:
            bad = True
        blocks = field(w, fn, F_blocks)
        block = blocks + 24
        bi = 0
        while bi < total(w, blocks):
            if profile_types(w, field(w, block, F_params), True, chain) == 0:
                bad = True
            term = term_id(w, field(w, field(w, block, F_term), F_op))
            if term == 0:
                return fail(w, 6, N, expected)
            ops = field(w, block, F_ops)
            ins = ops + 24
            oi = 0
            while oi < total(w, ops):
                op = opcode_id(w, field(w, ins, F_op))
                if op == 0 or op > 44 + chain * 6:
                    return fail(w, 7, field(w, fn, F_name), expected)
                if profile_types(w, field(w, ins, F_out), True, chain) == 0:
                    bad = True
                ins = end(w, ins)
                oi = oi + 1
            block = end(w, block)
            bi = bi + 1
        if bad:
            return fail(w, 8, field(w, fn, F_name), expected)
        fn = end(w, fn)
        fi = fi + 1
    return 1

def call_graph(w:mutbuf, functions:u64) -> u64:
    graph = heap_graph(w, total(w, functions))
    if graph == 0:
        return 0
    index = 0
    fn = functions + 24
    while index < total(w, functions):
        node = heap_node(w, graph, index)
        put(w, node, field(w, fn, F_name))
        put(w, node + 8, fn)
        fn = end(w, fn)
        index = index + 1
    index = 0
    while index < get(w, graph):
        fn = get(w, heap_node(w, graph, index) + 8)
        blocks = field(w, fn, F_blocks)
        block = blocks + 24
        bi = 0
        while bi < total(w, blocks):
            ops = field(w, block, F_ops)
            ins = ops + 24
            oi = 0
            while oi < total(w, ops):
                if opcode_id(w, field(w, ins, F_op)) == 44:
                    target = heap_named(w, graph, field(w, field(w, ins, F_attrs), F_function))
                    if heap_edge(w, graph, index, target) == 0:
                        return 0
                ins = end(w, ins)
                oi = oi + 1
            block = end(w, block)
            bi = bi + 1
        index = index + 1
    return graph

def block_graph(w:mutbuf, fn:u64) -> u64:
    blocks = field(w, fn, F_blocks)
    graph = heap_graph(w, total(w, blocks))
    if graph == 0:
        return 0
    index = 0
    block = blocks + 24
    while index < total(w, blocks):
        node = heap_node(w, graph, index)
        put(w, node, field(w, block, F_id))
        put(w, node + 8, block)
        block = end(w, block)
        index = index + 1
    index = 0
    while index < get(w, graph):
        block = get(w, heap_node(w, graph, index) + 8)
        term = field(w, block, F_term)
        kind = term_id(w, field(w, term, F_op))
        if kind == 2:
            if heap_edge(w, graph, index, heap_named(w, graph, field(w, term, F_target))) == 0:
                return 0
        elif kind == 3:
            if heap_edge(w, graph, index, heap_named(w, graph, field(w, field(w, term, F_then), F_target))) == 0:
                return 0
            if heap_edge(w, graph, index, heap_named(w, graph, field(w, field(w, term, F_else), F_target))) == 0:
                return 0
        index = index + 1
    return graph

def new_big(w:mutbuf) -> u64:
    value = heap_alloc(w, get(w, 528))
    if value == 0:
        return 0
    big_init(w, value, get(w, 520))
    return value

def graph_values(w:mutbuf, graph:u64) -> u64:
    index = 0
    while index < get(w, graph):
        node = heap_node(w, graph, index)
        alloc = new_big(w)
        ticks = new_big(w)
        if alloc == 0 or ticks == 0:
            return 0
        put(w, node + 32, alloc)
        put(w, node + 40, ticks)
        index = index + 1
    return 1

def capacity(w:mutbuf, functions:u64) -> u64:
    base = 2
    fn = functions + 24
    fi = 0
    while fi < total(w, functions):
        blocks = field(w, fn, F_blocks)
        base = base + total(w, blocks)
        block = blocks + 24
        bi = 0
        while bi < total(w, blocks):
            base = base + total(w, field(w, block, F_ops))
            block = end(w, block)
            bi = bi + 1
        fn = end(w, fn)
        fi = fi + 1
    bits = (total(w, functions) + 1) * bit_length(base) + 1
    limbs = (bits + 31) // 32
    put(w, 520, limbs)
    put(w, 528, 24 + limbs * 8)
    return 0

def block_value(w:mutbuf, calls:u64, cfg:u64, index:u64, depths:u64, one:u64) -> u64:
    node = heap_node(w, cfg, index)
    block = get(w, node + 8)
    alloc = get(w, node + 32)
    ticks = get(w, node + 40)
    ops = field(w, block, F_ops)
    big_set_u64(w, ticks, 0, total(w, ops) + 1)
    depth = 1
    oi = 0
    ins = ops + 24
    while oi < total(w, ops):
        op = opcode_id(w, field(w, ins, F_op))
        if op == 28 or op == 29 or op == 35:
            if big_add(w, alloc, alloc, one) == 0:
                return 0
        if op == 44:
            target = heap_named(w, calls, field(w, field(w, ins, F_attrs), F_function))
            child = heap_node(w, calls, target)
            if big_add(w, alloc, alloc, get(w, child + 32)) == 0:
                return 0
            if big_add(w, ticks, ticks, get(w, child + 40)) == 0:
                return 0
            candidate = 1 + get(w, get(w, 536) + target * 24)
            if candidate > depth:
                depth = candidate
        ins = end(w, ins)
        oi = oi + 1
    max_alloc = 0
    max_ticks = 0
    edge = get(w, node + 16)
    while edge != 0:
        target = get(w, edge + 8)
        child = heap_node(w, cfg, target)
        a = get(w, child + 32)
        t = get(w, child + 40)
        if max_alloc == 0:
            max_alloc = a
            max_ticks = t
        else:
            if big_cmp(w, a, max_alloc) == 2:
                max_alloc = a
            if big_cmp(w, t, max_ticks) == 2:
                max_ticks = t
        candidate = get(w, depths + target * 8)
        if candidate > depth:
            depth = candidate
        edge = get(w, edge)
    if max_alloc != 0:
        if big_add(w, alloc, alloc, max_alloc) == 0:
            return 0
        if big_add(w, ticks, ticks, max_ticks) == 0:
            return 0
    put(w, depths + index * 8, depth)
    return 1

def bound_function(w:mutbuf, calls:u64, index:u64) -> u64:
    fn_node = heap_node(w, calls, index)
    fn = get(w, fn_node + 8)
    cfg = block_graph(w, fn)
    if cfg == 0:
        if get(w, 80) == 2:
            fail(w, 19, field(w, fn, F_name), 0)
            return 1
        return 0
    ordered = heap_topological(w, cfg)
    if ordered == N:
        fail(w, 11, field(w, fn, F_name), 0)
        return 1
    if ordered == 0:
        return 0
    if graph_values(w, cfg) == 0:
        return 0
    depths = heap_alloc(w, get(w, cfg) * 8)
    one = new_big(w)
    if depths == 0 or one == 0:
        return 0
    big_set_u64(w, one, 0, 1)
    remaining = get(w, ordered)
    while remaining != 0:
        remaining = remaining - 1
        block = get(w, ordered + 8 + remaining * 8)
        if block_value(w, calls, cfg, block, depths, one) == 0:
            put(w, 80, 1)
            return 0
    entry = heap_named(w, cfg, field(w, fn, F_entry))
    node = heap_node(w, cfg, entry)
    big_copy(w, get(w, fn_node + 32), get(w, node + 32))
    big_add(w, get(w, fn_node + 40), get(w, node + 40), one)
    put(w, get(w, 536) + index * 24, get(w, depths + entry * 8))
    return 1

def frame_depth(w:mutbuf, calls:u64, index:u64) -> u64:
    depth = 1
    edge = get(w, heap_node(w, calls, index) + 16)
    while edge != 0:
        candidate = 1 + get(w, get(w, 536) + get(w, edge + 8) * 24)
        if candidate > depth:
            depth = candidate
        edge = get(w, edge)
    put(w, get(w, 536) + index * 24, depth)
    return 0
'''

CONTROL = r'''
def verify_request(w:mutbuf) -> u64:
    required = 0
    if get(w, 120) == 3 and get(w, 720) == 0:
        required = 1
    return issue(w, 2, get(w, 504), required, 0, 0, 20)

def identity_request(w:mutbuf) -> u64:
    required = 0
    if get(w, 120) == 1 or get(w, 200) >= 7:
        required = 1
    if get(w, 120) == 3 and get(w, 720) == 2:
        required = 1
    return issue(w, 9, get(w, 184), required, 0, 0, 301)
def metadata(w:mutbuf, record:u64, node:u64) -> u64:
    if tag(w, node) != 5 or total(w, node) != 4:
        put(w, 96, 3)
        return 0
    put(w, record + 8, decimal(w, element(w, node, 0)))
    put(w, record + 40, decimal(w, element(w, node, 1)))
    put(w, record + 16, decimal(w, element(w, node, 2)))
    put(w, record + 24, decimal(w, element(w, node, 3)))
    put(w, record + 32, 0)
    return 1

def nonnegative(w:mutbuf, record:u64) -> bool:
    return get(w, record + 8) == 2 and get(w, record + 40) == 0

def bounded_word(w:mutbuf, record:u64, low:u64, high:u64) -> bool:
    return nonnegative(w, record) and get(w, record + 16) <= 64 and get(w, record + 24) >= low and get(w, record + 24) <= high

def admission(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    mode = get(w, 120)
    reply = get(w, 112)
    if phase == 1:
        if mode == 4:
            if audit(w, get(w, 192), get(w, 688), get(w, 696)) != 0:
                put(w, 8, 380)
            return 0
        if mode == 1:
            return issue(w, 1, get(w, 352), 0, 0, 0, 2)
        if mode == 3:
            return issue(w, 1, get(w, 480), 0, 0, 0, 5)
        put(w, 232, 0)
        put(w, 8, 3)
    elif phase == 2:
        metadata(w, 352, reply)
        if not bounded_word(w, 352, 1, 256):
            return fail(w, 1, N, 0)
        return verify_request(w)
    elif phase == 3:
        index = get(w, 232)
        if index == 4:
            return verify_request(w)
        return issue(w, 1, get(w, 256 + index * 48), 0, 0, 0, 4)
    elif phase == 4:
        index = get(w, 232)
        record = 256 + index * 48
        metadata(w, record, reply)
        if get(w, record + 8) != 0 and not nonnegative(w, record):
            return fail(w, 2, N, index)
        put(w, 232, index + 1)
        put(w, 8, 3)
    elif phase == 5:
        metadata(w, 896, reply)
        if get(w, 904) != 6:
            return fail(w, 3, N, 0)
        return issue(w, 3, get(w, 480), 0, 0, 0, 6)
    elif phase == 6:
        put(w, 480, decimal(w, reply))
        return issue(w, 4, get(w, 480), 0, 0, 0, 7)
    elif phase == 7:
        put(w, 864, decimal(w, reply))
        return issue(w, 5, get(w, 864), get(w, 488), 0, 0, 8)
    elif phase == 8:
        put(w, 872, byte(w, reply + 16))
        return issue(w, 17, get(w, 864), 0, 0, 0, 15)
    elif phase == 15:
        if get(w, 872) != 0:
            return fail(w, 4, N, 0)
        return issue(w, 6, get(w, 480), 0, 0, 0, 9)
    elif phase == 9:
        put(w, 664, decimal(w, reply))
        return issue(w, 14, get(w, 664), 0, 0, 0, 10)
    elif phase == 10:
        if byte(w, element(w, reply, 0) + 16) != 0:
            return issue(w, 17, get(w, 664), 0, 0, 0, 16)
        else:
            return issue(w, 1, decimal(w, element(w, reply, 1)), 0, 0, 0, 11)
    elif phase == 11:
        metadata(w, 896, reply)
        if not nonnegative(w, 896):
            return issue(w, 17, get(w, 664), 0, 0, 0, 17)
        return issue(w, 14, get(w, 664), 0, 0, 0, 10)
    elif phase == 16:
        put(w, 232, 1)
        put(w, 8, 12)
    elif phase == 17:
        return fail(w, 4, N, 0)
    elif phase == 12:
        index = get(w, 232)
        if index == 4:
            return verify_request(w)
        return get_policy(w, o, index, 13)
    elif phase == 13:
        index = get(w, 232)
        put(w, 256 + index * 48, decimal(w, reply))
        return issue(w, 1, decimal(w, reply), 0, 0, 0, 14)
    elif phase == 14:
        index = get(w, 232)
        record = 256 + index * 48
        metadata(w, record, reply)
        low = 1
        high = 10000000
        if index == 2:
            high = 256
        elif index == 3:
            low = 0
            high = 1073741824
        if not bounded_word(w, record, low, high):
            return fail(w, 4, N, 0)
        put(w, 232, index + 1)
        put(w, 8, 12)
    elif phase == 20:
        checked = decimal(w, element(w, reply, 0))
        document = element(w, reply, 1)
        schema = schema_id(w, field(w, document, F_schema))
        put(w, 184, checked)
        put(w, 192, document)
        put(w, 200, schema)
        put(w, 208, field(w, document, F_functions))
        if mode == 3 and get(w, 720) == 0:
            if byte(w, element(w, reply, 2) + 16) != 0 or schema == 0 or schema == 7:
                return fail(w, 16, N, 0)
            exports = field(w, document, F_exports)
            if exports == N:
                return fail(w, 17, N, 0)
            if tag(w, exports) != 5 or total(w, exports) == 0 or total(w, exports) > 128:
                return fail(w, 17, N, 0)
            put(w, 448, checked)
            put(w, 456, document)
            put(w, 464, schema)
            put(w, 472, exports)
            put(w, 232, 0)
            put(w, 8, 22)
        else:
            put(w, 8, 100)
    elif phase == 22:
        index = get(w, 232)
        if index == 3:
            put(w, 400, get(w, 496))
            put(w, 504, get(w, 448))
            put(w, 720, 1)
            put(w, 232, 0)
            put(w, 8, 3)
        else:
            return get_policy(w, o, index, 23)
    elif phase == 23:
        put(w, 256 + get(w, 232) * 48, decimal(w, reply))
        put(w, 232, get(w, 232) + 1)
        put(w, 8, 22)
    else:
        put(w, 96, 3)
    return 0

def analysis(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    mode = get(w, 120)
    reply = get(w, 112)
    if phase == 100:
        schema = get(w, 200)
        if mode == 1:
            if schema == 8:
                if audit(w, get(w, 192), field(w, get(w, 192), F_schema), 1) == 0:
                    return 0
            elif schema == 0:
                return fail(w, 9, N, 0)
        else:
            if schema == 7 or schema == 8:
                if audit(w, get(w, 192), field(w, get(w, 192), F_schema), 0) == 0:
                    return 0
            elif schema == 0:
                return fail(w, 10, N, 0)
        put(w, 8, 101)
    elif phase == 101:
        mark = get(w, 64)
        calls = call_graph(w, get(w, 208))
        if calls == 0:
            if get(w, 80) == 2:
                return fail(w, 19, N, choose(mode == 1, 1, 2))
            return need_arena(w, mark)
        order = heap_topological(w, calls)
        if order == N:
            return fail(w, 11, N, choose(mode == 1, 1, 2))
        if order == 0:
            return need_arena(w, mark)
        extras = heap_alloc(w, get(w, calls) * 24)
        if extras == 0:
            return need_arena(w, mark)
        put(w, 536, extras)
        if mode != 1:
            capacity(w, get(w, 208))
            if graph_values(w, calls) == 0:
                return need_arena(w, mark)
        put(w, 216, calls)
        put(w, 224, order)
        put(w, 232, get(w, order))
        put(w, 544, get(w, 64))
        put(w, 8, 102)
    elif phase == 102:
        remaining = get(w, 232)
        if remaining != 0:
            index = get(w, get(w, 224) + 8 + (remaining - 1) * 8)
            if mode == 1:
                frame_depth(w, get(w, 216), index)
            else:
                if bound_function(w, get(w, 216), index) == 0:
                    return need_arena(w, get(w, 544))
                put(w, 64, get(w, 544))
                if get(w, 8) != 102:
                    return 0
            put(w, 232, remaining - 1)
        else:
            if mode == 1:
                index = 0
                while index < get(w, get(w, 216)):
                    if get(w, get(w, 536) + index * 24) > get(w, 376):
                        return fail(w, 12, N, 0)
                    index = index + 1
                put(w, 8, 300)
            elif get(w, 408) != 0:
                return issue(w, 10, get(w, 184), 0, 0, 0, 110)
            else:
                put(w, 232, 0)
                put(w, 240, 0)
                put(w, 8, 120)
    elif phase == 110:
        put(w, 648, decimal(w, reply))
        return issue(w, 4, get(w, 648), 0, 0, 0, 111)
    elif phase == 111:
        put(w, 656, decimal(w, reply))
        put(w, 8, 112)
    elif phase == 112:
        graph_reset(w)
        names_graph(w, o)
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 15, 0, 0, 113)
    elif phase == 113:
        put(w, 880, decimal(w, reply))
        return issue(w, 4, get(w, 880), 0, 0, 0, 114)
    elif phase == 114:
        put(w, 888, decimal(w, reply))
        return issue(w, 5, get(w, 656), get(w, 888), 0, 0, 115)
    elif phase == 115:
        put(w, 872, byte(w, reply + 16))
        return issue(w, 17, get(w, 656), 0, 0, 0, 127)
    elif phase == 127:
        return issue(w, 17, get(w, 888), 0, 0, 0, 128)
    elif phase == 128:
        return issue(w, 17, get(w, 880), 0, 0, 0, 129)
    elif phase == 129:
        if get(w, 872) != 0:
            return fail(w, 13, N, 0)
        return issue(w, 6, get(w, 648), 0, 0, 0, 116)
    elif phase == 116:
        put(w, 664, decimal(w, reply))
        return issue(w, 14, get(w, 664), 0, 0, 0, 117)
    elif phase == 117:
        if byte(w, element(w, reply, 0) + 16) != 0:
            return issue(w, 17, get(w, 664), 0, 0, 0, 125)
        else:
            return issue(w, 1, decimal(w, element(w, reply, 1)), 0, 0, 0, 118)
    elif phase == 118:
        metadata(w, 896, reply)
        if not nonnegative(w, 896):
            return issue(w, 17, get(w, 664), 0, 0, 0, 126)
        return issue(w, 14, get(w, 664), 0, 0, 0, 117)
    elif phase == 125:
        put(w, 232, 0)
        put(w, 8, 123)
    elif phase == 126:
        return fail(w, 13, N, 0)
    elif phase == 120:
        index = get(w, 232)
        key = get(w, 240)
        if index == get(w, get(w, 216)):
            put(w, 8, 300)
            return 0
        limit = 256 + key * 48
        above = 0
        if key == 2:
            if get(w, limit + 8) != 0 and get(w, limit + 16) <= 64:
                above = choose(get(w, get(w, 536) + index * 24) > get(w, limit + 24), 1, 0)
        else:
            count = get(w, heap_node(w, get(w, 216), index) + 32 + key * 8)
            above = big_limit(w, count, limit)
        if above == 2:
            return issue(w, 8, get(w, limit), 0, 0, 0, 121)
        if above != 0:
            return fail(w, 15, heap_name(w, get(w, 216), index), key)
        key = key + 1
        if key == 3:
            key = 0
            index = index + 1
        put(w, 232, index)
        put(w, 240, key)
    elif phase == 121:
        put(w, 256 + get(w, 240) * 48 + 32, reply)
        put(w, 8, 120)
    elif phase == 123:
        index = get(w, 232)
        if index == get(w, get(w, 216)):
            put(w, 232, 0)
            put(w, 240, 0)
            put(w, 8, 120)
        else:
            return get_node(w, o, get(w, 648), heap_name(w, get(w, 216), index), 124)
    elif phase == 124:
        index = get(w, 232)
        observed = decimal(w, reply)
        put(w, get(w, 536) + index * 24 + 8, observed)
        put(w, 232, index + 1)
        return compare_start(w, observed, 400, 123, 14, heap_name(w, get(w, 216), index), 0)
    elif phase >= 130 and phase <= 133:
        return comparison(w, phase)
    else:
        put(w, 96, 3)
    return 0

def big_limit(w:mutbuf, count:u64, limit:u64) -> u64:
    if get(w, limit + 8) == 0:
        return 0
    bits = big_bit_length(w, count)
    other = get(w, limit + 16)
    if bits != other:
        return choose(bits > other, 1, 0)
    if bits <= 64:
        value = big_limb(w, count, 0) | (big_limb(w, count, 1) << 32)
        return choose(value > get(w, limit + 24), 1, 0)
    raw = get(w, limit + 32)
    if raw == 0:
        return 2
    length = big_byte_length(w, count)
    while length != 0:
        length = length - 1
        a = big_byte(w, count, length)
        b = byte(w, raw + 17 + length)
        if a != b:
            return choose(a > b, 1, 0)
    return 0

def compare_start(w:mutbuf, left:u64, right:u64, next:u64, error:u64, fn:u64, arg:u64) -> u64:
    put(w, 736, left)
    put(w, 744, right)
    put(w, 752, next)
    put(w, 760, error)
    put(w, 768, fn)
    put(w, 776, arg)
    return issue(w, 1, left, 0, 0, 0, 130)

def compare_done(w:mutbuf, above:bool) -> u64:
    if above:
        if get(w, 760) == 18:
            return issue(w, 17, get(w, 664), 0, 0, 0, 228)
        return fail(w, get(w, 760), get(w, 768), get(w, 776))
    put(w, 8, get(w, 752))
    return 0

def comparison(w:mutbuf, phase:u64) -> u64:
    reply = get(w, 112)
    right = get(w, 744)
    if phase == 130:
        metadata(w, 896, reply)
        if not nonnegative(w, 896):
            put(w, 96, 3)
            return 0
        bits = get(w, 912)
        other = get(w, right + 16)
        if bits != other:
            return compare_done(w, bits > other)
        if bits <= 64:
            return compare_done(w, get(w, 920) > get(w, right + 24))
        return issue(w, 8, get(w, 736), 0, 0, 0, 131)
    if phase == 131:
        put(w, 928, reply)
        if get(w, right + 32) == 0:
            return issue(w, 8, get(w, right), 0, 0, 0, 132)
        put(w, 8, 133)
    elif phase == 132:
        put(w, right + 32, reply)
        put(w, 8, 133)
    else:
        a = get(w, 928)
        b = get(w, right + 32)
        count = size_of(w, a) - 1
        while count != 0:
            count = count - 1
            left = byte(w, a + 17 + count)
            right_byte = byte(w, b + 17 + count)
            if left != right_byte:
                return compare_done(w, left > right_byte)
        return compare_done(w, False)
    return 0
'''

COMPOSITION = r'''
def composition(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    reply = get(w, 112)
    if phase == 200:
        graph_reset(w)
        empty = graph_begin(w, o, 6, 0)
        graph_end(w, o, empty)
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 15, 0, 0, 201)
    if phase == 201:
        put(w, 816, decimal(w, reply))
        return get_key(w, o, get(w, 624), lit('functions'), 202)
    if phase == 202:
        return issue(w, 16, decimal(w, reply), 0, 0, 0, 203)
    if phase == 203:
        put(w, 664, decimal(w, reply))
        return issue(w, 14, get(w, 664), 0, 0, 0, 204)
    if phase == 204:
        if byte(w, element(w, reply, 0) + 16) != 0:
            return issue(w, 17, get(w, 664), 0, 0, 0, 209)
        else:
            put(w, 832, decimal(w, element(w, reply, 1)))
            return get_key(w, o, get(w, 832), lit('function'), 205)
    elif phase == 205:
        put(w, 840, decimal(w, reply))
        put(w, 8, 206)
    elif phase == 206:
        return set_objects(w, o, get(w, 816), get(w, 840), get(w, 832), 207)
    elif phase == 207:
        return issue(w, 14, get(w, 664), 0, 0, 0, 204)
    elif phase == 209:
        put(w, 8, 208)
    elif phase == 208:
        mark = get(w, 64)
        count = total(w, get(w, 472))
        rows = heap_alloc(w, count * 8)
        heaps = heap_alloc(w, count * 8)
        if rows == 0 or heaps == 0:
            return need_arena(w, mark)
        put(w, 632, rows)
        put(w, 640, heaps)
        put(w, 232, 0)
        if get(w, 464) == 8:
            put(w, 8, 210)
        else:
            return issue(w, 10, get(w, 448), 0, 0, 0, 220)
    elif phase == 210:
        index = get(w, 232)
        if index == total(w, get(w, 472)):
            put(w, 8, 213)
        else:
            return get_policy(w, o, 3, 211)
    elif phase == 211:
        put(w, 400, decimal(w, reply))
        put(w, 8, 218)
    elif phase == 218:
        graph_reset(w)
        graph_copy(w, o, element(w, get(w, 472), get(w, 232)))
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 11, get(w, 448), get(w, 400), 212)
    elif phase == 212:
        index = get(w, 232)
        put(w, get(w, 640) + index * 8, decimal(w, reply))
        put(w, 232, index + 1)
        put(w, 8, 210)
    elif phase == 213:
        graph_reset(w)
        empty = graph_begin(w, o, 6, 0)
        graph_end(w, o, empty)
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 15, 0, 0, 219)
    elif phase == 219:
        put(w, 824, decimal(w, reply))
        put(w, 232, 0)
        put(w, 8, 214)
    elif phase == 214:
        index = get(w, 232)
        if index == total(w, get(w, 472)):
            put(w, 232, 0)
            put(w, 8, 230)
        else:
            return get_key(w, o, get(w, get(w, 640) + index * 8), lit('function'), 215)
    elif phase == 215:
        put(w, 840, decimal(w, reply))
        return get_key(w, o, get(w, get(w, 640) + get(w, 232) * 8), lit('peak_bound_bytes'), 216)
    elif phase == 216:
        put(w, 848, decimal(w, reply))
        put(w, 8, 226)
    elif phase == 226:
        return set_objects(w, o, get(w, 824), get(w, 840), get(w, 848), 217)
    elif phase == 217:
        put(w, 232, get(w, 232) + 1)
        put(w, 8, 214)
    elif phase == 220:
        put(w, 824, decimal(w, reply))
        return issue(w, 6, get(w, 824), 0, 0, 0, 221)
    elif phase == 221:
        put(w, 664, decimal(w, reply))
        put(w, 8, 225)
    elif phase == 225:
        return issue(w, 14, get(w, 664), 0, 0, 0, 222)
    elif phase == 222:
        if byte(w, element(w, reply, 0) + 16) != 0:
            return issue(w, 17, get(w, 664), 0, 0, 0, 227)
        else:
            put(w, 736, decimal(w, element(w, reply, 1)))
            return get_policy(w, o, 3, 223)
    elif phase == 227:
        put(w, 232, 0)
        put(w, 8, 230)
    elif phase == 228:
        return fail(w, 18, N, 0)
    elif phase == 223:
        put(w, 400, decimal(w, reply))
        return issue(w, 1, get(w, 400), 0, 0, 0, 224)
    elif phase == 224:
        metadata(w, 400, reply)
        return compare_start(w, get(w, 736), 400, 225, 18, N, 0)
    elif phase == 230:
        index = get(w, 232)
        if index == total(w, get(w, 472)):
            put(w, 8, 300)
        else:
            return get_node(w, o, get(w, 816), element(w, get(w, 472), index), 231)
    elif phase == 231:
        return issue(w, 3, decimal(w, reply), 0, 0, 0, 232)
    elif phase == 232:
        put(w, 832, decimal(w, reply))
        return get_node(w, o, get(w, 824), element(w, get(w, 472), get(w, 232)), 233)
    elif phase == 233:
        put(w, 848, decimal(w, reply))
        put(w, 8, 235)
    elif phase == 235:
        return set_key_object(w, o, get(w, 832), lit('max_live_heap_bytes'), get(w, 848), 234)
    elif phase == 234:
        index = get(w, 232)
        put(w, get(w, 632) + index * 8, get(w, 832))
        put(w, 232, index + 1)
        put(w, 8, 230)
    else:
        put(w, 96, 3)
    return 0
'''

WRITERS = r'''
def graph_reset(w:mutbuf) -> u64:
    put(w, 152, 0)
    put(w, 160, 0)
    return 0

def append_byte(w:mutbuf, o:mutbuf, value:u64) -> u64:
    at = get(w, 152)
    if at < length(o):
        store(o, at, value)
    else:
        put(w, 160, 1)
    put(w, 152, at + 1)
    return 0

def graph_word(w:mutbuf, o:mutbuf, value:u64) -> u64:
    index = 0
    while index < 8:
        append_byte(w, o, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def graph_begin(w:mutbuf, o:mutbuf, kind:u64, count:u64) -> u64:
    at = get(w, 152)
    graph_word(w, o, kind)
    graph_word(w, o, 0)
    graph_word(w, o, count)
    return at

def graph_end(w:mutbuf, o:mutbuf, at:u64) -> u64:
    if get(w, 160) == 0:
        put(o, at + 8, get(w, 152) - at - 16)
    return 0

def graph_null(w:mutbuf, o:mutbuf) -> u64:
    graph_word(w, o, 0)
    graph_word(w, o, 0)
    return 0

def graph_bool(w:mutbuf, o:mutbuf, value:bool) -> u64:
    graph_word(w, o, 1)
    graph_word(w, o, 1)
    append_byte(w, o, choose(value, 1, 0))
    return 0

def graph_u64(w:mutbuf, o:mutbuf, value:u64) -> u64:
    graph_word(w, o, 2)
    count = 1
    scale = 1
    current = value
    while current >= 10:
        current = current // 10
        scale = scale * 10
        count = count + 1
    graph_word(w, o, count)
    while scale != 0:
        append_byte(w, o, 48 + (value // scale) % 10)
        scale = scale // 10
    return 0

def graph_object(w:mutbuf, o:mutbuf, ident:u64) -> u64:
    graph_word(w, o, 13)
    graph_word(w, o, 8)
    graph_word(w, o, ident)
    return 0

def graph_binary(w:mutbuf, o:mutbuf, value:u64) -> u64:
    count = big_byte_length(w, value)
    graph_word(w, o, 12)
    graph_word(w, o, count + 1)
    append_byte(w, o, get(w, value))
    index = 0
    while index < count:
        append_byte(w, o, big_byte(w, value, index))
        index = index + 1
    return 0

def graph_copy(w:mutbuf, o:mutbuf, node:u64) -> u64:
    count = size_of(w, node) + 16
    index = 0
    while index < count:
        append_byte(w, o, byte(w, node + index))
        index = index + 1
    return 0

def text_bytes(w:mutbuf, o:mutbuf, node:u64) -> u64:
    index = 0
    while index < size_of(w, node):
        append_byte(w, o, byte(w, node + 16 + index))
        index = index + 1
    return 0

def emit(w:mutbuf, o:mutbuf, count:u64, a:u64, b:u64, c:u64) -> u64:
    index = 0
    while index < count:
        word = a
        if index >= 8:
            word = b
        if index >= 16:
            word = c
        append_byte(w, o, (word >> ((index & 7) * 8)) & 255)
        index = index + 1
    return 0

def graph_literal(w:mutbuf, o:mutbuf, ident:u64) -> u64:
    at = get(w, 152)
    graph_word(w, o, 4)
    graph_word(w, o, 0)
    literal_bytes(w, o, ident)
    graph_end(w, o, at)
    return 0

def graph_ready(w:mutbuf, o:mutbuf) -> u64:
    if get(w, 160) != 0:
        issue(w, 101, get(w, 152), 0, 0, 0, get(w, 8))
        return 0
    return 1

def query(w:mutbuf, kind:u64, a:u64, b:u64, phase:u64) -> u64:
    size = get(w, 152)
    issue(w, kind, a, b, 0, 0, phase)
    put(w, 104, size)
    return 0

def get_policy(w:mutbuf, o:mutbuf, index:u64, phase:u64) -> u64:
    graph_reset(w)
    graph_object(w, o, decimal(w, element(w, get(w, 856), index)))
    if graph_ready(w, o) == 0:
        return 0
    return query(w, 7, get(w, 480), 0, phase)

def get_key(w:mutbuf, o:mutbuf, ident:u64, key:u64, phase:u64) -> u64:
    graph_reset(w)
    graph_literal(w, o, key)
    if graph_ready(w, o) == 0:
        return 0
    return query(w, 7, ident, 0, phase)

def get_node(w:mutbuf, o:mutbuf, ident:u64, key:u64, phase:u64) -> u64:
    graph_reset(w)
    graph_copy(w, o, key)
    if graph_ready(w, o) == 0:
        return 0
    return query(w, 7, ident, 0, phase)

def set_objects(w:mutbuf, o:mutbuf, target:u64, key:u64, value:u64, phase:u64) -> u64:
    graph_reset(w)
    array = graph_begin(w, o, 5, 2)
    graph_object(w, o, key)
    graph_object(w, o, value)
    graph_end(w, o, array)
    if graph_ready(w, o) == 0:
        return 0
    return query(w, 13, target, 0, phase)

def set_key_object(w:mutbuf, o:mutbuf, target:u64, key:u64, value:u64, phase:u64) -> u64:
    graph_reset(w)
    array = graph_begin(w, o, 5, 2)
    graph_literal(w, o, key)
    graph_object(w, o, value)
    graph_end(w, o, array)
    if graph_ready(w, o) == 0:
        return 0
    return query(w, 13, target, 0, phase)

def names_graph(w:mutbuf, o:mutbuf) -> u64:
    calls = get(w, 216)
    array = graph_begin(w, o, 5, get(w, calls))
    index = 0
    while index < get(w, calls):
        graph_copy(w, o, heap_name(w, calls, index))
        index = index + 1
    graph_end(w, o, array)
    return 0

def function_rows(w:mutbuf, o:mutbuf) -> u64:
    calls = get(w, 216)
    array = graph_begin(w, o, 5, get(w, calls))
    index = 0
    while index < get(w, calls):
        count = 2
        if get(w, 120) != 1:
            count = 4 + choose(get(w, 408) != 0, 1, 0)
        row = graph_begin(w, o, 6, count)
        graph_literal(w, o, lit('function'))
        graph_copy(w, o, heap_name(w, calls, index))
        if get(w, 120) != 1:
            graph_literal(w, o, lit('max_allocator_interactions'))
            graph_binary(w, o, get(w, heap_node(w, calls, index) + 32))
            graph_literal(w, o, lit('max_vm_ticks'))
            graph_binary(w, o, get(w, heap_node(w, calls, index) + 40))
        graph_literal(w, o, lit('max_call_depth'))
        graph_u64(w, o, get(w, get(w, 536) + index * 24))
        if get(w, 120) != 1 and get(w, 408) != 0:
            graph_literal(w, o, lit('max_live_heap_bytes'))
            graph_object(w, o, get(w, get(w, 536) + index * 24 + 8))
        graph_end(w, o, row)
        index = index + 1
    graph_end(w, o, array)
    return 0

def opaque_array(w:mutbuf, o:mutbuf, values:u64, count:u64) -> u64:
    array = graph_begin(w, o, 5, count)
    index = 0
    while index < count:
        graph_object(w, o, get(w, values + index * 8))
        index = index + 1
    graph_end(w, o, array)
    return 0

def reporting(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    reply = get(w, 112)
    if phase == 300:
        return identity_request(w)
    if phase == 301:
        put(w, 600, element(w, reply, 0))
        put(w, 608, element(w, reply, 1))
        put(w, 8, 304)
    elif phase == 304:
        graph_reset(w)
        if get(w, 120) == 1:
            depth_report(w, o)
        elif get(w, 120) == 3 and get(w, 720) == 2:
            bounded_report(w, o)
        else:
            static_report(w, o)
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 12, 0, 0, 302)
    elif phase == 302:
        put(w, 616, decimal(w, element(w, reply, 0)))
        put(w, 712, element(w, reply, 1))
        put(w, 8, 305)
    elif phase == 305:
        graph_reset(w)
        array = graph_begin(w, o, 5, 2)
        graph_literal(w, o, lit('sha256'))
        graph_copy(w, o, get(w, 712))
        graph_end(w, o, array)
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 13, get(w, 616), 0, 303)
    elif phase == 303:
        if get(w, 120) == 3 and get(w, 720) == 1:
            put(w, 624, get(w, 616))
            put(w, 720, 2)
            put(w, 184, get(w, 448))
            put(w, 192, get(w, 456))
            put(w, 200, get(w, 464))
            put(w, 8, 200)
        else:
            put(w, 8, 381)
    elif phase == 380 or phase == 381:
        graph_reset(w)
        if phase == 380:
            graph_null(w, o)
        else:
            graph_object(w, o, get(w, 616))
        if graph_ready(w, o) == 0:
            return 0
        put(w, 104, get(w, 152))
        put(w, 96, 1)
    elif phase == 390:
        graph_reset(w)
        error_report(w, o)
        if graph_ready(w, o) == 0:
            return 0
        put(w, 104, get(w, 152))
        put(w, 96, 2)
    else:
        put(w, 96, 3)
    return 0
'''

REPORTS = r'''
def depth_report(w:mutbuf, o:mutbuf) -> u64:
    returned = get(w, 200) == 8
    report = graph_begin(w, o, 6, 8 + choose(returned, 1, 0))
    graph_literal(w, o, lit('schema'))
    if returned:
        graph_literal(w, o, lit('hepta.hia.vm-call-depth-budget.v2'))
    else:
        graph_literal(w, o, lit('hepta.hia.vm-call-depth-budget.v1'))
    graph_literal(w, o, lit('status'))
    graph_literal(w, o, lit('qualified_root_inclusive_synchronous_vm_frames_only'))
    graph_literal(w, o, lit('core_sha256'))
    graph_copy(w, o, get(w, 600))
    graph_literal(w, o, lit('input_sha256'))
    graph_copy(w, o, get(w, 608))
    graph_literal(w, o, lit('core_schema'))
    graph_copy(w, o, field(w, get(w, 192), F_schema))
    graph_literal(w, o, lit('limit_frames'))
    graph_object(w, o, get(w, 352))
    graph_literal(w, o, lit('functions'))
    function_rows(w, o)
    graph_literal(w, o, lit('claims'))
    claims = graph_begin(w, o, 6, 8 + choose(returned, 2, 0))
    graph_literal(w, o, lit('synchronous_hia_vm_frames_bounded'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('whole_module_call_graph_acyclic'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('vm_ticks_bounded'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('allocator_interactions_bounded'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('process_rss_or_native_stack_bytes_bounded'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('async_task_stacks_bounded'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('source_to_core_or_backend_refinement_proved'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('whole_language_soundness_proved'))
    graph_bool(w, o, False)
    if returned:
        graph_literal(w, o, lit('canonical_return_origins_reverified'))
        graph_bool(w, o, True)
        graph_literal(w, o, lit('returned_view_creation_adds_synchronous_frames'))
        graph_bool(w, o, False)
    graph_end(w, o, claims)
    if returned:
        graph_literal(w, o, lit('profile'))
        graph_literal(w, o, lit('parameter-loan-synchronous-frames-v8'))
    graph_end(w, o, report)
    return 0

def static_report(w:mutbuf, o:mutbuf) -> u64:
    schema = get(w, 200)
    modern = schema == 7 or schema == 8
    heap = get(w, 408) != 0
    report = graph_begin(w, o, 6, 6 + choose(modern, 3, 0))
    graph_literal(w, o, lit('schema'))
    if schema == 8:
        graph_literal(w, o, lit('hepta.hia.static-budget.v2'))
    elif schema == 7:
        graph_literal(w, o, lit('hepta.hia.static-budget.v3'))
    else:
        graph_literal(w, o, lit('hepta.hia.static-budget.v1'))
    graph_literal(w, o, lit('status'))
    graph_literal(w, o, lit('finite_structural_upper_bound_not_native_time_proof'))
    graph_literal(w, o, lit('core_sha256'))
    graph_copy(w, o, get(w, 600))
    graph_literal(w, o, lit('functions'))
    function_rows(w, o)
    graph_literal(w, o, lit('limits'))
    limits = graph_begin(w, o, 6, 3 + choose(heap, 1, 0))
    index = 0
    while index < 3:
        graph_literal(w, o, limit_literal(index))
        graph_object(w, o, get(w, 256 + index * 48))
        index = index + 1
    if heap:
        graph_literal(w, o, lit('max_live_heap_bytes'))
        graph_object(w, o, get(w, 400))
    graph_end(w, o, limits)
    graph_literal(w, o, lit('claims'))
    count = 6 + choose(heap, 1, 0)
    if modern:
        count = count + choose(schema == 8, 3, 4)
    claims = graph_begin(w, o, 6, count)
    graph_literal(w, o, lit('finite_acyclic_cfg_and_call_graph_checked'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('allocator_interactions_upper_bounded'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('vm_tick_events_upper_bounded'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('native_cpu_time_or_rss_proved'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('full_source_to_core_refinement_proved'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('whole_language_soundness_proved'))
    graph_bool(w, o, False)
    if modern:
        if schema == 8:
            graph_literal(w, o, lit('canonical_return_origins_reverified'))
            graph_bool(w, o, True)
        else:
            graph_literal(w, o, lit('canonical_byte_only_resource_profile_reverified'))
            graph_bool(w, o, True)
            graph_literal(w, o, lit('zero_length_owner_operations_counted'))
            graph_bool(w, o, True)
        graph_literal(w, o, lit('recursive_chain_costs_bounded'))
        graph_bool(w, o, False)
        graph_literal(w, o, lit('runtime_view_storage_or_native_stack_bounded'))
        graph_bool(w, o, False)
    if heap:
        graph_literal(w, o, lit('requested_live_payload_bytes_upper_bounded'))
        graph_bool(w, o, True)
    graph_end(w, o, claims)
    if modern:
        graph_literal(w, o, lit('profile'))
        if schema == 8:
            graph_literal(w, o, lit('acyclic-byte-owner-parameter-loans-v8'))
        else:
            graph_literal(w, o, lit('acyclic-byte-owner-v7'))
        graph_literal(w, o, lit('core_schema'))
        graph_copy(w, o, field(w, get(w, 192), F_schema))
        graph_literal(w, o, lit('input_sha256'))
        graph_copy(w, o, get(w, 608))
    graph_end(w, o, report)
    return 0

def bounded_report(w:mutbuf, o:mutbuf) -> u64:
    report = graph_begin(w, o, 6, 11)
    graph_literal(w, o, lit('schema'))
    graph_literal(w, o, lit('hepta.hia.bounded-resources.v1'))
    graph_literal(w, o, lit('profile'))
    graph_literal(w, o, lit('explicit-scalar-exports-acyclic-byte-resources-v1'))
    graph_literal(w, o, lit('status'))
    graph_literal(w, o, lit('qualified_structural_events_and_requested_payload_only'))
    graph_literal(w, o, lit('core_schema'))
    graph_copy(w, o, field(w, get(w, 192), F_schema))
    graph_literal(w, o, lit('core_sha256'))
    graph_copy(w, o, get(w, 600))
    graph_literal(w, o, lit('input_sha256'))
    graph_copy(w, o, get(w, 608))
    graph_literal(w, o, lit('limits'))
    graph_object(w, o, get(w, 480))
    graph_literal(w, o, lit('exports'))
    opaque_array(w, o, get(w, 632), total(w, get(w, 472)))
    graph_literal(w, o, lit('static_events'))
    graph_object(w, o, get(w, 624))
    graph_literal(w, o, lit('borrowed_entry_payload'))
    opaque_array(w, o, get(w, 640), choose(get(w, 464) == 8, total(w, get(w, 472)), 0))
    graph_literal(w, o, lit('claims'))
    claims = graph_begin(w, o, 6, 14)
    graph_literal(w, o, lit('canonical_core_reverified'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('every_explicit_public_export_covered'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('acyclic_control_and_call_graphs_checked'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('allocator_interactions_and_vm_ticks_bounded'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('root_inclusive_synchronous_vm_frames_bounded'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('requested_live_hia_byte_payload_bounded'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('normal_return_resource_obligations_checked'))
    graph_bool(w, o, True)
    graph_literal(w, o, lit('program_traps_excluded'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('allocator_success_guaranteed'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('checker_to_formal_model_refinement_proved'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('source_to_core_or_native_backend_refinement_proved'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('process_rss_or_native_stack_bytes_bounded'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('whole_language_soundness_proved'))
    graph_bool(w, o, False)
    graph_literal(w, o, lit('retained_receipt_grants_admission'))
    graph_bool(w, o, False)
    graph_end(w, o, claims)
    graph_end(w, o, report)
    return 0

def limit_literal(index:u64) -> u64:
    if index == 0:
        return lit('max_allocator_interactions')
    if index == 1:
        return lit('max_vm_ticks')
    if index == 2:
        return lit('max_call_depth')
    return lit('max_live_heap_bytes')

def error_report(w:mutbuf, o:mutbuf) -> u64:
    kind = get(w, 560)
    fn = get(w, 568)
    arg = get(w, 576)
    array = graph_begin(w, o, 5, 2)
    if kind <= 4:
        graph_literal(w, o, lit('E_HIA_BUDGET_POLICY'))
    elif kind == 11:
        graph_literal(w, o, lit('E_HIA_BUDGET_UNBOUNDED'))
    elif kind == 13 or kind == 19:
        graph_literal(w, o, lit('E_HIA_BUDGET_GRAPH'))
    elif kind == 12 or kind == 14 or kind == 15 or kind == 18:
        graph_literal(w, o, lit('E_HIA_BUDGET_EXCEEDED'))
    else:
        graph_literal(w, o, lit('E_HIA_BUDGET_PROFILE'))
    at = get(w, 152)
    graph_word(w, o, 4)
    graph_word(w, o, 0)
    if kind == 1:
        literal_bytes(w, o, lit('max_call_depth requires an integer 1..256 (root frame inclusive)'))
    elif kind == 2:
        literal_bytes(w, o, limit_literal(arg))
        literal_bytes(w, o, lit(' must be a nonnegative integer'))
    elif kind == 3:
        literal_bytes(w, o, lit('bounded resource limits must be a plain object'))
    elif kind == 4:
        literal_bytes(w, o, lit('complete exact integer limits required: allocator interactions >=0, VM ticks 1..10000000, call frames 1..256, payload bytes 0..1073741824'))
    elif kind == 5:
        literal_bytes(w, o, lit('resource profile requires '))
        text_bytes(w, o, arg)
    elif kind == 6:
        literal_bytes(w, o, lit('unreviewed '))
        text_bytes(w, o, arg)
        literal_bytes(w, o, lit(' terminator'))
    elif kind == 7 or kind == 8:
        text_bytes(w, o, fn)
        if kind == 7:
            literal_bytes(w, o, lit(': opcode lacks this '))
        else:
            literal_bytes(w, o, lit(': resource type lacks this '))
        text_bytes(w, o, arg)
        literal_bytes(w, o, lit(' resource-event review'))
    elif kind == 9:
        literal_bytes(w, o, lit('synchronous VM frame budget requires an audited primitive v1..v8 Core'))
    elif kind == 10:
        literal_bytes(w, o, lit('this analyzer supports primitive v1..v6; recursive-chain budgets need separate invariants'))
    elif kind == 11 or kind == 19:
        if fn != N:
            text_bytes(w, o, fn)
            literal_bytes(w, o, lit(' control flow'))
        elif arg == 1:
            literal_bytes(w, o, lit('synchronous HIA call graph'))
        else:
            literal_bytes(w, o, lit('HIA call graph'))
        if kind == 19:
            literal_bytes(w, o, lit(': unknown dependency'))
        else:
            literal_bytes(w, o, lit(': recursion or CFG cycle requires a separate invariant'))
    elif kind == 12:
        literal_bytes(w, o, lit('at least one verified function exceeds the synchronous VM frame limit'))
    elif kind == 13:
        literal_bytes(w, o, lit('incomplete heap-bound inventory'))
    elif kind == 14:
        text_bytes(w, o, fn)
        literal_bytes(w, o, lit(': requested live payload bytes exceed explicit policy'))
    elif kind == 15:
        text_bytes(w, o, fn)
        literal_bytes(w, o, lit(': '))
        literal_bytes(w, o, limit_literal(arg))
        literal_bytes(w, o, lit(' exceeds explicit policy'))
    elif kind == 16:
        literal_bytes(w, o, lit('bounded resources require explicit primitive v1..v6 or reviewed byte-only v8 Core'))
    elif kind == 17:
        literal_bytes(w, o, lit('bounded resources require 1..128 explicit scalar exports'))
    else:
        literal_bytes(w, o, lit('requested payload peak exceeds bounded resource policy'))
    graph_end(w, o, at)
    graph_end(w, o, array)
    return 0
'''


def _pack(value):
    raw=value.encode('utf-8'); padded=raw+b'\0'*(24-len(raw))
    return (len(raw),*(int.from_bytes(padded[i:i+8],'little') for i in (0,8,16)))


def source_program():
    own=ast.parse(BODY+CONTROL+COMPOSITION+WRITERS+REPORTS+BIG_BODY)
    graph=ast.parse(GRAPH_BODY)
    keep={'heap_alloc','heap_text_cmp','heap_graph','heap_node','heap_name','heap_named',
          'heap_has_edge','heap_edge','heap_sort_ids','heap_neighbors','heap_topological'}
    own.body.extend(n for n in graph.body if isinstance(n,ast.FunctionDef) and n.name in keep)
    raw=TRANSPORT_SOURCE.replace('    DISPATCH','    pass')
    common={'word','put','get','tag','size_of','end','total','element','text_is','same_text'}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.FunctionDef) and node.name in common:
            for arg in node.args.args:
                if arg.annotation.id=='readbuf':arg.annotation.id='mutbuf'
            own.body.append(node)
    class Reader(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            node.name='src_'+node.name
            return self.generic_visit(node)
        def visit_Name(self,node):
            return ast.copy_location(ast.Name(id='src_word',ctx=node.ctx),node) if node.id=='word' else node
        def visit_Constant(self,node):
            if type(node.value) is int and node.value in (128,136):
                return ast.copy_location(ast.Constant(node.value+3968),node)
            return node
        def visit_Compare(self,node):
            if isinstance(node.left,ast.Name) and node.left.id in {'nodes','children'} and len(node.comparators)==1 and isinstance(node.comparators[0],ast.Constant) and node.comparators[0].value==1048576:
                expr='length(s) // 16' if node.left.id=='nodes' else '(size - 8) // 16'
                node.comparators[0]=ast.parse(expr,mode='eval').body
            return self.generic_visit(node)
    for node in ast.parse(raw).body:
        if isinstance(node,ast.FunctionDef) and node.name in {'validate','word'}:
            node=Reader().visit(node)
            for item in ast.walk(node):
                if isinstance(item,ast.Compare) and isinstance(item.left,ast.Name) and item.left.id=='depth' and isinstance(item.comparators[0],ast.Constant) and item.comparators[0].value==4096:
                    item.comparators[0].value=128
            if node.name=='src_validate':
                text=ast.unparse(node).replace('if kind > 7:', 'if kind > 7 and kind != 12:')
                text=text.replace('if kind == 0 and size != 0:', 'if kind == 12:\n                    if size == 0 or byte(s, at + 16) > 1:\n                        return 0\n                    if size == 1 and byte(s, at + 16) != 0:\n                        return 0\n                    if size > 1 and byte(s, finish - 1) == 0:\n                        return 0\n                if kind == 0 and size != 0:')
                node=ast.parse(text).body[0]
            own.body.append(node)
    tables={'field_id':FIELDS,'opcode_id':OPS,'type_id':TYPES,
            'schema_id':tuple('hepta.hia.program.v'+str(i) for i in range(1,9)),
            'term_id':('ret','jump','branch','trap')}
    for name,values in tables.items():
        lines=[f'def {name}(w:mutbuf, node:u64) -> u64:', '    if node == N:', '        return 0']
        for index,value in enumerate(values,1):
            lines += ['    if text_is(w, node, '+', '.join(map(str,_pack(value)))+') != 0:',f'        return {index}']
        lines.append('    return 0')
        own.body.extend(ast.parse('\n'.join(lines)).body)
    literals=[]
    class Literals(ast.NodeTransformer):
        def visit_Call(self,node):
            if isinstance(node.func,ast.Name) and node.func.id=='lit':
                value=node.args[0].value
                if value not in literals:literals.append(value)
                return ast.copy_location(ast.Constant(literals.index(value)+1),node)
            return self.generic_visit(node)
    own=Literals().visit(own)
    lens=['def literal_length(ident:u64) -> u64:']
    data=['def literal_bytes(w:mutbuf, o:mutbuf, ident:u64) -> u64:']
    for index,value in enumerate(literals,1):
        encoded=value.encode('utf-8')
        lens += [f'    if ident == {index}:',f'        return {len(encoded)}']
        data.append(f'    if ident == {index}:')
        for start in range(0,len(encoded),24):
            chunk=encoded[start:start+24];padded=chunk+b'\0'*(24-len(chunk))
            nums=[len(chunk),*(int.from_bytes(padded[j:j+8],'little') for j in(0,8,16))]
            data.append('        emit(w, o, '+', '.join(map(str,nums))+')')
        data.append('        return 0')
    lens.append('    return 0');data.append('    return 0')
    own.body.extend(ast.parse('\n'.join(data)).body)
    constants={'MAGIC':MAGIC,'ABI':ABI,'BASE':BASE,'N':N,**{'F_'+n:i for i,n in enumerate(FIELDS,1)}}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
    own=ast.fix_missing_locations(Expand().visit(own))
    names={n.name:n for n in own.body}
    reachable={'static_budget'}
    todo=['static_budget']
    while todo:
        node=names[todo.pop()]
        for item in ast.walk(node):
            if isinstance(item,ast.Call) and isinstance(item.func,ast.Name) and item.func.id in names and item.func.id not in reachable:
                reachable.add(item.func.id);todo.append(item.func.id)
    own.body=[n for n in own.body if n.name in reachable]
    return ast.unparse(own)+'\n'


def document():
    class StaticBuilder(ScalarBuilder):
        def expr(self,node):
            if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not):
                return self.op('bool.not',[self.expr(node.operand)],'bool')
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_in':
                args=[self.expr(a) for a in node.args]
                return self.op('buffer.copy_range',[args[0],args[1],*[self.cast(v,'usize') for v in args[2:]]])
            return super().expr(node)
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=StaticBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'static_budget','functions':functions})

if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/static_budget.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)
