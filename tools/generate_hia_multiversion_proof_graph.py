"""Author the scalar proof graph directly from independently admitted Core bytes.

Development-only author. Runtime parsing, public selection, profile checks,
topological ordering and SSA framing are performed by the emitted HIA module.
The original bounded Safe Core projector and Boolean fast profile are untouched.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import GRAPH_PROJECTION_REQUEST, _CORE_TRAP_TAGS, _GRAPH_OPERATIONS, _word_type, PROJECT_CHECKED_CAST
from hepta.hia_translation_validation import SCALARS, QUALIFIED_CORE_SCHEMAS
from tools.generate_hia_core_proof_wire import POLICY as BASE_POLICY, match
from tools.generate_hia_core_inspect_json import document, source_program
from tools.generate_hia_core_json_frontend import packed

SOURCE=Path('examples/hia_bootstrap/multiversion_proof_graph.hepta')
REFUSED=4294967292
# Control is an original function-array index in o[0]. UINT64_MAX infers only
# a single-function document. UINT64_MAX-1 selects the exact name in o[16:]
# with byte length o[8]. The caller supplies selection, never proof truth.
# On success w[40:64] holds the actual function index, decoded name offset,
# and name length. Work[64:80] gives an exact signature-type-id vector offset
# and count; it distinguishes usize/u64 and isize/i64. The name and signature
# bytes remain in the caller's 32 MiB work view.
ENTRY=r'''
def multiversion_proof_graph(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(o) < 4096 or length(w) < 4096:
        return REFUSED
    selected = get(o, 0)
    selection_only = selected == 18446744073709551613 or selected == 18446744073709551612
    if selection_only:
        selected = choose(selected == 18446744073709551613, 18446744073709551615, 18446744073709551614)
    named = selected == 18446744073709551614
    name_size = 0
    if named:
        name_size = get(o, 8)
        if name_size == 0 or name_size > length(o) - 16 or name_size > length(w):
            return REFUSED
        i = 0
        while i < name_size:
            store(w, length(w) - name_size + i, byte(o, 16 + i))
            i = i + 1
    put(o, 48, 262144)
    put(o, 56, 64)
    end = widen(decode_json(s, w, o))
    if end >= 4294967292:
        return end
    if length(w) - name_size < 1024 or end + RESERVED > length(w) - name_size - 1024:
        return profile_refused(w, 10)
    if selection_only == False and proof_schema(w, field(w, 0, K_schema)) == 0:
        return profile_refused(w, 1)
    functions = field(w, 0, K_functions)
    size = count(w, functions)
    if named:
        selected = size
        fn = child(w, functions)
        index = 0
        while fn != NONE:
            if requested_name(w, field(w, fn, K_name), name_size) != 0:
                selected = index
            index = index + 1
            fn = next_node(w, fn)
    if selected == NONE:
        if size != 1:
            if selection_only:
                return selection_record(w, o, size, NONE, NONE)
            return profile_refused(w, 2)
        selected = 0
    if selected >= size:
        if selection_only:
            return selection_record(w, o, size, NONE, NONE)
        return profile_refused(w, 2)
    fn = child(w, functions)
    index = 0
    while index < selected:
        fn = next_node(w, fn)
        index = index + 1
    if selection_only:
        return selection_record(w, o, size, selected, fn)
    if public_function(w, fn) == 0:
        return profile_refused(w, 3)
    refusal = profile_reason(w, fn)
    if refusal != 0:
        return profile_refused(w, refusal)
    params = field(w, fn, K_params)
    returns = field(w, fn, K_returns)
    blocks = field(w, fn, K_blocks)
    n = count(w, blocks)
    inputs = count(w, params)
    outputs = count(w, returns)
    if n < 1 or n > BLOCKS or inputs > 32 or outputs > 16:
        return profile_refused(w, 10)
    put(w, 8, end)
    put(w, 16, 0)
    put(w, 24, end + BLOCKS * 64 + BLOCKS * 8)
    put(w, 32, end + BLOCKS * 64 + BLOCKS * 8 + 8 * NODE_BUDGET)
    i = 0
    b = child(w, blocks)
    while b != NONE:
        record = end + 64 * i
        put(w, record, b)
        put(w, record + 8, field(w, b, K_id))
        put(w, record + 16, n)
        put(w, record + 24, n)
        put(w, record + 32, n)
        put(w, record + 48, 0)
        i = i + 1
        b = next_node(w, b)
    entry = block_slot(w, n, field(w, fn, K_entry))
    if entry >= n:
        return profile_refused(w, 10)
    if graph_order(w, n, entry) == 0:
        return profile_refused(w, 9)
    put(o, 0, REQUEST)
    put(o, 8, 1)
    put(o, 16, inputs)
    put(o, 24, outputs)
    at = 32
    p = child(w, params)
    while p != NONE:
        typ = proof_type(w, field(w, p, K_type))
        if typ == 0:
            return profile_refused(w, 7)
        put(o, at, typ)
        at = at + 8
        p = next_node(w, p)
    p = child(w, returns)
    while p != NONE:
        typ = proof_type(w, p)
        if typ == 0:
            return profile_refused(w, 7)
        put(o, at, typ)
        at = at + 8
        p = next_node(w, p)
    start = at
    put(o, start + 8, n)
    put(o, start + 16, get(w, end + 64 * entry + 32))
    put(w, 0, start + 24)
    i = 0
    while i < n:
        source_index = get(w, end + 64 * i + 40)
        b = get(w, end + 64 * source_index)
        if write_block(s, o, w, n, b) == 0:
            return profile_refused(w, 10)
        i = i + 1
    size = get(w, 0) - start
    put(o, start, size)
    signature = (length(w) - name_size - 1024) & 18446744073709551608
    count = 0
    parameter = child(w, params)
    while parameter != NONE:
        put(w, signature + 8 * count, proof_identity_type(w, field(w, parameter, K_type)))
        count = count + 1
        parameter = next_node(w, parameter)
    returned = child(w, returns)
    while returned != NONE:
        put(w, signature + 8 * count, proof_identity_type(w, returned))
        count = count + 1
        returned = next_node(w, returned)
    symbol = field(w, fn, K_name)
    put(w, 40, selected)
    put(w, 48, get(w, 64 + symbol * 56 + 24))
    put(w, 56, get(w, 64 + symbol * 56 + 32))
    put(w, 64, signature)
    put(w, 72, count)
    return get(w, 0)

def requested_name(w:mutbuf, node:u64, size:u64) -> u64:
    if kind(w, node) != 4 or get(w, 64 + node * 56 + 32) != size:
        return 0
    start = get(w, 64 + node * 56 + 24)
    expected = length(w) - size
    i = 0
    while i < size:
        if byte(w, start + i) != byte(w, expected + i):
            return 0
        i = i + 1
    return 1

def public_function(w:mutbuf, fn:u64) -> u64:
    name = field(w, fn, K_name)
    exports = field(w, 0, K_exports)
    if exports == NONE:
        if scalar_records(w, field(w, fn, K_params)) == 0 or scalar_returns(w, field(w, fn, K_returns)) == 0:
            return 0
        return 1
    node = child(w, exports)
    while node != NONE:
        if same_name(w, name, node):
            return 1
        node = next_node(w, node)
    return 0

def function_effects(w:mutbuf, fn:u64) -> u64:
    effect = child(w, field(w, fn, K_effects))
    while effect != NONE:
        if proof_effect(w, effect) == 0:
            return 0
        effect = next_node(w, effect)
    return 1
'''
SELECTION_HELPERS=r'''
def profile_refused(w:mutbuf, reason:u64) -> u32:
    put(w, 80, reason)
    return REFUSED

def selection_record(w:mutbuf, o:mutbuf, functions:u64, selected:u64, fn:u64) -> u32:
    at = 0
    while at < 128:
        put(o, at, 0)
        at = at + 8
    put(o, 0, SELECTION_MAGIC)
    put(o, 8, proof_schema(w, field(w, 0, K_schema)))
    put(o, 16, functions)
    put(o, 24, selected)
    if fn == NONE:
        put(o, 72, 128)
        return 128
    name = field(w, fn, K_name)
    size = get(w, 64 + name * 56 + 32)
    offset = get(w, 64 + name * 56 + 24)
    params = field(w, fn, K_params)
    returns = field(w, fn, K_returns)
    parameters = count(w, params)
    results = count(w, returns)
    required = 128 + size + 8 * (parameters + results)
    if required > length(o):
        return profile_refused(w, 10)
    put(o, 32, public_function(w, fn))
    put(o, 40, parameters)
    put(o, 48, results)
    put(o, 56, size)
    put(o, 64, 8 * (parameters + results))
    put(o, 72, required)
    index = 0
    while index < size:
        store(o, 128 + index, byte(w, offset + index))
        index = index + 1
    at = 128 + size
    parameter = child(w, params)
    while parameter != NONE:
        put(o, at, proof_identity_type(w, field(w, parameter, K_type)))
        at = at + 8
        parameter = next_node(w, parameter)
    returned = child(w, returns)
    while returned != NONE:
        put(o, at, proof_identity_type(w, returned))
        at = at + 8
        returned = next_node(w, returned)
    return at

def scalar_records(w:mutbuf, sequence:u64) -> u64:
    node = child(w, sequence)
    while node != NONE:
        if proof_type(w, field(w, node, K_type)) == 0:
            return 0
        node = next_node(w, node)
    return 1

def scalar_returns(w:mutbuf, sequence:u64) -> u64:
    node = child(w, sequence)
    while node != NONE:
        if proof_type(w, node) == 0:
            return 0
        node = next_node(w, node)
    return 1

def profile_reason(w:mutbuf, fn:u64) -> u64:
    blocks = field(w, fn, K_blocks)
    operations = 0
    block = child(w, blocks)
    while block != NONE:
        operations = operations + count(w, field(w, block, K_ops))
        block = next_node(w, block)
    if count(w, blocks) > 128 or operations > 2048:
        return 4
    if count(w, field(w, fn, K_params)) > 32 or count(w, field(w, fn, K_returns)) > 16:
        return 5
    if function_effects(w, fn) == 0:
        return 6
    if scalar_records(w, field(w, fn, K_params)) == 0 or scalar_returns(w, field(w, fn, K_returns)) == 0:
        return 7
    block = child(w, blocks)
    while block != NONE:
        if scalar_records(w, field(w, block, K_params)) == 0:
            return 7
        op = child(w, field(w, block, K_ops))
        while op != NONE:
            if scalar_records(w, field(w, op, K_out)) == 0:
                return 7
            op = next_node(w, op)
        block = next_node(w, block)
    block = child(w, blocks)
    while block != NONE:
        op = child(w, field(w, block, K_ops))
        while op != NONE:
            if proof_op(w, field(w, op, K_op)) == 0:
                return 8
            op = next_node(w, op)
        block = next_node(w, block)
    return 0
'''
ORDER=r'''
def graph_order(w:mutbuf, n:u64, entry:u64) -> u64:
    table = get(w, 8)
    queue = table + BLOCKS * 64
    i = 0
    while i < n:
        row = table + 64 * i
        term = field(w, get(w, row), K_term)
        role = proof_term(w, field(w, term, K_op))
        if role == 0:
            return 0
        if role == 3 or role == 4:
            first = term
            if role == 4:
                first = field(w, term, K_then)
                second = block_slot(w, n, field(w, field(w, term, K_else), K_target))
                if second >= n:
                    return 0
                put(w, row + 24, second)
                at = table + 64 * second + 48
                put(w, at, get(w, at) + 1)
            target = block_slot(w, n, field(w, first, K_target))
            if target >= n:
                return 0
            put(w, row + 16, target)
            at = table + 64 * target + 48
            put(w, at, get(w, at) + 1)
        i = i + 1
    # The original profile uses sorted initial roots, then FIFO successors.
    # Unreachable blocks participate, so an unreachable cycle still refuses.
    count = 0
    i = 0
    while i < n:
        row = table + 64 * i
        if get(w, row + 48) == 0:
            position = count
            shifting = 1
            while position != 0 and shifting != 0:
                previous = get(w, queue + 8 * (position - 1))
                if name_before(w, get(w, row + 8), get(w, table + 64 * previous + 8)) == 0:
                    shifting = 0
                else:
                    put(w, queue + 8 * position, previous)
                    position = position - 1
            put(w, queue + 8 * position, i)
            count = count + 1
        i = i + 1
    i = 0
    while i < n:
        if i >= count:
            return 0
        index = get(w, queue + 8 * i)
        row = table + 64 * index
        put(w, row + 32, i)
        put(w, table + 64 * i + 40, index)
        edge = 16
        while edge <= 24:
            target = get(w, row + edge)
            if target < n:
                at = table + 64 * target + 48
                degree = get(w, at)
                if degree == 0:
                    return 0
                degree = degree - 1
                put(w, at, degree)
                if degree == 0:
                    if count >= n:
                        return 0
                    put(w, queue + 8 * count, target)
                    count = count + 1
            edge = edge + 8
        i = i + 1
    return 1
'''
def policy():
    suffix=BASE_POLICY[BASE_POLICY.index('def same_name('):]
    a=suffix.index('def graph_order(');b=suffix.index('def value_slot(',a)
    suffix=suffix[:a]+ORDER+'\n'+suffix[b:]
    suffix=suffix.replace('table + 48 *','table + 64 *').replace('get(w, 8) + 48 *','get(w, 8) + 64 *')
    suffix=suffix.replace('    if tag == 1 or tag == 2:', '    if tag == 0 or tag == 1 or tag == 2:')
    source=ENTRY+'\n'+SELECTION_HELPERS+'\n'+suffix
    constants={'SELECTION_MAGIC':int.from_bytes(b'HIAPSL01','little'),'REFUSED':REFUSED,'REQUEST':GRAPH_PROJECTION_REQUEST,'BLOCKS':128,'NODE_BUDGET':262144,'OP_BUDGET':2048,'CHECKED_CAST':PROJECT_CHECKED_CAST,'RESERVED':128*72+8*262144+32}
    for name,value in constants.items():source=re.sub(rf'\b{name}\b',str(value),source)
    source=source.replace('MODE_KEY',', '.join(map(str,packed('mode')))).replace('VALUE_KEY',', '.join(map(str,packed('value'))))
    for name,domain in (('schema',{name:1 for name in sorted(QUALIFIED_CORE_SCHEMAS)}),('type',{name:_word_type(name) for name in sorted(SCALARS)}),('op',_GRAPH_OPERATIONS),('trap',_CORE_TRAP_TAGS),('term',{'ret':1,'trap':2,'jump':3,'branch':4}),('checked',{'checked':1}),('effect',{'trap':1})):
        source+='\n'+match(name,domain)
    source += '\n' + match('identity_type', {name: i + 1 for i, name in enumerate(('bool','unit','u8','u16','u32','u64','i8','i16','i32','i64','usize','isize'))})
    return source

def program():
    nodes=ast.parse(source_program(entry=policy())).body
    retained={'multiversion_proof_graph'}
    while True:
        called={x.func.id for n in nodes if n.name in retained for x in ast.walk(n) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)}
        if called <= retained:break
        retained.update(called)
    source=ast.unparse(ast.Module(body=[n for n in nodes if n.name in retained],type_ignores=[]))
    return document(source,'multiversion_proof_graph')

if __name__=='__main__':
    SOURCE.write_text(render_assembly(program()))
