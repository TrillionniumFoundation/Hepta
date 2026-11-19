"""Generate the checked-in HIA Boolean solver from its readable authoring form."""

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (CIRCUIT_CAPACITY, CIRCUIT_GATES_OFFSET, CIRCUIT_GATE_SLOTS,
                                  CIRCUIT_NODES, CIRCUIT_REQUEST, CIRCUIT_RETURNS,
                                  CIRCUIT_WORKSPACE, CLAUSE_LIMIT, REPLY, REQUEST, SOURCE, SPARSE_CLAUSES,
                                  SPARSE_ENTRIES, SPARSE_REPLY, SPARSE_REQUEST, SPARSE_VARIABLES,
                                  SPARSE_WORKSPACE, STEP_LIMIT, WORKSPACE)
from tools.generate_hia_artifact_publication import document


WORD_MASK = (1 << 64) - 1


BODY = '''
def solve(source:readbuf, result:mutbuf, stack:mutbuf) -> u32:
    if length(source) < 32 or length(result) < 32:
        return INVALID
    magic = read64(source, 0)
    if magic == SPARSE_REQUEST:
        return solve_sparse(source, result, stack)
    if magic == CIRCUIT_REQUEST:
        return encode_circuit(source, result, stack)
    if magic != REQUEST or length(stack) < WORKSPACE:
        return INVALID
    variables = read64(source, 8)
    clauses = read64(source, 16)
    budget = read64(source, 24)
    if variables > 64 or clauses > CLAUSE_LIMIT or budget > STEP_LIMIT:
        return INVALID
    if length(source) != 32 + 16 * clauses:
        return INVALID
    allowed = WORD_MASK
    if variables < 64:
        allowed = (1 << variables) - 1
    clause = 0
    while clause < clauses:
        positive = read64(source, 32 + 16 * clause)
        negative = read64(source, 40 + 16 * clause)
        if ((positive | negative) & (allowed ^ WORD_MASK)) != 0:
            return INVALID
        clause = clause + 1
    return search(source, result, stack, clauses, budget)

def search(source:readbuf, result:mutbuf, stack:mutbuf, clauses:u64, budget:u64) -> u32:
    steps = 0
    depth = 0
    assigned = 0
    model = 0
    while steps < budget:
        steps = steps + 1
        clause = 0
        choice = 0
        unit = 0
        wants_true = 0
        conflict = 0
        while clause < clauses and unit == 0 and conflict == 0:
            if steps == budget:
                return reply(result, 0, 0, steps)
            steps = steps + 1
            positive = read64(source, 32 + 16 * clause)
            negative = read64(source, 40 + 16 * clause)
            false_bits = assigned ^ model
            if (positive & negative) == 0 and (positive & model) == 0 and (negative & false_bits) == 0:
                free = (positive | negative) & (assigned ^ WORD_MASK)
                if free == 0:
                    conflict = 1
                elif (free & (free - 1)) == 0:
                    unit = free
                    wants_true = positive & unit
                elif choice == 0:
                    choice = free & (0 - free)
            clause = clause + 1
        if conflict == 1:
            if depth == 0:
                return reply(result, 2, 0, steps)
            # Pop the untried false branch for our most recent decision.
            depth = depth - 1
            assigned = read_stack(stack, 16 * depth)
            model = read_stack(stack, 16 * depth + 8)
        elif unit != 0:
            assigned = assigned | unit
            model = model | wants_true
        elif choice == 0:
            # Every clause is already satisfied (or tautological). Remaining
            # variables may all be false without invalidating the witness.
            return reply(result, 1, model, steps)
        else:
            if depth >= 64:
                return INVALID
            assigned = assigned | choice
            write64(stack, 16 * depth, assigned)
            write64(stack, 16 * depth + 8, model)
            depth = depth + 1
            model = model | choice
    return reply(result, 0, 0, steps)

def reply(output:mutbuf, status:u64, model:u64, steps:u64) -> u32:
    write64(output, 0, REPLY)
    write64(output, 8, status)
    write64(output, 16, model)
    write64(output, 24, steps)
    return 32

def read64(source:readbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(source, offset + index) << (8 * index))
        index = index + 1
    return value

def read_stack(stack:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(stack, offset + index) << (8 * index))
        index = index + 1
    return value

def write64(output:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(output, offset + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def solve_sparse(source:readbuf, result:mutbuf, stack:mutbuf) -> u32:
    if length(source) < 40 or length(stack) < SPARSE_WORKSPACE:
        return INVALID
    variables = read64(source, 8)
    clauses = read64(source, 16)
    budget = read64(source, 24)
    entries = read64(source, 32)
    if variables > SPARSE_VARIABLES or clauses > SPARSE_CLAUSES:
        return INVALID
    if entries > SPARSE_ENTRIES or budget > STEP_LIMIT or length(source) != 40 + 2 * entries:
        return INVALID
    if length(result) < 32 + ((variables + 7) >> 3):
        return INVALID
    # Zero terminates each clause. Every other token is twice a one-based
    # variable index, plus one for a negated literal.
    position = 40
    count = 0
    last = 0
    while position < length(source):
        last = read_token(source, position)
        if last == 0:
            count = count + 1
        elif last == 1 or (last >> 1) > variables:
            return INVALID
        position = position + 2
    if count != clauses or last != 0:
        return INVALID
    key = 0
    while key < variables:
        store(stack, key, 0)
        key = key + 1
    return search_sparse(source, result, stack, variables, budget)

def search_sparse(source:readbuf, result:mutbuf, stack:mutbuf, variables:u64, budget:u64) -> u32:
    steps = 0
    trail = 0
    depth = 0
    while steps < budget:
        observed = scan_sparse(source, stack, steps + 1, budget)
        steps = observed >> 17
        decision = observed & 131071
        if decision == 0:
            return reply_sparse(result, stack, variables, 1, steps)
        elif decision == 1:
            return reply_sparse(result, stack, variables, 0, steps)
        elif decision == 2:
            if depth == 0:
                return reply_sparse(result, stack, variables, 2, steps)
            # Undo exactly this branch, then consume its untried false side.
            depth = depth - 1
            mark = load_token(stack, DECISIONS + 4 * depth)
            variable = load_token(stack, DECISIONS + 4 * depth + 2)
            while trail > mark:
                trail = trail - 1
                store(stack, load_token(stack, TRAIL + 2 * trail), 0)
            store(stack, variable, 2)
            put_token(stack, TRAIL + 2 * trail, variable)
            trail = trail + 1
        else:
            literal = decision & 32767
            variable = (literal >> 1) - 1
            if decision >= 65536:
                put_token(stack, DECISIONS + 4 * depth, trail)
                put_token(stack, DECISIONS + 4 * depth + 2, variable)
                depth = depth + 1
                literal = literal & 65534
            store(stack, variable, 1 + (literal & 1))
            put_token(stack, TRAIL + 2 * trail, variable)
            trail = trail + 1
    return reply_sparse(result, stack, variables, 0, steps)

def scan_sparse(source:readbuf, stack:mutbuf, steps:u64, budget:u64) -> u64:
    position = 40
    choice = 0
    first = 0
    several = 0
    satisfied = 0
    while position < length(source):
        if steps == budget:
            return (steps << 17) | 1
        steps = steps + 1
        literal = read_token(source, position)
        if literal == 0:
            if satisfied == 0:
                if first == 0:
                    return (steps << 17) | 2
                if several == 0:
                    return (steps << 17) | (32768 + first)
                if choice == 0:
                    choice = first
            first = 0
            several = 0
            satisfied = 0
        elif satisfied == 0:
            state = byte(stack, (literal >> 1) - 1)
            if state == 1 + (literal & 1):
                satisfied = 1
            elif state == 0:
                if first == 0:
                    first = literal
                elif first != literal:
                    several = 1
        position = position + 2
    if choice == 0:
        return steps << 17
    return (steps << 17) | (65536 + choice)

def reply_sparse(result:mutbuf, stack:mutbuf, variables:u64, status:u64, steps:u64) -> u32:
    write64(result, 0, SPARSE_REPLY)
    write64(result, 8, status)
    write64(result, 16, variables)
    write64(result, 24, steps)
    if status != 1:
        return 32
    index = 0
    total = (variables + 7) >> 3
    while index < total:
        start = 8 * index
        end = start + 8
        if end > variables:
            end = variables
        variable = start
        packed = 0
        while variable < end:
            if byte(stack, variable) == 1:
                packed = packed | (1 << (variable - start))
            variable = variable + 1
        store(result, 32 + index, packed)
        index = index + 1
    return 32 + total

def read_token(source:readbuf, position:u64) -> u64:
    return byte(source, position) | (byte(source, position + 1) << 8)

def load_token(source:mutbuf, position:u64) -> u64:
    return byte(source, position) | (byte(source, position + 1) << 8)

def put_token(output:mutbuf, position:u64, value:u64) -> u64:
    store(output, position, value & 255)
    store(output, position + 1, value >> 8)
    return 0

def encode_circuit(source:readbuf, output:mutbuf, scratch:mutbuf) -> u32:
    if length(output) < CIRCUIT_CAPACITY or length(scratch) < CIRCUIT_WORKSPACE:
        return INVALID
    nodes = read64(source, 8)
    returns = read64(source, 16)
    budget = read64(source, 24)
    if nodes > CIRCUIT_NODES or returns > CIRCUIT_RETURNS or budget > STEP_LIMIT:
        return INVALID
    return_offset = 32 + 40 * nodes
    if length(source) != return_offset + 16 * returns:
        return INVALID
    index = 0
    while index < nodes:
        origin = 32 + 40 * index
        operation = read64(source, origin)
        width = read64(source, origin + 8)
        left = read64(source, origin + 16)
        right = read64(source, origin + 24)
        immediate = read64(source, origin + 32)
        if valid_node(source, index, operation, width, left, right, immediate) == 0:
            return INVALID
        index = index + 1
    index = 0
    while index < returns:
        left = read64(source, return_offset + 16 * index)
        right = read64(source, return_offset + 16 * index + 8)
        if left >= nodes or right >= nodes or node_width(source, left) != node_width(source, right):
            return INVALID
        index = index + 1
    return encode_checked_circuit(source, output, scratch, nodes, returns, budget)

def valid_node(source:readbuf, index:u64, operation:u64, width:u64, left:u64, right:u64, immediate:u64) -> u64:
    if width != 1 and width != 8 and width != 16 and width != 32 and width != 64:
        return 0
    if operation < 1 or operation > 8:
        return 0
    if operation <= 2:
        if left != 0 or right != 0 or (operation == 1 and immediate != 0):
            return 0
        if width < 64 and immediate >= (1 << width):
            return 0
        return 1
    if immediate != 0 or left >= index:
        return 0
    if operation == 6:
        if right != 0 or width != node_width(source, left):
            return 0
        return 1
    if right >= index or node_width(source, left) != node_width(source, right):
        return 0
    if operation >= 7:
        if width != 1:
            return 0
    elif width != node_width(source, left):
        return 0
    return 1

def node_width(source:readbuf, node:u64) -> u64:
    return read64(source, 40 + 40 * node)

def encode_checked_circuit(source:readbuf, output:mutbuf, scratch:mutbuf, nodes:u64, returns:u64, budget:u64) -> u32:
    write64(scratch, 0, 1)
    write64(scratch, 8, 0)
    write64(scratch, 16, 40)
    position = CIRCUIT_GATES_OFFSET
    while position < CIRCUIT_WORKSPACE:
        store(scratch, position, 0)
        position = position + 1
    emit_clause(output, scratch, 2, 0, 0)
    node = 0
    while node < nodes:
        origin = 32 + 40 * node
        operation = read64(source, origin)
        width = read64(source, origin + 8)
        left = read64(source, origin + 16)
        right = read64(source, origin + 24)
        immediate = read64(source, origin + 32)
        if operation >= 7:
            delta = unequal_bits(output, scratch, left, right, node_width(source, left))
            if delta == 0:
                return TOO_LARGE
            put_token(scratch, 32 + 128 * node, delta ^ (operation & 1))
        else:
            bit = 0
            while bit < width:
                token = encode_bit(output, scratch, operation, left, right, immediate, bit)
                if token == 0:
                    return TOO_LARGE
                put_token(scratch, 32 + 128 * node + 2 * bit, token)
                bit = bit + 1
        node = node + 1
    mismatch = 3
    offset = 32 + 40 * nodes
    end = offset + 16 * returns
    while offset < end:
        left_node = read64(source, offset)
        right_node = read64(source, offset + 8)
        delta_value = unequal_bits(output, scratch, left_node, right_node, node_width(source, left_node))
        if delta_value == 0:
            return TOO_LARGE
        mismatch = logic_or(output, scratch, mismatch, delta_value)
        if mismatch == 0:
            return TOO_LARGE
        offset = offset + 16
    emit_clause(output, scratch, mismatch, 0, 0)
    size = read_stack(scratch, 16)
    write64(output, 0, SPARSE_REQUEST)
    write64(output, 8, read_stack(scratch, 0))
    write64(output, 16, read_stack(scratch, 8))
    write64(output, 24, budget)
    write64(output, 32, (size - 40) >> 1)
    return size

def encode_bit(output:mutbuf, scratch:mutbuf, operation:u64, left:u64, right:u64, immediate:u64, bit:u64) -> u64:
    if operation == 1:
        return allocate_variable(scratch)
    if operation == 2:
        return 3 ^ ((immediate >> bit) & 1)
    a = load_token(scratch, 32 + 128 * left + 2 * bit)
    if operation == 6:
        return a ^ 1
    b = load_token(scratch, 32 + 128 * right + 2 * bit)
    if operation == 3:
        return logic_and(output, scratch, a, b)
    if operation == 4:
        return logic_or(output, scratch, a, b)
    return logic_xor(output, scratch, a, b)

def unequal_bits(output:mutbuf, scratch:mutbuf, left:u64, right:u64, width:u64) -> u64:
    delta = 3
    bit = 0
    while bit < width:
        a = load_token(scratch, 32 + 128 * left + 2 * bit)
        b = load_token(scratch, 32 + 128 * right + 2 * bit)
        differs = logic_xor(output, scratch, a, b)
        if differs == 0:
            return 0
        delta = logic_or(output, scratch, delta, differs)
        if delta == 0 or delta == 2:
            return delta
        bit = bit + 1
    return delta

def allocate_variable(scratch:mutbuf) -> u64:
    count = read_stack(scratch, 0)
    if count >= SPARSE_VARIABLES:
        return 0
    write64(scratch, 0, count + 1)
    return (count + 1) << 1

def logic_and(output:mutbuf, scratch:mutbuf, a:u64, b:u64) -> u64:
    if a == 3 or b == 3 or a == (b ^ 1):
        return 3
    if a == 2 or a == b:
        return b
    if b == 2:
        return a
    key = gate_key(1, a, b)
    slot = find_gate(scratch, key)
    cached = read_stack(scratch, slot) & 65535
    if cached != 0:
        return cached
    token = allocate_variable(scratch)
    if token != 0:
        write64(scratch, slot, (key << 16) | token)
        emit_clause(output, scratch, a ^ 1, b ^ 1, token)
        emit_clause(output, scratch, a, token ^ 1, 0)
        emit_clause(output, scratch, b, token ^ 1, 0)
    return token

def logic_or(output:mutbuf, scratch:mutbuf, a:u64, b:u64) -> u64:
    token = logic_and(output, scratch, a ^ 1, b ^ 1)
    if token == 0:
        return 0
    return token ^ 1

def logic_xor(output:mutbuf, scratch:mutbuf, a:u64, b:u64) -> u64:
    if a == b:
        return 3
    if a == (b ^ 1):
        return 2
    if a == 3:
        return b
    if b == 3:
        return a
    if a == 2:
        return b ^ 1
    if b == 2:
        return a ^ 1
    polarity = (a ^ b) & 1
    left = a & 65534
    right = b & 65534
    key = gate_key(2, left, right)
    slot = find_gate(scratch, key)
    cached = read_stack(scratch, slot) & 65535
    if cached != 0:
        return cached ^ polarity
    token = allocate_variable(scratch)
    if token == 0:
        return 0
    write64(scratch, slot, (key << 16) | token)
    emit_clause(output, scratch, left, right, token ^ 1)
    emit_clause(output, scratch, left ^ 1, right ^ 1, token ^ 1)
    emit_clause(output, scratch, left, right ^ 1, token)
    emit_clause(output, scratch, left ^ 1, right, token)
    return token ^ polarity

def gate_key(operation:u64, a:u64, b:u64) -> u64:
    if a < b:
        return (operation << 28) | (a << 14) | b
    return (operation << 28) | (b << 14) | a

def find_gate(scratch:mutbuf, key:u64) -> u64:
    mask = CIRCUIT_GATE_SLOTS - 1
    index = ((key ^ (key >> 14)) * 2654435761) & mask
    slot = CIRCUIT_GATES_OFFSET + 8 * index
    stored = read_stack(scratch, slot) >> 16
    # With no more than SPARSE_VARIABLES allocated canonical gates,
    # at least half of this private lookup table always stays empty.
    while stored != 0 and stored != key:
        index = (index + 1) & mask
        slot = CIRCUIT_GATES_OFFSET + 8 * index
        stored = read_stack(scratch, slot) >> 16
    return slot

def emit_clause(output:mutbuf, scratch:mutbuf, a:u64, b:u64, c:u64) -> u64:
    # Each allocated gate emits at most four four-token clauses.
    # SPARSE_VARIABLES bounds the resulting packet below CIRCUIT_CAPACITY.
    position = read_stack(scratch, 16)
    put_token(output, position, a)
    position = position + 2
    if b != 0:
        put_token(output, position, b)
        position = position + 2
        if c != 0:
            put_token(output, position, c)
            position = position + 2
    put_token(output, position, 0)
    write64(scratch, 16, position + 2)
    write64(scratch, 8, read_stack(scratch, 8) + 1)
    return 0
'''


def source_program():
    constants = dict(CIRCUIT_REQUEST=CIRCUIT_REQUEST, CIRCUIT_CAPACITY=CIRCUIT_CAPACITY, CIRCUIT_NODES=CIRCUIT_NODES,
                     CIRCUIT_GATES_OFFSET=CIRCUIT_GATES_OFFSET, CIRCUIT_GATE_SLOTS=CIRCUIT_GATE_SLOTS,
                     CIRCUIT_RETURNS=CIRCUIT_RETURNS, CIRCUIT_WORKSPACE=CIRCUIT_WORKSPACE,
                     TOO_LARGE=0xfffffffc, SPARSE_REQUEST=SPARSE_REQUEST, SPARSE_REPLY=SPARSE_REPLY, SPARSE_CLAUSES=SPARSE_CLAUSES,
                     SPARSE_ENTRIES=SPARSE_ENTRIES, SPARSE_VARIABLES=SPARSE_VARIABLES,
                     SPARSE_WORKSPACE=SPARSE_WORKSPACE, DECISIONS=SPARSE_VARIABLES * 3,
                     TRAIL=SPARSE_VARIABLES, REQUEST=REQUEST, REPLY=REPLY, CLAUSE_LIMIT=CLAUSE_LIMIT,
                     STEP_LIMIT=STEP_LIMIT, WORD_MASK=WORD_MASK, WORKSPACE=WORKSPACE, INVALID=0xfffffffd)
    code = BODY
    for name, value in constants.items():
        code = code.replace(name, str(value))
    return render_assembly(document(code, 'cnf'))


if __name__ == '__main__':
    SOURCE.write_text(source_program())
