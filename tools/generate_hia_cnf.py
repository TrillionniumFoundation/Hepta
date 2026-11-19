"""Generate the checked-in HIA Boolean solver from its readable authoring form."""

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (CLAUSE_LIMIT, REPLY, REQUEST, SOURCE, SPARSE_CLAUSES,
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
'''


def source_program():
    constants = dict(SPARSE_REQUEST=SPARSE_REQUEST, SPARSE_REPLY=SPARSE_REPLY, SPARSE_CLAUSES=SPARSE_CLAUSES,
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
