"""Generate the checked-in HIA Boolean solver from its readable authoring form."""

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import CLAUSE_LIMIT, REPLY, REQUEST, SOURCE, STEP_LIMIT, WORKSPACE
from tools.generate_hia_artifact_publication import document


WORD_MASK = (1 << 64) - 1


BODY = '''
def solve(source:readbuf, result:mutbuf, stack:mutbuf) -> u32:
    if length(source) < 32 or length(result) < 32 or length(stack) < WORKSPACE:
        return INVALID
    if read64(source, 0) != REQUEST:
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
'''


def source_program():
    constants = dict(REQUEST=REQUEST, REPLY=REPLY, CLAUSE_LIMIT=CLAUSE_LIMIT, STEP_LIMIT=STEP_LIMIT,
                     WORD_MASK=WORD_MASK, WORKSPACE=WORKSPACE, INVALID=0xfffffffd)
    code = BODY
    for name, value in constants.items():
        code = code.replace(name, str(value))
    return render_assembly(document(code, 'cnf'))


if __name__ == '__main__':
    SOURCE.write_text(source_program())
