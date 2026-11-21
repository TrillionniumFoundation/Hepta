"""Generate the checked-in HIA Boolean solver from its readable authoring form."""

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (BATCH_REQUEST, GUARDED_CIRCUIT_REQUEST, CIRCUIT_CAPACITY, CIRCUIT_GATES_OFFSET, CIRCUIT_GATE_SLOTS,
                                  CIRCUIT_NODES, CIRCUIT_REQUEST, CIRCUIT_RETURNS, WORD_WITNESS_REQUEST,
                                  WORD_TABLE_REQUEST, WORD_TABLE_INPUT_BITS, WORD_TABLE_WORK_LIMIT,
                                  CIRCUIT_WORKSPACE, CLAUSE_LIMIT, REPLY, REQUEST, SOURCE, SPARSE_CLAUSES,
                                  CIRCUIT_DIVISION_TEMP, WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM, WORD_PRODUCT_EXCEEDS,
                                  CIRCUIT_SIGNED_MAGNITUDES, WORD_VARIABLE_SHL, WORD_VARIABLE_SHR,
                                  WORD_ARITHMETIC_SHR, WORD_SIGNED_DIV, WORD_SIGNED_REM,
                                  PROJECT_CHECKED_SHL, PROJECT_CHECKED_SHR, PROJECT_CHECKED_DIV, PROJECT_CHECKED_REM,
                                  PROJECT_CHECKED_CAST, PROJECT_CHECKED_MUL, PROJECT_DIRECT_CALL,
                                 LEARNED_CLAUSES, LEARNED_ENTRIES, LEARNING_BYTES, LEARNING_REASONS,
                                 LEARNING_REQUEST, RESTART_REQUEST, LEARNING_SEEN, LEARNING_TEMP, LEARNING_TOKENS,
                                 LEARNING_ORDER, LEARNING_HEAD, LEARNING_PHASE,
                                  SPARSE_ENTRIES, SPARSE_REPLY, SPARSE_REQUEST, SPARSE_VARIABLES,
                                  SPARSE_WORKSPACE, STEP_LIMIT, WATCHED_REQUEST, WATCH_HEADS,
                                  WATCH_ROWS, WATCH_ROW_BYTES, WORKSPACE)
from hepta.hia_cnf_native import (
    FEEDBACK_BLOCK_LIMIT, FEEDBACK_LAYER_LIMIT, FEEDBACK_OP_LIMIT, FEEDBACK_REPLY,
    FEEDBACK_REQUEST, FEEDBACK_WORKSPACE,
    ARTIFACT_PROJECTION_REQUEST, GRAPH_PROJECTION_REQUEST, CALL_PROJECTION_REQUEST, SCALAR_SUMMARY,
    PROJECTION_INPUT_LIMIT, PROJECTION_OUTPUT,
    PROJECT_CALL_RESULT, PROJECT_UNIT_TYPE, PROJECTION_WORKSPACE, SUMMARIZED_CALL_INPUTS, TUPLE_SUMMARY, _CORE_TRAP_TAGS,
)
from tools.generate_hia_artifact_publication import document


WORD_MASK = (1 << 64) - 1


BODY = '''
def solve(source:readbuf, result:mutbuf, stack:mutbuf) -> u32:
    if length(source) < 32 or length(result) < 32:
        return INVALID
    magic = read64(source, 0)
    if magic == SPARSE_REQUEST or magic == BATCH_REQUEST or magic == WATCHED_REQUEST or magic == LEARNING_REQUEST or magic == RESTART_REQUEST:
        return solve_sparse(source, result, stack, magic)
    if magic == CIRCUIT_REQUEST or magic == GUARDED_CIRCUIT_REQUEST:
        return encode_circuit(source, result, stack, magic == GUARDED_CIRCUIT_REQUEST)
    if magic == GRAPH_PROJECTION_REQUEST or magic == CALL_PROJECTION_REQUEST:
        return project_graphs(source, result, stack, magic == CALL_PROJECTION_REQUEST)
    if magic == ARTIFACT_PROJECTION_REQUEST:
        return project_artifact_circuit(source, result, stack)
    if magic == WORD_WITNESS_REQUEST:
        return check_word_witness(source, stack)
    if magic == WORD_TABLE_REQUEST:
        return search_word_table(source, result, stack)
    if magic == FEEDBACK_REQUEST:
        return plan_feedback(source, result, stack)
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

def solve_sparse(source:readbuf, result:mutbuf, stack:mutbuf, magic:u64) -> u32:
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
    learning = magic == LEARNING_REQUEST or magic == RESTART_REQUEST
    required = choose(magic == BATCH_REQUEST, SPARSE_WORKSPACE + 8, SPARSE_WORKSPACE)
    required = choose(magic == WATCHED_REQUEST, WATCH_ROWS + 2 * clauses * WATCH_ROW_BYTES, required)
    required = choose(learning, WATCH_ROWS + 2 * (clauses + LEARNED_CLAUSES) * WATCH_ROW_BYTES + LEARNING_BYTES, required)
    if length(stack) < required:
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
    if magic == WATCHED_REQUEST or learning:
        return search_watched(source, result, stack, variables, budget, learning)
    return search_sparse(source, result, stack, variables, budget, magic == BATCH_REQUEST)

def search_watched(source:readbuf, result:mutbuf, stack:mutbuf, variables:u64, budget:u64, learning:bool) -> u32:
    head = 0
    while head < 2 * variables + 2:
        write64(stack, WATCH_HEADS + head * 8, 0)
        head = head + 1
    write64(stack, SPARSE_WORKSPACE, 0)
    seeded = watch_seed(source, stack, budget)
    steps = seeded >> 2
    status = seeded & 3
    if status != 0:
        return reply_sparse(result, stack, variables, choose(status == 2, 2, 0), steps)
    if learning:
        return search_learning(source, result, stack, variables, budget, steps)
    propagated = 0
    depth = 0
    while steps < budget:
        trail = read_stack(stack, SPARSE_WORKSPACE)
        observed = watch_propagate(source, stack, propagated, steps, budget, 0)
        steps = observed >> 18
        status = observed & 262143
        if status == 1:
            return reply_sparse(result, stack, variables, 0, steps)
        decision = 2
        if status == 0:
            trail = read_stack(stack, SPARSE_WORKSPACE)
            observed = watch_decision(source, stack, steps, budget)
            steps = observed >> 17
            decision = observed & 131071
        if decision == 0:
            return reply_sparse(result, stack, variables, 1, steps)
        if decision == 1:
            return reply_sparse(result, stack, variables, 0, steps)
        if decision == 2:
            if depth == 0:
                return reply_sparse(result, stack, variables, 2, steps)
            depth = depth - 1
            mark = load_token(stack, DECISIONS + 4 * depth)
            alternative = load_token(stack, DECISIONS + 4 * depth + 2)
            trail = read_stack(stack, SPARSE_WORKSPACE)
            while trail > mark:
                trail = trail - 1
                store(stack, load_token(stack, TRAIL + 2 * trail), 0)
            write64(stack, SPARSE_WORKSPACE, mark)
            propagated = mark
            watch_enqueue(stack, alternative)
        else:
            # Try the observed polarity first; retain precisely its complement.
            literal = decision & 32767
            put_token(stack, DECISIONS + 4 * depth, trail)
            put_token(stack, DECISIONS + 4 * depth + 2, literal ^ 1)
            depth = depth + 1
            propagated = trail
            watch_enqueue(stack, literal)
    return reply_sparse(result, stack, variables, 0, steps)

def watch_enqueue(stack:mutbuf, literal:u64) -> u64:
    variable = (literal >> 1) - 1
    target = 1 + (literal & 1)
    state = byte(stack, variable)
    if state != 0:
        return choose(state == target, 0, 2)
    trail = read_stack(stack, SPARSE_WORKSPACE)
    store(stack, variable, target)
    put_token(stack, TRAIL + 2 * trail, variable)
    write64(stack, SPARSE_WORKSPACE, trail + 1)
    return 0

def watch_row(token:u64) -> u64:
    return WATCH_ROWS + (token - 1) * WATCH_ROW_BYTES

def watched_literal(source:readbuf, stack:mutbuf, position:u64) -> u64:
    if position < length(source):
        return read_token(source, position)
    aux = length(stack) - LEARNING_BYTES
    return load_token(stack, aux + LEARNING_TOKENS + position - length(source))

def watch_link(source:readbuf, stack:mutbuf, link:u64, start:u64, end:u64, at:u64) -> u64:
    row = watch_row(link)
    head = WATCH_HEADS + 8 * watched_literal(source, stack, at)
    write64(stack, row, start)
    write64(stack, row + 8, end)
    write64(stack, row + 16, at)
    write64(stack, row + 24, read_stack(stack, head))
    write64(stack, head, link)
    return 0

def watch_seed(source:readbuf, stack:mutbuf, budget:u64) -> u64:
    steps = 0
    start = 40
    link = 1
    while start < length(source):
        first = read_token(source, start)
        at = start
        second = 0
        active = True
        while active:
            if steps == budget:
                return (steps << 2) | 1
            steps = steps + 1
            literal = read_token(source, at)
            if literal == 0:
                active = False
            else:
                if second == 0 and literal != first:
                    second = at
                at = at + 2
        if first == 0:
            return (steps << 2) | 2
        if second == 0:
            if watch_enqueue(stack, first) != 0:
                return (steps << 2) | 2
        else:
            watch_link(source, stack, link, start, at, start)
            watch_link(source, stack, link + 1, start, at, second)
        start = at + 2
        link = link + 2
    return steps << 2

def watch_propagate(source:readbuf, stack:mutbuf, propagated:u64, steps:u64, budget:u64, depth:u64) -> u64:
    cursor = propagated
    while cursor < read_stack(stack, SPARSE_WORKSPACE):
        variable = load_token(stack, TRAIL + 2 * cursor)
        false_literal = 2 * (variable + 1) + (2 - byte(stack, variable))
        previous = WATCH_HEADS + 8 * false_literal
        while read_stack(stack, previous) != 0:
            if steps == budget:
                return (steps << 18) | 1
            steps = steps + 1
            link = read_stack(stack, previous)
            row = watch_row(link)
            sibling = watch_row(((link - 1) ^ 1) + 1)
            other_literal = watched_literal(source, stack, read_stack(stack, sibling + 16))
            other_state = byte(stack, (other_literal >> 1) - 1)
            if other_state == 1 + (other_literal & 1):
                previous = row + 24
            else:
                start = read_stack(stack, row)
                end = read_stack(stack, row + 8)
                replacement = 0
                while start < end and replacement == 0:
                    if steps == budget:
                        return (steps << 18) | 1
                    steps = steps + 1
                    literal = watched_literal(source, stack, start)
                    state = byte(stack, (literal >> 1) - 1)
                    if literal != other_literal and state != 2 - (literal & 1):
                        replacement = start
                    start = start + 2
                if replacement == 0:
                    if other_state != 0:
                        return (steps << 18) | (link + 2)
                    watch_enqueue(stack, other_literal)
                    if depth != 0:
                        learn_cause(stack, other_literal, depth, link)
                    previous = row + 24
                else:
                    write64(stack, previous, read_stack(stack, row + 24))
                    watch_link(source, stack, link, read_stack(stack, row), end, replacement)
        cursor = cursor + 1
    return steps << 18

def watch_decision(source:readbuf, stack:mutbuf, steps:u64, budget:u64) -> u64:
    # Search backward from the retained result constraint, where unresolved
    # gates are typically closer to the observation than arbitrary input bits.
    position = length(source)
    choice = 0
    satisfied = 1
    while position > 40:
        if steps == budget:
            return (steps << 17) | 1
        steps = steps + 1
        position = position - 2
        literal = read_token(source, position)
        if literal == 0:
            if satisfied == 0:
                return (steps << 17) | choose(choice == 0, 2, 32768 + choice)
            choice = 0
            satisfied = 0
        elif satisfied == 0:
            state = byte(stack, (literal >> 1) - 1)
            if state == 1 + (literal & 1):
                satisfied = 1
            elif state == 0 and choice == 0:
                choice = literal
    if satisfied == 0:
        return (steps << 17) | choose(choice == 0, 2, 32768 + choice)
    return steps << 17

def learn_cause(stack:mutbuf, literal:u64, depth:u64, reason:u64) -> u64:
    aux = length(stack) - LEARNING_BYTES
    variable = (literal >> 1) - 1
    put_token(stack, aux + 2 * variable, depth)
    write64(stack, aux + LEARNING_REASONS + 8 * variable, reason)
    return 0

def init_learning(stack:mutbuf, aux:u64, variables:u64) -> u64:
    order = aux + LEARNING_ORDER
    first = choose(variables == 0, 0, 1)
    put_token(stack, aux + LEARNING_HEAD, first)
    put_token(stack, aux + LEARNING_HEAD + 2, first)
    variable = 0
    while variable < variables:
        put_token(stack, aux + 2 * variable, 0)
        put_token(stack, aux + LEARNING_SEEN + 2 * variable, 0)
        store(stack, aux + LEARNING_PHASE + variable, 0)
        index = variable + 1
        put_token(stack, order + 4 * index, index - 1)
        put_token(stack, order + 4 * index + 2, choose(index == variables, 0, index + 1))
        variable = variable + 1
    return 0

def promote_learning(stack:mutbuf, aux:u64, index:u64) -> u64:
    order = aux + LEARNING_ORDER
    head = load_token(stack, aux + LEARNING_HEAD)
    if head == index:
        return 0
    row = order + 4 * index
    previous = load_token(stack, row)
    next_index = load_token(stack, row + 2)
    put_token(stack, order + 4 * previous + 2, next_index)
    if next_index != 0:
        put_token(stack, order + 4 * next_index, previous)
    put_token(stack, order + 4 * head, index)
    put_token(stack, row, 0)
    put_token(stack, row + 2, head)
    put_token(stack, aux + LEARNING_HEAD, index)
    return 0

def choose_learning(stack:mutbuf, aux:u64, steps:u64, budget:u64) -> u64:
    index = load_token(stack, aux + LEARNING_HEAD + 2)
    order = aux + LEARNING_ORDER
    while index != 0:
        if steps == budget:
            return (steps << 17) | 1
        steps = steps + 1
        if byte(stack, index - 1) == 0:
            put_token(stack, aux + LEARNING_HEAD + 2, load_token(stack, order + 4 * index + 2))
            return (steps << 17) | 32768 | (2 * index + byte(stack, aux + LEARNING_PHASE + index - 1))
        index = load_token(stack, order + 4 * index + 2)
    return steps << 17

def drop_learning_levels(stack:mutbuf, aux:u64, trail:u64, depth:u64) -> u64:
    mark = load_token(stack, DECISIONS + 4 * depth)
    while trail > mark:
        trail = trail - 1
        popped = load_token(stack, TRAIL + 2 * trail)
        store(stack, aux + LEARNING_PHASE + popped, byte(stack, popped) - 1)
        store(stack, popped, 0)
        put_token(stack, aux + 2 * popped, 0)
    put_token(stack, aux + LEARNING_HEAD + 2, load_token(stack, aux + LEARNING_HEAD))
    write64(stack, SPARSE_WORKSPACE, mark)
    return mark

def search_learning(source:readbuf, result:mutbuf, stack:mutbuf, variables:u64,
                    budget:u64, steps:u64) -> u32:
    aux = length(stack) - LEARNING_BYTES
    init_learning(stack, aux, variables)
    propagated = 0
    depth = 0
    learned = 0
    position = length(source)
    restart_interval = 128
    next_restart = choose(read64(source, 0) == RESTART_REQUEST, restart_interval, LEARNED_CLAUSES + 1)
    while steps < budget:
        observed = watch_propagate(source, stack, propagated, steps, budget, depth)
        steps = observed >> 18
        status = observed & 262143
        if status == 1:
            return reply_sparse(result, stack, variables, 0, steps)
        trail = read_stack(stack, SPARSE_WORKSPACE)
        if status == 0:
            # Restart only after propagation is complete. Keep root
            # implications, learned clauses, and saved phases.
            if learned >= next_restart:
                restart_interval = restart_interval + (restart_interval >> 1)
                next_restart = learned + restart_interval
                if depth != 0:
                    root = load_token(stack, DECISIONS)
                    removed = trail - root
                    if removed >= budget - steps:
                        return reply_sparse(result, stack, variables, 0, budget)
                    steps = steps + removed
                    trail = drop_learning_levels(stack, aux, trail, 0)
                    depth = 0
            pick = choose_learning(stack, aux, steps, budget)
            steps = pick >> 17
            literal = pick & 32767
            if literal < 2:
                return reply_sparse(result, stack, variables, literal ^ 1, steps)
            if (pick & 32768) == 0 or depth >= variables:
                return INVALID
            put_token(stack, DECISIONS + 4 * depth, trail)
            depth = depth + 1
            propagated = trail
            watch_enqueue(stack, literal)
            learn_cause(stack, literal, depth, 0)
        else:
            if depth == 0:
                return reply_sparse(result, stack, variables, 2, steps)
            # Exhausted learning storage is not a conclusive result.
            if learned == LEARNED_CLAUSES:
                return reply_sparse(result, stack, variables, 0, budget)
            level_and_stamp = (depth << 13) | (learned + 1)
            analyzed = analyze_conflict(source, stack, level_and_stamp, status - 2, steps, budget)
            steps = analyzed >> 26
            count = analyzed & 8191
            if count == 0 or position + 2 * count > length(source) + 2 * LEARNED_ENTRIES:
                return reply_sparse(result, stack, variables, 0, budget)
            depth = (analyzed >> 13) & 8191
            propagated = drop_learning_levels(stack, aux, trail, depth)
            link = 1 + 2 * (read64(source, 16) + learned)
            if count > 1:
                position = publish_learned(source, stack, position, count, link)
            else:
                link = 0
            literal = load_token(stack, aux + LEARNING_TEMP)
            if watch_enqueue(stack, literal) != 0:
                return INVALID
            learn_cause(stack, literal, depth, link)
            learned = learned + 1
    return reply_sparse(result, stack, variables, 0, budget)

def analyze_conflict(source:readbuf, stack:mutbuf, level_and_stamp:u64, link:u64,
                     steps:u64, budget:u64) -> u64:
    aux = length(stack) - LEARNING_BYTES
    depth = level_and_stamp >> 13
    stamp = level_and_stamp & 8191
    seen = aux + LEARNING_SEEN
    literals = aux + LEARNING_TEMP
    # The low three 13-bit fields hold unresolved variables at this level,
    # learned literal count, and the highest earlier-level literal's index.
    # All fit 4096 variables; the remaining high bits hold the work count.
    progress = (steps << 39) | 8192
    pivot = 65535
    trail = read_stack(stack, SPARSE_WORKSPACE)
    while link != 0:
        progress = analyze_clause(source, stack, link, (level_and_stamp << 16) | pivot, progress, budget)
        if progress == 0:
            return 0
        steps = progress >> 39
        # Walk the implication trail backward to the first unique
        # implication point. Repeated literals are marked once per conflict.
        found = False
        while trail != 0 and found == False:
            if steps == budget:
                return 0
            steps = steps + 1
            trail = trail - 1
            pivot = load_token(stack, TRAIL + 2 * trail)
            found = load_token(stack, aux + 2 * pivot) == depth and load_token(stack, seen + 2 * pivot) == stamp
        if found == False or (progress & 8191) == 0:
            return 0
        progress = (steps << 39) | ((progress & 549755813887) - 1)
        if (progress & 8191) == 0:
            put_token(stack, literals, 2 * (pivot + 1) + 2 - byte(stack, pivot))
            second = (progress >> 26) & 8191
            backjump = learned_level(stack, aux, second)
            if second > 1:
                saved = load_token(stack, literals + 2)
                put_token(stack, literals + 2, load_token(stack, literals + 2 * second))
                put_token(stack, literals + 2 * second, saved)
            return (steps << 26) | (backjump << 13) | ((progress >> 13) & 8191)
        link = read_stack(stack, aux + LEARNING_REASONS + 8 * pivot)
    return 0

def learned_level(stack:mutbuf, aux:u64, index:u64) -> u64:
    if index == 0:
        return 0
    literal = load_token(stack, aux + LEARNING_TEMP + 2 * index)
    return load_token(stack, aux + 2 * ((literal >> 1) - 1))

def analyze_clause(source:readbuf, stack:mutbuf, link:u64, phase:u64,
                   progress:u64, budget:u64) -> u64:
    row = watch_row(link)
    position = read_stack(stack, row)
    end = read_stack(stack, row + 8)
    aux = length(stack) - LEARNING_BYTES
    while position < end:
        if (progress >> 39) == budget:
            return 0
        progress = progress + 549755813888
        literal = watched_literal(source, stack, position)
        variable = (literal >> 1) - 1
        level = load_token(stack, aux + 2 * variable)
        stamp = (phase >> 16) & 8191
        if variable != (phase & 65535) and level != 0 and load_token(stack, aux + LEARNING_SEEN + 2 * variable) != stamp:
            put_token(stack, aux + LEARNING_SEEN + 2 * variable, stamp)
            promote_learning(stack, aux, variable + 1)
            progress = note_learned(stack, aux, literal, level, phase >> 29, progress)
            if progress == 0:
                return 0
        position = position + 2
    return progress

def note_learned(stack:mutbuf, aux:u64, literal:u64, level:u64, depth:u64, progress:u64) -> u64:
    if level == depth:
        return progress + 1
    count = (progress >> 13) & 8191
    if count >= SPARSE_VARIABLES:
        return 0
    second = (progress >> 26) & 8191
    if level > learned_level(stack, aux, second):
        progress = progress ^ ((second ^ count) << 26)
    put_token(stack, aux + LEARNING_TEMP + 2 * count, literal)
    return progress + 8192

def publish_learned(source:readbuf, stack:mutbuf, position:u64, count:u64, link:u64) -> u64:
    # Position is in one logical address space. Learned literals occupy a
    # disjoint scratch region beyond the end of the original frame.
    aux = length(stack) - LEARNING_BYTES
    destination = aux + LEARNING_TOKENS + position - length(source)
    index = 0
    while index < count:
        put_token(stack, destination + 2 * index, load_token(stack, aux + LEARNING_TEMP + 2 * index))
        index = index + 1
    end = position + 2 * count
    watch_link(source, stack, link, position, end, position)
    watch_link(source, stack, link + 1, position, end, position + 2)
    return end

def search_sparse(source:readbuf, result:mutbuf, stack:mutbuf, variables:u64,
                  budget:u64, batch:bool) -> u32:
    steps = 0
    trail = 0
    depth = 0
    while steps < budget:
        if batch:
            write64(stack, SPARSE_WORKSPACE, trail)
        observed = scan_sparse(source, stack, steps + 1, budget, batch)
        if batch:
            trail = read_stack(stack, SPARSE_WORKSPACE)
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
        elif decision != 3:
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

def scan_sparse(source:readbuf, stack:mutbuf, steps:u64, budget:u64, batch:bool) -> u64:
    position = 40
    choice = 0
    first = 0
    several = 0
    satisfied = 0
    changed = 0
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
                    if batch:
                        variable = (first >> 1) - 1
                        trail = read_stack(stack, SPARSE_WORKSPACE)
                        put_token(stack, TRAIL + 2 * trail, variable)
                        store(stack, variable, 1 + (first & 1))
                        write64(stack, SPARSE_WORKSPACE, trail + 1)
                        changed = 1
                    else:
                        return (steps << 17) | (32768 + first)
                elif choice == 0:
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
    if changed != 0:
        # An earlier clause can have become newly unit in this pass.
        return (steps << 17) | 3
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

def encode_circuit(source:readbuf, output:mutbuf, scratch:mutbuf, guarded:bool) -> u32:
    if length(output) < CIRCUIT_CAPACITY or length(scratch) < CIRCUIT_WORKSPACE:
        return INVALID
    nodes = read64(source, 8)
    returns = read64(source, 16)
    budget = read64(source, 24)
    if nodes > CIRCUIT_NODES or returns > CIRCUIT_RETURNS or budget > STEP_LIMIT:
        return INVALID
    return_offset = 32 + 40 * nodes
    end = return_offset + 16 * returns
    expected_size = end
    if guarded:
        expected_size = end + 16
    if length(source) != expected_size:
        return INVALID
    if valid_circuit(source, nodes, returns, guarded) == 0:
        return INVALID
    return encode_checked_circuit(source, output, scratch, nodes, returns, budget, guarded)

def valid_word_graph(source:readbuf, rows:u64, nodes:u64) -> u64:
    index = 0
    while index < nodes:
        origin = rows + 40 * index
        operation = read64(source, origin)
        width = read64(source, origin + 8)
        left = read64(source, origin + 16)
        right = read64(source, origin + 24)
        immediate = read64(source, origin + 32)
        if valid_node(source, rows, index, operation, width, left, right, immediate) == 0:
            return 0
        index = index + 1
    return 1

def valid_circuit(source:readbuf, nodes:u64, returns:u64, guarded:bool) -> u64:
    if valid_word_graph(source, 32, nodes) == 0:
        return 0
    return_offset = 32 + 40 * nodes
    index = 0
    while index < returns:
        left = read64(source, return_offset + 16 * index)
        right = read64(source, return_offset + 16 * index + 8)
        if left >= nodes or right >= nodes or node_width(source, left) != node_width(source, right):
            return 0
        index = index + 1
    if guarded:
        end = return_offset + 16 * returns
        left_guard = read64(source, end)
        right_guard = read64(source, end + 8)
        if left_guard >= nodes or right_guard >= nodes:
            return 0
        if node_width(source, left_guard) != 1 or node_width(source, right_guard) != 1:
            return 0
    return 1

def check_word_witness(source:readbuf, scratch:mutbuf) -> u32:
    nodes = read64(source, 8)
    returns = read64(source, 16)
    guards = read64(source, 24)
    if nodes > CIRCUIT_NODES or returns > CIRCUIT_RETURNS or guards > 1 or length(scratch) < nodes * 8:
        return INVALID
    return_offset = 32 + 40 * nodes
    end = return_offset + 16 * returns
    begin = end + 16 * guards
    if length(source) < begin or length(source) > begin + 8 * nodes:
        return INVALID
    if valid_circuit(source, nodes, returns, guards != 0) == 0:
        return INVALID
    if evaluate_word_nodes(source, scratch, nodes, begin) == 0:
        return INVALID
    if word_mismatch(source, scratch, return_offset, end, guards != 0):
        return 1
    return 0

def word_mismatch(source:readbuf, scratch:mutbuf, at:u64, end:u64, guarded:bool) -> bool:
    if guarded:
        left_guard = read_stack(scratch, 8 * read64(source, end))
        right_guard = read_stack(scratch, 8 * read64(source, end + 8))
        if left_guard != right_guard:
            return True
        if left_guard == 1:
            return False
    while at < end:
        left = read_stack(scratch, 8 * read64(source, at))
        right = read_stack(scratch, 8 * read64(source, at + 8))
        if left != right:
            return True
        at = at + 16
    return False

def search_word_table(source:readbuf, output:mutbuf, scratch:mutbuf) -> u32:
    nodes = read64(source, 8)
    returns = read64(source, 16)
    guards = read64(source, 24)
    if nodes > CIRCUIT_NODES or returns > CIRCUIT_RETURNS or guards > 1 or length(scratch) < nodes * 8:
        return INVALID
    start = 32 + 40 * nodes
    end = start + 16 * returns
    budget_at = end + 16 * guards
    if length(source) != budget_at + 8 or valid_circuit(source, nodes, returns, guards != 0) == 0:
        return INVALID
    budget = read64(source, budget_at)
    if budget > WORD_TABLE_WORK_LIMIT:
        return INVALID
    bits = 0
    cost = 1 + nodes + returns + guards
    node = 0
    while node < nodes:
        at = 32 + 40 * node
        operation = read64(source, at)
        width = read64(source, at + 8)
        if operation == 1:
            bits = bits + width
        elif operation == WORD_UNSIGNED_DIV or operation == WORD_UNSIGNED_REM:
            cost = cost + width
        elif operation == WORD_PRODUCT_EXCEEDS:
            cost = cost + node_width(source, read64(source, at + 16))
        node = node + 1
    if bits > WORD_TABLE_INPUT_BITS:
        return TOO_LARGE
    count = 1 << bits
    if count * cost > budget:
        return TOO_LARGE
    candidate = 0
    while candidate < count:
        evaluate_table_nodes(source, scratch, nodes, candidate)
        if word_mismatch(source, scratch, start, end, guards != 0):
            return word_table_reply(output, 1, candidate, candidate + 1)
        candidate = candidate + 1
    return word_table_reply(output, 2, 0, count)

def word_table_reply(output:mutbuf, verdict:u64, assignment:u64, checked:u64) -> u32:
    write64(output, 0, WORD_TABLE_REQUEST)
    write64(output, 8, verdict)
    write64(output, 16, assignment)
    write64(output, 24, checked)
    return 32

def evaluate_table_nodes(source:readbuf, scratch:mutbuf, nodes:u64, assignment:u64) -> u64:
    node = 0
    while node < nodes:
        origin = 32 + 40 * node
        operation = read64(source, origin)
        width = read64(source, origin + 8)
        word = read64(source, origin + 32)
        if operation == 1:
            word = assignment & word_mask(width)
            assignment = assignment >> width
        elif operation > 2:
            word = evaluate_word_node(source, scratch, operation, width, origin)
        write64(scratch, 8 * node, word)
        node = node + 1
    return 0

def evaluate_word_nodes(source:readbuf, scratch:mutbuf, nodes:u64, at:u64) -> u64:
    node = 0
    while node < nodes:
        origin = 32 + 40 * node
        operation = read64(source, origin)
        width = read64(source, origin + 8)
        word = read64(source, origin + 32)
        if operation == 1:
            if length(source) - at < 8:
                return 0
            word = read64(source, at)
            if word > word_mask(width):
                return 0
            at = at + 8
        elif operation > 2:
            word = evaluate_word_node(source, scratch, operation, width, origin)
        write64(scratch, 8 * node, word)
        node = node + 1
    return choose(at == length(source), 1, 0)

def evaluate_word_node(source:readbuf, scratch:mutbuf, operation:u64, width:u64, origin:u64) -> u64:
    left = read64(source, origin + 16)
    right = read64(source, origin + 24)
    immediate = read64(source, origin + 32)
    a = read_stack(scratch, 8 * left)
    b = read_stack(scratch, 8 * right)
    if operation == 3:
        return a & b
    if operation == 4:
        return a | b
    if operation == 5:
        return a ^ b
    if operation == 6:
        return a ^ word_mask(width)
    if operation == 7 or operation == 8:
        return choose((a == b) == (operation == 7), 1, 0)
    if operation == 9:
        return (a + b) & word_mask(width)
    if operation == 10:
        return (a - b) & word_mask(width)
    if operation == 11:
        return choose(a == 1, b, read_stack(scratch, 8 * immediate))
    source_width = node_width(source, left)
    if operation < 20:
        return evaluate_word_order(a, b, source_width, operation)
    if operation >= 22 and operation <= 25:
        return evaluate_word_overflow(a, b, source_width, operation)
    if operation == 32:
        return (a * b) & word_mask(width)
    if operation == WORD_UNSIGNED_DIV or operation == WORD_UNSIGNED_REM:
        return evaluate_word_division(a, b, width, operation)
    if operation == WORD_SIGNED_DIV or operation == WORD_SIGNED_REM:
        return evaluate_signed_division(a, b, width, operation == WORD_SIGNED_DIV)
    if operation == WORD_PRODUCT_EXCEEDS:
        if b == 0:
            return 0
        limit = read_stack(scratch, 8 * immediate)
        return choose(a > evaluate_word_division(limit, b, source_width, WORD_UNSIGNED_DIV), 1, 0)
    if operation == 26:
        return (a >> immediate) & word_mask(width)
    if operation == 27:
        return (a << node_width(source, right)) | b
    if operation == 28 or operation == 29:
        if immediate >= width:
            return 0
        return choose(operation == 28, (a << immediate) & word_mask(width), a >> immediate)
    if operation == WORD_ARITHMETIC_SHR:
        mask = word_mask(width)
        negative = (a >> (width - 1)) != 0
        if b >= width:
            return choose(negative, mask, 0)
        fill = choose(negative, mask ^ (mask >> b), 0)
        return fill | (a >> b)
    if operation == WORD_VARIABLE_SHL or operation == WORD_VARIABLE_SHR:
        if b >= width:
            return 0
        return choose(operation == WORD_VARIABLE_SHL, (a << b) & word_mask(width), a >> b)
    if (operation == 21 or operation == 31) and (a >> (source_width - 1)) == 1:
        a = a | (WORD_MASK ^ word_mask(source_width))
    return a & word_mask(width)

def evaluate_word_division(a:u64, b:u64, width:u64, operation:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = width
    mask = word_mask(width)
    while bit > 0:
        bit = bit - 1
        carried = remainder >> (width - 1)
        remainder = ((remainder << 1) | ((a >> bit) & 1)) & mask
        if carried != 0 or remainder >= b:
            remainder = (remainder - b) & mask
            quotient = quotient | (1 << bit)
    return choose(operation == WORD_UNSIGNED_DIV, quotient, remainder)

def evaluate_signed_division(a:u64, b:u64, width:u64, quotient:bool) -> u64:
    mask = word_mask(width)
    left_negative = (a >> (width - 1)) != 0
    right_negative = (b >> (width - 1)) != 0
    dividend = choose(left_negative, (0 - a) & mask, a)
    divisor = choose(right_negative, (0 - b) & mask, b)
    unsigned_operation = choose(quotient, WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM)
    magnitude = evaluate_word_division(dividend, divisor, width, unsigned_operation)
    negative = choose(quotient, left_negative != right_negative, left_negative)
    # Restoring division returns all ones or the original dividend for zero.
    # Restoring the sign gives SMT-LIB's signed quotient/remainder zero case.
    return choose(negative, (0 - magnitude) & mask, magnitude)

def word_mask(width:u64) -> u64:
    if width == 64:
        return WORD_MASK
    return (1 << width) - 1

def evaluate_word_order(a:u64, b:u64, width:u64, operation:u64) -> u64:
    if operation >= 16:
        sign = 1 << (width - 1)
        a = a ^ sign
        b = b ^ sign
    relation = operation & 3
    if relation == 0:
        return choose(a < b, 1, 0)
    if relation == 1:
        return choose(a <= b, 1, 0)
    if relation == 2:
        return choose(a > b, 1, 0)
    return choose(a >= b, 1, 0)

def evaluate_word_overflow(a:u64, b:u64, width:u64, operation:u64) -> u64:
    if operation == 22:
        return choose(a > word_mask(width) - b, 1, 0)
    if operation == 23:
        return choose(a < b, 1, 0)
    sign = 1 << (width - 1)
    if operation == 24:
        result = a + b
        return choose(((a ^ result) & (b ^ result) & sign) != 0, 1, 0)
    result = a - b
    return choose(((a ^ b) & (a ^ result) & sign) != 0, 1, 0)

def valid_node(source:readbuf, rows:u64, index:u64, operation:u64, width:u64, left:u64, right:u64, immediate:u64) -> u64:
    if width == 0 or width > 64:
        return 0
    if operation < 1 or operation > WORD_SIGNED_REM:
        return 0
    if operation <= 2:
        if left != 0 or right != 0 or (operation == 1 and immediate != 0):
            return 0
        if width < 64 and immediate >= (1 << width):
            return 0
        return 1
    if left >= index:
        return 0
    # The left operand is already known, so use it as the in-range
    # placeholder for unused or out-of-range operands. Admission still
    # rejects every invalid operand before accepting its type.
    lw = word_graph_width(source, rows, left)
    rw = word_graph_width(source, rows, choose(right < index, right, left))
    iw = word_graph_width(source, rows, choose(immediate < index, immediate, left))
    if operation == 11:
        return choose(right < index and immediate < index and lw == 1 and width == rw and width == iw, 1, 0)
    if operation == WORD_PRODUCT_EXCEEDS:
        return choose(width == 1 and right < index and immediate < index and lw > 1 and rw == lw and iw == lw, 1, 0)
    if operation == 26:
        return choose(right == 0 and immediate <= lw and width <= lw - immediate, 1, 0)
    if operation == 27:
        return choose(right < index and immediate == 0 and width == lw + rw, 1, 0)
    if operation == 28 or operation == 29:
        return choose(right == 0 and width == lw, 1, 0)
    if operation == 30 or operation == 31:
        return choose(right == 0 and immediate == 0 and width >= lw, 1, 0)
    if immediate != 0:
        return 0
    if operation == 20 or operation == 21:
        return choose(right == 0 and width != 1 and lw != 1, 1, 0)
    if operation == 6:
        return choose(right == 0 and width == lw, 1, 0)
    if right >= index or lw != rw:
        return 0
    if operation == 32 or operation == WORD_UNSIGNED_DIV or operation == WORD_UNSIGNED_REM or operation == WORD_SIGNED_DIV or operation == WORD_SIGNED_REM:
        return choose(width > 1 and width == lw, 1, 0)
    if operation == WORD_VARIABLE_SHL or operation == WORD_VARIABLE_SHR or operation == WORD_ARITHMETIC_SHR:
        return choose(width == lw, 1, 0)
    if operation >= 12:
        return choose(width == 1 and lw != 1, 1, 0)
    elif operation == 7 or operation == 8:
        return choose(width == 1, 1, 0)
    return choose(width == lw and (width != 1 or (operation != 9 and operation != 10)), 1, 0)

def node_width(source:readbuf, node:u64) -> u64:
    return word_graph_width(source, 32, node)

def word_graph_width(source:readbuf, rows:u64, node:u64) -> u64:
    return read64(source, rows + 8 + 40 * node)

def word_arguments(operation:u64) -> u64:
    if operation <= 2:
        return 0
    if operation == 6 or operation == 20 or operation == 21 or operation == 26 or (operation >= 28 and operation <= 31):
        return 1
    if operation == 11 or operation == WORD_PRODUCT_EXCEEDS:
        return 3
    return 2

def mark_observed_nodes(source:readbuf, scratch:mutbuf, nodes:u64, returns:u64, guarded:bool) -> u64:
    # The first byte of each token row temporarily marks liveness. Nodes
    # are visited backwards here and consume the mark before encoding.
    node = 0
    while node < nodes:
        store(scratch, 32 + 128 * node, 0)
        node = node + 1
    offset = 32 + 40 * nodes
    end = offset + 16 * returns
    if guarded:
        end = end + 16
    while offset < end:
        store(scratch, 32 + 128 * read64(source, offset), 1)
        offset = offset + 8
    while node > 0:
        node = node - 1
        origin = 32 + 40 * node
        operation = read64(source, origin)
        if byte(scratch, 32 + 128 * node) != 0:
            count = word_arguments(operation)
            argument = 0
            while argument < count:
                dependency = read64(source, origin + 16 + 8 * argument)
                store(scratch, 32 + 128 * dependency, 1)
                argument = argument + 1
    return 0

def encode_checked_circuit(source:readbuf, output:mutbuf, scratch:mutbuf, nodes:u64, returns:u64, budget:u64, guarded:bool) -> u32:
    write64(scratch, 0, 1)
    write64(scratch, 8, 0)
    write64(scratch, 16, 40)
    position = CIRCUIT_GATES_OFFSET
    while position < CIRCUIT_WORKSPACE:
        store(scratch, position, 0)
        position = position + 1
    emit_clause(output, scratch, 2, 0, 0)
    mark_observed_nodes(source, scratch, nodes, returns, guarded)
    node = 0
    while node < nodes:
        origin = 32 + 40 * node
        operation = read64(source, origin)
        # Preserve allocation and witness decoding for every input even
        # when its computation does not flow to an observed result.
        if operation == 1 or byte(scratch, 32 + 128 * node) != 0:
            width = read64(source, origin + 8)
            left = read64(source, origin + 16)
            right = read64(source, origin + 24)
            immediate = read64(source, origin + 32)
            if operation == WORD_PRODUCT_EXCEEDS:
                if encode_product_limit(output, scratch, node, left, right, immediate, node_width(source, left)) == 0:
                    return TOO_LARGE
            elif operation == WORD_UNSIGNED_DIV or operation == WORD_UNSIGNED_REM:
                if encode_division(output, scratch, 32 + 128 * node, 32 + 128 * left, 32 + 128 * right,
                                   width, operation == WORD_UNSIGNED_DIV) == 0:
                    return TOO_LARGE
            elif operation == WORD_SIGNED_DIV or operation == WORD_SIGNED_REM:
                if encode_signed_division(output, scratch, node, left, right, width, operation == WORD_SIGNED_DIV) == 0:
                    return TOO_LARGE
            elif operation == WORD_VARIABLE_SHL or operation == WORD_VARIABLE_SHR or operation == WORD_ARITHMETIC_SHR:
                if encode_variable_shift(output, scratch, node, left, right, width, operation) == 0:
                    return TOO_LARGE
            elif operation == 32:
                if encode_product(output, scratch, node, choose(left < right, left, right), choose(left < right, right, left), width) == 0:
                    return TOO_LARGE
            elif operation >= 26:
                encode_projection(source, scratch, node, operation, width, left, right, immediate)
            elif operation == 7 or operation == 8:
                delta = unequal_bits(output, scratch, left, right, node_width(source, left))
                if delta == 0:
                    return TOO_LARGE
                put_token(scratch, 32 + 128 * node, delta ^ (operation & 1))
            elif operation == 9 or operation == 10:
                if encode_sum(output, scratch, node, left, right, width, operation) == 0:
                    return TOO_LARGE
            elif operation >= 22:
                if encode_sum(output, scratch, node, left, right, node_width(source, left), operation) == 0:
                    return TOO_LARGE
            elif operation >= 12 and operation <= 19:
                digit = ordered_comparison(output, scratch, source, operation, left, right)
                if digit == 0:
                    return TOO_LARGE
                put_token(scratch, 32 + 128 * node, digit)
            elif operation >= 20:
                encode_wrapping_cast(scratch, node, left, width, node_width(source, left), operation == 21)
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
    if guarded:
        left_guard = load_token(scratch, 32 + 128 * read64(source, end))
        right_guard = load_token(scratch, 32 + 128 * read64(source, end + 8))
        trap_mismatch = logic_xor(output, scratch, left_guard, right_guard)
        success = logic_and(output, scratch, left_guard ^ 1, right_guard ^ 1)
        if trap_mismatch == 0 or success == 0:
            return TOO_LARGE
        observed_return_mismatch = logic_and(output, scratch, success, mismatch)
        if observed_return_mismatch == 0:
            return TOO_LARGE
        mismatch = logic_or(output, scratch, trap_mismatch, observed_return_mismatch)
        if mismatch == 0:
            return TOO_LARGE
    emit_clause(output, scratch, mismatch, 0, 0)
    size = read_stack(scratch, 16)
    write64(output, 0, SPARSE_REQUEST)
    write64(output, 8, read_stack(scratch, 0))
    write64(output, 16, read_stack(scratch, 8))
    write64(output, 24, budget)
    write64(output, 32, (size - 40) >> 1)
    return size

def encode_projection(source:readbuf, scratch:mutbuf, node:u64, operation:u64, width:u64,
                      left:u64, right:u64, immediate:u64) -> u64:
    bit = 0
    while bit < width:
        token = 3
        if operation == 26:
            token = load_token(scratch, 32 + 128 * left + 2 * (bit + immediate))
        elif operation == 27:
            low_width = node_width(source, right)
            if bit < low_width:
                token = load_token(scratch, 32 + 128 * right + 2 * bit)
            else:
                token = load_token(scratch, 32 + 128 * left + 2 * (bit - low_width))
        elif operation == 28:
            if bit >= immediate:
                token = load_token(scratch, 32 + 128 * left + 2 * (bit - immediate))
        elif operation == 29:
            if immediate < width and bit < width - immediate:
                token = load_token(scratch, 32 + 128 * left + 2 * (bit + immediate))
        else:
            source_width = node_width(source, left)
            if bit < source_width:
                token = load_token(scratch, 32 + 128 * left + 2 * bit)
            elif operation == 31:
                token = load_token(scratch, 32 + 128 * left + 2 * (source_width - 1))
        put_token(scratch, 32 + 128 * node + 2 * bit, token)
        bit = bit + 1
    return 1

def encode_bit(output:mutbuf, scratch:mutbuf, operation:u64, left:u64, right:u64, immediate:u64, bit:u64) -> u64:
    if operation == 1:
        return allocate_variable(scratch)
    if operation == 2:
        return 3 ^ ((immediate >> bit) & 1)
    if operation == 11:
        condition = load_token(scratch, 32 + 128 * left)
        first = load_token(scratch, 32 + 128 * right + 2 * bit)
        second = load_token(scratch, 32 + 128 * immediate + 2 * bit)
        return logic_select(output, scratch, condition, first, second)
    a = load_token(scratch, 32 + 128 * left + 2 * bit)
    if operation == 6:
        return a ^ 1
    b = load_token(scratch, 32 + 128 * right + 2 * bit)
    if operation == 3:
        return logic_and(output, scratch, a, b)
    if operation == 4:
        return logic_or(output, scratch, a, b)
    return logic_xor(output, scratch, a, b)

def encode_wrapping_cast(scratch:mutbuf, node:u64, source:u64, width:u64, source_width:u64, signed:bool) -> u64:
    extension = 3
    if signed:
        extension = load_token(scratch, 32 + 128 * source + 2 * (source_width - 1))
    bit = 0
    while bit < width:
        digit = extension
        if bit < source_width:
            digit = load_token(scratch, 32 + 128 * source + 2 * bit)
        put_token(scratch, 32 + 128 * node + 2 * bit, digit)
        bit = bit + 1
    return 1

def ordered_comparison(output:mutbuf, scratch:mutbuf, source:readbuf, operation:u64, left:u64, right:u64) -> u64:
    # LT, LE, GT, GE are respectively a<b, not b<a, b<a, not a<b.
    form = operation & 3
    signed = operation >= 16
    width = node_width(source, left)
    if form == 1 or form == 2:
        swapped = left
        left = right
        right = swapped
    bit = 0
    lower_less = 3
    while bit < width:
        a = load_token(scratch, 32 + 128 * left + 2 * bit)
        b = load_token(scratch, 32 + 128 * right + 2 * bit)
        if signed and bit + 1 == width:
            a = a ^ 1
            b = b ^ 1
        if a != b:
            current_less = logic_and(output, scratch, a ^ 1, b)
            mismatch = logic_xor(output, scratch, a, b)
            if current_less == 0 or mismatch == 0:
                return 0
            lower_if_equal = logic_and(output, scratch, mismatch ^ 1, lower_less)
            if lower_if_equal == 0:
                return 0
            lower_less = logic_or(output, scratch, current_less, lower_if_equal)
            if lower_less == 0:
                return 0
        bit = bit + 1
    return lower_less ^ (form & 1)

def logic_select(output:mutbuf, scratch:mutbuf, condition:u64, first:u64, second:u64) -> u64:
    if first == second or condition == 2:
        return first
    if condition == 3:
        return second
    a = logic_and(output, scratch, condition, first)
    b = logic_and(output, scratch, condition ^ 1, second)
    if a == 0 or b == 0:
        return 0
    return logic_or(output, scratch, a, b)

def encode_sum(output:mutbuf, scratch:mutbuf, node:u64, left:u64, right:u64, width:u64, operation:u64) -> u64:
    # Literal 2 is true and 3 false. For subtraction, add the complement
    # of the right operand with incoming carry one; drop the high carry.
    carry = 3
    complement = 0
    flag_only = operation >= 22
    if operation == 10 or (flag_only and (operation & 1) == 1):
        carry = 2
        complement = 1
    bit = 0
    while bit < width:
        a = load_token(scratch, 32 + 128 * left + 2 * bit)
        b = load_token(scratch, 32 + 128 * right + 2 * bit) ^ complement
        parity = logic_xor(output, scratch, a, b)
        if parity == 0:
            return 0
        if operation < 22:
            digit = logic_xor(output, scratch, parity, carry)
            if digit == 0:
                return 0
            put_token(scratch, 32 + 128 * node + 2 * bit, digit)
        bit = bit + 1
        if bit < width or flag_only:
            next_carry = carry_after_digit(output, scratch, a, b, parity, carry)
            if next_carry == 0:
                return 0
            if flag_only and bit == width:
                overflow = next_carry ^ complement
                if operation >= 24:
                    overflow = logic_xor(output, scratch, carry, next_carry)
                    if overflow == 0:
                        return 0
                put_token(scratch, 32 + 128 * node, overflow)
            carry = next_carry
    return 1

def carry_after_digit(output:mutbuf, scratch:mutbuf, a:u64, b:u64, parity:u64, carry:u64) -> u64:
    generate = logic_and(output, scratch, a, b)
    propagate = logic_and(output, scratch, parity, carry)
    if generate == 0 or propagate == 0:
        return 0
    return logic_or(output, scratch, generate, propagate)

def encode_variable_shift(output:mutbuf, scratch:mutbuf, node:u64, left:u64, right:u64,
                          width:u64, operation:u64) -> u64:
    row = 32 + 128 * node
    value = 32 + 128 * left
    keys = 32 + 128 * right
    leftward = operation == WORD_VARIABLE_SHL
    fill = 3
    if operation == WORD_ARITHMETIC_SHR:
        fill = load_token(scratch, value + 2 * (width - 1))
    bit = 0
    while bit < width:
        put_token(scratch, row + 2 * bit, load_token(scratch, value + 2 * bit))
        bit = bit + 1
    power = 1
    stage = 0
    while power < width:
        enabled = load_token(scratch, keys + 2 * stage)
        if shift_stage(output, scratch, row, width, power, enabled, leftward, fill) == 0:
            return 0
        power = power * 2
        stage = stage + 1
    # In-range stages already implement the extended word. A remaining
    # high count bit forces every result bit to the extension bit.
    high = 3
    while stage < width:
        high = logic_or(output, scratch, high, load_token(scratch, keys + 2 * stage))
        if high == 0:
            return 0
        stage = stage + 1
    bit = 0
    while bit < width:
        at = row + 2 * bit
        token = logic_select(output, scratch, high, fill, load_token(scratch, at))
        if token == 0:
            return 0
        put_token(scratch, at, token)
        bit = bit + 1
    return 1

def shift_stage(output:mutbuf, scratch:mutbuf, row:u64, width:u64, power:u64,
                enabled:u64, leftward:bool, fill:u64) -> u64:
    # Visit opposite to displacement so an in-place stage never reads a
    # token it already wrote. Vacated bits use the supplied word extension.
    position = 0
    while position < width:
        bit = choose(leftward, width - position - 1, position)
        shifted = fill
        if leftward:
            if bit >= power:
                shifted = load_token(scratch, row + 2 * (bit - power))
        elif bit + power < width:
            shifted = load_token(scratch, row + 2 * (bit + power))
        at = row + 2 * bit
        token = logic_select(output, scratch, enabled, shifted, load_token(scratch, at))
        if token == 0:
            return 0
        put_token(scratch, at, token)
        position = position + 1
    return 1

def encode_division(output:mutbuf, scratch:mutbuf, result:u64, left:u64, right:u64,
                    width:u64, quotient:bool) -> u64:
    # Unsigned restoring division. Keep the extra bit separately: a carry
    # from shifting the remainder makes subtraction unconditional.
    row = CIRCUIT_DIVISION_TEMP
    bit = 0
    while bit < width:
        put_token(scratch, row + 2 * bit, 3)
        bit = bit + 1
    incoming = width
    while incoming > 0:
        incoming = incoming - 1
        high = load_token(scratch, row + 2 * (width - 1))
        digit = load_token(scratch, left + 2 * incoming)
        carry = division_trial(output, scratch, right, width, digit)
        if carry == 0:
            return 0
        subtract = logic_or(output, scratch, high, carry)
        if subtract == 0:
            return 0
        if quotient:
            put_token(scratch, result + 2 * incoming, subtract)
        if division_restore(output, scratch, width, subtract) == 0:
            return 0
    if quotient == False:
        bit = 0
        while bit < width:
            put_token(scratch, result + 2 * bit, load_token(scratch, row + 2 * bit))
            bit = bit + 1
    return 1

def division_trial(output:mutbuf, scratch:mutbuf, divisor_row:u64, width:u64, digit:u64) -> u64:
    bit = 0
    carry = 2
    while bit < width:
        at = CIRCUIT_DIVISION_TEMP + 2 * bit
        old = load_token(scratch, at)
        put_token(scratch, at, digit)
        divisor = load_token(scratch, divisor_row + 2 * bit) ^ 1
        parity = logic_xor(output, scratch, digit, divisor)
        if parity == 0:
            return 0
        trial = logic_xor(output, scratch, parity, carry)
        if trial == 0:
            return 0
        put_token(scratch, at + 128, trial)
        carry = carry_after_digit(output, scratch, digit, divisor, parity, carry)
        if carry == 0:
            return 0
        digit = old
        bit = bit + 1
    return carry

def division_restore(output:mutbuf, scratch:mutbuf, width:u64, subtract:u64) -> u64:
    bit = 0
    while bit < width:
        at = CIRCUIT_DIVISION_TEMP + 2 * bit
        remainder = logic_select(output, scratch, subtract, load_token(scratch, at + 128), load_token(scratch, at))
        if remainder == 0:
            return 0
        put_token(scratch, at, remainder)
        bit = bit + 1
    return 1

def encode_signed_division(output:mutbuf, scratch:mutbuf, node:u64, left:u64, right:u64,
                           width:u64, quotient:bool) -> u64:
    left_word = 32 + 128 * left
    right_word = 32 + 128 * right
    result = 32 + 128 * node
    left_sign = load_token(scratch, left_word + 2 * (width - 1))
    right_sign = load_token(scratch, right_word + 2 * (width - 1))
    magnitude = CIRCUIT_SIGNED_MAGNITUDES
    divisor = magnitude + 128
    if conditional_negation(output, scratch, magnitude, left_word, width, left_sign) == 0:
        return 0
    if conditional_negation(output, scratch, divisor, right_word, width, right_sign) == 0:
        return 0
    if encode_division(output, scratch, result, magnitude, divisor, width, quotient) == 0:
        return 0
    negative = left_sign
    if quotient:
        negative = logic_xor(output, scratch, left_sign, right_sign)
        if negative == 0:
            return 0
    return conditional_negation(output, scratch, result, result, width, negative)

def conditional_negation(output:mutbuf, scratch:mutbuf, result:u64, source:u64, width:u64, negative:u64) -> u64:
    # Conditional two's complement: flip all bits, then add the same sign bit.
    carry = negative
    bit = 0
    while bit < width:
        digit = logic_xor(output, scratch, load_token(scratch, source + 2 * bit), negative)
        if digit == 0:
            return 0
        value = logic_xor(output, scratch, digit, carry)
        if value == 0:
            return 0
        put_token(scratch, result + 2 * bit, value)
        carry = logic_and(output, scratch, digit, carry)
        if carry == 0:
            return 0
        bit = bit + 1
    return 1

def encode_product(output:mutbuf, scratch:mutbuf, node:u64, left:u64, right:u64, width:u64) -> u64:
    return accumulate_product(output, scratch, 32 + 128 * node, left, right, width, width)

def accumulate_product(output:mutbuf, scratch:mutbuf, destination:u64, left:u64, right:u64,
                       width:u64, extent:u64) -> u64:
    # Low products use the ordinary word row; checked products retain
    # twice as many bits in scratch for comparison with the signed limit.
    bit = 0
    while bit < extent:
        put_token(scratch, destination + 2 * bit, 3)
        bit = bit + 1
    row = 0
    while row < width:
        factor = load_token(scratch, 32 + 128 * right + 2 * row)
        if factor != 3:
            carry = 3
            bit = row
            while bit < extent:
                a = load_token(scratch, destination + 2 * bit)
                b = 3
                if bit - row < width:
                    b = logic_and(output, scratch, factor, load_token(scratch, 32 + 128 * left + 2 * (bit - row)))
                if b == 0:
                    return 0
                parity = logic_xor(output, scratch, a, b)
                if parity == 0:
                    return 0
                digit = logic_xor(output, scratch, parity, carry)
                if digit == 0:
                    return 0
                put_token(scratch, destination + 2 * bit, digit)
                bit = bit + 1
                if bit < extent:
                    carry = carry_after_digit(output, scratch, a, b, parity, carry)
                    if carry == 0:
                        return 0
        row = row + 1
    return 1

def encode_product_limit(output:mutbuf, scratch:mutbuf, node:u64, left:u64, right:u64,
                         limit:u64, width:u64) -> u64:
    # Division and this full product never run at the same time; both
    # need two word rows. The full product keeps all high bits.
    row = CIRCUIT_DIVISION_TEMP
    if accumulate_product(output, scratch, row, left, right, width, width * 2) == 0:
        return 0
    above = 3
    bit = 0
    while bit < width * 2:
        product = load_token(scratch, row + 2 * bit)
        bound = 3
        if bit < width:
            bound = load_token(scratch, 32 + 128 * limit + 2 * bit)
        changed = logic_xor(output, scratch, product, bound)
        if changed == 0:
            return 0
        above = logic_select(output, scratch, changed, product, above)
        if above == 0:
            return 0
        bit = bit + 1
    put_token(scratch, 32 + 128 * node, above)
    return 1

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


# Workspace: node count and graph controls in the first 128 bytes, currently
# projected returns at 128, the retained left observation at 256, block offsets
# at 512 and incoming guards at 1536. Local typed slots begin at 2560; incoming
# parameter values use 128 disjoint 2 KiB rows from 4608.
PROJECTION = '''
def project_artifact_circuit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    capacity = length(o)
    workspace = length(w)
    if size < 88 or capacity < PROJECTION_OUTPUT or workspace < PROJECTION_WORKSPACE:
        return TOO_LARGE
    inputs = read64(s, 8)
    machine = read64(s, 16)
    core = read64(s, 24)
    if inputs > 6 or machine < inputs or core < inputs or machine > CIRCUIT_NODES or core > CIRCUIT_NODES:
        return TOO_LARGE
    base = 88 + 40 * machine
    signed = read64(s, 72)
    if signed > 1 or size != base + 40 * core:
        return TOO_LARGE
    machine_valid = valid_word_graph(s, 88, machine)
    core_valid = valid_word_graph(s, base, core)
    if machine_valid == 0 or core_valid == 0:
        return TOO_LARGE
    if p_artifact_graph(s, o, w, 88, machine, inputs, True) == 0:
        return TOO_LARGE
    actual = p_artifact_observation(s, w, 88, machine, 32, 64)
    machine_abort = p_artifact_observation(s, w, 88, machine, 80, 1)
    if actual == 65535 or machine_abort == 65535:
        return TOO_LARGE
    if p_artifact_graph(s, o, w, base, core, inputs, False) == 0:
        return TOO_LARGE
    return p_artifact_observations(s, o, w, base, core, actual, signed == 1, machine_abort)

def p_artifact_graph(s:readbuf, o:mutbuf, w:mutbuf, base:u64, count:u64, inputs:u64, machine:bool) -> u64:
    index = 0
    while index < inputs:
        row = base + 40 * index
        width = read64(s, row + 8)
        if read64(s, row) != 1:
            return 0
        node = index
        if machine:
            if width != 64:
                return 0
            node = p_append_node(o, w, 1, width, 0, 0, 0)
        elif width < 64:
            node = p_node(o, w, 26, width, index, 0, 0)
        write64(w, 270336 + 8 * index, node)
        index = index + 1
    # p_node folds constant Boolean relations into these protocol nodes.
    if machine:
        write64(w, 32, p_node(o, w, 2, 1, 0, 0, 1))
        write64(w, 40, p_node(o, w, 2, 1, 0, 0, 0))
    while index < count:
        row = base + 40 * index
        # All source rows were validated with their own ABI and node base.
        node = p_clone_bound_word(s, o, w, row, index, True)
        if node >= CIRCUIT_NODES:
            return 0
        write64(w, 270336 + 8 * index, node)
        index = index + 1
    return 1

def p_artifact_observation(s:readbuf, w:mutbuf, base:u64, count:u64, field:u64, width:u64) -> u64:
    node = read64(s, field)
    if node >= count:
        return 65535
    observed = word_graph_width(s, base, node)
    if width != 0 and observed != width:
        return 65535
    return read_stack(w, 270336 + 8 * node)

def p_artifact_observations(s:readbuf, o:mutbuf, w:mutbuf, base:u64, core:u64, actual:u64, signed:bool, machine_abort:u64) -> u32:
    known = p_artifact_observation(s, w, base, core, 40, 1)
    expected = p_artifact_observation(s, w, base, core, 48, 1)
    trap = p_artifact_observation(s, w, base, core, 56, 8)
    value = p_artifact_observation(s, w, base, core, 64, 0)
    if known == 65535 or expected == 65535 or trap == 65535 or value == 65535:
        return TOO_LARGE
    if read_stack(o, 40 + 40 * value) < 64:
        value = p_node(o, w, choose(signed, 31, 30), 64, value, 0, 0)
    no_trap = p_node(o, w, 2, 8, 0, 0, 0)
    if machine_abort != read_stack(w, 40):
        # Core retains its detailed trap code in its own proof. An ELF call
        # to abort observes only whether there was a normal return. Both
        # projections set the return word to zero on their abort terminals.
        trap = p_artifact_abort(o, w, trap, no_trap)
        no_trap = machine_abort
    nodes = read_stack(w, 0)
    if nodes > CIRCUIT_NODES:
        return TOO_LARGE
    at = 32 + 40 * nodes
    write64(o, 0, CIRCUIT_REQUEST)
    write64(o, 8, nodes)
    write64(o, 16, 3)
    write64(o, 24, 0)
    write64(o, at, known)
    write64(o, at + 8, expected)
    write64(o, at + 16, trap)
    write64(o, at + 24, no_trap)
    write64(o, at + 32, value)
    write64(o, at + 40, actual)
    return at + 48

def p_artifact_abort(o:mutbuf, w:mutbuf, tag:u64, zero:u64) -> u64:
    row = 32 + 40 * tag
    if read_stack(o, row) == 11 and read_stack(o, row + 32) == zero:
        first = read_stack(o, row + 24)
        if read_stack(o, 32 + 40 * first) == 2 and first != zero:
            return read_stack(o, row + 16)
    return p_node(o, w, 8, 1, tag, zero, 0)

def p_machine_low_word(o:mutbuf, w:mutbuf, node:u64, width:u64) -> u64:
    # Each word operand points backward. Project the fixed prefix in order
    # rather than using the machine stack to walk a shared expression DAG.
    if width != 1 and width != 8 and width != 16 and width != 32:
        return p_node(o, w, 26, width, node, 0, 0)
    index = 0
    while index <= node:
        value = p_machine_low_node(o, w, index, width)
        write64(w, 273408 + 8 * index, value)
        index = index + 1
    return read_stack(w, 273408 + 8 * node)

def p_machine_low_node(o:mutbuf, w:mutbuf, node:u64, width:u64) -> u64:
    row = 32 + 40 * node
    original_width = read_stack(o, row + 8)
    if width > original_width:
        return 65535
    if width == original_width:
        return node
    op = read_stack(o, row)
    immediate = read_stack(o, row + 32)
    if op == 2:
        return p_node(o, w, 2, width, 0, 0, immediate & word_mask(width))
    left = read_stack(w, 273408 + 8 * read_stack(o, row + 16))
    if op == 30 or op == 31 or (op == 26 and immediate == 0):
        if left != 65535:
            return left
    # Projection to low bits is a homomorphism for these operations only.
    if op == 6:
        return p_node(o, w, op, width, left, 0, 0)
    if op == 3 or op == 4 or op == 5 or (width > 1 and (op == 9 or op == 10 or op == 32)):
        right = read_stack(w, 273408 + 8 * read_stack(o, row + 24))
        swap = op != 10 and left > right
        return p_node(o, w, op, width, choose(swap, right, left), choose(swap, left, right), 0)
    return p_node(o, w, 26, width, node, 0, 0)

def p_artifact_word(o:mutbuf, w:mutbuf, op:u64, width:u64, a:u64, b:u64, c:u64) -> u64:
    if op == 11:
        predicate = 32 + 40 * a
        if read_stack(o, predicate) == 6:
            return p_node(o, w, 11, width, read_stack(o, predicate + 16), c, b)
    if (op == 3 or op == 4 or op == 5 or op == 9 or op == 32 or op == WORD_PRODUCT_EXCEEDS) and a > b:
        swap = a
        a = b
        b = swap
    if op == WORD_VARIABLE_SHL or op == WORD_VARIABLE_SHR or op == WORD_ARITHMETIC_SHR:
        right = 32 + 40 * b
        if read_stack(o, right) == 2:
            shift = read_stack(o, right + 32)
            if shift == 0:
                return a
            left = 32 + 40 * a
            previous = read_stack(o, left)
            previous_shift = read_stack(o, left + 24)
            if op != WORD_VARIABLE_SHL and shift < width and previous == WORD_VARIABLE_SHL and previous_shift == b:
                low = p_machine_low_word(o, w, read_stack(o, left + 16), width - shift)
                if low >= CIRCUIT_NODES:
                    return CIRCUIT_NODES
                ext = choose(op == WORD_ARITHMETIC_SHR, 31, 30)
                return p_node(o, w, ext, width, low, 0, 0)
    return p_node(o, w, op, width, a, b, c)

def project_graphs(s:readbuf, o:mutbuf, w:mutbuf, calls:bool) -> u32:
    if length(s) > PROJECTION_INPUT_LIMIT or length(o) < PROJECTION_OUTPUT or length(w) < PROJECTION_WORKSPACE:
        return TOO_LARGE
    mode = read64(s, 8)
    inputs = read64(s, 16)
    outputs = read64(s, 24)
    origin = 32
    if calls:
        origin = 40
    if mode < 1 or mode > 4 or inputs > SUMMARIZED_CALL_INPUTS or outputs > CIRCUIT_RETURNS or length(s) < origin + 8 * (inputs + outputs):
        return TOO_LARGE
    if mode == 2 and outputs + 2 > CIRCUIT_RETURNS:
        return TOO_LARGE
    if mode == 3 and calls == False:
        return TOO_LARGE
    if mode == 4 and (calls or outputs != 1 or read64(s, origin + 8 * inputs) != 1):
        return TOO_LARGE
    tail = length(s)
    if calls:
        tail = read64(s, 32)
        if tail < origin + 8 * (inputs + outputs) or tail > length(s):
            return TOO_LARGE
    write64(w, 72, origin)
    write64(w, 120, tail)
    write64(w, 0, 0)
    write64(w, 8, mode)
    write64(w, 16, inputs)
    write64(w, 24, outputs)
    i = 0
    while i < inputs + outputs:
        typ = read64(s, origin + 8 * i)
        if p_width(typ) == 0:
            return TOO_LARGE
        if i < inputs:
            # Fixed unit nodes keep parameter positions without adding an
            # input bit. Append rather than intern to keep every index.
            operation = choose(typ == PROJECT_UNIT_TYPE, 2, 1)
            p_append_node(o, w, operation, p_width(typ), 0, 0, 0)
        i = i + 1
    yes = p_node(o, w, 2, 1, 0, 0, 1)
    no = p_node(o, w, 2, 1, 0, 0, 0)
    write64(w, 32, yes)
    write64(w, 40, no)
    cursor = origin + 8 * (inputs + outputs)
    cursor = p_function(s, o, w, cursor)
    if cursor == 0:
        return TOO_LARGE
    if mode == 2:
        write64(w, 256, read_stack(w, 56))
        write64(w, 264, read_stack(w, 64))
        i = 0
        while i < outputs:
            write64(w, 272 + 8 * i, read_stack(w, 128 + 8 * i))
            i = i + 1
        cursor = p_function(s, o, w, cursor)
        if cursor == 0:
            return TOO_LARGE
    if cursor != tail:
        return TOO_LARGE
    both = read_stack(w, 64)
    pairs = 1
    if mode == 2:
        both = p_logic(o, w, 3, both, read_stack(w, 264))
        pairs = outputs + 2
    over_bound = no
    if mode == 4:
        over_bound = p_logic(o, w, 3, read_stack(w, 80), read_stack(w, 128))
        pairs = 2
    nodes = read_stack(w, 0)
    if nodes > CIRCUIT_NODES:
        return TOO_LARGE
    if mode == 3:
        return write_scalar_summary(s, o, w, nodes, inputs, origin)
    at = 32 + 40 * nodes
    write64(o, 0, CIRCUIT_REQUEST)
    write64(o, 8, nodes)
    write64(o, 16, pairs)
    write64(o, 24, 0)
    write64(o, at, both)
    write64(o, at + 8, yes)
    if mode == 4:
        write64(o, at + 16, over_bound)
        write64(o, at + 24, no)
    if mode == 2:
        write64(o, at + 16, read_stack(w, 256))
        write64(o, at + 24, read_stack(w, 56))
        i = 0
        while i < outputs:
            write64(o, at + 32 + 16 * i, read_stack(w, 272 + 8 * i))
            write64(o, at + 40 + 16 * i, read_stack(w, 128 + 8 * i))
            i = i + 1
    return at + 16 * pairs

def write_scalar_summary(s:readbuf, o:mutbuf, w:mutbuf, nodes:u64, inputs:u64, origin:u64) -> u64:
    at = 32 + 40 * nodes
    outputs = read_stack(w, 24)
    write64(o, 8, nodes)
    write64(o, 16, inputs)
    write64(o, at, read_stack(w, 64))      # known outcome
    write64(o, at + 8, read_stack(w, 80))  # normal return
    write64(o, at + 16, read_stack(w, 56)) # selected first trap tag
    types = at + 32
    if outputs == 1:
        write64(o, 0, SCALAR_SUMMARY)
        write64(o, 24, read64(s, origin + 8 * inputs))
        write64(o, at + 24, read_stack(w, 128))
    else:
        write64(o, 0, TUPLE_SUMMARY)
        write64(o, 24, outputs)
        types = at + 24
        index = 0
        while index < outputs:
            write64(o, types, read64(s, origin + 8 * (inputs + index)))
            write64(o, types + 8, read_stack(w, 128 + 8 * index))
            types = types + 16
            index = index + 1
    i = 0
    while i < inputs:
        write64(o, types + 8 * i, read64(s, origin + 8 * i))
        i = i + 1
    return types + 8 * inputs

def p_width(typ:u64) -> u64:
    if typ == PROJECT_UNIT_TYPE:
        return 1
    bits = typ & 127
    if typ > 192 or (bits == 1 and typ != 1):
        return 0
    if bits == 1 or bits == 8 or bits == 16 or bits == 32 or bits == 64:
        return bits
    return 0

def p_node(o:mutbuf, w:mutbuf, op:u64, width:u64, a:u64, b:u64, c:u64) -> u64:
    index = read_stack(w, 0)
    if (op == 9 or op == 10) and a < index and b < index and index <= CIRCUIT_NODES:
        left = 32 + 40 * a
        right = 32 + 40 * b
        if read_stack(o, left) == 2 and read_stack(o, right) == 2:
            if read_stack(o, left + 8) == width and read_stack(o, right + 8) == width:
                av = read_stack(o, left + 32)
                bv = read_stack(o, right + 32)
                c = choose(op == 9, av + bv, av - bv) & word_mask(width)
                a = 0
                b = 0
                op = 2
        if op != 2 and read_stack(o, left + 8) == width and read_stack(o, right + 8) == width:
            reduced = p_cancel_wrapping(o, op, a, b)
            if reduced < index and read_stack(o, 40 + 40 * reduced) == width:
                return reduced
    if op > 2 and index <= CIRCUIT_NODES:
        folded = p_fold(o, op, width, a, b, c, index)
        if folded < CIRCUIT_NODES:
            return folded
        if folded != 65535:
            # The helper's non-node form encodes a Boolean literal.
            return choose(folded == 65536, read_stack(w, 40), read_stack(w, 32))
    # A repeated word expression has the same value everywhere in this DAG.
    # Input nodes are intentionally never shared: their order binds models.
    if op != 1 and index <= CIRCUIT_NODES:
        previous = 0
        while previous < index:
            at = 32 + 40 * previous
            if read_stack(o, at) == op and read_stack(o, at + 8) == width and read_stack(o, at + 16) == a:
                if read_stack(o, at + 24) == b and read_stack(o, at + 32) == c:
                    return previous
            previous = previous + 1
    return p_append_node(o, w, op, width, a, b, c)

def p_cancel_wrapping(o:mutbuf, op:u64, a:u64, b:u64) -> u64:
    # These identities are exact in the same bounded word ring. A checked
    # operation has already recorded its separate ordered trap predicate.
    left = 32 + 40 * a
    right = 32 + 40 * b
    if op == 10 and read_stack(o, left) == 9:
        x = read_stack(o, left + 16)
        y = read_stack(o, left + 24)
        if x == b:
            return y
        if y == b:
            return x
    if op == 9:
        if read_stack(o, left) == 10 and read_stack(o, left + 24) == b:
            return read_stack(o, left + 16)
        if read_stack(o, right) == 10 and read_stack(o, right + 24) == a:
            return read_stack(o, right + 16)
    return 65535

def p_append_node(o:mutbuf, w:mutbuf, op:u64, width:u64, a:u64, b:u64, c:u64) -> u64:
    index = read_stack(w, 0)
    if index >= CIRCUIT_NODES:
        write64(w, 0, CIRCUIT_NODES + 1)
        return CIRCUIT_NODES
    at = 32 + 40 * index
    write64(o, at, op)
    write64(o, at + 8, width)
    write64(o, at + 16, a)
    write64(o, at + 24, b)
    write64(o, at + 32, c)
    write64(w, 0, index + 1)
    return index

def p_fold(o:mutbuf, op:u64, width:u64, a:u64, b:u64, c:u64, nodes:u64) -> u64:
    if a >= nodes:
        return 65535
    left = 32 + 40 * a
    left_width = read_stack(o, left + 8)
    left_known = read_stack(o, left) == 2
    av = read_stack(o, left + 32)
    if op == 6 and left_width == 1 and width == 1 and left_known:
        return 65536 + (av ^ 1)
    if b >= nodes:
        return 65535
    right = 32 + 40 * b
    right_width = read_stack(o, right + 8)
    right_known = read_stack(o, right) == 2
    bv = read_stack(o, right + 32)
    if op == 11 and left_width == 1 and right_width == width and c < nodes:
        if read_stack(o, 40 + 40 * c) == width:
            if b == c:
                return b
            if left_known:
                return choose(av == 1, b, c)
    if width != 1 or left_width != right_width:
        return 65535
    if (op == 3 or op == 4) and left_width == 1:
        literal = op - 3
        if a == b:
            return a
        if left_known:
            return choose(av == literal, a, b)
        if right_known:
            return choose(bv == literal, b, a)
        if (read_stack(o, left) == 6 and read_stack(o, left + 16) == b) or (read_stack(o, right) == 6 and read_stack(o, right + 16) == a):
            return 65536 + literal
    if op == 7 or op == 8:
        if a == b or (left_known and right_known):
            return 65536 + choose((a == b or av == bv) == (op == 7), 1, 0)
    if op >= 12 and op < 20 and left_known and right_known:
        return 65536 + evaluate_word_order(av, bv, left_width, op)
    return 65535

def p_logic(o:mutbuf, w:mutbuf, op:u64, a:u64, b:u64) -> u64:
    return p_node(o, w, op, 1, a, b, 0)

def p_function(s:readbuf, o:mutbuf, w:mutbuf, start:u64) -> u64:
    tail = read_stack(w, 120)
    if start > tail or tail - start < 24:
        return 0
    extent = read64(s, start)
    count = read64(s, start + 8)
    entry = read64(s, start + 16)
    if extent < 24 or extent > tail - start or count == 0 or count > 128 or entry >= count:
        return 0
    end = start + extent
    cursor = start + 24
    index = 0
    while index < count:
        if end - cursor < 64:
            return 0
        params = read64(s, cursor)
        ops = read64(s, cursor + 8)
        argc = read64(s, cursor + 40)
        argd = read64(s, cursor + 56)
        if params > CIRCUIT_NODES or ops > CIRCUIT_NODES - params or argc > CIRCUIT_NODES or argd > CIRCUIT_NODES:
            return 0
        size = 64 + 8 * (params + argc + argd) + 48 * ops
        if size > end - cursor:
            return 0
        write64(w, 512 + 8 * index, cursor)
        write64(w, 1536 + 8 * index, 65535)
        cursor = cursor + size
        index = index + 1
    if cursor != end:
        return 0
    inputs = read_stack(w, 16)
    origin = read_stack(w, 512 + 8 * entry)
    if read64(s, origin) != inputs:
        return 0
    write64(w, 1536 + 8 * entry, read_stack(w, 32))
    types = read_stack(w, 72)
    i = 0
    while i < inputs:
        typ = read64(s, types + 8 * i)
        if read64(s, origin + 64 + 8 * i) != typ:
            return 0
        write64(w, 4608 + 2048 * entry + 8 * i, i)
        i = i + 1
    write64(w, 64, read_stack(w, 40))
    write64(w, 80, read_stack(w, 40))
    if read_stack(w, 8) != 1:
        write64(w, 56, p_node(o, w, 2, 8, 0, 0, 0))
        i = 0
        while i < read_stack(w, 24):
            typ = read64(s, types + 8 * (inputs + i))
            write64(w, 128 + 8 * i, p_node(o, w, 2, p_width(typ), 0, 0, 0))
            i = i + 1
    index = 0
    while index < count:
        inherited = read_stack(w, 1536 + 8 * index)
        if inherited != 65535:
            if p_block(s, o, w, index, count, inherited) == 0:
                return 0
        index = index + 1
    return end

def p_block(s:readbuf, o:mutbuf, w:mutbuf, index:u64, count:u64, inherited:u64) -> u64:
    row = read_stack(w, 512 + 8 * index)
    params = read64(s, row)
    ops = read64(s, row + 8)
    write64(w, 88, read_stack(w, 40))
    write64(w, 96, params)
    write64(w, 104, read_stack(w, 40))
    write64(w, 112, inherited)
    i = 0
    while i < params:
        typ = read64(s, row + 64 + 8 * i)
        if p_width(typ) == 0:
            return 0
        node = read_stack(w, 4608 + 2048 * index + 8 * i)
        write64(w, 2560 + 8 * i, typ * 65536 + node)
        i = i + 1
    cursor = row + 64 + 8 * params
    i = 0
    while i < ops:
        consumed = p_operation(s, o, w, cursor + 48 * i, ops - i)
        if consumed == 0:
            return 0
        i = i + consumed
    cursor = cursor + 48 * ops
    reach = p_flush_faults(o, w)
    mode = read_stack(w, 8)
    kind = read64(s, row + 16)
    control = read64(s, row + 24)
    argc = read64(s, row + 40)
    argd = read64(s, row + 56)
    if kind == 1:
        if argd != 0 or argc != read_stack(w, 24):
            return 0
        p_complete(o, w, reach)
        if mode == 3 or mode == 4:
            write64(w, 80, p_logic(o, w, 4, reach, read_stack(w, 80)))
        if mode != 1:
            i = 0
            while i < argc:
                value = p_var(w, read64(s, cursor + 8 * i))
                typ = read64(s, read_stack(w, 72) + 8 * (read_stack(w, 16) + i))
                if value >> 16 != typ:
                    return 0
                previous = read_stack(w, 128 + 8 * i)
                selected = p_node(o, w, 11, p_width(typ), reach, value & 65535, previous)
                write64(w, 128 + 8 * i, selected)
                i = i + 1
        return 1
    if kind == 2:
        if argc != 0 or argd != 0 or control == 0 or control > PROJECT_TRAP_CODE_MAX:
            return 0
        if mode == 4:
            p_complete(o, w, reach)
        elif mode != 1:
            p_trap(o, w, reach, control)
        return 1
    if kind == 3:
        if argd != 0:
            return 0
        return p_edge(s, o, w, read64(s, row + 32), count * 256 + index, cursor, argc, reach)
    if kind == 4:
        flag = p_var(w, control)
        if flag >> 16 != 1:
            return 0
        yes = p_logic(o, w, 3, reach, flag & 65535)
        no_edge = p_logic(o, w, 3, reach, p_logic(o, w, 6, flag & 65535, 0))
        if p_edge(s, o, w, read64(s, row + 32), count * 256 + index, cursor, argc, yes) == 0:
            return 0
        return p_edge(s, o, w, read64(s, row + 48), count * 256 + index, cursor + 8 * argc, argd, no_edge)
    return 0

def p_flush_faults(o:mutbuf, w:mutbuf) -> u64:
    reach = read_stack(w, 112)
    no = read_stack(w, 40)
    fault = read_stack(w, 88)
    if fault == no:
        return reach
    mode = read_stack(w, 8)
    if mode == 4:
        p_complete(o, w, p_logic(o, w, 3, reach, fault))
    elif mode != 1:
        division = read_stack(w, 104)
        overflow = fault
        if division != no:
            overflow = p_logic(o, w, 3, fault, p_logic(o, w, 6, division, 0))
            p_trap(o, w, p_logic(o, w, 3, reach, division), PROJECT_DIVISION_CODE)
        p_trap(o, w, p_logic(o, w, 3, reach, overflow), PROJECT_OVERFLOW_CODE)
    write64(w, 88, no)
    write64(w, 104, no)
    return p_logic(o, w, 3, reach, p_logic(o, w, 6, fault, 0))

def p_complete(o:mutbuf, w:mutbuf, reach:u64) -> u64:
    return write64(w, 64, p_logic(o, w, 4, reach, read_stack(w, 64)))

def p_trap(o:mutbuf, w:mutbuf, reach:u64, code:u64) -> u64:
    tag = p_node(o, w, 2, 8, 0, 0, code)
    return p_trap_tag(o, w, reach, tag)

def p_trap_tag(o:mutbuf, w:mutbuf, reach:u64, tag:u64) -> u64:
    p_complete(o, w, reach)
    return write64(w, 56, p_node(o, w, 11, 8, reach, tag, read_stack(w, 56)))

def p_call(s:readbuf, o:mutbuf, w:mutbuf, instruction:u64, typ:u64, remaining:u64) -> u64:
    summary = read64(s, instruction + 16)
    arguments = read64(s, instruction + 24)
    argc = read64(s, instruction + 32)
    output_count = read64(s, instruction + 40)
    tail = read_stack(w, 120)
    if summary < tail or summary > length(s) or length(s) - summary < 56:
        return 0
    if arguments < tail or arguments > length(s) or argc > SUMMARIZED_CALL_INPUTS or argc * 8 > length(s) - arguments:
        return 0
    count = read64(s, summary + 8)
    if count < argc or count > CIRCUIT_NODES or read64(s, summary + 16) != argc:
        return 0
    end = summary + 32 + 40 * count
    table = end + 32
    legacy_scalar = output_count == 0 and typ != 0
    if legacy_scalar:
        if p_width(typ) == 0 or read64(s, summary) != SCALAR_SUMMARY or read64(s, summary + 24) != typ:
            return 0
    else:
        if output_count == 1 or output_count > CIRCUIT_RETURNS or output_count > remaining:
            return 0
        if read64(s, summary) != TUPLE_SUMMARY or read64(s, summary + 24) != output_count:
            return 0
        table = end + 24 + 16 * output_count
    if table > length(s) or 8 * argc > length(s) - table:
        return 0
    if p_rebind_summary(s, o, w, summary, arguments, argc, count, table) == 0:
        return 0
    known = p_summary_result(s, w, summary, read64(s, end), 1)
    normal = p_summary_result(s, w, summary, read64(s, end + 8), 1)
    tag = p_summary_result(s, w, summary, read64(s, end + 16), 8)
    if known == 65535 or normal == 65535 or tag == 65535:
        return 0
    # Commit earlier caller traps once. Only normal callee returns reach
    # later operations, regardless of the number of result bindings.
    reached = p_flush_faults(o, w)
    if read_stack(w, 8) != 1:
        failed = p_logic(o, w, 3, known, p_logic(o, w, 6, normal, 0))
        p_trap_tag(o, w, p_logic(o, w, 3, reached, failed), tag)
    write64(w, 112, p_logic(o, w, 3, reached, normal))
    if legacy_scalar:
        value = p_summary_result(s, w, summary, read64(s, end + 24), p_width(typ))
        if value == 65535:
            return 0
        return p_bind(w, typ, value)
    if output_count == 0:
        return 1
    return p_bind_call_tuple(s, w, instruction, summary, end + 24, output_count)

def p_bind_call_tuple(s:readbuf, w:mutbuf, instruction:u64, summary:u64, results:u64, count:u64) -> u64:
    index = 0
    while index < count:
        row = instruction + 48 * index
        if index != 0:
            if read64(s, row) != PROJECT_CALL_RESULT:
                return 0
            if (read64(s, row + 16) | read64(s, row + 24) | read64(s, row + 32) | read64(s, row + 40)) != 0:
                return 0
        typ = read64(s, row + 8)
        width = p_width(typ)
        if width == 0 or read64(s, results + 16 * index) != typ:
            return 0
        node = p_summary_result(s, w, summary, read64(s, results + 16 * index + 8), width)
        if node == 65535:
            return 0
        p_bind(w, typ, node)
        index = index + 1
    return count

def p_summary_result(s:readbuf, w:mutbuf, summary:u64, node:u64, width:u64) -> u64:
    if node >= read64(s, summary + 8) or read64(s, summary + 40 + 40 * node) != width:
        return 65535
    return read_stack(w, 270336 + 8 * node)

def p_rebind_summary(s:readbuf, o:mutbuf, w:mutbuf, summary:u64, arguments:u64, argc:u64, count:u64, types:u64) -> u64:
    index = 0
    while index < argc:
        value = p_var(w, read64(s, arguments + 8 * index))
        typ = read64(s, types + 8 * index)
        at = summary + 32 + 40 * index
        operation = choose(typ == PROJECT_UNIT_TYPE, 2, 1)
        if typ == 0 or value >> 16 != typ or read64(s, at) != operation or read64(s, at + 8) != p_width(typ):
            return 0
        if (read64(s, at + 16) | read64(s, at + 24) | read64(s, at + 32)) != 0:
            return 0
        write64(w, 270336 + 8 * index, value & 65535)
        index = index + 1
    while index < count:
        node = p_clone_bound_word(s, o, w, summary + 32 + 40 * index, index, False)
        if node == 65535:
            return 0
        write64(w, 270336 + 8 * index, node)
        index = index + 1
    return 1

def p_clone_bound_word(s:readbuf, o:mutbuf, w:mutbuf, at:u64, index:u64, artifact:bool) -> u64:
    op = read64(s, at)
    width = read64(s, at + 8)
    limit = choose(artifact, WORD_SIGNED_REM, WORD_PRODUCT_EXCEEDS)
    if op < 2 or op > limit or width == 0 or width > 64:
        return 65535
    count = word_arguments(op)
    a = read64(s, at + 16)
    b = read64(s, at + 24)
    c = read64(s, at + 32)
    if count > 0:
        if a >= index:
            return 65535
        a = read_stack(w, 270336 + 8 * a)
    if count > 1:
        if b >= index:
            return 65535
        b = read_stack(w, 270336 + 8 * b)
    if count == 3:
        if c >= index:
            return 65535
        c = read_stack(w, 270336 + 8 * c)
    if artifact:
        return p_artifact_word(o, w, op, width, a, b, c)
    return p_node(o, w, op, width, a, b, c)

def p_var(w:mutbuf, index:u64) -> u64:
    if index >= read_stack(w, 96):
        return 0
    return read_stack(w, 2560 + 8 * index)

def p_edge(s:readbuf, o:mutbuf, w:mutbuf, target:u64, extent:u64, cursor:u64, argc:u64, reach:u64) -> u64:
    # The caller supplies block count in the high bits and source index in the low byte.
    if target >= (extent >> 8) or target <= (extent & 255):
        return 0
    row = read_stack(w, 512 + 8 * target)
    if read64(s, row) != argc:
        return 0
    prior = read_stack(w, 1536 + 8 * target)
    merge = reach
    if prior != 65535:
        merge = p_logic(o, w, 4, reach, prior)
    i = 0
    while i < argc:
        value = p_var(w, read64(s, cursor + 8 * i))
        typ = read64(s, row + 64 + 8 * i)
        if value == 0 or (value >> 16) != typ:
            return 0
        node = value & 65535
        slot = 4608 + 2048 * target + 8 * i
        if prior != 65535:
            node = p_node(o, w, 11, p_width(typ), reach, node, read_stack(w, slot))
        write64(w, slot, node)
        i = i + 1
    write64(w, 1536 + 8 * target, merge)
    return 1

def p_operation(s:readbuf, o:mutbuf, w:mutbuf, row:u64, remaining:u64) -> u64:
    role = read64(s, row)
    typ = read64(s, row + 8)
    if role == PROJECT_DIRECT_CALL:
        return p_call(s, o, w, row, typ, remaining)
    width = p_width(typ)
    if width == 0:
        return 0
    if role == 2:
        literal = read64(s, row + 40) & word_mask(width)
        return p_bind(w, typ, p_node(o, w, 2, width, 0, 0, literal))
    if (role < 3 or role > 15) and role != 20 and role != 22 and role != 23 and (role < 32 or role > PROJECT_CHECKED_MUL):
        return 0
    first = p_var(w, read64(s, row + 16))
    if first == 0:
        return 0
    a = first & 65535
    signed = (first >> 23) & 1
    if role == PROJECT_CHECKED_CAST:
        origin = first >> 16
        if width < 8 or p_width(origin) < 8:
            return 0
        return p_checked_cast(o, w, origin, typ, a)
    if role == 6 or role == 20:
        if role == 20:
            role = role + signed
        return p_bind(w, typ, p_node(o, w, role, width, a, 0, 0))
    if role == 33:
        boundary = p_node(o, w, 2, width, 0, 0, signed << (width - 1))
        condition = 8 - signed
        p_fault(o, w, p_logic(o, w, condition, a, boundary))
        zero = p_node(o, w, 2, width, 0, 0, 0)
        return p_bind(w, typ, p_node(o, w, 10, width, zero, a, 0))
    second = p_var(w, read64(s, row + 24))
    if second == 0:
        return 0
    b = second & 65535
    if role >= PROJECT_CHECKED_SHL:
        if width < 8 or (first >> 16) != typ or (second >> 16) != typ:
            return 0
        if role == PROJECT_CHECKED_DIV or role == PROJECT_CHECKED_REM:
            return p_checked_division(o, w, typ, role, a, b)
        if role == PROJECT_CHECKED_MUL:
            return p_checked_mul(o, w, typ, a, b)
        return p_checked_shift(o, w, typ, role, a, b)
    third = 0
    if role == 11:
        last = p_var(w, read64(s, row + 32))
        if last == 0:
            return 0
        third = last & 65535
    if role >= 12 and role <= 15:
        role = role + 4 * signed
    if role == 22 or role == 23:
        p_fault(o, w, p_logic(o, w, role + 2 * signed, a, b))
        role = role - 13
    return p_bind(w, typ, p_node(o, w, role, width, a, b, third))

def p_checked_shift(o:mutbuf, w:mutbuf, typ:u64, role:u64, a:u64, count:u64) -> u64:
    width = p_width(typ)
    limit = p_node(o, w, 2, width, 0, 0, width)
    # An unsigned comparison rejects both a count >= width and a signed
    # negative count, whose word representation has its high bit set.
    p_fault(o, w, p_logic(o, w, 15, count, limit))

    signed_right = role == PROJECT_CHECKED_SHR and (typ & 128) != 0
    padding = 0
    if signed_right:
        sign = p_node(o, w, 26, 1, a, 0, width - 1)
        padding = p_node(o, w, 31, width, sign, 0, 0)
        a = p_node(o, w, 5, width, a, padding, 0)
    shift = 28
    if role == PROJECT_CHECKED_SHR:
        shift = 29
    power = 1
    bit = 0
    while power < width:
        enabled = p_node(o, w, 26, 1, count, 0, bit)
        displaced = p_node(o, w, shift, width, a, 0, power)
        a = p_node(o, w, 11, width, enabled, displaced, a)
        power = power * 2
        bit = bit + 1
    if signed_right:
        # Complementing a negative input before and after a zero-fill right
        # shift produces the required sign fill; positive words are unchanged.
        a = p_node(o, w, 5, width, a, padding, 0)
    return p_bind(w, typ, a)

def p_fault(o:mutbuf, w:mutbuf, fault:u64) -> u64:
    return write64(w, 88, p_logic(o, w, 4, read_stack(w, 88), fault))

def p_checked_division(o:mutbuf, w:mutbuf, typ:u64, role:u64, a:u64, b:u64) -> u64:
    width = p_width(typ)
    zero = p_node(o, w, 2, width, 0, 0, 0)
    by_zero = p_logic(o, w, 7, b, zero)
    mode = read_stack(w, 8)
    if mode == 2 or mode == 3:
        prior = read_stack(w, 88)
        first_zero = p_logic(o, w, 3, by_zero, p_logic(o, w, 6, prior, 0))
        write64(w, 104, p_logic(o, w, 4, read_stack(w, 104), first_zero))
    p_fault(o, w, by_zero)
    operation = choose(role == PROJECT_CHECKED_DIV, WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM)
    if (typ & 128) == 0:
        return p_bind(w, typ, p_node(o, w, operation, width, a, b, 0))

    minimum = p_node(o, w, 2, width, 0, 0, 1 << (width - 1))
    minus_one = p_node(o, w, 2, width, 0, 0, word_mask(width))
    minimum_input = p_logic(o, w, 7, a, minimum)
    minus_one_input = p_logic(o, w, 7, b, minus_one)
    p_fault(o, w, p_logic(o, w, 3, minimum_input, minus_one_input))

    sign_a = p_node(o, w, 26, 1, a, 0, width - 1)
    sign_b = p_node(o, w, 26, 1, b, 0, width - 1)
    magnitude_a = p_magnitude(o, w, width, zero, sign_a, a)
    magnitude_b = p_magnitude(o, w, width, zero, sign_b, b)
    result = p_node(o, w, operation, width, magnitude_a, magnitude_b, 0)
    sign = sign_a
    if operation == WORD_UNSIGNED_DIV:
        sign = p_logic(o, w, 5, sign_a, sign_b)
    return p_bind(w, typ, p_node(o, w, 11, width, sign, p_node(o, w, 10, width, zero, result, 0), result))

def p_magnitude(o:mutbuf, w:mutbuf, width:u64, zero:u64, sign:u64, value:u64) -> u64:
    negative = p_node(o, w, 10, width, zero, value, 0)
    return p_node(o, w, 11, width, sign, negative, value)

def p_checked_mul(o:mutbuf, w:mutbuf, typ:u64, a:u64, b:u64) -> u64:
    width = p_width(typ)
    limit = p_node(o, w, 2, width, 0, 0, word_mask(width))
    magnitude_a = a
    magnitude_b = b
    if (typ & 128) != 0:
        negative = 1 << (width - 1)
        zero = p_node(o, w, 2, width, 0, 0, 0)
        sign_a = p_node(o, w, 26, 1, a, 0, width - 1)
        sign_b = p_node(o, w, 26, 1, b, 0, width - 1)
        magnitude_a = p_magnitude(o, w, width, zero, sign_a, a)
        magnitude_b = p_magnitude(o, w, width, zero, sign_b, b)
        negative_limit = p_node(o, w, 2, width, 0, 0, negative)
        positive_limit = p_node(o, w, 2, width, 0, 0, negative - 1)
        sign = p_logic(o, w, 5, sign_a, sign_b)
        limit = p_node(o, w, 11, width, sign, negative_limit, positive_limit)
    p_fault(o, w, p_node(o, w, WORD_PRODUCT_EXCEEDS, 1, magnitude_a, magnitude_b, limit))
    return p_bind(w, typ, p_node(o, w, 32, width, a, b, 0))

def p_checked_cast(o:mutbuf, w:mutbuf, origin:u64, target:u64, value:u64) -> u64:
    source_width = p_width(origin)
    target_width = p_width(target)
    source_signed = origin >> 7
    target_signed = target >> 7
    # Compare in the source type. Emit only bounds that can exclude
    # a source value, so every threshold fits its comparison type.
    if source_signed != 0:
        if target_signed == 0:
            zero = p_node(o, w, 2, source_width, 0, 0, 0)
            p_fault(o, w, p_logic(o, w, 16, value, zero))
        elif target_width < source_width:
            below = word_mask(source_width) ^ ((1 << (target_width - 1)) - 1)
            lower = p_node(o, w, 2, source_width, 0, 0, below)
            p_fault(o, w, p_logic(o, w, 16, value, lower))
    source_positive = source_width - source_signed
    target_positive = target_width - target_signed
    if target_positive < source_positive:
        upper = p_node(o, w, 2, source_width, 0, 0, (1 << target_positive) - 1)
        p_fault(o, w, p_logic(o, w, 14 + 4 * source_signed, value, upper))
    return p_bind(w, target, p_node(o, w, 20 + source_signed, target_width, value, 0, 0))

def p_bind(w:mutbuf, typ:u64, node:u64) -> u64:
    index = read_stack(w, 96)
    write64(w, 2560 + 8 * index, typ * 65536 + node)
    write64(w, 96, index + 1)
    return 1
'''


FEEDBACK = '''
def plan_feedback(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 48 or length(w) < FEEDBACK_WORKSPACE:
        return INVALID
    blocks = read64(s, 8)
    entry = read64(s, 16)
    maximum = read64(s, 24)
    block_budget = read64(s, 32)
    op_budget = read64(s, 40)
    if blocks == 0 or blocks > FEEDBACK_BLOCK_LIMIT or entry >= blocks or maximum > FEEDBACK_LAYER_LIMIT:
        return INVALID
    if block_budget == 0 or block_budget > FEEDBACK_BLOCK_LIMIT or op_budget > FEEDBACK_OP_LIMIT:
        return INVALID
    if length(s) != 48 + 24 * blocks or length(o) < 40 + 16 * block_budget:
        return INVALID
    node = 0
    while node < blocks:
        at = 48 + 24 * node
        a = read64(s, at)
        b = read64(s, at + 8)
        if (a >= blocks and a != FEEDBACK_BLOCK_LIMIT) or (b >= blocks and b != FEEDBACK_BLOCK_LIMIT):
            return INVALID
        if (a == FEEDBACK_BLOCK_LIMIT and b != FEEDBACK_BLOCK_LIMIT) or read64(s, at + 16) > FEEDBACK_OP_LIMIT:
            return INVALID
        store(w, node, 0)
        node = node + 1
    edge = discover_feedback(s, w, blocks, entry)
    if edge == 0 or edge == 65535:
        return feedback_reply(o, 1, 0, 0, 0)
    if block_budget < 2:
        return feedback_reply(o, 2, 0, 0, 0)
    return feedback_states(s, o, w, entry, maximum, edge, block_budget, op_budget)

def discover_feedback(s:readbuf, w:mutbuf, blocks:u64, entry:u64) -> u64:
    edge = 0
    root = 0
    while root <= blocks:
        node = entry
        if root != 0:
            node = root - 1
        if byte(w, node) == 0:
            edge = visit_feedback(s, w, node, edge)
            if edge == 65535:
                return edge
        root = root + 1
    return edge

def visit_feedback(s:readbuf, w:mutbuf, root:u64, edge:u64) -> u64:
    depth = 1
    store(w, root, 1)
    write64(w, 256, root)
    write64(w, 264, 0)
    while depth > 0:
        frame = 256 + 16 * (depth - 1)
        node = read_stack(w, frame)
        choice = read_stack(w, frame + 8)
        if choice == 2:
            store(w, node, 2)
            depth = depth - 1
        else:
            child = ordered_feedback_child(s, node, choice)
            write64(w, frame + 8, choice + 1)
            if child != FEEDBACK_BLOCK_LIMIT:
                color = byte(w, child)
                if color == 0:
                    store(w, child, 1)
                    write64(w, frame + 16, child)
                    write64(w, frame + 24, 0)
                    depth = depth + 1
                elif color == 1:
                    if edge != 0:
                        return 65535
                    edge = 1 + node * FEEDBACK_BLOCK_LIMIT + child
    return edge

def ordered_feedback_child(s:readbuf, node:u64, choice:u64) -> u64:
    at = 48 + 24 * node
    a = read64(s, at)
    b = read64(s, at + 8)
    if choice == 0:
        return choose(a < b, a, b)
    if a == b:
        return FEEDBACK_BLOCK_LIMIT
    return choose(a > b, a, b)

def feedback_states(s:readbuf, o:mutbuf, w:mutbuf, entry:u64, maximum:u64, edge:u64,
                    block_budget:u64, op_budget:u64) -> u32:
    # Keep one byte per (layer, original block); output doubles as the queue.
    index = 0
    while index < (maximum + 1) * FEEDBACK_BLOCK_LIMIT:
        store(w, 4096 + index, 0)
        index = index + 1
    store(w, 4096 + entry, 1)
    write64(o, 40, entry)
    write64(o, 48, 0)
    total = 1
    index = 0
    ops = 0
    while index < total:
        node = read_stack(o, 40 + 16 * index)
        layer = read_stack(o, 48 + 16 * index)
        at = 48 + 24 * node
        ops = ops + read64(s, at + 16)
        if index + 2 > block_budget or ops + index + 2 > op_budget:
            return feedback_reply(o, 2, 0, 0, 0)
        total = append_feedback_states(s, o, w, node, layer, maximum, edge, total, block_budget)
        if total == 0:
            return feedback_reply(o, 3, 0, 0, 0)
        index = index + 1
    source = (edge - 1) >> 7
    target = (edge - 1) & (FEEDBACK_BLOCK_LIMIT - 1)
    return feedback_reply(o, 0, source, target, total)

def append_feedback_states(s:readbuf, o:mutbuf, w:mutbuf, node:u64, layer:u64, maximum:u64,
                           edge:u64, total:u64, block_budget:u64) -> u64:
    arm = 0
    while arm < 2:
        child = read64(s, 48 + 24 * node + 8 * arm)
        if child != FEEDBACK_BLOCK_LIMIT:
            following = layer + choose(1 + node * FEEDBACK_BLOCK_LIMIT + child == edge, 1, 0)
            if following <= maximum:
                seen = 4096 + following * FEEDBACK_BLOCK_LIMIT + child
                if byte(w, seen) == 0:
                    if total + 2 > block_budget:
                        return 0
                    store(w, seen, 1)
                    write64(o, 40 + 16 * total, child)
                    write64(o, 48 + 16 * total, following)
                    total = total + 1
        arm = arm + 1
    return total

def feedback_reply(o:mutbuf, status:u64, source:u64, target:u64, states:u64) -> u32:
    write64(o, 0, FEEDBACK_REPLY)
    write64(o, 8, status)
    write64(o, 16, source)
    write64(o, 24, target)
    write64(o, 32, states)
    return 40 + 16 * states
'''


def source_program():
    constants = dict(GUARDED_CIRCUIT_REQUEST=GUARDED_CIRCUIT_REQUEST, CIRCUIT_REQUEST=CIRCUIT_REQUEST,
                     CIRCUIT_CAPACITY=CIRCUIT_CAPACITY, CIRCUIT_NODES=CIRCUIT_NODES,
                     PROJECT_CHECKED_SHL=PROJECT_CHECKED_SHL, PROJECT_CHECKED_SHR=PROJECT_CHECKED_SHR,
                     PROJECT_CHECKED_DIV=PROJECT_CHECKED_DIV, PROJECT_CHECKED_REM=PROJECT_CHECKED_REM,
                     PROJECT_CHECKED_CAST=PROJECT_CHECKED_CAST,
                     PROJECT_CHECKED_MUL=PROJECT_CHECKED_MUL,
                     PROJECT_DIRECT_CALL=PROJECT_DIRECT_CALL, PROJECT_CALL_RESULT=PROJECT_CALL_RESULT,
                     PROJECT_UNIT_TYPE=PROJECT_UNIT_TYPE,
                     WORD_UNSIGNED_DIV=WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM=WORD_UNSIGNED_REM,
                     WORD_PRODUCT_EXCEEDS=WORD_PRODUCT_EXCEEDS,
                     WORD_VARIABLE_SHL=WORD_VARIABLE_SHL, WORD_VARIABLE_SHR=WORD_VARIABLE_SHR,
                     WORD_ARITHMETIC_SHR=WORD_ARITHMETIC_SHR, WORD_SIGNED_DIV=WORD_SIGNED_DIV,
                     WORD_SIGNED_REM=WORD_SIGNED_REM, CIRCUIT_DIVISION_TEMP=CIRCUIT_DIVISION_TEMP,
                     CIRCUIT_SIGNED_MAGNITUDES=CIRCUIT_SIGNED_MAGNITUDES,
                     CIRCUIT_GATES_OFFSET=CIRCUIT_GATES_OFFSET, CIRCUIT_GATE_SLOTS=CIRCUIT_GATE_SLOTS,
                     CIRCUIT_RETURNS=CIRCUIT_RETURNS, CIRCUIT_WORKSPACE=CIRCUIT_WORKSPACE,
                     WORD_WITNESS_REQUEST=WORD_WITNESS_REQUEST,
                     WORD_TABLE_REQUEST=WORD_TABLE_REQUEST, WORD_TABLE_INPUT_BITS=WORD_TABLE_INPUT_BITS,
                     WORD_TABLE_WORK_LIMIT=WORD_TABLE_WORK_LIMIT,
                     GRAPH_PROJECTION_REQUEST=GRAPH_PROJECTION_REQUEST,
                     ARTIFACT_PROJECTION_REQUEST=ARTIFACT_PROJECTION_REQUEST,
                     CALL_PROJECTION_REQUEST=CALL_PROJECTION_REQUEST, SCALAR_SUMMARY=SCALAR_SUMMARY,
                     TUPLE_SUMMARY=TUPLE_SUMMARY, SUMMARIZED_CALL_INPUTS=SUMMARIZED_CALL_INPUTS,
                     FEEDBACK_REQUEST=FEEDBACK_REQUEST, FEEDBACK_REPLY=FEEDBACK_REPLY,
                     FEEDBACK_BLOCK_LIMIT=FEEDBACK_BLOCK_LIMIT, FEEDBACK_OP_LIMIT=FEEDBACK_OP_LIMIT,
                     FEEDBACK_LAYER_LIMIT=FEEDBACK_LAYER_LIMIT, FEEDBACK_WORKSPACE=FEEDBACK_WORKSPACE,
                     PROJECTION_INPUT_LIMIT=PROJECTION_INPUT_LIMIT, PROJECTION_OUTPUT=PROJECTION_OUTPUT,
                     PROJECTION_WORKSPACE=PROJECTION_WORKSPACE, PROJECT_OVERFLOW_CODE=_CORE_TRAP_TAGS['overflow'],
                     PROJECT_DIVISION_CODE=_CORE_TRAP_TAGS['division_by_zero'],
                     PROJECT_TRAP_CODE_MAX=len(_CORE_TRAP_TAGS),
                     TOO_LARGE=0xfffffffc, BATCH_REQUEST=BATCH_REQUEST, SPARSE_REQUEST=SPARSE_REQUEST,
                     WATCHED_REQUEST=WATCHED_REQUEST, WATCH_HEADS=WATCH_HEADS,
                     WATCH_ROWS=WATCH_ROWS, WATCH_ROW_BYTES=WATCH_ROW_BYTES,
                     LEARNED_CLAUSES=LEARNED_CLAUSES, LEARNED_ENTRIES=LEARNED_ENTRIES,
                     LEARNING_REQUEST=LEARNING_REQUEST, RESTART_REQUEST=RESTART_REQUEST, LEARNING_BYTES=LEARNING_BYTES,
                     LEARNING_REASONS=LEARNING_REASONS, LEARNING_SEEN=LEARNING_SEEN,
                     LEARNING_TEMP=LEARNING_TEMP, LEARNING_TOKENS=LEARNING_TOKENS,
                     LEARNING_ORDER=LEARNING_ORDER, LEARNING_HEAD=LEARNING_HEAD, LEARNING_PHASE=LEARNING_PHASE,
                     SPARSE_REPLY=SPARSE_REPLY, SPARSE_CLAUSES=SPARSE_CLAUSES,
                     SPARSE_ENTRIES=SPARSE_ENTRIES, SPARSE_VARIABLES=SPARSE_VARIABLES,
                     SPARSE_WORKSPACE=SPARSE_WORKSPACE, DECISIONS=SPARSE_VARIABLES * 3,
                     TRAIL=SPARSE_VARIABLES, REQUEST=REQUEST, REPLY=REPLY, CLAUSE_LIMIT=CLAUSE_LIMIT,
                     STEP_LIMIT=STEP_LIMIT, WORD_MASK=WORD_MASK, WORKSPACE=WORKSPACE, INVALID=0xfffffffd)
    code = BODY + PROJECTION + FEEDBACK
    for name, value in constants.items():
        code = code.replace(name, str(value))
    return render_assembly(document(code, 'cnf'))


if __name__ == '__main__':
    SOURCE.write_text(source_program())
