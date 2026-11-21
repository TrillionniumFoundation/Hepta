"""Author one standalone HIA artifact obligation, including exact native replay."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    CIRCUIT_CAPACITY, CIRCUIT_NODES, CIRCUIT_REQUEST, CIRCUIT_WORKSPACE, LEARNED_CLAUSES, LEARNING_BYTES,
    LEARNING_REQUEST, RESTART_REQUEST, SAT, SEARCH_PLAN_REQUEST, SPARSE_CLAUSES, SPARSE_ENTRIES,
    SPARSE_REPLY, SPARSE_REQUEST, SPARSE_VARIABLES, SPARSE_WORKSPACE, STEP_LIMIT, UNKNOWN, UNSAT,
    WATCH_ROW_BYTES, WATCH_ROWS, WORD_TABLE_REQUEST, WORD_WITNESS_REQUEST,
)
from hepta.hia_core_proof_wire_native import OBLIGATION_REQUEST, OBLIGATION_SOLVER_REQUEST, OBLIGATION_WITNESS_REQUEST
from tools.generate_hia_safe_core_binder import document as transport_document, shared_transport

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_obligation.hepta'
REQUEST_MAGIC = int.from_bytes(b'HIAPROQ1', 'little')
RESPONSE_MAGIC = int.from_bytes(b'HIAPROR1', 'little')
WORK_OFFSET = 17002496
WORK_LIMIT = 8 << 20
OUTPUT_LIMIT = 221184
REQUEST_HEAD = 24
RESPONSE_HEAD = 80
CIRCUIT = 8192
PLAN_REPLY = 32768
FRAME = 65536
PACKED = 327680
FORMULA = 524288
SPARSE_FRAME = 786432
ANSWER = 1048576
ENCODE_WORK = 1114112
CHECK_WORK = 1376256
TABLE_ANSWER = 1409024
SEARCH_WORK = 2 << 20
CIRCUIT_LIMIT = 64 + 40 * CIRCUIT_NODES
SPARSE_RESULT_LIMIT = 32 + (SPARSE_VARIABLES >> 3)
WITNESS_RESULT_LIMIT = CIRCUIT_LIMIT + 8 * CIRCUIT_NODES
TOO_LARGE = 0xfffffffc

SOURCE = '''
def prove(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORK_LIMIT or length(o) != OUTPUT_LIMIT:
        return 0
    phase = get(w, 0)
    if phase == 0:
        return admit(s, w)
    if clock_ns(w) >= get(w, 128):
        return 0
    if phase <= 4:
        return encode_plan(w, phase)
    if phase <= 8:
        return find_model(w, phase)
    if phase == 13:
        return table_start(w)
    if phase <= 12:
        return result(o, w, phase)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < REQUEST_HEAD or length(s) > REQUEST_HEAD + 80 + 40 * CIRCUIT_NODES:
        return 0
    if uint(s, 0, 8) != REQUEST_MAGIC:
        return 0
    role = uint(s, 8, 8)
    budget = uint(s, 16, 8)
    extent = length(s) - REQUEST_HEAD
    if role > 4 or budget < 100 or budget > 60000:
        return 0
    if role < 3 and extent != 0 or role >= 3 and extent < 80:
        return 0
    put(w, 72, role)
    put(w, 128, clock_ns(w) + 1000000 * budget)
    put(w, FRAME, OBLIGATION_REQUEST)
    put(w, FRAME + 8, role)
    put(w, FRAME + 16, extent)
    put(w, FRAME + 24, 0)
    copy_input(s, w, REQUEST_HEAD, FRAME + 32, extent)
    return next(w, 1, 2, WORK_OFFSET + FRAME, 32 + extent, CIRCUIT, CIRCUIT_LIMIT, PLAN, 1)

def encode_plan(w:mutbuf, phase:u64) -> u64:
    size = get(w, 64)
    if phase == 1:
        if size < 32 or size > CIRCUIT_LIMIT or get(w, CIRCUIT) != CIRCUIT_REQUEST:
            return 0
        nodes = get(w, CIRCUIT + 8)
        if nodes > CIRCUIT_NODES:
            return 0
        put(w, 136, size)
        return control(w, 2, 0, remaining(w), CIRCUIT, size, 0, PACKED, 32 + 16 * CIRCUIT_NODES)
    if phase == 2:
        if size < 32 or size > 32 + 16 * CIRCUIT_NODES or get(w, PACKED) != SEARCH_PLAN_REQUEST:
            return 0
        return next(w, 3, 1, WORK_OFFSET + PACKED, size, PLAN_REPLY, 32, PLAN, 1)
    if phase == 3:
        if size != 32 or get(w, PLAN_REPLY) != SEARCH_PLAN_REQUEST:
            return 0
        steps = get(w, PLAN_REPLY + 8)
        if steps == 0 or steps > STEP_LIMIT:
            return 0
        return control(w, 4, 1, 0, CIRCUIT, get(w, 136), 32, PACKED, CIRCUIT_LIMIT)
    if size != get(w, 136) or get(w, PACKED) != CIRCUIT_REQUEST:
        return 0
    return encode(w, 5, size)

def find_model(w:mutbuf, phase:u64) -> u64:
    size = get(w, 64)
    if phase == 5 or phase == 7:
        if phase == 5 and size == TOO_LARGE:
            put(w, 144, 1)
            return control(w, 6, 3, 0, CIRCUIT, get(w, 136), 32, PACKED, CIRCUIT_CAPACITY)
        if formula_ok(w, size) == 0:
            return 0
        put(w, 152, size)
        return control(w, 8, 2, 0, FORMULA, size, 32, SPARSE_FRAME, CIRCUIT_CAPACITY)
    if phase == 6:
        if size < 32 or size > CIRCUIT_LIMIT or get(w, PACKED) != CIRCUIT_REQUEST:
            return 0
        return encode(w, 7, size)
    if size != get(w, 152):
        return 0
    return search(w, size)

def result(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    size = get(w, 64)
    if phase == 9:
        return decision(o, w, size)
    if phase == 10:
        if size < get(w, 136) or size > WITNESS_RESULT_LIMIT or get(w, PACKED) != WORD_WITNESS_REQUEST:
            return 0
        put(w, 160, size - get(w, 136))
        return next(w, 11, 1, WORK_OFFSET + PACKED, size, TABLE_ANSWER, 32,
                    CHECK_WORK, check_extent(get(w, CIRCUIT + 8)))
    if phase == 11:
        if size != 1:
            return 0
        return emit(o, w, SAT)
    if size != 32 or get(w, TABLE_ANSWER) != WORD_TABLE_REQUEST:
        return 0
    if get(w, TABLE_ANSWER + 8) != UNSAT or get(w, TABLE_ANSWER + 16) != 0:
        return 0
    expected = table_assignments(w)
    if expected == 0 or get(w, TABLE_ANSWER + 24) != expected:
        return 0
    put(w, 176, expected)
    return emit(o, w, UNSAT)

def decision(o:mutbuf, w:mutbuf, size:u64) -> u64:
    variables = get(w, FORMULA + 8)
    model = get(w, ANSWER + 8)
    cost = get(w, ANSWER + 24)
    lease = get(w, PLAN_REPLY + 8)
    if get(w, ANSWER) != SPARSE_REPLY or get(w, ANSWER + 16) != variables or cost > lease:
        return 0
    put(w, 168, cost)
    if model == SAT and size == 32 + ((variables + 7) >> 3):
        return check_model(w, size)
    if model == UNSAT and size == 32:
        return emit(o, w, UNSAT)
    if model == UNKNOWN and size == 32 and cost == lease and get(w, 144) == 1:
        return control(w, 13, 4, remaining(w), CIRCUIT, get(w, 136), 0, PACKED, CIRCUIT_CAPACITY)
    return 0

def table_start(w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 40 or size > CIRCUIT_LIMIT + 8 or get(w, PACKED) != WORD_TABLE_REQUEST:
        return 0
    nodes = get(w, PACKED + 8)
    if nodes > CIRCUIT_NODES:
        return 0
    put(w, 184, size - 8)
    return next(w, 12, 1, WORK_OFFSET + PACKED, size, TABLE_ANSWER, 32,
                CHECK_WORK, check_extent(nodes))

def check_model(w:mutbuf, size:u64) -> u64:
    circuit = get(w, 136)
    mapping = 32 + 128 * get(w, CIRCUIT + 8)
    put(w, FRAME, OBLIGATION_WITNESS_REQUEST)
    put(w, FRAME + 8, circuit)
    put(w, FRAME + 16, size)
    put(w, FRAME + 24, mapping)
    copy_work(w, CIRCUIT, FRAME + 32, circuit)
    copy_work(w, ANSWER, FRAME + 32 + circuit, size)
    copy_work(w, ENCODE_WORK, FRAME + 32 + circuit + size, mapping)
    return next(w, 10, 2, WORK_OFFSET + FRAME, 32 + circuit + size + mapping,
                PACKED, WITNESS_RESULT_LIMIT, PLAN, 1)

def search(w:mutbuf, size:u64) -> u64:
    mode = get(w, SPARSE_FRAME)
    clauses = get(w, FORMULA + 16)
    extent = SPARSE_WORKSPACE
    if mode == LEARNING_REQUEST or mode == RESTART_REQUEST:
        extent = WATCH_ROWS + 2 * (clauses + LEARNED_CLAUSES) * WATCH_ROW_BYTES + LEARNING_BYTES
    elif mode != SPARSE_REQUEST:
        return 0
    return next(w, 9, 1, WORK_OFFSET + SPARSE_FRAME, size, ANSWER, SPARSE_RESULT_LIMIT,
                SEARCH_WORK, extent)

def encode(w:mutbuf, phase:u64, size:u64) -> u64:
    fill_range(w, ENCODE_WORK, CIRCUIT_WORKSPACE, 0)
    return next(w, phase, 1, WORK_OFFSET + PACKED, size, FORMULA, CIRCUIT_CAPACITY,
                ENCODE_WORK, CIRCUIT_WORKSPACE)

def formula_ok(w:mutbuf, size:u64) -> u64:
    if size < 40 or size > CIRCUIT_CAPACITY or get(w, FORMULA) != SPARSE_REQUEST:
        return 0
    variables = get(w, FORMULA + 8)
    clauses = get(w, FORMULA + 16)
    entries = get(w, FORMULA + 32)
    if variables > SPARSE_VARIABLES or clauses > SPARSE_CLAUSES or entries > SPARSE_ENTRIES:
        return 0
    if get(w, FORMULA + 24) != get(w, PLAN_REPLY + 8) or size != 40 + 2 * entries:
        return 0
    return 1

def table_assignments(w:mutbuf) -> u64:
    count = get(w, PACKED + 8)
    bits = 0
    i = 0
    while i < count:
        at = PACKED + 32 + 40 * i
        if get(w, at) == 1:
            bits = bits + get(w, at + 8)
        i = i + 1
    if bits > 16:
        return 0
    return 1 << bits

def check_extent(count:u64) -> u64:
    return choose(count > 0, count * 8, 8)

def control(w:mutbuf, turn:u64, phase:u64, parameter:u64, at:u64, size:u64, plan:u64,
            answer:u64, limit:u64) -> u64:
    put(w, FRAME, OBLIGATION_SOLVER_REQUEST)
    put(w, FRAME + 8, phase)
    put(w, FRAME + 16, get(w, 72))
    put(w, FRAME + 24, parameter)
    copy_work(w, PLAN_REPLY, FRAME + 32, plan)
    copy_work(w, at, FRAME + 32 + plan, size)
    return next(w, turn, 2, WORK_OFFSET + FRAME, 32 + plan + size, answer, limit, PLAN, 1)

def emit(o:mutbuf, w:mutbuf, verdict:u64) -> u64:
    formula = get(w, 152)
    witness = get(w, 160)
    table = get(w, 184)
    size = RESPONSE_HEAD + formula + witness + table
    if size > length(o):
        return 0
    put(o, 0, RESPONSE_MAGIC)
    put(o, 8, get(w, 72))
    put(o, 16, verdict)
    put(o, 24, get(w, 168))
    put(o, 32, get(w, FORMULA + 8))
    put(o, 40, get(w, FORMULA + 16))
    put(o, 48, formula)
    put(o, 56, witness)
    put(o, 64, table)
    put(o, 72, get(w, 176))
    copy_output(o, w, FORMULA, RESPONSE_HEAD, formula)
    put(o, RESPONSE_HEAD + 24, 0)
    copy_output(o, w, PACKED + get(w, 136), RESPONSE_HEAD + formula, witness)
    copy_output(o, w, PACKED, RESPONSE_HEAD + formula + witness, table)
    return size

def copy_output(o:mutbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(w, source + i))
        i = i + 1
    return 0

def clock_ns(w:mutbuf) -> u64:
    return get(w, 112) * 1000000000 + get(w, 120)

def remaining(w:mutbuf) -> u64:
    return (get(w, 128) - clock_ns(w)) // 1000000
'''


def document():
    constants = {name: value for name, value in globals().items() if name.isupper() and type(value) is int}
    return transport_document(SOURCE + shared_transport(), module='safe_core_obligation', extra=constants)


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
