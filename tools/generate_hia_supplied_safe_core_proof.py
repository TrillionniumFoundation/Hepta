"""Author the sealed supplied-artifact Safe Core verifier's HIA coordinator."""
from pathlib import Path

from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly
from hepta.hia_safe_core_elf_inventory_native import REFUSAL_IDS
from tools.generate_hia_core_proof_wire import SUBJECT_HEADER, SUBJECT_MAGIC
from tools.generate_hia_safe_core_binder import (
    DIAGNOSTIC_REPLY as BIND_DIAGNOSTIC_REPLY, DIAGNOSTIC_REQUEST as BIND_DIAGNOSTIC_REQUEST,
    FRAME_MAGIC as BIND_MAGIC, OUTPUT_LIMIT as BIND_CAP, REPLY_MAGIC as BIND_REPLY,
    document as transport_document,
)
from tools.generate_hia_safe_core_machine_observe import (
    OBSERVATION_CAP as MACHINE_CAP, REQUEST_MAGIC as MACHINE_MAGIC, RESPONSE_MAGIC as MACHINE_REPLY,
)
from tools.generate_hia_safe_core_obligation import (
    OUTPUT_LIMIT as OBLIGATION_CAP, REQUEST_MAGIC as OBLIGATION_MAGIC, RESPONSE_MAGIC as OBLIGATION_REPLY,
)
from tools.generate_hia_safe_core_observations import JOIN_REQUEST
from hepta.hia_cnf_native import CIRCUIT_REQUEST, PROJECTION_INPUT_LIMIT, PROJECTION_OUTPUT, SAT, UNSAT

SOURCE_PATH = 'examples/hia_bootstrap/supplied_safe_core_proof.hepta'
REQUEST_MAGIC = int.from_bytes(b'HIAPRF01', 'little')
TYPED_REQUEST_MAGIC = int.from_bytes(b'HIAPRF02', 'little')
RECEIPT_MAGIC = int.from_bytes(b'HIAPRR01', 'little')
REGISTER_REQUEST = int.from_bytes(b'HIAPRF03', 'little')
REGISTER_RECEIPT = int.from_bytes(b'HIAPRR03', 'little')
REGISTER_MODE_SLOT = 1024
REGISTER_DEPTH_SLOT = 1032
FAILURE_MAGIC = int.from_bytes(b'HIAPRX01', 'little')
LOADER_SECTION_REFUSAL = REFUSAL_IDS['loader_section_unreviewed']
DEADLINE = 3
OUTSIDE_PROFILE = 4
INCOMPLETE = 5
TYPED_REQUEST_SLOT = 256
SIMD_ISA_SLOT = 264
SIMD_KIND_SLOT = 272
SIMD_REQUEST = int.from_bytes(b'HIASP001', 'little')
SIMD_DATA_QUERY = int.from_bytes(b'HIASMOC1', 'little')
SIMD_DETAIL_REQUEST = int.from_bytes(b'HIASP002', 'little')
SIMD_DETAIL_RECEIPT = int.from_bytes(b'HIASIMR2', 'little')
SIMD_DETAIL_SLOT = 512
SIMD_DELTA_SLOT = 520
SIMD_ORDINAL_SLOT = 528
SIMD_GUARD_SLOT = 536
SIMD_ADVANCE_SLOT = 544
SIMD_OTHER_ADVANCE_SLOT = 552
SIMD_DECREMENT_SLOT = 560
SIMD_COUNT_SLOT = 568
SIMD_RESULT_MOVE_SLOT = 576
SIMD_COUNT_MOVE_SLOT = 584
SIMD_SOLVER_PHASE = 12
SIMD_MACHINE_PHASE = 13
SIMD_SUBJECT = int.from_bytes(b'HIASIMC1', 'little')
SIMD_RECEIPT = int.from_bytes(b'HIASIMR1', 'little')
REQUEST_HEAD = 48
RECEIPT_HEAD = 464
FILE_LIMIT = 8 << 20
INPUT_LIMIT = REQUEST_HEAD + 3 * FILE_LIMIT
INPUT_CAP = ((INPUT_LIMIT + 4096) // 4096) * 4096
OUTPUT_LIMIT = 1 << 21
WORK_OFFSET = INPUT_CAP + OUTPUT_LIMIT
WORK_LIMIT = 1 << 20
HEADER = 4096
SUBJECT = 8192
BINDING = 147456
MACHINE = 221184
OBSERVATION = 245760
FRAME = 270336
OBLIGATION = 458752
DIGEST = 704512
DIGEST_WORK = 708608
NAME_LIMIT = 256
SUBJECT_CAP = SUBJECT_HEADER + PROJECTION_INPUT_LIMIT

SOURCE = '''
def prove(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) == 33554432 and length(o) == 16777216:
        put(w, 48, 262144)
        put(w, 56, 64)
        return canonical_wire(s, o, w)
    if length(o) != OUTPUT_LIMIT or length(w) != WORK_LIMIT:
        return 0
    phase = get(w, 0)
    if phase == 0:
        return admit(s, w)
    if now(w) >= get(w, 128):
        return failure(o, w, phase, DEADLINE, 0)
    if get(w, 72) != 0:
        return failure(o, w, phase, INCOMPLETE, 0)
    result = proof_step(o, w, phase)
    if result != 0:
        return result
    return failure(o, w, phase, INCOMPLETE, 0)

def proof_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase <= 3:
        return digest_inputs(o, w, phase)
    if phase == 4:
        return bind_subject(o, w)
    if phase == 5:
        return digest_text(o, w)
    if phase == 6:
        return observe_machine(o, w)
    if phase == 7:
        return join_observations(w)
    if phase == 8:
        return first_obligation(w)
    if phase == 9:
        return receive_obligation(o, w)
    if phase == 10:
        end = get(w, 224)
        span = get(w, 248)
        obj = get(w, 144)
        if get(w, REGISTER_MODE_SLOT) != 1 or get(w, 64) != 32 or end > length(o) - 72:
            return 0
        if obj < 64 or span > obj - 64:
            return 0
        put(o, end, get(w, 152))
        copy_output(o, w, DIGEST, end + 40, 32)
        return dispatch(w, 11, 6, REQUEST_HEAD + get(w, 136) + 64, span, DIGEST, 32, DIGEST_WORK, 1088)
    if phase == 11:
        end = get(w, 224)
        if get(w, 64) != 32 or end > length(o) - 72:
            return 0
        copy_output(o, w, DIGEST, end + 8, 32)
        return end + 72
    if phase == SIMD_SOLVER_PHASE:
        return receive_simd_induction(o, w)
    if phase == SIMD_MACHINE_PHASE:
        return received_simd_circuit(w)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < REQUEST_HEAD:
        return 0
    magic = uint(s, 0, 8)
    if magic != REQUEST_MAGIC and magic != TYPED_REQUEST_MAGIC and magic != SIMD_REQUEST and magic != SIMD_DETAIL_REQUEST and magic != REGISTER_REQUEST:
        return 0
    profile = uint(s, 8, 8)
    budget = uint(s, 16, 8)
    core = uint(s, 24, 8)
    obj = uint(s, 32, 8)
    final = uint(s, 40, 8)
    if magic == SIMD_REQUEST or magic == SIMD_DETAIL_REQUEST:
        put(w, SIMD_DETAIL_SLOT, choose(magic == SIMD_DETAIL_REQUEST, 1, 0))
        if profile < 1 or profile > 3:
            return 0
        put(w, SIMD_ISA_SLOT, profile)
    if profile > 6 or budget < 100 or budget > 60000:
        return 0
    if core == 0 or core > FILE_LIMIT or obj < 64 or obj > FILE_LIMIT or final < 64 or final > FILE_LIMIT:
        return 0
    if length(s) != REQUEST_HEAD + core + obj + final:
        return 0
    put(w, 128, now(w) + budget * 1000000)
    put(w, 136, core)
    put(w, 144, obj)
    put(w, 152, final)
    put(w, 160, profile)
    put(w, TYPED_REQUEST_SLOT, choose(magic == TYPED_REQUEST_MAGIC or magic == REGISTER_REQUEST, 1, 0))
    put(w, REGISTER_MODE_SLOT, choose(magic == REGISTER_REQUEST, 1, 0))
    return dispatch(w, 1, 6, REQUEST_HEAD, core, DIGEST, 32, DIGEST_WORK, 1088)

def digest_inputs(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if get(w, 64) != 32:
        return 0
    copy_output(o, w, DIGEST, 80 + 32 * (phase - 1), 32)
    core = get(w, 136)
    obj = get(w, 144)
    if phase == 1:
        return dispatch(w, 2, 6, REQUEST_HEAD + core, obj, DIGEST, 32, DIGEST_WORK, 1088)
    if phase == 2:
        return dispatch(w, 3, 6, REQUEST_HEAD + core + obj, get(w, 152), DIGEST, 32, DIGEST_WORK, 1088)
    return dispatch(w, 4, 1, REQUEST_HEAD, core, SUBJECT, SUBJECT_CAP, 0, 0)

def bind_subject(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    if get(w, SIMD_ISA_SLOT) != 0:
        if size < 25 or size > 152 or get(w, SUBJECT) != SIMD_SUBJECT:
            return 0
        shape = get(w, SUBJECT + 8)
        name = get(w, SUBJECT + 16)
        if shape < 1 or shape > 3 or name != size - 24:
            return 0
        put(w, SIMD_KIND_SLOT, shape)
        return bind_export(o, w, SUBJECT + 24, name)
    if size < SUBJECT_HEADER + 40 or size > SUBJECT_CAP or get(w, SUBJECT) != SUBJECT_MAGIC:
        return 0
    minimum = get(w, SUBJECT + 16)
    profile = get(w, 160)
    if minimum == 0 or minimum > 6:
        return 0
    if profile == 0:
        profile = choose(minimum > 2, minimum, 2)
    if profile < minimum:
        return 0
    arguments = get(w, SUBJECT + 8)
    paths = get(w, SUBJECT + 24)
    graph = get(w, SUBJECT + 32)
    name = get(w, SUBJECT + 40)
    if arguments > 6 or paths == 0 or paths > 1024 or name == 0 or name > NAME_LIMIT:
        return 0
    if graph != size - SUBJECT_HEADER or get(w, SUBJECT + 48) != 0 or get(w, SUBJECT + 56) != 0:
        return 0
    put(w, 160, profile)
    put(w, 168, graph)
    put(w, 176, arguments)
    put(w, 184, paths)
    return bind_export(o, w, SUBJECT + 64, name)

def bind_export(o:mutbuf, w:mutbuf, symbol:u64, name:u64) -> u64:
    put(o, 64, name)
    copy_output(o, w, symbol, 208, name)
    obj = get(w, 144)
    final = get(w, 152)
    put(w, HEADER, choose(get(w, TYPED_REQUEST_SLOT) == 1, BIND_DIAGNOSTIC_REQUEST, BIND_MAGIC))
    put(w, HEADER + 8, obj)
    put(w, HEADER + 16, final)
    put(w, HEADER + 24, name)
    copy_work(w, symbol, HEADER + 32, name)
    return dispatch(w, 5, 2, WORK_OFFSET + HEADER, 288, BINDING, BIND_CAP,
                    REQUEST_HEAD + get(w, 136), obj + final)

def digest_text(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    if size == 40 and get(w, BINDING) == BIND_DIAGNOSTIC_REPLY:
        if (get(w, BINDING + 8) == 2 and get(w, BINDING + 16) == LOADER_SECTION_REFUSAL
                and get(w, BINDING + 24) == 0 and get(w, BINDING + 32) == 0):
            return failure(o, w, 5, OUTSIDE_PROFILE, LOADER_SECTION_REFUSAL)
        return 0
    if size < 80 + 56 or size > BIND_CAP or get(w, BINDING) != BIND_REPLY:
        return 0
    span = get(w, BINDING + 24)
    offset = get(w, BINDING + 8)
    final = get(w, 152)
    if offset > final or span == 0 or span > final - offset:
        return 0
    put(w, 192, size)
    put(w, 240, offset)
    put(w, 248, span)
    final_start = REQUEST_HEAD + get(w, 136) + get(w, 144)
    return dispatch(w, 6, 6, final_start + offset, span, DIGEST, 32, DIGEST_WORK, 1088)

def observe_machine(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 64) != 32:
        return 0
    copy_output(o, w, DIGEST, 176, 32)
    if get(w, SIMD_ISA_SLOT) != 0:
        shape = get(w, SIMD_KIND_SLOT)
        put(w, BINDING - 8, shape)
        isa = get(w, SIMD_ISA_SLOT)
        if isa == 1:
            checked = simd_validate(w)
        elif isa == 2:
            checked = avx2_validate(w)
        else:
            checked = avx512_validate(w)
        if checked != 32 or get(w, OBSERVATION + 8) != shape or get(w, OBSERVATION + 16) != isa or get(w, OBSERVATION + 24) != get(w, 248):
            return 0
        return start_simd_induction(w)
    profile = get(w, 160)
    flags = 0
    if profile > 2:
        flags = (1 << (profile - 2)) - 1
    put(w, HEADER, MACHINE_MAGIC)
    put(w, HEADER + 8, get(w, 176))
    put(w, HEADER + 16, flags)
    return dispatch(w, 7, 3, WORK_OFFSET + HEADER, 24, MACHINE, MACHINE_CAP + 16,
                    WORK_OFFSET + BINDING, get(w, 192))

def start_simd_induction(w:mutbuf) -> u64:
    span = get(w, 248)
    text = BINDING + 80
    # One binder-owned abort relocation. Relocation offset addresses the call's
    # displacement. Read the subtraction operand from the linked text itself.
    rel = get(w, text + span + 24)
    if rel < 5 or rel + 4 > span:
        return 0
    if byte(w, text + rel - 5) != 72 or byte(w, text + rel - 4) != 131:
        return 0
    if byte(w, text + rel - 3) != 236 or byte(w, text + rel - 1) != 232:
        return 0
    delta = byte(w, text + rel - 2)
    if delta >= 128:
        return 0
    put(w, SIMD_DELTA_SLOT, delta)
    put(w, SIMD_COUNT_SLOT, 0)
    put(w, SIMD_ORDINAL_SLOT, 1)
    put(w, 224, RECEIPT_HEAD)
    return send_simd_induction(w)

def simd_immediate(w:mutbuf, at:u64, end:u64, rex:u64, modrm:u64) -> u64:
    if end - at < 4 or byte(w, at) != rex or byte(w, at + 2) != modrm:
        return 0
    op = byte(w, at + 1)
    if op == 131:
        imm = byte(w, at + 3)
        if imm == 0 or imm >= 128:
            return 0
        return (imm << 8) | 4
    if op != 129 or end - at < 7:
        return 0
    imm = get(w, at + 3) & 4294967295
    if imm == 0 or imm > 256:
        return 0
    return (imm << 8) | 7

def simd_interval_obligation(w:mutbuf, width:u64) -> u64:
    # Locate the update after its independently validated unsigned branch.
    # Extract the live pointer advances and remaining-count decrement from
    # linked text, including the second pointer for each copy.
    at = BINDING + 80
    end = at + get(w, 248)
    guard = 0
    count = 0
    while at < end:
        cmp = simd_immediate(w, at, end, 73, 250)
        step = cmp & 255
        if cmp != 0 and end - at >= step + 6:
            if byte(w, at + step) == 15 and byte(w, at + step + 1) == 130:
                guard = cmp >> 8
        if end - at >= 9 and (get(w, at) & 1099511627775) == 567201137997:
            guard = 1
        add = simd_immediate(w, at, end, 72, 199)
        if guard == width and add != 0:
            next = at + (add & 255)
            other = add
            if get(w, SIMD_KIND_SLOT) == 3:
                other = simd_immediate(w, next, end, 72, 194)
                if other == 0:
                    return 0
                next = next + (other & 255)
            dec = simd_immediate(w, next, end, 73, 234)
            if dec == 0 or count != 0:
                return 0
            put(w, SIMD_GUARD_SLOT, guard)
            put(w, SIMD_ADVANCE_SLOT, add >> 8)
            put(w, SIMD_OTHER_ADVANCE_SLOT, other >> 8)
            put(w, SIMD_DECREMENT_SLOT, dec >> 8)
            count = count + 1
        at = at + 1
    if count != 1:
        return 0
    return simd_interval_step(w, width)

def simd_endpoint_obligation(w:mutbuf, role:u64) -> u64:
    # The width codes for the second query of each pair are eight higher.
    width = 1 << (role & 7)
    if width >= (8 << get(w, SIMD_ISA_SLOT)):
        return 0
    at = BINDING + 80
    end = at + get(w, 248)
    observed = 0
    while at < end:
        extent = simd_endpoint_extent(w, at, end, width)
        if extent > 0:
            if extent > 64 or observed != 0:
                return 0
            observed = extent
        at = at + 1
    if observed == 0:
        return 0
    put(w, SIMD_DECREMENT_SLOT, observed)
    if role < 24:
        return simd_endpoint_bounds(w, width)
    return simd_endpoint_effects(w, width)

def send_machine_simd(w:mutbuf, role:u64) -> u64:
    put(w, HEADER, SIMD_DATA_QUERY)
    put(w, HEADER + 8, get(w, SIMD_ISA_SLOT))
    put(w, HEADER + 16, get(w, SIMD_KIND_SLOT))
    put(w, HEADER + 24, role)
    return dispatch(w, SIMD_MACHINE_PHASE, 3, WORK_OFFSET + HEADER, 32, FRAME, 10320,
                    WORK_OFFSET + BINDING, get(w, 192))

def received_simd_circuit(w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 120 or size > 10320 or get(w, FRAME) != CIRCUIT_REQUEST:
        return 0
    nodes = get(w, FRAME + 8)
    if nodes == 0 or nodes > 256 or size != 80 + 40 * nodes or get(w, FRAME + 16) != 3 or get(w, FRAME + 24) != 0:
        return 0
    budget = (get(w, 128) - now(w)) // 1000000
    if budget < 100:
        return 0
    put(w, HEADER, OBLIGATION_MAGIC)
    put(w, HEADER + 8, 3)
    put(w, HEADER + 16, budget)
    return dispatch(w, SIMD_SOLVER_PHASE, 5, WORK_OFFSET + HEADER, 24, OBLIGATION, OBLIGATION_CAP,
                    WORK_OFFSET + FRAME, size)

def following_data_role(isa:u64, shape:u64, role:u64) -> u64:
    if role == 40 or role == 41 or role == 42:
        return role + 1
    if role == 43:
        if shape == 3:
            return choose(isa == 1, 52, 53)
        return choose(isa == 1, choose(shape == 1, 47, 44), 44)
    if role == 44:
        return choose(isa == 1, 47, 45)
    if role == 45 or role == 46:
        return role + 1
    if role == 47:
        return choose(isa == 1, 52, 48)
    if role >= 48 and role < 51:
        return role + 1
    if role == 52:
        return choose(shape == 3, 53, 0)
    return 0

def next_simd_ordinal(w:mutbuf, role:u64) -> u64:
    isa = get(w, SIMD_ISA_SLOT)
    copy = get(w, SIMD_KIND_SLOT) == 3
    if role == 2:
        return choose(isa == 1, 3, 4)
    if role < 5:
        return role + 1
    if role == 5:
        if isa != 1 and copy:
            return 7
        return 6
    if role == 6:
        return choose(isa == 1, 31, 9)
    if role == 7:
        return 16
    if role == 9:
        return 30
    if role >= 16 and role <= 21:
        return role + 8
    if role >= 24 and role <= 29:
        widest = choose(isa == 2, 28, 29)
        return choose(role == widest, 30, role - 7)
    if role == 30 or role == 31:
        return role + 1
    if role == 32:
        return choose(isa == 1, 42, choose(copy, 42, 33))
    if role == 33:
        return 40
    if role >= 40:
        return following_data_role(isa, get(w, SIMD_KIND_SLOT), role)
    return 0

def send_simd_induction(w:mutbuf) -> u64:
    role = get(w, SIMD_ORDINAL_SLOT)
    budget = (get(w, 128) - now(w)) // 1000000
    if budget < 100:
        return 0
    delta = get(w, SIMD_DELTA_SLOT)
    if role >= 30:
        return send_machine_simd(w, role)
    if role == 1:
        if get(w, SIMD_KIND_SLOT) == 3:
            extent = simd_copy_caller(w, delta)
        else:
            extent = simd_read_caller(w, delta)
    elif role == 2:
        extent = simd_abort_stack(w, delta)
    elif role == 3 and get(w, SIMD_ISA_SLOT) == 1:
        extent = simd_scalar_tail_exit(w, delta)
    elif role >= 4 and role <= 6:
        vector = 8 << get(w, SIMD_ISA_SLOT)
        width = choose(role == 4, 4 * vector, choose(role == 5, vector, choose(vector == 16, 1, 16)))
        extent = simd_interval_obligation(w, width)
    elif role == 7:
        extent = simd_endpoint_partition(w, 8 << get(w, SIMD_ISA_SLOT))
    elif role == 9:
        extent = simd_bounded_partition(w, 0)
    elif role >= 16 and role <= 29:
        extent = simd_endpoint_obligation(w, role)
    else:
        return 0
    if extent == 0:
        return 0
    put(w, HEADER, OBLIGATION_MAGIC)
    put(w, HEADER + 8, 3)
    put(w, HEADER + 16, budget)
    return dispatch(w, SIMD_SOLVER_PHASE, 5, WORK_OFFSET + HEADER, 24, OBLIGATION, OBLIGATION_CAP,
                    WORK_OFFSET + FRAME, extent)

def receive_simd_induction(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 120 or size > OBLIGATION_CAP or get(w, OBLIGATION) != OBLIGATION_REPLY:
        return 0
    if get(w, OBLIGATION + 8) != 3:
        return 0
    verdict = get(w, OBLIGATION + 16)
    if verdict != SAT and verdict != UNSAT:
        return 0
    formula = get(w, OBLIGATION + 48)
    witness = get(w, OBLIGATION + 56)
    table = get(w, OBLIGATION + 64)
    if formula < 40 or formula > size - 80 or witness > size - 80 - formula or table != size - 80 - formula - witness:
        return 0
    role = get(w, SIMD_ORDINAL_SLOT)
    detail = get(w, SIMD_DETAIL_SLOT)
    expected = choose(role == 1, SAT, UNSAT)
    cursor = get(w, 224)
    if detail == 1:
        if cursor + 16 + size > length(o):
            return 0
        put(o, cursor, role)
        put(o, cursor + 8, size)
        copy_output(o, w, OBLIGATION, cursor + 16, size)
        put(w, 224, cursor + 16 + size)
    put(w, SIMD_COUNT_SLOT, get(w, SIMD_COUNT_SLOT) + 1)
    if verdict != expected:
        if detail == 0:
            return 0
        return finish_simd_receipt(o, w, 2)
    next = next_simd_ordinal(w, role)
    if next == 0:
        return finish_simd_receipt(o, w, 1)
    put(w, SIMD_ORDINAL_SLOT, next)
    return send_simd_induction(w)

def finish_simd_receipt(o:mutbuf, w:mutbuf, status:u64) -> u64:
    detail = get(w, SIMD_DETAIL_SLOT)
    isa = get(w, SIMD_ISA_SLOT)
    put(o, 0, choose(detail == 1, SIMD_DETAIL_RECEIPT, SIMD_RECEIPT))
    put(o, 8, status)
    put(o, 16, isa)
    put(o, 24, get(w, SIMD_KIND_SLOT))
    put(o, 32, 8 << isa)
    put(o, 40, 4)
    put(o, 48, get(w, 240))
    put(o, 56, get(w, 248))
    put(o, 72, choose(detail == 1, get(w, SIMD_COUNT_SLOT), 0))
    return get(w, 224)

def join_observations(w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 72 or size > MACHINE_CAP + 16 or get(w, MACHINE) != MACHINE_REPLY:
        return 0
    # The child validated this graph and its maximum depth before returning it.
    put(w, REGISTER_DEPTH_SLOT, get(w, MACHINE + 48))
    graph = get(w, 168)
    put(w, FRAME, JOIN_REQUEST)
    put(w, FRAME + 8, graph)
    put(w, FRAME + 16, size)
    copy_work(w, SUBJECT + SUBJECT_HEADER, FRAME + 24, graph)
    copy_work(w, MACHINE, FRAME + 24 + graph, size)
    return dispatch(w, 8, 4, WORK_OFFSET + FRAME, 24 + graph + size, OBSERVATION, PROJECTION_OUTPUT, 0, 0)

def first_obligation(w:mutbuf) -> u64:
    extent = get(w, 64)
    if extent < 120 or extent > PROJECTION_OUTPUT or get(w, OBSERVATION) != CIRCUIT_REQUEST:
        return 0
    put(w, 208, extent)
    put(w, 216, 0)
    put(w, 224, RECEIPT_HEAD)
    return send_obligation(w)

def send_obligation(w:mutbuf) -> u64:
    role = get(w, 216)
    budget = (get(w, 128) - now(w)) // 1000000
    if role > 4 or budget < 100:
        return 0
    put(w, HEADER, OBLIGATION_MAGIC)
    put(w, HEADER + 8, role)
    put(w, HEADER + 16, budget)
    extent = choose(role >= 3, get(w, 208), 0)
    return dispatch(w, 9, 5, WORK_OFFSET + HEADER, 24, OBLIGATION, OBLIGATION_CAP,
                    WORK_OFFSET + OBSERVATION, extent)

def receive_obligation(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    role = get(w, 216)
    if size < 120 or size > OBLIGATION_CAP or get(w, OBLIGATION) != OBLIGATION_REPLY:
        return 0
    if get(w, OBLIGATION + 8) != role:
        return 0
    expected = choose(role == 0, SAT, UNSAT)
    observed = get(w, OBLIGATION + 16)
    if observed != expected and (role < 3 or observed != SAT):
        return 0
    formula = get(w, OBLIGATION + 48)
    witness = get(w, OBLIGATION + 56)
    table = get(w, OBLIGATION + 64)
    if formula > size - 80 or witness > size - 80 - formula or table != size - 80 - formula - witness:
        return 0
    cursor = get(w, 224)
    if cursor + 8 + size > length(o):
        return 0
    put(o, cursor, size)
    copy_output(o, w, OBLIGATION, cursor + 8, size)
    put(w, 224, cursor + 8 + size)
    if role == 4 or observed != expected:
        return finish(o, w, role, observed == expected)
    put(w, 216, role + 1)
    return send_obligation(w)

def finish(o:mutbuf, w:mutbuf, role:u64, exact:bool) -> u64:
    put(o, 0, choose(get(w, REGISTER_MODE_SLOT) == 1, REGISTER_RECEIPT, RECEIPT_MAGIC))
    put(o, 8, choose(exact, 1, 2))
    put(o, 16, get(w, 160))
    put(o, 24, get(w, 176))
    put(o, 32, get(w, 184))
    put(o, 40, role + 1)
    put(o, 48, get(w, 240))
    put(o, 56, get(w, 248))
    put(o, 72, choose(get(w, REGISTER_MODE_SLOT) == 1, get(w, REGISTER_DEPTH_SLOT), 0))
    if exact and role == 4 and get(w, REGISTER_MODE_SLOT) == 1:
        return dispatch(w, 10, 7, REQUEST_HEAD, get(w, 136), DIGEST, 32, DIGEST_WORK, 1088)
    return get(w, 224)

def canonical_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    # Authoring links this entry to the same complete canonicalizer used by verify.
    return 0

def failure(o:mutbuf, w:mutbuf, phase:u64, status:u64, reason:u64) -> u64:
    # A typed result is admissible only after hashing all three inputs.
    # Keep those digests in the same offsets as a complete proof. No
    # partly computed entry, linked-text hash or obligation escapes.
    if get(w, TYPED_REQUEST_SLOT) != 1 or phase < 4:
        return 0
    put(o, 0, FAILURE_MAGIC)
    put(o, 8, status)
    put(o, 16, phase)
    put(o, 24, reason)
    at = 32
    while at < 80:
        put(o, at, 0)
        at = at + 8
    at = 176
    while at < RECEIPT_HEAD:
        put(o, at, 0)
        at = at + 8
    return RECEIPT_HEAD

def dispatch(w:mutbuf, phase:u64, role:u64, source:u64, size:u64,
             output:u64, capacity:u64, extra:u64, extent:u64) -> u64:
    put(w, 0, phase)
    put(w, 8, role)
    put(w, 16, source)
    put(w, 24, size)
    put(w, 32, output)
    put(w, 40, capacity)
    put(w, 48, extra)
    put(w, 56, extent)
    return 1

def copy_output(o:mutbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(w, source + i))
        i = i + 1
    return 0

def now(w:mutbuf) -> u64:
    return get(w, 112) * 1000000000 + get(w, 120)
'''


def document():
    from tools.generate_hia_safe_core_binder import shared_transport

    from tools.generate_hia_verified_simd_sse2_check import embedded_source
    from tools.generate_hia_verified_simd_avx2_check import source_program as avx2_checker
    from tools.generate_hia_verified_simd_avx512_check import source_program as avx512_checker

    from tools.hia_verified_simd_induction import source as induction_source

    helpers = shared_transport()
    helpers = helpers[helpers.index('\ndef copy_work('):helpers.index('\ndef next(')]
    constants = {name: value for name, value in globals().items() if name.isupper() and type(value) is int}
    grammar_words = [f'word{i}' for i in range(8)]
    grammar_args = ', '.join(name + ':u64' for name in grammar_words)
    grammar_writer = [f'def store_simd_grammar8(w:mutbuf, at:u64, {grammar_args}) -> u64:']
    grammar_writer.extend(f'    put(w, at + {8 * i}, {name})' for i, name in enumerate(grammar_words))
    grammar_writer.append('    return 0')
    machine = '\n'.join(grammar_writer) + '\n' + embedded_source(BINDING, OBLIGATION, OBSERVATION)
    for prefix,checker in [('avx2_',avx2_checker),('avx512_',avx512_checker)]:
        machine += '\n' + embedded_source(BINDING, OBLIGATION, OBSERVATION, source_factory=checker, prefix=prefix)
    import ast

    policy = transport_document(SOURCE + induction_source() + helpers + '\n' + machine, module='supplied_safe_core_proof', extra=constants)
    slot = next(i for i, function in enumerate(ast.parse(SOURCE).body) if function.name == 'canonical_wire')
    root = Path(__file__).resolve().parents[1]
    source = (root / 'examples/hia_bootstrap/json_canonical.hepta').read_bytes()
    canonicalizer = _parse_assembly_document(source)['functions']
    placement = {function['name']: f'f{slot if i == 0 else len(policy["functions"]) + i - 1}'
                 for i, function in enumerate(canonicalizer)}
    for function in canonicalizer:
        function['name'] = placement[function['name']]
        for block in function['blocks']:
            for instruction in block['ops']:
                if instruction['op'] == 'call':
                    attrs = instruction['attrs']
                    attrs['function'] = placement[attrs['function']]
    policy['functions'][slot] = canonicalizer[0]
    policy['functions'].extend(canonicalizer[1:])
    return policy


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
