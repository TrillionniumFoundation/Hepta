"""Author the sealed supplied-artifact Safe Core verifier's HIA coordinator."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
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
FAILURE_MAGIC = int.from_bytes(b'HIAPRX01', 'little')
LOADER_SECTION_REFUSAL = REFUSAL_IDS['loader_section_unreviewed']
DEADLINE = 3
OUTSIDE_PROFILE = 4
INCOMPLETE = 5
TYPED_REQUEST_SLOT = 256
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
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < REQUEST_HEAD:
        return 0
    magic = uint(s, 0, 8)
    if magic != REQUEST_MAGIC and magic != TYPED_REQUEST_MAGIC:
        return 0
    profile = uint(s, 8, 8)
    budget = uint(s, 16, 8)
    core = uint(s, 24, 8)
    obj = uint(s, 32, 8)
    final = uint(s, 40, 8)
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
    put(w, TYPED_REQUEST_SLOT, choose(magic == TYPED_REQUEST_MAGIC, 1, 0))
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
    put(o, 64, name)
    copy_output(o, w, SUBJECT + 64, 208, NAME_LIMIT)
    obj = get(w, 144)
    final = get(w, 152)
    put(w, HEADER, choose(get(w, TYPED_REQUEST_SLOT) == 1, BIND_DIAGNOSTIC_REQUEST, BIND_MAGIC))
    put(w, HEADER + 8, obj)
    put(w, HEADER + 16, final)
    put(w, HEADER + 24, name)
    copy_work(w, SUBJECT + 64, HEADER + 32, NAME_LIMIT)
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
    profile = get(w, 160)
    flags = 0
    if profile > 2:
        flags = (1 << (profile - 2)) - 1
    put(w, HEADER, MACHINE_MAGIC)
    put(w, HEADER + 8, get(w, 176))
    put(w, HEADER + 16, flags)
    return dispatch(w, 7, 3, WORK_OFFSET + HEADER, 24, MACHINE, MACHINE_CAP + 16,
                    WORK_OFFSET + BINDING, get(w, 192))

def join_observations(w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 72 or size > MACHINE_CAP + 16 or get(w, MACHINE) != MACHINE_REPLY:
        return 0
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
    put(o, 0, RECEIPT_MAGIC)
    put(o, 8, choose(exact, 1, 2))
    put(o, 16, get(w, 160))
    put(o, 24, get(w, 176))
    put(o, 32, get(w, 184))
    put(o, 40, role + 1)
    put(o, 48, get(w, 240))
    put(o, 56, get(w, 248))
    put(o, 72, 0)
    return get(w, 224)

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

    helpers = shared_transport()
    helpers = helpers[helpers.index('\ndef copy_work('):helpers.index('\ndef next(')]
    constants = {name: value for name, value in globals().items() if name.isupper() and type(value) is int}
    return transport_document(SOURCE + helpers, module='supplied_safe_core_proof', extra=constants)


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
