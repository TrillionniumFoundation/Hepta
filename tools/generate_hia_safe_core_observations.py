"""Author the HIA join of an admitted Core graph and native machine observations."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    ARTIFACT_PROJECTION_REQUEST, CIRCUIT_NODES, CIRCUIT_REQUEST, GRAPH_PROJECTION_REQUEST,
    PROJECTION_INPUT_LIMIT, PROJECTION_OUTPUT, PROJECTION_WORKSPACE,
)
from hepta.hia_safe_core_x64_decode_native import ARTIFACT_WIRE_OUTPUT, ARTIFACT_WIRE_REQUEST, MAX_INSTRUCTIONS
from tools.generate_hia_safe_core_binder import document as transport_document, shared_transport
from tools.generate_hia_safe_core_machine_observe import (
    OBSERVATION_CAP, RESPONSE_MAGIC as MACHINE_OBSERVATION_MAGIC,
)

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_observations.hepta'
JOIN_REQUEST = int.from_bytes(b'HIAOBV01', 'little')
CORE_OBSERVATION = 8192
PAIR_FRAME = 32768
ARTIFACT_REQUEST = 196608
ARTIFACT_OBSERVATION = 229376
PROJECTION_SCRATCH = 1 << 20
ARTIFACT_SCRATCH = 2 << 20
HEAD = 24
MACHINE_HEAD = 16

SOURCE = '''
def join(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORK_LIMIT or length(o) != OUTPUT_LIMIT:
        return 0
    phase = get(w, 0)
    if phase == 0:
        return admit(s, w)
    if phase == 1:
        return paired_frame(s, w)
    if phase == 2:
        return artifact(w)
    if phase == 3:
        return emit(o, w)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < HEAD + 40 + MACHINE_HEAD + 56 or uint(s, 0, 8) != JOIN_REQUEST:
        return 0
    graph = uint(s, 8, 8)
    machine = uint(s, 16, 8)
    if graph < 40 or graph > PROJECTION_INPUT_LIMIT or machine < MACHINE_HEAD + 56:
        return 0
    if machine > MACHINE_HEAD + OBSERVATION_CAP or length(s) != HEAD + graph + machine:
        return 0
    if uint(s, HEAD, 8) != GRAPH_PROJECTION_REQUEST or uint(s, HEAD + 8, 8) != 2:
        return 0
    at = HEAD + graph
    if uint(s, at, 8) != MACHINE_OBSERVATION_MAGIC:
        return 0
    decoded = uint(s, at + 8, 8)
    if decoded == 0 or decoded > MAX_INSTRUCTIONS:
        return 0
    put(w, 72, graph)
    put(w, 80, machine - MACHINE_HEAD)
    return next(w, 1, 1, HEAD, graph, CORE_OBSERVATION, PROJECTION_OUTPUT,
                PROJECTION_SCRATCH, PROJECTION_WORKSPACE)

def paired_frame(s:readbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 120 or get(w, CORE_OBSERVATION) != CIRCUIT_REQUEST or get(w, CORE_OBSERVATION + 16) != 3:
        return 0
    graph = get(w, 72)
    machine = get(w, 80)
    put(w, PAIR_FRAME, ARTIFACT_WIRE_REQUEST)
    put(w, PAIR_FRAME + 8, graph)
    put(w, PAIR_FRAME + 16, machine)
    put(w, PAIR_FRAME + 24, size)
    copy_input(s, w, HEAD, PAIR_FRAME + 32, graph)
    copy_input(s, w, HEAD + graph + MACHINE_HEAD, PAIR_FRAME + 32 + graph, machine)
    copy_work(w, CORE_OBSERVATION, PAIR_FRAME + 32 + graph + machine, size)
    return next(w, 2, 2, WORK_OFFSET + PAIR_FRAME, 32 + graph + machine + size,
                ARTIFACT_REQUEST, ARTIFACT_WIRE_OUTPUT, PLAN, 2)

def artifact(w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 88 or get(w, ARTIFACT_REQUEST) != ARTIFACT_PROJECTION_REQUEST:
        return 0
    return next(w, 3, 1, WORK_OFFSET + ARTIFACT_REQUEST, size, ARTIFACT_OBSERVATION, PROJECTION_OUTPUT,
                ARTIFACT_SCRATCH, PROJECTION_WORKSPACE)

def emit(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 120 or get(w, ARTIFACT_OBSERVATION) != CIRCUIT_REQUEST:
        return 0
    count = get(w, ARTIFACT_OBSERVATION + 8)
    if count == 0 or count > CIRCUIT_NODES or size != 80 + 40 * count:
        return 0
    if get(w, ARTIFACT_OBSERVATION + 16) != 3 or get(w, ARTIFACT_OBSERVATION + 24) != 0:
        return 0
    index = 0
    while index < size:
        store(o, index, byte(w, ARTIFACT_OBSERVATION + index))
        index = index + 1
    return size
'''


def document():
    constants = {name: value for name, value in globals().items() if name.isupper() and type(value) is int}
    return transport_document(SOURCE + shared_transport(), module='safe_core_observations', extra=constants)


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
