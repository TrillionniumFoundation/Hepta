"""Author the native machine-observation coordinator over a bound ELF receipt."""
from __future__ import annotations

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import CIRCUIT_NODES
from hepta.hia_core_proof_wire_native import MACHINE_RELOCATION_REQUEST
from hepta.hia_safe_core_x64_decode_native import (
    MACHINE_VALUES_BRANCH_DEPTH, MACHINE_VALUES_HEADER, MACHINE_VALUES_NODE, MACHINE_VALUES_REPLY,
    MACHINE_VALUES_REQUEST, MACHINE_VALUES_STACK_BYTES, MACHINE_VALUES_WORKSPACE,
    MAX_INSTRUCTIONS, ROW, WORKSPACE,
)
from tools.generate_hia_safe_core_binder import document as transport_document, shared_transport

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_machine_observe.hepta'
REQUEST_MAGIC = int.from_bytes(b'HIAMOP01', 'little')
RESPONSE_MAGIC = int.from_bytes(b'HIAMOPR1', 'little')
REL_FRAME = 8192
DECODE_WORK = 16384
DECODED = 131072
PROJECT_WORK = 1 << 20
OBSERVATION = 3 << 20
DECODE_CAP = 32 + MAX_INSTRUCTIONS * ROW.size
OBSERVATION_CAP = MACHINE_VALUES_HEADER.size + CIRCUIT_NODES * MACHINE_VALUES_NODE.size
REQUEST_BYTES = 24
SIMD_DATA_QUERY = int.from_bytes(b'HIASMOC1', 'little')
SD_SPAN, SD_ISA, SD_SHAPE, SD_ROLE, SD_LANES, SD_MEMORY = range(512, 560, 8)
SD_CLASS_COUNT, SD_NODE_COUNT, SD_BAD_NODE, SD_FALSE_NODE, SD_RAW_MASK, SD_RAW_GPR = range(560, 608, 8)
SD_TEXT, SD_OPS, SD_VEC, SD_GPR, SD_DST, SD_CLASSES = 8192, 12288, 12544, 13184, 13440, 13824
FRAME = 16384
SIMD_RESULT_MOVE_SLOT, SIMD_COUNT_MOVE_SLOT = 608, 616
BINDING = SD_TEXT - 80

SOURCE = '''
def observe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORK_LIMIT or length(o) != OUTPUT_LIMIT:
        return 0
    phase = get(w, 0)
    if phase == 0:
        if length(s) >= 32 and uint(s, 0, 8) == SIMD_DATA_QUERY:
            return simd_data(s, o, w)
        return admit(s, w)
    if phase == 1:
        return decode(w)
    if phase == 2:
        return project(w)
    if phase == 3:
        return emit(o, w)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < REQUEST_BYTES + REPLY_HEAD + 56:
        return 0
    if uint(s, 0, 8) != REQUEST_MAGIC or uint(s, REQUEST_BYTES, 8) != REPLY_MAGIC:
        return 0
    arguments = uint(s, 8, 8)
    profile = uint(s, 16, 8)
    if arguments > 6 or profile > 15:
        return 0
    span = uint(s, REQUEST_BYTES + 24, 8)
    entry = uint(s, REQUEST_BYTES + 32, 8)
    direct = uint(s, REQUEST_BYTES + 56, 8)
    count = 2 - direct
    relocations = uint(s, REQUEST_BYTES + 64, 8)
    if span == 0 or span > TEXT_LIMIT or entry >= span or direct > 1:
        return 0
    if uint(s, REQUEST_BYTES + 72, 8) != 0 or relocations != 24 + 32 * count:
        return 0
    if length(s) != REQUEST_BYTES + REPLY_HEAD + span + relocations:
        return 0
    put(w, 72, span)
    put(w, 80, entry)
    put(w, 88, arguments)
    put(w, 96, count)
    put(w, REL_FRAME, MACHINE_RELOCATION_REQUEST)
    put(w, REL_FRAME + 8, span)
    put(w, REL_FRAME + 16, uint(s, REQUEST_BYTES + 16, 8))
    put(w, REL_FRAME + 24, entry)
    put(w, REL_FRAME + 32, arguments)
    put(w, REL_FRAME + 40, profile)
    copy_input(s, w, REQUEST_BYTES + REPLY_HEAD + span, REL_FRAME + 48, relocations)
    return next(w, 1, 2, WORK_OFFSET + REL_FRAME, 48 + relocations,
                DECODE_WORK, DECODER_WORK + 56, PLAN, 1)

def decode(w:mutbuf) -> u64:
    size = get(w, 64)
    if size != DECODER_WORK + 8 + 24 * get(w, 96):
        return 0
    return next(w, 2, 1, REQUEST_BYTES + REPLY_HEAD, get(w, 72),
                DECODED, DECODE_CAP, DECODE_WORK, size)

def project(w:mutbuf) -> u64:
    size = get(w, 64)
    if size < 32 or get(w, DECODED) != MACHINE_VALUES_REQUEST:
        return 0
    if get(w, DECODED + 8) != get(w, 80) or get(w, DECODED + 16) != get(w, 88):
        return 0
    decoded = get(w, DECODED + 24)
    if decoded == 0 or decoded > MAX_INSTRUCTIONS or decoded > get(w, 72):
        return 0
    if size != 32 + decoded * ROW_BYTES:
        return 0
    put(w, 104, decoded)
    return next(w, 3, 1, WORK_OFFSET + DECODED, size, OBSERVATION, OBSERVATION_CAP,
                PROJECT_WORK, MACHINE_VALUES_WORKSPACE)

def emit(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    if size < OBSERVATION_HEAD or get(w, OBSERVATION) != MACHINE_VALUES_REPLY:
        return 0
    nodes = get(w, OBSERVATION + 8)
    paths = get(w, OBSERVATION + 40)
    steps = get(w, OBSERVATION + 24)
    if nodes == 0 or nodes > CIRCUIT_NODES or paths == 0 or paths > PATHS:
        return 0
    if steps == 0 or steps > paths * MAX_INSTRUCTIONS:
        return 0
    if get(w, OBSERVATION + 16) >= nodes or get(w, OBSERVATION + 48) >= nodes:
        return 0
    if get(w, OBSERVATION + 32) > MACHINE_VALUES_STACK_BYTES:
        return 0
    if size != OBSERVATION_HEAD + OBSERVATION_NODE * nodes:
        return 0
    put(o, 0, RESPONSE_MAGIC)
    put(o, 8, get(w, 104))
    i = 0
    while i < size:
        store(o, 16 + i, byte(w, OBSERVATION + i))
        i = i + 1
    return 16 + size
'''


def document():
    constants = {name: value for name, value in globals().items() if name.isupper() and type(value) is int}
    constants.update(DECODER_WORK=WORKSPACE, ROW_BYTES=ROW.size,
                     OBSERVATION_HEAD=MACHINE_VALUES_HEADER.size, OBSERVATION_NODE=MACHINE_VALUES_NODE.size,
                     PATHS=1 << MACHINE_VALUES_BRANCH_DEPTH)
    from tools.hia_verified_simd_data_obligations import source as simd_data_source

    helpers = shared_transport()
    helpers = helpers[:helpers.index('\ndef copy_work(')] + helpers[helpers.index('\ndef next('):]
    return transport_document(SOURCE + helpers + simd_data_source(), module='safe_core_machine_observe', extra=constants)


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
