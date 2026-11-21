"""Author the HIA coordinator for independent binding of two Safe Core ELFs."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_core_proof_wire_native import ELF_FUNCTION_LINK_REQUEST, ELF_OBJECT_RELOCATION_REQUEST
from hepta.hia_safe_core_elf_inventory_native import (
    AUTHORITY_BYTES, AUTHORITY_MAGIC, CAPACITY, FINAL_LOADER_NAME, FINAL_LOADER_RECEIPT_MAGIC,
    FINAL_LOADER_WORK, FUNCTION_LINK_BYTES, FUNCTION_LINK_RECEIPT_MAGIC, FUNCTION_RECEIPT_BYTES,
    FUNCTION_RECEIPT_MAGIC, LOADER_SECTION_MAGIC, MAX_ELF, MAX_SECTIONS, MAX_SEGMENTS, MAX_SYMBOLS,
    OBJECT_INVENTORY_CONTROL_BYTES, OBJECT_RELOCATION_CONTROL_BYTES, OWNED_SHARED_SYMBOL_CAPACITY,
    OWNED_SHARED_EXPECTED_WORK, OWNED_SHARED_SYMBOL_HEAD, OWNED_SHARED_SYMBOL_MAGIC, OWNED_SHARED_SYMBOL_WORK, RELOCATION,
    SECTION, SECTION_AUTHORITIES, SEGMENT, SYMBOL, UNWINDING_MAGIC,
)
from tools.generate_hia_elf_linker import LinkerBuilder, SOURCE as LINK_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_binder.hepta'
FRAME_MAGIC = int.from_bytes(b'HIAEBND1', 'little')
DIAGNOSTIC_REQUEST = int.from_bytes(b'HIAEBND2', 'little')
DIAGNOSTIC_REPLY = int.from_bytes(b'HIAEBNX1', 'little')
REPLY_MAGIC = int.from_bytes(b'HIAEBNR1', 'little')
FRAME_HEAD = 32 + 256
REPLY_HEAD = 80
TEXT_LIMIT = 64 << 10
INPUT_LIMIT = FRAME_HEAD + 2 * MAX_ELF
OUTPUT_LIMIT = REPLY_HEAD + TEXT_LIMIT + 24 + 2 * RELOCATION.size
OUTPUT_OFFSET = ((INPUT_LIMIT + 4096) // 4096) * 4096
WORK_OFFSET = OUTPUT_OFFSET + ((OUTPUT_LIMIT + 4095) // 4096) * 4096
WORK_LIMIT = 5 << 20
PLAN = 4096
SOURCE_LAYOUT = 8192
SOURCE_FUNCTIONS = 16384
FINAL_FUNCTIONS = 28672
COORDINATES = 40960
DETAIL = 45056
WIRE = 65536
CONTROLS = 147456
BIG_REPLY = 1 << 20
BIG_WORK = 3 << 20
INVENTORY_CAP = CAPACITY + AUTHORITY_BYTES
FUNCTION_CAP = INVENTORY_CAP + FUNCTION_RECEIPT_BYTES
CONTROL_CAP = OBJECT_INVENTORY_CONTROL_BYTES + OBJECT_RELOCATION_CONTROL_BYTES + TEXT_LIMIT

# The carrier owns only bytes and bounded call dispatch. Each protocol choice,
# expected extent, observation, and publication-sized answer below is HIA.
SOURCE = '''
def bind(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORK_LIMIT or length(o) != OUTPUT_LIMIT:
        return 0
    phase = get(w, 0)
    result = stage(s, o, w, phase)
    if result != 0 or length(s) < FRAME_HEAD or uint(s, 0, 8) != DIAGNOSTIC_REQUEST:
        return result
    return refusal(o, w, phase)

def stage(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 0:
        return start(s, w)
    if phase <= 4:
        return image_inventory(s, w, phase)
    if phase <= 8:
        return linked_functions(s, w, phase)
    if phase <= 13:
        return relocated_text(s, w, phase)
    if phase == 14:
        return emit(s, o, w)
    return 0

def refusal(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    at = 0
    if phase == 1:
        at = BIG_REPLY
    if phase == 2 or phase == 3 or phase == 4 or phase == 10:
        at = DETAIL
    if phase == 5:
        at = SOURCE_LAYOUT
    if phase == 6 or phase == 12:
        at = SOURCE_FUNCTIONS
    if phase == 7 or phase == 13 or phase == 14:
        at = FINAL_FUNCTIONS
    if phase == 9:
        at = COORDINATES
    put(o, 0, DIAGNOSTIC_REPLY)
    put(o, 8, phase)
    put(o, 16, 0)
    put(o, 24, 0)
    put(o, 32, 0)
    size = get(w, 64)
    if at != 0 and (size == 24 or phase == 1 and size == 64):
        put(o, 16, get(w, at))
        put(o, 24, get(w, at + 8))
        put(o, 32, get(w, at + 16))
    return 40

def start(s:readbuf, w:mutbuf) -> u64:
    if length(s) < FRAME_HEAD:
        return 0
    magic = uint(s, 0, 8)
    if magic != FRAME_MAGIC and magic != DIAGNOSTIC_REQUEST:
        return 0
    obj = uint(s, 8, 8)
    final = uint(s, 16, 8)
    name = uint(s, 24, 8)
    if obj < 64 or obj > MAX_ELF or final < 64 or final > MAX_ELF:
        return 0
    if name == 0 or name > 256 or length(s) != FRAME_HEAD + obj + final:
        return 0
    i = name
    while i < 256:
        if byte(s, 32 + i) != 0:
            return 0
        i = i + 1
    put(w, 72, obj)
    put(w, 80, final)
    put(w, 88, name)
    put(w, BIG_WORK, OWNED_SHARED_SYMBOL_MAGIC)
    put(w, BIG_WORK + OWNED_SHARED_SYMBOL_WORK, 1)
    put(w, BIG_WORK + OWNED_SHARED_SYMBOL_WORK + 8, name)
    copy_input(s, w, 32, BIG_WORK + OWNED_SHARED_SYMBOL_WORK + 16, name)
    return next(w, 1, 1, FRAME_HEAD + obj, final, BIG_REPLY, OWNED_SHARED_SYMBOL_CAPACITY, BIG_WORK, OWNED_WORK)

def image_inventory(s:readbuf, w:mutbuf, phase:u64) -> u64:
    obj = get(w, 72)
    final = get(w, 80)
    size = get(w, 64)
    if phase == 1:
        if get(w, BIG_REPLY) != 0 or get(w, BIG_REPLY + 16) != 1:
            return 0
        count = get(w, BIG_REPLY + 8)
        if count > 65536 or size != OWNED_SHARED_SYMBOL_HEAD + 24 * count:
            return 0
        put(w, PLAN, LOADER_SECTION_MAGIC)
        return next(w, 2, 1, FRAME_HEAD + obj, final, DETAIL, INVENTORY_CAP, PLAN, 8)
    if phase == 2:
        if terminal(w, DETAIL, size) == 0:
            return 0
        put(w, PLAN, AUTHORITY_MAGIC)
        put(w, PLAN + 8, 3)
        return next(w, 3, 1, FRAME_HEAD + obj, final, DETAIL, INVENTORY_CAP, PLAN, 16)
    if phase == 3:
        if inventory(w, DETAIL, size) == 0:
            return 0
        at = DETAIL + size - AUTHORITY_BYTES + UNWINDING_ROLE
        row = get(w, at)
        if row == 0 or row > get(w, DETAIL + 8):
            return 0
        put(w, PLAN, UNWINDING_MAGIC)
        put(w, PLAN + 8, row - 1)
        return next(w, 4, 1, FRAME_HEAD + obj, final, DETAIL, INVENTORY_CAP, PLAN, 64)
    if terminal(w, DETAIL, size) == 0:
        return 0
    put(w, PLAN, AUTHORITY_MAGIC)
    put(w, PLAN + 8, 1)
    return next(w, 5, 1, FRAME_HEAD, obj, SOURCE_LAYOUT, INVENTORY_CAP, PLAN, 16)

def linked_functions(s:readbuf, w:mutbuf, phase:u64) -> u64:
    obj = get(w, 72)
    final = get(w, 80)
    size = get(w, 64)
    if phase == 5:
        if inventory(w, SOURCE_LAYOUT, size) == 0 or get(w, SOURCE_LAYOUT + 16) != 0:
            return 0
        put(w, 96, size)
        put(w, PLAN, FUNCTION_RECEIPT_MAGIC)
        put(w, PLAN + 8, 1)
        return next(w, 6, 1, FRAME_HEAD, obj, SOURCE_FUNCTIONS, FUNCTION_CAP, PLAN, 16)
    if phase == 6:
        if functions(w, SOURCE_FUNCTIONS, size) == 0:
            return 0
        put(w, 104, size)
        put(w, PLAN + 8, 3)
        return next(w, 7, 1, FRAME_HEAD + obj, final, FINAL_FUNCTIONS, FUNCTION_CAP, PLAN, 16)
    if phase == 7:
        if functions(w, FINAL_FUNCTIONS, size) == 0:
            return 0
        first = get(w, 104)
        put(w, WIRE, ELF_FUNCTION_LINK_REQUEST)
        put(w, WIRE + 8, first)
        put(w, WIRE + 16, size)
        put(w, WIRE + 24, get(w, 88))
        copy_input(s, w, 32, WIRE + 32, 256)
        copy_work(w, SOURCE_FUNCTIONS, WIRE + 288, first)
        copy_work(w, FINAL_FUNCTIONS, WIRE + 288 + first, size)
        return next(w, 8, 2, WORK_OFFSET + WIRE, 288 + first + size, CONTROLS, FUNCTION_LINK_BYTES, PLAN, 1)
    if size != FUNCTION_LINK_BYTES:
        return 0
    put(w, PLAN, FUNCTION_LINK_RECEIPT_MAGIC)
    return next(w, 9, 1, WORK_OFFSET + CONTROLS, size, COORDINATES, INVENTORY_CAP, PLAN, 8)

def relocated_text(s:readbuf, w:mutbuf, phase:u64) -> u64:
    obj = get(w, 72)
    final = get(w, 80)
    size = get(w, 64)
    if phase == 9:
        if size != 48 or get(w, COORDINATES) != 0 or get(w, COORDINATES + 8) > 1 or get(w, COORDINATES + 16) != 0:
            return 0
        put(w, PLAN, FINAL_LOADER_RECEIPT_MAGIC)
        put(w, PLAN + 8, get(w, 88))
        copy_input(s, w, 32, PLAN + FINAL_LOADER_NAME, 256)
        return next(w, 10, 1, FRAME_HEAD + obj, final, DETAIL, INVENTORY_CAP, PLAN, FINAL_LOADER_WORK)
    if phase == 10:
        if size != 56 or get(w, DETAIL) != 0 or get(w, DETAIL + 8) != 0 or get(w, DETAIL + 16) != 0:
            return 0
        return relocation_frame(s, w)
    if phase == 11:
        if size != RELOCATION_HEAD + get(w, DETAIL + 40):
            return 0
        return next(w, 12, 1, FRAME_HEAD, obj, SOURCE_FUNCTIONS, INVENTORY_CAP, CONTROLS, OBJECT_INVENTORY_CONTROL_BYTES)
    if phase == 12:
        if terminal(w, SOURCE_FUNCTIONS, size) == 0:
            return 0
        put(w, PLAN, get(w, CONTROLS + 24))
        put(w, PLAN + 8, 0)
        return next(w, 13, 1, FRAME_HEAD, obj, FINAL_FUNCTIONS, INVENTORY_CAP, PLAN, 16)
    names = get(w, FINAL_FUNCTIONS + 8)
    if get(w, FINAL_FUNCTIONS) != 0 or get(w, FINAL_FUNCTIONS + 16) != 0:
        return 0
    if names > MAX_SYMBOLS or size != 24 + SYMBOL_SIZE * names:
        return 0
    return next(w, 14, 1, FRAME_HEAD, obj, FINAL_FUNCTIONS, INVENTORY_CAP,
                CONTROLS + OBJECT_INVENTORY_CONTROL_BYTES, OBJECT_RELOCATION_CONTROL_BYTES + get(w, DETAIL + 40))

def relocation_frame(s:readbuf, w:mutbuf) -> u64:
    obj = get(w, 72)
    final = get(w, 80)
    extent = get(w, DETAIL + 40)
    offset = get(w, DETAIL + 24)
    address = get(w, DETAIL + 32)
    entry = get(w, COORDINATES + 24)
    helper = get(w, COORDINATES + 40)
    if extent > TEXT_LIMIT or offset > final or extent > final - offset or entry >= extent:
        return 0
    if get(w, COORDINATES + 32) - address != entry:
        return 0
    if helper != 0 and helper - address >= extent:
        return 0
    layout = get(w, 96)
    put(w, WIRE, ELF_OBJECT_RELOCATION_REQUEST)
    put(w, WIRE + 8, layout)
    put(w, WIRE + 16, address)
    put(w, WIRE + 24, get(w, DETAIL + 48))
    put(w, WIRE + 32, helper)
    copy_work(w, SOURCE_LAYOUT, WIRE + 40, layout)
    copy_input(s, w, FRAME_HEAD + obj + offset, WIRE + 40 + layout, extent)
    return next(w, 11, 2, WORK_OFFSET + WIRE, 40 + layout + extent, CONTROLS, CONTROL_CAP, PLAN, 1)

def emit(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = get(w, 64)
    direct = get(w, COORDINATES + 8)
    count = 2 - direct
    if get(w, FINAL_FUNCTIONS) != 0 or get(w, FINAL_FUNCTIONS + 8) != count or get(w, FINAL_FUNCTIONS + 16) != 0:
        return 0
    if size != 24 + RELOCATION_SIZE * count:
        return 0
    offset = get(w, DETAIL + 24)
    extent = get(w, DETAIL + 40)
    base = FRAME_HEAD + get(w, 72) + offset
    put(o, 0, REPLY_MAGIC)
    put(o, 8, offset)
    put(o, 16, get(w, DETAIL + 32))
    put(o, 24, extent)
    put(o, 32, get(w, COORDINATES + 24))
    put(o, 40, get(w, COORDINATES + 40))
    put(o, 48, get(w, DETAIL + 48))
    put(o, 56, direct)
    put(o, 64, size)
    put(o, 72, 0)
    j = 0
    while j < extent:
        store(o, REPLY_HEAD + j, byte(s, base + j))
        j = j + 1
    j = 0
    while j < size:
        store(o, REPLY_HEAD + extent + j, byte(w, FINAL_FUNCTIONS + j))
        j = j + 1
    return REPLY_HEAD + extent + size

def inventory(w:mutbuf, at:u64, size:u64) -> u64:
    count = get(w, at + 8)
    segments = get(w, at + 16)
    if get(w, at) != 0 or count == 0 or count > MAX_SECTIONS or segments > MAX_SEGMENTS:
        return 0
    return choose(size == 24 + AUTHORITY_BYTES + SECTION_SIZE * count + SEGMENT_SIZE * segments, 1, 0)

def functions(w:mutbuf, at:u64, size:u64) -> u64:
    count = get(w, at + 8)
    if get(w, at) != 0 or get(w, at + 16) != 0 or count == 0 or count > 2:
        return 0
    return choose(size == 24 + SYMBOL_SIZE * count + FUNCTION_RECEIPT_BYTES, 1, 0)

def terminal(w:mutbuf, at:u64, size:u64) -> u64:
    if size != 24 or get(w, at) != 0 or get(w, at + 8) != 0 or get(w, at + 16) != 0:
        return 0
    return 1

def copy_input(s:readbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0

def copy_work(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def next(w:mutbuf, phase:u64, role:u64, source:u64, size:u64, answer:u64,
         capacity:u64, scratch:u64, space:u64) -> u64:
    put(w, 0, phase)
    put(w, 8, role)
    put(w, 16, source)
    put(w, 24, size)
    put(w, 32, answer)
    put(w, 40, capacity)
    put(w, 48, scratch)
    put(w, 56, space)
    return 1
'''


def document(source=SOURCE, *, module='safe_core_binder', extra=None):
    constants = {name: value for name, value in globals().items() if name.isupper() and type(value) is int}
    constants.update(RELOCATION_HEAD=OBJECT_INVENTORY_CONTROL_BYTES + OBJECT_RELOCATION_CONTROL_BYTES,
                     OWNED_WORK=OWNED_SHARED_EXPECTED_WORK,
                     UNWINDING_ROLE=8 * SECTION_AUTHORITIES.index('.eh_frame'),
                     SECTION_SIZE=SECTION.size, SEGMENT_SIZE=SEGMENT.size,
                     SYMBOL_SIZE=SYMBOL.size, RELOCATION_SIZE=RELOCATION.size)
    if extra is not None:
        constants.update(extra)
    source = re.sub(r'\b[A-Z][A-Z_0-9]+\b', lambda match: str(constants[match[0]]), source)
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):LINK_SOURCE.index('\ndef copy_bytes(')]
    nodes = ast.parse(source + helpers).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module,
                                  'functions': functions})


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
