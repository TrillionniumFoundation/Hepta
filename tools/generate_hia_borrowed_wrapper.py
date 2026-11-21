"""Author the canonical standalone SysV wrapper for admitted borrowed exports."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_native_byte_abi import MAX_EXTENT, MAX_RANGES
from hepta.hia_program_native import MAX_FRAME_BYTES, WIDTHS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_borrowed_export_wire import KINDS
from tools.generate_hia_machine_encoding import SOURCE as ENCODING

SOURCE = Path('examples/hia_bootstrap/borrowed_wrapper.hepta')
INPUT = int.from_bytes(b'HIABWR01', 'little')
OUTPUT = int.from_bytes(b'HIABWO01', 'little')
OUTPUT_BYTES = 256 << 10
WORKSPACE_BYTES = 2048
INVALID = 4294967293

POLICY = r'''
# Input: tag, extent, parameter count, then one admitted type id per parameter.
# Output: tag, text bytes, unresolved internal call offset, frame bytes, text.
# Every local jump is resolved here. Only the Core callee remains a relocation.
# Private workspace: position and fixup count, at most 52 failure fixups
# (three per loan, one per pair), then eight (argument slot, mutable) rows.
def borrow_wrapper(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if size < 32 or length(o) < OUTPUT_LIMIT or length(w) < WORKSPACE_LIMIT or word(s, 0) != INPUT:
        return INVALID
    extent = word(s, 8)
    count = word(s, 16)
    if count > (FRAME_LIMIT >> 3) or size != 24 + count * 8 or extent == 0 or extent > EXTENT_LIMIT:
        return INVALID
    words = 0
    ranges = 0
    index = 0
    while index < count:
        kind = word(s, 24 + index * 8)
        if kind == 0 or kind > TYPE_COUNT:
            return INVALID
        if kind <= 2:
            if ranges == RANGE_LIMIT:
                return INVALID
            put(w, 896 + ranges * 16, words)
            put(w, 904 + ranges * 16, choose(kind == 2, 1, 0))
            ranges = ranges + 1
            words = words + 1
        words = words + 1
        index = index + 1
    frame = ((words + 1) * 8 + 15) & 18446744073709551600
    if ranges == 0 or frame > FRAME_LIMIT:
        return INVALID
    put(w, 0, 32)
    put(w, 8, 0)
    prologue(o, w, frame)
    save_arguments(s, o, w, frame, count)
    guard_extents(o, w, frame, ranges, extent)
    guard_aliases(o, w, frame, ranges)
    memory(o, w, 6, 7, 5, 0 - frame)
    memory(o, w, 6, 6, 5, 0 - 8)
    emit(o, w, 232)
    call = get(w, 0) - 32
    little(o, w, 0, 4)
    memory(o, w, 4, 0, 5, 0 - 8)
    normalize(o, w, U32_KIND)
    epilogue(o, w)
    status = 1
    while status <= 4:
        failure(o, w, status)
        status = status + 1
    end = get(w, 0)
    out_word(o, 0, OUTPUT)
    out_word(o, 8, end - 32)
    out_word(o, 16, call)
    out_word(o, 24, frame)
    return end

def prologue(o:mutbuf, w:mutbuf, frame:u64) -> u64:
    emit(o, w, 85)
    rr(o, w, 137, 0, 4, 5)
    remaining = frame
    while remaining != 0:
        amount = choose(remaining < 4096, remaining, 4096)
        encode_arithmetic(o, w, 16, 4, 0, amount, 3, 0, 0)
        memory(o, w, 4, 11, 4, 0)
        remaining = remaining - amount
    return 0

def save_arguments(s:readbuf, o:mutbuf, w:mutbuf, frame:u64, count:u64) -> u64:
    index = 0
    slot = 0
    while index < count:
        kind = word(s, 24 + index * 8)
        if kind <= 2:
            save_word(o, w, frame, slot, 0)
            slot = slot + 1
            kind = 0
        save_word(o, w, frame, slot, kind)
        slot = slot + 1
        index = index + 1
    return 0

def save_word(o:mutbuf, w:mutbuf, frame:u64, slot:u64, kind:u64) -> u64:
    if slot < 6:
        rr(o, w, 137, 0, argument_register(slot), 0)
    else:
        memory(o, w, 4, 0, 5, 16 + 8 * (slot - 6))
    normalize(o, w, kind)
    return memory(o, w, 5, 0, 5, 0 - frame + 8 * slot)

def argument_register(slot:u64) -> u64:
    if slot == 0:
        return 7
    if slot == 1:
        return 6
    if slot == 2:
        return 2
    if slot == 3:
        return 1
    return slot + 4

def load_arg(o:mutbuf, w:mutbuf, frame:u64, slot:u64, register:u64) -> u64:
    return memory(o, w, 4, register, 5, 0 - frame + 8 * slot)

def normalize(o:mutbuf, w:mutbuf, kind:u64) -> u64:
    if kind == BOOL_KIND:
        return encode_arithmetic(o, w, 16, 0, 0, 1, 2, 0, 0)
    code = shift_code(kind)
    if code != 0:
        bits = code & 63
        encode_arithmetic(o, w, 17, 0, 0, bits, 0, 0, 0)
        encode_arithmetic(o, w, 17, 0, 0, bits, choose(code > 63, 2, 1), 0, 0)
    return 0

def guard_extents(o:mutbuf, w:mutbuf, frame:u64, ranges:u64, extent:u64) -> u64:
    index = 0
    while index < ranges:
        slot = get(w, 896 + index * 16)
        load_arg(o, w, frame, slot + 1, 1)
        encode_data(o, w, 3, 2, 0, extent, 0, 0, 0)
        rr(o, w, 57, 0, 2, 1)
        failure_branch(o, w, 7, 1)
        load_arg(o, w, frame, slot, 0)
        rr(o, w, 133, 0, 1, 1)
        empty = branch_to(o, w, 4)
        rr(o, w, 133, 0, 0, 0)
        failure_branch(o, w, 4, 2)
        rr(o, w, 1, 0, 1, 0)
        failure_branch(o, w, 2, 3)
        relative(o, empty, get(w, 0))
        index = index + 1
    return 0

def guard_aliases(o:mutbuf, w:mutbuf, frame:u64, ranges:u64) -> u64:
    left = 0
    while left < ranges:
        right = left + 1
        while right < ranges:
            if get(w, 904 + left * 16) != 0 or get(w, 904 + right * 16) != 0:
                disjoint(o, w, frame, get(w, 896 + left * 16), get(w, 896 + right * 16))
            right = right + 1
        left = left + 1
    return 0

def disjoint(o:mutbuf, w:mutbuf, frame:u64, left:u64, right:u64) -> u64:
    load_arg(o, w, frame, left + 1, 1)
    rr(o, w, 133, 0, 1, 1)
    left_empty = branch_to(o, w, 4)
    load_arg(o, w, frame, right + 1, 2)
    rr(o, w, 133, 0, 2, 2)
    right_empty = branch_to(o, w, 4)
    load_arg(o, w, frame, left, 0)
    rr(o, w, 1, 0, 1, 0)
    load_arg(o, w, frame, right, 1)
    rr(o, w, 57, 0, 1, 0)
    before = branch_to(o, w, 6)
    rr(o, w, 1, 0, 2, 1)
    load_arg(o, w, frame, left, 0)
    rr(o, w, 57, 0, 0, 1)
    after = branch_to(o, w, 6)
    failure_branch(o, w, 16, 4)
    end = get(w, 0)
    relative(o, left_empty, end)
    relative(o, right_empty, end)
    relative(o, before, end)
    return relative(o, after, end)

def branch_to(o:mutbuf, w:mutbuf, condition:u64) -> u64:
    if condition == 16:
        emit(o, w, 233)
    else:
        emit(o, w, 15)
        emit(o, w, 128 + condition)
    at = get(w, 0)
    little(o, w, 0, 4)
    return at

def failure_branch(o:mutbuf, w:mutbuf, condition:u64, status:u64) -> u64:
    at = branch_to(o, w, condition)
    index = get(w, 8)
    put(w, 16 + index * 16, at)
    put(w, 24 + index * 16, status)
    return put(w, 8, index + 1)

def failure(o:mutbuf, w:mutbuf, status:u64) -> u64:
    end = get(w, 0)
    index = 0
    count = get(w, 8)
    while index < count:
        if get(w, 24 + index * 16) == status:
            relative(o, get(w, 16 + index * 16), end)
        index = index + 1
    encode_data(o, w, 3, 0, 0, status << 32, 0, 0, 0)
    return epilogue(o, w)

def relative(o:mutbuf, at:u64, target:u64) -> u64:
    value = target - at - 4
    index = 0
    while index < 4:
        store(o, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def epilogue(o:mutbuf, w:mutbuf) -> u64:
    emit(o, w, 201)
    return emit(o, w, 195)
'''


def source_program():
    values = {'INPUT': INPUT, 'OUTPUT': OUTPUT, 'INVALID': INVALID,
              'OUTPUT_LIMIT': OUTPUT_BYTES, 'WORKSPACE_LIMIT': WORKSPACE_BYTES,
              'TYPE_COUNT': len(KINDS), 'FRAME_LIMIT': MAX_FRAME_BYTES, 'RANGE_LIMIT': MAX_RANGES,
              'EXTENT_LIMIT': MAX_EXTENT, 'U32_KIND': KINDS.index('u32') + 1,
              'BOOL_KIND': KINDS.index('bool') + 1}
    material = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), POLICY)
    shifts = ['def shift_code(kind:u64) -> u64:']
    for identifier, kind in enumerate(KINDS, 1):
        if kind in WIDTHS and WIDTHS[kind] < 64:
            code = 64 - WIDTHS[kind] + (64 if kind.startswith('i') else 0)
            shifts.extend((f'    if kind == {identifier}:', f'        return {code}'))
    shifts.append('    return 0')
    start, stop = ENCODING.index('\ndef encode_data('), ENCODING.index('\ndef encode_control(')
    primitives = ENCODING[ENCODING.index('\ndef rr('):]
    return '\n'.join((material, '\n'.join(shifts), ENCODING[start:stop], primitives))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
