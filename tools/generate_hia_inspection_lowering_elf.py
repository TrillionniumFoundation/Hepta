"""Author the native lowering observation of the selected canonical object."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import MAX_FUNCTIONS
from hepta.hia_program_native import MAX_ARTIFACT_BYTES, MAX_FRAME_BYTES, MAX_TEXT_BYTES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_effect import source_program as discovery
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/inspection_lowering_elf.hepta')
LIMITS = dict(ELF_LIMIT=MAX_ARTIFACT_BYTES, FRAME_LIMIT=MAX_FRAME_BYTES, TEXT_LIMIT=MAX_TEXT_BYTES,
              FN_LIMIT=MAX_FUNCTIONS, WORK_BYTES=16 * MAX_FUNCTIONS, OUT_BYTES=32 + 8 * MAX_FUNCTIONS)
LITERALS = {
    'ELF64_TAG': b'\x7fELF\x02\x01\x01\0',
    'FACTS': b'HIAILF01',
    'LOCAL_FUNCTION': b'\x02\x02\x01\x00',
    'ELF64_SECTIONS': b'@\x00\x07\x00\x05\x00',
    'ELF64_REL': b'\x01\x00>\x00\x01\x00\x00\x00',
    'NAME_HEAD': b'__hia_na',
    'NAME_TAIL': b'tive_fn_',
    'PROLOGUE': b'\x55\x48\x89\xe5',
    'PAGED_PROBE': b'\x4c\x8b\x9c\x24\0\0\0\0',
    'SUB_IMM32': b'\x48\x81\xec',
    'SUB_IMM8': b'\x48\x83\xec',
}
POLICY = r'''
# Inspect the exact HIA ELF ET_REL carrying the canonical machine image.
# Output is text offset, extent and frame sizes in the admitted Core's order.
# This projects evidence from the sealed bytes; it never executes object code.
def lowering_elf(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = length(s)
    if n < 512 or n > ELF_LIMIT or length(o) < OUT_BYTES or length(w) < WORK_BYTES:
        return INVALID
    if input_word(s, 0) != ELF64_TAG or input_word(s, 8) != 0 or input_word(s, 16) != ELF64_REL:
        return INVALID
    if input_word(s, 24) != 0 or input_word(s, 32) != 0 or small(s, 48, 4) != 0:
        return INVALID
    if small(s, 52, 6) != 64 or small(s, 58, 6) != ELF64_SECTIONS:
        return INVALID
    sections = input_word(s, 40)
    if sections < 64 or sections != n - 448 or sections & 7 != 0:
        return INVALID
    text = sections + 64
    symbols = sections + 192
    names = sections + 256
    if small(s, text, 4) != 1 or small(s, text + 4, 4) != 1 or input_word(s, text + 8) != 6:
        return INVALID
    if input_word(s, text + 24) != 64 or input_word(s, text + 48) != 16:
        return INVALID
    text_bytes = input_word(s, text + 32)
    if text_bytes < 20 or text_bytes > TEXT_LIMIT or text_bytes > sections - 64:
        return INVALID
    if small(s, symbols, 4) != 18 or small(s, symbols + 4, 4) != 2 or small(s, symbols + 40, 4) != 4:
        return INVALID
    if small(s, names, 4) != 26 or small(s, names + 4, 4) != 3 or input_word(s, symbols + 56) != 24:
        return INVALID
    sym_start = input_word(s, symbols + 24)
    sym_size = input_word(s, symbols + 32)
    first_global = small(s, symbols + 44, 4)
    name_start = input_word(s, names + 24)
    name_size = input_word(s, names + 32)
    if first_global < 3 or first_global > FN_LIMIT + 2 or sym_size > 1572864 or sym_size < (first_global + 1) * 24:
        return INVALID
    if sym_start < 64 + text_bytes or sym_start > sections or sym_size > sections - sym_start:
        return INVALID
    if name_start < sym_start + sym_size or name_start > sections or name_size > sections - name_start or name_size == 0:
        return INVALID
    remaining = sym_size
    while remaining >= 24:
        remaining = remaining - 24
    if remaining != 0:
        return INVALID
    # Clear only the actual row slots, so a reused private arena cannot imply
    # that an omitted internal function owned an old symbol's range.
    rows = first_global - 2
    index = 0
    while index < rows:
        state_put(w, index * 16 + 8, 0)
        index = index + 1
    index = 2
    while index < first_global:
        row = sym_start + index * 24
        name = small(s, row, 4)
        if small(s, row + 4, 4) != LOCAL_FUNCTION or name == 0 or name >= name_size:
            return INVALID
        ordinal = function_ordinal(s, name_start + name, name_start + name_size, rows)
        if ordinal >= rows or state_word(w, ordinal * 16 + 8) != 0:
            return INVALID
        start = input_word(s, row + 8)
        size = input_word(s, row + 16)
        if start >= text_bytes or size < 20 or size > text_bytes - start:
            return INVALID
        frame = stack_frame(s, 64 + start, 64 + start + size)
        if frame == 0:
            return INVALID
        state_put(o, 32 + ordinal * 8, frame)
        state_put(w, ordinal * 16, start)
        state_put(w, ordinal * 16 + 8, size)
        index = index + 1
    index = 0
    cursor = 0
    while index < rows:
        offset = state_word(w, index * 16)
        if offset != cursor:
            return INVALID
        cursor = offset + state_word(w, index * 16 + 8)
        index = index + 1
    state_put(o, 0, FACTS)
    state_put(o, 8, 64)
    state_put(o, 16, text_bytes)
    state_put(o, 24, rows)
    return 32 + rows * 8

def function_ordinal(s:readbuf, at:u64, end:u64, count:u64) -> u64:
    if end - at < 18 or input_word(s, at) != NAME_HEAD or input_word(s, at + 8) != NAME_TAIL:
        return count
    at = at + 16
    if byte(s, at) == 48 and byte(s, at + 1) != 0:
        return count
    ordinal = 0
    digits = 0
    while at < end and digits <= 4:
        unit = byte(s, at)
        if unit == 0:
            return choose(digits == 0, count, ordinal)
        if unit < 48 or unit > 57:
            return count
        ordinal = ordinal * 10 + unit - 48
        digits = digits + 1
        at = at + 1
    return count

def stack_frame(s:readbuf, at:u64, end:u64) -> u64:
    if small(s, at, 4) != PROLOGUE:
        return 0
    at = at + 4
    total = 0
    while at + 12 <= end:
        opcode = small(s, at, 3)
        if opcode != SUB_IMM32 and opcode != SUB_IMM8:
            return total
        immediate = choose(opcode == SUB_IMM32, 4, 1)
        probe = at + 3 + immediate
        if probe + 8 > end:
            return 0
        amount = small(s, at + 3, immediate)
        if amount == 0 or amount > 4096 or amount & 15 != 0 or amount > FRAME_LIMIT - total:
            return 0
        if input_word(s, probe) != PAGED_PROBE:
            return 0
        total = total + amount
        at = probe + 8
        if amount < 4096:
            if at + 3 <= end and (small(s, at, 3) == SUB_IMM32 or small(s, at, 3) == SUB_IMM8):
                return 0
            return total
    return 0

def small(s:readbuf, at:u64, count:u64) -> u64:
    index = 0
    value = 0
    while index < count:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value
'''


def source_program():
    values = {**LIMITS, **{name: int.from_bytes(raw, 'little') for name, raw in LITERALS.items()},
              'INVALID': 4294967293}
    policy = POLICY
    for name, value in values.items():
        policy = policy.replace(name, str(value))
    shared = discovery()
    return '\n'.join((policy, *(function(shared, name) for name in ('input_word', 'state_put', 'state_word'))))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
