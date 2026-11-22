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
    'SWAPPED_PROBE': b'\x4c\x8b\x94\x24\0\0\0\0',
    'SUB_IMM32': b'\x48\x81\xec',
    'SUB_IMM8': b'\x48\x83\xec',
    'PLAN_GATE': b'HIAILP02',
    'PLAN_LAYOUT': b'HIABLP02',
    'SELECT_LAYOUT': b'HIABLP03',
    'REGISTER_LAYOUT': b'HIABLP04',
}
POLICY = r'''
# Inspect the exact HIA ELF ET_REL with an optional projected machine layout.
# Output is text offset, extent and frame sizes in the admitted Core's order.
# This projects evidence from the sealed bytes; it never executes object code.
def lowering_elf(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = length(s)
    if n < 512 or length(o) < OUT_BYTES or length(w) < WORK_BYTES:
        return INVALID
    base = 0
    alignment = 1
    encoding = 8
    plan_count = 0
    permutation = 0
    if input_word(s, 0) == PLAN_GATE:
        extent = input_word(s, 8)
        if n < 608 or extent < 80 or extent > 8388608 or extent > n - 528:
            return INVALID
        tag = input_word(s, 16)
        select_layout = tag == SELECT_LAYOUT or tag == REGISTER_LAYOUT
        if (tag != PLAN_LAYOUT and select_layout == False) or input_word(s, 32) != extent:
            return INVALID
        header = choose(select_layout, 64, 56)
        plan_count = input_word(s, 24)
        if plan_count == 0 or plan_count > FN_LIMIT or header + plan_count * 24 > extent:
            return INVALID
        if select_layout and input_word(s, 72) > 1:
            return INVALID
        alignment = input_word(s, 40)
        if alignment != 1 and alignment != 16 and alignment != 32 and alignment != 64:
            return INVALID
        scratch = input_word(s, 48)
        narrow_move = input_word(s, 56)
        narrow_alu = input_word(s, 64)
        if scratch > 1 or narrow_move > 1 or narrow_alu > 1:
            return INVALID
        encoding = scratch | (narrow_alu << 1)
        permutation = 16 + header
        base = 16 + extent
        n = n - base
    if n > ELF_LIMIT:
        return INVALID
    if input_word(s, base) != ELF64_TAG or input_word(s, base + 8) != 0 or input_word(s, base + 16) != ELF64_REL:
        return INVALID
    if input_word(s, base + 24) != 0 or input_word(s, base + 32) != 0 or small(s, base + 48, 4) != 0:
        return INVALID
    if small(s, base + 52, 6) != 64 or small(s, base + 58, 6) != ELF64_SECTIONS:
        return INVALID
    relative_sections = input_word(s, base + 40)
    if relative_sections < 64 or relative_sections != n - 448 or relative_sections & 7 != 0:
        return INVALID
    sections = base + relative_sections
    text = sections + 64
    symbols = sections + 192
    names = sections + 256
    if small(s, text, 4) != 1 or small(s, text + 4, 4) != 1 or input_word(s, text + 8) != 6:
        return INVALID
    if input_word(s, text + 24) != 64 or input_word(s, text + 48) != choose(alignment >= 16, alignment, 16):
        return INVALID
    text_bytes = input_word(s, text + 32)
    if text_bytes < 20 or text_bytes > TEXT_LIMIT or text_bytes > relative_sections - 64:
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
    if sym_start < 64 + text_bytes or sym_start > relative_sections or sym_size > relative_sections - sym_start:
        return INVALID
    if name_start < sym_start + sym_size or name_start > relative_sections or name_size > relative_sections - name_start or name_size == 0:
        return INVALID
    remaining = sym_size
    while remaining >= 24:
        remaining = remaining - 24
    if remaining != 0:
        return INVALID
    # Clear only the actual row slots, so a reused private arena cannot imply
    # that an omitted internal function owned an old symbol's range.
    rows = first_global - 2
    if base != 0 and plan_count != rows:
        return INVALID
    return frame_inventory(s, o, w, base, alignment, encoding, text_bytes,
                           sym_start + base, name_start + base, name_start + base + name_size,
                           rows, permutation)

def frame_inventory(s:readbuf, o:mutbuf, w:mutbuf, base:u64, alignment:u64, encoding:u64, text_bytes:u64, symbols:u64, names:u64, names_end:u64, rows:u64, permutation:u64) -> u64:
    text_base = base + 64
    index = 0
    while index < rows:
        state_put(w, index * 16 + 8, 0)
        index = index + 1
    row = symbols + 48
    limit = row + rows * 24
    while row < limit:
        if frame_row(s, o, w, row, text_base, text_bytes, names, names_end, rows, encoding) == False:
            return INVALID
        row = row + 24
    index = 0
    cursor = 0
    while index < rows:
        original = index
        if permutation != 0:
            original = input_word(s, permutation + index * 8)
        if original >= rows:
            return INVALID
        offset = state_word(w, original * 16)
        size = state_word(w, original * 16 + 8)
        aligned = cursor + ((0 - cursor) & (alignment - 1))
        if size == 0 or offset != aligned:
            return INVALID
        while cursor < aligned:
            if byte(s, text_base + cursor) != 144:
                return INVALID
            cursor = cursor + 1
        state_put(w, original * 16 + 8, 0)
        cursor = offset + size
        index = index + 1
    state_put(o, 0, FACTS)
    state_put(o, 8, 64)
    state_put(o, 16, text_bytes)
    state_put(o, 24, rows)
    return 32 + rows * 8

def frame_row(s:readbuf, o:mutbuf, w:mutbuf, row:u64, text_base:u64, text_bytes:u64, names:u64, names_end:u64, rows:u64, encoding:u64) -> bool:
    name = small(s, row, 4)
    if small(s, row + 4, 4) != LOCAL_FUNCTION or name == 0 or name >= names_end - names:
        return False
    ordinal = function_ordinal(s, names + name, names_end, rows)
    if ordinal >= rows or state_word(w, ordinal * 16 + 8) != 0:
        return False
    start = input_word(s, row + 8)
    size = input_word(s, row + 16)
    if start >= text_bytes or size < 20 or size > text_bytes - start:
        return False
    frame = stack_frame(s, text_base + start, text_base + start + size, encoding)
    if frame == 0:
        return False
    state_put(o, 32 + ordinal * 8, frame)
    state_put(w, ordinal * 16, start)
    state_put(w, ordinal * 16 + 8, size)
    return True

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

def stack_frame(s:readbuf, at:u64, end:u64, encoding:u64) -> u64:
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
        if encoding < 8:
            if (opcode == SUB_IMM8) != (encoding & 2 != 0 and amount <= 127):
                return 0
        if input_word(s, probe) != choose(encoding & 1 == 0, PAGED_PROBE, SWAPPED_PROBE):
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
