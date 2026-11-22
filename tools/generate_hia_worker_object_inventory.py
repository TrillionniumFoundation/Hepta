"""Author retained ELF symbol inventory for native Worker build receipts."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program_native import IMPORTS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_inspection_lowering_elf import LIMITS, source_program as lowering

SOURCE = Path('examples/hia_bootstrap/worker_object_inventory.hepta')

POLICY = r'''
# Check the table geometry and internal frame rows before projecting imports.
def object_imports(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 32768 or lowering_elf(s, o, w) > LOWERING_OUTPUT:
        return INVALID
    sections = input_word(s, 40)
    symbols = sections + 192
    strings = sections + 256
    start = input_word(s, symbols + 24)
    end = start + input_word(s, symbols + 32)
    names = input_word(s, strings + 24)
    names_end = names + input_word(s, strings + 32)
    row = start + small(s, symbols + 44, 4) * 24
    imported = 0
    while row < end:
        name = names + small(s, row, 4)
        if name <= names or name >= names_end:
            return INVALID
        section = small(s, row + 6, 2)
        symbol = small(s, row + 4, 2)
        if section == 0:
            if symbol != 16 or input_word(s, row + 8) != 0 or input_word(s, row + 16) != 0:
                return INVALID
            flag = allowed_import(s, name, names_end)
            if flag == 0 or imported & flag != 0:
                return INVALID
            imported = imported | flag
        elif section != 1 or symbol != 18:
            return INVALID
        row = row + 24
    return write_inventory(s, o, start + small(s, symbols + 44, 4) * 24, end, imported)

def write_inventory(s:readbuf, o:mutbuf, row:u64, end:u64, imports:u64) -> u64:
    sections = input_word(s, 40)
    text_bytes = input_word(s, sections + 96)
    names = input_word(s, sections + 280)
    names_end = names + input_word(s, sections + 288)
    at = defined_prefix(o, 0)
    count = 0
    previous = 0
    while row < end:
        if small(s, row + 6, 2) == 1:
            name = names + small(s, row, 4)
            size = name_size(s, name, names_end)
            offset = input_word(s, row + 8)
            width = input_word(s, row + 16)
            if size == 0 or count == 128 or offset >= text_bytes or width == 0 or width > text_bytes - offset:
                return INVALID
            if count != 0:
                if name_after(s, previous, name) == False:
                    return INVALID
                store(o, at, 44)
                at = at + 1
            at = write_name(s, o, name, size, at)
            count = count + 1
            previous = name
        row = row + 24
    if count == 0:
        return INVALID
    return write_imports(o, undefined_prefix(o, at), imports)

def name_size(s:readbuf, at:u64, end:u64) -> u64:
    size = 0
    while at + size < end and size <= 128:
        unit = byte(s, at + size)
        if unit == 0:
            return size
        letter = unit == 95 or (unit >= 65 and unit <= 90) or (unit >= 97 and unit <= 122)
        if letter == False and (size == 0 or unit < 48 or unit > 57):
            return 0
        size = size + 1
    return 0

def name_after(s:readbuf, prior:u64, current:u64) -> bool:
    index = 0
    while index <= 128:
        old = byte(s, prior)
        new = byte(s, current)
        if old != new or new == 0:
            return old < new
        prior = prior + 1
        current = current + 1
        index = index + 1
    return False

def write_name(s:readbuf, o:mutbuf, name:u64, size:u64, at:u64) -> u64:
    store(o, at, 34)
    index = 0
    while index < size:
        store(o, at + index + 1, byte(s, name + index))
        index = index + 1
    store(o, at + size + 1, 34)
    return at + size + 2
'''


def program():
    head = POLICY.replace('LOWERING_OUTPUT', str(LIMITS['OUT_BYTES'])).replace('INVALID', '4294967293')
    imports = tuple(sorted(IMPORTS))
    dispatch = ['def allowed_import(s:readbuf, at:u64, end:u64) -> u64:']
    render = ['def write_imports(o:mutbuf, at:u64, flags:u64) -> u64:', '    first = at']
    for index, name in enumerate(imports):
        raw = name.encode('ascii') + b'\0'
        dispatch.extend((
            f'    if end - at >= {len(raw)} and small(s, at, {len(raw)}) == {int.from_bytes(raw, "little")}:',
            f'        return {1 << index}',
        ))
        render.extend((
            f'    if flags & {1 << index} != 0:',
            '        if at != first:',
            '            store(o, at, 44)',
            '            at = at + 1',
        ))
        literal = ('"' + name + '"').encode('ascii')
        render.extend(f'        store(o, at + {at}, {digit})' for at, digit in enumerate(literal))
        render.append(f'        at = at + {len(literal)}')
    dispatch.append('    return 0')
    render.extend(('    store(o, at, 93)', '    store(o, at + 1, 125)', '    return at + 2'))
    literals = []
    for name, value in (('defined_prefix', '{"defined":['), ('undefined_prefix', '],"undefined":[')):
        literals.append(f'def {name}(o:mutbuf, at:u64) -> u64:')
        literals.extend(f'    store(o, at + {index}, {ord(unit)})' for index, unit in enumerate(value))
        literals.append(f'    return at + {len(value)}')
    geometry = lowering().replace('w:mutbuf) -> u32:', 'w:mutbuf) -> u64:', 1)
    return '\n'.join((head, '\n'.join(dispatch), '\n'.join(render), '\n'.join(literals), geometry))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
