"""Author retained ELF import facts for native Worker build receipts."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program_native import IMPORTS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_inspection_lowering_elf import LIMITS, source_program as lowering

SOURCE = Path('examples/hia_bootstrap/worker_object_imports.hepta')

POLICY = r'''
# Check the table geometry and internal frame rows before projecting imports.
def object_imports(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if lowering_elf(s, o, w) > LOWERING_OUTPUT:
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
    return write_imports(o, imported)
'''


def program():
    head = POLICY.replace('LOWERING_OUTPUT', str(LIMITS['OUT_BYTES'])).replace('INVALID', '4294967293')
    imports = tuple(sorted(IMPORTS))
    dispatch = ['def allowed_import(s:readbuf, at:u64, end:u64) -> u64:']
    render = ['def write_imports(o:mutbuf, flags:u64) -> u64:', '    store(o, 0, 91)', '    at = 1']
    for index, name in enumerate(imports):
        raw = name.encode('ascii') + b'\0'
        dispatch.extend((
            f'    if end - at >= {len(raw)} and small(s, at, {len(raw)}) == {int.from_bytes(raw, "little")}:',
            f'        return {1 << index}',
        ))
        render.extend((
            f'    if flags & {1 << index} != 0:',
            '        if at != 1:',
            '            store(o, at, 44)',
            '            at = at + 1',
        ))
        literal = ('"' + name + '"').encode('ascii')
        render.extend(f'        store(o, at + {at}, {digit})' for at, digit in enumerate(literal))
        render.append(f'        at = at + {len(literal)}')
    dispatch.append('    return 0')
    render.extend(('    store(o, at, 93)', '    return at + 1'))
    geometry = lowering().replace('w:mutbuf) -> u32:', 'w:mutbuf) -> u64:', 1)
    return '\n'.join((head, '\n'.join(dispatch), '\n'.join(render), geometry))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
