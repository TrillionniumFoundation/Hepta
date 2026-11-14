"""Independent fixed Linux-entry adapter to the existing HIA ELF linker.

The inherited parser, symbol resolver, relocation checks and RX/RW/NX layout
remain byte-for-byte SOURCE. Only the new packet's three-object/_start admission
and direct e_entry replace the original zero-argument C startup profile.
This file has not been imported, generated, compiled, linked, or executed.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools import generate_hia_elf_linker as original

ORIGINAL_AUTHOR_SHA256 = 'cc57ae400052a47aa9861606eb9681e585d20b19a9b1f0a29fbc30b849a4071d'
MAGIC = int.from_bytes(b'HIAPGLK2', 'little')
REPLACEMENTS = (
    (
        '    if count == 0 or count > 64 or name == 0 or name > 4096 or name > length(s) - 32:\n'
        '        return 4294967295\n',
        '    if count != 3 or name != 6 or name > length(s) - 32:\n'
        '        return 4294967295\n'
        '    if uint(s, 32, 6) != ' + str(int.from_bytes(b'_start', 'little')) + ':\n'
        '        return 4294967295\n',
    ),
    (
        '    if symbols(s, w) == 0:\n'
        '        return 4294967295\n',
        '    if symbols(s, w) == 0 or get(w, 24) != 3:\n'
        '        return 4294967295\n',
    ),
    (
        '    put(o, 24, 4194536)\n',
        '    put(o, 24, 4194304 + get(w, 88))\n',
    ),
    (
        '    # SysV zero-argument entry, scalar result -> Linux exit status.\n'
        '    write(o, 232, 264864245804337, 6)\n'
        '    store(o, 238, 232)\n'
        '    write(o, 239, get(w, 88) - 243, 4)\n'
        '    write(o, 243, 260798122312, 8)\n'
        '    write(o, 251, 185533711, 4)\n',
        '    # Linux initial-stack entry is the resolved _start itself.\n'
        '    # Header padding 232..255 stays zero; no C-call startup is emitted.\n',
    ),
)

def source_program():
    raw = Path(original.__file__).read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_AUTHOR_SHA256:
        raise ValueError('original HIA ELF author changed')
    source = original.SOURCE
    for before, after in REPLACEMENTS:
        if source.count(before) != 1:
            raise ValueError('nonunique original linker delta')
        source = source.replace(before, after, 1)
    inverse = source
    for before, after in reversed(REPLACEMENTS):
        if inverse.count(after) != 1:
            raise ValueError('nonunique inverse linker delta')
        inverse = inverse.replace(after, before, 1)
    if inverse != original.SOURCE:
        raise ValueError('linker inverse projection differs')
    return source.replace('MAGIC', str(MAGIC))

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f'+str(index) for index,node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                             node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = original.LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read','write','trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8',
        'module':'pager_fixed_linux_elf_linker', 'functions':functions})

def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(render_assembly(document()))

if __name__ == '__main__':
    main()
