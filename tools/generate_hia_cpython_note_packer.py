"""Author the fixed CPython note/delivery adapter with an HIA byte packer.

The HIA program emits every byte of the bounded SysV AMD64 mechanism. Production
emission requires no C compiler, assembler, linker, Python source evaluation, or
target-source input inside the emitted code. The independent .S reference is a
test oracle only. The mechanism still calls four explicitly pinned CPython
functions; it is not a standalone interpreter or an HIA JSON policy owner.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

# Audited fixed mechanism, independently assembled from the reference in tests.
# SysV: api, error, kind, container, key, signed index.
ADAPTER = bytes.fromhex(
    '4885ff0f84ca0000004885f60f84c10000004883fa010f82b70000004883fa04'
    '0f87ad0000004883fa02750b4d85c90f889e000000eb1d4d85c90f8593000000'
    '4883fa04750e4885c90f85840000004d85c0757f555341544155415641574883'
    'ec084c89cd4889d34989fc4989f54989ce4d89c74c89ef41ff14244c89ef41ff'
    '54240883fb04743a4c89f683fb01740e83fb027415488d3d73000000eb164c89'
    'fa488d3d2e000000eb0a4889ea488d3d3e00000031c041ff54241841ff542410'
    'eb0231c04883c408415f415e415d415c5b5dc331c0c37768656e207365726961'
    '6c697a696e67202554206974656d202552007768656e2073657269616c697a69'
    '6e67202554206974656d20257a64007768656e2073657269616c697a696e6720'
    '2554206f626a65637400'
)


def reference_image():
    return ADAPTER


def source_program():
    image = reference_image()
    lines = ['def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
             '    if length(s) != 0:', '        return 4294967295',
             '    if length(o) < '+str(len(image))+':', '        return 4294967294']
    for offset in range(0, len(image), 8):
        word = image[offset:offset+8]
        lines.append('    word(o, '+str(offset)+', '+str(int.from_bytes(word, 'little'))+', '+str(len(word))+')')
    lines += ['    return '+str(len(image)), '',
        'def word(o:mutbuf, at:u64, value:u64, count:u64) -> u64:',
        '    i = 0', '    while i < count:',
        '        store(o, at + i, value & 255)', '        value = value >> 8',
        '        i = i + 1', '    return 0']
    return '\n'.join(lines)+'\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures = {node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'cpython_note_packer','functions':functions})


def main():
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/cpython_note_packer.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
