"""Author a HIA packer for a bounded syscall-only native byte-ABI observer.

The literal instruction stream is the audited Linux/SysV runtime adapter in
hia_native_observer_template.S, not compiled user code. That assembly reference
is NOT assembled by the build. The generated HIA function emits ELF headers and
all adapter bytes. Actual observers are produced by executing that HIA packer
with an already self-compiled HIA compiler; no Python runtime or dynamic loader
runs inside an observer child. Host supervision/oracles still remain Python.
"""
from __future__ import annotations
import ast
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ADAPTER = bytes.fromhex(
    '48833c24010f85280300004881ec00010000bf0400000031f6b89d0000000f05'
    '4885c00f8503030000bf03000000b89d0000000f054885c00f85ee020000bf04'
    '00000031f6e865020000bf00000000be0a000000e856020000bf09000000be00'
    '000010e847020000bf03000000be00008000e838020000bf01000000be000000'
    '01e829020000bf07000000be20000000e81a020000be00006000e83302000049'
    '89c431db31c031ff498d341cba310050004829da0f054883f8fc74e84885c00f'
    '886702000074124801c34881fb300050000f874e020000ebcb4883fb300f823b'
    '02000048b84849414f42533031493904240f8527020000498b4424084885c00f'
    '8419020000483d000040000f870d0200004889442410498b4c24104881f90000'
    '10000f87f601000048894c24184801c84883c0304839d80f85e1010000498b44'
    '2418483d000010000f87d00100004889442420498b442420483d000010000f87'
    'ba010000488944242849817c2428ff0000000f87a6010000488b742410e85001'
    '00004989c54889c7498d742430488b4c2410fcf3a44c89ef488b742410ba0500'
    '0000b80a0000000f054885c00f857a010000be00002000e8160100004989c64c'
    '8db8000010004c89f7488b4c2420b0a5f3aa4c89ff488b4c2428418a442428f3'
    'aabf01000000488d742440b8e40000000f054885c00f8531010000488b7c2410'
    '498d7c3c30488b7424184c89f2488b4c24204d89f84c8b4c242841ffd5488944'
    '2468bf01000000488d742450b8e40000000f054885c00f85f0000000488b4424'
    '50482b4424404869c000ca9a3b4803442458482b442448488944247048b84849'
    '414f425230314889442460488d742460ba18000000e87f000000488b74241049'
    '8d743430488b542418e86b0000004c89f6488b542420e85e0000004c89fe488b'
    '542428e85100000031ffe98900000048897424f048897424f889fe31ff488d54'
    '24f04531d2b82e0100000f054885c0755bc331ffba0300000041ba2200000049'
    'c7c0ffffffff4531c9b8090000000f05483d01f0ffff7334c34885d2741fb801'
    '000000bf010000000f054883f8fc74e94885c07e174801c64829c2ebdcc3bf02'
    '000000eb13bf03000000eb0cbf04000000eb05bf40000000b83c0000000f050f'
    '0b'
)


def reference_image():
    size = 176 + len(ADAPTER)
    header = b'\x7fELF\x02\x01\x01' + bytes(9)
    header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x400000 + 176, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    header += struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
    header += struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    return header + ADAPTER


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
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'native_observer_packer','functions':functions})


def main():
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/native_observer_packer.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
