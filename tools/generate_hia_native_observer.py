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
    '48833c24010f858a0300004881ec00010000bf0400000031f6b89d0000000f05'
    '4885c00f8565030000bf03000000b89d0000000f054885c00f8550030000bf04'
    '00000031f6e8c7020000bf00000000be0a000000e8b8020000bf09000000be00'
    '000010e8a9020000bf03000000be00008000e89a020000bf01000000be000000'
    '01e88b020000bf07000000be20000000e87c020000be00006000e89502000049'
    '89c431db31c031ff498d341cba390050004829da0f054883f8fc74e84885c00f'
    '88c902000074124801c34881fb380050000f87b0020000ebcb4883fb380f829d'
    '02000048b84849414f42533032493904240f8589020000498b4424084885c00f'
    '847b020000483d000040000f876f0200004889442410498b4c24104881f90000'
    '10000f875802000048894c24184801c84883c0384839d80f8543020000498b44'
    '2418483d000010000f87320200004889442420498b442420483d000010000f87'
    '1c020000488944242849817c2428ff0000000f8708020000498b4424304883f8'
    'ff74164883f8030f82f3010000483dffffff7f0f87e7010000488b742410e891'
    '0100004989c54889c7498d742438488b4c2410fcf3a44c89ef488b742410ba05'
    '000000b80a0000000f054885c00f85bb010000be00001000e8570100004989c7'
    '488b7424204885f6750348ffc64d8b4424304983f8ff7516e8370100004989c6'
    '4c89f7488b4c2420b0a5f3aaeb2631ffba0300000041ba010000004531c9b809'
    '0000000f05483d01f0ffff0f835d0100004989c64c89ff488b4c2428418a4424'
    '28f3aabf01000000488d742440b8e40000000f054885c00f8531010000488b7c'
    '2410498d7c3c38488b7424184c89f2488b4c24204d89f84c8b4c242841ffd548'
    '89442468bf01000000488d742450b8e40000000f054885c00f85f0000000488b'
    '442450482b4424404869c000ca9a3b4803442458482b442448488944247048b8'
    '4849414f425230324889442460488d742460ba18000000e87f000000488b7424'
    '10498d743438488b542418e86b0000004c89f6488b542420e85e0000004c89fe'
    '488b542428e85100000031ffe98900000048897424f048897424f889fe31ff48'
    '8d5424f04531d2b82e0100000f054885c0755bc331ffba0300000041ba220000'
    '0049c7c0ffffffff4531c9b8090000000f05483d01f0ffff7334c34885d2741f'
    'b801000000bf010000000f054883f8fc74e94885c07e174801c64829c2ebdcc3'
    'bf02000000eb13bf03000000eb0cbf04000000eb05bf40000000b83c0000000f'
    '050f0b'
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
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/native_observer_packer.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
