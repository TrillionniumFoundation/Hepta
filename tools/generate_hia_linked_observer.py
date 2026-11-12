"""Author a HIA emitter for a system-dlopen byte-ABI observer.

The fixed machine adapter is separately audited in the accompanying assembly
reference. It is an operating-system ABI adapter, not a replacement ELF loader:
the actual supplied shared object goes through system dlopen(RTLD_NOW) and
dlsym("f0") in a new process. The build runs the HIA emitter. The Python image
builder is the independent authoring/VM reference, never an activated child.
"""
from __future__ import annotations

import ast
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ADAPTER = bytes.fromhex(
    '48833c24010f856f0400004881ec00010000bf0400000031f6b89d0000000f054885c00f8543040000bf03000000b89d'
    '0000000f054885c00f852e040000bf0400000031f6e8a5030000bf00000000be0a000000e896030000bf09000000be00'
    '000010e887030000bf03000000be00008000e878030000bf01000000be00000001e869030000bf07000000be20000000'
    'e85a030000be00006000e8730300004989c431db31c031ff498d341cba390050004829da0f054883f8fc74e84885c00f'
    '88a703000074124801c34881fb380050000f878e030000ebcb4883fb380f827b03000048b84849414c44533031493904'
    '240f8567030000498b4424084885c00f8459030000483d000040000f874d0300004889442410498b4c24104881f90000'
    '10000f873603000048894c24184801c84883c0384839d80f8521030000498b442418483d000010000f87100300004889'
    '442420498b442420483d000010000f87fa020000488944242849817c2428ff0000000f87e6020000498b4424304883f8'
    'ff74164883f8030f82d1020000483dffffff7f0f87c5020000488d3de8020000be02000000b83f0100000f054885c00f'
    '88b70200004889442478498d742438488b542410488b7c2478b8010000000f054883f8fc74ee4885c00f8e8d02000048'
    '01c64829c275dd488b7c2478be09040000ba0f000000b8480000000f054885c00f8566020000488b7c2478be0a040000'
    '31d2b8480000000f054885c00f884a02000083e00f83f80f0f853e020000488dbc24a0000000488d3560020000b90e00'
    '0000fcf3a4488b44247831d2b90a00000048f7f14885c074030430aa89d00430aa31c0aa488dbc24a0000000be020000'
    '00ff15891300004885c00f84f30100004889c7488d3521020000ff15781300004885c00f84da0100004989c5488b7c24'
    '78b8030000000f054885c00f85bb010000be00001000e8570100004989c7488b7424204885f6750348ffc64d8b442430'
    '4983f8ff7516e8370100004989c64c89f7488b4c2420b0a5f3aaeb2631ffba0300000041ba010000004531c9b8090000'
    '000f05483d01f0ffff0f835d0100004989c64c89ff488b4c2428418a442428f3aabf01000000488d742440b8e4000000'
    '0f054885c00f8531010000488b7c2410498d7c3c38488b7424184c89f2488b4c24204d89f84c8b4c242841ffd5488944'
    '2468bf01000000488d742450b8e40000000f054885c00f85f0000000488b442450482b4424404869c000ca9a3b480344'
    '2458482b442448488944247048b84849414c445230314889442460488d742460ba18000000e87f000000488b74241049'
    '8d743438488b542418e86b0000004c89f6488b542420e85e0000004c89fe488b542428e85100000031ffe99000000048'
    '897424f048897424f889fe31ff488d5424f04531d2b82e0100000f054885c0755bc331ffba0300000041ba2200000049'
    'c7c0ffffffff4531c9b8090000000f05483d01f0ffff7334c34885d2741fb801000000bf010000000f054883f8fc74e9'
    '4885c07e174801c64829c2ebdcc3bf02000000eb1abf03000000eb13bf04000000eb0cbf05000000eb05bf40000000b8'
    '3c0000000f050f0b6869612d6c696e6b65642d737563636573736f72002f70726f632f73656c662f66642f663000'
)


def reference_image():
    # The two PT_LOAD mappings have distinct virtual pages. Their file-page
    # overlap is private (as in ordinary ELF segment packing), so relocations
    # cannot alter the RX mapping. RELRO covers the complete writable page.
    base, code_at, data_at, data_address = 0x400000, 512, 2048, 0x401800
    interpreter = b'/lib64/ld-linux-x86-64.so.2\0'
    ph_count = 7
    interp_at = 64 + ph_count * 56
    image = bytearray(code_at)
    image[interp_at:interp_at + len(interpreter)] = interpreter
    image.extend(ADAPTER)

    def append(raw, alignment=8):
        image.extend(bytes((-len(image)) % alignment))
        at = len(image)
        image.extend(raw)
        return at

    strings = b'\0libdl.so.2\0dlopen\0dlsym\0'
    string_at = append(strings)
    symbols = bytes(24)
    for name in (b'dlopen', b'dlsym'):
        symbols += struct.pack('<IBBHQQ', strings.index(name), 0x12, 0, 0, 0, 0)
    symbol_at = append(symbols)
    hash_at = append(struct.pack('<6I', 1, 3, 1, 0, 2, 0))
    reloc_at = append(b''.join(struct.pack('<QQq', data_address + i * 8,
        ((i + 1) << 32) | 6, 0) for i in range(2)))
    text_end = len(image)
    if text_end > data_at:
        raise AssertionError('fixed adapter crossed the separate writable page')
    image.extend(bytes(data_at - len(image)))
    image.extend(bytes(16))
    dynamic_at = len(image)
    dynamic = [(1, 1), (4, base + hash_at), (5, base + string_at),
        (6, base + symbol_at), (10, len(strings)), (11, 24),
        (7, base + reloc_at), (8, 48), (9, 24), (24, 0), (30, 8), (0, 0)]
    image.extend(b''.join(struct.pack('<QQ', tag, value) for tag, value in dynamic))
    data_bytes = len(image) - data_at

    image[:64] = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, base + code_at, 64, 0, 0,
            64, 56, ph_count, 0, 0, 0))
    headers = [
        (6, 4, 64, base + 64, base + 64, ph_count * 56, ph_count * 56, 8),
        (3, 4, interp_at, base + interp_at, base + interp_at,
            len(interpreter), len(interpreter), 1),
        (1, 5, 0, base, base, text_end, text_end, 4096),
        (1, 6, data_at, data_address, data_address, data_bytes, 2048, 4096),
        (2, 6, dynamic_at, data_address + 16, data_address + 16,
            len(dynamic) * 16, len(dynamic) * 16, 8),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16),
        (0x6474e552, 4, data_at, data_address, data_address,
            data_bytes, 2048, 1),
    ]
    image[64:64 + ph_count * 56] = b''.join(struct.pack('<IIQQQQQQ', *row) for row in headers)
    return bytes(image)


def source_program():
    image = reference_image()
    lines = ['def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        '    if length(s) != 0:', '        return 4294967295',
        '    if length(o) < ' + str(len(image)) + ':', '        return 4294967294',
        '    at = 0', '    while at < ' + str(len(image)) + ':',
        '        store(o, at, 0)', '        at = at + 1']
    for offset in range(0, len(image), 8):
        word = image[offset:offset + 8]
        if any(word):
            lines.append('    word(o, ' + str(offset) + ', '
                + str(int.from_bytes(word, 'little')) + ', ' + str(len(word)) + ')')
    lines += ['    return ' + str(len(image)), '',
        'def word(o:mutbuf, at:u64, value:u64, count:u64) -> u64:',
        '    i = 0', '    while i < count:',
        '        store(o, at + i, value & 255)', '        value = value >> 8',
        '        i = i + 1', '    return 0']
    return '\n'.join(lines) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
        for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'linked_observer_packer', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/linked_observer_packer.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
