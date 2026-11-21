"""Embed the syscall transport and admit the three cold HIA image placements."""
from __future__ import annotations

import ast
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE
from tools.generate_hia_native_filter import bind_adapter, elf_header
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = 'tools/hia_safe_core_binder_syscalls.S'
PACKER = 'examples/hia_bootstrap/safe_core_binder_packer.hepta'
CALLS = {name: name + '_call_hole' for name in ('binder', 'elf', 'wire')}
MAGIC = b'HIAEBPK1'

PACK = '''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or length(s) > 1048576 or uint(s, 0, 8) != MAGIC:
        return 4294967295
    a = uint(s, 8, 8)
    b = uint(s, 16, 8)
    c = uint(s, 24, 8)
    if a == 0 or b == 0 or c == 0 or a > length(s) - 32:
        return 4294967295
    if b > length(s) - 32 - a or c != length(s) - 32 - a - b:
        return 4294967295
    first = (PREFIX + 7) & (0 - 8)
    second = (first + a + 7) & (0 - 8)
    third = (second + b + 7) & (0 - 8)
    size = third + c
    if size > 1048576 or length(o) < size:
        return 4294967294
    envelope(o)
    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, FIRST_HOLE, first - FIRST_HOLE - 4, 4)
    write(o, SECOND_HOLE, second - SECOND_HOLE - 4, 4)
    write(o, THIRD_HOLE, third - THIRD_HOLE - 4, 4)
    clear(o, PREFIX, first)
    clear(o, first + a, second)
    clear(o, second + b, third)
    copy_bytes(s, o, 32, first, a)
    copy_bytes(s, o, 32 + a, second, b)
    copy_bytes(s, o, 32 + a + b, third, c)
    return size

def clear(o:mutbuf, start:u64, end:u64) -> u64:
    i = start
    while i < end:
        store(o, i, 0)
        i = i + 1
    return 0
'''


PROOF_PACKER = 'examples/hia_bootstrap/safe_core_obligation_packer.hepta'


def adapter_source(raw, *, proof=False):
    return b'.set proof_transport, 1\n' + raw if proof else raw


def document(*, proof=False):
    adapter = adapter_source((ROOT / ADAPTER).read_bytes(), proof=proof)
    with TemporaryDirectory(prefix='hia-elf-binder-transport-') as temporary:
        stub, holes, _ = adapter_layout(Path(temporary), ADAPTER, adapter, CALLS)
    header = elf_header()
    prefix = header + stub
    ordered = tuple(holes.values())
    source = PACK
    for name, value in dict(MAGIC=int.from_bytes(MAGIC, 'little'), PREFIX=len(prefix),
                            FIRST_HOLE=len(header) + ordered[0], SECOND_HOLE=len(header) + ordered[1],
                            THIRD_HOLE=len(header) + ordered[2]).items():
        source = source.replace(name, str(value))
    source += '\ndef envelope(o:mutbuf) -> u64:\n'
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        source += f"    write(o, {at}, {int.from_bytes(chunk, 'little')}, {len(chunk)})\n"
    source += '    return 0\n'
    source += LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    nodes = ast.parse(source).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    scalar = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, scalar)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    packer = compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': ('safe_core_obligation_packer' if proof else 'safe_core_binder_packer'),
                                   'functions': functions})
    return bind_adapter(packer, adapter, stub, ordered)


if __name__ == '__main__':
    (ROOT / PACKER).write_text(render_assembly(document()))
    (ROOT / PROOF_PACKER).write_text(render_assembly(document(proof=True)))
