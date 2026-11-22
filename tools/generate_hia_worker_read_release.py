"""Author the HIA final link of the four position-independent Read entries."""

from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.generate_hia_agent_stdio import document, writes
from tools.generate_hia_native_filter import bind_adapter, elf_header
from tools.generate_hia_worker_describe_reactor import program as entry_program
from tools.generate_hia_worker_inspection_effect import function

SOURCE = 'examples/hia_bootstrap/worker_read_release_packer.hepta'
ADAPTER = 'tools/hia_worker_read_entry.S'
MAGIC = b'HIARLF01'
ENTRIES = {
    'read': 'read_main_hole',
    'read-store': 'read_store_hole',
    'cost': 'read_cost_hole',
    'read-external': 'read_external_hole',
}


def source_packer(adapter):
    with TemporaryDirectory(prefix='hia-read-release-entry-') as temporary:
        stub, symbols, _ = assemble_adapter(Path(temporary), Path(ADAPTER).name, adapter)
    holes = tuple(symbols[label] for label in ENTRIES.values())
    if len(set(holes)) != len(holes) or any(
            not 0 < at <= len(stub) - 4 or stub[at - 1:at + 4] != b'\xe9\0\0\0\0'
            for at in holes):
        raise ValueError('invalid Read entry jump placement')
    header = elf_header()
    prefix = header + stub
    lengths_end = 8 * (1 + len(holes))
    source = f'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) <= {lengths_end} or length(s) > 1048576 or input_word(s, 0) != {int.from_bytes(MAGIC, 'little')}:
        return 4294967295
    if length(o) < {len(prefix)}:
        return 4294967294
    emit_prefix(o)
    source_at = {lengths_end}
    cursor = {len(prefix)}
'''
    for ordinal, hole in enumerate(holes, 1):
        source += f'''
    begin = align_entry(o, cursor)
    amount = input_word(s, {8 * ordinal})
    if amount == 0 or amount > length(s) - source_at or begin > length(o) or amount > length(o) - begin:
        return 4294967294
    put_four(o, {len(header) + hole}, begin - {len(header) + hole + 4})
    copy_bytes(s, o, source_at, begin, amount)
    source_at = source_at + amount
    cursor = begin + amount
'''
    source += f'''
    if source_at != length(s):
        return 4294967295
    put(o, 96, cursor)
    put(o, 104, cursor)
    return cursor

def align_entry(o:mutbuf, at:u64) -> u64:
    aligned = ((at - {len(header)} + 7) & 18446744073709551608) + {len(header)}
    while at < aligned and at < length(o):
        store(o, at, 0)
        at = at + 1
    return aligned

def copy_bytes(s:readbuf, o:mutbuf, src:u64, dest:u64, extent:u64) -> u64:
    index = 0
    while index < extent:
        store(o, dest + index, byte(s, src + index))
        index = index + 1
    return extent

def put_four(o:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(o, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def put_word(o:mutbuf, at:u64, value:u64) -> u64:
    return put(o, at, value)

def emit_prefix(o:mutbuf) -> u64:
'''
    source += writes(prefix) + '    return 0\n'
    entry = entry_program()
    source += ''.join(function(entry, name) for name in ('input_word', 'put', 'write'))
    asm = document(source, Path(SOURCE).stem)
    return bind_adapter(asm, adapter, stub, holes)


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(source_packer(Path(ADAPTER).read_bytes())), encoding='utf-8')
