"""Author the HIA ELF packer and its exact transport identity."""
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.generate_hia_native_filter import bind_adapter, elf_header
from tools.generate_hia_safe_core_binder import document as transport_document

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = 'tools/hia_supplied_safe_core_proof_syscalls.S'
PACKER = 'examples/hia_bootstrap/supplied_safe_core_proof_packer.hepta'
MAGIC = int.from_bytes(b'HIAPKP01', 'little')
# Seven individually bounded components plus the aligned, package-pinned transport.
PACK_LIMIT = 8 << 20
PACK_HEAD = 64
ROLE_TABLE = 80
CALLS = ('proof_policy_hole', 'proof_hash_hole')

SOURCE = '''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) <= PACK_HEAD or length(s) > PACK_HEAD + PACK_LIMIT:
        return 4294967295
    if uint(s, 0, 8) != MAGIC:
        return 4294967295
    size = extent(s)
    if size == 0 or size > PACK_LIMIT or size > length(o):
        return 4294967294
    envelope(o)
    put(o, 96, size)
    put(o, 104, size)
    index = 0
    at = PREFIX
    source = PACK_HEAD
    while index < 7:
        aligned = (at + 7) & (0 - 8)
        clear(o, at, aligned)
        at = aligned
        piece = uint(s, 8 + index * 8, 8)
        if index == 0:
            write(o, POLICY, at - POLICY - 4, 4)
        elif index == 1:
            write(o, HASH, at - HASH - 4, 4)
        else:
            entry = TABLE + 16 * (index - 2)
            put(o, entry, at - TABLE)
            put(o, entry + 8, piece)
        copy_bytes(s, o, source, at, piece)
        source = source + piece
        at = at + piece
        index = index + 1
    return size

def extent(s:readbuf) -> u64:
    index = 0
    at = PREFIX
    source = PACK_HEAD
    while index < 7:
        piece = uint(s, 8 + index * 8, 8)
        if piece == 0 or piece > 1048576 or piece > length(s) - source:
            return 0
        source = source + piece
        at = ((at + 7) & (0 - 8)) + piece
        index = index + 1
    if source != length(s):
        return 0
    return at

def clear(o:mutbuf, start:u64, end:u64) -> u64:
    i = start
    while i < end:
        store(o, i, 0)
        i = i + 1
    return 0

def copy_bytes(s:readbuf, o:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(s, source + i))
        i = i + 1
    return 0
'''


def document():
    adapter = (ROOT / ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-proof-transport-') as temporary:
        stub, symbols, _ = assemble_adapter(Path(temporary), ADAPTER, adapter)
    holes = tuple(symbols[name] for name in CALLS)
    table = symbols['embedded_roles']
    if table % 8 or stub[table:table + ROLE_TABLE] != bytes(ROLE_TABLE):
        raise ValueError('invalid supplied Safe Core component table')
    if len(set(holes)) != 2 or any(stub[hole-1:hole+4] != b'\xe8\0\0\0\0' for hole in holes):
        raise ValueError('invalid HIA supplied-proof call placement')
    header = elf_header()
    prefix = header + stub
    constants = dict(PREFIX=len(prefix), TABLE=len(header)+table,
                     POLICY=len(header)+holes[0], HASH=len(header)+holes[1],
                     PACK_LIMIT=PACK_LIMIT, PACK_HEAD=PACK_HEAD, MAGIC=MAGIC)
    source = SOURCE + '\ndef envelope(o:mutbuf) -> u64:\n'
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        source += f"    write(o, {at}, {int.from_bytes(chunk, 'little')}, {len(chunk)})\n"
    source += '    return 0\n'
    return bind_adapter(transport_document(source, module='supplied_safe_core_proof_packer', extra=constants),
                        adapter, stub, (*holes, table))


if __name__ == '__main__':
    (ROOT / PACKER).write_text(render_assembly(document()))
