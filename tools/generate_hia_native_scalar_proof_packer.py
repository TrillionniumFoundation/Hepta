"""HIA packer for the fixed native scalar-proof transport and nine HIA roles."""
from pathlib import Path
from tempfile import TemporaryDirectory
from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.generate_hia_native_filter import bind_adapter,elf_header
from tools.generate_hia_safe_core_binder import document as transport_document
ROOT=Path(__file__).resolve().parents[1]
ADAPTER='tools/hia_native_scalar_proof_syscalls.S'
PACKER='examples/hia_bootstrap/native_scalar_proof_packer.hepta'
MAGIC=int.from_bytes(b'HIAMVK02','little')
POLICY=r'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 80 or length(s) > 8388688 or uint(s, 0, 8) != MAGIC:
        return 4294967295
    size = extent(s)
    if size == 0 or size > 8388608 or size > length(o):
        return 4294967294
    envelope(o)
    put(o, 96, size)
    put(o, 104, size)
    index = 0
    at = PREFIX
    source = 80
    while index < 9:
        aligned = (at + 7) & 18446744073709551608
        clear(o, at, aligned)
        at = aligned
        piece = uint(s, 8 + 8 * index, 8)
        if index == 0:
            write(o, POLICY_HOLE, at - POLICY_HOLE - 4, 4)
        put(o, TABLE + 16 * index, at - TABLE)
        put(o, TABLE + 16 * index + 8, piece)
        copy_bytes(s, o, source, at, piece)
        source = source + piece
        at = at + piece
        index = index + 1
    return size

def extent(s:readbuf) -> u64:
    index = 0
    at = PREFIX
    source = 80
    while index < 9:
        piece = uint(s, 8 + 8 * index, 8)
        if piece == 0 or piece > 1048576 or piece > length(s) - source:
            return 0
        source = source + piece
        at = ((at + 7) & 18446744073709551608) + piece
        index = index + 1
    if source != length(s):
        return 0
    return at

def clear(o:mutbuf, start:u64, end:u64) -> u64:
    while start < end:
        store(o, start, 0)
        start = start + 1
    return 0

def copy_bytes(s:readbuf, o:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(s, source + i))
        i = i + 1
    return 0
'''
def document():
    adapter=(ROOT/ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-native-scalar-proof-transport-') as temporary:
        stub,symbols,_=assemble_adapter(Path(temporary),ADAPTER,adapter)
    hole=symbols['proof_policy_hole'];table=symbols['embedded_roles']
    assert stub[hole-1:hole+4]==b'\xe8\0\0\0\0' and table%8==0 and stub[table:table+144]==bytes(144)
    header=elf_header();prefix=header+stub
    constants={'PREFIX':len(prefix),'TABLE':len(header)+table,'POLICY_HOLE':len(header)+hole,'MAGIC':MAGIC}
    source=POLICY+'\ndef envelope(o:mutbuf) -> u64:\n'
    for at in range(0,len(prefix),8):
        piece=prefix[at:at+8]
        source+=f'    write(o, {at}, {int.from_bytes(piece,"little")}, {len(piece)})\n'
    source+='    return 0\n'
    return bind_adapter(transport_document(source,module='native_scalar_proof_packer',extra=constants),adapter,stub,(hole,table))
if __name__=='__main__':
    (ROOT/PACKER).write_text(render_assembly(document()))
