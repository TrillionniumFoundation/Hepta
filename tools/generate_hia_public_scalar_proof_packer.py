"""Pack a public HIA proof owner, fixed capture transport, and two child images.

The children retain their original eight-MiB executable limit. Only this whole
parent envelope admits sixteen MiB; all role identities are real packed bytes.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.generate_hia_native_filter import bind_adapter,elf_header
from tools.generate_hia_safe_core_binder import document as transport_document
from tools.generate_hia_multiversion_prepare_process_packer import BRIDGE as PROCESS_BRIDGE,HOLES as PROCESS_HOLES
ROOT=Path(__file__).resolve().parents[1]
ADAPTER='tools/hia_public_scalar_proof_syscalls.S'
PROCESS='tools/hia_multiversion_prepare_process_bridge.S'
MAGIC=int.from_bytes(b'HIAPKP01','little')
POLICY=r'''
def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(s)>16777280 or uint(s,0,8)!=MAGIC:
        return 4294967295
    size=extent(s)
    if size==0 or size>16777216 or size>length(o):
        return 4294967294
    envelope(o)
    put(o,96,size)
    put(o,104,size)
    index=0
    at=PREFIX
    source=64
    while index<7:
        aligned=(at+7)&18446744073709551608
        clear(o,at,aligned)
        at=aligned
        piece=uint(s,8+8*index,8)
        if index==0:
            write(o,POLICY_HOLE,at-POLICY_HOLE-4,4)
        if index==2:
            write(o,PROCESS_HOLE,at-PROCESS_HOLE-4,4)
            put(o,TABLE+16*index,PROCESS_START-TABLE)
        else:
            put(o,TABLE+16*index,at-TABLE)
        put(o,TABLE+16*index+8,piece)
        copy_bytes(s,o,source,at,piece)
        source=source+piece
        at=at+piece
        index=index+1
    return size

def extent(s:readbuf) -> u64:
    index=0
    at=PREFIX
    source=64
    while index<7:
        piece=uint(s,8+8*index,8)
        cap=1048576
        if index>=5:
            cap=8388608
        if piece==0 or piece>cap or piece>length(s)-source:
            return 0
        if index>=5 and piece<176:
            return 0
        source=source+piece
        at=((at+7)&18446744073709551608)+piece
        index=index+1
    if source!=length(s):
        return 0
    return at

def clear(o:mutbuf,start:u64,end:u64) -> u64:
    while start<end:
        store(o,start,0)
        start=start+1
    return 0

def copy_bytes(s:readbuf,o:mutbuf,source:u64,target:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(o,target+i,byte(s,source+i))
        i=i+1
    return 0
'''
def document():
    adapter=(ROOT/ADAPTER).read_bytes();process=(ROOT/PROCESS).read_bytes()
    with TemporaryDirectory(prefix='hia-public-proof-transport-') as td:
        stub,symbols,_=assemble_adapter(Path(td),ADAPTER,adapter)
    ps=PROCESS_BRIDGE
    hole=symbols['public_policy_hole'];table=symbols['embedded_roles']
    assert stub[hole-1:hole+4]==b'\xe8\0\0\0\0' and table%8==0 and stub[table:table+112]==bytes(112)
    ph=PROCESS_HOLES['policy'];assert ps[ph-1:ph+4]==b'\xe8\0\0\0\0'
    header=elf_header();prefix=header+stub
    prefix+=bytes((-len(prefix))%8);start=len(prefix);prefix+=ps
    prefix+=bytes((-len(prefix))%8)
    constants={'PREFIX':len(prefix),'TABLE':len(header)+table,'POLICY_HOLE':len(header)+hole,'PROCESS_START':start,'PROCESS_HOLE':start+ph,'MAGIC':MAGIC}
    source=POLICY+'\ndef envelope(o:mutbuf) -> u64:\n'
    for at in range(0,len(prefix),8):
        piece=prefix[at:at+8];source+=f'    write(o, {at}, {int.from_bytes(piece,"little")}, {len(piece)})\n'
    source+='    return 0\n'
    # Both readable mechanical capsules are captured in the product source.
    doc=transport_document(source,module='public_scalar_proof_packer',extra=constants)
    return bind_adapter(doc,adapter+b'\n'+process,prefix[len(header):],(hole,table,start-len(header)+ph))
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/public_scalar_proof_packer.hepta';p.write_text(render_assembly(document()));print(p.name,p.stat().st_size)
