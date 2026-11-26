"""Author the source-bound native lease lifecycle packer; no product Python dependency."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIAGLPK1','little')
BRIDGE=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4d85e40f84ec0000004d85ed0f84e30000004d85f60f84da0000004983ff400f85d00000004881fd004000060f82c30000004881fb800000000f82b600000041f6c6070f85ac0000004c89e04c01f80f82a00000004c89ea4801ea0f82940000004c89f14801d90f82880000004c39e876054c39e2777e4c39f076054c39e177744c39f276054c39e9776a49c78500010000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0744983f80a74e083f801743183f80c753a498dbd00100000498b7500498d9500400000b9000000064d8b46104d8b4e1841ff560849898580010000ebaab8270000000f05ebeeb8fdffffff4883c408415f415e415d415c5d5bc30f1f8000000000')
HOLES={'policy':201}

def reference_image(flats):
    if len(flats)!=1 or any(not f or len(f)>4194304 for f in flats):
        raise ValueError('one bounded actual HIA policy required')
    raw=bytearray(BRIDGE)
    for role,body in zip(ROLES,flats,strict=True):
        hole=HOLES[role]
        struct.pack_into('<i',raw,hole,len(raw)-hole-4)
        raw.extend(body)
    return bytes(raw)

def source_program():
    source=f'''
def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or word_load(s,0)!={MAGIC} or word_load(s,8)!=1:
        return 4294967293
    if word_load(s,24)!=0 or word_load(s,32)!=0 or word_load(s,40)!=0 or word_load(s,48)!=0 or word_load(s,56)!=0:
        return 4294967293
    total=64
    i=0
    while i<1:
        n=word_load(s,16+i*8)
        if n==0 or n>4194304:
            return 4294967293
        total=total+n
        i=i+1
    if length(s)!=total or length(o)<total-64+{len(BRIDGE)}:
        return 4294967293
    prefix(o)
    at={len(BRIDGE)}
'''
    for index,role in enumerate(ROLES):
        hole=HOLES[role]
        source+=f'    word32(o,{hole},at-{hole+4})\n    at=at+word_load(s,{16+index*8})\n'
    source+=f'''    copy_bytes(s,o,64,{len(BRIDGE)},total-64)
    return total-64+{len(BRIDGE)}

def prefix(o:mutbuf) -> u64:
'''
    for i in range(0,len(BRIDGE),8):
        source+=f'    word(o,{i},{int.from_bytes(BRIDGE[i:i+8],"little")})\n'
    source+='''    return 0

def word(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def word32(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<4:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def copy_bytes(s:readbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
'''
    return source

def main():
    doc=document(source_program(),'generation_lease_public_lifecycle_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_public_lifecycle_packer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size)

if __name__=='__main__':
    main()
