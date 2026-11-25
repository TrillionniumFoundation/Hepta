"""Closed allocation and immutable-payload native packers.
All runtime bytes are emitted by the HIA sources. GNU assembly is only the
independent development check of the readable fixed mechanical templates.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
ALLOC=bytes.fromhex('534889fb4889fe4883c620724c31ffba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05483d01f0ffff732649ba4849414e4b414c314c8910488d4b20488948084889581048f7d3488958184883c0205bc331c05bc34885ff744a40f6c70f75454883ff20723f4883ef2048b84849414e4b414c31483907752c488b7708488b57104889d148f7d148394f1875184883c22072124839f2750db80b0000000f054885c07501c30f0b')
FREE_OFFSET=93
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd00020000727a4881fb00010000727149c745400000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f841001000083f80a74dc83f801743383f802747a83f8030f848a00000083f8060f849400000083f8070f849600000083f8080f849a000000b8fdffffffe9d30000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb7b49837d002075a3498d5620418b4508418b4d10f00fb10aeb6249837d0020758a498d5620418b45088702eb4f498b7d00e800000000eb44498b7d00e80000000031c0eb37498b45004883f8030f8758ffffff498b7508480334c4498b45104883f8030f8742ffffff498b7d1848033cc4498b4d20fcf3a431c0eb00498985c0010000e9d1feffff4881c488000000415f415e415d415c5d5bc3')
GUARD=bytes.fromhex('4885ff745d4885d274584d85c074534881fe80000000724a4881f90002000072414981f90001000072384889f84801f072304989d24901ca72284d89c34d01cb72204c39d773054839c272164c39df73054939c0720c4c39da73054d39d07202eb06b8fdffffffc3')
def literal(name,raw):
    lines=[f'def {name}(o:mutbuf,at:u64) -> u64:']
    for at in range(0,len(raw)//8*8,8):
        lines.append(f'    word_store(o, at + {at}, {int.from_bytes(raw[at:at+8],"little")})')
    for at in range(len(raw)//8*8,len(raw)):
        lines.append(f'    store(o, at + {at}, {raw[at]})')
    lines.append(f'    return {len(raw)}')
    return '\n'.join(lines)+'\n'
COMMON=r"""
def readword(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def put32(o:mutbuf,at:u64,value:u64) -> u64:
    store(o,at,value & 255)
    store(o,at+1,(value >> 8) & 255)
    store(o,at+2,(value >> 16) & 255)
    store(o,at+3,(value >> 24) & 255)
    return 0
"""
def allocator_program():
    s=r"""
def pack_allocator(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16:
        return 4294967295
    if readword(s,0)!=ALLOC_MAGIC or readword(s,8)!=1:
        return 4294967295
    if length(o)<ALLOC_SIZE:
        return 4294967294
    emit_allocator(o,0)
    return ALLOC_SIZE
"""
    return s.replace('ALLOC_MAGIC',str(int.from_bytes(b'HIANKAL1','little'))).replace('ALLOC_SIZE',str(len(ALLOC)))+COMMON+literal('emit_allocator',ALLOC)
def payload_program():
    s=r"""
def pack_payload(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<32 or readword(s,0)!=PAYLOAD_MAGIC:
        return 4294967295
    n=readword(s,8)
    if n<16 or n>1048576 or n!=length(s)-32 or readword(s,16)!=0 or readword(s,24)!=0:
        return 4294967295
    if length(o)<PREFIX_SIZE+n+ALLOC_SIZE:
        return 4294967294
    emit_prefix(o,0)
    i=0
    while i<n:
        store(o,PREFIX_SIZE+i,byte(s,32+i))
        i=i+1
    emit_allocator(o,PREFIX_SIZE+n)
    put32(o,GUARD_SIZE+103,405-107)
    put32(o,GUARD_SIZE+301,405+n-305)
    put32(o,GUARD_SIZE+312,405+n+FREE_OFFSET-316)
    return PREFIX_SIZE+n+ALLOC_SIZE
"""
    vals={'PAYLOAD_MAGIC':int.from_bytes(b'HIANKPL1','little'),'PREFIX_SIZE':len(GUARD)+len(BRIDGE),'GUARD_SIZE':len(GUARD),'ALLOC_SIZE':len(ALLOC),'FREE_OFFSET':FREE_OFFSET}
    for k,v in vals.items():s=s.replace(k,str(v))
    return s+COMMON+literal('emit_prefix',GUARD+BRIDGE)+literal('emit_allocator',ALLOC)
def main():
    for name,program in [('ndu_rank_context_allocator_packer',allocator_program()),('ndu_rank_context_payload_packer',payload_program())]:
        d=document(program,name);p=ROOT/'examples/hia_bootstrap'/f'{name}.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
