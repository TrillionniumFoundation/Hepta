"""Native fixed-role rank context flat packer; no runtime assembler."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools.generate_hia_ndu_rank_context_payload import ALLOC,FREE_OFFSET,literal,COMMON
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('4885ff74634885d2745e4d85c0745941f6c00775534881fe80000000724a4881f90002000072414981f90000020072384889f84801f072304989d24901ca72284d89c34d01cb72204c39d773054839c272164c39df73054939c0720c4c39da73054d39d07202eb06b8fdffffffc3535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb49c78580000000000000004d89a5e00100004d89ade80100004d89b5f001000049899df801000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f840402000083f80a74dc83f801744983f8020f848f00000083f8030f84a200000083f8060f84af00000083f8070f84b400000083f8080f84bb00000083f8090f841001000083f80b0f846e010000b8fdffffffe9b10100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e95601000049837d002075a0498d5620418b4508418b4d10f00fb10ae93a01000049837d00207584498d5620418b45088702e924010000498b7d00e800000000e916010000498b7d00e80000000031c0e906010000498b45004883f8030f8749ffffff498b7508480334c40f823bffffff498b45104883f8030f872dffffff498b7d1848033cc40f821fffffff498b4d204889f04801c80f820fffffff4889f84801c80f8203fffffffcf3a431c0e9a8000000498b45004883f8030f87ebfeffff498b7d0848033cc40f82ddfeffff498b75104889f84801f00f82cdfeffff4d8b45184939d80f87c0feffff4889d84c29c0483d000100000f82aefeffff4d01f0498d9600220000b90002000041b900010000e800000000eb41498b7d004839df0f8785feffff498b75084889d84829f84839c60f8772feffff4c01f7498d96384a0000b9200000004d8d860040000041b9a0040000e800000000498985c0010000e9ddfdffff4881c488000000415f415e415d415c5d5bc3')
HOLES={'policy': 226, 'malloc': 455, 'free': 469, 'payload': 671, 'sha': 738}
def program():
    s=r"""
def pack_context(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<40 or readword(s,0)!=MAGIC or readword(s,32)!=0:
        return 4294967295
    a=readword(s,8)
    b=readword(s,16)
    c=readword(s,24)
    if a<16 or a>4194304 or b<16 or b>4194304 or c<16 or c>4194304:
        return 4294967295
    if a+b+c!=length(s)-40:
        return 4294967295
    total=PREFIX+a+b+c+ALLOC_SIZE
    if length(o)<total:
        return 4294967294
    emit_bridge(o,0)
    i=0
    while i<a+b+c:
        store(o,PREFIX+i,byte(s,40+i))
        i=i+1
    emit_allocator(o,PREFIX+a+b+c)
    put32(o,POLICY_HOLE,PREFIX-POLICY_HOLE-4)
    put32(o,SHA_HOLE,PREFIX+a-SHA_HOLE-4)
    put32(o,PAYLOAD_HOLE,PREFIX+a+b-PAYLOAD_HOLE-4)
    put32(o,MALLOC_HOLE,PREFIX+a+b+c-MALLOC_HOLE-4)
    put32(o,FREE_HOLE,PREFIX+a+b+c+FREE_OFFSET-FREE_HOLE-4)
    return total
"""
    vals={'MAGIC':int.from_bytes(b'HIANKP01','little'),'PREFIX':len(BRIDGE),'ALLOC_SIZE':len(ALLOC),'FREE_OFFSET':FREE_OFFSET}
    for k,v in HOLES.items():vals[k.upper()+'_HOLE']=v
    import re
    s=re.sub(r'\b[A-Z][A-Z_]*\b',lambda m:str(vals.get(m.group(),m.group())),s)
    return s+COMMON+literal('emit_bridge',BRIDGE)+literal('emit_allocator',ALLOC)
def main():
    d=document(program(),'ndu_rank_context_packer')
    p=ROOT/'examples/hia_bootstrap/ndu_rank_context_packer.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),flush=True)
if __name__=='__main__':main()
