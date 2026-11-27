"""Native flat packer for the fixed VFY error-owner capsule."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIARTXP1','little')
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000001000f82cc0000004881fb002000000f85bf0000004d85e40f84b60000004d85ed0f84ad0000004d85f60f84a40000004c89e04c01f80f82980000004c89ea4801ea0f828c0000004c89f14801d90f82800000004939d473054939c572764939cc73054939c6726c4939cd73054939d6726249c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84f600000083f80a74dc83f801742183f8040f848e00000083f8080f849700000083f8097415b8fdffffffe9cb00000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb574c89d14d8b5d0041ffd389c0eb49498b45004839e80f8373ffffff4c01e8eb37498b45004883f8030f8760ffffff498b7508480334c4498b45104883f8030f874affffff498b7d1848033cc4498b4d20fcf3a431c0eb0049898500040000e9ebfeffff4881c488000000415f415e415d415c5d5bc3')
HOLE=207
def reference_image(body):
    if not body or len(body)>4194304:raise ValueError('one bounded native HIA policy required')
    raw=bytearray(BRIDGE);struct.pack_into('<i',raw,HOLE,len(raw)-HOLE-4);return bytes(raw)+body
def source_program():
    text=f'''
def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or word_load(s,0)!={MAGIC} or word_load(s,8)!=1:
        return 4294967293
    n=word_load(s,16)
    if n==0 or n>4194304 or length(s)!=64+n or length(o)<{len(BRIDGE)}+n:
        return 4294967293
    at=24
    while at<64:
        if word_load(s,at)!=0:
            return 4294967293
        at=at+8
    prefix(o)
    write(o,{HOLE},{len(BRIDGE)-HOLE-4},4)
    i=0
    while i<n:
        store(o,{len(BRIDGE)}+i,byte(s,64+i))
        i=i+1
    return {len(BRIDGE)}+n
def prefix(o:mutbuf) -> u64:
'''
    for at in range(0,len(BRIDGE),8):
        chunk=BRIDGE[at:at+8];text+=f'    write(o,{at},{int.from_bytes(chunk,"little")},{len(chunk)})\n'
    text+='''    return 0
def write(o:mutbuf,at:u64,value:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
    return text
def main():
    tree=document(source_program(),'generation_runtime_verify_exception_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_verify_exception_packer.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
