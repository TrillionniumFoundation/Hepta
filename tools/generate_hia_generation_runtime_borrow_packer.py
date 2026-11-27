"""One fixed native Runtime installed-resource lifetime capsule."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIARTLP1','little')
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000004000f82ab0100004881fb000800000f859e0100004981ff800000000f859101000049f7c6070000000f85840100004d85e40f847b0100004d85ed0f84720100004d85f60f846901000048b848494152544c5131493904240f85550100004d8b5424084983fa020f87460100004983fa00750d4881fd008000060f8233010000b9100000004983fa00750a83f918721083f92876164983fa01750583f918740b49833c0c000f850801000083c10881f98000000072cf4983fa02740c49837c2418000f84eb0000004c89e04c01f80f82df0000004c89ea4801ea0f82d30000004c89f14801d90f82c70000004939d473094939c50f82b90000004939cc73094939c60f82ab0000004939cd73094939d60f829d0000004d89b500020000488d050000000049898508020000488d050000000049898510020000488d05000000004989851802000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f844301000083f80a74dc83f8010f84a600000083f802742283f803743183f80c746683f8080f84da00000083f809742bb8fdffffffe90e01000031c0b901000000f0490fb14e40f390e9ee00000031c04987464031c0e9e1000000498dbd00100000be80000000498d9500800000b9004002004d89f041b900080000e80000000089c0e9b4000000498dbd00100000be80000000498d9500800000b9000000064d8d860001000041b900010000e80000000089c0e9830000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb37498b45004883f8030f871dffffff498b7508480334c4498b45104883f8030f8707ffffff498b7d1848033cc4498b4d20fcf3a431c0eb0049898588000000e99efeffff4881c488000000415f415e415d415c5d5bc3')
HOLE=420
FIXED_HOLES=dict(owner=[328],global_owner=[342,552],carrier=[356,601])
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
    tree=document(source_program(),'generation_runtime_borrow_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_borrow_packer.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
