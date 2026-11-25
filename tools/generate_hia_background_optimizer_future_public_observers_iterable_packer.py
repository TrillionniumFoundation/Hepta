"""Native packer for the Future observer owner and binary64 deadline role."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document as author_document
ROOT=Path(__file__).resolve().parents[1]
PREFIX=bytes.fromhex('535541544155415641574883ec584989fc4989f74989d54889cd4d89c64c89cb4881fd000004000f820d0100004881fb000100000f82000100004d85ed0f84f70000004d85f60f84ee0000004c89e84801e80f82e20000004d89f24901da0f82d60000004939c673094d39ea0f87c80000004d89e34d01fb0f82bc0000004d85ff74254d85e40f84ae0000004939c473094d39eb0f87a00000004d39d473094d39f30f879200000049c785800000000000000049c785c00100000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84c901000083f80a74dc83f8010f849d00000083f8020f840301000083f8030f841a01000083f8050f842801000083f8080f843101000083f806744b83f807745483f809745f83f80b740ab8fdffffffe979010000498b45004883f80377ec498b7d0848033cc4498b7510498d9500200000b9000002004d89f04989d9e800000000e93b010000498b7d00e84d010000e92d010000498b7d00e89c01000031c0e91d01000048c744245001000000eb0948c7442450000000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c245000750b498b45000f05e9b20000004c89d14d8b5d0041ffd3e9a300000049837d00200f8521ffffff498d5620418b4508418b4d10f00fb10ae98300000049837d00200f8501ffffff498d5620418b45088702eb6c498b45004839d80f83e8feffff4c01f0eb5a498b45004883f8030f87d5feffff498b7508480334c4498b45104883f8030f87bffeffff498b7d1848033cc4498b4d204839f776204889f84829f04839c873154885c97413488d740eff488d7c0ffffdf3a4fceb03fcf3a431c0498985c0010000e918feffff4883c458415f415e415d415c5d5bc3534889fb4889fe4883c620724c31ffba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05483d01f0ffff732649ba4849414e4b414c314c8910488d4b20488948084889581048f7d3488958184883c0205bc331c05bc34885ff744a40f6c70f75454883ff20723f4883ef2048b84849414e4b414c31483907752c488b7708488b57104889d148f7d148394f1875184883c22072124839f2750db80b0000000f054885c07501c30f0b')
MAIN_HOLE=232
ARRAY_HOLE=365
SOURCE=r"""
def observer_packer(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<34 or length(w)<64:
        return 4294967293
    if word_load(s,0)!=MAGIC or word_load(s,24)!=0:
        return 4294967293
    main=word_load(s,8)
    math=word_load(s,16)
    if main==0 or math==0 or main>4194304 or math>4194304 or main+math!=length(s)-32:
        return 4294967293
    need=PREFIX_BYTES+main+math
    word_store(w,0,need)
    if length(o)<need:
        return 4294967294
    PREFIX_WRITES
    patch32(o,MAIN_HOLE,PREFIX_BYTES-MAIN_HOLE-4)
    patch32(o,ARRAY_HOLE,PREFIX_BYTES+main-ARRAY_HOLE-4)
    i=0
    while i<main+math:
        store(o,PREFIX_BYTES+i,byte(s,32+i))
        i=i+1
    return 0
def patch32(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<4:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
"""
def document():
 writes=[]
 for i in range(0,len(PREFIX),8):
  q=PREFIX[i:i+8]
  if len(q)==8:writes.append('word_store(o,'+str(i)+','+str(int.from_bytes(q,'little'))+')')
  else:
   for j,b in enumerate(q):writes.append('store(o,'+str(i+j)+','+str(b)+')')
 source=SOURCE.replace('PREFIX_WRITES','\n    '.join(writes)).replace('PREFIX_BYTES',str(len(PREFIX))).replace('MAIN_HOLE',str(MAIN_HOLE)).replace('ARRAY_HOLE',str(ARRAY_HOLE)).replace('MAGIC',str(int.from_bytes(b'HIABFAPK','little')))
 return author_document(source,'background_optimizer_future_public_observers_iterable_packer')
def main():
 d=document();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_observers_iterable_packer.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
if __name__=='__main__':main()
