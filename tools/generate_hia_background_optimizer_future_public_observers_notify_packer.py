"""Native mechanical six-view and full-u64 return binding for MV snapshots."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document as author_document
ROOT=Path(__file__).resolve().parents[1]
PREFIX=bytes.fromhex('535541544155415641574883ec584989fc4989f74989d54889cd4d89c64c89cb4881fd002000000f82f60000004881fb000100000f82e90000004d85ed0f84e00000004d85f60f84d70000004c89e84801e80f82cb0000004d89f24901da0f82bf0000004939c673094d39ea0f87b10000004d89e34d01fb0f82a50000004d85ff74214d85e40f84970000004939c473094d39eb0f87890000004d39d473054d39f3777f49c785800000000000000049c785c00100000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e89f01000085c00f848801000083f80a74dc83f801743383f8020f84c600000083f8030f84dd00000083f8050f84eb00000083f8080f84f400000083f8097459b8fdffffffe94b0100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9f00000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c244841ff5500e9a300000049837d00200f854fffffff498d5620418b4508418b4d10f00fb10ae98300000049837d00200f852fffffff498d5620418b45088702eb6c498b45004839d80f8316ffffff4c01f0eb5a498b45004883f8030f8703ffffff498b7508480334c4498b45104883f8030f87edfeffff498b7d1848033cc4498b4d204839f776204889f84829f04839c873154885c97413488d740eff488d7c0ffffdf3a4fceb03fcf3a431c0498985c0010000e959feffff4883c458415f415e415d415c5d5bc3')
SOURCE=r'''
def observer_notify_packer(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<33 or length(w)<64:
        return 4294967293
    if word_load(s,0)!=MAGIC or word_load(s,16)!=0 or word_load(s,24)!=0:
        return 4294967293
    n=word_load(s,8)
    if n==0 or n>4194304 or n!=length(s)-32:
        return 4294967293
    need=n+PREFIX_BYTES
    word_store(w,0,need)
    if length(o)<need:
        return 4294967294
    PREFIX_WRITES
    i=0
    while i<n:
        store(o,PREFIX_BYTES+i,byte(s,32+i))
        i=i+1
    return 0
'''
def document():
    writes=[]
    for i in range(0,len(PREFIX),8):
        q=PREFIX[i:i+8]
        if len(q)==8:writes.append('word_store(o,'+str(i)+','+str(int.from_bytes(q,'little'))+')')
        else:
            for j,b in enumerate(q):writes.append('store(o,'+str(i+j)+','+str(b)+')')
    source=SOURCE.replace('PREFIX_WRITES','\n    '.join(writes)).replace('PREFIX_BYTES',str(len(PREFIX))).replace('MAGIC',str(int.from_bytes(b'HIABFNPK','little')))
    return author_document(source,'background_optimizer_future_public_observers_notify_packer')
def main():
    p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_observers_notify_packer.hepta';j=document();p.write_text(render_assembly(j))
    print('observer_notify_packer',p.stat().st_size,len(j['functions']),sum(len(f['blocks'])for f in j['functions']),sum(len(b['ops'])for f in j['functions']for b in f['blocks']))
if __name__=='__main__':main()
