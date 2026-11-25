from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_future_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec981000004989fc4989f748895424504889cd4d89c64c89cb4983ff400f85540100004881fd800000000f82470100004883fb400f823d0100004d85e40f84340100004885d20f842b0100004d85f60f84220100004c89e04c01f80f821601000048894424604889d04801e80f820501000048894424684c89f04801d80f82f400000048894424704c3b74246873094839d00f87df0000004c3b642468730b48395424600f87cd0000004c3b642470730b4c397424600f87bb0000004c8dac248000000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89eab9001000004d89f04989d9e80000000085c0746083f80a74de83f804756a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c24484d8b5d0041ffd389c049898588000000eb834c89ee488b7c2450b980000000fcf3a431c0eb05b8fdffffff4881c498100000415f415e415d415c5d5bc3')
HOLES={'policy': 263}
RELOCATIONS=()
EXPORT_SIZE=410
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIABJRP1','little')
def fixed_parts():
    strings=b'\0hia_mv_background_job_refs\0malloc\0free\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0) for name in ('malloc','free')])
    relas=b''.join(struct.pack('<QQq',off,((3+('malloc','free').index(name))<<32)|4,-4) for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,strings,b''.join(rows)

def apply(function,*args):
    changes={'BRIDGE':BRIDGE,'RELOCATIONS':RELOCATIONS,'HOLES':HOLES,'EXPORT_SIZE':EXPORT_SIZE,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        return function(*args)
    finally:
        for k,v in old.items():setattr(base,k,v)
def source_program():
    return apply(base.source_program)
def reference_object(flats):
    return apply(base.reference_object,flats)
def main():
    t=document(source_program(),'multiversion_background_job_refs_packer');p=ROOT/'examples/hia_bootstrap/multiversion_background_job_refs_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
