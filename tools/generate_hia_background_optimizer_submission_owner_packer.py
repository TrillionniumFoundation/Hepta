from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_future_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000008000f82e20000004881fb002000000f82d50000004d85e40f84cc0000004d85ed0f84c30000004d85f60f84ba0000004c89e04c01f80f82ae0000004c89ea4801ea0f82a20000004c89f14801d90f82960000004939d473094939c50f82880000004939cc73054939c6727e4939cd73054939d6727449c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f842001000083f80a74dc83f801743383f8040f84a000000083f8060f84a900000083f8070f84ab00000083f8080f84af00000083f8097415b8fdffffffe9e300000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb6f4c89d14d8b5d0041ffd389c0eb61498b45004839e80f8373ffffff4c01e8eb4f498b7d00e800000000eb44498b7d00e80000000031c0eb37498b45004883f8030f8748ffffff498b7508480334c4498b45104883f8030f8732ffffff498b7d1848033cc4498b4d20fcf3a431c0eb00498985c0010000e9c1feffff4881c488000000415f415e415d415c5d5bc3')
HOLES={'policy': 211}
RELOCATIONS=((425, 'malloc'), (436, 'free'))
EXPORT_SIZE=529
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIABSOP1','little')
def fixed_parts():
    strings=b'\0hia_background_submission_owner\0malloc\0free\0'
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
    t=document(source_program(),'background_optimizer_submission_owner_packer');p=ROOT/'examples/hia_bootstrap/background_optimizer_submission_owner_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
