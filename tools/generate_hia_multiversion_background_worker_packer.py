from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_future_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84c90000004d85ed0f84c00000004d85f60f84b70000004c89e04c01f80f82ab0000004c89e84801e80f829f0000004c89f04801d80f82930000004881fd002000000f82860000004881fb00020000727d49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f844a01000083f80a74dc83f801743c83f8020f84ef00000083f8030f840801000083f804743083f8060f849700000083f8070f84a700000083f8080f84ad000000b8fdffffffe90601000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b4424404c8b4c244848837c24780075104c8b542438498b45000f05e98d000000488b4c24384d8b5d0041ffd389c0eb7d498d7e1031f6488d15900000004c89f1e80000000089c0eb64498b7e1031f6e80000000089c0eb554d89b500020000488d0550feffff4989850802000031c0eb3c498b55004881fa800000000f8529ffffff4c01f2418b4508418b4d10f00fb10aeb1a498b55004881fa800000000f8507ffffff4c01f2418b45088702498985c0010000e997feffff31c04881c488000000415f415e415d415c5d5bc3534889fb4881ec8020000031c04889e7b910000000fcf348ab48b848494142475730314889042448c7442408040000004889e7be80000000488d942480000000b9002000004989d841b900020000e896fdffff4881c4802000005b31c0c3')
HOLES={'policy': 173}
RELOCATIONS=((395, 'pthread_create'), (410, 'pthread_join'))
EXPORT_SIZE=629
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIABGWP1','little')
def fixed_parts():
    strings=b'\0hia_mv_background_worker\0pthread_create\0pthread_join\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0) for name in ('pthread_create','pthread_join')])
    relas=b''.join(struct.pack('<QQq',off,((3+('pthread_create','pthread_join').index(name))<<32)|4,-4) for off,name in RELOCATIONS)
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
    t=document(source_program(),'multiversion_background_worker_packer');p=ROOT/'examples/hia_bootstrap/multiversion_background_worker_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
