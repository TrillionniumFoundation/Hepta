"""Native ET_REL packaging for exact VM/native multiversion probes."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb48c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84cf00000083f801741d83f802720e83f804765f83f8050f849e000000b8fdffffffe9b10000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb5889442450498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d28837c245002740e837c245003740ee800000000eb1ee800000000eb17e800000000eb10498b7d00498b75084c01f6e81f00000049894608e912ffffff418b45084881c488000000415f415e415d415c5d5bc35341544883ec584889fb4989f4498b44243048890424498b4424384889442408498b4424404889442410498b4424484889442418498b4424504889442420498b4424584889442428498b4424604889442430498b4424684889442438498b4424704889442440498b4424784889442448498b3c24498b742408498b542410498b4c24184d8b4424204d8b4c242831c0ffd34883c458415c5bc3')
HOLES={'policy': 77, 'vectors': 258, 'projector': 265, 'vm': 251}
EXPORT_SIZE=318
ROLES=('policy','vectors','projector','vm')
MAGIC=int.from_bytes(b'HIAMVPP1','little')
def fixed_parts():
    strings=b'\0hia_mv_probe\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)])
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,0,3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,b'',symbols,strings,b''.join(rows)
def context_call(fn,*args):
    changes={'BRIDGE':BRIDGE,'HOLES':HOLES,'EXPORT_SIZE':EXPORT_SIZE,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        return fn(*args)
    finally:
        for k,v in old.items():setattr(base,k,v)
def source_program():return context_call(base.source_program)
def reference_object(flats):return context_call(base.reference_object,flats)
def main():
    t=document(source_program(),'multiversion_probe_packer');p=ROOT/'examples/hia_bootstrap/multiversion_probe_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
