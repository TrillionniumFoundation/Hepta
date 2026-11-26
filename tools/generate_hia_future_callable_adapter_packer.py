from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_future_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec480001004881f9200100000f825d0100004881fec00000000f85570100004981f9000100000f854a0100004885ff0f84410100004885d20f84380100004d85c00f842f01000049f7c0070000000f85220100004889f84801f00f82160100004989d24901ca0f820a0100004d89c34d01cb0f82fe0000004839d076094939fa0f87f00000004c39c076094939fb0f87e20000004d39c276094939d30f87d40000004989fc4989f7488954242048894c24284d89c64c89cb4c8d6c2440bd0000010049c78580000000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0747283f80a74e083f801740c83f80c741783f80f743beb7d49837d00277571b8270000000f05eb40498dbd00020000be80000000498d9500400000b9008000004d8b467041b900010000e800000000eb174d89b5b0000000488d0500000000498985b800000031c049898588000000e973ffffff488b7c24204c89eeb924000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c448000100415f415e415d415c5d5bc3')
HOLES={'policy': 236}
RELOCATIONS=((317, 'hia_resource_values'), (333, 'hia_resource_values'))
EXPORT_SIZE=409
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIAFCAP1','little')
def fixed_parts():
    strings=b'\0hia_future_callable_adapter\0hia_resource_values\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0) for name in ('hia_resource_values',)])
    relas=b''.join(struct.pack('<QQq',off,((3+('hia_resource_values',).index(name))<<32)|4,-4) for off,name in RELOCATIONS)
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
    t=document(source_program(),'future_callable_adapter_packer');p=ROOT/'examples/hia_bootstrap/future_callable_adapter_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
