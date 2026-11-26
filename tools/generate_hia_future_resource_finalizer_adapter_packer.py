from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_future_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec481000004881f9800000000f82e40100004881fe800000000f85de0100004981f9000100000f85d10100004885ff0f84c80100004885d20f84bf0100004d85c00f84b601000049f7c0070000000f85a90100004889f84801f00f829d0100004989d24901ca0f82910100004d89c34d01cb0f82850100004839d076094939fa0f87770100004c39c076094939fb0f87690100004d39c276094939d30f875b0100004989fc4989f7488954242048894c24284d89c64c89cb4c8d6c2440bd0010000048c70424000000004c897424084c896424104c896c241849c78580000000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84de00000083f80a74dc83f801741483f808742683f80c745883f80f747ce9e100000049837d00270f85d1000000b8270000000f05e99d000000498b45004883f8030f87b7000000498b7508480334c4498b45104883f8030f87a1000000498b7d1848033cc4498b4d20fcf3a431c0eb66498dbd00020000be80000000498d9500030000b9800000004d8b462841b900020000e800000000eb3d4d89b598000000488d054efeffff498985a0000000488d05e2ffffff486315d7ffffff4801d0498985a8000000488d0500000000498985b000000031c049898588000000e903ffffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c448100000415f415e415d415c5d5bc3')
HOLES={'policy': 259}
RELOCATIONS=((414, 'hia_resource_owner'), (468, 'hia_resource_values'))
EXPORT_SIZE=544
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIAFRAP1','little')
def fixed_parts():
    strings=b'\0hia_future_resource_finalizer_adapter\0hia_resource_owner\0hia_resource_values\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0) for name in ('hia_resource_owner','hia_resource_values')])
    relas=b''.join(struct.pack('<QQq',off,((3+('hia_resource_owner','hia_resource_values').index(name))<<32)|4,-4) for off,name in RELOCATIONS)
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
    t=document(source_program(),'future_resource_finalizer_adapter_packer');p=ROOT/'examples/hia_bootstrap/future_resource_finalizer_adapter_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
