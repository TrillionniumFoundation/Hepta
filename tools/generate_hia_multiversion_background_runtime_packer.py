"""Native provider capsule: fixed provider, payload owner and qualified runtime.
Readable mechanical sources are retained; production packing is entirely HIA.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_runtime_handles_packer as base
from tools import generate_hia_multiversion_background_payload_packer as payload
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ecc81000004881f9800000000f823f0200004981f9000400000f82390200004989fc4989f7488954242048894c24284c8dac24c0000000bd001000004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84b901000083f80a74dc83f8010f84c000000083f8020f840601000083f8030f841a01000083f8040f842801000083f8060f843601000083f8070f843801000083f8080f843c01000083f80c0f828d01000083f80e0f87840100008944246031c9498b44cd004883f8040f876a010000498b54cd08480314c4488954cc6883c10383f90972db488b7c2468498b7510488b942480000000498b4d284c8b8424980000004d8b4d408b44246083f80c740f83f80d7414e800000000e9f3000000e800000000e9e9000000e800000000e9df0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05e99000000049837d00180f85ad000000498d5618418b4508418b4d10f00fb10aeb7349837d00180f8590000000498d5618418b45088702eb5c498b45004883f804777a498b5508480314c44889d0eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f804774b498b7508480334c4498b45104883f8047739498b7d1848033cc4498b4d20fcf3a431c049898588000000e928feffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8100000415f415e415d415c5d5bc3')
OUTER_HOLES={'provider':131,'effects':320,'handles':330,'payload':340}
OUTER_RELOCATIONS=((508,'malloc'),(519,'free'))
IMPORTS=base.IMPORTS
ROLES=('provider','payload')+base.ROLES
MAGIC=int.from_bytes(b'HIAMVBK1','little')
EXPORT_SIZE=len(OUTER)
def bridges():
    raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));pa=len(raw);raw.extend(payload.BRIDGE)
    raw.extend(bytes((-len(raw))%16));ha=len(raw);raw.extend(base.BRIDGE)
    targets={'payload':pa,'handles':ha,'effects':ha+((len(base.OUTER)+15)&~15)}
    for name,target in targets.items():
        off=OUTER_HOLES[name];struct.pack_into('<i',raw,off,target-off-4)
    holes={'provider':[OUTER_HOLES['provider']],'payload':[pa+payload.HOLES['policy']]}
    holes.update({name:[ha+x for x in values] for name,values in base.HOLES.items()})
    relocs=tuple(OUTER_RELOCATIONS)+tuple((pa+x,sym) for x,sym in payload.RELOCATIONS)+tuple((ha+x,sym) for x,sym in base.RELOCATIONS)
    return bytes(raw),holes,relocs,ha+base.SIZE_HOLE
BRIDGE,HOLES,RELOCATIONS,SIZE_HOLE=bridges()
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_mv_background_runtime',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_background_runtime'],18,0,1,0,EXPORT_SIZE)]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((3+IMPORTS.index(name))<<32)|4,-4) for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def apply(function,*args):
    changes={'BRIDGE':BRIDGE,'HOLES':HOLES,'RELOCATIONS':RELOCATIONS,'SIZE_HOLE':SIZE_HOLE,
             'ROLES':ROLES,'MAGIC':MAGIC,'EXPORT_SIZE':EXPORT_SIZE,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        return function(*args)
    finally:
        for k,v in old.items():setattr(base,k,v)
def source_program():return apply(base.source_program)
def reference_object(flats):return apply(base.reference_object,flats)
def main():
    result=document(source_program(),'multiversion_background_runtime_packer')
    p=ROOT/'examples/hia_bootstrap/multiversion_background_runtime_packer.hepta';p.write_text(render_assembly(result))
    print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks']) for f in result['functions']),flush=True)
if __name__=='__main__':main()
