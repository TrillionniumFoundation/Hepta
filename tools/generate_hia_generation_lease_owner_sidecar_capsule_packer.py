"""Native trusted sidecar capsule with fixed external owner bindings.

This flat image owns policy, code-provider and tempdir bodies. Only the enclosing
native HIA packer resolves its fixed core, Value and finalizer imports.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGSCP1','little')
ROLES=('sidecar','code','tempdir')
BRIDGE=bytes.fromhex('535541544155415641574881ecc88000004881f9800000000f82c30200004981f9000800000f85bd0200004881fe800000000f85b00200004885ff0f84a70200004885d20f849e0200004d85c00f849502000049f7c0070000000f85880200004889f84801f00f827c0200004989d24901ca0f82700200004d89c34d01cb0f82640200004839d076094939fa0f87560200004c39c076094939fb0f87480200004d39c276094939d30f873a0200004989fc4989f7488954242048894c24284c8dac24c0000000bd008000004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84ba01000083f80a74dc83f8010f841001000083f8020f845301000083f8030f845901000083f8080f845801000083f80f0f848a00000083f80c0f82a001000083f80e0f87970100008944246031c9498b44cd004883f8030f877d010000498b54cd08480314c4488954cc6883c10383f90972db488b7c2468498b7510488b942480000000498b4d284c8b8424980000004d8b4d408b44246083f80c741983f80d740ae85b010000e906010000e841010000e9fc000000e800000000e9f20000004d89b500020000488d050000000049898508020000488d050000000049898510020000488d050801000049898518020000488d050a01000049898520020000488d050000000049898528020000488d05defdffff4989853002000031c0e9900000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05eb4431c0b901000000f0410fb14e40eb3531c041874640eb2d498b45004883f803774b498b7508480334c4498b45104883f8037739498b7d1848033cc4498b4d20fcf3a431c049898588000000e927feffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8800000415f415e415d415c5d5bc390e90000000090662e0f1f840000000000e900000000')
HOLES=dict(sidecar=262,code=769,tempdir=785)
OUTER_HOLES=dict(core=(472,),values=(453,486),finalizer=(528,))
CODE_EXPORT=768
TEMPDIR_EXPORT=784
def reference_flat(flats):
    if len(flats)!=3 or any(not f or len(f)>4194304 for f in flats):
        raise ValueError('three actual bounded native products required')
    raw=bytearray(BRIDGE)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));at=len(raw)
        struct.pack_into('<i',raw,HOLES[role],at-HOLES[role]-4)
        raw.extend(flat)
    if len(raw)>4194304:raise ValueError('original four MiB capsule bound')
    return bytes(raw)
def source_program():
    calls,emitters=common.emitters('bridge',BRIDGE)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<128:
        return 4294967294
    if length(s)<40 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=3:
        return 4294967295
    a=uint(s,16,8)
    b=uint(s,24,8)
    c=uint(s,32,8)
    if a==0 or a>4194304 or b==0 or b>4194304 or c==0 or c>4194304:
        return 4294967295
    if length(s)!=40+a+b+c:
        return 4294967295
    x=({len(BRIDGE)}+15)&18446744073709551600
    y=(x+a+15)&18446744073709551600
    z=(y+b+15)&18446744073709551600
    size=z+c
    if size>4194304:
        return 4294967295
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for fn in calls:source+=f'    {fn}(o,0)\n'
    for role,at in [('sidecar','x'),('code','y'),('tempdir','z')]:
        h=HOLES[role];source+=f'    write(o,{h},{at}-{h+4},4)\n'
    source+='''    copy(s,o,40,x,a)
    copy(s,o,40+a,y,b)
    copy(s,o,40+a+b,z,c)
    return size
'''
    return source+'\n\n'+emitters+common.HELPERS
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_capsule_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_capsule_packer.hepta'
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
