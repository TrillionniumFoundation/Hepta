"""Native two-role provider capsule for the fixed enclosing owner linker.

The three owner imports and allocator calls remain unresolved until the enclosing
HIA packer binds them. This capsule is not a standalone callable product.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_generation_lease_owner_provider_packer as provider
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGPCP1','little')
ROLES=provider.ROLES
BRIDGE=provider.BRIDGE
HOLES=provider.HOLES
EXTERNAL_RELOCATIONS=provider.RELOCATIONS
def reference_flat(flats):
    if len(flats)!=2 or any(not f or len(f)>4194304 for f in flats):
        raise ValueError('two bounded actual native policies required')
    raw=bytearray(BRIDGE)
    for name,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        hole=HOLES[name]
        struct.pack_into('<i',raw,hole,len(raw)-hole-4)
        raw.extend(flat)
    if len(raw)>4194304:raise ValueError('one capsule role retains the four MiB bound')
    return bytes(raw)
def source_program():
    calls,emitters=common.emitters('bridge',BRIDGE)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<128:
        return 4294967294
    if length(s)<32 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=2:
        return 4294967295
    first=uint(s,16,8)
    second=uint(s,24,8)
    if first==0 or first>4194304 or second==0 or second>4194304:
        return 4294967295
    if length(s)!=32+first+second:
        return 4294967295
    a=({len(BRIDGE)}+15)&18446744073709551600
    b=(a+first+15)&18446744073709551600
    size=b+second
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
    source+=f'''    write(o,{HOLES['provider']},a-{HOLES['provider']+4},4)
    write(o,{HOLES['payload']},b-{HOLES['payload']+4},4)
    copy(s,o,32,a,first)
    copy(s,o,32+first,b,second)
    return size
'''
    return source+'\n\n'+emitters+common.HELPERS
def main():
    doc=document(source_program(),'generation_lease_owner_provider_capsule_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_provider_capsule_packer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
