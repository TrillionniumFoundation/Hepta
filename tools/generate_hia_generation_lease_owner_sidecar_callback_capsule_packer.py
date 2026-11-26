"""Native managed-Future sidecar with fixed Value70 callback adapter.
All six bodies remain one bounded capsule and share the enclosing Value entry.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_sidecar_future_capsule_packer as original
from tools import generate_hia_future_resource_callable_owner_packer as provider
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGSCP3','little')
ROLES=('sidecar','code','tempdir','future_provider','future_registry','future_callback')
OUTER=original.OUTER
CODE_EXPORT=original.CODE_EXPORT
TEMPDIR_EXPORT=original.TEMPDIR_EXPORT
PROVIDER_STUB=original.PROVIDER_STUB
raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16))
FUTURE_PROVIDER_EXPORT=len(raw);raw.extend(provider.BRIDGE)
for hole,target in ((897,FUTURE_PROVIDER_EXPORT),(624,FUTURE_PROVIDER_EXPORT+provider.REGISTRY_OFFSET)):
    struct.pack_into('<i',raw,hole,target-hole-4)
BRIDGE=bytes(raw)
HOLES=dict(sidecar=262,code=865,tempdir=881,
           future_provider=FUTURE_PROVIDER_EXPORT+provider.HOLES['owner'],
           future_registry=FUTURE_PROVIDER_EXPORT+provider.HOLES['registry'],
           future_callback=FUTURE_PROVIDER_EXPORT+provider.HOLES['callback'])
OUTER_HOLES={name:tuple(off for off in holes if off<len(OUTER))
             for name,holes in original.OUTER_HOLES.items()}
RELOCATIONS=[]
for off,name in provider.RELOCATIONS:
    off+=FUTURE_PROVIDER_EXPORT
    if name=='hia_resource_future':OUTER_HOLES['future']+=(off,)
    elif name=='hia_resource_values':OUTER_HOLES['values']+=(off,)
    else:RELOCATIONS.append((off,name))
RELOCATIONS=tuple(RELOCATIONS)
assert all(BRIDGE[h:h+4]==bytes(4) for hs in OUTER_HOLES.values()for h in hs)
assert all(BRIDGE[h:h+4]==bytes(4)for h,_ in RELOCATIONS)
def reference_flat(flats):
    if len(flats)!=len(ROLES)or any(not f or len(f)>4194304 for f in flats):
        raise ValueError('six actual bounded native products required')
    raw=bytearray(BRIDGE)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));at=len(raw)
        struct.pack_into('<i',raw,HOLES[role],at-HOLES[role]-4);raw.extend(flat)
    if len(raw)>4194304:raise ValueError('original four MiB capsule bound')
    return bytes(raw)
def source_program():
    changes=dict(BRIDGE=BRIDGE,ROLES=ROLES,HOLES=HOLES,MAGIC=MAGIC)
    saved={name:getattr(original,name)for name in changes}
    try:
        for name,value in changes.items():setattr(original,name,value)
        return original.source_program()
    finally:
        for name,value in saved.items():setattr(original,name,value)
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_callback_capsule_packer')
    p=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_callback_capsule_packer.hepta'
    p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),flush=True)
if __name__=='__main__':main()
