"""Closed native generation child with preserved GX1/GX2 and actual Clang GX3.

The native product contains no Value implementation. Fixed identical HIA
policies are shared by explicit role aliases checked against the captured
native bytes during construction. The original budgets remain unchanged.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_clang_prepare_packer as prepare
from tools import generate_hia_multiversion_runtime_generation_packer as legacy
from tools import generate_hia_clang_value_packer as base
ROOT=Path(__file__).resolve().parents[1]
GENERATION=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fb000000200f82410100004881fd001000000f823401000049c7860000401f0000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84ed00000083f8010f848e00000083f8020f82e600000083f8090f87dd000000498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d2883f809742583f802742783f803742983f804742b83f805742d83f806742f83f8077431e800000000eb7be800000000eb74e800000000eb6de800000000eb66e800000000eb5fe800000000eb58e800000000eb51e800000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f054989860800401fe9f4feffff418b4508eb05b8fdffffff4881c488000000415f415e415d415c5d5bc3')
GENERATION_HOLES={'generation':114,'retirement':222,'clang_prepare':229,'intake':236,'proof':243,'prepare':250,'capture':257,'image':264,'probe':271}
ALIASES={"gen_generation":"gen_generation","gen_intake_prepare":"gen_intake_prepare","gen_intake_process":"gen_intake_process","gen_intake_intake":"gen_intake_intake","gen_intake_admission":"c_admission","gen_intake_canonical":"c_canonical","gen_intake_hash":"c_hash","gen_intake_profile":"gen_intake_profile","gen_intake_scalar":"gen_intake_scalar","gen_intake_abi":"gen_intake_abi","gen_proof_prepare":"gen_proof_prepare","gen_proof_process":"gen_intake_process","gen_proof_hash":"c_hash","gen_proof_json":"i_json","gen_proof_receipt":"gen_proof_receipt","gen_prepare_owner":"gen_prepare_owner","gen_prepare_capture":"gen_prepare_capture","gen_prepare_process":"gen_intake_process","gen_prepare_hash":"c_hash","gen_prepare_json":"i_json","gen_prepare_image":"gen_prepare_image","gen_prepare_sha":"i_sha","gen_prepare_elf":"c_shared","gen_prepare_mapping":"i_mapping","gen_prepare_probe":"p_policy","gen_prepare_vectors":"p_vectors","gen_prepare_projector":"p_projector","gen_prepare_vm":"p_vm","gen_prepare_retire":"i_retire","gen_prepare_retirement_state":"i_retirement_state"}
ROLES=prepare.ROLES+tuple(dict.fromkeys(v for v in ALIASES.values()if v not in prepare.ROLES))
MAGIC=int.from_bytes(b'HIAGCDP1','little')
EXPORT=prepare.EXPORT
EXPORT_SIZE=prepare.EXPORT_SIZE
IMPORTS=prepare.IMPORTS
def bridges():
    raw=bytearray(prepare.BRIDGE)
    raw.extend(bytes((-len(raw))%16));generation_at=len(raw);raw.extend(GENERATION)
    fixups=list(prepare.FIXUPS)
    fixups.append(('gen_generation',generation_at+GENERATION_HOLES['generation']))
    h=generation_at+GENERATION_HOLES['clang_prepare']
    struct.pack_into('<i',raw,h,-h-4)
    dynamic=list(prepare.DYNAMIC_RELOCATIONS)
    for name,module in [('intake',legacy.intake),('proof',legacy.proof),('prepare',legacy.prepare)]:
        raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(module.BRIDGE)
        if name!='prepare':
            h=generation_at+GENERATION_HOLES[name]
            struct.pack_into('<i',raw,h,at-h-4)
        else:
            fixups.append((ALIASES['gen_prepare_owner'],generation_at+GENERATION_HOLES['prepare']))
            for outer,inner in [('capture','build'),('image','image'),('probe','probe'),('retirement','retirement')]:
                ih=module.OUTER_HOLES[inner]
                target=at+ih+4+struct.unpack_from('<i',module.BRIDGE,ih)[0]
                h=generation_at+GENERATION_HOLES[outer]
                struct.pack_into('<i',raw,h,target-h-4)
        for role,positions in module.HOLES.items():
            if isinstance(positions,int):positions=[positions]
            for h in positions:fixups.append((ALIASES['gen_'+name+'_'+role],at+h))
        dynamic.extend(('@bridge',at+h,symbol)for h,symbol in getattr(module,'RELOCATIONS',()))
    dynamic.sort(key=lambda row:(0,row[1])if row[0]=='@bridge'else(1+ROLES.index(row[0]),row[1]))
    return bytes(raw),tuple(fixups),tuple(dynamic),generation_at
BRIDGE,FIXUPS,DYNAMIC_RELOCATIONS,GENERATION_AT=bridges()
ENTRY_OFFSETS=prepare.ENTRY_OFFSETS
LENGTH_FIXUPS=prepare.LENGTH_FIXUPS
BRIDGE_EXPORTS=dict(prepare.BRIDGE_EXPORTS,**{'@generation':(GENERATION_AT,len(GENERATION))})
EXTRA_EXPORTS=prepare.EXTRA_EXPORTS+(('hia_mv_runtime_generation','@generation'),)
assert len(ROLES)==59 and all(role in ROLES for role,h in FIXUPS)
def context_call(fn,*args):
    changes={name:globals()[name]for name in (
      'ROLES','MAGIC','BRIDGE','FIXUPS','ENTRY_OFFSETS','LENGTH_FIXUPS',
      'DYNAMIC_RELOCATIONS','IMPORTS','EXPORT','EXTRA_EXPORTS','BRIDGE_EXPORTS','EXPORT_SIZE')}
    old={name:getattr(base,name)for name in changes}
    try:
        for name,value in changes.items():setattr(base,name,value)
        return fn(*args)
    finally:
        for name,value in old.items():setattr(base,name,value)
def fixed_bridge_source(raw):
    """Encode only build-time immutable bytes, including exact back references."""
    buckets={};commands=[];literal=bytearray();literal_at=0;at=0
    def flush():
        nonlocal literal
        for i in range(0,len(literal),8):
            chunk=literal[i:i+8]
            commands.append(f'    write(o,at+{literal_at+i},{int.from_bytes(chunk,"little")},{len(chunk)})')
        literal=bytearray()
    while at<len(raw):
        best=0;prior=0
        if at+8<=len(raw):
            for old in reversed(buckets.get(raw[at:at+8],())[-96:]):
                n=8
                while at+n<len(raw)and raw[old+n]==raw[at+n]:n+=1
                if n>best:best=n;prior=old
        if best>=24:
            flush()
            commands.append(f'    generation_child_bridge_copy(o,at+{at},at+{prior},{best})')
            step=best
        else:
            if not literal:literal_at=at
            literal.append(raw[at]);step=1
        for pos in range(at,at+step):
            if pos+8<=len(raw):buckets.setdefault(raw[pos:pos+8],[]).append(pos)
        at+=step
    flush()
    calls=[];functions=[]
    for i in range(0,len(commands),120):
        name='generation_child_bridge_bytes_'+str(i//120)
        calls.append(name)
        functions.append('def '+name+'(o:mutbuf,at:u64) -> u32:\n'+'\n'.join(commands[i:i+120])+'\n    return 0\n')
    functions.append('''def generation_child_bridge_copy(o:mutbuf,to:u64,source:u64,n:u64) -> u32:
    i=0
    while i<n:
        store(o,to+i,byte(o,source+i))
        i=i+1
    return 0
''')
    return calls,'\n'.join(functions)
def source_program():
    original=base.base.emitters
    calls,body=fixed_bridge_source(BRIDGE)
    def emit(name,raw):
        if name=='prefix':
            assert raw[64:]==BRIDGE
            header_calls,header=original('generation_child_elf_header',raw[:64])
            wrapper='def generation_child_object_bridge(o:mutbuf,at:u64) -> u32:\n'
            for call in calls:wrapper+='    '+call+'(o,at+64)\n'
            wrapper+='    return 0\n'
            return header_calls+['generation_child_object_bridge'],header+'\n'+body+'\n'+wrapper
        if name=='flat_prefix':
            assert raw==BRIDGE
            return calls,''
        return original(name,raw)
    try:
        base.base.emitters=emit
        return context_call(base.source_program)
    finally:
        base.base.emitters=original
def reference_object(parts):return context_call(base.reference_object,parts)
def reference_flat(parts):return context_call(base.reference_flat,parts)
def main():
    tree=document(source_program(),'generation_lease_owner_generation_child_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_generation_child_packer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),len(ROLES),flush=True)
if __name__=='__main__':main()
