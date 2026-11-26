"""Fixed native Clang preparation child; Python is an author/oracle only.

The product contains no Value implementation. The LLVM and shared-ELF bodies
are each emitted once; the distinct single-shot and streaming SHA roles retain
their original interfaces. All dynamic calls are fixed imports, not request
provided targets.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_clang_value_packer as clang
from tools import generate_hia_generation_lease_owner_clang_fresh_image_packer as image
from tools import generate_hia_multiversion_probe_packer as probe
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('41ba01000000eb0b4531d2eb0641ba02000000535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4c899424980000004d85e40f842c0600004d85ed0f84230600004d85f60f841a06000049f7c6070000000f850d0600004881fb000000200f85000600004881fd800000000f82f30500004c89e04c01f80f82e705000048898424800000004c89e84801e80f82d305000048898424880000004c89f04801d80f82bf05000048898424900000004c3ba42488000000730e4c3bac24800000000f829f0500004c3ba4249000000073274c3bb42480000000731d498d860000001e4939c40f857b0500004981ff0000a0000f876e0500004c3bac249000000073274c3bb42488000000731d498d86000000184939c50f854a0500004881fd000020000f873d0500004c8b9424980000004d85d20f84600100004983fa020f84cf0100004981ff000100000f82150500004881fd000800000f820805000048b84849414d56474632493904240f85f4040000498b4424084883f8020f87e50400004885c0742d4981ff000100000f85d3040000b91000000049833c0c000f85c304000083c10881f90001000072eae9a80100004881fd000810000f82a604000049837c2410000f859a04000049837c2418000f848e04000049f7442420070000000f857f04000049837c2440000f847304000049837c2458000f8567040000498b4424284885c00f8459040000483d000080000f874d040000498b4c24304881f9500100000f823b0400004881f9101400000f872e0400004801c80f8225040000498b4c24384885c90f84170400004881f9ff0f00000f870a0400004801c80f82010400004805000100000f82f50300004c39f80f85ec030000b96000000049833c0c000f85dc03000083c10881f90001000072eae9c10000004981ff800000000f85bf03000048b84849414d56474231493904240f85ab03000049837c2408000f849f03000049837c2410000f849303000049f7442410070000000f858403000049817c2418000100000f857503000049837c2420000f846903000049817c2428ffffff7f0f875a030000b930000000eb324981ff800000000f854603000048b84849414d56474531493904240f853203000049837c2408010f8726030000b91000000049833c0c000f851603000083c10881f98000000072eab8270000000f054885c00f8efb02000048898424a00000004983be1000001900745649bb4849414d564757324d399e100000190f85d20200004d39b6180000190f85c5020000493986200000190f85b8020000488d053efcffff493986280000190f85a40200004883bc2498000000000f8495020000eb0f4883bc2498000000000f858402000031c0b901000000f0410fb18e3801001985c00f856c020000498b86000000194889442458498b86080000194889442460498b8630000019488944246848c70424000000004c897424084c896424104c896c241849c786000000190000000049c7860800001900000000488b842498000000498986300000194c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84a901000083f8010f844a01000083f8020f842901000083f8030f842501000083f80b0f842501000083f8040f828001000083f80a0f877701000089442450498b7d00498b75084889f84801f00f825f0100004839d80f87560100004c01f7498b5510498b4d184889d04801c80f823f0100004839d80f87360100004c01f24d8b45204d8b4d28837c24500a0f8482000000837c245006763b4c89c04c01c80f820d0100004839d80f87040100004d01f0837c245007740e837c245008740ee800000000eb76e800000000eb6fe800000000eb684981f9000020200f85d10000004d8b86680000194d85c00f84c1000000837c245004740e837c245005740ee800000000eb36e800000000eb2fe800000000eb284981f9000100000f85910000004d8b86480000194d8b9e400000194d85c0747e4d85db747941ffd389c0eb624c89f0eb5d488d0533faffffeb54488b8424a0000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898608000019e938feffff31c0eb334983be00000019007524488b44245849898600000019488b44246049898608000019488b44246849898630000019b8fdffffff49c7863801001900000000eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3534154415541564881ec080100004989d44989cd4d89c64885ff0f84c20100004883fe200f85b801000048b848494147504f42314839070f85a501000048817f08ffffff7f0f879701000048837f10000f858c01000048837f18000f8581010000488b470848898424000100004d85e40f846c01000049f7c4070000000f855f0100004981fd000000200f85520100004d85f60f84490100004981f9000800000f853c0100004c89e04c01e80f82300100004c89f14c01c90f82240100004939cc73094939c60f821601000048b8484941474c4f57314939060f85030100004d3976100f85f900000049837e18000f84ee00000049837e50010f85e3000000b8270000000f05493b46080f85d2000000498d8600020000493946300f85c100000049817e38000100000f85b30000004889e7b90001000031c0fcf3aa48b84849414d5647423148890424498b46284889442408498b46304889442410498b46384889442418498b86980200004889442420488b84240001000048894424284889e7be80000000488d942480000000b9800000004d89e04d89e9e8e0f7ffff85c0754548b84849414d56474252483984248000000075254883bc248800000000751a4883bc24d800000001750f4883bc24e000000001750431c0eb0cb8fbffffffeb05b8fdffffff4881c408010000415e415d415c5bc3')
OUTER_HOLES={"clang_bind":1416,"clang_compile":1423,"clang_exception":1409,"image":1352,"policy":1146,"probe":1359,"retire":1345}
OUTER_EXPORTS={"hia_generation_lease_clang_prepare":0,"hia_generation_lease_clang_prepare_bind":8,"hia_generation_lease_clang_prepare_bind_owner":1674,"hia_generation_lease_clang_prepare_exception":13}
ROLES=('owner',)+tuple('c_'+r for r in clang.ROLES)+(
    'i_image','i_sha','i_mapping','i_json','i_retire','i_retirement_state',
    'p_policy','p_vectors','p_projector','p_vm')
assert len(ROLES)==47
MAGIC=int.from_bytes(b'HIAGCPP1','little')
IMPORTS=('dlsym','dlopen','dlclose')
EXPORT='hia_generation_lease_clang_prepare'
EXPORT_SIZE=len(OUTER)
def bridges():
    raw=bytearray(OUTER)
    starts={}
    for name,part in [('clang',clang.BRIDGE),('image',image.BRIDGE),('probe',probe.BRIDGE)]:
        raw.extend(bytes((-len(raw))%16));starts[name]=len(raw);raw.extend(part)
    c=starts['clang'];i=starts['image'];p=starts['probe']
    targets={'clang_compile':c,'clang_bind':c+clang.BRIDGE_EXPORTS['@bind'][0],
      'clang_exception':c+clang.BRIDGE_EXPORTS['@exception'][0],
      'image':i,'retire':i+image.RETIRE_AT,'probe':p}
    for name,target in targets.items():
        hole=OUTER_HOLES[name]
        assert raw[hole:hole+4]==bytes(4)
        struct.pack_into('<i',raw,hole,target-hole-4)
    fixups=[('owner',OUTER_HOLES['policy'])]
    fixups.extend(('c_'+role,c+hole)for role,hole in clang.FIXUPS)
    mapping={'image':'i_image','sha':'i_sha','elf':'c_shared','mapping':'i_mapping',
      'json':'i_json','retire':'i_retire','retirement_state':'i_retirement_state','llvm':'c_llvm'}
    for role,holes in image.HOLES.items():
        for hole in holes:fixups.append((mapping[role],i+hole))
    for role,hole in probe.HOLES.items():fixups.append(('p_'+role,p+hole))
    dynamic=[('@bridge'if role=='@bridge'else'c_'+role,c+at if role=='@bridge'else at,name)
      for role,at,name in clang.DYNAMIC_RELOCATIONS]
    dynamic.extend(('@bridge',i+at,name)for at,name in image.RELOCATIONS)
    dynamic.sort(key=lambda row:(0,row[1])if row[0]=='@bridge'else(1+ROLES.index(row[0]),row[1]))
    length=tuple(('c_'+role,c+at)for role,at in clang.LENGTH_FIXUPS)
    return bytes(raw),tuple(fixups),tuple(dynamic),length,starts
BRIDGE,FIXUPS,DYNAMIC_RELOCATIONS,LENGTH_FIXUPS,STARTS=bridges()
ENTRY_OFFSETS={'c_'+role:at for role,at in clang.ENTRY_OFFSETS.items()}
BRIDGE_EXPORTS={
    '@bind':(OUTER_EXPORTS['hia_generation_lease_clang_prepare_bind'],len(OUTER)-8),
    '@exception':(OUTER_EXPORTS['hia_generation_lease_clang_prepare_exception'],len(OUTER)-13),
    '@owner_bind':(OUTER_EXPORTS['hia_generation_lease_clang_prepare_bind_owner'],
                  len(OUTER)-OUTER_EXPORTS['hia_generation_lease_clang_prepare_bind_owner']),
    '@image':(STARTS['image'],len(image.IMAGE)),
    '@retire':(STARTS['image']+image.RETIRE_AT,len(image.retirement.BRIDGE)),
    '@probe':(STARTS['probe'],probe.EXPORT_SIZE),
}
EXTRA_EXPORTS=(
    ('hia_generation_lease_clang_prepare_bind','@bind'),
    ('hia_generation_lease_clang_prepare_exception','@exception'),
    ('hia_generation_lease_clang_prepare_bind_owner','@owner_bind'),
    ('hia_generation_lease_clang_prepare_image','@image'),
    ('hia_generation_lease_clang_prepare_retire','@retire'),
    ('hia_generation_lease_clang_prepare_probe','@probe'),
    ('hia_program_llvm','c_llvm'),
    ('hia_program_llvm_metadata','c_llvm_meta'),
)
def context_call(fn,*args):
    changes={name:globals()[name]for name in (
      'ROLES','MAGIC','BRIDGE','FIXUPS','ENTRY_OFFSETS','LENGTH_FIXUPS',
      'DYNAMIC_RELOCATIONS','IMPORTS','EXPORT','EXTRA_EXPORTS','BRIDGE_EXPORTS','EXPORT_SIZE')}
    old={name:getattr(clang,name)for name in changes}
    try:
        for name,value in changes.items():setattr(clang,name,value)
        return fn(*args)
    finally:
        for name,value in old.items():setattr(clang,name,value)
def source_program():
    original=clang.base.emitters
    bridge_calls,bridge_source=original('prepare_bridge_bytes',BRIDGE)
    def emit(name,raw):
        if name=='prefix':
            assert raw[64:]==BRIDGE
            calls,header_source=original('prepare_elf_header',raw[:64])
            wrapper='def prepare_object_bridge(o:mutbuf,at:u64) -> u32:\n'
            for call in bridge_calls:wrapper+='    '+call+'(o,at+64)\n'
            wrapper+='    return 0\n'
            return calls+['prepare_object_bridge'],header_source+'\n'+bridge_source+'\n'+wrapper
        if name=='flat_prefix':
            assert raw==BRIDGE
            return bridge_calls,''
        return original(name,raw)
    try:
        clang.base.emitters=emit
        return context_call(clang.source_program)
    finally:
        clang.base.emitters=original
def reference_object(parts):return context_call(clang.reference_object,parts)
def reference_flat(parts):return context_call(clang.reference_flat,parts)
def main():
    tree=document(source_program(),'generation_lease_owner_clang_prepare_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_clang_prepare_packer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),flush=True)
if __name__=='__main__':main()
