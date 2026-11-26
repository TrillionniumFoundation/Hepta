"""Owned Path.resolve fixed identity boundary and single-role HIA packer."""
from pathlib import Path
from tools import generate_hia_native_path_resolve_packer as original
from tools.generate_hia_artifact_publication import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd800000000f82a80100004881fb001003000f829b0100004d85ed0f84920100004d85f60f84890100004c89e04c01f80f827d0100004c89ea4801ea0f82710100004c89f14801d90f82650100004939cd73094939d60f82570100004d85ff74254d85e40f84490100004939d473094939c50f823b0100004939cc73094939c60f822d0100004983ff200f822301000048b848494150544f3031493904240f850f01000049837c240802754f4983ff200f85fd00000048b8484941504f573031493986000900000f85e60000004d39b6080900000f85d900000049399e180900000f85cc000000b8270000000f05493986100900000f85b80000004d8976104c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849a00000083f80374dc83f8010f85870000004d8b553831c9498b44cd084d89d34183e30349c1ea024585db742e4183fb0174124183fb0274184839d8775b4c01f07256eb164c39f8774f4c01e0724aeb0a4839e877434c01e8723e488944cc20ffc183f90672b14d85d2752d488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549894608e94cffffffb8fdffffff4881c488000000415f415e415d415c5d5bc3')
HOLES={'policy':311}
EXPORT_SIZE=495
MAGIC=int.from_bytes(b'HIAPTOP1','little')
def changed(call,*args):
 changes=dict(BRIDGE=BRIDGE,HOLES=HOLES,EXPORT_SIZE=EXPORT_SIZE,MAGIC=MAGIC)
 old={k:getattr(original,k)for k in changes}
 try:
  for k,v in changes.items():setattr(original,k,v)
  return call(*args)
 finally:
  for k,v in old.items():setattr(original,k,v)
def source_program():return changed(original.source_program)
def reference_object(parts):return changed(original.reference_object,parts)
def main():
 t=document(source_program(),'native_path_resolve_owned_packer');p=ROOT/'examples/hia_bootstrap/native_path_resolve_owned_packer.hepta'
 p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),flush=True)
if __name__=='__main__':main()
