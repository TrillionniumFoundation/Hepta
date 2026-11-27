"""Single-root typed VFY frontend profile, with unchanged original root limits."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_frontend_fusion_packer as prior
from tools import generate_hia_generation_runtime_verified_frontend_capsule_packer as front
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGFUP8','little')
ROLES=prior.ROLES;BRIDGE=prior.BRIDGE;IMPORTS=prior.IMPORTS;HOLES=prior.HOLES
RELOCATIONS=prior.prior.RELOCATIONS+front.DYNAMIC_RELOCATIONS
def call(fn,*args):
 changes=dict(MAGIC=MAGIC,front=front,RELOCATIONS=RELOCATIONS)
 old={name:getattr(prior,name)for name in changes}
 try:
  for name,value in changes.items():setattr(prior,name,value)
  return fn(*args)
 finally:
  for name,value in old.items():setattr(prior,name,value)
def fixed_parts():return call(prior.fixed_parts)
def source_program():return call(prior.source_program)
def reference_object(parts):return call(prior.reference_object,parts)
def main():
 tree=document(source_program(),'generation_runtime_verified_frontend_fusion_packer')
 path=ROOT/'examples/hia_bootstrap/generation_runtime_verified_frontend_fusion_packer.hepta';path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
