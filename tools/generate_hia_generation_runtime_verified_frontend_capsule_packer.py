"""Typed native Runtime verification capsule; the original frontend profile is retained."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_frontend_capsule_packer as prior
from tools import generate_hia_generation_runtime_verify_exception_packer as error
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIARTFP2','little')
ROLES=prior.ROLES+('exception',)
DISPATCH=bytes.fromhex('4885ff741a4883fe08721448b848494152545851314839077505e900000000e900000000')
raw=bytearray(prior.BIND);raw.extend(bytes((-len(raw))%16));OPTIONS_AT=len(raw);raw.extend(prior.OPTIONS)
raw.extend(bytes((-len(raw))%16));VERIFY_AT=len(raw);raw.extend(DISPATCH);VERIFY_BODY_AT=len(raw);raw.extend(prior.VERIFY)
raw.extend(bytes((-len(raw))%16));ERROR_AT=len(raw);raw.extend(error.BRIDGE)
struct.pack_into('<i',raw,VERIFY_AT+27,ERROR_AT-VERIFY_AT-31)
struct.pack_into('<i',raw,VERIFY_AT+32,VERIFY_BODY_AT-VERIFY_AT-36)
raw.extend(bytes((-len(raw))%16));MALLOC_AT=len(raw);raw.extend(bytes.fromhex('4883ec08e8')+bytes(4)+bytes.fromhex('4883c408c3'))
FREE_AT=len(raw);raw.extend(bytes.fromhex('4883ec08e8')+bytes(4)+bytes.fromhex('4883c408c3'))
BRIDGE=bytes(raw)
HOLES={name:list(items)for name,items in prior.HOLES.items()}
HOLES['options']=[OPTIONS_AT+207];HOLES['verify']=[VERIFY_BODY_AT+207];HOLES['exception']=[ERROR_AT+207]
FIXED_HOLES=prior.FIXED_HOLES
IMPORTS=prior.IMPORTS
DYNAMIC_RELOCATIONS=((MALLOC_AT+5,'malloc'),(FREE_AT+5,'free'))
RELOCATIONS=DYNAMIC_RELOCATIONS+tuple((off,'hia_frontend_'+name)for name,holes in FIXED_HOLES.items()for off in holes)
LEAF_RELOCATIONS=(('transport',425,MALLOC_AT),('transport',436,FREE_AT),('freeze',425,MALLOC_AT),('freeze',436,FREE_AT))
EXPORTS=(('hia_generation_runtime_frontend_bind',0,len(prior.BIND)),
 ('hia_generation_runtime_constructor_options',OPTIONS_AT,len(prior.OPTIONS)),
 ('hia_generation_runtime_verify',VERIFY_AT,len(DISPATCH)+len(prior.VERIFY)))
def call(fn,*args):
 values=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,HOLES=HOLES,FIXED_HOLES=FIXED_HOLES,IMPORTS=IMPORTS,
  DYNAMIC_RELOCATIONS=DYNAMIC_RELOCATIONS,RELOCATIONS=RELOCATIONS,LEAF_RELOCATIONS=LEAF_RELOCATIONS,EXPORTS=EXPORTS)
 old={name:getattr(prior,name)for name in values}
 try:
  for name,value in values.items():setattr(prior,name,value)
  return fn(*args)
 finally:
  for name,value in old.items():setattr(prior,name,value)
def fixed_parts():return call(prior.fixed_parts)
def source_program():
 source=call(prior.source_program)
 for old,new in[('length(s)<104','length(s)<112'),('uint(s,8,8)!=11','uint(s,8,8)!=12'),
  ('total=104','total=112'),('while count<11:','while count<12:'),('at=104','at=112'),
  ('while i<11:','while i<12:'),('if i!=10:','if i!=11:')]:
  assert old in source,old;source=source.replace(old,new)
 return source
def reference_object(parts):
 if len(parts)!=12 or any(not x or len(x)>4194304 for x in parts):raise ValueError('twelve actual bounded native roles required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);positions={}
 for name,part in zip(ROLES,parts):
  raw.extend(bytes((-len(raw))%16));at=len(raw);positions[name]=at
  for off in HOLES[name]:struct.pack_into('<i',raw,64+off,at-64-off-4)
  raw.extend(part)
 for name,off,stub in LEAF_RELOCATIONS:
  at=positions[name]+off
  if raw[at:at+4]!=bytes(4):raise ValueError('exact unresolved fixed leaf import required')
  struct.pack_into('<i',raw,at,64+stub-at-4)
 size=len(raw)-64
 if size>4194304:raise ValueError('original bounded role limit')
 raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in[relas,symbols,strings,prior.common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
 for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
 return bytes(raw)
def main():
 tree=document(source_program(),'generation_runtime_verified_frontend_capsule_packer')
 path=ROOT/'examples/hia_bootstrap/generation_runtime_verified_frontend_capsule_packer.hepta';path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
