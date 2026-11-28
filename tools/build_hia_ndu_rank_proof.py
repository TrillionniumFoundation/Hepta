"""Native reconstruction of the original scalar/call/public proof dependency.

All proof decisions remain in the actual HIA images. This constructor only
captures sources, compiles them, and supplies the fixed native pack frames.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
from tools.build_hia_ndu_evaluator import _read,_run,_SELF as LEAF_SELF
from tools.build_hia_ndu_rank_components import NativeFlat,SELF_BYTES as RANK_SELF
ROOT=Path(__file__).resolve().parents[1]
SELF="tools/build_hia_ndu_rank_proof.py"
SELF_BYTES=Path(__file__).read_bytes()
SCALAR=("native_scalar_proof_policy","native_scalar_proof_hash","core_admission",
 "json_canonical","multiversion_proof_graph","cnf","evaluate_reference_wire",
 "scalar_reference","general_cnf")
CALL=("native_call_proof_policy","native_scalar_proof_hash","core_admission",
 "json_canonical","multiversion_proof_graph","native_call_closure_graph",
 "evaluate_reference_wire","scalar_reference","general_call_cnf","native_call_graph_linker")
FACADE=("public_proof_facade","ndu_rank_sha_stream_private","multiversion_prepare_process",
 "native_public_proof_receipt","native_public_proof_json",
 "native_public_call_proof_receipt","public_proof_typed","public_proof_values",
 "bounded_unroll_transform","bounded_unroll_interface","bounded_unroll_solver","bounded_unroll_workflow",
 "normalizer_image","primitive_proof_image","call_proof_image","bounded_unroll_receipt")
PACKERS=("native_scalar_proof_packer","native_call_proof_packer","public_proof_facade_packer")
COMPILER="494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af"
NORMALIZER="84619bd15d8408f52c04519af11664cc4fa52cac352e7ad6680b6d50429123c6"
ORIGINAL="744900be77472942723f0f9b3d640825cb48a75ae5bcb4a166092a0ddf0dc4f6"
def build(output,compiler,normalizer,*,root=ROOT,observe_current=False):
 root=Path(root).resolve(strict=True);output=Path(output)
 compiler=Path(compiler).resolve(strict=True);normalizer=Path(normalizer).resolve(strict=True)
 if sys.platform!="linux" or os.uname().machine!="x86_64":raise ValueError("Linux x86_64 required")
 names=sorted((set(SCALAR)|set(CALL)|set(FACADE)|set(PACKERS))-{"normalizer_image","primitive_proof_image","call_proof_image"})
 paths={n:"examples/hia_bootstrap/"+n+".hepta" for n in names}
 captured={n:_read(root/path) for n,path in paths.items()}
 tools={SELF:SELF_BYTES,"tools/build_hia_ndu_evaluator.py":LEAF_SELF,"tools/build_hia_ndu_rank_components.py":RANK_SELF}
 if any(_read(root/p)!=v for p,v in tools.items()) or _read(Path(__file__))!=SELF_BYTES:raise ValueError("executed constructor differs")
 comp=_read(compiler);norm=_read(normalizer)
 if sha256(comp).hexdigest()!=COMPILER or len(norm)!=5980873 or sha256(norm).hexdigest()!=NORMALIZER:raise ValueError("fixed native dependency differs")
 def unchanged():
  if any(_read(root/paths[n])!=v for n,v in captured.items()) or any(_read(root/p)!=v for p,v in tools.items()) or _read(compiler)!=comp or _read(normalizer)!=norm or _read(Path(__file__))!=SELF_BYTES:raise ValueError("proof construction inputs changed")
 before={paths[n]:{"bytes":len(v),"sha256":sha256(v).hexdigest()} for n,v in captured.items()}
 before.update({p:{"bytes":len(v),"sha256":sha256(v).hexdigest()} for p,v in tools.items()})
 output.mkdir(mode=0o700);start=time.monotonic()
 (output/"source-before.json").write_text(json.dumps(before,indent=2)+"\n")
 flats={};compiled=[]
 for n in names:
  raw,record=_run(output,n,[compiler,"compile"],captured[n],executable=comp);flats[n]=raw
  (output/(n+".flat")).write_bytes(raw)
  compiled.append({"name":n,"bytes":len(raw),"sha256":sha256(raw).hexdigest()})
  (output/"compiled.json").write_text(json.dumps(compiled,indent=2)+"\n")
  print("PROOF_COMPILED",n,len(raw),sha256(raw).hexdigest(),flush=True)
 unchanged()
 products={}
 def pack(label,policy,magic,parts,capacity):
  request=magic+struct.pack("<"+str(len(parts))+"Q",*(len(p) for p in parts))+b"".join(parts)
  (output/(label+".stdin")).write_bytes(request)
  with NativeFlat(flats[policy]) as pk:
   rc,raw=pk.call(request,capacity)
   if rc>=0xfffffffc:raise ValueError(("native proof pack refused",label,rc))
   image=raw[:rc]
   rc2,raw2=pk.call(request,capacity)
   if rc2!=rc or raw2[:rc2]!=image:raise ValueError("native proof constructions differ")
  if image[:4]!=b"\x7fELF":raise ValueError("native proof image is not ELF")
  p=output/label;p.write_bytes(image);p.chmod(0o500)
  products[label]={"bytes":len(image),"sha256":sha256(image).hexdigest(),"native_pack_calls":2}
  (output/"products.json").write_text(json.dumps(products,indent=2)+"\n")
  print("PROOF_PACKED",label,len(image),sha256(image).hexdigest(),flush=True)
  return image
 primitive=pack("hia-native-scalar-proof","native_scalar_proof_packer",b"HIAMVK02",[flats[x] for x in SCALAR],8<<20)
 call=pack("hia-native-call-proof","native_call_proof_packer",b"HIAMCK01",[flats[x] for x in CALL],8<<20)
 extra={"normalizer_image":norm,"primitive_proof_image":primitive,"call_proof_image":call}
 public=pack("hia-public-proof","public_proof_facade_packer",b"HIAUFP01",[extra[x] if x in extra else flats[x] for x in FACADE],16<<20)
 unchanged()
 if not observe_current and (len(public)!=16159172 or sha256(public).hexdigest()!=ORIGINAL):raise ValueError("original public proof image differs")
 report={"schema":"hepta.hia.ndu-rank-proof-construction.v1","passed":not observe_current,
  "construction_completed":True,"original_identity_match":len(public)==16159172 and sha256(public).hexdigest()==ORIGINAL,
  "source_unchanged":True,"compile":compiled,"products":products,"wall_seconds":time.monotonic()-start,
  "matching_cold":False,"whole_installed_rebuild":False}
 (output/"source-after.json").write_text(json.dumps(before,indent=2)+"\n")
 (output/"report.json").write_text(json.dumps(report,indent=2)+"\n")
 print("CURRENT_PROOF_CONSTRUCTION_OBSERVED" if observe_current else "ORIGINAL_PROOF_IDENTITY_PASS",flush=True)
if __name__=="__main__":
 p=argparse.ArgumentParser(description=__doc__)
 for x in ("output","compiler","normalizer"):p.add_argument("--"+x,type=Path,required=True)
 p.add_argument("--observe-current",action="store_true")
 a=p.parse_args();build(a.output,a.compiler,a.normalizer,observe_current=a.observe_current)
