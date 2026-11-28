"""Native NDU facade packer for a typed sealed-constructor identity record.

All prior role layouts and byte caps remain. The independent HIANFP01 frame
replaces only the embedded constructor image with a 64-byte HIANRM01 record.
The actual descriptor is captured and fully hashed by the new facade.
"""
from pathlib import Path
from hashlib import sha256
from tempfile import TemporaryDirectory
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_public_proof_facade_packer as prior
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_proof_facade_packer.hepta"
PRIOR_SHA256="400b3b9213ac158e44a69b11882c4105905d1d96dee77135bb8f28a8ea2163bc"
MAGIC=int.from_bytes(b"HIANFP01","little")
RECORD=int.from_bytes(b"HIANRM01","little")

def policy():
    source=prior.POLICY
    def change(old,new):
        nonlocal source
        if source.count(old)!=1:raise ValueError("facade pack predecessor differs")
        source=source.replace(old,new,1)
    change("        if index>=12 and index<=14:\n            cap=8388608",
           "        if index==12:\n            cap=64\n        elif index==13 or index==14:\n            cap=8388608")
    change("        if index>=12 and index<=14 and child(s,source,piece,index!=12)==False:\n            return 0",
           "        if index==12 and normalizer_record(s,source,piece)==False:\n            return 0\n        if (index==13 or index==14) and child(s,source,piece,True)==False:\n            return 0")
    source+="""
def normalizer_record(s:readbuf,at:u64,n:u64) -> bool:
    if n!=64 or uint(s,at,8)!=RECORD or uint(s,at+8,8)<176 or uint(s,at+8,8)>8388608:
        return False
    return uint(s,at+16,8)==320 and uint(s,at+56,8)==0
"""
    return source

def document():
    original=Path(prior.__file__).read_bytes()
    if sha256(original).hexdigest()!=PRIOR_SHA256:raise ValueError("fixed facade packer differs")
    paths=(prior.ADAPTER,prior.PROCESS,prior.PRIMITIVE)
    captured={name:(ROOT/name).read_bytes() for name in paths}
    adapter,process,primitive=(captured[name]for name in paths)
    with TemporaryDirectory(prefix="hia-ndu-facade-transport-")as td:
        stub,symbols,_=prior.assemble_adapter(Path(td),prior.ADAPTER,adapter)
        _,primitive_symbols,_=prior.assemble_adapter(Path(td),prior.PRIMITIVE,primitive)
    hole=symbols["public_policy_hole"];table=symbols["embedded_roles"]
    assert stub[hole-1:hole+4]==b"\xe8\0\0\0\0" and table%8==0 and stub[table:table+336]==bytes(336)
    ph=prior.HOLES["policy"];assert prior.BRIDGE[ph-1:ph+4]==b"\xe8\0\0\0\0"
    header=prior.elf_header();prefix=header+stub;prefix+=bytes((-len(prefix))%8)
    start=len(prefix);prefix+=prior.BRIDGE;prefix+=bytes((-len(prefix))%8)
    constants={"PREFIX":len(prefix),"TABLE":len(header)+table,"POLICY_HOLE":len(header)+hole,
               "PROCESS_START":start,"PROCESS_HOLE":start+ph,
               "PRIMITIVE_TABLE":len(header)+primitive_symbols["embedded_roles"],"MAGIC":MAGIC,"RECORD":RECORD}
    source=policy()+"\ndef envelope(o:mutbuf) -> u64:\n"
    for at in range(0,len(prefix),8):
        piece=prefix[at:at+8];source+=f"    write(o, {at}, {int.from_bytes(piece,'little')}, {len(piece)})\n"
    source+="    return 0\n"
    result=prior.transport_document(source,module="ndu_rank_proof_facade_packer",extra=constants)
    result=prior.bind_adapter(result,adapter+b"\n"+process+b"\n"+primitive,prefix[len(header):],(hole,table,start-len(header)+ph))
    if Path(prior.__file__).read_bytes()!=original or any((ROOT/n).read_bytes()!=v for n,v in captured.items()):
        raise ValueError("NDU facade source changed during generation")
    return result

if __name__=="__main__":
    raw=render_assembly(document()).encode();(ROOT/OUTPUT).write_bytes(raw)
    print(OUTPUT,len(raw),sha256(raw).hexdigest())
