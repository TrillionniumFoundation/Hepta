"""Generate reconstructed HIA OS-byte capture; authoring only."""
from pathlib import Path
import ast,json,unicodedata
from cli_authoring import document,expanded,profile
from cli_argv_common import BODY as SHARED
from cli_capture_owner import BODY
from hepta.hia_agent_assembly import render_assembly
assert unicodedata.unidata_version == "15.0.0", "exact original Unicode profile required"
ranges=[]
for cp in range(0x110000):
 if unicodedata.category(chr(cp))=="Nd":
  if ranges and cp==ranges[-1][1]+1:ranges[-1][1]=cp
  else:ranges.append([cp,cp])
assert 1024+16*len(ranges)<=4096
init="def nd_initialize(w:mutbuf) -> u64:\n"+"".join("    put(w, %d, %d)\n    put(w, %d, %d)\n"%(1024+i*16,a,1032+i*16,b) for i,(a,b) in enumerate(ranges))+"    return 0\n"
shared="\n".join(ast.unparse(n) for n in ast.parse(SHARED).body if isinstance(n,ast.FunctionDef) and n.name in {"get","put","uint","point"})+"\n"
magic=lambda s:int.from_bytes(s.encode(),"little")
constants=dict(C_MAGIC=magic("HIACOW01"),C_EVENT=magic("HIACOE01"),SOURCE_MAGIC=magic("HIACOS01"),ARG_MAGIC=magic("HIACLA01"),BASE=4096,NDTAB=1024,NDCOUNT=len(ranges),MAX=(1<<64)-1,NONE=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,COLUMNS=int.from_bytes(b"COLUMNS=","little"))
doc=document(expanded(BODY+"\n"+init+shared,constants),"hia_cli_capture")
path=Path(__file__).resolve().parents[1]/"examples/hia_bootstrap/cli_capture.hiaasm"
path.parent.mkdir(parents=True,exist_ok=True);path.write_text(render_assembly(doc),encoding="utf-8")
print(json.dumps({"source":str(path),"profile":profile(doc),"unicode_version":unicodedata.unidata_version,"nd_intervals":len(ranges)},sort_keys=True))
