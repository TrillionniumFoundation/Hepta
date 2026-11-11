"""Authoring only. New complete CLI bounded-file HIA state machine."""
from pathlib import Path
import ast,json
from cli_authoring import document,expanded,profile
from cli_argv_common import BODY as SHARED
from cli_file_owner import BODY
from hepta.hia_agent_assembly import render_assembly
nodes=ast.parse(SHARED).body
shared=[n for n in nodes if isinstance(n,ast.FunctionDef) and n.name in {"get","put","uint","point"}]
mutable=ast.parse(ast.unparse(next(n for n in shared if n.name=="point"))).body[0]
mutable.name="point_mut";mutable.args.args=mutable.args.args[1:]
mutable.args.args[0].annotation=ast.Name(id="mutbuf",ctx=ast.Load())
class Rename(ast.NodeTransformer):
 def visit_Name(self,n):
  return ast.copy_location(ast.Name(id="w",ctx=n.ctx),n) if n.id=="s" else n
mutable=ast.fix_missing_locations(Rename().visit(mutable))
texts=["E_HIA_EDIT: cannot read ordinary input","E_HIA_EDIT: input must be a bounded ordinary file",
 "E_HIA_EDIT: input exceeds byte limit","open: embedded null character in path",
 "object of type 'NoneType' has no len()","'utf-8' codec can't encode character",
 " '\\u","' in position ","s in position ",": surrogates not allowed"]
literal=["def text(w:mutbuf, index:u64) -> u64:"]
for i,value in enumerate(texts):
 raw=value.encode("ascii");literal.append(f"    if index == {i}:")
 for at in range(0,len(raw),8):
  literal.append(f"        put(w, DIAG + get(w, 160) + {at}, {int.from_bytes(raw[at:at+8],'little')})")
 literal.append(f"        put(w, 160, get(w, 160) + {len(raw)})")
 literal.append("        return 0")
literal.extend(["    put(w, 8, 1)","    return 0"])
magic=lambda s:int.from_bytes(s.encode(),"little")
constants=dict(MAX=(1<<64)-1,NONE=(1<<64)-1,STATE_MAGIC=magic("HIAFRW01"),COMMAND=magic("HIAFRB01"),ACK=magic("HIAFRA01"),EVENT=magic("HIACRE01"),PATH=2048,DIAG=1024,BAD=0xfffffffd,GROW=0xfffffffe,OPEN_FLAGS=657408)
body=BODY+"\n"+"\n".join(literal)+"\n"+"\n".join(ast.unparse(n) for n in shared+[mutable])+"\n"
doc=document(expanded(body,constants),"hia_cli_file")
p=Path(__file__).resolve().parents[1]/"examples/hia_bootstrap/cli_file.hiaasm"
p.parent.mkdir(parents=True,exist_ok=True);p.write_text(render_assembly(doc),encoding="utf-8")
print(json.dumps({"source":str(p),"profile":profile(doc)},sort_keys=True))
