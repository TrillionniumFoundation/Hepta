"""Generate reconstructed CLI JSON pretty owner, without worker output quotas."""
from pathlib import Path
import ast,json
from cli_authoring import document,expanded,profile
from cli_pretty_owner import BODY
from cli_argv_common import BODY as SHARED
from hepta.hia_agent_assembly import render_assembly
magic=lambda x:int.from_bytes(x.encode(),'little')
constants=dict(COMMAND=magic('HIAJPC01'),MAGIC=magic('HIAJPW01'),EVENT=magic('HIAJPE01'),BAD=0xfffffffd,GROW=0xfffffffe,MAX=(1<<64)-1,NONE=(1<<64)-1,STACK=2048,POS=96,DEPTH=104,ROOT=112,FAULT=120,MODE=128,CURSOR=136,NEEDED=144,OUTBASE=152,INFINITY=int.from_bytes(b'Infinity','little'),NAN=int.from_bytes(b'NaN','little'))
shared='\n'.join(ast.unparse(x) for x in ast.parse(SHARED).body if isinstance(x,ast.FunctionDef) and x.name in {'get','put','uint','point'})+'\n'
doc=document(expanded(BODY+shared,constants),'hia_cli_pretty')
target=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/cli_pretty.hiaasm';target.write_text(render_assembly(doc),encoding='utf-8')
print(json.dumps({'source':str(target),'profile':profile(doc)},sort_keys=True))
