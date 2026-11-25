"""HTTP default ServerConfig presentation, sharing the SDK/session state machine."""
import ast,json
from pathlib import Path
from tools import generate_hia_mcp_service_session as base
INSTRUCTIONS="Filesystem tools. File lines render as `N:hh|content`; `N:hh` is the line id edit tools target, and edit results are diffs with fresh ids, so edits chain without re-viewing files. Reuse returned content and ids; read complete relevant blocks, then act on them. Each response costs a round trip: first decide what you need next, then request every call that doesn't depend on another's result in that one response."
CAPABILITIES={'experimental':{'claude/channel':{}},'resources':{'subscribe':True},'tools':{}}
SERVER_INFO={'name':'rmcp','version':'3.9.0'}
def render():
 tree=ast.parse(Path(base.__file__).read_text())
 found=0
 for n in ast.walk(tree):
  if isinstance(n,ast.Tuple) and len(n.elts)==2 and isinstance(n.elts[0],ast.Constant) and n.elts[0].value=='server_info':
   suffix=b'","capabilities":'+json.dumps(CAPABILITIES,separators=(',',':')).encode()+b',"serverInfo":'+json.dumps(SERVER_INFO,separators=(',',':')).encode()+b',"instructions":'+json.dumps(INSTRUCTIONS,separators=(',',':')).encode()+b'}}\n'
   n.elts[1]=ast.Constant(suffix);found+=1
 for n in ast.walk(tree):
  if isinstance(n,ast.Tuple) and len(n.elts)==2 and isinstance(n.elts[0],ast.Constant) and n.elts[0].value=='discovery':
   value={'resultType':'complete','supportedVersions':list(base.VERSIONS),'capabilities':CAPABILITIES,'instructions':INSTRUCTIONS,'ttlMs':0,'cacheScope':'private','_meta':{'io.modelcontextprotocol/serverInfo':SERVER_INFO}}
   n.elts[1]=ast.Constant(b',"result":'+json.dumps(value,separators=(',',':')).encode()+b'}\n');found+=1
 assert found==2
 namespace={'__name__':'http_session_policy_author','__file__':base.__file__}
 exec(compile(ast.fix_missing_locations(tree),base.__file__,'exec'),namespace)
 return namespace['render']()
if __name__=='__main__':
 p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_session_policy.hepta'
 raw=render();p.write_text(raw);print(p.name,len(raw.encode()))
