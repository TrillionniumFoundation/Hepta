"""Generate the full native immutable release-kit gate; no runtime host policy."""
from pathlib import Path
import sys,json
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
sys.path[:0]=[str(ROOT/'tools'),str(BASE/'Hepta-agent-edit-native')]
from build_authoring import document,expanded,profile
from clean_build_gate import BODY
from clean_build_gate_common import BODY as COMMON,CONSTANTS,literals,hashing
from hepta.hia_agent_assembly import render_assembly

def source():
 return expanded(BODY+COMMON+literals()+literals(True)+'\n'+hashing(),CONSTANTS)

def main():
 body=source();doc=document(body,'clean_build_gate');target=ROOT/'examples/hia_bootstrap/clean_build_gate.hiaasm';target.write_text(render_assembly(doc))
 (ROOT/'development/gate-profile-r1.json').write_text(json.dumps(profile(doc),indent=2)+'\n');print(target.stat().st_size,profile(doc))
if __name__=='__main__':main()
