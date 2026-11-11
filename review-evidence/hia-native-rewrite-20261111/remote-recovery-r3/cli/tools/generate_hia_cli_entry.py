from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT.parent/'Hepta-agent-edit-native')]
from cli_authoring import document,expanded,profile
from cli_entry_owner import CONSTANTS,BODY,COMMON,literals
from hepta.hia_agent_assembly import render_assembly
if __name__=='__main__':
    doc=document(expanded(BODY+literals()+COMMON,CONSTANTS),'cli_entry_controller')
    p=ROOT/'examples/hia_bootstrap/cli_entry_controller.hiaasm'
    p.write_text(render_assembly(doc))
    (ROOT/'development/entry-profile-r1.json').write_text(json.dumps(profile(doc),sort_keys=True,indent=2)+'\n')
    print(p.stat().st_size,profile(doc))
