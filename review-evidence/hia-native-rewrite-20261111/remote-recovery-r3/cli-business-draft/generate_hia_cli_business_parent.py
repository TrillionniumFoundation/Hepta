from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT.parent/'Hepta-agent-edit-native')]
from cli_authoring import document,expanded,profile
from cli_business_parent import CONSTANTS,BODY,COMMON,literals
from hepta.hia_agent_assembly import render_assembly
if __name__=='__main__':
    document_value=document(expanded(BODY+literals()+COMMON,CONSTANTS),'cli_business_parent')
    target=ROOT/'examples/hia_bootstrap/cli_business_parent.hiaasm'
    target.write_text(render_assembly(document_value))
    (ROOT/'development/business-parent-profile.json').write_text(
        json.dumps(profile(document_value),sort_keys=True,indent=2)+'\n')
    print(target.stat().st_size,profile(document_value))
