"""Generate the new native CLI publication Path prefix owner."""
from pathlib import Path
import json
from cli_authoring import document,expanded,profile
from cli_publication_path_owner import BODY,CONSTANTS
from hepta.hia_agent_assembly import render_assembly
def make():
    doc=document(expanded(BODY,CONSTANTS),"hia_cli_publication_path_prefix")
    return doc
if __name__=="__main__":
    doc=make();target=Path(__file__).resolve().parents[1]/"examples/hia_bootstrap/cli_publication_path.hiaasm"
    target.parent.mkdir(parents=True,exist_ok=True);target.write_text(render_assembly(doc),encoding="utf-8")
    print(json.dumps(dict(source=str(target),profile=profile(doc)),sort_keys=True))
