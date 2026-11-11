"""Generate the native verified-publication transaction; development only."""
from pathlib import Path
from hashlib import sha256
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import cli_authoring
import cli_publication_verified_owner as owner
from hepta.hia_agent_assembly import render_assembly
def main():
    p=argparse.ArgumentParser();p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    body=cli_authoring.expanded(owner.BODY+owner.message_body(),owner.CONSTANTS)
    document=cli_authoring.document(body,"cli_verified_publication")
    profile=cli_authoring.profile(document)
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_params"]<=16,profile
    raw=render_assembly(document).encode("utf-8")
    a.out.mkdir(parents=True,exist_ok=False)
    (a.out/"authoring-expanded.py").write_text(body)
    (a.out/"source.hiaasm").write_bytes(raw)
    row=dict(scope="NEW_UNQUALIFIED_VERIFIED_PUBLICATION_TRANSACTION",
        bytes=len(raw),sha256=sha256(raw).hexdigest(),profile=profile)
    (a.out/"source.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
    print(json.dumps(row,sort_keys=True),flush=True)
if __name__=="__main__":main()
