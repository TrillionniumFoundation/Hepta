"""Physical-join cleanup for the bound native business-worker profile."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_business_cleanup as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 INPUT='HIABGCQ2',REPLY='HIABGCR2',CONTEXT='HIABGCC2',
 BUSINESS_CONTEXT='HIABWBC2').items()})
def source_program():
    saved=original.C
    try:
        original.C=C
        return original.source_program()
    finally:
        original.C=saved
def main():
    doc=document(source_program(),'background_optimizer_business_owner_cleanup')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_business_owner_cleanup.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
