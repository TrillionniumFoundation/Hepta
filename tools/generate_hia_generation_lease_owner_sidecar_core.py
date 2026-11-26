"""New sole-owner sidecar core; legacy raw/bound profiles remain unchanged."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_lease_owner_bound as bound
ROOT=Path(__file__).resolve().parents[1]
def source_program():
    source=bound.source_program()
    token='        magic = word_load(s, 64)\n'
    if token not in source:token='        magic=word_load(s,64)\n'
    assert source.count(token)==1
    source=source.replace(token,token+'        if magic=='+str(int.from_bytes(b'HIABVQ06','little'))+':\n            return 4294967293\n')
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_core')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_core.hepta'
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
