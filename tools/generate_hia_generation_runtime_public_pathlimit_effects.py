"""Constructor-only exact retirement path boundary, retaining raw profiles."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_public_effects as prior
from tools import generate_hia_generation_runtime_constructor_handles as handles
ROOT=Path(__file__).resolve().parents[1]
def source_program():
 s=prior.source_program();old='    if n>4045:\n'
 assert s.count(old)==1
 return s.replace(old,f'    if n>4045+choose(get(w,424)=={handles.CONTEXT},1,0):\n',1)
def main():
 t=document(source_program(),'generation_runtime_public_pathlimit_effects')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_public_pathlimit_effects.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
