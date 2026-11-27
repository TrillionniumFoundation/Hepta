"""Preserve the native retirement 4096-byte path boundary."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_generation_runtime_directory as prior
ROOT=Path(__file__).resolve().parents[1]
def source_program():
 s=prior.source_program()
 assert s.count('>4045')==2
 return s.replace('>4045','>4046')
def main():
 prior.base.C.update(prior.C)
 t=prior.base.document(source_program(),'generation_runtime_directory_pathlimit','directory')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_directory_pathlimit.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
