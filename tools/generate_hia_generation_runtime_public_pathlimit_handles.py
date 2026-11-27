"""Capture the actual syscall errno and full admitted retirement path."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_public_filesystem_handles as prior
ROOT=Path(__file__).resolve().parents[1]
def source_program():
 s=prior.source_program()
 assert s.count('if n==0 or n>4095:')==1
 return s.replace('if n==0 or n>4095:','if n==0 or n>4096:',1)
def main():
 t=document(source_program(),'generation_runtime_public_pathlimit_handles')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_public_pathlimit_handles.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
