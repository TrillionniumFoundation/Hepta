"""Reviewed installation-relative frontend child with exact path boundary."""
from pathlib import Path
import json
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_fixed_component_catalog import source_program
from tools.generate_hia_generation_runtime_frontend_catalog import EXPORTS
ROOT=Path(__file__).resolve().parents[1]
def main():
 rows=json.loads((ROOT/'docs/HIA_RUNTIME_FRONTEND_PATHLIMIT_CHILD_CATALOG.json').read_text())['components']
 assert len(rows)==1 and rows[0]['id']==1 and rows[0]['artifact']=='hia-generation-runtime-frontend-component.so'
 assert rows[0]['source_directory']=='source'and rows[0]['exports']==list(EXPORTS)
 t=document(source_program(rows),'generation_runtime_frontend_pathlimit_catalog')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_pathlimit_catalog.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
