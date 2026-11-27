"""Emit the reviewed, fixed BackgroundOptimizer child catalog."""
from pathlib import Path
import json
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_fixed_component_catalog import source_program
ROOT=Path(__file__).resolve().parents[1]
EXPORTS=('hia_background_native_public','hia_background_native_context',
         'hia_background_native_finalizer','hia_background_native_registry')
def main():
    manifest=ROOT/'docs/HIA_BACKGROUND_NATIVE_CHILD_CATALOG.json'
    rows=json.loads(manifest.read_text())['components']
    assert len(rows)==1 and rows[0]['id']==1
    assert rows[0]['artifact']=='hia-background-native-component.so'
    assert rows[0]['source_directory']=='source'and rows[0]['exports']==list(EXPORTS)
    tree=document(source_program(rows),'generation_background_catalog')
    p=ROOT/'examples/hia_bootstrap/generation_background_catalog.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
