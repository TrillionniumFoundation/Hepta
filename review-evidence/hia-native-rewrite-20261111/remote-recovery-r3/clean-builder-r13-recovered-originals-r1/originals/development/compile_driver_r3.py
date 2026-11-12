from pathlib import Path
from hashlib import sha256
import json,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
sys.path[:0]=[str(ROOT/'tools'),str(BASE/'Hepta-v67-workflow-qualified')]
from tools.qualify_hia_selfhost import compile_stage
from hepta.hia_agent_assembly import assemble_program
OUT=ROOT/'development/driver-compile-r3';OUT.mkdir(exist_ok=False)
compiler=BASE/'hia-v67-0ef-qualification-local-01/cold.cold/qualification.evidence/B3.image.bin'
source=ROOT/'examples/hia_bootstrap/clean_build_driver.hiaasm';decoder=BASE/'Hepta-v67-workflow-qualified/examples/hia_bootstrap/agent_data_json.hiaasm'
packer=ROOT/'examples/hia_bootstrap/clean_build_packer.hiaasm'
paths=[source,packer,decoder,compiler,Path(__file__),ROOT/'tools/clean_build_executor.S']+[p for p in (ROOT/'tools').glob('*.py')]+[BASE/'Hepta-v67-workflow-qualified/tools/generate_hia_selfhost.py',BASE/'Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py']
frozen={p:p.read_bytes() for p in paths};rows=[]
for i,(p,b) in enumerate(frozen.items()):
 q=OUT/'source'/str(i)/p.name;q.parent.mkdir(parents=True);q.write_bytes(b);rows.append(dict(path=str(p),copy=str(q),bytes=len(b),sha256=sha256(b).hexdigest()))
(OUT/'source.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
result=dict(status='INCOMPLETE',scope='DEVELOPMENT_ONLY_NOT_CURRENT_SOURCE_COLD');start=time.monotonic_ns()
try:
 manifests={}
 for label,p in [('clean-build-driver',source)]:
  checked=assemble_program(frozen[p]);image,receipt=compile_stage(OUT,label,compiler,frozen[p]);b=image.read_bytes()
  assert receipt['input_sha256']==sha256(frozen[p]).hexdigest() and receipt['artifact_sha256']==sha256(frozen[compiler]).hexdigest() and receipt['produced_sha256']==sha256(b).hexdigest()
  m=dict(schema='hepta.hia.clean-build-development.v1',source_path=next(r['copy'] for r in rows if r['path']==str(p)),source_sha256=sha256(frozen[p]).hexdigest(),image_path=str(image),image_sha256=sha256(b).hexdigest(),compiler_sha256=sha256(frozen[compiler]).hexdigest(),scope='DEVELOPMENT_ONLY')
  mp=OUT/(label+'.manifest.json');mp.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n');manifests[label]=str(mp)
 result.update(status='PASS',manifests=manifests)
except BaseException as e:result.update(status='FAIL',error_class=type(e).__name__,error=str(e));traceback.print_exc();raise
finally:
 result['all_pins_unchanged']=all(p.read_bytes()==b for p,b in frozen.items());assert result['all_pins_unchanged'];result['elapsed_ns']=time.monotonic_ns()-start;(OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True),flush=True)
