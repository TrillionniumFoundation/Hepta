import json,os,sys,time,subprocess,hashlib
from pathlib import Path
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src')
out=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807/source-diagnostics-v1/attribute-opcode-v1')
out.mkdir(exist_ok=False)
sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_oracle as oracle
from tests.hia_service_bootstrap_observer import Backend
from types import FunctionType
import dis,io
backend=Backend('vm',None,compatibility=True)
cases,_=oracle.cases()
selected={case['id']:case for case in cases}
case=selected['_program.store-getter-error.outer0']
rows=[]
for label,functions,namespace,builtin in [
 ('original',None,None,None),
 ('actual-port',{'_program':backend.imports['program_get']},backend.namespace,backend.captured_builtins),
 ('actual-vm',*backend.select(case))]:
 for run in range(12):
  actual,trace=oracle.observe(case,functions=functions,namespace=namespace,captured_builtins=builtin)
  row={'label':label,'run':run,'outcome':actual['parts'][0]['outcome'],'hits':actual['parts'][0]['target_hits']}
  rows.append(row)
 raw=io.StringIO();fn=oracle.ORIGINALS['_program'] if label=='original' else backend.imports['program_get']
 dis.dis(fn,file=raw,adaptive=True,show_caches=True)
 (out/(label+'.dis.txt')).write_text(raw.getvalue())
(out/'observations.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
print(json.dumps({'runtime':sys.version,'rows':rows}),flush=True)
