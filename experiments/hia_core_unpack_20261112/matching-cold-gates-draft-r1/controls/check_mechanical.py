"""Read-only exact-delta checks for the independent proposed integration."""
from pathlib import Path
import ast,json,hashlib,yaml
ROOT=Path(__file__).resolve().parents[1];BASE=Path('/tmp/hia-core-unpack-v83-20261112-r1/source');NEW=ROOT/'inputs'
checks=[]
def check(name,value):
 checks.append({'name':name,'passed':bool(value)})
 if not value:raise AssertionError(name)
def dump(raw):return ast.dump(ast.parse(raw),include_attributes=False)
def functions(raw):return {x.name:x for x in ast.parse(raw).body if isinstance(x,ast.FunctionDef)}
changes=json.loads((ROOT/'controls/legacy-reader-replacements.json').read_bytes())
a=(BASE/'tools/hia_compiler_owner_gates.py').read_text();b=(NEW/'tools/hia_compiler_owner_gates.py').read_text()
for old,new in reversed(changes):
 check('unique new Core reader substitution',b.count(new)==1);b=b.replace(new,old)
check('five inverses reproduce complete old Core reader bytes',a==b)
a=(BASE/'tests/test_hia_core_unpack_native.py').read_text();b=(NEW/'tests/test_hia_core_unpack_native.py').read_text()
for old,new in reversed(json.loads((ROOT/'controls/retained-suite-setup-replacements.json').read_bytes())):
 check('unique retained-suite fixture substitution',b.count(new)==1);b=b.replace(new,old)
check('existing eight method bodies and all other test source exact after two inverses',a==b)
old=(BASE/'experiments/hia_native_successor_runner_20261111/run_hia_qualification_v9.py').read_text()
new=(NEW/'experiments/hia_native_successor_runner_20261111/run_hia_qualification_v10.py').read_text()
f0,f1=functions(old),functions(new)
check('v10 adds one full conjunction function',set(f1)-set(f0)=={'complete_core_unpack'})
for name in set(f0)-{'run'}:check('retained function AST '+name,ast.dump(f0[name])==ast.dump(f1[name]))
run=f1['run'];run.body=[x for x in run.body if not (isinstance(x,ast.If) and ast.unparse(x.test)=="name == 'full-retained-regression'")]
check('run AST only adds isolated full-suite evidence admission',ast.dump(f0['run'])==ast.dump(run))
assign=lambda raw:{x.targets[0].id:ast.dump(x.value) for x in ast.parse(raw).body if isinstance(x,ast.Assign) and len(x.targets)==1 and isinstance(x.targets[0],ast.Name)}
a0,a1=assign(old),assign(new)
for name in ('mandatory_gates','mandatory_v8_gates','mandatory_store_page_gates','mandatory_v9_gates'):
 check('old mandatory map unchanged '+name,a0[name]==a1[name])
left=yaml.safe_load((BASE/'.github/workflows/hia-core.yml').read_bytes())
right=yaml.safe_load((NEW/'.github/workflows/hia-core.yml').read_bytes())
right['jobs']['native']['steps']=[step for step in right['jobs']['native']['steps'] if step.get('name') not in (
 'Matching-cold UNPACK with the original complete Core116','Complete 18 UNPACK controls and independent two-gate conjunction')]
for step in right['jobs']['source']['steps']:
 if step.get('name')=='Core source and independent reference controls':
  step['run']=step['run'].replace("    'tests.test_hia_core_unpack_gates',\n",'')
for step in right['jobs']['native']['steps']:
 if step.get('name')=='Preserve actual cold failure and stage evidence':
  for item in ('hia-core-unpack-evidence/','hia-core-unpack-callers-admission.json','hia-core-unpack-gates.json'):
   step['with']['path']=step['with']['path'].replace('${{ runner.temp }}/'+item+'\n','')
check('workflow old jobs and steps exact after declared additions',left==right)
source=(NEW/'tools/hia_selfhost_contract.py').read_bytes();tree=ast.parse(source)
seq=next(x for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCE_FILES' for t in x.targets))
# This tuple is a literal; the complete source manifest is generated only after integration.
listed=ast.literal_eval(seq.value)
for name in ('tools/hia_core_unpack_gates.py','tools/qualify_hia_core_unpack_ci.py',
 'tools/hia_core_unpack_controls/finite_controls.py','tools/hia_core_unpack_controls/finite_launcher.py',
 'tests/test_hia_core_unpack_gates.py','docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json',
 'experiments/hia_native_successor_runner_20261111/run_hia_qualification_v10.py'):
 check('new dependency declared '+name,name in listed)
check('no generated HIA/ABI image changed by this draft',not any(x.suffix in ('.hiaasm','.bin') or x.name.endswith('_abi.json') for x in NEW.rglob('*') if x.is_file()))
value={'schema':'hia.core-unpack-gate-draft-mechanical-check.v1','status':'PASS','checks':checks,
 'baseline':'006accd3d73d48b9ef39c821be55a5346cd48ce0','native_executed':False,'cold_executed':False,
 'complete_source_rederived':False}
(ROOT/'MECHANICAL-CHECK.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':value['status'],'checks':len(checks)}))
