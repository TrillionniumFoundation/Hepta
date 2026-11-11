import ast,copy,json,runpy
from hashlib import sha256
from pathlib import Path
from datetime import datetime,timezone
root=Path('/tmp/hia-wire-e26e-controller')
path=root/'run_wire_r7_development_package_r2.py'
old=ast.parse((root/'run_wire_r7_development_package.py').read_text());new=ast.parse(path.read_text())
old_main=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='main')
main=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='main')
dump=lambda n:ast.dump(n,include_attributes=False)
old_try=next(n for n in old_main.body if isinstance(n,ast.Try));new_try=next(n for n in main.body if isinstance(n,ast.Try))
assert [dump(n) for n in old_try.body]==[dump(n) for n in new_try.body]
assert [dump(n) for n in old_try.handlers]==[dump(n) for n in new_try.handlers]
old_ns=runpy.run_path(str(root/'run_wire_r7_development_package.py'),run_name='old_controller')
ns=runpy.run_path(str(path),run_name='new_controller')
assert set(ns['RECOVERY_FILES'])=={'generate_hia_json_wire.py','test_hia_json_wire_native.py'}
assert sorted(old_ns['RECOVERY_FILES'].values())==sorted(ns['RECOVERY_FILES'].values())
assert old_ns['CORE_IDS']==ns['CORE_IDS'] and old_ns['BUDGET_IDS']==ns['BUDGET_IDS'] and old_ns['PLANNED']==ns['PLANNED']
assert dump(next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='materialized_snapshot'))==dump(next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='materialized_snapshot'))
assert dump(next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='read_source_package_manifest'))==dump(next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='read_source_package_manifest'))
folder=root/'terminal-gate-controls-r2';folder.mkdir()
arguments=ast.arguments(posonlyargs=[],args=[ast.arg(arg=x) for x in ('report','snapshot','candidate','evidence','save','report_path')],kwonlyargs=[],kw_defaults=[],defaults=[])
function=ast.FunctionDef(name='terminal_gate',args=arguments,body=copy.deepcopy(new_try.finalbody)+[copy.deepcopy(main.body[-1])],decorator_list=[])
module=ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[]))
ns.update(PLANNED=[],print=lambda *args,**kwargs:None)
exec(compile(module,'<exact-controller-finally-and-return>','exec'),ns)
rows=[]
for label,start_status,observation,expected_rc in [('stable-pass','PASS_LIMITED_DEVELOPMENT_CONTROLS','stable',0),('drift-after-pass','PASS_LIMITED_DEVELOPMENT_CONTROLS','drift',1),('read-error-after-pass','PASS_LIMITED_DEVELOPMENT_CONTROLS','error',1),('existing-hold-stable','HOLD','stable',1),('existing-hold-plus-drift','HOLD','drift',1)]:
 evidence=folder/label;evidence.mkdir();candidate={'member':{'sha256':'original'}}
 report={'status':start_status,'steps':[]}
 if start_status=='HOLD':report['exception']={'type':'OriginalFailure','message':'preserve earlier failure'}
 def snapshot():
  if observation=='error':raise OSError('synthetic final snapshot error')
  return candidate if observation=='stable' else {'member':{'sha256':'different'}}
 saved=[]
 result=ns['terminal_gate'](report,snapshot,candidate,evidence,lambda:saved.append(copy.deepcopy(report)),evidence/'audit.json')
 assert result==expected_rc and len(saved)==1
 assert report['status']==('PASS_LIMITED_DEVELOPMENT_CONTROLS' if expected_rc==0 else 'HOLD')
 if start_status=='HOLD':assert report['exception']=={'type':'OriginalFailure','message':'preserve earlier failure'}
 rows.append({'case':label,'returncode':result,'report':report})
report={'schema':'hepta.hia.wire-package-controller-final-gate-controls.v1','scope':'SYNTHETIC_EXACT_FINAL_AST_CONTROLS_NOT_NATIVE_PRODUCT_EXECUTION','controller_sha256':sha256(path.read_bytes()).hexdigest(),'old_controller_sha256':sha256((root/'run_wire_r7_development_package.py').read_bytes()).hexdigest(),'recovery_filenames_match_outer':True,'recovery_expected_blobs_unchanged':True,'all_main_try_stage_and_semantic_gate_statements_unchanged':True,'all_planned_phases_and_ids_unchanged':True,'package_inventory_admission_functions_unchanged':True,'cases':rows,'case_count':len(rows),'status':'PASS'}
report['review_script_sha256']=sha256(Path(__file__).read_bytes()).hexdigest()
(root/'package-controller-r2-controls.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='cases'}))
