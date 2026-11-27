from pathlib import Path
import ast
import difflib
import hashlib
import json
import re
import yaml

BASE=Path('/workspace/scratch/dda74a4fae35')
OUT=BASE/'v87-r11-workflow-review-r1'
OUT.mkdir(exist_ok=True)
TEMP_EXPR='$'+'{{ runner.temp }}'
def ident(p):
    b=p.read_bytes()
    return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def source_span(text,name):
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name)
    lines=text.splitlines(keepends=True)
    return ''.join(lines[node.lineno-1:node.end_lineno]), node, ''.join(lines[:node.lineno-1]+lines[node.end_lineno:])
r10=BASE/'recovered-v85/harness/tools/materialize_candidate_r10.py'
r11=BASE/'v87-union-r5/harness/tools/materialize_candidate_r11.py'
a,b=r10.read_text(),r11.read_text()
oldfn,oldnode,oldrest=source_span(a,'source_gate')
newfn,newnode,newrest=source_span(b,'source_gate')
assert oldrest==newrest
calls=lambda node:[ast.dump(n,include_attributes=False) for n in ast.walk(node)
                   if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='python_command']
assert calls(oldnode)==calls(newnode)
oldgate=BASE/'recovered-v85/harness/tools/run_source_gate.py'
newgate=BASE/'v87-union-r5/harness/tools/run_source_gate.py'
assert oldgate.read_bytes()==newgate.read_bytes()
oldids=BASE/'recovered-v85/harness/inputs/ORIGINAL-SOURCE-IDS.json'
newids=BASE/'v87-union-r5/harness/inputs/ORIGINAL-SOURCE-IDS.json'
assert oldids.read_bytes()==newids.read_bytes()
plan_path=BASE/'v87-union-r5/harness/inputs/MATERIALIZATION-R5.json'
plan=json.loads(plan_path.read_text())
assert plan['source_test_environment']=={'HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE':'@EVIDENCE@/checks/hia-candidate-build-source'}
oldwf=BASE/'recovered-v85/candidate-r4-ci314/.github/workflows/hia-core.yml'
newwf=BASE/'v87-union-r5/local-source-r1/.github/workflows/hia-core.yml'
old,new=yaml.safe_load(oldwf.read_text()),yaml.safe_load(newwf.read_text())
assert {k:v for k,v in old.items() if k!='jobs'}=={k:v for k,v in new.items() if k!='jobs'}
assert list(old['jobs'])==list(new['jobs'])==['source','native']
for key in old['jobs']:
    assert {k:v for k,v in old['jobs'][key].items() if k!='steps'}=={k:v for k,v in new['jobs'][key].items() if k!='steps'}
oldsteps=old['jobs']['native']['steps'];newsteps=new['jobs']['native']['steps']
assert (len(oldsteps),len(newsteps))==(110,116)
def key(s):return s.get('name',s.get('run',s.get('uses')))
mapping=[];added=[];cursor=0
for i,step in enumerate(oldsteps):
    match=next(j for j in range(cursor,len(newsteps)) if key(newsteps[j])==key(step))
    added.extend({'index':j+1,'step':newsteps[j]} for j in range(cursor,match))
    current=newsteps[match]
    if key(step)=='Preserve actual cold failure and stage evidence':
        sa=json.loads(json.dumps(step));sb=json.loads(json.dumps(current))
        oldpaths=sa['with'].pop('path').splitlines();newpaths=sb['with'].pop('path').splitlines()
        assert sa==sb
        assert [p for p in newpaths if p in oldpaths]==oldpaths
        addedpaths=[p for p in newpaths if p not in oldpaths]
    else:assert step==current
    mapping.append({'original_index':i+1,'r5_index':match+1,'name':key(step),'all_original_fields_preserved':key(step)!='Preserve actual cold failure and stage evidence'})
    cursor=match+1
added.extend({'index':j+1,'step':newsteps[j]} for j in range(cursor,len(newsteps)))
assert len(added)==6
expected=['hia-release-launch-matching-cold','hia-candidate-build','hia-store-lifecycle','hia-store-lifecycle-agent','hia-store-lifecycle-namespace','hia-store-lifecycle-ledger']
assert addedpaths==[TEMP_EXPR+'/'+p+'/' for p in expected]
upload=newsteps[114]
assert upload['if']=='always()' and upload['with']['include-hidden-files'] is True
for row,folder in zip(added,expected):
    s=row['step']; run=s['run'];env=s.get('env',{})
    assert folder in run or any(folder in v for v in env.values())
    assert 'hia-cold.json' in run or any('hia-cold.json' in v for v in env.values())
    assert 'DEVELOPMENT' not in run and not any('DEVELOPMENT' in k for k in env)
source_steps=new['jobs']['source']['steps']
control=next(s for s in source_steps if s.get('name')=='Core source and independent reference controls')
original_control=next(s for s in old['jobs']['source']['steps'] if s.get('name')=='Core source and independent reference controls')
def selectors(run):
    tree=ast.parse(run.split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0])
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='names' for t in n.targets))
sels=selectors(control['run']);old_sels=selectors(original_control['run'])
assert len(sels)==220 and len(old_sels)==213
assert sels[:213]==old_sels
assert list(sels)==plan['source_registration']['selectors']
assert control['env']=={'HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE':TEMP_EXPR+'/hia-candidate-build-source'}
oldcontrol=original_control['run'];newcontrol=control['run']
old_lines=oldcontrol.splitlines(keepends=True);new_lines=newcontrol.splitlines(keepends=True)
extra=[line for line in new_lines if line not in old_lines]
assert len(extra)==7 and all("tests.test_hia_" in line for line in extra)
assert ''.join(line for line in new_lines if line not in extra)==oldcontrol
gen=next(s['run'] for s in source_steps if s.get('name')=='Regenerate actual HIA sources')
names=re.search(r'for component in (.*?); do',gen).group(1).split()
assert len(names)==113 and names==plan['generators']
source_upload=next(s for s in source_steps if s.get('name')=='Preserve actual candidate Source VM buffers')
assert source_upload['if']=='always()'
assert source_upload['with']['path']==TEMP_EXPR+'/hia-candidate-build-source/'
harnesswf=next((BASE/'v87-union-r5/harness/.github/workflows').glob('*.yml'))
h=yaml.safe_load(harnesswf.read_text());hs=h['jobs']['generate-and-check-source']['steps']
assert next(s for s in hs if s.get('if')=='always()')['with']['path']==TEMP_EXPR+'/hia-combined-source-v87-r5/evidence'
assert hs[1]['with']['python-version']=='3.14.4'
report={
 'schema':'hia-r11-r10-r5-workflow-independent-source-review-v1',
 'scope':'READ_ONLY_SOURCE_AND_DATA_COMPARISON_NO_PRODUCT_TEST_EXECUTION',
 'status':'REVIEWED_NO_DETERMINATE_BLOCKER_IN_THIS_SCOPE',
 'inputs':[ident(p) for p in (r10,r11,plan_path,oldwf,newwf,harnesswf,newids,newgate)],
 'driver':{'only_changed_function':'source_gate','all_bytes_outside_function_identical':True,
   'python_command_call_ast_identical':True,'source_runner_bytes_identical':True,'original_ids_bytes_identical':True,
   'original_1800_second_group_and_existing_cleanup_code_unchanged':True,
   'source_environment':plan['source_test_environment'],
   'boundary':'Exact one-key manifest, reject ambient value, resolve outside source, mkdir exist_ok=False, pass only during child, finally remove env. Evidence lives under capture.raw and existing full evidence upload.'},
 'workflow':{'trigger_permissions_and_job_metadata_identical':True,'original_native_steps':110,
   'new_native_steps':116,'original_native_order_preserved':True,'all_original_gate_bodies_env_conditions_budgets_identical':True,
   'only_original_step_change':'Append six evidence directories to existing always upload',
   'native_mapping':mapping,'new_native_steps_detail':added,'added_upload_paths':addedpaths,
   'source_selectors':220,'original213_preserved_in_order':True,'new_source_selectors':list(sels[213:]),
   'generators':113,'source_gate_body_other_than7selectors_identical':True,
   'source_vm_upload_always':True,'harness_complete_evidence_upload_always':True,
   'no_cold_or_development_authority_inherited':True},
 'nonblocking_metadata_note':'source_registration.required_support_actions still contains historical prose counts109/213; active generators/selectors are113/220 and exact list comparisons pass. No runtime decision reads these prose counts.',
 'limits':'This is static source review and data comparison, not execution of any Source/native/cold component and not confirmation of pending actual3.14 results.',
 'review_authoring_failure':'First V8 attempt had a JavaScript template interpolation SyntaxError before any tool or file mutation; rewritten with explicit expression strings. No product execution was attempted.',
 'diff':''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile=str(r10),tofile=str(r11)))
}
out=OUT/'REVIEW.json';out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'report':str(out),'identity':ident(out),'native':116,'source_selectors':220,'generators':113,'blockers':[]}))

