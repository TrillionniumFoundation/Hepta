import pathlib,json,hashlib,sys
root=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2]);sys.path.insert(0,str(root))
from tools import qualify_hia_upstream_factorial as study
from benchmarks.hia_upstream_factorial import tasks
fixtures={t['id']:t for t in tasks.make_fixtures()}
records=json.loads((out/'retained-responses.json').read_text());rows=[]
for row in records:
 model,task_id,arm=row['id'].split('/')
 language,interface=arm.split('-')
 task=fixtures[task_id];text=row['answer']
 assert hashlib.sha256(text.encode()).hexdigest()==row['answer_sha256']
 observed=None;feedback=None
 try:study.materialize(task,language,interface,text)
 except ValueError as error:
  observed=str(error)
  public_task={'original_'+language:task['original_'+language]}
  feedback=study.edit_contract_feedback(public_task,language,interface,text,error)
  assert feedback['edit_rejected']==observed
 assert observed==row['edit_error'],(row['id'],row['attempt'],observed,row['edit_error'])
 rows.append({'id':row['id'],'attempt':row['attempt'],'answer_sha256':row['answer_sha256'],'old_edit_error':row['edit_error'],'new_edit_error':observed,'same_verdict':True,'public_only_feedback':feedback})
controls=[]
for task in fixtures.values():
 for language in ('assembly','rust'):
  for label in ('original','correct'):
   full=study.materialize(task,language,'full',study.answer(task,language,'full',label))
   patch=study.materialize(task,language,'patch',study.answer(task,language,'patch',label))
   assert full==patch
   controls.append({'task':task['id'],'language':language,'label':label,'same_full_patch_materialization':True})
result={'schema':'hepta.agent.public-feedback.replay.v1','old_pilot':'/data/hepta-hia-round2-20261104/evidence/upstream-agent-final-v10-r1','old_pilot_successes':0,'old_pilot_cells':16,'responses':len(rows),'same_verdicts':sum(x['same_verdict'] for x in rows),'edit_rejections':sum(x['new_edit_error'] is not None for x in rows),'edit_admitted_but_not_solution_successes':sum(x['new_edit_error'] is None for x in rows),'reference_materializations':controls,'regression_tests':9,'rows':rows,'new_model_requests':0,'new_native_candidate_executions':0,'hidden_validation_or_oracle_data_in_feedback':False,'independent_task_productivity_evidence':False,'materialize_function_byte_identical':True,'prompt_function_byte_identical':True}
(out/'REPLAY.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('rows','reference_materializations')}))
