#!/usr/bin/env python3
"""Read-only receipt/SSE audit: no model, compiler, execution or recompression."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT=Path('/workspace/scratch/cd43ab608057/hepta-hia')
EVIDENCE=Path('/workspace/scratch/cd43ab608057/hia-run-evidence')
CAL=EVIDENCE/'agent-v9-calibration'
CAP=EVIDENCE/'agent-v9-capacity-system-python'
OUTPUT=EVIDENCE/'agent-v9-independent-audit.json'
if OUTPUT.exists(): raise SystemExit('Refusing to replace an existing independent audit')
started=time.monotonic_ns()
checks=[]
def check(name,passed,details=None):
 row={'name':name,'passed':bool(passed)}
 if details is not None:row['details']=details
 checks.append(row)
def load(path):return json.loads(Path(path).read_text())
def sha(path):
 with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def identity(path):
 path=Path(path).resolve()
 return {'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def git(*arguments):return subprocess.check_output(['git',*arguments],cwd=ROOT,text=True).strip()

result=load(CAL/'RESULT.json');capacity=load(CAP/'CAPACITY.json')
plan=load(CAL/'PLAN.json');cap_plan=load(CAP/'PLAN.json')
stop=load(EVIDENCE/'AGENT_STOP.json')
admission=load(EVIDENCE/'agent-runtime-admission.json')
outer=load(EVIDENCE/'agent-v9-calibration.outer.json')
cap_outer=load(EVIDENCE/'agent-v9-capacity-system-python.outer.json')
python_preflight=load(EVIDENCE/'agent-system-python-preflight.json')
protocol_path=ROOT/'experiments/hia_agent_toolstudy_v9_20261029/PROTOCOL.json'
protocol=load(protocol_path)
expected_commit='865a4626910efbc882cad47a7816e9aa276a9600'
check('measured_source_and_current_clean_head',git('rev-parse','HEAD') == expected_commit and git('status','--porcelain') == '' and all(x['source_commit'] == expected_commit for x in (result,capacity,plan,cap_plan,stop)))
check('capacity_result_plan_and_protocol_binding',result['capacity_sha256'] == sha(CAP/'CAPACITY.json') and result['plan_sha256'] == sha(CAL/'PLAN.json') and all(x['protocol_sha256'] == sha(protocol_path) for x in (result,capacity,cap_plan)) and plan['protocol'] == protocol)
check('same_tools_model_source_and_prompt_bindings_between_stages',all(result[key] == capacity[key] == plan[key] == cap_plan[key] for key in ('tools','model','source_bindings','prompt_bindings')))
source_bad=[]
for name,expected in result['source_bindings'].items():
 for base in (ROOT,CAL/'source_snapshot',CAP/'source_snapshot'):
  if not (base/name).is_file() or sha(base/name) != expected:source_bad.append(str(base/name))
check('current_source_and_both_retained_snapshots_match_all_bound_files',not source_bad,{'bound_files':len(result['source_bindings']),'mismatches':source_bad})
expected_ids=['calibration/'+name+'/calibration' for name in protocol['qualification']['tasks']]
for index,task in enumerate(protocol['tasks']):
 arms=protocol['arms'][index%4:]+protocol['arms'][:index%4]
 expected_ids.extend('main/'+task+'/'+arm for arm in arms)
check('all_19_capacity_rows_in_registered_order',len(capacity['rows']) == 19 and [row['id'] for row in capacity['rows']] == expected_ids)
check('capacity_complete_without_generation',capacity['complete'] is True and capacity['model_requests'] == 0 and capacity['references_are_agent_successes'] is False and capacity['engine_exited'] is True and all(capacity[key] is True for key in ('source_unchanged','tools_unchanged','model_unchanged')))
check('all_capacity_rows_fit_frozen_limits',all(all(row[key] is True for key in ('passed','reference_passed_all_gates','capacity_passed','template_exact_match','tokenizer_ids_match')) and row['reference_is_model_answer'] is False and 0 < row['complete_reference_output_tokens'] <= 1536 and row['allocated_worst_repair_plus_output_reserve'] <= 8192 for row in capacity['rows']))
capacity_controls_ok=True
for row in capacity['rows']:
 folder=CAP/row['id']
 hidden=load(folder/'REFERENCE_HIDDEN.json')
 token=load(folder/'REFERENCE_TOKENS.json')
 initial=load(folder/'INITIAL.json')
 initial_text=initial['messages'][0]['content']
 capacity_controls_ok &= (hidden['status'] == 'correct' and hidden['artifact_unchanged'] is True
  and token['server_token_ids'] == token['cli_token_ids'] and len(token['server_token_ids']) == row['complete_reference_output_tokens']
  and len(initial['input_token_ids']) == row['initial_input_tokens']
  and sha(folder/'REFERENCE.json') is not None
  and hashlib.sha256(initial_text.encode()).hexdigest() == result['prompt_bindings'][row['id']]['prompt_sha256'])
check('19_capacity_reference_hidden_and_token_receipts_present_and_consistent',capacity_controls_ok)
check('capacity_has_no_completion_transports',not list((CAP/'tokenizer-runtime').glob('transport-*.request.json')))

# Review initial/retry message hashes and parse all retained native SSE events.
module=ast.parse((ROOT/'experiments/hia_agent_toolstudy_v9_20261029/prompts.py').read_text())
repair_prefix=next(ast.literal_eval(node.value) for node in module.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id == 'REPAIR' for target in node.targets))
expected_tasks=protocol['qualification']['tasks']
check('three_registered_qualification_tasks_only',[(cell['task'],cell['arm']) for cell in result['cells']] == [(task,'rust_node') for task in expected_tasks])
engine_records=result['engines'];check('one_recorded_engine',len(engine_records) == 1)
engine=CAL/'engine-00'
identity_before=load(engine/'identity.json');identity_after=load(engine/'identity-after.json')
check('engine_final_identity_and_exit_receipt',engine_records[0]['exited'] is True and engine_records[0]['identity'] == identity_after and identity_after['runtime_unchanged'] is True and identity_after['model_unchanged'] is True and identity_after['runtime_files'] == identity_before['runtime_files'] and identity_after['model'] == identity_before['model'])
pid=identity_before['pid'];cap_engine_identity=load(CAP/'tokenizer-runtime/identity.json');cap_pid=cap_engine_identity['pid']
check('recorded_engine_pids_no_longer_present',not Path('/proc',str(pid)).exists() and not Path('/proc',str(cap_pid)).exists(),{'qualification_pid':pid,'capacity_pid':cap_pid})
check('both_actual_engines_report_pinned_b11669',all('build 11669' in value['version_stdout']+value['version_stderr'] for value in (identity_before,cap_engine_identity)))
transport_sets={suffix:sorted(path.name for path in engine.glob('transport-*.'+suffix)) for suffix in ('request.json','response.json','response.sse','usage.json')}
check('exactly_nine_complete_retained_transports',all(names == ['transport-'+str(n).zfill(3)+'.'+suffix for n in range(1,10)] for suffix,names in transport_sets.items()))
request_records=[];cell_records=[];input_total=output_total=0
all_sse=True;all_messages=True;all_gates=True;all_usage=True;all_limits=True;all_revisions=True
serial=0
for cell in result['cells']:
 folder=CAL/cell['id'];query=load(folder/'CAPTURED_QUERY.json')
 all_gates &= load(folder/'CELL.json') == cell and len(cell['attempts']) == 3 and cell['correct'] is False and cell['hidden_evaluated'] is False
 initial=None;previous=None;cell_in=cell_out=0
 statuses=[];response_hashes=[]
 for index,attempt in enumerate(cell['attempts']):
  serial+=1;stem='transport-'+str(serial).zfill(3)
  request=load(engine/(stem+'.request.json'));raw=load(engine/(stem+'.response.json'));receipt=load(engine/(stem+'.usage.json'))
  prep=load(engine/('preparation-'+str(serial).zfill(3)+'.json'))
  saved_request=load(folder/f'attempt-{index}.request.json');answer=load(folder/f'attempt-{index}.response.json');saved_attempt=load(folder/f'attempt-{index}.evaluation.json')
  wire=(engine/(stem+'.response.sse')).read_bytes().replace(b'\r\n',b'\n')
  pieces=wire.split(b'\n\n');all_sse &= not pieces[-1].strip()
  events=[]
  for block in pieces[:-1]:
   data=[line[5:].lstrip(b' ') for line in block.split(b'\n') if line.startswith(b'data:')]
   if data:events.append(json.loads(b'\n'.join(data)))
  ids=[token for event in events for token in event['tokens']]
  text=''.join(event['content'] for event in events)
  final=events[-1];rebuilt={**final,'content':text,'tokens':ids}
  settings=final['generation_settings'];sampling=settings.get('params',settings)
  actual_input=len(prep['input_token_ids']);actual_output=final['timings']['predicted_n']
  all_sse &= (len(events) == receipt['events'] and rebuilt == raw and final['stop'] is True
   and all(event['stop'] is False for event in events[:-1]) and text == answer['text']
   and ids == answer['output_token_ids'] == receipt['observed_output_token_ids']
   and receipt['response_bytes'] == (engine/(stem+'.response.sse')).stat().st_size
   and all(type(token) is int and 0 <= token < 2**31 for token in ids))
  usage={'input_tokens':actual_input,'output_tokens':actual_output,'returned_token_ids':len(ids),'total_tokens':actual_input+actual_output}
  all_usage &= (answer['usage'] == attempt['usage'] == usage and receipt['complete'] is True
   and receipt['input_tokens'] == actual_input and receipt['output_tokens'] == actual_output and receipt['total_tokens'] == actual_input+actual_output
   and receipt['unknown_output_tokens'] is False and receipt['unknown_reason'] is None and receipt['error'] is None
   and raw['tokens_evaluated'] == actual_input and len(ids) <= actual_output <= len(ids)+1)
  payload=request['payload']
  all_limits &= (prep['fits'] is True and prep['actual_generation_submitted'] is True and prep['context'] == 8192 and prep['reserved_output_tokens'] == 1536
   and actual_input+1536 <= 8192 and 0 < actual_output <= 1536 and raw['truncated'] is False
   and raw['stop_type'] in ('eos','limit') and payload['prompt'] == prep['input_token_ids'] == answer['input_token_ids']
   and payload['n_predict'] == 1536 and payload['temperature'] == 0 and payload['seed'] == 0 and payload['cache_prompt'] is False
   and sampling['temperature'] == 0 and sampling['seed'] == 0 and sampling['grammar_lazy'] is False and bool(sampling['grammar']))
  messages=request['messages'];all_messages &= messages == prep['messages'] == saved_request['messages']
  if index == 0:
   initial=messages[0]['content']
   binding=result['prompt_bindings']['calibration/'+cell['task']+'/calibration']
   all_messages &= len(messages) == 1 and messages[0]['role'] == 'user' and hashlib.sha256(initial.encode()).hexdigest() == binding['prompt_sha256'] and binding['query_sha256'] == query['query_sha256']
  else:
   budget=load(folder/f'attempt-{index-1}.repair-budget.json')
   all_messages &= messages == [{'role':'user','content':initial},{'role':'assistant','content':previous},{'role':'user','content':repair_prefix+canonical(budget['feedback']).decode()}]
   all_limits &= budget['previous_response_tokens'] <= 1664 and budget['feedback_tokens'] <= 1024 and budget['previous_code_truncated'] is False and budget['public_cases_removed'] is False
  evaluation=attempt['evaluation']
  all_gates &= saved_attempt == attempt and attempt['index'] == index and attempt['actual_generation_requested'] is True and evaluation['accepted'] is False and evaluation['hidden_evaluated'] is False
  all_revisions &= (saved_request['captured_query_sha256'] == query['query_sha256'] and evaluation['before_revision'] == evaluation['after_revision'] == query['source_revision'] and evaluation['failed_transaction_left_source_unchanged'] is True and evaluation['source_published'] is False)
  statuses.append(attempt['status']);response_hashes.append(hashlib.sha256(text.encode()).hexdigest())
  input_total+=actual_input;output_total+=actual_output;cell_in+=actual_input;cell_out+=actual_output
  request_records.append({'transport':serial,'task':cell['task'],'attempt_index':index,'status':attempt['status'],
                          'input_tokens':actual_input,'output_tokens':actual_output,'total_tokens':actual_input+actual_output,
                          'sse_events':len(events),'returned_output_ids':len(ids),'sse_sha256':sha(engine/(stem+'.response.sse'))})
  previous=text
 cell_records.append({'task':cell['task'],'arm':cell['arm'],'attempts':len(cell['attempts']),'correct':cell['correct'],'hidden_evaluated':cell['hidden_evaluated'],
                      'statuses':statuses,'input_tokens':cell_in,'output_tokens':cell_out,'total_tokens':cell_in+cell_out,'distinct_response_texts':len(set(response_hashes))})
check('all_nine_sse_streams_reconstruct_saved_responses',all_sse)
check('all_nine_token_usage_receipts_recompute',all_usage)
check('initial_prompts_and_complete_previous_response_repair_history',all_messages)
check('frozen_generation_context_and_repair_limits_respected',all_limits)
check('all_nine_attempt_and_rejection_records_consistent',all_gates)
check('all_rejected_candidates_leave_original_revision_unchanged',all_revisions)
check('exact_9_requests_9_responses_and_25336_tokens',serial == result['requests'] == result['responses'] == engine_records[0]['requests'] == engine_records[0]['responses'] == 9 and input_total == result['known_input_tokens'] == 21857 and output_total == result['known_output_tokens'] == 3479 and input_total+output_total == result['total_tokens'] == 25336 and result['unknown_usage_requests'] == result['partial_output_token_lower_bound'] == 0)
check('valid_observation_is_true_and_eligibility_independently_false',result['status'] == 'all_cells_attempted' and result['valid_observation'] is True and all(result[key] is True for key in ('source_unchanged','tools_unchanged','model_unchanged')) and sum(cell['correct'] for cell in result['cells']) == 0 and result['calibration_eligible'] is False and result['selection'] is None and result['human_answer_repairs'] == 0)
check('no_qualification_hidden_evaluation',result['terminal_hidden_calls'] == 0 and not list(CAL.rglob('HIDDEN.json')) and all(cell['hidden_evaluated'] is False for cell in result['cells']))
known_main_paths=list(EVIDENCE.glob('agent-v9-main*'))
observed_result_paths=list(EVIDENCE.glob('agent-v9-*/RESULT.json'))
check('no_main_result_in_reviewed_evidence_namespace',not known_main_paths and all(load(path).get('stage') != 'main' for path in observed_result_paths),{'observed_result_paths':[str(path.relative_to(EVIDENCE)) for path in observed_result_paths]})
check('operator_stop_binds_exact_failed_result_and_counts',stop['qualification_result_sha256'] == sha(CAL/'RESULT.json') and stop['qualified_tasks'] == 0 and stop['total_tasks'] == 3 and stop['generation_requests'] == 9 and stop['total_tokens'] == 25336 and stop['main_started'] is False and stop['model_qualified'] is False and stop['agent_productivity_advantage_established'] is False)
check('frozen_single_run_stopping_rule_and_outer_declaration','do not tune prompts' in protocol['prospective_amendment']['stop_rule'] and outer['single_registered_qualification'] is True and outer['exit_zero_does_not_imply_eligible'] is True)

# Runtime provenance consistency without rereading the 4.68 GB model.
check('model_identity_matches_frozen_gguf_and_acquisition_receipt',all(result['model'][key] == protocol['model'][key] for key in ('id','repository','revision','filename','bytes','sha256')) and all(result['model']['file'][key] == admission['model_acquisition'][key] == protocol['model'][key] for key in ('bytes','sha256')) and identity_before['model'] == result['model']['file'])
check('runtime_archive_admission_matches_protocol',admission['release'] == protocol['runtime']['release'] == 'b11669' and admission['archive_bytes'] == protocol['runtime']['bytes'] and admission['archive_sha256'] == protocol['runtime']['sha256'] and admission['extraction_verified'] is True and admission['version_stderr'] == identity_before['version_stderr'])
runtime_bad=[];runtime_seen=set();runtime_rehashed_bytes=0
for key,record in result['tools'].items():
 if key not in ('binary','tokenizer') and not key.startswith('runtime_companion:'):continue
 member='llama-b11669/'+Path(record['path']).name
 entry=admission['files'].get(member)
 if entry is None or any(entry[field] != record[field] for field in ('bytes','sha256')):runtime_bad.append(member)
 if record['path'] not in runtime_seen:
  runtime_seen.add(record['path'])
  if identity(record['path']) != record:runtime_bad.append(record['path'])
  runtime_rehashed_bytes+=record['bytes']
check('actual_runtime_files_match_archive_admission_and_stage_bindings',not runtime_bad,{'unique_files':len(runtime_seen),'bytes_read':runtime_rehashed_bytes,'mismatches':runtime_bad})
check('supported_python_preflight_and_outer_interpreter_binding',python_preflight == capacity['runtime_preflight'] == cap_plan['runtime_preflight'] == plan['runtime_preflight'] and python_preflight['kernel_seal_check'] is True and Path(outer['argv'][0]).resolve() == Path(cap_outer['argv'][0]).resolve() == Path(result['tools']['python']['path']) and python_preflight['python'] == result['tools']['python'])
check('both_outer_processes_completed_and_costs_bound',outer['returncode'] == cap_outer['returncode'] == 0 and outer['outer_wall_ns'] >= result['experiment_wall_ns'] and cap_outer['outer_wall_ns'] >= capacity['experiment_wall_ns'] and cap_outer['generation_requests_authorized'] is False)
first_log=(EVIDENCE/'agent-v9-capacity.log').read_text()
check('initial_unsupported_python_preflight_failure_retained_before_generation','E_REPAIR_PYTHON_SEAL_API' in first_log and 'runtime_preflight()' in first_log and stop['failed_initial_python_preflight']['model_requests'] == 0 and not list((EVIDENCE/'agent-v9-capacity').rglob('transport-*.request.json')))
check('source_still_clean_at_audit_end',git('status','--porcelain') == '' and git('rev-parse','HEAD') == expected_commit)

report={'schema':'hepta.agent.v9.independent-audit.v1','audit_date_utc':'2026-10-30','audit_ok':all(row['passed'] for row in checks),
        'source_commit':expected_commit,'source_tree':git('rev-parse','HEAD^{tree}'),'scope':'Read-only source/receipt/SSE arithmetic audit of completed qualification; no new inference, compilation, native validation, model tokenization or compression.',
        'checks':checks,'qualification':{'correct_tasks':0,'total_tasks':3,'actual_requests':serial,'actual_responses':len(request_records),'input_tokens':input_total,'output_tokens':output_total,'total_tokens':input_total+output_total,
                                         'valid_observation':result['valid_observation'],'calibration_eligible':result['calibration_eligible'],'hidden_calls':result['terminal_hidden_calls'],'human_answer_repairs':result['human_answer_repairs'],
                                         'cells':cell_records,'requests':request_records},
        'capacity':{'rows':len(capacity['rows']),'passed':capacity['complete'],'generation_requests':capacity['model_requests'],'reference_hidden_controls':19,
                    'reference_controls_are_model_successes':False,'engine_exited':capacity['engine_exited']},
        'stop':{'main_started':stop['main_started'],'main_cells_observed':0,'main_model_requests_observed':0,'single_failed_qualification_stopped':True,
                'scope':'Operator stop and reviewed evidence namespace; no global proof about unlogged external runs.'},
        'engine':{'qualification_pid':pid,'capacity_pid':cap_pid,'both_recorded_pids_currently_absent':not Path('/proc',str(pid)).exists() and not Path('/proc',str(cap_pid)).exists(),
                  'shutdown_ns':engine_records[0]['shutdown_ns'],'runtime_release':admission['release'],'runtime_unique_files_rehashed':len(runtime_seen),'runtime_bytes_rehashed':runtime_rehashed_bytes,
                  'model_bytes_freshly_rehashed_in_this_audit':False,'model_identity_source':'pinned protocol, acquisition admission, capacity and pre/post owned-engine receipts'},
        'costs':{'capacity_experiment_wall_ns':capacity['experiment_wall_ns'],'capacity_outer_wall_ns':cap_outer['outer_wall_ns'],
                 'qualification_experiment_wall_ns':result['experiment_wall_ns'],'qualification_outer_wall_ns':outer['outer_wall_ns'],
                 'two_measured_outer_stages_wall_ns':cap_outer['outer_wall_ns']+outer['outer_wall_ns'],
                 'initial_failed_python_preflight_outer_wall_ns':stop['failed_initial_python_preflight']['outer_wall_ns'],
                 'runtime_admission_verification_wall_ns':admission['verification_wall_ns'],'model_download_seconds_recorded':admission['model_acquisition']['download_seconds'],
                 'total_project_cost_measured':False},
        'limitations':['No HIA main arm was run; 0/3 Rust-node qualification does not establish a HIA/Rust language or Agent productivity advantage.',
                       'valid_observation means this registered run was completely observed; it does not mean tasks passed or the model is qualified.',
                       'Qualification hidden calls are zero; the 19 reference capacity controls did execute terminal hidden checks and are not model results.',
                       'The initial unsupported-Python preflight failed before generation, but its outer duration is missing; this cost is unknown, not zero.',
                       'The 4.68 GB model and runtime archive were not freshly rehashed or re-extracted in this lightweight audit; their historical byte identities are checked across retained receipts. Runtime executable/companion bytes were freshly checked.',
                       'Single-run stopping is an operator/protocol rule; absence of main evidence in the reviewed namespace is not a proof about all possible external activity.',
                       'The study is an adaptive V8 follow-up with one pinned 7B model, three qualification tasks and a finite Rust node profile; no broad model or language capability inference.',
                       'Hash-bound source, SSE and receipts are trusted-host evidence rather than hardware attestation or protection against fabricated records.'],
        'evidence_identities':{name:identity(EVIDENCE/name) for name in ('agent-v9-calibration/RESULT.json','agent-v9-calibration/PLAN.json','AGENT_STOP.json','agent-v9-capacity-system-python/CAPACITY.json','agent-v9-calibration.outer.json','agent-v9-capacity-system-python.outer.json','agent-runtime-admission.json','agent-system-python-preflight.json','agent-v9-capacity.log')},
        'auditor_script_identity':identity(Path(__file__)),'audit_wall_ns':time.monotonic_ns()-started}
with OUTPUT.open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2,allow_nan=False);stream.write('\n')
print(json.dumps({'audit_ok':report['audit_ok'],'checks':len(checks),'failed_checks':[row for row in checks if not row['passed']],
                  'output':identity(OUTPUT),'input_tokens':input_total,'output_tokens':output_total,'total_tokens':input_total+output_total,
                  'audit_wall_seconds':report['audit_wall_ns']/1e9},sort_keys=True))
