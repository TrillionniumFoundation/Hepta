#!/usr/bin/env python3
"""Package completed V9 records only; never modify or interpret model answers."""
from pathlib import Path
import hashlib,json,shutil
RAW=Path('/tmp/hepta-next-agent-v9-qwen7b-01')
OUT=Path('/tmp/hepta-next-agent-v9-evidence-package')
SOURCE='ef9fbafabe9db52a5e59220f1738d5842ac164cc'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(d,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
def ident(p): return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def collect(raw,label):
 rows=[]
 for p in sorted(raw.rglob('*')):
  if not p.is_file(): continue
  rel=p.relative_to(raw);b=p.read_bytes();copy=None
  if 'source_snapshot' not in rel.parts and not b.startswith(b'\x7fELF') and b'\0' not in b:
   try: b.decode('utf-8')
   except UnicodeDecodeError: pass
   else:
    target=OUT/label/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b);copy=str(target.relative_to(OUT))
  rows.append({'path':str(p),'relative_path':str(rel),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'compact_copy':copy})
 save(OUT/(label.upper()+'_RAW_MANIFEST.json'),{'files':rows})
 return rows

def main():
 result=json.loads((RAW/'RESULT.json').read_text())
 assert result['source_commit']==SOURCE
 assert all(e['exited'] for e in result['engines']), 'all owned engines must have exited'
 assert result['status']=='all_cells_attempted', 'partial runs require separate explicit classification'
 assert len(result['cells'])==3
 manifest=collect(RAW,'qualification')
 attempts=[a for c in result['cells'] for a in c['attempts']]
 rows=[]
 for c in result['cells']:
  response_files=sorted((RAW/c['id']).glob('attempt-*.response.json'))
  response_hashes=[]
  for p in response_files:
   response=json.loads(p.read_text());response_hashes.append(hashlib.sha256(response['text'].encode()).hexdigest())
  a=c['attempts'];usage=[x['usage'] for x in a if x.get('usage')];partial=[x['partial_usage'] for x in a if x.get('partial_usage')]
  rows.append({'task':c['task'],'submissions':len(a),'correct':c['correct'],'hidden_evaluated':c['hidden_evaluated'],
   'statuses':[x['status'] for x in a], 'known_input_tokens':sum(x['input_tokens'] for x in usage)+sum(x['input_tokens'] for x in partial),
   'known_output_tokens':sum(x['output_tokens'] for x in usage),
   'request_wall_ns':sum(x.get('request_wall_ns',0) for x in a),'cell_wall_ns':c['cell_wall_ns'],
   'response_text_sha256':response_hashes,'identical_complete_responses':len(response_hashes)==len(a) and len(set(response_hashes))==1,
   'complete_responses':len(usage),'unknown_usage_requests':sum(x.get('actual_generation_requested',False) for x in a)-len(usage),
   'observed_partial_output_token_lower_bound':sum(x['observed_output_token_lower_bound'] for x in partial),
   'errors':[x.get('evaluation',{}).get('feedback',{}).get('diagnostic') or x.get('error') for x in a]})
 budget_receipts=[json.loads(p.read_text()) for p in RAW.rglob('attempt-*.repair-budget.json')]
 summary={key:result[key] for key in ['source_commit','calibration_eligible','requests','responses','known_input_tokens',
   'known_output_tokens','total_tokens','unknown_usage_requests','experiment_wall_ns','first_submission_correct',
   'human_answer_repairs','source_unchanged','tools_unchanged','model_unchanged','valid_observation']}
 summary.update(schema='hepta.agent.toolstudy-evidence.v9', qualification_result=ident(RAW/'RESULT.json'),
  qualification_correct=sum(c['correct'] for c in result['cells']),qualification_tasks=len(result['cells']),
  request_wall_ns=sum(a.get('request_wall_ns',0) for a in attempts),
  all_owned_engines_exited=all(e['exited'] for e in result['engines']),rows=rows,
  max_actual_input_tokens=max(((a.get('usage') or a.get('partial_usage'))['input_tokens'] for a in attempts if a.get('usage') or a.get('partial_usage')),default=0),
  max_actual_output_tokens=max((a['usage']['output_tokens'] for a in attempts if a.get('usage')),default=0),
  independent_pregeneration_review='34cafc7eb0efe9e016ed7f0070414c01576bd642',
  independent_v8_raw_review='103218400fa2ce6e6fa4196b1be924be0d819147',
  adaptation='One prospectively registered minimal generic-contract amendment after observed V8 failures; no acceptance/model/budget/task changes.',
  old_v8_source='33c46cdef12c60faf0c1dbef02ea20caa3ad7d56',
  old_v8_result={'qualification_correct':1,'qualification_tasks':3,'requests':8,'total_tokens':22412,'experiment_wall_ns':2059597590950},
  prior_results_reclassified=False,automatic_host_answer_repairs=0,general_agent_productivity_proved=False,
  max_previous_retokenized_tokens=max((b['previous_response_tokens'] for b in budget_receipts),default=0),
  max_public_feedback_tokens=max((b['feedback_tokens'] for b in budget_receipts),default=0),
  diagnostic_clipping_count=sum(b['feedback']['diagnostic_clipped'] for b in budget_receipts),
  code_truncation_count=sum(b['previous_code_truncated'] for b in budget_receipts),
  public_case_removal_count=sum(b['public_cases_removed'] for b in budget_receipts),
  history_budget_receipts=budget_receipts)
 if not result['calibration_eligible']:
  refusal=Path('/tmp/hepta-next-agent-v9-main-refusal.json');r=json.loads(refusal.read_text())
  assert r['gate_rejected_before_engine_construction'] and r['model_requests']==0 and not r['main_output_directory_created']
  summary.update(main_cells_started=0,main_model_requests=0,main_refusal={**ident(refusal),'wall_ns':r['wall_ns']},
   registered_stop_rule_taken=True,remaining_empirical_requirement='An independently capable model under the unchanged complete qualification; no further same-task prompt tuning or pointless same7B repeat.')
  target=OUT/'receipts'/refusal.name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(refusal,target)
 old=json.loads(Path('/tmp/hepta-next-agent-evidence-20261029/experiments/hia_agent_toolstudy_v8_20261029/evidence/SUMMARY.json').read_text())['all_V5_V6_V8_retained_model_runs']
 summary['all_V5_V6_V8_V9_retained_model_runs']={'requests':old['requests']+result['requests'],
   'known_total_tokens':old['known_total_tokens']+result['known_input_tokens']+result['known_output_tokens'],
   'experiment_wall_ns':old['experiment_wall_ns']+result['experiment_wall_ns'],
   'unknown_usage_requests':result['unknown_usage_requests'],
   'observed_partial_output_token_lower_bound':result['partial_output_token_lower_bound'],
   'minimum_total_tokens':old['known_total_tokens']+result['known_input_tokens']+result['known_output_tokens']+result['partial_output_token_lower_bound'],
   'exact_total_tokens':None if result['unknown_usage_requests'] else old['known_total_tokens']+result['total_tokens'],
   'excludes':old['excludes']}
 save(OUT/'SUMMARY.json',summary)
 logfile=Path('/tmp/hepta-next-agent-v9-qwen7b-01.log')
 if logfile.exists(): shutil.copy2(logfile,OUT/'receipts'/logfile.name)
 print(json.dumps({'manifest_files':len(manifest),'compact_files':sum(x['compact_copy'] is not None for x in manifest),
   'summary':str(OUT/'SUMMARY.json'),'correct':summary['qualification_correct'],'requests':summary['requests'],
   'total_tokens':summary['total_tokens'],'result_sha256':summary['qualification_result']['sha256']}))
if __name__=='__main__': main()
