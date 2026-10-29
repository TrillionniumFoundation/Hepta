#!/usr/bin/env python3
"""Independent evidence-only V8 accounting. No runner or experiment import."""
from pathlib import Path
import collections
import datetime
import hashlib
import json

RAW=Path('/tmp/hepta-next-agent-v7-toolstudy-v8-qwen7b-01')
CAPACITY=Path('/tmp/hepta-next-agent-v7-capacity-v8-01/CAPACITY.json')
REFUSAL=Path('/tmp/hepta-next-agent-v7-toolstudy-v8-main-refusal.json')
OUT=Path('/tmp/hepta-v8-raw-review-20261029')
EXPECTED_SOURCE='33c46cdef12c60faf0c1dbef02ea20caa3ad7d56'
EXPECTED_RESULT='7f411804f0c161b5ffbc7d54d4065504074e0a3e2acfafac1ba4b1fe009567fe'
READS={}

def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):
    path=Path(path); data=path.read_bytes()
    READS[str(path)]={'path':str(path),'bytes':len(data),'sha256':sha(data)}
    return data
def load(path):return json.loads(read(path))
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def same(a,b):assert a==b

def main():
    result=load(RAW/'RESULT.json');same(READS[str(RAW/'RESULT.json')]['sha256'],EXPECTED_RESULT)
    plan=load(RAW/'PLAN.json');capacity=load(CAPACITY);refusal=load(REFUSAL)
    same(sha(read(RAW/'PLAN.json')),result['plan_sha256'])
    same(sha(read(CAPACITY)),result['capacity_sha256'])
    for value in [plan,result,capacity,refusal]:same(value['source_commit'],EXPECTED_SOURCE)
    same(result['source_bindings'],plan['source_bindings']);same(result['source_bindings'],capacity['source_bindings']);same(result['source_bindings'],refusal['source_bindings'])
    for name,expected in result['source_bindings'].items():same(sha(read(RAW/'source_snapshot'/name)),expected)
    for key in ['model','tools','prompt_bindings']:
        same(result[key],plan[key]);same(result[key],capacity[key])
    same(result['protocol_sha256'],capacity['protocol_sha256'])
    same(result['protocol_sha256'],sha(canonical(plan['protocol'])+b'\n')) if False else None
    same(sha(read(RAW/'source_snapshot/experiments/hia_agent_toolstudy_v8_20261029/PROTOCOL.json')),result['protocol_sha256'])
    for key in ['source_unchanged','model_unchanged','tools_unchanged','valid_observation']:
        assert result[key] is True
    same(result['stage'],'calibration');same(result['selection'],None)

    engine=RAW/'engine-00'
    before=load(engine/'identity.json');after=load(engine/'identity-after.json')
    same(before['model'],after['model']);same(before['runtime_files'],after['runtime_files'])
    assert after['model_unchanged'] is True and after['runtime_unchanged'] is True
    same(result['model']['file'],before['model'])
    same(len(result['engines']),1);e=result['engines'][0]
    assert e['exited'] is True
    same(e['requests'],8);same(e['responses'],8);same(e['preparations'],8)
    same(e['identity'],after)
    service=load(engine/'SERVICE_CALLS.json');same(e['service_calls'],service)
    routes=collections.Counter(v['endpoint'] for v in service)
    assert set(routes).issubset({'/health','/props','/apply-template','/tokenize'})
    assert all(v['success'] is True for v in service)
    read(engine/'server.log');startup=load(engine/'STARTUP.json')
    same(len(list(RAW.glob('engine-*'))),1)
    transports=sorted(engine.glob('transport-*.request.json'))
    same(len(transports),8)
    for suffix in ['response.json','response.sse','usage.json']:
        same(len(list(engine.glob('transport-*.'+suffix))),8)
    ordered=[]
    for cell in result['cells']:
        same(load(RAW/cell['id']/'CELL.json'),cell)
        boundary=load(RAW/cell['id']/'BOUNDARY.json')
        assert all(boundary[k] is True for k in ['source_unchanged','model_unchanged','tools_unchanged'])
        for attempt in cell['attempts']:
            ordered.append((cell,attempt))
    same(len(ordered),8)
    rows=[];by_task=collections.defaultdict(list)
    total_transport_ns=0;total_request_ns=0
    for number,((cell,attempt),transport) in enumerate(zip(ordered,transports),1):
        prefix='transport-'+str(number).zfill(3)
        same(transport.name,prefix+'.request.json')
        request=load(transport);response=load(engine/(prefix+'.response.json'));usage=load(engine/(prefix+'.usage.json'))
        preparation=load(engine/('preparation-'+str(number).zfill(3)+'.json'))
        body=read(engine/(prefix+'.response.sse'))
        events=[]
        for line in body.decode().splitlines():
            if line.startswith('data:'):
                value=line[5:].strip()
                if value=='[DONE]':continue
                events.append(json.loads(value))
        assert events and sum(event.get('stop') is True for event in events)==1 and events[-1]['stop'] is True
        final=events[-1]
        text=''.join(v.get('content','') for v in events)
        ids=[token for v in events for token in v.get('tokens',[])]
        prompt_ids=request['payload']['prompt']
        assert type(prompt_ids) is list and all(type(v) is int for v in prompt_ids)
        same(preparation['input_token_ids'],prompt_ids);same(preparation['messages'],request['messages'])
        same(preparation['rendered_prompt'],request['rendered_prompt']);same(response['prompt'],request['rendered_prompt']);same(final['prompt'],request['rendered_prompt'])
        assert preparation['actual_generation_submitted'] is True and preparation['fits'] is True
        same(preparation['reserved_output_tokens'],1536);same(preparation['context'],8192)
        assert len(prompt_ids)+1536<=8192
        same(text,response['content']);same(ids,response['tokens']);same(ids,usage['observed_output_token_ids'])
        for v in [response,final]:
            same(v['tokens_evaluated'],len(prompt_ids));same(v['tokens_predicted'],len(ids))
            same(v['timings']['prompt_n'],len(prompt_ids));same(v['timings']['predicted_n'],len(ids))
            assert v['truncated'] is False and v['stop_type']=='eos'
        same(usage['events'],len(events));same(usage['response_bytes'],len(body))
        same(usage['input_tokens'],len(prompt_ids));same(usage['output_tokens'],len(ids));same(usage['total_tokens'],len(prompt_ids)+len(ids))
        same(usage['observed_output_token_lower_bound'],len(ids))
        assert usage['complete'] is True and usage['unknown_output_tokens'] is False
        assert usage['error'] is None and usage['unknown_reason'] is None
        folder=RAW/cell['id'];index=attempt['index']
        req=load(folder/f'attempt-{index}.request.json');ans=load(folder/f'attempt-{index}.response.json');obs=load(folder/f'attempt-{index}.evaluation.json')
        same(req['messages'],request['messages']);same(req['captured_query_sha256'],load(folder/'CAPTURED_QUERY.json')['query_sha256'])
        same(obs,attempt);same(ans['text'],text);same(ans['input_token_ids'],prompt_ids);same(ans['output_token_ids'],ids)
        same(ans['usage'],attempt['usage'])
        same(attempt['usage']['input_tokens'],len(prompt_ids));same(attempt['usage']['output_tokens'],len(ids));same(attempt['usage']['returned_token_ids'],len(ids))
        same(attempt['usage']['total_tokens'],len(prompt_ids)+len(ids))
        assert attempt['actual_generation_requested'] is True and 'partial_usage' not in attempt
        assert attempt['request_wall_ns']>=usage['wall_ns']
        ev=attempt['evaluation']
        same(load(folder/f'candidate-{index}/STUDY_EVALUATION.json'),ev)
        if ev.get('accepted') is True:
            assert ev['status']=='correct' and ev['build']['status']=='compiled' and ev['build']['native_built'] is True
            assert all(ev['public'][k] is True for k in ['native_executed','artifact_unchanged','resource_contract_passed','vm_contract_passed'])
            same(ev['public']['status'],'correct');same(index,len(cell['attempts'])-1)
        else:
            assert ev['hidden_evaluated'] is False
        row={'transport':number,'task':cell['task'],'attempt':index,'input_tokens':len(prompt_ids),'output_tokens':len(ids),'text_bytes':len(text.encode()),'text_sha256':sha(text.encode()),'sse_sha256':sha(body),'sse_events':len(events),'complete':True,'status':attempt['status'],'accepted':ev.get('accepted') is True,'error_category':(ev.get('error') or {}).get('message'),'transport_wall_ns':usage['wall_ns'],'generation_wrapper_wall_ns':attempt['request_wall_ns'],'messages_sha256':sha(canonical(request['messages'])),'prompt_ids_sha256':sha(canonical(prompt_ids)),'output_ids_sha256':sha(canonical(ids))}
        rows.append(row);by_task[cell['task']].append(row)
        total_transport_ns+=usage['wall_ns'];total_request_ns+=attempt['request_wall_ns']
    totals={'requests':len(rows),'input_tokens':sum(r['input_tokens'] for r in rows),'output_tokens':sum(r['output_tokens'] for r in rows)}
    totals['total_tokens']=totals['input_tokens']+totals['output_tokens']
    same(totals,{'requests':8,'input_tokens':19014,'output_tokens':3398,'total_tokens':22412})
    same(result['known_input_tokens'],totals['input_tokens']);same(result['known_output_tokens'],totals['output_tokens']);same(result['total_tokens'],totals['total_tokens'])
    same(result['requests'],8);same(result['responses'],8);same(result['unknown_usage_requests'],0);same(result['partial_output_token_lower_bound'],0)
    same(total_request_ns,2015920246400);same(result['experiment_wall_ns'],2059597590950)
    same(sum(c['correct'] for c in result['cells']),1);same(len(result['cells']),3);assert result['calibration_eligible'] is False
    same(result['first_submission_correct'],0);same(result['terminal_hidden_calls'],1);same(result['validation_calls'],8)
    hidden_count=0
    for c in result['cells']:
        hidden_file=RAW/c['id']/'HIDDEN.json'
        if c['hidden_evaluated']:
            hidden=load(hidden_file);same(hidden['status'],'correct')
            assert all(hidden[k] is True for k in ['native_executed','artifact_unchanged','resource_contract_passed','vm_contract_passed'])
            hidden_count+=1
        else:assert not hidden_file.exists()
    same(hidden_count,1)
    same(len(list(RAW.glob('*_hia_*'))),0)
    expected_repeats={'two_file_signature_repair':(2072,790,'03c92c5e2fce541959e3dd66c3493e9f7349d264e48a73e5615527ba04252ecb','E_STRUCTURED_RUST: only disclosed scalar/Vec<u8> types'),'owner_flow_repair':(794,280,'bed9d4b42dd651c4bbd0a6c874cdafd875e6e8d6d8598f7a577d65617fb95313','E_STRUCTURED_RUST: trailing tokens outside selected fragment')}
    for task,(length,tokens,digest,error) in expected_repeats.items():
        group=by_task[task];same(len(group),3)
        for row in group:
            same(row['text_bytes'],length);same(row['output_tokens'],tokens);same(row['text_sha256'],digest);same(row['error_category'],error)
            assert row['accepted'] is False
    same(refusal['returncode'],1);same(refusal['model_requests'],0);same(refusal['main_cells_started'],0)
    assert refusal['gate_rejected_before_engine_construction'] is True and refusal['main_output_directory_created'] is False
    assert 'E_TOOLSTUDY_NO_QUALIFIED_MODEL' in refusal['stderr']
    same(refusal['qualification']['sha256'],EXPECTED_RESULT);same(refusal['capacity']['sha256'],result['capacity_sha256'])
    same(refusal['wall_ns'],5690141661)
    same(len(capacity['rows']),19);assert capacity['complete'] is True and capacity['model_requests']==0
    capstats={key:max(r[key] for r in capacity['rows']) for key in ['initial_input_tokens','complete_reference_output_tokens','max_observed_repair_plus_output_reserve','allocated_worst_repair_plus_output_reserve']}
    same(capstats,{'initial_input_tokens':2758,'complete_reference_output_tokens':1059,'max_observed_repair_plus_output_reserve':5001,'allocated_worst_repair_plus_output_reserve':7238})
    for r in capacity['rows']:
        assert all(r[k] is True for k in ['passed','capacity_passed','reference_passed_all_gates','template_exact_match','tokenizer_ids_match','actual_complete_requests_always_rechecked'])
    report={
      'schema':'hepta.agent.v8.independent-raw-accounting-review.v1',
      'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'source_commit':EXPECTED_SOURCE,'result_sha256':EXPECTED_RESULT,
      'review_script_sha256':sha(Path(__file__).read_bytes()),'passed_checks':True,
      'totals':totals,'transport_wall_ns':total_transport_ns,'generation_wrapper_wall_ns':total_request_ns,
      'experiment_wall_ns':result['experiment_wall_ns'],'capacity_reference_wall_ns':capacity['experiment_wall_ns'],
      'main_refusal_wall_ns':refusal['wall_ns'],
      'sum_three_recorded_phase_wall_ns':result['experiment_wall_ns']+capacity['experiment_wall_ns']+refusal['wall_ns'],
      'phase_sum_is_not_total_project_or_outer_process_cost':True,
      'rows':rows,'correct_tasks':1,'qualification_tasks':3,'first_submission_correct':0,'calibration_eligible':False,
      'public_native_execution_count':sum(a['evaluation'].get('public') is not None for c in result['cells'] for a in c['attempts']),
      'terminal_hidden_execution_count':hidden_count,'main_cells_started':0,'main_requests':0,'HIA_model_cells':0,
      'source_snapshot_files_rehashed':len(result['source_bindings']),
      'source_model_tools_boundaries_all_true':True,'retained_model_and_runtime_identities_before_after_equal':True,
      'runtime_companion_records':len(before['runtime_files']),
      'owned_server_exited_in_retained_shutdown_record':e['exited'],
      'service_call_routes':dict(routes),'capacity_summary_rechecked':capstats,
      'read_only_limits':[
        'This reviewer parsed/hashes retained files using Python standard library only; no experiment runner, model, tokenizer, native executable, compiler or tests were invoked.',
        'Prompt token identities were compared across captured preparation, actual submitted payload, generated response, SSE final usage and per-attempt records; no tokenizer was rerun to independently map text to vocabulary IDs.',
        'Source snapshot bytes were checked against every recorded source binding. Historical Git attribution and source-method review remain separate producer/reviewer records; this script does not rewrite or upgrade those records.',
        'Model/runtime stability and owned server exit are checks of retained before/after/exit records and per-cell boundaries, not a fresh hash of multi-gigabyte model weights or independent historical process observation.',
        'Model outputs are preserved verbatim. API/owner failures occur at disclosed fragment parsing, before compilation and overlap checks; no counterfactual repaired-answer success is inferred.',
        'Only fresh Rust node qualification ran. No HIA language arm or four-arm model main was run, so this is not evidence of relative language or Agent productivity.',
        'Wall durations are retained producer clock measurements. The reviewer recomputes request sums and phase arithmetic, but cannot independently recreate historical elapsed time.',
      ],
      'no_hidden_feedback_repair_evidence':{'hidden_files':1,'hidden_acceptance_is_terminal_in_each_cell':True,'failed_cells_hidden_files':0,'next_task_resets_messages':True,'runner_source_path':'source_snapshot/tools/qualify_hia_agent_toolstudy.py','scope':'Raw attempt ordering and static call flow; no evaluator replay'},
      'scientific_acceptance_gates_changed':False,'authority':'DENY_ALL',
    }
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'REVIEW.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    (OUT/'READ_FILES.json').write_text(json.dumps({'schema':'hepta.agent.v8.review-read-files.v1','files':list(READS.values())},indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({k:report[k] for k in ['passed_checks','totals','transport_wall_ns','generation_wrapper_wall_ns','experiment_wall_ns','capacity_reference_wall_ns','main_refusal_wall_ns','sum_three_recorded_phase_wall_ns','correct_tasks','public_native_execution_count','terminal_hidden_execution_count','source_snapshot_files_rehashed','runtime_companion_records','service_call_routes']},indent=2))

if __name__=='__main__':main()
