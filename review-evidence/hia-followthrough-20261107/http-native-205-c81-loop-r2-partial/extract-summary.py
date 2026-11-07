import pathlib,json,hashlib,os
root=pathlib.Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9/http-native-qualification-205-c81-loop-r2')
raw=(root/'result.json').read_bytes(); report=json.loads(raw)
assert report['status']=='passed' and report['tool_call_count']==39 and len(report['calls'])==39
assert len(report['tool_names_observed'])==11 and len(set(report['tool_names_observed']))==11
scenario=report['scenario']; slot='qualification-http-c81a938150d2-372e7da9-r2'
calls=[r for r in report['calls'] if 'target_slot' in r['arguments']]
assert [r['tool'] for r in calls]==['hia_adopt','hia_adopt','hia_rollback'] and all(r['arguments']['target_slot']==slot for r in calls)
assert [r['response']['status'] for r in calls]==['completed','rejected','completed']
assert scenario['adoption']['previous']=={'generation':'0','epoch':'0'} and scenario['adoption']['current']=={'generation':'1','epoch':'1'}
assert scenario['rollback']['current']=={'generation':'0','epoch':'2'}
summary={'schema':'hia-http-completed-loop-projection-v1','status':report['status'],'result_bytes':len(raw),'result_sha256':hashlib.sha256(raw).hexdigest(),'tool_call_count':report['tool_call_count'],'tool_names_observed':report['tool_names_observed'],'target_slot':slot,'prefix':report['registration']['prefix'],'adapter_sha256':report['registration']['adapter_sha256'],'adoption':scenario['adoption'],'stale_adoption':scenario['stale_adoption'],'rollback':scenario['rollback'],'planned_workload_complete':scenario['evaluation']['planned_workload_complete'],'evaluation_outcome':scenario['evaluation']['outcome'],'claims':report['claims'],'elapsed_ns':report['elapsed_ns'],'mcp_protocol_records':len(report['mcp_protocol_records']),'http_events_sha256':hashlib.sha256((root/'http-events.jsonl').read_bytes()).hexdigest()}
body=(json.dumps(summary,indent=2)+'\n').encode();fd=os.open(root/'execution-summary.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as output:output.write(body);output.flush();os.fsync(output.fileno())
print(json.dumps(summary),flush=True)
