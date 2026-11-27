import ast, hashlib, json
from pathlib import Path
OLD=Path('/workspace/scratch/dda74a4fae35/v134-u32-hosted-publication-r1/custody-relay-prepared-r1')
NEW=Path('/tmp/hia-u32-custody-relay-r2-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/ROOT-CUSTODY-R2-STATIC-CORRECTED.json')
def pin(raw):
 return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
script=(NEW/'harness/tools/retain_original.py').read_bytes()
assert script==(OLD/'harness/tools/retain_original.py').read_bytes()
sp=pin(script);assert sp['git_blob']=='60625d1ca0a83220f711365e7aebbd40c250e7bb'
old=(OLD/'harness/.github/workflows/custody.yml').read_bytes()
new=(NEW/'harness/.github/workflows/custody.yml').read_bytes()
bad=b'CUSTODY_'+sp['sha256'].encode()+b'256:'
assert old.count(bad)==1 and new==old.replace(bad,b'CUSTODY_SCRIPT_SHA256:',1)
assert new.count(b'CUSTODY_SCRIPT_SHA256: '+sp['sha256'].encode())==1
assert pin(new)['git_blob']=='bca1ebb06c30ac9447500f717facda12ebb9158a'
parsed=ast.parse(script);values={}
for n in parsed.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
  try:values[n.targets[0].id]=ast.literal_eval(n.value)
  except (ValueError,TypeError):pass
assert values['REPO']=='TrillionniumFoundation/Hepta'
assert values['ORIGINAL_RUN']==43579403463 and values['ARTIFACT_ID']==14108215158
assert values['ORIGINAL_HEAD']=='de4afa1f7f4cb1fc2d5284965f7f2a7c55632d2a'
assert values['ORIGINAL_BYTES']==1270286664
assert values['ORIGINAL_SHA']=='f318593523cc6294e9507aae9ef351d64231a2ead829d325e2e563a96176fb02'
proof=json.loads((NEW/'MANDATORY-PATH-PROVENANCE.json').read_bytes());sources={}
for label,row in proof['source_identities'].items():
 raw=Path(row['path']).read_bytes();got=pin(raw)
 assert all(row['identity'][k]==v for k,v in got.items()),label
 sources[label]=raw.decode()
for row in proof['exact_AST_write_binding_and_read_points']:
 source=sources[row['source']]
 hits=[ast.get_source_segment(source,n) for n in ast.walk(ast.parse(source)) if getattr(n,'lineno',None)==row['line'] and getattr(n,'end_lineno',None)==row['end_line']]
 assert row['exact_source'] in hits,(row['source'],row['line'])
mandatory={'evidence/launch/PROCESS-EXIT.json','evidence/launch/RESULT.json',
 'scope/evidence/full-qualification-r2/OUTER.json','scope/evidence/full-qualification-r2/OWNER.json',
 'scope/evidence/full-qualification-r2/qualification.json'}
assert {x['logical_path'] for x in proof['mandatory_paths']}==mandatory
assert all(x['collector_storage_path']=='files/'+x['logical_path'] for x in proof['mandatory_paths'])
for row in proof['actual_hosted_success_stage_log'].values():
 assert row['raw_line'] in sources['ACTUAL_HOSTED_FULL_JOB_LOG'].splitlines()
plan=json.loads((NEW/'PLAN.json').read_bytes())
assert plan['branch_intent_only']=='codex/hia-u32-original-custody-v134-r1-20261114-dda7'
assert plan['parent_intent_only']==values['ORIGINAL_HEAD']
assert plan['commit_message_intent_only']=='Preserve exact completed u32 artifact as bounded original byte spans'
assert plan['transport']['span_bytes']==134217728 and plan['transport']['fixed_max_spans']==10
assert plan['transport']['last_complete_span_bytes']==62327112
for path,expected in plan['complete_harness_files'].items():
 assert all(expected[k]==v for k,v in pin((NEW/'harness'/path).read_bytes()).items())
report=dict(schema='hepta.root-custody-r2-static.v1',status='PASS_STATIC_ONLY',
 script=sp,workflow=pin(new),harness_files=2,expected_tree='f297aa49d35f63dc0168aaad5fe79c08b12b6076',
 unchanged_complete_script=True,only_workflow_change='CUSTODY_SCRIPT_SHA256 environment key',
 full_R1_workflow_inverse=True,mandatory_paths=sorted(mandatory),
 all_provenance_input_full_bytes_verified=True,all_source_write_read_and_collector_spans_exact=True,
 actual_original_ZIP_member_readback=False,custody_executions=0,product_executions=0,
 no_original_run_mutation=True,original_artifact_id=14108215158)
with OUT.open('x') as f:f.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(status=report['status'],report=str(OUT),pin=pin(OUT.read_bytes()))))
