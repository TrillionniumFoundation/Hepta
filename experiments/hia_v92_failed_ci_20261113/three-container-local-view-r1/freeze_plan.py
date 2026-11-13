"""Freeze this new consumer/source20 request; does not import its controls."""
from pathlib import Path
import ast,hashlib,json,os
R=Path(__file__).resolve().parent
F=Path('/tmp/hia-v92-ci-failed-original-parts-r1-20261113-e26e')
C=Path('/workspace/scratch/e26ed3e2edcf/full32-stream-private-proxy-plan-r3-20261113-e26e')
def pin(p):
 b=p.read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def save(name,v):
 b=(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 with (R/name).open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return pin(R/name)
old=json.loads((F/'REQUEST.json').read_bytes());prior=json.loads((R/'inputs/FINAL.json').read_bytes())
observed=json.loads((R/'inputs/SMALL-READBACK.json').read_bytes());cold=json.loads((C/'POLICY.json').read_bytes())
assert prior['artifact']==old['artifact'] and observed['status']=='HOLD'
newparts=[]
for item,(aid,count,sha,volume) in zip(old['parts'],[
 (13998272481,268838037,'481f17946b97dad14c56ff94cb13ae0033f77d145811dfdd422e5c134fc64e19','tmp'),
 (13997637506,268838053,'f12a3d4e2c267a23ba487b75abb289c83e06e00dcdb95bb369de8f5442db8c89','workspace'),
 (13997917943,119894487,'0303930e3e9dae1108d6a656148f1f6eec86a007f2e066469c0f79ba52453d07','tmp')]):
 row={**item,'sha256':prior['parts'][item['ordinal']]['retained']['sha256'],'volume':volume,
      'artifact':{'id':aid,'bytes':count,'sha256':sha}};newparts.append(row)
roots={'tmp':'/tmp/hia-v92-three-part-view-r1-20261113-e26e',
       'workspace':'/workspace/scratch/e26ed3e2edcf/core/v92-three-part-view-r1-20261113-e26e'}
volumes={}
for key,root in roots.items():
 p=Path(root);assert not os.path.lexists(p)
 volumes[key]={'root':root,'parent':str(p.parent),'parent_device':p.parent.stat().st_dev,
  'limits':{'container':sum(x['artifact']['bytes'] for x in newparts if x['volume']==key),
            'selected':128<<20 if key=='tmp' else 0,'metadata':8<<20 if key=='tmp' else 64<<20,
            'parent':8<<20 if key=='tmp' else 16<<20,'reserve':512<<20,'inodes':4096}}
 assert volumes[key]['limits']['container'] in (388732524,268838053)
files=sorted(p for folder in ('control','controls','inputs','reference') for p in (R/folder).rglob('*') if p.is_file())
input_pins={str(p.relative_to(R)):{k:v for k,v in pin(p).items() if k!='git_blob_sha1'} for p in files}
for p in files:
 if p.suffix=='.py':ast.parse(p.read_bytes())
t=ast.parse((R/'controls/check_view.py').read_bytes());cl=next(x for x in t.body if isinstance(x,ast.ClassDef) and x.name=='StoredContainerControls')
ids=[cl.name+'.'+x.name for x in cl.body if isinstance(x,ast.FunctionDef) and x.name.startswith('test_')];assert len(ids)==20
policy={'schema':'hia.v92.three-stored-container-view-policy.v1','status':'FROZEN_UNEXECUTED',
 'original_artifact':old['artifact'],'receiver':{'run_id':43338002642,'attempt':1,'status':'failure',
    'workflow_commit':'55225e8e954f19e0c6559a6e3d0c29bf16b70ba5',
    'control_commit':'89aa086c8e345ecae66cb32a2dd9ff39fe1f35de',
    'policy_sha256':'c4171e09f97480c0ba4d1b7b31aac477590f579b6dcc370b4f8505d5e4dc7806'},
 'prior_small_canonical':'b32b3e5ff65e8161cd705c3e90724559c7aa04a8','parts':newparts,
 'operation_root':roots['tmp'],'volumes':volumes,
 'runtime':cold['runtime'],'runtime_scope':'new local CPython3.12.14 read-only operation; no claim runner/runtime equivalence to original3.14.4',
 'guardian_sha256':old['controls']['guardian.py']['sha256'],
 'lifecycle_implementation_sha256':old['controls']['process_owner_impl.py']['sha256'],
 'inputs':input_pins,'limits':{'owner_seconds':900,'cleanup_seconds':3,'complete_seconds':720},
 'diagnostics':old['diagnostics'],
 'observed_original_denominator':{'members':observed['complete_members'],'expanded_bytes':observed['complete_expanded_bytes'],
                                 'selected_files':observed['selected_count'],'selected_bytes':observed['selected_bytes']},
 'selection':old['selection'],'provider_references_path':'/tmp/hia-v92-three-view-provider-refs-r1-20261113-e26e.private.json',
 'proxy_configuration_path':'/tmp/hia-v92-three-view-original-proxy-r1-20261113-e26e.private.json',
 'private_inputs':'Only mode0600 owned single-link exact external refs/proxy bytes; opaque SHA/runtime identity accepted on fixed launch argv. Original values never public.',
 'connector_reference_acquisition':'Three fixed artifact references are acquired and logged separately before this local owner; no claim their connector operations fit within local900/720.',
 'network':{'provider_GETs':3,'per_artifact_GETs':1,'retries':0,'redirect_hops_per_GET':3,'direct_after_proxy_error_fallback':False,
            'original_urllib_proxy_auth_NO_PROXY_and_CA_semantics':True,'TLS_default_ALPN_and_PHA_preserved':True},
 'completion_clock':'One monotonic start before mkdir/owner, deadline=start+720 throughout worker, parent all-container/all-original-body readback and final fsync/readback; no reset.',
 'mandatory_source_controls':{'methods':20,'expected_ids':ids,'request':'CONTROL-REQUEST.json','actual_root':'/tmp/hia-v92-three-view-source20-r1-20261113-e26e'},
 'all_three_original_containers_retained':True,'part_disposal_permitted':False,'whole_656MB_copy_permitted':False,
 'original_remote_8GiB_gate_changed':False,'new_distinct_local_per_volume_capacity_proof':True,
 'product_execution_permitted':False,'original_CI_and_recovery_failures_preserved':True,'any_old_run_replayed':False}
policy_pin=save('POLICY.json',policy)
source_inputs={**input_pins,'POLICY.json':{k:policy_pin[k] for k in ('bytes','sha256')}}
environment={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','PYTHONUNBUFFERED':'1'}
control_request={'schema':'hia.v92-three-view-source20-request.v1','status':'FROZEN_UNEXECUTED',
 'qualification_seconds':20,'cleanup_seconds':3,'operation_root':'/tmp/hia-v92-three-view-source20-r1-20261113-e26e',
 'output':'/tmp/hia-v92-three-view-source20-r1-20261113-e26e/tests','expected_ids':ids,'inputs':source_inputs,
 'command':[cold['runtime']['path'],'-I','-S','-B',str(R/'controls/run_controls.py')], 'environment':environment,
 'runtime':cold['runtime'],'minimum_free_bytes':128<<20,'minimum_free_inodes':4096,'maximum_output_bytes':32<<20,
 'network_used':False,'private_inputs_captured':False,'receiver_execution':False,'product_execution':False,
 'scope':'20 newly written synthetic tiny-file boundary controls. Not inherited74static/old20+8 runtime controls; all UNEXECUTED.'}
control_pin=save('CONTROL-REQUEST.json',control_request)
save('CONTROL-LAUNCH.json',{'schema':'hia.exact-one-source20-launch.v1','request':control_pin,
 'command':[cold['runtime']['path'],'-I','-S','-B',str(R/'controls/launch_controls.py')],
 'cwd':str(R),'environment':environment,'owner_seconds':20,'cleanup_seconds':3,'executions_authorized_by_this_file':0})
request={'schema':'hia.v92.three-container-view-readonly-request.v1','status':'FROZEN_UNEXECUTED',
 'policy':policy_pin,'controls':input_pins,'parts':newparts,'original_artifact':old['artifact'],
 'limits':policy['limits'],'volumes':volumes,'source20_request':control_pin,'network':policy['network'],
 'private_input_capture_required_before_invocation':True,'private_input_shapes':{
  'provider_refs':{'schema':'hia.v92.three-official-provider-references.v1','receiver_run_id':43338002642,
   'parts':[{'ordinal':x['ordinal'],'artifact_id':x['artifact']['id'],'url':'PRIVATE_PROVIDER_REF_NOT_FILLED_OR_PUBLISHED'} for x in newparts]},
  'proxy':'exact copied control/freeze_private_proxy.py reads actual original proxy/CA environment once into a fresh0600file; no network or owner'},
 'source_only_validation_pending':True,'receiver_execution_permitted_only_by_separate_root_authorization':True,
 'root_cause_original_native42':'UNKNOWN until actual step42 originals read','all_original_failures_retained':True,
 'success_label':'THREE_CONTAINERS_ALL_ORIGINAL_BODIES_READ_ONLY_PASS, never product PASS',
 'failure_policy':{'no_retry':True,'all_partial_bytes_retained':True,'unknown_owner_no_child_read':True,
                   'closed_nonzero_bounded_custody':True,'whole_files_not_truncated':True,'no_limits_or_originals_modified':True}}
request_pin=save('REQUEST.json',request)
save('LAUNCH.json',{'schema':'hia.v92.three-container-exact-launch-template.v1','request':request_pin,
 'argv_prefix':[cold['runtime']['path'],'-I','-S','-B',str(R/'control/launch.py')],
 'required_final_argv':['--provider-references-sha256','ROOT_VERIFIED_PRIVATE_REFS_SHA256','--proxy-configuration-sha256','ROOT_VERIFIED_PRIVATE_PROXY_SHA256'],
 'substitution_scope':'Only two opaque SHA256 from original create-only private input receipts. No path, command, source or budget change.',
 'cwd':str(R),'environment':'inherit current original proxy/CA only for launcher preflight; frozen launch constructs public worker env without proxy URLs',
 'owner_seconds':900,'cleanup_seconds':3,'global_complete_seconds':720,'executions_authorized_by_this_file':0})
proof={}
for key,v in volumes.items():
 s=os.statvfs(v['parent']);limit=v['limits'];required=sum(limit[x] for x in ('container','selected','metadata','parent','reserve'))
 proof[key]={'parent':v['parent'],'device':v['parent_device'],'container_bytes':limit['container'],
             'selected_maximum':limit['selected'],'metadata_maximum':limit['metadata'],'parent_metadata_maximum':limit['parent'],
             'persistent_total_maximum':required-limit['reserve'],'reserve':limit['reserve'],'minimum_start_free_bytes':required,
             'minimum_free_inodes':4096,'observed_authoring_free_bytes':s.f_bavail*s.f_frsize,
             'observed_authoring_free_inodes':s.f_favail,'fresh_check_required_at_launch_and_each_read_write':True}
save('CAPACITY-PROOF.json',{'schema':'hia.v92.three-container-cross-volume-proof.v1','volumes':proof,
 'whole_original_zip_copy_bytes':0,'no_existing_artifact_deleted':True,'parent_after_read_and_metadata_included':True,
 'temporary_overflow_or_same_device_fallback_permitted':False})
save('STATIC-AUTHORING.json',{'schema':'hia.v92.three-container-static-authoring.v1','AST_files':len([p for p in files if p.suffix=='.py']),
 'new_source_methods':20,'declared_input_files':len(input_pins),'all_inputs':{str(p.relative_to(R)):pin(p) for p in files},
 'actual_source_controls_run':0,'consumer_runs':0,'provider_large_GETs':0,'prior_small_actual_canonical':'b32b3e5ff65e8161cd705c3e90724559c7aa04a8',
 'unchanged_inherited_bytes':['control/local_io.py','control/freeze_private_proxy.py','control/guardian.py','control/process_owner_impl.py','control/original_receiver.py'],
 'not_a_product_or_full_custody_pass':True})
print(json.dumps({'policy':policy_pin,'request':request_pin,'control_request':control_pin,'inputs':len(input_pins),'methods':len(ids),'capacity':proof},indent=2))
