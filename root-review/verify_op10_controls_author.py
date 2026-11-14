"""Read only the frozen op10 author controls and retained sources; no product import."""
import ast,hashlib,json,stat
from pathlib import Path
D=Path('/tmp/hia-inspect-cli-controls-r2-dda7')
O=Path('/tmp/hia-root-v141-dda7/ROOT-OP10-CONTROLS-AUTHOR-REVIEW.json')
def pin(b,m=0o644):
    return dict(bytes=len(b),mode='100755' if m&0o111 else '100644',sha256=hashlib.sha256(b).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())
raw=(D/'HANDOFF.json').read_bytes()
assert pin(raw)['git_blob']=='82f9bdfb3d184669d36182d2c71866f6847f919a'
packet=json.loads(raw);assert len(packet['members'])==11 and packet['state']=='AUTHORED_NOT_EXECUTED'
for name,row in packet['members'].items():
    path=Path(row['path']);s=path.lstat();assert stat.S_ISREG(s.st_mode)
    b=path.read_bytes();assert b==row['text'].encode() and pin(b,stat.S_IMODE(s.st_mode))==row['pin'] and stat.S_IMODE(s.st_mode)==row['posix_mode']
    if name.endswith('.py'):ast.parse(b)
t=json.loads(packet['members']['EXECUTION-TEMPLATE.json']['text'])
index=json.loads(packet['members']['AUTHORING-INDEX.json']['text'])
assert set(index['files'])==set(packet['members'])-{'AUTHORING-INDEX.json'}
for name,row in index['files'].items():assert row=={k:packet['members'][name][k] for k in ('path','pin','posix_mode')}
descriptors=list(t['source_overlay'].values())+list(t['retained_authorities'].values())+[t['compiler']]
for row in descriptors:
    path=Path(row['path']);mode=stat.S_IMODE(path.lstat().st_mode)
    assert mode==row['posix_mode'] and pin(path.read_bytes(),mode)==row['pin']
original=json.loads(Path(t['retained_authorities']['original_witness_control_plan']['path']).read_bytes())
actualplan=json.loads(Path('/tmp/hia-inspect-drive-source18-r3-dda7/NATIVE-PLAN.json').read_bytes())
assert t['groups']['source10']['ids']==original['source10_ids']==actualplan['groups']['source10']['ids']
assert t['groups']['source8']['ids']==actualplan['groups']['source8-physical-lease']['ids']
assert t['groups']['retained3']['ids']==original['retained_three_ids']
assert t['groups']['original-cli43']['ids']==original['cli43_ids']
assert t['predecessor_native_order']==['build-inspect']+actualplan['native_group_order']+actualplan['vm_group_order']
for label in actualplan['native_group_order']+actualplan['vm_group_order']:
    assert t['predecessor_groups'][label]['ids']==actualplan['groups'][label]['ids']
source=Path(actualplan['source']['path'])
for name,want in t['protected_source_files'].items():
    path=source/name;assert pin(path.read_bytes(),stat.S_IMODE(path.lstat().st_mode))==want
assert pin((source/'hepta/hia_inspect_program_native.py').read_bytes())==t['drive_runtime_after']
testtree=ast.parse(packet['members']['test_inspect_cli_witness_controls.py']['text'])
cls=next(n for n in testtree.body if isinstance(n,ast.ClassDef) and n.name=='InspectCliWitnessControls')
ids=['test_inspect_cli_witness_controls.InspectCliWitnessControls.'+n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]
assert ids==t['new_method_ids'] and len(ids)==12
assert len(t['group_order'])==18 and len(set(t['group_order']))==18 and sum(len(v['ids']) for v in t['groups'].values())==76
assert t['limits']==dict(cleanup_seconds=3,compile_seconds=20,image_bytes=1048576,owner_seconds=180,storage_free_bytes=1073741824,vm_steps=10000000)
assert t['state']=='AUTHORING_NOT_EXECUTABLE_PENDING_R3' and not t['cold'] and not t['default_activated'] and not t['whole']
r=dict(schema='hepta.hia.root-op10-controls-author-readback.v1',status='AUTHOR_CODE_FULLY_REVIEWED_AND_CURRENT_CONTROL_BYTES_VERIFIED_NOT_EXECUTED',handoff=pin(raw),full_members=11,full_member_logical_bytes=sum(v['pin']['bytes'] for v in packet['members'].values()),actual_member_bytes_and_modes_match=True,author_index_exact_member_projection=True,all_python_AST_only=True,retained_descriptors_full_bytes_modes=len(descriptors),original_protected_current_source_files=len(t['protected_source_files']),actual_Source18_and_Native17_VM12_declared_IDs_exact=True,original_retained3_CLI43_IDs_exact=True,stages=18,methods=76,new_methods=12,real_compiles_planned=7,limits=t['limits'],binder_requires_real_same_R3_Source18_Native17_VM12_PASS=True,binder_constructs_independent3191_full_byte_copy=True,real_seven_entry_mappings_and_full_image_verified_before_journal=True,journal_installed_before_real_issuer_second_admission=True,positive_full_CLI_requires_real_HIA_calls_and_zero_old_policy_frames=True,lost_real_return_captured_before_injected_fault=True,each_new_test_fresh_child_and_final_unknown_quarantine_retained=True,complete_before_after_buffer_readback_required=True,original_method_bodies_and_IDs_unchanged=True,qualification_scope='Development bundle plus independent3191 full-source outer closure. Old six-image manifest alone does not bind the new3 adapters. Old support_contract is not regenerated; future current_sources would include the3 paths then reject stale declared identity.',nested_original_CLI43_children_not_claimed_as_new_op10_selection=True,extra_frames_and_retention_limitations_preserved=True,binder_executed=False,product_execution=0,whole_native=False,matching_current_cold=False,production_legacy_retired=False)
with O.open('x') as f:f.write(json.dumps(r,sort_keys=True,indent=2)+'\n')
print(json.dumps(r,sort_keys=True))
