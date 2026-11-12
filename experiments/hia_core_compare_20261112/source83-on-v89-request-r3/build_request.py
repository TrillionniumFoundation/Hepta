"""Build request metadata only; never invokes a generator, VM, owner or test."""
from pathlib import Path
import ast, difflib, hashlib, importlib.util, json, os, shutil, stat, sys
root=Path(__file__).resolve().parent
oldroot=root.parent/'core-numeric-source83-on-v89-r2'
base=json.loads((oldroot/'REQUEST.json').read_text())
module_ast=ast.parse((root/'control/child.py').read_bytes())
process_policy=ast.literal_eval(next(n.value for n in module_ast.body
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NEGATIVE_PROCESS_POLICY' for t in n.targets)))
spec=importlib.util.spec_from_file_location('r3_source_metadata_only',root/'control/common.py')
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
source=root/'source'
rows=common.snapshot(source)
additions=json.loads((root/'FIXTURE-ADDITIONS.json').read_text())['added']
expected=sorted(base['source_files']+additions,key=lambda x:x['relative_path'])
assert common.content(rows)==expected and len(rows)==1658
assert sum(r['size'] for r in rows)==40254784
request=dict(base)
removed=request.pop('native_and_compiler_and_subprocess_entry_poison_required_in_each_source_child')
assert removed is True
request.update(
 revision='source83-on-v89-r3-exact-four-negative-python-permissions',
 source_root=str(source),evidence_root=str(root/'unexecuted-local-template-only'),
 runtime=common.pin(Path(sys.executable).resolve(strict=True)),
 process_owner=common.pin(source/'tools/hia_selfhost_process_owner.py'),
 control_inputs=[common.pin(p) for p in sorted((root/'control').glob('*.py'))],
 source_files=common.content(rows),physical_source_count=1658,physical_source_bytes=40254784,
 native_and_compiler_entry_poison_required_in_each_source_child=True,
 all_other_subprocess_entry_poison_required_in_each_source_child=True,
 source_child_process_policy=process_policy,
 allowed_negative_processes_expected=4,zero_process_scope_claimed=False,
 original_fixture_closure_additions=additions)
assert len(request['control_inputs'])==4
for key in ('expected_ids','test_classes','generator_names','derivations','class_denominators',
 'qualification_seconds','cleanup_seconds','minimum_available_bytes','minimum_available_inodes',
 'base_commit','base_tree','base_full_leaf_count','virtual_source_tree_before_derivation',
 'allowed_derived_changes'):
 assert request[key]==base[key],key
for name in ('common.py',):
 assert (root/'control'/name).read_bytes()==(oldroot/'control'/name).read_bytes()
common.save(root/'REQUEST.json',request)
diffs={}
for name in ('child.py','worker.py','launch.py'):
 before=(oldroot/'control'/name).read_text().splitlines(keepends=True)
 after=(root/'control'/name).read_text().splitlines(keepends=True)
 diff=''.join(difflib.unified_diff(before,after,fromfile='r2/control/'+name,tofile='r3/control/'+name))
 (root/(name+'.diff')).write_text(diff);diffs[name]=len(diff.encode())
ledger={'schema':'hepta.source83-r3-negative-command-control-change.v1',
 'status':'FROZEN_UNEXECUTED','preserved_failed_run':43272140755,
 'failed_originals_commit':'5af9ae52de56d257f2c80f91e14b4cb24cecf7be',
 'pure_product_before_derivation':'545e7814b97bc767a15810dd99534aaccc23adf4',
 'pure_product_tree':'4e59cae3f3c498980bb347694be78043e8115e3f',
 'product_bytes_changed_since_C':[],
 'old_request_unconditional_poison_flag_removed':
  'native_and_compiler_and_subprocess_entry_poison_required_in_each_source_child',
 'native_and_compiler_entries_always_poisoned':True,
 'all_other_subprocess_entries_poisoned':True,
 'explicit_exception_policy':process_policy,
 'all_eighty_three_product_test_method_bodies_unchanged':True,
 'all_sixty_two_generators_and_four_plus_four_derivations_unchanged':True,
 'frozen_scope':'Four original real Python negative-admission commands, not zero-process.',
 'original_run_Popen_communicate_and_exit_implementations_delegated_without_result_mocking':True,
 'failed_or_timed_out_permission_never_retried':True,
 'failure_recording_does_not_replace_original_exception':True,
 'common_control_unchanged':True,
 'fixture_additions':additions,'physical_source_count':1658,'physical_source_bytes':40254784,
 'qualification_seconds':180,'cleanup_seconds':3,'original_negative_command_timeout_seconds':10,
 'changed_control_diffs':diffs,'source_or_native_or_real_negative_command_execution_performed':False}
common.save(root/'CONTROL-CHANGES.json',ledger)
pins=[]
for relative in ['REQUEST.json','BASE-GIT-TREE.json','SOURCE-DELTA.json',
                 'FIXTURE-GIT-LEAVES.json','FIXTURE-ADDITIONS.json','CONTROL-CHANGES.json',
                 'control/child.py','control/common.py','control/worker.py','control/launch.py',
                 'child.py.diff','worker.py.diff','launch.py.diff',
                 'independent_negative_reader.py','negative_admission_fragment.py','build_child.py',
                 'refine_controls.py','build_request.py']:
 p=root/relative
 pins.append({'relative_path':relative,**common.pin(p)})
common.save(root/'INPUTS.json',pins)
print(json.dumps({'status':'FROZEN_UNEXECUTED','source_files':len(rows),
 'source_bytes':sum(r['size'] for r in rows),'request':common.pin(root/'REQUEST.json'),
 'control_sizes':{Path(r['path']).name:r['size'] for r in request['control_inputs']},
 'product_source_changes':0,'added_fixtures':5,'expected_source_methods':83}))

