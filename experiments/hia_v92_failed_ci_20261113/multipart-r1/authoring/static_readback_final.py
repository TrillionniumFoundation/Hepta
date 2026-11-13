"""Independent textual/AST/pin checks only; no receiver or product execution."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import json

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / 'control'
REFERENCE = ROOT / 'reference'
checks = []

def require(value, label):
    if not value:
        raise AssertionError(label)
    checks.append(label)

def wire(x):
    return (json.dumps(x, sort_keys=True, indent=2) + '\n').encode()

def pin(path):
    b = path.read_bytes()
    return {'path': str(path), 'bytes': len(b), 'sha256': sha256(b).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest()}

def functions(path):
    raw = path.read_text()
    return {n.name: ast.get_source_segment(raw, n) for n in ast.parse(raw).body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))}

policy = json.loads((CONTROL / 'policy.json').read_bytes())
old_policy = json.loads((REFERENCE / 'policy.json').read_bytes())
for name, expected in policy['control_files'].items():
    actual = pin(CONTROL / name)
    require(all(actual[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob')), 'control_full_pin:' + name)
    ast.parse((CONTROL / name).read_bytes())
require(set(policy['control_files']) == {'controller.py', 'worker.py', 'diagnostics.py',
        'guardian.py', 'process_owner_impl.py', 'original_receiver.py'}, 'exact_six_controls')
for name in ('guardian.py', 'process_owner_impl.py', 'original_receiver.py'):
    require((CONTROL / name).read_bytes() == (REFERENCE / name).read_bytes(), 'original_whole_bytes:' + name)
for key in set(old_policy['limits']) - {'part_bytes'}:
    require(policy['limits'][key] == old_policy['limits'][key], 'old_limit_preserved:' + key)
require(policy['limits']['part_bytes'] == 256 << 20, 'raw_range_reduced_to_256MiB')
require(policy['parts'] == [
    {'ordinal': 0, 'offset': 0, 'bytes': 268435456, 'name': 'part-00.bin'},
    {'ordinal': 1, 'offset': 268435456, 'bytes': 268435456, 'name': 'part-01.bin'},
    {'ordinal': 2, 'offset': 536870912, 'bytes': 119491890, 'name': 'part-02.bin'}], 'exact_three_range_partition')
require(sum(x['bytes'] for x in policy['parts']) == policy['artifact']['bytes'] == 656362802,
        'whole_external_size_partition')
artifact = json.loads((REFERENCE / 'ARTIFACT-13994959899.metadata.json').read_bytes())
require(artifact['id'] == policy['artifact']['id'] and artifact['size_in_bytes'] == policy['artifact']['bytes']
        and artifact['digest'] == 'sha256:' + policy['artifact']['sha256']
        and artifact['workflow_run']['head_sha'] == policy['artifact']['checkout_commit']
        and artifact['workflow_run']['id'] == policy['artifact']['run_id'], 'actual_provider_pin_exact')
old_worker, new_worker = functions(REFERENCE / 'worker.py'), functions(CONTROL / 'worker.py')
network = ['NoRedirect', 'new_client', 'deadline_check', 'api_request', 'bounded_response',
           'metadata', 'official_location', 'storage_download']
for name in network:
    require(old_worker[name] == new_worker[name], 'network_full_original_body:' + name)
require(old_worker['split_original'] == new_worker['split_original'], 'complete_original_splitter_body_unchanged')
require(old_worker['load_helper'] == new_worker['load_helper'], 'original_helper_loader_unchanged')
old_control, new_control = functions(REFERENCE / 'controller.py'), functions(CONTROL / 'controller.py')
for name in ['Refusal','require','wire','identity','read','file_record','create','sync_dir','document',
             'run','expected_setup_identities','closed_guardian','natural_guardian','copy_original',
             'same_original_record','concat_parts','relocate_slice','typed_observation',
             'copy_unverified_range','final_input_records']:
    require(old_control[name] == new_control[name], 'controller_original_full_body:' + name)
for path in [CONTROL/'controller.py', CONTROL/'worker.py',CONTROL/'diagnostics.py',CONTROL/'render_workflow.py']:
    tree = ast.parse(path.read_bytes())
    require(not any(isinstance(n,(ast.Import,ast.ImportFrom)) and (
        (isinstance(n,ast.ImportFrom) and n.module and n.module.split('.')[0] in ('hepta','tools')) or
        (isinstance(n,ast.Import) and any(a.name.split('.')[0] in ('hepta','tools') for a in n.names)))
        for n in ast.walk(tree)), 'no_project_import:' + path.name)
diag = (CONTROL/'diagnostics.py').read_text()
require("PREFIX = 'hia-core-unpack-evidence/'" in diag and "name.endswith(('.json', '.jsonl', '.log'))" in diag,
        'fixed_step42_prefix_and_metadata_suffixes')
require('maximum_selected_files\': 1024' in diag and "'maximum_selected_bytes': 128 << 20" in diag,
        'whole_diagnostic_file_count_and_total_bound')
require("'expected_originals_all_present'" in diag and "'missing_expected'" in diag
        and "original_failure_reclassified': False" in diag, 'explicit_missing_and_old_failure_preserved')
parent_raw = json.loads((REFERENCE/'PARENT-COMMIT.raw.json').read_bytes())['structuredContent']['content']
parent = json.loads(parent_raw)
tree_raw = json.loads((REFERENCE/'PARENT-TREE.raw.json').read_bytes())['structuredContent']['content']
tree = json.loads(tree_raw)
require(parent['sha'] == '0504beb11c0dae875d8590660c42488b7bc634fb'
        and parent['tree']['sha'] == tree['sha'] == policy['artifact']['checkout_tree']
        and tree['truncated'] is False, 'exact_pure_parent_and_full_tree')
leaves = {row['path']:row for row in tree['tree'] if row['type'] != 'tree'}
require(len(leaves) == 4125, 'all4125_parent_leaves')
def tree_digest(mapping):
    nested = {}
    for name, row in mapping.items():
        current = nested
        parts = name.split('/')
        for part in parts[:-1]: current = current.setdefault(part,{})
        current[parts[-1]] = (row['mode'], row['sha'])
    def digest(directory):
        values = []
        for name,item in directory.items():
            if isinstance(item,dict): mode,oid,key='40000',digest(item),name+'/'
            else: mode,oid=item;key=name
            values.append((key.encode(), mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)))
        raw=b''.join(v for k,v in sorted(values))
        return sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return digest(nested)
require(tree_digest(leaves)==tree['sha'],'independent_full_parent_tree_SHA1')
for name,expected in policy['unchanged_original_workflows'].items():
    require(leaves[name]['sha']==expected['git_blob'] and leaves[name]['size']==expected['bytes'],
            'unchanged_parent_workflow:' + name)
for name,local in [('docs/HIA_SELFHOST_CORE_SUPPORT.json', REFERENCE/'HIA_SELFHOST_CORE_SUPPORT.json')]:
    actual=pin(local)
    require(leaves[name]['sha']==actual['git_blob'] and leaves[name]['size']==actual['bytes'],
            'current_source_provenance_raw:' + name)
require(policy['artifact']['checkout_commit']=='d96a5ae4783a123013351a511be9fc1a6d8f1c2c'
        and policy['source']['head']==policy['artifact']['checkout_commit']
        and policy['source']['tree']==tree['sha'], 'current_failed_CI_scope')
workflow=(CONTROL/'workflow-template.yml').read_text()
require(workflow.count('CONTROL_COMMIT_PLACEHOLDER')==4
        and workflow.count('POLICY_SHA256_PLACEHOLDER')==3
        and workflow.count('UPLOAD_STEPS_PENDING_ACTUAL_COUNT')==1,'exact_workflow_substitution_count')
require(workflow.index('hia-v92-failed-ci-step42-originals') < workflow.index('UPLOAD_STEPS_PENDING_ACTUAL_COUNT'),
        'small_originals_upload_precedes_three_ranges')
require('python-version: \'3.14.4\'' in workflow and 'timeout-minutes: 16' in workflow,
        'fixed_Python3144_original900_guardian_hosting')
require(workflow.count('HIA_CUSTODY_GITHUB_TOKEN: ${{ github.token }}')==1,
        'credential_only_owned_collection_step')
result={'schema':'hia.v92.failed-ci-recovery-static-readback.v1','status':'STATIC_CHECKS_PASS_UNEXECUTED',
        'checks':checks,'count':len(checks),'parent_commit':parent['sha'],'parent_tree':tree['sha'],
        'parent_leaves':len(leaves),'all_covered_controls':[pin(CONTROL/f) for f in policy['control_files']],
        'policy':pin(CONTROL/'policy.json'),'no_new_execution':True,
        'not_executed':['network','receiver','guardian','new_ZIP_inspector','product','CI'],
        'runtime_validation_remaining':'Peer/full static review and one separately authorized new read-only recovery execution. No historical product result upgraded.'}
path=ROOT/'STATIC-READBACK-FINAL.json'
with path.open('xb') as f:f.write(wire(result))
assert json.loads(path.read_bytes())==result
print(json.dumps({'status':result['status'],'checks':len(checks),'record':pin(path)},sort_keys=True))
