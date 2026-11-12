"""Create the v89 full32 supply-owner revision. No workflow or child is run."""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import os

ROOT = Path(__file__).resolve().parent
CAPSULE = ROOT / 'capsule'
PROOF = CAPSULE / 'apt-ownership-r4'
SOURCE = Path('/tmp/hia-full32-privileged-apt-owner-source-io-r2-20261112-e26e')
ACTUAL = Path('/tmp/hia-apt-owner-source-io-r2-actual-readback-20261112-e26e')
PREFIX = 'experiments/hia_v89_full_retained_capsule_20261112/r1'
BRANCH = 'codex/hia-v89-full-retained-run-r4-20261112-e26e'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    assert path.read_bytes() == raw


def main():
    assert not PROOF.exists()
    expected = json.loads(Path('/tmp/hia-full32-r3-capsule-expected-files.json').read_bytes())
    old = {}
    for row in expected:
        path = CAPSULE / row['path']
        raw = path.read_bytes()
        assert len(raw) == row['bytes'] and pin(raw)['git_blob_sha1'] == row['sha'], row['path']
        old[row['path']] = raw
    assert len(old) == 67
    old_policy = json.loads(old['plan/policy.json'])
    policy = json.loads(old['plan/policy.json'])
    replacements = {
        'control/supply_v87.py': (SOURCE / 'candidate/supply_v87.py').read_bytes(),
        'plan/supply-plan.json': (SOURCE / 'candidate/supply-plan.json').read_bytes()}
    for path, raw in replacements.items():
        put(PROOF / 'previous-active' / path, old[path])
        target = CAPSULE / path
        assert target.read_bytes() == old[path]
        with target.open('wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        assert target.read_bytes() == raw
        name = Path(path).name
        policy['control_files'][name] = {'path': path, **pin(raw)}
    policy['intended_branch'] = BRANCH
    policy['pending'] = [
        'R4 privileged APT ownership is a new unexecuted supply request. The original R3 full32 run 43283027193 failed after apt-install when the original workflow helper observed EPERM; its original HOLD and incomplete qualification remain unchanged.',
        'The exact 22 source/ordinary-IO controls passed once under the original 180/3 owner and are archived at 2a1b42edc3d2c24bbc8f56718bbc4d19aa470b32. Root UID/event positives in those finite controls are synthetic; actual privileged APT ownership is not yet proved.',
        'The product checkout remains the original v89 standard-CI head 784f088fcc5ad81c65de541d54e26d380c86293c and tree d9e8407c70e44a3ea0152b8b4c5eb2ed3833d790. This request makes no claim about v90/v91 or integer integration.']
    put(PROOF / 'previous-active/plan/policy.json', old['plan/policy.json'])
    new_policy_raw = wire(policy)
    with (CAPSULE / 'plan/policy.json').open('wb') as stream:
        stream.write(new_policy_raw); stream.flush(); os.fsync(stream.fileno())
    assert (CAPSULE / 'plan/policy.json').read_bytes() == new_policy_raw
    assert policy['source'] == old_policy['source'] and policy['standard_ci'] == old_policy['standard_ci']
    assert policy['mandatory_gate_keys'] == old_policy['mandatory_gate_keys'] and len(policy['mandatory_gate_keys']) == 32
    assert policy['limits'] == old_policy['limits'] and policy['packages'] == old_policy['packages']
    assert policy['source']['pure_source_commit'] == 'e4fc00a775dab323758d77a2ef4918fd35585cdc'
    assert policy['source']['commit'] == '784f088fcc5ad81c65de541d54e26d380c86293c'
    assert policy['source']['tree'] == 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790'
    assert policy['source']['regular_leaves'] == 4076
    supply = json.loads(replacements['plan/supply-plan.json'])
    assert supply['source'] == {'head': policy['source']['commit'], 'tree': policy['source']['tree']}
    assert supply['supply_seconds'] == policy['limits']['supply_seconds'] == 3600
    assert supply['outer_seconds'] == policy['limits']['controller_seconds'] == 10800
    assert supply['control'] == {key: pin(replacements['control/supply_v87.py'])[key] for key in ('bytes','sha256')}
    controls = {}
    for name, item in policy['control_files'].items():
        raw = (CAPSULE / item['path']).read_bytes()
        assert pin(raw) == {key: item[key] for key in ('bytes','sha256','git_blob_sha1')}, name
        if item['path'].endswith('.py'):
            ast.parse(raw, filename=item['path'])
        controls[name] = item
    assert len(controls) == 15
    for name, item in supply['privileged_apt_owner'].items():
        if name in ('guardian', 'implementation'):
            source = (CAPSULE / policy['control_files'][item['path']]['path']).read_bytes()
            assert all(pin(source)[k] == item[k] for k in ('bytes','sha256'))
    prior = [policy['standard_ci']['run_record'], *policy['standard_ci']['job_records'], *policy['prior_evidence'].values()]
    for item in prior:
        assert all(pin((CAPSULE / item['path']).read_bytes())[k] == item[k] for k in ('bytes','sha256'))
    assert json.loads((CAPSULE / policy['standard_ci']['run_record']['path']).read_bytes())['head_sha'] == policy['source']['commit']
    actual_plan = json.loads(Path('/tmp/hia-apt-owner-source-io-r2-actual-publication-plan.json').read_bytes())
    actual_copied = []
    for row in actual_plan['files']:
        raw = (ACTUAL / row['path']).read_bytes()
        assert all(pin(raw)[key] == row[key] for key in ('bytes','sha256')) and pin(raw)['git_blob_sha1'] == row['git_blob']
        put(PROOF / 'source-io-actual' / row['path'], raw)
        actual_copied.append({'path': 'source-io-actual/' + row['path'], **pin(raw)})
    for name in ('SOURCE-IO-REQUEST.json', 'SOURCE-IO-R2-CORRECTION.json', 'SOURCE-IO-R2-STATIC-REVIEW.json', 'SOURCE-IO-R2.diff'):
        put(PROOF / 'source-io-request' / name, (SOURCE / name).read_bytes())
    template = old['custody-r3/workflow-r3.template.yml'].decode()
    old_policy_sha = pin(old['plan/policy.json'])['sha256']
    assert template.count('__R3_CONTROL_COMMIT__') == 5 and template.count(old_policy_sha) == 4
    assert template.count(old_policy['intended_branch']) == 1
    new_template = template.replace('__R3_CONTROL_COMMIT__', '__R4_CONTROL_COMMIT__').replace(
        old_policy_sha, pin(new_policy_raw)['sha256']).replace(old_policy['intended_branch'], BRANCH)
    assert new_template.replace('__R4_CONTROL_COMMIT__','__R3_CONTROL_COMMIT__').replace(
        pin(new_policy_raw)['sha256'],old_policy_sha).replace(BRANCH,old_policy['intended_branch']) == template
    put(PROOF / 'workflow-r4.template.yml', new_template.encode())
    diff = ''.join(''.join(difflib.unified_diff(old[name].decode().splitlines(True),
        (CAPSULE / name).read_text().splitlines(True), fromfile='r3/' + name, tofile='r4/' + name))
        for name in ('control/supply_v87.py','plan/supply-plan.json','plan/policy.json'))
    put(PROOF / 'R3-TO-R4.diff', diff.encode())
    unchanged = [name for name in old if name not in ('control/supply_v87.py','plan/supply-plan.json','plan/policy.json')]
    assert len(unchanged) == 64 and all((CAPSULE / name).read_bytes() == old[name] for name in unchanged)
    request_sha = pin((SOURCE / 'SOURCE-IO-REQUEST.json').read_bytes())['sha256']
    context = {'schema': 'hia.v89.full32.apt-owner-r4-context.v1', 'status': 'FROZEN_FOR_ROOT_REVIEW_UNEXECUTED',
        'prior_A': '7b184c92396cb2afcfd9667c9e520831cb3cd98d', 'prior_tree': 'e47bfa6e0da6f1eaa859a42117c3dc44c9eb3d90',
        'pure_parent': policy['source']['pure_source_commit'], 'source': policy['source'],
        'branch': BRANCH, 'prefix': PREFIX, 'old_capsule_files': 67, 'old_complete_files_unchanged': 64,
        'changed_active_files': {name: {'before': pin(old[name]), 'after': pin((CAPSULE / name).read_bytes())}
                                 for name in ('control/supply_v87.py','plan/supply-plan.json','plan/policy.json')},
        'only_executable_algorithm_change': 'The two fixed APT commands enter the unchanged external guardian under actual root, then require bound ECHILD before handing back six original files. Existing outer helper and product owners are unchanged.',
        'source_io_request_commit': '073abcfa888286f08384ca31c03d637630ee69b1', 'source_io_request_sha256': request_sha,
        'source_io_actual_commit': '2a1b42edc3d2c24bbc8f56718bbc4d19aa470b32',
        'source_io_actual_tree': '637d3ff2da612471ab7f5638793228b80215164c',
        'source_io_actual_scope': '22 source/ordinary IO methods; natural 180/3 ECHILD; root process positives synthetic; no privileged APT proof',
        'source_io_actual_files': actual_copied, 'unchanged_active_controls': [n for n in controls if n not in ('supply_v87.py','supply-plan.json')],
        'active_controls': controls, 'original_32_gate_keys': policy['mandatory_gate_keys'], 'limits': policy['limits'],
        'APT_owner_supply_suballocation': {'update_outer': 600, 'update_inner_max': 590, 'install_outer': 900,
            'install_inner_max': 890, 'inner_cleanup': 3, 'cache_owner_original_separate': 180,
            'remaining_supply_time_still_limits_each_step': True, 'original_run_owned_180_hard_gate_changed': False},
        'original_partial_custody_reader_unchanged': True, 'original_workflow_process_EPERM_not_swallowed': True,
        'same_v89_standard_CI_records_unchanged': True, 'v90_v91_or_integer_qualification_claimed': False,
        'old_full32_r3_failure_not_reclassified': True, 'old_a548_HOME_request_not_executed': True,
        'old_capsule_manifest_and_prior_contexts_are_historical': True,
        'current_authoritative_policy': 'plan/policy.json', 'full32_or_APT_executed_for_this_revision': False,
        'no_request_dispatched': True, 'no_branch_created': True, 'root_review_required_before_unique_trigger': True,
        'workflow_inverse_exact': {'A_placeholders': 5, 'policy_SHA_occurrences': 4, 'branch_occurrences': 1}}
    put(PROOF / 'CONTEXT.json', wire(context))
    put(PROOF / 'prepare_r4.py', Path(__file__).read_bytes())
    all_rows = [{'path': p.relative_to(CAPSULE).as_posix(), **pin(p.read_bytes())}
                for p in sorted(CAPSULE.rglob('*')) if p.is_file()]
    put(ROOT / 'CANDIDATE-FILES.json', wire({'schema':'hia.v89.full32.apt-owner-r4-candidate-files.v1',
        'prefix':PREFIX, 'files':all_rows, 'new_policy':pin(new_policy_raw), 'pure_parent':context['pure_parent'],
        'source':policy['source'], 'branch':BRANCH, 'old_67_complete_verified':True,
        'actual_full32_unexecuted':True, 'expected_workflow':'.github/workflows/hia-v89-full-retained-r4.yml'}))
    print(json.dumps({'files':len(all_rows),'bytes':sum(row['bytes'] for row in all_rows),'policy':pin(new_policy_raw),
        'changed':list(context['changed_active_files']),'unchanged':len(unchanged),'scope':'STATIC_UNEXECUTED'},sort_keys=True))


if __name__ == '__main__':
    main()
