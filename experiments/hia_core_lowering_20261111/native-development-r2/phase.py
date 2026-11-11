"""Run one complete development-only Core caller group under its own original owner."""
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback
from development_common import (
    BASE_HEAD, BASE_SOURCE, BASE_TREE, CANDIDATE, CANDIDATE_TREE, LEAVES,
    OWNER, PREPARE_ROOT, PYTHON, ROOTS, binding, candidate_snapshot, digest,
    inspect_bundle, metadata, natural_owner, require, save, validate_group,
    verify_binding)

root = Path(sys.argv[1]).resolve(strict=True)
request = json.loads((root / 'request.json').read_bytes())
group = request['phase']
source = PREPARE_ROOT / 'source'
started = time.monotonic()
report = {
    'schema': 'hia.core-lowering-owned-development-phase.v1', 'status': 'STARTED',
    'scope': 'EXPLICIT_DEVELOPMENT_GROUP_ONLY', 'group': group,
    'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
    'actual_checkout_HEAD': BASE_HEAD, 'actual_HEAD_is_candidate': False,
    'default_complete_qualifier_executed': False, 'default_180_second_qualification_pass': False,
    'matching_current_cold': False, 'complete_three_group_qualification_claimed': False,
    'owner_seconds': 180, 'ordinary_caller_budgets_unchanged': True,
    'python': sys.version, 'executable': sys.executable,
}
source_before = base_before = None
inputs_before = controls_before = []
try:
    require(group in {'component', 'original-machine', 'original-core'}
            and root == ROOTS[group], 'fixed development group root differs')
    require(request['candidate_commit'] == CANDIDATE
            and request['candidate_tree'] == CANDIDATE_TREE
            and request['candidate_leaf_count'] == LEAVES, 'frozen product differs')
    require(digest(Path(sys.executable).resolve().read_bytes()) == PYTHON,
            'actual interpreter binary differs')
    report['python_binary_sha256'] = PYTHON
    controls_before = [binding(root / name) for name in (
        'development_common.py', 'worker.py', 'request.json', 'source-files.json',
        'launch-payload.original.json')]
    require(request['preparation_root'] == str(PREPARE_ROOT)
            and request['preparation_job_id'], 'actual preparation job is required')
    pins = request['input_bindings']
    require(type(pins) is list and pins and len({p['path'] for p in pins}) == len(pins),
            'complete preparation input bindings required')
    by_path = {}
    for pin in pins:
        raw = verify_binding(pin)
        require(PREPARE_ROOT in Path(pin['path']).parents, 'input escaped the new preparation root')
        by_path[pin['path']] = raw
    inputs_before = pins
    def prior(name):
        path = str(PREPARE_ROOT / name)
        require(path in by_path, 'required preparation receipt absent: ' + name)
        return json.loads(by_path[path])
    prepared = prior('report.json')
    controlled = prior('control.json')
    life = prior('lifecycle.json')
    require(prepared['status'] == 'EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED'
            and prepared['scope'] == 'EXPLICIT_DEVELOPMENT_ONLY'
            and prepared['candidate_commit'] == CANDIDATE
            and prepared['candidate_tree'] == CANDIDATE_TREE
            and prepared['candidate_stable'] is True
            and prepared['matching_current_cold'] is False
            and len(prepared['native_compiles']) == 32,
            'preparation did not build the exact complete development candidate')
    require(controlled['status'] == 'PASS' and controlled['phase'] == 'prepare'
            and controlled['natural_owner_cleanup'] is True
            and controlled['natural_owner_success'] is True
            and controlled['inner_report_sha256'] == digest(by_path[str(PREPARE_ROOT / 'report.json')])
            and controlled['lifecycle']['supervisor_returncode'] == 0
            and controlled['lifecycle']['receipt_sha256'] == digest(by_path[str(PREPARE_ROOT / 'lifecycle.json')])
            and set(controlled['lifecycle']) == set(life) | {'supervisor_returncode', 'receipt_sha256'}
            and {k: v for k, v in controlled['lifecycle'].items()
                 if k not in {'supervisor_returncode', 'receipt_sha256'}} == life
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and natural_owner(life) and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('returncode') == 0, 'preparation owner did not complete naturally')
    expected_inputs = {
        str(PREPARE_ROOT / 'report.json'), str(PREPARE_ROOT / 'control.json'),
        str(PREPARE_ROOT / 'lifecycle.json'), prepared['candidate_after']['path'],
        *[r['path'] for r in prepared['build_inputs']]}
    require(set(by_path) == expected_inputs, 'frozen preparation file population differs')
    for row in [prepared['candidate_after'], *prepared['build_inputs']]:
        require(next(p for p in pins if p['path'] == row['path']) == row,
                'actual preparation build input identity differs')
    require(prepared['source_path'] == str(source), 'prepared source root differs')
    base_before = metadata(BASE_SOURCE, BASE_TREE)
    require(base_before['head'] == BASE_HEAD and not base_before['tracked_status']
            and base_before['owner_sha256'] == OWNER, 'original base metadata differs')
    source_before = candidate_snapshot(source)
    original_source = json.loads(by_path[prepared['candidate_after']['path']])
    require(source_before == original_source, 'complete current source differs from actual preparation')
    report['source_before'] = save(root, 'source-before.json', source_before)
    manifest = Path(prepared['manifest'])
    require(manifest == PREPARE_ROOT / 'bundle/manifest.json', 'prepared bundle path differs')
    original_bundle = inspect_bundle(manifest, source)
    require(original_bundle == prepared['bundle_observation'], 'prepared complete bundle changed')
    report['original_bundle'] = original_bundle
    report['preparation_job_id'] = request['preparation_job_id']
    report['preparation_report_sha256'] = digest(by_path[str(PREPARE_ROOT / 'report.json')])
    argv = [sys.executable, '-B', str(source / 'tools/qualify_hia_core_lowering_callers.py'),
            '--development-manifest', str(manifest), '--development-group', group,
            '--evidence', str(root / 'qualifier')]
    report['command'] = argv
    at = time.monotonic()
    with (root / 'qualifier.stdout').open('xb') as out, (root / 'qualifier.stderr').open('xb') as err:
        result = subprocess.run(argv, cwd=source, stdout=out, stderr=err, timeout=180)
    report['qualifier_returncode'] = result.returncode
    report['qualifier_seconds'] = time.monotonic() - at
    observed_path = root / 'qualifier/report.json'
    report['qualifier_report'] = binding(observed_path)
    observed = json.loads(observed_path.read_bytes())
    report['qualifier_status'] = observed.get('status')
    require(result.returncode == 0, 'complete development group process failed')
    report['validation'] = validate_group(observed, group, request['group'], source, original_bundle)
    report['status'] = 'EXPLICIT_DEVELOPMENT_GROUP_PASS_NOT_COMPLETE_QUALIFICATION'
except BaseException:
    report['status'] = 'HOLD'
    report['exception'] = traceback.format_exc()
finally:
    try:
        if source_before is not None:
            after = candidate_snapshot(source)
            report['source_after'] = save(root, 'source-after.json', after)
            report['source_stable'] = after == source_before
            require(report['source_stable'], 'complete candidate source changed during the group')
        if base_before is not None:
            report['original_base_after'] = metadata(BASE_SOURCE, BASE_TREE)
            require(report['original_base_after'] == base_before, 'original base metadata changed')
        report['input_bindings_after'] = [binding(Path(p['path'])) for p in inputs_before]
        report['inputs_stable'] = report['input_bindings_after'] == inputs_before
        require(report['inputs_stable'], 'preparation inputs changed during the group')
        report['control_bindings_after'] = [binding(Path(p['path'])) for p in controls_before]
        require(report['control_bindings_after'] == controls_before, 'frozen group controller changed')
        for name in ('qualifier.stdout', 'qualifier.stderr', 'qualifier/report.json'):
            path = root / name
            if path.is_file():
                report.setdefault('retained_outputs', []).append(binding(path))
    except BaseException:
        report['status'] = 'HOLD'
        report['final_identity_error'] = traceback.format_exc()
    report['seconds'] = time.monotonic() - started
    save(root, 'report.json', report)
    print(json.dumps({k: report.get(k) for k in (
        'schema', 'scope', 'status', 'group', 'seconds', 'source_stable', 'inputs_stable',
        'qualifier_returncode', 'exception', 'final_identity_error')}, sort_keys=True), flush=True)
raise SystemExit(0 if report['status'] == 'EXPLICIT_DEVELOPMENT_GROUP_PASS_NOT_COMPLETE_QUALIFICATION' else 1)
