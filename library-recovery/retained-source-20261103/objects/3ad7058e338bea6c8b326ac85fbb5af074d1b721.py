"""Losslessly package already-terminal Agent calibration; never invoke a model."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import time

ROOT = Path('/workspace/scratch/220b9d034358/Hepta-agent')
OUT = ROOT / 'experiments/hia_agent_factorial_v4_20261028'
BASE = Path('/tmp')
SOURCE_COMMIT = '68cbd79ac61224a08be1f3ec2f3026ef0881745e'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text())


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


sources = {
    'controls': BASE / 'hepta-agent-v4-controls-01',
    'hostile': BASE / 'hepta-agent-v4-hostile-01',
    'capacity': BASE / 'hepta-agent-v4-capacity-01',
    'calibration-qwen1_5b': BASE / 'hepta-agent-v4-calibration-qwen1_5b-01',
    'calibration-qwen7b': BASE / 'hepta-agent-v4-calibration-qwen7b-01',
}
calibrations = []
for model, destination in [('qwen1_5b', 'CALIBRATION_QWEN1_5B_RESULT.json'),
                           ('qwen7b', 'CALIBRATION_QWEN7B_RESULT.json')]:
    folder = sources['calibration-' + model]
    result = read(folder / 'RESULT.json')
    plan = read(folder / 'PLAN.json')
    assert plan['source_commit'] == SOURCE_COMMIT
    assert plan['performance_timing_qualified'] is False
    assert result['valid_observation'] and result['source_unchanged'] and result['tools_unchanged'] and result['model_unchanged']
    assert result['status'] == 'all_cells_attempted'
    assert not result['calibration_eligible'] and not any(c['correct'] for c in result['cells'])
    assert len(result['cells']) == 3 and result['requests'] == 3
    assert all(e['exited'] and e['identity']['model_unchanged'] and e['identity']['runtime_unchanged'] for e in result['engines'])
    for name, expected in plan['source_bindings'].items():
        assert digest((folder / 'source_snapshot' / name).read_bytes()) == expected
    shutil.copyfile(folder / 'RESULT.json', OUT / destination)
    transports = sorted(folder.glob('engine-*/transport-*.request.json'))
    assert len(transports) == result['requests']
    request_inputs = []
    for p in transports:
        req = read(p)
        ids = req['payload']['prompt']
        assert isinstance(ids, list) and all(isinstance(i, int) for i in ids)
        request_inputs.append({'file': 'calibration-' + model + '/' + str(p.relative_to(folder)),
                               'sha256': digest(p.read_bytes()), 'input_tokens': len(ids)})
    startup_ns = sum(read(p)['wall_ns'] for p in folder.glob('engine-*/STARTUP.json'))
    all_attempts = [a for c in result['cells'] for a in c['attempts']]
    input_tokens = sum(r['input_tokens'] for r in request_inputs)
    known_output_tokens = sum(a['usage']['output_tokens'] for a in all_attempts if a['usage'] is not None)
    unknown_output_requests = sum(a['usage'] is None for a in all_attempts)
    calibrations.append({
        'model_id': result['model']['id'], 'source_commit': SOURCE_COMMIT,
        'result_file': destination, 'result_sha256': digest((folder / 'RESULT.json').read_bytes()),
        'plan_sha256': digest((folder / 'PLAN.json').read_bytes()),
        'valid_observation': result['valid_observation'], 'calibration_eligible': False,
        'correct': 0, 'planned_tasks': 3, 'attempted_tasks': 3,
        'requests': result['requests'], 'complete_responses': result['responses'],
        'statuses': {c['id']: c['status'] for c in result['cells']},
        'input_token_method': 'Sum lengths of payload.prompt integer token ID arrays from every actual transport request, including timeout.',
        'input_requests': request_inputs, 'known_input_tokens_all_requests': input_tokens,
        'original_result_known_input_tokens': result['known_input_tokens'],
        'known_output_tokens_complete_responses': known_output_tokens,
        'unknown_output_requests': unknown_output_requests,
        'complete_token_usage': unknown_output_requests == 0,
        'accounted_token_subtotal': input_tokens + known_output_tokens,
        'total_tokens': None if unknown_output_requests else input_tokens + known_output_tokens,
        'request_wall_ns': sum(a['request_wall_ns'] for a in all_attempts),
        'candidate_validation_wall_ns': sum(a.get('validation_wall_ns', 0) for a in all_attempts),
        'engine_startup_wall_ns': startup_ns,
        'engine_shutdown_wall_ns': sum(e['shutdown_ns'] for e in result['engines']),
        'experiment_wall_ns': result['experiment_wall_ns'],
        'performance_timing_qualified': False,
        'human_repairs': 0, 'retries': 0,
        'no_model_result_was_rescored': True,
    })

controls = read(sources['controls'] / 'CONTROLS.json')
hostile = read(sources['hostile'] / 'HOSTILE.json')
assert controls['passed'] == controls['count'] == 35
assert hostile['passed'] == hostile['count'] == 4
assert digest((sources['controls'] / 'CONTROLS.json').read_bytes()) == read(OUT / 'DEVELOPMENT_CONTROLS.json')['raw_controls_sha256']
hostile_rows = []
for r in hostile['rows']:
    observed = r['execution']
    assert observed['native_executed'] and observed['status'] != 'correct'
    numerical = [row[:2] for row in observed['observations']] == observed['expected']
    assert numerical
    hostile_rows.append({'id': r['id'], 'passed': r['passed'], 'model_answer': False,
                         'native_executed': observed['native_executed'],
                         'numeric_outputs_match_expected': numerical,
                         'execution_status': observed['status'],
                         'resource_contract_passed': observed['resource_contract_passed'],
                         'vm_contract_passed': observed['vm_contract_passed']})
save(OUT / 'DEVELOPMENT_HOSTILE.json', {
    'schema': 'hepta.agent.factorial.hostile-summary.v1',
    'count': 4, 'passed': 4, 'model_requests': 0,
    'raw_archive_path': 'hostile/HOSTILE.json',
    'raw_sha256': digest((sources['hostile'] / 'HOSTILE.json').read_bytes()),
    'scope': 'Correct numeric outputs alone must not pass a wrong provider-call or peak-live-owner contract.',
    'rows': hostile_rows,
})
shutil.copyfile(sources['capacity'] / 'CAPACITY.json', OUT / 'TOKENIZER_CAPACITY.json')

receipts = sorted((BASE / 'hepta-agent-v4-acquisition').glob('*.json'))
receipt_records = [{'filename': p.name, 'sha256': digest(p.read_bytes()), 'receipt': read(p)} for p in receipts]
save(OUT / 'ACQUISITION.json', {
    'schema': 'hepta.agent.factorial.acquisition.v1', 'model_requests': 0,
    'receipts': receipt_records,
    'sum_recorded_attempt_wall_ns': sum(r['receipt']['wall_ns'] for r in receipt_records),
    'notes': ['Includes the initial denied network attempts, not only successful downloads.',
              'Model weights and upstream runtime binaries are not stored in the evidence archive.',
              'Publisher URLs, revisions, sizes and SHA-256 are recorded in receipts and protocol.'],
})

entries = []
for label, folder in sources.items():
    for p in sorted(folder.rglob('*')):
        if p.is_file():
            assert not p.is_symlink()
            entries.append((label + '/' + str(p.relative_to(folder)), p))
entries += [('acquisition/' + p.name, p) for p in receipts]
entries.append(('provenance/package_evidence.py', Path(__file__)))
manifest_entries = []
archive = OUT / 'raw-evidence.tar.xz'
before = time.monotonic_ns()
with tarfile.open(archive, 'w:xz', preset=1, format=tarfile.USTAR_FORMAT) as tar:
    for name, p in entries:
        data = p.read_bytes()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o755 if p.stat().st_mode & 0o111 else 0o644
        info.mtime = 0
        tar.addfile(info, io.BytesIO(data))
        manifest_entries.append({'path': name, 'original_path': str(p), 'bytes': len(data), 'sha256': digest(data)})
with tarfile.open(archive, 'r:xz') as tar:
    actual_names = tar.getnames()
    assert len(actual_names) == len(set(actual_names)) == len(manifest_entries)
    assert set(actual_names) == {e['path'] for e in manifest_entries}
    for entry in manifest_entries:
        data = tar.extractfile(entry['path']).read()
        assert len(data) == entry['bytes'] and digest(data) == entry['sha256']
manifest = {
    'schema': 'hepta.agent.factorial.raw-evidence.v1',
    'archive': archive.name, 'archive_bytes': archive.stat().st_size,
    'archive_sha256': digest(archive.read_bytes()),
    'file_count': len(manifest_entries), 'uncompressed_file_bytes': sum(e['bytes'] for e in manifest_entries),
    'all_member_bytes_verified': True, 'package_and_verify_wall_ns': time.monotonic_ns() - before,
    'original_path_mapping': {label: str(folder) for label, folder in sources.items()},
    'stored_native_candidates_are_evidence_not_model_weights': True,
    'entries': manifest_entries,
}
save(OUT / 'EVIDENCE_MANIFEST.json', manifest)

amendment = read(OUT / 'PROTOCOL_AMENDMENT.json')
assert amendment['main_completions_started'] == 0
assert amendment['original_protocol_sha256'] == digest((OUT / 'PROTOCOL.json').read_bytes())
stopped = {
    'schema': 'hepta.agent.factorial.stopped.v1',
    'status': 'baseline_capability_unqualified_main_not_run',
    'reason': 'The user requires adequate baseline model capability before comparison. Neither frozen model passed the original 3/3 first-response gate.',
    'source_commit_for_all_calibration_inference': SOURCE_COMMIT,
    'no_claim_that_later_integrated_source_was_executed_in_calibration': True,
    'original_protocol_sha256': amendment['original_protocol_sha256'],
    'amendment_sha256': digest((OUT / 'PROTOCOL_AMENDMENT.json').read_bytes()),
    'amendment_created_utc': amendment['created_utc'],
    'original_protocol_and_observations_preserved': True,
    'qualification_complete': False,
    'baseline_qualified_models': [], 'selected_main_model': None,
    'main': {'planned_cells': 16, 'attempted_cells': 0, 'requests': 0, 'responses': 0,
             'correct': None, 'comparative_advantage_evaluated': False,
             'complete_costed_coverage': False, 'descriptive_advantage_gate': False,
             'general_agent_productivity_proved': False, 'main_evidence_directory': None},
    'calibrations': calibrations,
    'calibration_totals': {
        'requests': sum(c['requests'] for c in calibrations),
        'complete_responses': sum(c['complete_responses'] for c in calibrations),
        'planned_tasks': 6, 'attempted_tasks': 6, 'correct': 0,
        'known_input_tokens_all_requests': sum(c['known_input_tokens_all_requests'] for c in calibrations),
        'known_output_tokens_complete_responses': sum(c['known_output_tokens_complete_responses'] for c in calibrations),
        'unknown_output_requests': sum(c['unknown_output_requests'] for c in calibrations),
        'accounted_token_subtotal': sum(c['accounted_token_subtotal'] for c in calibrations),
        'total_tokens': None,
        'experiment_wall_ns': sum(c['experiment_wall_ns'] for c in calibrations),
        'performance_timing_qualified': False,
        'human_repairs': 0, 'retries': 0,
    },
    'controls': {'native_reference_and_partial_repair_checks': 35,
                 'native_reference_and_partial_repair_checks_passed': 35,
                 'hostile_numeric_correct_contract_wrong_checks': 4,
                 'hostile_numeric_correct_contract_wrong_checks_passed': 4,
                 'controls_are_model_answers': False, 'model_requests': 0},
    'other_measured_costs': {
        'controls_build_ns': sum(r['build']['build_ns'] for r in controls['rows']),
        'controls_execute_ns': sum(r['execution']['evaluation_ns'] for r in controls['rows'] if r['execution']),
        'hostile_build_ns': sum(r['build']['build_ns'] for r in hostile['rows']),
        'hostile_execute_ns': sum(r['execution']['evaluation_ns'] for r in hostile['rows']),
        'reference_tokenizer_wall_ns': read(sources['capacity'] / 'CAPACITY.json')['wall_ns'],
        'acquisition_attempt_wall_ns': sum(r['receipt']['wall_ns'] for r in receipt_records),
        'aggregate_control_wall_time_was_not_recorded': True,
    },
    'unmeasured_costs': ['human and tool-development labor', 'model training', 'upstream integration'],
    'evidence': {'archive': archive.name, 'manifest': 'EVIDENCE_MANIFEST.json',
                 'archive_sha256': manifest['archive_sha256'], 'file_count': manifest['file_count']},
    'limitations': [
        'Both observed cohorts used the fixed Rust baseline calibration; no HIA/main model cell was attempted.',
        'Zero of three under this exact first-response constrained local pipeline is not a claim that the model cannot code in other settings.',
        'Calibration ran on a CPU shared with development/functional builds. Its wall time is retained as cost, not qualified efficiency comparison.',
        'Timeout output usage is unknown. The original RESULT totals are unchanged; request token IDs recover the timeout input only.',
        'The three-problem screen measures baseline Rust performance, not HIA proficiency, and is not a representative corpus.',
        'Adaptive 1.5B-to-7B model selection is not an unbiased sample of model families.',
        'Query is a whole-function context slice, not a production single-node graph patch API.',
        'HIA four-file fixtures compose one Core module, not independently linked HIA object modules.',
        'Native resource observations and same-Core VM checks are finite executable controls, not a backend or OS proof.',
        'Reference and hostile controls establish limited evaluator behavior; they never establish Agent correctness or productivity.',
    ],
}
save(OUT / 'STOPPED.json', stopped)
print(json.dumps({'archive_bytes': manifest['archive_bytes'], 'archive_sha256': manifest['archive_sha256'],
                  'files': manifest['file_count'], 'uncompressed_bytes': manifest['uncompressed_file_bytes'],
                  'calibration_totals': stopped['calibration_totals']}, indent=2))
