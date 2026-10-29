#!/usr/bin/env python3
"""Retain completed V10 observations and exact text copies; do not run inference."""
from pathlib import Path
import hashlib
import json
import shutil

SOURCE = '11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0'
RAW = Path('/tmp/hepta-next-agent-v10-qwen4b-01')
CAP = Path('/tmp/hepta-next-agent-v10-capacity-01')
OUT = Path('/tmp/hepta-next-agent-v10-evidence-package')
EARLIER = Path('/tmp/hepta-next-agent-evidence-20261029/experiments/hia_agent_toolstudy_v9_20261029/evidence/SUMMARY.json')

def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n')

def collect(folder, label):
    rows = []
    for path in sorted(folder.rglob('*')):
        assert not path.is_symlink(), 'Unreviewed symlink'
        if not path.is_file():
            continue
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
        assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
        rel = path.relative_to(folder)
        copied = None
        if 'source_snapshot' not in rel.parts and not data.startswith(b'\x7fELF') and b'\0' not in data:
            try:
                data.decode('utf-8')
            except UnicodeDecodeError:
                pass
            else:
                target = OUT / label / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                copied = str(target.relative_to(OUT))
        rows.append({'path': str(path), 'relative_path': str(rel), 'bytes': len(data),
                     'sha256': hashlib.sha256(data).hexdigest(), 'compact_copy': copied})
    save(OUT / (label.upper() + '_RAW_MANIFEST.json'), {'files': rows})
    return rows

def main():
    result = json.loads((RAW / 'RESULT.json').read_text())
    capacity = json.loads((CAP / 'CAPACITY.json').read_text())
    refusal_path = Path('/tmp/hepta-next-agent-v10-main-refusal.json')
    refusal = json.loads(refusal_path.read_text())
    assert result['source_commit'] == capacity['source_commit'] == SOURCE
    assert result['valid_observation'] and result['status'] == 'all_cells_attempted'
    assert len(result['cells']) == 3 and not result['calibration_eligible']
    assert all(e['exited'] for e in result['engines']) and capacity['engine_exited']
    assert capacity['complete'] and capacity['model_requests'] == 0
    assert result['capacity_sha256'] == identity(CAP / 'CAPACITY.json')['sha256']
    assert refusal['gate_rejected_before_engine_construction'] and refusal['model_requests'] == 0
    assert not refusal['main_output_directory_created']
    OUT.mkdir(exist_ok=False)
    manifests = collect(CAP, 'capacity') + collect(RAW, 'qualification')
    rows = []
    for cell in result['cells']:
        attempts = cell['attempts']
        known = [a['usage'] for a in attempts if a.get('usage')]
        partials = [a['partial_usage'] for a in attempts if a.get('partial_usage')]
        hashes = [hashlib.sha256(json.loads(p.read_text())['text'].encode()).hexdigest()
                  for p in sorted((RAW / cell['id']).glob('attempt-*.response.json'))]
        rows.append({'task': cell['task'], 'submissions': len(attempts), 'correct': cell['correct'],
                     'hidden_evaluated': cell['hidden_evaluated'], 'statuses': [a['status'] for a in attempts],
                     'known_input_tokens': sum(u['input_tokens'] for u in known + partials),
                     'known_output_tokens': sum(u['output_tokens'] for u in known),
                     'complete_responses': len(known),
                     'request_wall_ns': sum(a.get('request_wall_ns', 0) for a in attempts),
                     'cell_wall_ns': cell['cell_wall_ns'], 'response_text_sha256': hashes,
                     'identical_complete_responses': len(hashes) == len(attempts) and len(set(hashes)) == 1,
                     'errors': [a.get('evaluation', {}).get('feedback', {}).get('diagnostic') or a.get('error') for a in attempts]})
    attempts = [a for cell in result['cells'] for a in cell['attempts']]
    budgets = [json.loads(p.read_text()) for p in sorted(RAW.rglob('attempt-*.repair-budget.json'))]
    fields = ['source_commit', 'calibration_eligible', 'requests', 'responses', 'known_input_tokens',
              'known_output_tokens', 'total_tokens', 'partial_output_token_lower_bound', 'unknown_usage_requests',
              'experiment_wall_ns', 'first_submission_correct', 'human_answer_repairs', 'source_unchanged',
              'tools_unchanged', 'model_unchanged', 'valid_observation', 'terminal_hidden_calls']
    summary = {key: result[key] for key in fields}
    summary.update(schema='hepta.agent.toolstudy-evidence.v10', qualification_correct=sum(c['correct'] for c in result['cells']),
                   qualification_tasks=3, qualification_result=identity(RAW / 'RESULT.json'),
                   capacity_result=identity(CAP / 'CAPACITY.json'), capacity_controls=19,
                   independent_cli_controls=capacity['independent_cli_tokenizer']['calls'],
                   capacity_wall_ns=capacity['experiment_wall_ns'], capacity_model_requests=0,
                   main_cells_started=0, main_model_requests=0,
                   main_refusal={**identity(refusal_path), 'wall_ns': refusal['wall_ns']},
                   registered_capacity_qualification_refusal_wall_ns=capacity['experiment_wall_ns']+result['experiment_wall_ns']+refusal['wall_ns'],
                   all_owned_engines_exited=True, rows=rows,
                   max_actual_input_tokens=max((a.get('usage') or a.get('partial_usage'))['input_tokens'] for a in attempts if a.get('usage') or a.get('partial_usage')),
                   max_actual_output_tokens=max((a['usage']['output_tokens'] for a in attempts if a.get('usage')), default=0),
                   request_wall_ns=sum(a.get('request_wall_ns', 0) for a in attempts),
                   public_native_process_calls=sum((a.get('evaluation', {}).get('public') or {}).get('native_executed') is True for a in attempts),
                   diagnostic_clipping_count=sum(b['feedback']['diagnostic_clipped'] for b in budgets),
                   code_truncation_count=sum(b['previous_code_truncated'] for b in budgets),
                   public_case_removal_count=sum(b['public_cases_removed'] for b in budgets),
                   max_previous_retokenized_tokens=max((b['previous_response_tokens'] for b in budgets), default=0),
                   max_public_feedback_tokens=max((b['feedback_tokens'] for b in budgets), default=0),
                   independent_capacity_review='d265b614a844d568904197ddae434d727a4fc2b5',
                   independent_capacity_review_receipt=identity(Path('/tmp/hepta-next-agent-v10-independent-capacity-review-01/REVIEW.json')),
                   adaptation='One prospectively pinned distinct model and exact official-template controls; V9 tasks/messages/validator/budgets unchanged.',
                   prior_results_reclassified=False, automatic_host_answer_repairs=0,
                   registered_single_candidate_stop_rule_taken=True, general_agent_productivity_proved=False,
                   measurement_scope='Three-task fresh qualification only; no HIA model/main efficiency comparison. Complete project labor, orchestration waiting and other exclusions are not included in registered experiment wall.')
    old = json.loads(EARLIER.read_text())['all_V5_V6_V8_V9_retained_model_runs']
    known = old['known_total_tokens'] + result['known_input_tokens'] + result['known_output_tokens']
    summary['all_V5_V6_V8_V9_V10_retained_model_runs'] = {
        'requests': old['requests'] + result['requests'], 'known_total_tokens': known,
        'minimum_total_tokens': known + result['partial_output_token_lower_bound'],
        'exact_total_tokens': None if result['unknown_usage_requests'] else known,
        'experiment_wall_ns': old['experiment_wall_ns'] + result['experiment_wall_ns'],
        'unknown_usage_requests': result['unknown_usage_requests'],
        'observed_partial_output_token_lower_bound': result['partial_output_token_lower_bound'],
        'excludes': old['excludes']}
    acquisition = Path('/tmp/hepta-next-model-qwen3-4b-20261029/ACQUISITION.json')
    summary['model_acquisition'] = {**identity(acquisition), 'wall_ns': json.loads(acquisition.read_text())['wall_ns'],
                                  'included_in_registered_experiment_wall': False}
    extra = [refusal_path, acquisition, Path('/tmp/hepta-next-agent-v10-capacity-owned-exit.json'),
             Path('/tmp/hepta-next-agent-v10-owned-exit.json'), Path('/tmp/hepta-next-agent-v10-capacity-launch-transport.json'),
             Path('/tmp/hepta-next-agent-v10-capacity-01.log'), Path('/tmp/hepta-next-agent-v10-qwen4b-01.log'),
             Path(__file__), Path('/tmp/hepta-next-agent-v10-record-refusal.py')]
    for path in extra:
        target = OUT / 'receipts' / path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    save(OUT / 'SUMMARY.json', summary)
    checks = {'raw_files_verified': 0, 'compact_copies_verified': 0}
    for row in manifests:
        path = Path(row['path']); actual = identity(path)
        assert actual['sha256'] == row['sha256'] and actual['bytes'] == row['bytes']
        checks['raw_files_verified'] += 1
        if row['compact_copy']:
            assert (OUT / row['compact_copy']).read_bytes() == path.read_bytes()
            checks['compact_copies_verified'] += 1
    checks.update(all_original_files_match=True, all_compact_copies_match=True)
    save(OUT / 'RETENTION_CHECK.json', checks)
    print(json.dumps({'output': str(OUT), 'correct': summary['qualification_correct'], 'requests': result['requests'],
                      'tokens': result['total_tokens'], 'retention': checks}))

if __name__ == '__main__':
    main()
