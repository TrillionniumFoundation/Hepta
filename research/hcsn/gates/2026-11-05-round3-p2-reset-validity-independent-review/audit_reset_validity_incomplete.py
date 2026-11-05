"""Independently verify the retained budget-stop result and development diagnosis.

This verifier performs no fit and constructs no heldout panel. It reconstructs
training data digests, reads four fixed checkpoints, and replays only the already
registered multi_reset development panel to check the disclosed diagnosis.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import torch
from torch.nn import functional as F

from reset_review_parser import parse_grammar


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--registration-repo', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--diagnostic', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('refuse to overwrite independent audit')
    root = args.root.resolve(); sys.path.insert(0, str(root))
    from research.hcsn.p2_reset_validity import RawResetValidityMemory, make_reset_validity_panel
    from research.hcsn.p2_associative_memory import delta_batch
    from research.hcsn.p2_round2_raw_tokens import batch_digest
    here = root/'research/hcsn'
    evidence = args.evidence or here/'gates/2026-11-05-round3-p2-reset-validity-results.json'
    diagnostic = args.diagnostic or here/'gates/2026-11-05-round3-p2-reset-validity-development-diagnostic.json'
    report = json.loads(evidence.read_text()); diag = json.loads(diagnostic.read_text())
    protocol_path = root/report['registration']['protocol_path']
    protocol = json.loads(protocol_path.read_text())
    artifacts = evidence.parent/(evidence.stem+'-artifacts')
    assert report['status'] == 'INCOMPLETE_RETAINED'
    assert report['all_four_training_runs_completed'] is False
    assert report['paired_initialization_and_training_verified'] is False
    assert report['reset_gap_closed_on_registered_panels'] is False
    assert 'heldout_construction_started_time_utc' not in report
    assert report['source_hashes_unchanged'] is True
    assert len(report['runs']) == 4
    assert diag['report_sha256'] == sha(evidence)
    assert diag['new_fits'] == 0 and diag['post_hoc'] and not diag['fitting_or_checkpoint_selection']
    assert sha(protocol_path) == report['protocol_sha256'] == report['registration']['protocol_sha256']
    registration_repo = args.registration_repo or root
    commit = report['registration']['commit']
    registered_protocol = subprocess.check_output(['git', 'show', f'{commit}:{report["registration"]["protocol_path"]}'], cwd=registration_repo)
    assert hashlib.sha256(registered_protocol).hexdigest() == sha(protocol_path)
    for name, digest in protocol['source_sha256'].items():
        assert sha(here/name) == digest
        committed = subprocess.check_output(['git', 'show', f'{commit}:research/hcsn/{name}'], cwd=registration_repo)
        assert hashlib.sha256(committed).hexdigest() == digest
    assert datetime.fromisoformat(report['registration']['commit_time_utc']) <= datetime.fromisoformat(report['start_time_utc'])
    assert datetime.fromisoformat(report['start_time_utc']) <= datetime.fromisoformat(report['all_training_finished_time_utc']) <= datetime.fromisoformat(report['end_time_utc'])
    assert abs(sum(entry['training_cpu_seconds'] for entry in report['runs'])-report['training_cpu_seconds']) < 1e-9
    assert report['training_cpu_seconds'] >= protocol['budget']['training_cpu_soft_stop_seconds']
    assert report['cpu_seconds'] >= report['training_cpu_seconds']
    assert report['wall_seconds'] >= 0
    expected_files = sorted(entry['checkpoint']['filename'] for entry in report['runs'])
    assert sorted(path.name for path in artifacts.iterdir()) == expected_files
    assert not list(artifacts.glob('*queries*'))
    torch.set_num_threads(1)
    training = protocol['training']
    stream_checks = {}
    for seed in training['model_seeds']:
        pair = [entry for entry in report['runs'] if entry['seed'] == seed]
        assert len(pair) == 2
        checkpoints = {entry['updates']: entry for entry in pair}
        digest = hashlib.sha256(); count = 0
        for step in range(max(checkpoints)):
            stage = training['stages'][0] if step < training['stages'][0]['updates'] else training['stages'][1]
            batch = delta_batch(training['stream_base']+seed*100000+step, n=training['batch_size'],
                kinds=tuple(stage['tasks_round_robin']), noise_gap=training['noise_gap'],
                overwrites=training['overwrites'], episodes=training['episodes'],
                ignore_probability=training['ignore_probability'])
            digest.update(batch_digest(batch).encode()); count += int((batch.targets != -100).sum())
            if step+1 in checkpoints:
                for entry in pair:
                    if entry['updates'] == step+1:
                        assert digest.hexdigest() == entry['training_stream_sha256']
                        assert count == entry['training_queries']
                stream_checks[f'{seed}:{step+1}'] = dict(sha256=digest.hexdigest(), query_labels=count)
    batch = make_reset_validity_panel(protocol['development']['panels']['multi_reset'])
    assert batch_digest(batch) == diag['dataset_sha256']
    shape = batch.tokens.shape
    group_masks = {name: torch.zeros(shape, dtype=torch.bool) for name in
                   ('true_write_value', 'ignored_value', 'query', 'visible_reset', 'other')}
    valid_tokens = torch.zeros(shape, dtype=torch.bool)
    for row, length in enumerate(batch.lengths):
        labels, writes, resets, _ = parse_grammar(batch.tokens[row, :length].tolist())
        np.testing.assert_array_equal(labels, batch.targets[row, :length].numpy())
        valid_tokens[row, :length] = True
        group_masks['true_write_value'][row, :length] = torch.from_numpy(writes)
        group_masks['query'][row, :length] = torch.from_numpy(labels != -100)
        group_masks['visible_reset'][row, resets] = True
        for position in (batch.tokens[row, :length] == 19).nonzero().flatten().tolist():
            group_masks['ignored_value'][row, position+2] = True
    group_masks['other'] = valid_tokens & ~torch.stack([mask for name, mask in group_masks.items() if name != 'other']).any(0)
    known = group_masks['query'] & (batch.targets != 4)
    unknown = group_masks['query'] & (batch.targets == 4)
    result = dict(schema='hcsn.p2.independent-incomplete-and-development-audit.v1',
        evidence_sha256=sha(evidence), diagnostic_sha256=sha(diagnostic), reviewer_sha256=sha(Path(__file__)),
        parser_source_sha256=sha(Path(__file__).with_name('reset_review_parser.py')),
        registration_commit=commit, registration_and_source_bytes_verified=True,
        training_fits=0, heldout_panels_constructed_or_evaluated=0,
        incomplete_branch_no_heldout_fields_or_artifacts=True,
        training_updates_retained=sum(entry['updates'] for entry in report['runs']),
        training_cpu_seconds=report['training_cpu_seconds'], total_campaign_cpu_seconds=report['cpu_seconds'],
        original_training_budget_seconds=protocol['budget']['training_cpu_soft_stop_seconds'],
        budget_overshoot_seconds=report['training_cpu_seconds']-protocol['budget']['training_cpu_soft_stop_seconds'],
        training_data_stream_checks=stream_checks, optimizer_state_saved=False,
        development_only=True, development_dataset_sha256=batch_digest(batch),
        maximum_soft_probability_mean_reduction_difference=0.,
        soft_probability_mean_comparison_atol=4*float(np.finfo(np.float32).eps),
        runs=[], reset_gap_closed_on_registered_panels=False,
        scientific_scope='This verifies retention and a development failure. It is not heldout evidence, a budget-compliant completed campaign, or external attestation.')
    for entry in report['runs']:
        assert not any(key in entry for key in ('heldout', 'raw_queries', 'conditional_erasure_witness', 'registered_reset_gap_criteria_pass'))
        steps = entry['updates']
        assert len(entry['losses']) == len(entry['preclip_gradient_norms']) == steps
        assert np.isfinite(entry['losses']).all() and np.isfinite(entry['preclip_gradient_norms']).all()
        if entry['status'] == 'COMPLETED':
            assert steps == training['steps_per_model']
        else:
            assert entry['status'] == 'BUDGET_EXHAUSTED' and steps < training['steps_per_model']
        weights = artifacts/entry['checkpoint']['filename']
        assert sha(weights) == entry['checkpoint']['sha256']
        torch.manual_seed(entry['seed']); model = RawResetValidityMemory(entry['mode'])
        digest = hashlib.sha256()
        for parameter in model.parameters():
            digest.update(parameter.detach().numpy().tobytes())
        assert digest.hexdigest() == entry['initial_parameters_sha256']
        assert sum(parameter.numel() for parameter in model.parameters()) == entry['parameter_count'] == 2276
        with np.load(weights, allow_pickle=False) as data:
            assert set(data.files) == set(model.state_dict())
            assert all(np.isfinite(data[name]).all() for name in data.files)
            model.load_state_dict({name: torch.from_numpy(data[name].copy()) for name in data.files})
        model.eval()
        with torch.inference_mode():
            logits, trace = model(batch.tokens, batch.duration, return_trace=True)
            events = trace['events']; soft = trace['soft_controls']
            prediction = logits.argmax(-1)
            groups = {}
            for name, mask in group_masks.items():
                proposed, reset = events[mask].unbind(-1)
                groups[name] = dict(tokens=int(mask.sum()), reset_events=int(reset.sum()),
                    proposed_write_events=int(proposed.sum()),
                    actual_write_events_after_reset_priority=int((proposed*(1-reset)).sum()),
                    mean_soft_reset_probability=float(soft[..., 1][mask].mean()),
                    mean_soft_write_probability=float(soft[..., 0][mask].mean()))
            summary = dict(mode=entry['mode'], seed=entry['seed'], updates=steps,
                fit_status=entry['status'], known_queries=int(known.sum()),
                known_predictions_UNKNOWN=int((prediction[known] == 4).sum()),
                unknown_queries=int(unknown.sum()), unknown_false_accepts=int((prediction[unknown] != 4).sum()),
                query_binding_logit_min=float(trace['binding_logit'][group_masks['query']].min()),
                query_binding_logit_max=float(trace['binding_logit'][group_masks['query']].max()),
                token_groups=groups)
            actual = next(record for record in diag['runs'] if record['mode'] == entry['mode'] and record['seed'] == entry['seed'])
            for name, value in summary.items():
                if name == 'token_groups':
                    for group, metrics in value.items():
                        for key, metric in metrics.items():
                            difference = abs(metric-actual[name][group][key])
                            if isinstance(metric, float):
                                result['maximum_soft_probability_mean_reduction_difference'] = max(result['maximum_soft_probability_mean_reduction_difference'], difference)
                                assert difference <= result['soft_probability_mean_comparison_atol'], (entry['mode'], group, key, metric, actual[name][group][key])
                            else:
                                assert difference == 0, (entry['mode'], group, key, metric, actual[name][group][key])
                else:
                    assert actual[name] == value, (entry['mode'], name, value, actual[name])
            correct = prediction == batch.targets
            summary['query_accuracy'] = float(correct[group_masks['query']].double().mean())
            summary['exact_sequences'] = int((correct | ~group_masks['query']).all(-1).sum())
            summary['all_queries_trigger_reset'] = groups['query']['reset_events'] == groups['query']['tokens']
            summary['all_queries_predict_UNKNOWN'] = bool((prediction[group_masks['query']] == 4).all())
            summary['all_reset_windows_covered_development_diagnostic_only'] = True
            for row, length in enumerate(batch.lengths):
                _, _, resets, _ = parse_grammar(batch.tokens[row, :length].tolist())
                for start in resets:
                    end = start+int((batch.targets[row, start:length] != -100).nonzero().flatten()[0])
                    if not bool(events[row, start:end+1, 1].any()):
                        summary['all_reset_windows_covered_development_diagnostic_only'] = False
            if entry['status'] == 'COMPLETED':
                prior = entry['development'][-1]
                assert prior['update'] == steps
                expected = prior['panels']['multi_reset']
                assert summary['query_accuracy'] == expected['query_accuracy']
                assert summary['exact_sequences'] == expected['exact_sequences']
                assert summary['unknown_false_accepts'] == expected['unknown_false_accepts']
            summary['checkpoint_sha256'] = sha(weights)
            summary['retained_losses_and_gradient_norms_finite'] = True
            result['runs'].append(summary)
    assert sum(entry['status'] == 'COMPLETED' for entry in report['runs']) == 3
    assert result['training_updates_retained'] == 1073
    result['all_checks_passed'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False); stream.write('\n')
    print(json.dumps({key: result[key] for key in ('all_checks_passed', 'training_fits',
        'heldout_panels_constructed_or_evaluated', 'training_updates_retained',
        'training_cpu_seconds', 'reset_gap_closed_on_registered_panels')}, indent=2))


if __name__ == '__main__':
    main()
