"""Read-only audit of a completed, registered reset-validity campaign.

No fit, checkpoint selection, tuning, or new quality panel is performed.
Registered panels are regenerated only to verify archived raw arrays and metrics.
The original mechanism criterion is preserved. Attribution classes describe
event evidence; off-grammar events alone are not a causal error certificate.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import torch
from reset_review_parser import parse_grammar


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit_panel(batch, arrays, name, reported):
    positions = arrays[name+'_positions']
    targets = arrays[name+'_targets']
    predictions = arrays[name+'_predictions']
    probabilities = arrays[name+'_probabilities']
    binding = arrays[name+'_binding_logits']
    events = arrays[name+'_events']
    assert np.isfinite(probabilities).all() and np.isfinite(binding).all()
    assert ((probabilities >= 0) & (probabilities <= 1)).all()
    np.testing.assert_allclose(probabilities.sum(-1), 1., rtol=0, atol=2e-6)
    np.testing.assert_array_equal(predictions, probabilities.argmax(-1))
    assert np.isin(events, [0, 1]).all()
    expected_positions = np.argwhere(batch.targets.numpy() != -100)
    np.testing.assert_array_equal(positions, expected_positions)
    np.testing.assert_array_equal(targets, batch.targets.numpy()[tuple(positions.T)])
    incorrect = predictions != targets
    error_count = np.bincount(positions[:, 0], weights=incorrect, minlength=len(batch.lengths))
    stale = batch.stale_answers.numpy()[tuple(positions.T)]
    old = (stale >= 0) & (stale != targets)
    unknown = targets == 4
    counts = dict(queries=len(targets), correct_queries=int((~incorrect).sum()),
                  sequences=len(batch.lengths), exact_sequences=int((error_count == 0).sum()),
                  stale_answer_opportunities=int(old.sum()),
                  stale_answers_emitted=int(((predictions == stale) & old).sum()),
                  unknown_queries=int(unknown.sum()),
                  unknown_false_accepts=int((unknown & incorrect).sum()))
    for key, value in counts.items():
        assert reported[key] == value, (name, key, reported[key], value)
    counts['query_accuracy'] = counts['correct_queries']/counts['queries']
    counts['sequence_exact_accuracy'] = counts['exact_sequences']/counts['sequences']
    for key in ('query_accuracy', 'sequence_exact_accuracy'):
        assert abs(reported[key]-counts[key]) < 1e-12
    assert reported['maximum_token_length'] == max(batch.lengths)
    true_probability = probabilities[np.arange(len(targets)), targets].astype(np.float64)
    if bool((true_probability > 0).all()):
        counts['nll_recomputed_from_archived_probabilities'] = float(-np.log(true_probability).mean())
        counts['nll_difference_from_reported_float32_cross_entropy'] = abs(counts['nll_recomputed_from_archived_probabilities']-reported['query_nll'])
        assert counts['nll_difference_from_reported_float32_cross_entropy'] < 1e-5
    else:
        counts['nll_recomputed_from_archived_probabilities'] = None
        counts['nll_limitation'] = 'Probability underflow prevents exact reconstruction of the original log-space loss.'
    counts['bounded_quality_pass'] = counts['query_accuracy'] >= .95 and counts['sequence_exact_accuracy'] >= .9
    assert counts['bounded_quality_pass'] == reported['bounded_quality_pass']
    counts['false_unknown_on_known_target'] = int(((targets != 4) & (predictions == 4)).sum())
    counts['wrong_known_value_on_known_target'] = int(((targets != 4) & (predictions != 4) & incorrect).sum())
    counts['old_known_value_emissions'] = int(((predictions == stale) & old & (stale < 4)).sum())
    counts['old_unknown_emissions'] = int(((predictions == stale) & old & (stale == 4)).sum())
    tags = [batch.query_kinds[int(row)][int(col)] for row, col in positions]
    for tag, metric in reported['by_query_type'].items():
        selected = np.asarray([x == tag for x in tags])
        assert metric['queries'] == int(selected.sum())
        assert metric['correct'] == int((~incorrect & selected).sum())
        assert abs(metric['accuracy']-float((~incorrect)[selected].mean())) < 1e-12
    diagnostics = Counter()
    attribution = Counter()
    cases = []
    for row, length in enumerate(batch.lengths):
        tokens = batch.tokens[row, :length].tolist()
        labels, semantic_writes, resets, last_binding = parse_grammar(tokens)
        np.testing.assert_array_equal(labels, batch.targets[row, :length].numpy())
        reset = events[row, :length, 1].astype(bool)
        write = events[row, :length, 0].astype(bool)
        active_write = write & ~reset
        covered = np.zeros(length, dtype=bool); covered[0] = True
        for start in resets:
            later = np.flatnonzero(labels[start:] != -100)
            if not len(later):
                continue
            end = start+int(later[0]); covered[start:end+1] = True
            diagnostics['observed_reset_windows'] += 1
            diagnostics['windows_with_detected_event'] += int(reset[start:end+1].any())
        diagnostics['reset_events'] += int(reset.sum())
        diagnostics['reset_events_outside_command_to_first_query_windows'] += int((reset & ~covered).sum())
        diagnostics['write_events'] += int(write.sum())
        diagnostics['effective_write_events_after_reset_priority'] += int(active_write.sum())
        diagnostics['off_grammar_effective_write_events'] += int((active_write & ~semantic_writes).sum())
        diagnostics['effective_write_events_on_semantic_value_positions'] += int((active_write & semantic_writes).sum())
        for index in np.flatnonzero((positions[:, 0] == row) & incorrect):
            q = int(positions[index, 1])
            preceding_resets = [r for r in resets if r <= q]
            semantic_reset = preceding_resets[-1] if preceding_resets else -1
            learned = np.flatnonzero(reset[:q+1])
            learned_reset = int(learned[-1]) if len(learned) else -1
            if targets[index] != 4:
                if learned_reset >= int(last_binding[q]) >= 0:
                    attribution['known_errors_with_reset_after_last_semantic_binding'] += 1
                if last_binding[q] >= 0 and not active_write[last_binding[q]]:
                    attribution['known_errors_without_effective_write_at_last_semantic_value'] += 1
                continue
            if semantic_reset < 0:
                category = 'unknown_error_without_prior_semantic_reset'
            elif learned_reset < semantic_reset:
                category = 'unknown_error_without_learned_reset_since_latest_semantic_reset'
            else:
                effective = active_write[learned_reset+1:q+1]
                legal = semantic_writes[learned_reset+1:q+1]
                if not effective.any():
                    category = 'VIOLATION_unknown_error_despite_reset_and_no_effective_write'
                elif not (effective & ~legal).any():
                    category = 'unknown_error_after_only_legitimate_other_key_writes'
                else:
                    category = 'unknown_error_with_post_reset_off_grammar_writes'
            attribution[category] += 1
            cases.append(dict(row=row, position=q, prediction=int(predictions[index]),
                binding_logit=float(binding[index]), latest_semantic_reset=semantic_reset,
                latest_learned_reset=learned_reset, category=category,
                post_learned_reset_effective_writes=int(active_write[learned_reset+1:q+1].sum()),
                post_learned_reset_off_grammar_writes=int((active_write & ~semantic_writes)[learned_reset+1:q+1].sum())))
    for key, expected in reported['event_diagnostics'].items():
        if isinstance(expected, int) and not isinstance(expected, bool):
            assert diagnostics[key] == expected, (name, key, diagnostics[key], expected)
    assert attribution['VIOLATION_unknown_error_despite_reset_and_no_effective_write'] == 0
    counts['event_diagnostics'] = dict(diagnostics)
    counts['error_event_attribution'] = dict(attribution)
    counts['unknown_error_cases'] = cases
    counts['reported_integer_metrics_and_accuracy_rates_recomputed'] = True
    return counts


def independent_witness(model, batch, reported):
    with torch.inference_mode():
        _, trace = model(batch.tokens, batch.duration, return_trace=True)
        chosen = None
        for row, length in enumerate(batch.lengths):
            labels, _, resets, _ = parse_grammar(batch.tokens[row, :length].tolist())
            for start in resets:
                later = np.flatnonzero(labels[start:] != -100)
                if not len(later):
                    continue
                end = start+int(later[0])
                matches = torch.nonzero(trace['events'][row, start:end+1, 1] == 1).flatten()
                if len(matches):
                    chosen = row, start+int(matches[0]); break
            if chosen is not None:
                break
        if chosen is None:
            assert reported['status'] == 'NO_LEARNED_EVENT_IN_DEVELOPMENT_RESET_WINDOW'
            return dict(status='NO_LEARNED_EVENT_IN_DEVELOPMENT_RESET_WINDOW')
        row, t = chosen
        assert (reported['row'], reported['position']) == chosen
        _, state = model(batch.tokens[row:row+1, :t], batch.duration[row:row+1, :t], return_state=True)
        perturbed = state[0]*-7+11, state[1]*5-13, state[2].clone(), state[3].clone()
        x, sx, tx = model(batch.tokens[row:row+1, t:t+1], batch.duration[row:row+1, t:t+1], state,
                          return_state=True, return_trace=True)
        y, sy, ty = model(batch.tokens[row:row+1, t:t+1], batch.duration[row:row+1, t:t+1], perturbed,
                          return_state=True, return_trace=True)
        assert float(tx['events'][0, 0, 1]) == float(ty['events'][0, 0, 1]) == 1
        for a, b in zip(sx, sy):
            torch.testing.assert_close(a, b, rtol=0, atol=0)
        torch.testing.assert_close(x, y, rtol=0, atol=0)
        for index in (0, 1, 3):
            assert bool((sx[index] == 0).all())
        torch.testing.assert_close(sx[2], model.embedding(batch.tokens[row:row+1, t]), rtol=0, atol=0)
        assert reported['status'] == 'WITNESSED'
    return dict(status='WITNESSED', row=row, position=t, exact_zero_memory_validity_older=True,
                both_local_reset_events_equal_one=True, same_current_embedding=True,
                exact_counterfactual_state_and_output_equality=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--registration-repo', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('refuse to overwrite independent audit')
    root = args.root.resolve(); sys.path.insert(0, str(root))
    from research.hcsn.p2_reset_validity import RawResetValidityMemory, make_reset_validity_panel
    from research.hcsn.p2_round2_raw_tokens import batch_digest
    here = root/'research/hcsn'
    evidence = args.evidence or here/'gates/2026-11-05-round3-p2-reset-validity-results.json'
    report = json.loads(evidence.read_text())
    assert report['status'] in ('COMPLETED', 'COMPLETED_FIXED_CONFIGURATION_SET') and report['all_four_training_runs_completed']
    protocol_path = root/report['registration']['protocol_path']
    assert sha(protocol_path) == report['protocol_sha256']
    protocol = json.loads(protocol_path.read_text())
    registration_repo = args.registration_repo or root
    registered = subprocess.check_output(['git', 'show', report['registration']['commit']+':'+report['registration']['protocol_path']], cwd=registration_repo)
    assert hashlib.sha256(registered).hexdigest() == sha(protocol_path)
    for name, digest in protocol['source_sha256'].items():
        assert sha(here/name) == digest
        registered_source = subprocess.check_output(['git', 'show', report['registration']['commit']+':research/hcsn/'+name], cwd=registration_repo)
        assert hashlib.sha256(registered_source).hexdigest() == digest
    assert datetime.fromisoformat(report['registration']['commit_time_utc']) <= datetime.fromisoformat(report['start_time_utc'])
    ready_time = report.get('all_training_finished_time_utc', report.get('all_final_checkpoints_ready_time_utc'))
    assert datetime.fromisoformat(ready_time) <= datetime.fromisoformat(report['heldout_construction_started_time_utc'])
    artifacts = evidence.parent/(evidence.stem+'-artifacts')
    torch.set_num_threads(1)
    result = dict(schema='hcsn.p2.independent-reset-results-audit.v1',
        evidence_sha256=sha(evidence), reviewer_sha256=sha(Path(__file__)), parser_source_sha256=sha(Path(__file__).with_name('reset_review_parser.py')),
        registration_commit=report['registration']['commit'], source_sha256=protocol['source_sha256'],
        registration_and_source_bytes_verified=True,
        training_fits=0, new_quality_panels=0, archived_quality_panels_recomputed=0,
        mapped_verification_panel_replays=0,
        model_forwards_are_verification_not_new_quality_trials=True, runs=[],
        statistical_scope='Two paired training seeds; repeated within-sequence queries are not independent trials.',
        attribution_scope='Raw event conditions, not causal blame for every off-grammar event. Only-legitimate-write UNKNOWN failures after erasure establish validity/address interference within this representation.')
    if report['status'] == 'COMPLETED_FIXED_CONFIGURATION_SET':
        for name, digest in protocol['parent_evidence_sha256'].items():
            assert sha(here/name) == digest
        parent_path = here/protocol['parent_results_path']
        parent_protocol = json.loads((here/protocol['parent_protocol_path']).read_text())
        parent = json.loads(parent_path.read_text())
        assert sha(parent_path) == report['parent_results_sha256']
        assert parent['status'] == 'INCOMPLETE_RETAINED' and not parent['all_four_training_runs_completed']
        assert not report['original_180_second_budget_pass']
        assert report['prefix_replay_verified_before_heldout'] and report['all_four_final_configurations_completed']
        for field in ('training', 'development', 'heldout', 'acceptance', 'model', 'mechanism_claim'):
            assert protocol[field] == parent_protocol[field], field
        additional = []
        for entry in report['runs']:
            old = next(item for item in parent['runs'] if (item['mode'], item['seed']) == (entry['mode'], entry['seed']))
            if entry['completion_origin'] == 'reused_parent_final_checkpoint_without_training':
                for field in ('checkpoint', 'losses', 'preclip_gradient_norms', 'updates', 'training_stream_sha256'):
                    assert entry[field] == old[field], field
            else:
                assert entry['completion_origin'] == 'additional_full_replay_fit_from_same_seed'
                prefix = old['updates']; additional.append(entry)
                assert entry['losses'][:prefix] == old['losses']
                assert entry['preclip_gradient_norms'][:prefix] == old['preclip_gradient_norms']
                assert entry['prefix_losses_exact'] == entry['prefix_gradients_exact'] == prefix
                assert entry['prefix_checkpoint_verification']['all_tensors_bitwise_equal']
                assert entry['prefix_checkpoint_verification']['parent_checkpoint_sha256'] == old['checkpoint']['sha256']
                for field in ('arrays', 'metadata'):
                    item = entry['optimizer_checkpoint'][field]
                    assert sha(artifacts/item['filename']) == item['sha256']
        assert len(additional) == 1
        assert report['original_actual_fit_attempts'] == len(parent['runs']) == 4
        assert report['additional_actual_fit_attempts'] == 1 and report['total_actual_fit_attempts'] == 5
        assert report['total_actual_optimizer_updates'] == sum(item['updates'] for item in parent['runs'])+additional[0]['updates']
        result['completion_provenance'] = dict(parent_report_sha256=sha(parent_path), original_status='INCOMPLETE_RETAINED',
            original_budget_pass=False, reused_unchanged_final_checkpoints=3, additional_actual_fit_executions=1,
            total_actual_fit_executions=len(parent['runs'])+1, total_actual_optimizer_updates=report['total_actual_optimizer_updates'],
            exact_loss_and_gradient_norm_prefix_length=additional[0]['prefix_losses_exact'],
            prefix_state_comparison_scope='Verified the recorded runtime guard and its source; this auditor does not retrain the prefix.')
    panels = {name: make_reset_validity_panel(spec) for name, spec in protocol['heldout'].items()}
    passes = []
    for entry in report['runs']:
        weights = artifacts/entry['checkpoint']['filename']; raw = artifacts/entry['raw_queries']['filename']
        assert sha(weights) == entry['checkpoint']['sha256'] and sha(raw) == entry['raw_queries']['sha256']
        model = RawResetValidityMemory(entry['mode'])
        with np.load(weights, allow_pickle=False) as data:
            model.load_state_dict({name: torch.from_numpy(data[name].copy()) for name in data.files})
        model.eval()
        reviewed = dict(mode=entry['mode'], seed=entry['seed'], panels={})
        mapped = None; mapped_error = 0.; mapped_events_equal = True
        if entry['mode'] == 'hcsn_reset_validity':
            mapped = RawResetValidityMemory('put_linear_reset_validity')
            mapped.load_state_dict(model.state_dict()); mapped.eval()
        with np.load(raw, allow_pickle=False) as arrays, torch.inference_mode():
            for name, batch in panels.items():
                assert batch_digest(batch) == entry['heldout'][name]['dataset_sha256']
                metric = audit_panel(batch, arrays, name, entry['heldout'][name])
                logits, trace = model(batch.tokens, batch.duration, return_trace=True)
                query = batch.targets != -100
                np.testing.assert_array_equal(trace['events'].to(torch.uint8).numpy(), arrays[name+'_events'])
                np.testing.assert_array_equal(logits[query].argmax(-1).numpy(), arrays[name+'_predictions'])
                np.testing.assert_array_equal(logits[query].exp().numpy(), arrays[name+'_probabilities'])
                np.testing.assert_array_equal(trace['binding_logit'][query].numpy(), arrays[name+'_binding_logits'])
                if mapped is not None:
                    other, other_trace = mapped(batch.tokens, batch.duration, return_trace=True)
                    mapped_error = max(mapped_error, float((other-logits).abs().max()))
                    mapped_events_equal = mapped_events_equal and bool(torch.equal(other_trace['events'], trace['events']))
                    result['mapped_verification_panel_replays'] += 1
                metric['checkpoint_replay_exact'] = True
                reviewed['panels'][name] = metric
                result['archived_quality_panels_recomputed'] += 1
        if mapped is not None:
            assert mapped_error == entry['mapped_put_linear_max_log_probability_error']
            assert mapped_events_equal == entry['mapped_put_linear_events_identical']
            reviewed['mapped_verification'] = dict(max_log_probability_error=mapped_error, all_events_identical=mapped_events_equal)
        witness_batch = make_reset_validity_panel(protocol['development']['erasure_witness'])
        reviewed['conditional_erasure_witness'] = independent_witness(model, witness_batch, entry['conditional_erasure_witness'])
        reset_panels = [reviewed['panels'][name] for name in protocol['mechanism_claim']['reset_panels']]
        unknown_errors = sum(x['unknown_false_accepts'] for x in reset_panels)
        windows_detected = all(x['event_diagnostics'].get('observed_reset_windows', 0) ==
                               x['event_diagnostics'].get('windows_with_detected_event', 0) for x in reset_panels)
        passed = all(x['bounded_quality_pass'] for x in reviewed['panels'].values()) and unknown_errors == 0 and windows_detected and reviewed['conditional_erasure_witness']['status'] == 'WITNESSED'
        assert unknown_errors == entry['reset_panel_unknown_false_accepts']
        assert windows_detected == entry['all_reset_windows_detected']
        assert passed == entry['registered_reset_gap_criteria_pass']
        reviewed['reset_unknown_false_accepts'] = unknown_errors
        reviewed['reset_windows_all_detected'] = windows_detected
        reviewed['registered_criteria_pass'] = passed
        result['runs'].append(reviewed); passes.append(passed)
    for seed in protocol['training']['model_seeds']:
        pair = [entry for entry in report['runs'] if entry['seed'] == seed]
        assert len(pair) == 2
        for field in ('initial_parameters_sha256', 'training_stream_sha256', 'parameter_count', 'updates'):
            assert pair[0][field] == pair[1][field]
    assert all(passes) == report['reset_gap_closed_on_registered_panels']
    result['reset_gap_closed_on_registered_panels'] = all(passes)
    result['all_checks_passed'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False); stream.write('\n')
    print(json.dumps({key: result[key] for key in ('all_checks_passed', 'training_fits', 'new_quality_panels',
          'archived_quality_panels_recomputed', 'reset_gap_closed_on_registered_panels')}, indent=2))


if __name__ == '__main__':
    main()
