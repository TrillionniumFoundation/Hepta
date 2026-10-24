"""Intention-to-treat counts: missing, failed, and timed-out cells stay in N."""
from __future__ import annotations

import math

from experiments.agent_eval.harness import Budget, EvalError, validate_usage
from ._private.oracles import hidden_cases
from .plan import sample_id, verify_plan
from .records import seal_record, verify_record
from .tasks import ARMS, TASK_IDS, snapshot_id, task_request, validate_files


def _finite_nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _facts(plan, report, coordinates):
    model, task, arm, replicate = coordinates
    request = task_request(task, ARMS[arm]['language'])
    issues, success, attested, usage_valid = [], False, False, False
    if any(report.get(key) != value for key, value in {
        'schema': 'hepta.crossfile_run.v1', 'run_kind': 'provider_adapter_run',
        'model': model, 'task_id': task, 'arm': arm, 'language': ARMS[arm]['language'], 'replicate': replicate,
        'plan_sha256': plan['plan_sha256'], 'evaluator_sha256': plan['evaluator_sha256'],
        'compiler': plan['compiler'], 'budget': plan['budget'], 'budget_sha256': Budget(**plan['budget']).sha256,
        'taskset_sha256': request['taskset_sha256'], 'task_sha256': request['task_sha256'], 'base_sha256': request['base_sha256'],
    }.items()):
        issues.append('frozen model/task/arm/compiler/budget identity mismatch or fixture provenance')
    usage = report.get('usage')
    tools = report.get('observed_tool_calls')
    validated_tools = report.get('validated_tool_calls')
    over_budget = False
    if usage is not None:
        try:
            if any(type(usage[k]) is not int or usage[k] < 0 for k in ('input_tokens', 'output_tokens', 'total_tokens')):
                raise ValueError('invalid counters')
            relaxed = Budget(**{**plan['budget'], **{k: max(plan['budget'][k], usage[k])
                               for k in ('input_tokens', 'output_tokens', 'total_tokens')}})
            if (type(tools) is not int or tools < 0 or type(validated_tools) is not int
                    or not 0 <= validated_tools <= tools): raise ValueError('invalid tool counter prefix')
            validate_usage(usage, model, relaxed, validated_tools, 'provider')
            usage_valid = True
            over_budget = any(usage[k] > plan['budget'][k] for k in ('input_tokens', 'output_tokens', 'total_tokens'))
            over_budget |= tools > plan['budget']['tool_calls']
        except (EvalError, ValueError, TypeError, KeyError):
            issues.append('invalid provider usage receipts')
    isolated = report.get('sandbox', {}).get('available') is True and report.get('isolation') == 'allowlisted_namespace_capsules'
    attested = usage_valid and isolated and report.get('adapter_invoked') is True and not issues
    wall = report.get('agent_wall_seconds')
    if wall is not None and not _finite_nonnegative(wall): issues.append('invalid wall-time observation')
    if report.get('status') == 'provider_scored':
        if not attested or report.get('usage_complete') is not True or validated_tools != tools:
            issues.append('scored provider attempt lacks complete final receipts or namespace evidence')
        try:
            submitted = validate_files(request, report['submitted_files'])
            if snapshot_id(submitted) != report.get('submitted_sha256'):
                raise ValueError('candidate snapshot identity mismatch')
            score = report['score']
            if not isinstance(score, dict) or type(score.get('ok')) is not bool:
                raise ValueError('invalid native score')
            if score['ok']:
                total = len(hidden_cases(task))
                if (score.get('compiled') is not True or score.get('passed') != total or score.get('total') != total
                        or type(score.get('passed')) is not int or score.get('native_status') != 'exited'
                        or type(score.get('native_returncode')) is not int or score['native_returncode'] != 0
                        or score.get('protocol_error') is not None
                        or score.get('source_sha256') != report['submitted_sha256']
                        or not isinstance(score.get('artifact_sha256'), str) or len(score['artifact_sha256']) != 64
                        or any(c not in '0123456789abcdef' for c in score['artifact_sha256'])):
                    raise ValueError('successful outcome lacks matching complete native evidence')
                success = (attested and not over_budget and _finite_nonnegative(wall)
                           and wall <= plan['budget']['wall_seconds'])
        except (ValueError, TypeError, KeyError) as exc:
            issues.append(str(exc))
    elif report.get('status') not in {'attempt_failed', 'environment_blocked'}:
        issues.append('unknown or non-provider run status')
    if issues: success = False
    return {'success': success, 'attested_attempt': attested and not issues, 'issues': issues,
            'tokens': usage['total_tokens'] if usage_valid and not issues else None,
            'tokens_complete': usage_valid and not issues and report.get('usage_complete') is True,
            'wall': wall if _finite_nonnegative(wall) else None,
            'status': report.get('status'), 'report': report}


def compare(plan, reports, cost_records=()):
    verify_plan(plan)
    planned = {sample_id(plan, plan['models'][s['model_index']], s['task'], s['arm'], s['replicate']):
               (plan['models'][s['model_index']], s['task'], s['arm'], s['replicate']) for s in plan['schedule']}
    received, duplicates, issues = {}, set(), []
    for report in reports:
        try: verify_record(report)
        except (ValueError, TypeError):
            issues.append('unsealed or changed run record'); continue
        key = report.get('sample_id')
        if not isinstance(key, str) or key not in planned:
            issues.append('fixture or unknown sample cannot enter the provider comparison'); continue
        if key in received:
            duplicates.add(key)
            issues.append('duplicate planned sample; no best-of retry selection is allowed')
        else: received[key] = report
    facts = {}
    for key, report in received.items():
        if key in duplicates: continue
        fact = _facts(plan, report, planned[key])
        facts[key] = fact
        issues += [key + ': ' + item for item in fact['issues']]
    # A fresh session must not recycle another planned cell's provider call.
    # Repeated cumulative receipts inside one run are already checked by the
    # runner; this check establishes ownership across the entire experiment.
    receipt_owners = {}
    for key, fact in facts.items():
        if not fact['attested_attempt']: continue
        report = fact['report']
        for receipt in report['usage']['provider_calls']:
            identity = (report['model']['provider'], receipt['request_id'])
            receipt_owners.setdefault(identity, set()).add(key)
    reused = set().union(*(owners for owners in receipt_owners.values() if len(owners) > 1)) if receipt_owners else set()
    for key in reused:
        facts[key].update(success=False, attested_attempt=False, tokens=None, tokens_complete=False)
        facts[key]['issues'].append('provider receipt was reused across planned samples')
        issues.append(key + ': provider receipt was reused across planned samples')
    cost_map, cost_duplicates = {}, set()
    for record in cost_records:
        try:
            verify_record(record)
            key = record.get('sample_id')
            if (record.get('schema') != 'hepta.crossfile_cost.v1' or key not in facts
                    or record.get('run_record_sha256') != facts[key]['report']['record_sha256']
                    or record.get('run_kind') != 'provider_adapter_run'):
                raise ValueError('cost does not match one planned provider record')
            if any(record.get(field) is not None and not _finite_nonnegative(record[field])
                   for field in ('human_seconds', 'monetary_cost_usd')):
                raise ValueError('cost observation is invalid')
            if key in cost_map:
                cost_duplicates.add(key)
                raise ValueError('duplicate cost totals for one run are ambiguous')
            cost_map[key] = record
        except (ValueError, TypeError, KeyError) as exc:
            issues.append('cost: ' + str(exc))
    for key in cost_duplicates: cost_map.pop(key, None)
    rows, contrasts = [], []
    total_attested = sum(f['attested_attempt'] for f in facts.values())
    complete_outcomes = len(facts) == len(planned) and total_attested == len(planned) and not issues
    for model in plan['models']:
        rates = {}
        for arm in ARMS:
            keys = [key for key, coordinates in planned.items() if coordinates[0] == model and coordinates[2] == arm]
            group = [facts[k] for k in keys if k in facts]
            solved = sum(f['success'] for f in group)
            known_tokens = [f['tokens'] for f in group if f['tokens'] is not None]
            token_complete = len(group) == len(keys) and all(f['tokens_complete'] for f in group)
            known_wall = [f['wall'] for f in group if f['wall'] is not None]
            human = [cost_map[k]['human_seconds'] for k in keys if k in cost_map and cost_map[k].get('human_seconds') is not None]
            money = [cost_map[k]['monetary_cost_usd'] for k in keys if k in cost_map and cost_map[k].get('monetary_cost_usd') is not None]
            human_total = sum(human) if len(human) == len(keys) else None
            money_total = sum(money) if len(money) == len(keys) else None
            token_total = sum(known_tokens) if token_complete else None
            rates[arm] = solved / len(keys)
            rows.append({'model': model, 'arm': arm, 'planned_attempts': len(keys),
                         'attested_provider_attempts': sum(f['attested_attempt'] for f in group),
                         'successful_tasks': solved, 'failures_including_missing': len(keys) - solved,
                         'missing_or_invalid_records': len(keys) - sum(not f['issues'] for f in group),
                         'environment_blocked': sum(f['status'] == 'environment_blocked' for f in group),
                         'success_fraction_all_planned': rates[arm],
                         'provider_tokens_known': sum(known_tokens) if known_tokens else None,
                         'provider_tokens_total': token_total, 'provider_token_cost_complete': token_complete,
                         'provider_tokens_per_success': token_total / solved if token_total is not None and solved else None,
                         'wall_seconds_known': sum(known_wall) if known_wall else None,
                         'wall_seconds_total': sum(known_wall) if len(known_wall) == len(keys) else None,
                         'human_seconds_known': sum(human) if human else None, 'human_seconds_total': human_total,
                         'human_seconds_per_success': human_total / solved if human_total is not None and solved else None,
                         'monetary_cost_usd_known': sum(money) if money else None, 'monetary_cost_usd_total': money_total,
                         'monetary_cost_usd_per_success': money_total / solved if money_total is not None and solved else None})
        if total_attested:
            contrasts.append({'model': model, 'basis': 'all_planned_cells_missing_and_failures_count_as_zero_success',
                              'rust_semantic_minus_plain': rates['rust_semantic'] - rates['rust_plain'],
                              'hepta_protocol_minus_plain': rates['hepta_protocol'] - rates['hepta_plain'],
                              'hepta_minus_rust_plain': rates['hepta_plain'] - rates['rust_plain'],
                              'hepta_minus_rust_semantic': rates['hepta_protocol'] - rates['rust_semantic'],
                              'language_by_tools_interaction': (rates['hepta_protocol'] - rates['hepta_plain']) -
                                                               (rates['rust_semantic'] - rates['rust_plain']),
                              'outcome_comparison_eligible': complete_outcomes})
    missing = len(planned) - len(facts)
    if missing: issues.append(str(missing) + ' planned records missing or duplicate-invalidated; all remain in denominators')
    return seal_record({'schema': 'hepta.crossfile_comparison.v1', 'plan_sha256': plan['plan_sha256'],
                        'status': 'complete_adapter_attested_pilot' if complete_outcomes else 'not_qualified',
                        'planned_attempts': len(planned), 'received_unique_records': len(facts),
                        'actual_ai_model_runs': total_attested, 'issues': issues, 'rows': rows, 'contrasts': contrasts,
                        'outcome_comparison_eligible': complete_outcomes,
                        'provider_token_cost_comparison_complete': complete_outcomes and all(r['provider_token_cost_complete'] for r in rows),
                        'human_time_comparison_complete': complete_outcomes and all(r['human_seconds_total'] is not None for r in rows),
                        'monetary_cost_comparison_complete': complete_outcomes and all(r['monetary_cost_usd_total'] is not None for r in rows),
                        'cost_comparison_complete': complete_outcomes and all(r['provider_token_cost_complete']
                            and r['human_seconds_total'] is not None and r['monetary_cost_usd_total'] is not None for r in rows),
                        'provider_receipts_independently_verified': False,
                        'statistical_scope': 'descriptive paired five-task pilot; tasks are not a random population sample; no significance or general productivity claim',
                        'claims': {'hepta_advantage_established': False, 'general_productivity_advantage_established': False,
                                   'production_workspace_v4_exercised': False}})
