"""Summarize completed immutable V13 stage receipts; never invoke inference."""
from pathlib import Path
from collections import Counter
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'p7-v13-integrated-953fa62'
HEAD = '953fa62dee5aa563551d57b1374ab95b6d548b45'
TREE = 'aa0683509a02ca97e4e0c1dd723e4047f50d81b3'


def read(path):
    return json.loads(path.read_bytes())


def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    output = BASE / 'SUMMARY.json'
    if output.exists():
        raise ValueError('refuse to overwrite observed summary')
    cap = read(BASE / 'capacity/CAPACITY.json')
    cal = read(BASE / 'calibration/RESULT.json')
    receipts = {phase: read(BASE / 'operations' / (phase.upper() + '_EXECUTION.json'))
                for phase in ('capacity', 'calibration', 'main')}
    for phase, receipt in receipts.items():
        if (receipt['status'] != 'process_exited' or receipt['postflight_errors']
                or not receipt['direct_runner_reaped'] or not receipt['raw_source_unchanged']
                or receipt['source_commit'] != HEAD or receipt['source_commit_after'] != HEAD
                or receipt['source_tree'] != TREE or not receipt['source_clean_after']):
            raise ValueError('incomplete stage: ' + phase)
    if not cap['complete'] or not cal['valid_observation'] or cal['status'] != 'all_cells_attempted':
        raise ValueError('incomplete capacity/calibration')
    if cal['calibration_eligible'] or receipts['main']['returncode'] != 1 or (BASE / 'main').exists():
        raise ValueError('this summary requires the actual failed qualification and pre-engine main refusal')
    stderr = (BASE / 'operations/main.stderr').read_text()
    if 'E_TOOLSTUDY_NO_QUALIFIED_MODEL' not in stderr or 'validate_qualification' not in stderr:
        raise ValueError('actual CLI refusal is absent')
    cells = cal['cells']
    attempts = [attempt for cell in cells for attempt in cell['attempts']]
    usage = {key: sum(attempt['usage'][key] for attempt in attempts)
             for key in ('input_tokens', 'output_tokens', 'total_tokens')}
    if (cal['requests'] != len(attempts) or cal['responses'] != len(attempts)
            or not cal['complete_usage'] or cal['unknown_usage_requests']
            or usage['input_tokens'] != cal['known_input_tokens']
            or usage['output_tokens'] != cal['known_output_tokens']
            or usage['total_tokens'] != cal['total_tokens']):
        raise ValueError('actual usage accounting differs')
    value = {
        'schema': 'hepta.p7.integrated-v13-actual-summary.v1',
        'source_commit': HEAD, 'source_tree': TREE,
        'source_and_tools_unchanged': all(report['source_commit'] == HEAD
            and all(report[key] for key in ('source_unchanged', 'tools_unchanged', 'model_unchanged'))
            for report in (cap, cal)),
        'capacity': {'passed': cap['complete'], 'controls': len(cap['rows']),
            'controls_passed': sum(row['passed'] for row in cap['rows']),
            'CLI_tokenizer_calls': cap['independent_cli_tokenizer']['calls'],
            'CLI_token_ids_all_match': cap['independent_cli_tokenizer']['all_matched'],
            'model_generation_requests': cap['model_requests'],
            'references_are_model_successes': False},
        'calibration': {'tasks': len(cells), 'correct': sum(cell['correct'] for cell in cells),
            'eligible': cal['calibration_eligible'], 'requests': cal['requests'], 'responses': cal['responses'],
            'usage': usage, 'complete_usage': cal['complete_usage'],
            'unknown_usage_requests': cal['unknown_usage_requests'],
            'human_answer_repairs': cal['human_answer_repairs'],
            'terminal_hidden_calls': cal['terminal_hidden_calls'],
            'actual_attempt_statuses': dict(Counter(a['status'] for a in attempts)),
            'all_actual_wire_checks_selection_first': all(a.get('decoder_wire_check', {}).get('selection_before_replacement') is True
                                                        for a in attempts),
            'cells': [{'id': cell['id'], 'correct': cell['correct'],
                       'statuses': [a['status'] for a in cell['attempts']],
                       'diagnostics': [a.get('evaluation', {}).get('error') for a in cell['attempts']] for cell in cells]},
        'main': {'CLI_invoked': True, 'returncode': receipts['main']['returncode'],
                 'startup_refused': True, 'engine_constructed': False,
                 'output_directory_created': False, 'attempted_cells': 0, 'generation_requests': 0},
        'costs': {'outer_wall_ns': {phase: receipt['outer_wall_ns'] for phase, receipt in receipts.items()},
                  'inner_experiment_wall_ns': {'capacity': cap['experiment_wall_ns'], 'calibration': cal['experiment_wall_ns']},
                  'inner_costs_included_in_outer_do_not_add': True,
                  'new_model_acquisition_performed': False,
                  'full_human_and_agent_development_review_cost': None,
                  'unknown_cost_treated_as_zero': False},
        'historical_results_reused_as_fresh': False,
        'adaptive_same_task_interface_followup': True,
        'new_independent_task_holdout': False,
        'public_preregistration_claimed': False,
        'AI_development_or_maintenance_advantage_proved': False,
        'model_weights_added_to_evidence': False,
        'receipts': {phase: identity(BASE / 'operations' / (phase.upper() + '_EXECUTION.json'))
                     for phase in receipts},
        'capacity_report': identity(BASE / 'capacity/CAPACITY.json'),
        'calibration_report': identity(BASE / 'calibration/RESULT.json'),
        'protocol': identity(ROOT / 'hepta-integration/experiments/hia_agent_toolstudy_v13_20261030/PROTOCOL.json'),
        'historical_3533_plan': {'source_head': '3533b95c53d23de2d22c91fcc05cb601b8448eb3',
                                 'capacity_executions': 0, 'model_requests': 0},
        'summary_creation_does_not_execute_model_or_native': True,
    }
    if not value['source_and_tools_unchanged']:
        raise ValueError('source/tool final identity differs')
    output.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'output': identity(output), 'calibration': value['calibration'], 'costs': value['costs']}))


if __name__ == '__main__':
    main()
