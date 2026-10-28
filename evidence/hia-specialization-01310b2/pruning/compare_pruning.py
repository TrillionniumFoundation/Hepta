"""Replay controller costs only; not an optimization/runtime speedup claim."""
from pathlib import Path
from hashlib import sha256
import importlib.util
import json
import statistics
import sys
import time

ROOT = Path('/workspace/scratch/bf7d454bbc83')
SOURCE = ROOT / 'hepta-ndu-next'
PRIOR = ROOT / 'hepta-integrated'
CAMPAIGN = ROOT / 'hia-specialization-frozen-01310b2'
OUTPUT = ROOT / 'hia-pruning-replay-01310b2'


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main():
    OUTPUT.mkdir(mode=0o700)
    campaign = json.loads((CAMPAIGN / 'RESULT.json').read_text())
    identities = {
        'previous_ranker': digest(PRIOR / 'hepta/hia_ndu_optimizer.py'),
        'current_ranker': digest(SOURCE / 'hepta/hia_ndu_optimizer.py'),
        'shared_current_validator': digest(SOURCE / 'hepta/hia_translation_validation.py'),
        'shared_current_core': digest(SOURCE / 'hepta/hia_program.py'),
        'observations_source_result': digest(CAMPAIGN / 'RESULT.json'),
        'bridge': digest(CAMPAIGN / 'ndu-target/debug/hia-ndu-bridge'),
        'build_receipt': digest(CAMPAIGN / 'ndu-build/build-receipt.json'),
        'replay_script': digest(__file__),
    }
    protocol = {
        'schema': 'hepta.hia.preproof-pruning-replay.v1',
        'previous_ranker_revision': '817713b163b6812a6516179951412b4a6c93ae2b',
        'current_ranker_revision': '01310b2e6c1676e73cd0f338fcf0b8bf072d3fe4',
        'profiles': list(campaign['protocol']['profiles']), 'repetitions': 3,
        'order': 'current/previous on even repetition+profile index; previous/current on odd',
        'pairs': 9, 'native_ranking_calls': 18, 'proof_timeout_ms': 5000,
        'primary_metric': 'median paired reduction in actual rank_candidates call wall time',
        'non_claims': ['whole_pipeline_speedup', 'native_workload_speedup', 'NDU_selector_incremental_value'],
        'shared_inputs': 'same canonical baseline, two proposals, frozen native observations, objective, bridge and CURRENT validator/core in both arms',
        'isolation': 'only the ranker Python module differs; previous source is loaded read-only from frozen baseline worktree',
        'source_sha256': identities,
    }
    dump(OUTPUT / 'PROTOCOL.json', protocol)
    import hepta.hia_ndu_optimizer as current
    name = 'hepta.hia_ndu_optimizer_previous_for_pruning_replay'
    spec = importlib.util.spec_from_file_location(name, PRIOR / 'hepta/hia_ndu_optimizer.py')
    previous = importlib.util.module_from_spec(spec)
    sys.modules[name] = previous
    spec.loader.exec_module(previous)
    assert previous.validate_translation is current.validate_translation
    assert previous.verify_program is current.verify_program
    bridge = {'binary': CAMPAIGN / 'ndu-target/debug/hia-ndu-bridge',
              'build_receipt': CAMPAIGN / 'ndu-build/build-receipt.json'}
    objective = {'expected_calls': campaign['protocol']['holdout_calls'],
        'resource_cap_ns': campaign['protocol']['resource_cap_ns'],
        'target': campaign['protocol']['target'],
        'measurement_profile': campaign['protocol']['measurement_profile']}
    rows = []
    modules = {'previous': previous, 'current': current}
    for repetition in range(protocol['repetitions']):
        for index, profile in enumerate(protocol['profiles']):
            order = ['current', 'previous'] if (repetition + index) % 2 == 0 else ['previous', 'current']
            for arm in order:
                row = {'arm': arm, 'profile': profile, 'repetition': repetition, 'status': 'failed'}
                started = time.perf_counter_ns()
                try:
                    row['decision'] = modules[arm].rank_candidates(campaign['baseline'], campaign['candidates'],
                        campaign['observations'][profile], function='calculate', bridge=bridge,
                        objective=objective, timeout_ms=protocol['proof_timeout_ms'])
                    decision = row['decision']
                    row.update(status='completed', selected_id=decision['selected_id'],
                        proof_attempts=sum(c['proof'] is not None for c in decision['candidate_reports'])
                            + int(decision['selected_fresh_proof'] is not None),
                        native_called='native_response' in decision)
                except Exception as error:
                    row['error'] = f'{type(error).__name__}: {error}'
                row['wall_ns'] = time.perf_counter_ns() - started
                rows.append(row)
                with (OUTPUT / 'CALLS.jsonl').open('a') as stream:
                    stream.write(json.dumps(row, sort_keys=True) + '\n')
    pairs = []
    for repetition in range(protocol['repetitions']):
        for profile in protocol['profiles']:
            matched = {r['arm']: r for r in rows if r['profile'] == profile and r['repetition'] == repetition}
            pairs.append({'profile': profile, 'repetition': repetition,
                          'reduction_ns': matched['previous']['wall_ns'] - matched['current']['wall_ns']})
    result = {'protocol': protocol, 'calls': rows, 'pairs': pairs,
        'summary': {arm: {'calls': sum(r['arm'] == arm for r in rows),
            'median_wall_ns': statistics.median(r['wall_ns'] for r in rows if r['arm'] == arm),
            'proof_attempts': sum(r.get('proof_attempts', 0) for r in rows if r['arm'] == arm),
            'native_calls': sum(r.get('native_called', False) for r in rows if r['arm'] == arm),
            'abstentions': sum(r.get('selected_id') == 'abstain' for r in rows if r['arm'] == arm)}
            for arm in modules},
        'median_paired_reduction_ns': statistics.median(row['reduction_ns'] for row in pairs),
        'qualified_for_controller_cost_replay': len(rows) == 18 and all(r['status'] == 'completed' for r in rows),
        'whole_pipeline_speedup_claimed': False, 'ndu_incremental_value_claimed': False}
    result['source_inputs_unchanged'] = identities == {
        'previous_ranker': digest(PRIOR / 'hepta/hia_ndu_optimizer.py'),
        'current_ranker': digest(SOURCE / 'hepta/hia_ndu_optimizer.py'),
        'shared_current_validator': digest(SOURCE / 'hepta/hia_translation_validation.py'),
        'shared_current_core': digest(SOURCE / 'hepta/hia_program.py'),
        'observations_source_result': digest(CAMPAIGN / 'RESULT.json'),
        'bridge': digest(CAMPAIGN / 'ndu-target/debug/hia-ndu-bridge'),
        'build_receipt': digest(CAMPAIGN / 'ndu-build/build-receipt.json'),
        'replay_script': digest(__file__),
    }
    result['qualified_for_controller_cost_replay'] &= result['source_inputs_unchanged']
    dump(OUTPUT / 'RESULT.json', result)
    print(json.dumps({k: result[k] for k in ('summary', 'median_paired_reduction_ns',
        'qualified_for_controller_cost_replay', 'source_inputs_unchanged')}, indent=2))
    return 0 if result['qualified_for_controller_cost_replay'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
