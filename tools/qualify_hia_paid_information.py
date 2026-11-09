#!/usr/bin/env python3
"""Record finite paid-information controls, separately from empirical value."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.hia_ndu_feedback_20261106.paid_probe import (
    State, plan, observe, independent_policy_oracle, witness_problems,
)


def identity():
    paths = [Path(__file__), ROOT/'experiments/hia_ndu_feedback_20261106/paid_probe.py',
             ROOT/'experiments/hia_ndu_feedback_20261106/model.py',
             ROOT/'experiments/hia_ndu_feedback_20261106/native.py']
    return {'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'status': subprocess.check_output(['git', 'status', '--porcelain=v1'], cwd=ROOT, text=True),
            'files': {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in paths}}


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def cpu():
    return {n: round((r.ru_utime+r.ru_stime)*1e9) for n, r in
        ((n, resource.getrusage(k)) for n, k in (('parent', resource.RUSAGE_SELF), ('children', resource.RUSAGE_CHILDREN)))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--mode', choices=['reference', 'native'], required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    if args.mode == 'native' and not (args.binary and args.manifest):
        parser.error('native requires original binary and build manifest')
    if args.mode == 'reference' and (args.binary or args.manifest):
        parser.error('reference mode accepts no native artifacts')
    output, before = args.output.resolve(), identity()
    if output.is_relative_to(ROOT) or before['head'] != args.expected_head or before['status']:
        parser.error('require new external evidence directory and exact clean expected head')
    output.mkdir(parents=True, exist_ok=False)
    problems = witness_problems()
    expected_actions = ['read', 'abstain', 'abstain', 'read-a']
    write(output/'protocol.json', dict(source=before, mode=args.mode,
        problems=[p.public() for p in problems], expected_actions=expected_actions,
        failure_policy='retain failure and stop; no retry or reference substitution',
        scope='authored finite model; supplied likelihoods and fees; no independent user tasks',
        provider_calls=0, training_runs=0, monetary_cost=None))
    report = dict(status='started', mode=args.mode, cases=[], native_calls=0, authority='DENY_ALL',
                  ndu_increment_established=False, economic_benefit_established=False)
    backend = None
    started, cpu_start = time.monotonic_ns(), cpu()
    try:
        if args.mode == 'native':
            from experiments.hia_ndu_feedback_20261106.native import NativeValueBackend
            backend = NativeValueBackend(args.binary, args.manifest, log=output/'native.jsonl')
        for index, problem in enumerate(problems):
            row = dict(name=problem.name, status='started')
            report['cases'].append(row)
            state = State((), problem.budget)
            row['no_observation'] = plan(problem, state, depth=0)
            row['one_step_voi'] = plan(problem, state, depth=1)
            full = row['same_objective'] = plan(problem, state)
            oracle = row['independent_policy_tree'] = independent_policy_oracle(problem, state)
            if (full['selected_action'] != expected_actions[index]
                    or (full['selected_action'], full['value_q32']) != (oracle['selected_action'], oracle['value_q32'])):
                raise ValueError('registered choice or independent full policy control disagrees')
            if backend is not None:
                native = row['native'] = plan(problem, state, backend=backend, require_native=True)
                if native['candidate_values_q32'] != full['candidate_values_q32']:
                    raise ValueError('native and strong same-objective control disagree')
            row['status'] = 'passed'
        first = problems[0]
        report['signal_continuations'] = [plan(first, observe(first, State((), first.budget), 'read', s),
            backend=backend, require_native=backend is not None) for s in (0, 1)]
        if identity() != before:
            raise ValueError('execution source changed')
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error))
    finally:
        if backend is not None:
            try:
                backend.close()
                report.update(native_calls=backend.calls, native_returncode=backend.returncode)
                if backend.returncode != 0:
                    report['status'] = 'failed'
            except Exception as error:
                report.update(status='failed', close_error=str(error))
        after_cpu = cpu()
        report['outer_wall_ns'] = time.monotonic_ns()-started
        report['outer_cpu_ns'] = {k: after_cpu[k]-cpu_start[k] for k in cpu_start}
        report['cost_scope'] = 'all planning, controls, failures and native start/close; excludes prior builds/acquisition, authorship, final persistence and upload'
        write(output/'result.json', report)
    print(json.dumps({k: report[k] for k in ('status', 'mode', 'native_calls', 'ndu_increment_established')}))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
