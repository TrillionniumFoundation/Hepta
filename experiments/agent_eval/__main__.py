"""python -m experiments.agent_eval --help"""
import argparse
import json
from pathlib import Path
import sys

from hepta.ast import HeptaError

from .harness import Budget, compare, evaluate, make_plan, replay, verify_plan
from .qualification import qualify_fixtures
from .sandbox import probe_sandbox
from .tasks import TASK_IDS, LANGUAGES, verify_manifest


def read(path):
    return json.loads(Path(path).read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(description='Frozen paired Hepta/Rust agent pilot; no provider is selected automatically.')
    subs = parser.add_subparsers(dest='operation', required=True)
    for name in ('verify', 'probe'):
        sub = subs.add_parser(name)
        sub.add_argument('--output')
    plan = subs.add_parser('plan', help='Freeze a full paired matrix before any model runs')
    plan.add_argument('--models', required=True, help='JSON file: list of exact provider/name/revision objects')
    plan.add_argument('--budget', help='JSON file with Budget fields; defaults are documented')
    plan.add_argument('--replicates', type=int, default=1)
    plan.add_argument('--output', required=True)
    run = subs.add_parser('run', help='Run a supplied provider adapter with strict namespace isolation')
    run.add_argument('--plan', required=True)
    run.add_argument('--model-index', type=int, required=True)
    run.add_argument('--task', choices=TASK_IDS, required=True)
    run.add_argument('--language', choices=LANGUAGES, required=True)
    run.add_argument('--replicate', type=int, default=0)
    run.add_argument('--adapter-dir', required=True)
    run.add_argument('--command', required=True, help='JSON file with argv; use {adapter} for the copied adapter directory')
    run.add_argument('--rustc')
    run.add_argument('--pass-env', action='append', default=[], help='Explicit variable name; values are never recorded')
    run.add_argument('--network', action='store_true', help='Explicitly allow the adapter to reach its configured provider')
    run.add_argument('--output', required=True)
    comparison = subs.add_parser('compare')
    comparison.add_argument('--plan', required=True)
    comparison.add_argument('reports', nargs='+')
    comparison.add_argument('--output')
    qualification = subs.add_parser('qualify-fixtures', help='Run deterministic scripts and trusted native solutions, not AI models')
    qualification.add_argument('--rustc')
    qualification.add_argument('--output', required=True)
    replay_parser = subs.add_parser('replay', help='Re-score a saved candidate without calling a provider')
    replay_parser.add_argument('--run', required=True)
    replay_parser.add_argument('--rustc')
    replay_parser.add_argument('--trusted-fixture', action='store_true')
    replay_parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    if args.output and Path(args.output).exists():
        print(json.dumps({'status': 'rejected', 'error': 'E_OUTPUT_EXISTS: reports and plans are append-only; choose a new path'}))
        return 2
    try:
        if args.operation == 'verify': result = {'ok': True, 'manifest': verify_manifest()}
        elif args.operation == 'probe': result = probe_sandbox()
        elif args.operation == 'plan':
            result = make_plan(read(args.models), Budget(**read(args.budget)) if args.budget else Budget(), args.replicates)
        elif args.operation == 'run':
            plan_data = verify_plan(read(args.plan))
            if not 0 <= args.model_index < len(plan_data['models']):
                raise ValueError('E_MODEL: model-index is outside the frozen plan')
            result = evaluate(args.task, args.language, args.adapter_dir, read(args.command),
                              plan_data['models'][args.model_index], plan=plan_data,
                              replicate=args.replicate, rustc=args.rustc,
                              pass_env=args.pass_env, network=args.network)
        elif args.operation == 'compare': result = compare(read(args.plan), [read(path) for path in args.reports])
        elif args.operation == 'replay': result = replay(read(args.run), rustc=args.rustc, trusted_fixture=args.trusted_fixture)
        else: result = qualify_fixtures(args.rustc)
    except (ValueError, OSError, KeyError, TypeError, HeptaError) as exc:
        result = {'schema': 'hepta.agent_error.v1', 'status': 'rejected', 'error': str(exc)}
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x') as stream:
            stream.write(rendered)
        print(json.dumps({'output': str(output.resolve()), 'status': result.get('status', 'ok')}))
    else: print(rendered, end='')
    return 2 if result.get('status') in {'rejected', 'environment_blocked', 'qualification_failed', 'not_qualified'} else 0


if __name__ == '__main__':
    sys.exit(main())
