"""Explicit CLI for new, append-only cross-file study artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from experiments.agent_eval.harness import Budget
from experiments.agent_eval.sandbox import probe_sandbox
from .plan import make_plan, verify_plan
from .qualification import qualify_fixtures
from .workspace_qualification import qualify_workspace
from .workspace_crash_qualification import qualify_workspace_crashes
from .records import cost_record, seal_record, write_append_only
from .reporting import compare
from .runner import evaluate, replay
from .tasks import ARMS, TASK_IDS, verify_manifest


def read(path):
    return json.loads(Path(path).read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for name in ('verify', 'probe'):
        command = sub.add_parser(name)
        command.add_argument('--output')
    plan = sub.add_parser('plan')
    plan.add_argument('--models', required=True, help='JSON array of at least two exact provider/name/revision identities')
    plan.add_argument('--budget')
    plan.add_argument('--adapter-configs', help='JSON array freezing one public adapter configuration per exact model')
    plan.add_argument('--replicates', type=int, default=1)
    plan.add_argument('--rustc')
    plan.add_argument('--output', required=True)
    run = sub.add_parser('run')
    run.add_argument('--plan', required=True)
    run.add_argument('--model-index', type=int, required=True)
    run.add_argument('--task', choices=TASK_IDS, required=True)
    run.add_argument('--arm', choices=ARMS, required=True)
    run.add_argument('--replicate', type=int, default=0)
    run.add_argument('--adapter-dir', required=True)
    run.add_argument('--command', required=True, help='JSON argv array, use {adapter}/script for the isolated copy')
    run.add_argument('--pass-env', action='append', default=[])
    run.add_argument('--network', action='store_true')
    run.add_argument('--rustc')
    run.add_argument('--output', required=True)
    comparison = sub.add_parser('compare')
    comparison.add_argument('--plan', required=True)
    comparison.add_argument('--reports', nargs='*', default=[])
    comparison.add_argument('--costs', nargs='*', default=[])
    comparison.add_argument('--output', required=True)
    qualify = sub.add_parser('qualify-fixtures')
    qualify.add_argument('--rustc')
    qualify.add_argument('--output', required=True)
    workspace = sub.add_parser('qualify-workspace', help='Actual production v4 fixture transactions inside strict namespaces')
    workspace.add_argument('--rustc')
    workspace.add_argument('--execution-context', default='unspecified_operator_environment',
                           help='Public operator annotation of the outer execution environment; not an attestation')
    workspace.add_argument('--output', required=True)
    crashes = sub.add_parser('qualify-workspace-crashes',
                             help='Actual pre/post publication child deaths for all five tasks, in strict namespaces')
    crashes.add_argument('--rustc')
    crashes.add_argument('--execution-context', default='unspecified_operator_environment',
                         help='Public operator annotation of the outer execution environment; not an attestation')
    crashes.add_argument('--output', required=True)
    cost = sub.add_parser('cost')
    cost.add_argument('--run', required=True)
    cost.add_argument('--human-seconds', type=float)
    cost.add_argument('--human-observer')
    cost.add_argument('--usd', type=float)
    cost.add_argument('--price-source')
    cost.add_argument('--note', default='')
    cost.add_argument('--output', required=True)
    replay_parser = sub.add_parser('replay')
    replay_parser.add_argument('--run', required=True)
    replay_parser.add_argument('--rustc')
    replay_parser.add_argument('--trusted-fixture', action='store_true')
    replay_parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    if args.output and Path(args.output).exists():
        print(json.dumps({'status': 'rejected', 'error': 'E_OUTPUT_EXISTS: append-only records require a new output path'}))
        return 2
    try:
        if args.operation == 'verify': result = {'ok': True, 'manifest': verify_manifest()}
        elif args.operation == 'probe': result = probe_sandbox()
        elif args.operation == 'plan':
            result = make_plan(read(args.models), Budget(**read(args.budget)) if args.budget else None,
                               args.replicates, rustc=args.rustc,
                               adapter_configs=read(args.adapter_configs) if args.adapter_configs else None)
        elif args.operation == 'run':
            frozen = verify_plan(read(args.plan), rustc=args.rustc, current_environment=True)
            if not 0 <= args.model_index < len(frozen['models']): raise ValueError('E_MODEL: model-index outside plan')
            result = evaluate(args.task, args.arm, args.adapter_dir, read(args.command), frozen['models'][args.model_index],
                              plan=frozen, replicate=args.replicate, rustc=args.rustc, pass_env=args.pass_env, network=args.network)
        elif args.operation == 'compare':
            result = compare(read(args.plan), [read(p) for p in args.reports], [read(p) for p in args.costs])
        elif args.operation == 'qualify-fixtures': result = qualify_fixtures(args.rustc)
        elif args.operation == 'qualify-workspace':
            result = qualify_workspace(args.rustc, execution_context=args.execution_context)
        elif args.operation == 'qualify-workspace-crashes':
            result = qualify_workspace_crashes(args.rustc, execution_context=args.execution_context)
        elif args.operation == 'cost':
            result = cost_record(read(args.run), human_seconds=args.human_seconds, human_observer=args.human_observer,
                                 monetary_cost_usd=args.usd, price_source=args.price_source, note=args.note)
        else: result = replay(read(args.run), rustc=args.rustc, trusted_fixture=args.trusted_fixture)
    except (ValueError, TypeError, OSError, KeyError) as exc:
        result = seal_record({'schema': 'hepta.crossfile_error.v1', 'status': 'rejected', 'error': str(exc)})
    if args.output:
        destination = write_append_only(args.output, result)
        print(json.dumps({'output': destination, 'status': result.get('status', 'ok')}))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result.get('status') in {'rejected', 'attempt_failed', 'environment_blocked', 'qualification_failed', 'not_qualified'} else 0


if __name__ == '__main__':
    sys.exit(main())
