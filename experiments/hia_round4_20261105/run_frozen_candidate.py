"""One fresh proof, independent replay, then the unchanged 36-command campaign.

Run from a committed checkout with an explicitly selected commit. This observer
does not repair source, retry failed commands, change qualification budgets, or
convert a successful experiment into a positive performance conclusion.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import qualify_hia_composition as composition


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def record(path):
    raw = Path(path).read_bytes()
    return {'path': str(Path(path).absolute()), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def write(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--base-launch-plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    cpus = parser.add_mutually_exclusive_group()
    cpus.add_argument('--proof-cpu', type=int)
    cpus.add_argument('--proof-cpus', default=None)
    args = parser.parse_args()
    started = time.monotonic_ns()
    if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE', '0') != '0':
        raise ValueError('assertions must remain enabled')
    output = args.output.absolute()
    if output.exists() or output.is_relative_to(ROOT):
        raise ValueError('fresh output outside the checkout required')
    template = json.loads(args.base_launch_plan.read_bytes())
    source = composition.source_identity()
    if source['commit'] != args.expected_head:
        raise ValueError('explicit commit differs from actual checkout')
    tool_args = argparse.Namespace(**{
        name: template['argv'][template['argv'].index('--' + name.replace('_', '-')) + 1]
        for name in ('cargo', 'cc', 'clang', 'clangxx', 'lean', 'rustc', 'source_rustc')})
    tools = composition.tool_identity(tool_args)
    if tools != template['fresh_tool_identity']:
        raise ValueError('fixed toolchain differs from reviewed template')
    selected = ([args.proof_cpu] if args.proof_cpu is not None else
                [int(value) for value in (args.proof_cpus or '20,21').split(',')])
    if (not 1 <= len(selected) <= 2 or len(set(selected)) != len(selected)
            or not set(selected) <= os.sched_getaffinity(0)):
        raise ValueError('one or two distinct available proof CPUs required')
    output.mkdir(parents=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0', PYTHONOPTIMIZE='0')
    python = template['python']
    source_digest = sha256(canonical(source)).hexdigest()
    tool_digest = sha256(canonical(tools)).hexdigest()
    write(output / 'SOURCE.json', source)
    write(output / 'TOOLS.json', tools)
    write(output / 'REGISTRATION.json', {
        'schema': 'hepta.hia.round4-frozen-sequence.v2',
        'source_commit': source['commit'], 'source_tree': source['tree'],
        'source_identity_sha256': source_digest, 'tools_identity_sha256': tool_digest,
        'observer': record(__file__), 'base_launch_plan': record(args.base_launch_plan),
        'proof_cpus': selected, 'proof_hash_max_workers': 2, 'lean_threads': 1,
        'composition_cpus': [0, 1, 2, 3],
        'proof_budget_seconds': 600, 'independent_replay_budget_seconds': 600,
        'same_source_required': True, 'one_attempt_per_command': True,
        'exclusive_host': False, 'registered_unix_ns': time.time_ns(),
        'preparation_wall_ns': time.monotonic_ns() - started,
        'authority': 'DENY_ALL', 'safety_certificate': False})
    rows = []
    identity_errors = []

    def unchanged():
        try:
            return composition.source_identity() == source and composition.tool_identity(tool_args) == tools
        except Exception as error:
            identity_errors.append({'type': type(error).__name__, 'message': str(error)[:1000]})
            return False

    def step(name, argv, budget):
        if not unchanged():
            raise ValueError('source or tools changed before ' + name)
        directory = output / (name + '-outer')
        directory.mkdir()
        write(directory / 'LAUNCH.json', {'argv': argv, 'cwd': str(ROOT),
              'source_commit': source['commit'], 'source_tree': source['tree'],
              'budget_seconds': budget, 'registered_unix_ns': time.time_ns()})
        before = time.monotonic_ns()
        with (directory / 'stdout').open('xb') as out, (directory / 'stderr').open('xb') as err:
            result = subprocess.run(['/usr/bin/timeout', str(budget) + 's', *argv],
                cwd=ROOT, env=env, stdout=out, stderr=err)
        elapsed = time.monotonic_ns() - before
        stable = unchanged()
        row = {'name': name, 'returncode': result.returncode, 'elapsed_ns': elapsed,
               'source_and_tools_unchanged': stable,
               'stdout': record(directory / 'stdout'), 'stderr': record(directory / 'stderr'),
               'source_commit': source['commit'], 'source_tree': source['tree']}
        rows.append(row)
        write(directory / 'RESULT.json', row)
        print(json.dumps(row, sort_keys=True), flush=True)
        if result.returncode != 0 or not stable:
            raise ValueError('fresh command failed or identity changed: ' + name)

    report = {'schema': 'hepta.hia.round4-frozen-sequence.v2', 'passed': False,
              'source_commit': source['commit'], 'source_tree': source['tree'],
              'all_seven_research_targets_closed': False, 'authority': 'DENY_ALL',
              'safety_certificate': False, 'exclusive_host': False}
    try:
        proof = output / 'proof'
        command = ['taskset', '-c', ','.join(map(str, selected)), python, '-u', '-B', '-m',
                   'tools.check_core_seven_shared', '--output-directory', str(proof)]
        step('proof', command + ['--lean', tools['lean']['path']], 600)
        step('independent-replay', command + ['--replay'], 600)
        proof_result = json.loads((proof / 'RESULT.json').read_bytes())
        if (proof_result.get('status') != 'passed' or proof_result.get('invocations') != 11
                or proof_result.get('kernel_core_syntax_connection_checked') is not True
                or len(proof_result.get('stage_receipt_sha256', [])) != 11):
            raise ValueError('full eleven-stage proof receipt required')
        release = {'schema': 'hepta.hia.same-source-proof-release.v1', 'authorized': True,
            'source_commit': source['commit'], 'source_tree': source['tree'],
            'fresh_local_full_acceptance_passed': True, 'independent_desktop_replay_passed': True,
            'files': [record(path) for path in sorted(proof.rglob('*')) if path.is_file()]
                + [record(output / (name + '-outer') / 'RESULT.json')
                   for name in ('proof', 'independent-replay')],
            'no_budget_increase': True, 'no_kernel_stage_rerun': True,
            'scope': 'Narrow syntax connection only; all twelve wider production obligations remain unproved.'}
        observer = ROOT / 'experiments/hia_round4_20261105/composition_observer.py'
        plan = dict(template)
        plan.update(source={'commit': source['commit'], 'tree': source['tree']},
            cwd=str(ROOT), output_prefix=str(output / 'composition'),
            observer_path=str(observer), observer_sha256=record(observer)['sha256'],
            fresh_tool_identity=tools, release=release, same_source_retained=True,
            composition_entry_sha256=record(ROOT / 'tools/qualify_hia_composition.py')['sha256'],
            registration_unix_ns=time.time_ns(),
            explicit_environment={key: env[key] for key in ('PYTHONDONTWRITEBYTECODE', 'PYTHONHASHSEED', 'PYTHONOPTIMIZE')},
            concurrent_work_scope='Shared host; fixed CPU0-3. No universal performance conclusion.',
            historical_preparation={'cache_acquisition_cost_ns': None, 'human_effort_cost_ns': None,
                'prior_template': record(args.base_launch_plan),
                'accounting': 'This sequence separately measures fresh proof, replay and composition. Historical cache acquisition remains unknown; nested clocks are never added twice.'},
            plan_revision_note='Fresh source, proof and independently replayed evidence; original36 commands,34 flags and all qualification budgets retained.')
        plan['argv'] = list(template['argv'])
        plan['argv'][plan['argv'].index('--output') + 1] = str(output / 'composition')
        plan_path = output / 'composition.launch-plan.json'
        write(plan_path, plan)
        step('composition', [python, '-u', '-B', str(observer), str(plan_path), record(plan_path)['sha256']], 10800)
        actual = json.loads((output / 'composition.outer.json').read_bytes())
        if actual.get('successful_process_and_source_identity') is not True:
            raise ValueError('complete composition observer receipt required')
        report['passed'] = True
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        report.update(commands=rows, elapsed_ns=time.monotonic_ns() - started,
            cost_accounting='Sequence wall includes nested command walls; do not add them twice. Historical acquisition, human and energy costs are unknown.',
            source_and_tools_unchanged=unchanged())
        report['identity_errors'] = identity_errors
        report['passed'] = report['passed'] and report['source_and_tools_unchanged']
        write(output / 'RESULT.json', report)
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
