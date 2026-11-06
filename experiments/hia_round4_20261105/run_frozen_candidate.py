"""One fresh proof, independent replay, then the unchanged 36-command campaign.

Run from a committed checkout with an explicitly selected commit. This observer
does not repair source, retry failed commands, change qualification budgets, or
convert a successful experiment into a positive performance conclusion.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
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


def _proc_stat(path):
    raw = path.read_text()
    fields = raw.rsplit(')', 1)[1].split()
    if len(fields) < 20:
        raise ValueError('incomplete process-group observation')
    return int(raw.split('(', 1)[0]), fields


def _proc_nspid(path):
    rows = [line.partition(':')[2].split() for line in path.read_text().splitlines()
            if line.startswith('NSpid:')]
    if len(rows) != 1 or not rows[0] or any(not value.isdigit() for value in rows[0]):
        raise ValueError('unavailable process PID-namespace identity')
    return tuple(map(int, rows[0]))


def _owned_proc_leader(leader, deadline):
    """Map our unreaped direct child into the mounted procfs PID namespace.

    A container may expose an ancestor's /proc: syscall PID 6 need not mean
    /proc/6. The kernel's pidfd fdinfo binds the owned syscall PID to procfs
    coordinates. Parent, namespace depth and session checks must agree; an
    unavailable mapping is never evidence that the process group is empty.
    """
    _owned_leader_exit(leader)
    parent, _ = _proc_stat(Path('/proc/self/stat'))
    namespace = _proc_nspid(Path('/proc/self/status'))
    if namespace[0] != parent or namespace[-1] != os.getpid():
        raise ValueError('observer procfs PID namespace cannot be authenticated')
    descriptor = os.pidfd_open(leader)
    try:
        identity = Path('/proc/self/fdinfo')/str(descriptor)
        child_namespace = _proc_nspid(identity)
        if len(child_namespace) != len(namespace) or child_namespace[-1] != leader:
            raise ValueError('owned child PID namespace differs from its observer')
        proc_leader = child_namespace[0]
        pid, fields = _proc_stat(Path('/proc')/str(proc_leader)/'stat')
        if (proc_leader <= 0 or pid != proc_leader or int(fields[1]) != parent
                or int(fields[2]) != proc_leader or int(fields[3]) != proc_leader):
            raise ValueError('owned leader procfs identity or session changed')
        # Keep both pidfd and WNOWAIT ownership during authentication. Only
        # syscall namespace IDs are passed to waitid/getpgid/getsid/killpg.
        _owned_leader_exit(leader)
        if os.getpgid(leader) != leader or os.getsid(leader) != leader:
            raise ValueError('owned syscall process-group session changed')
    finally:
        os.close(descriptor)
    if time.monotonic() >= deadline:
        raise subprocess.TimeoutExpired(['owned-process-group', str(leader)], 2)
    return proc_leader


def _owned_group_live(leader, deadline):
    """Observe same-session group members while the leader is still unreaped."""
    proc_leader = _owned_proc_leader(leader, deadline)
    live = []
    for entry in Path('/proc').iterdir():
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(['owned-process-group', str(leader)], 2)
        if not entry.name.isdigit() or int(entry.name) == proc_leader:
            continue
        try:
            pid, fields = _proc_stat(entry/'stat')
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(fields[2]) != proc_leader:
            continue
        if pid != int(entry.name) or int(fields[3]) != proc_leader:
            raise ValueError('owned process-group session changed')
        if fields[0] not in ('Z', 'X'):
            live.append(pid)
    _owned_leader_exit(leader)
    return live


def _owned_leader_exit(leader):
    # WNOWAIT retains the direct child's PID and therefore the group's identity.
    # ECHILD is an ownership failure; callers must not signal a recycled number.
    return os.waitid(os.P_PID, leader, os.WEXITED | os.WNOWAIT | os.WNOHANG)


def run_with_deadline(argv, budget, *, cwd=None, env=None, stdout=None, stderr=None,
                      capture_output=False, text=False):
    """Observe a Linux command and its original process group before reaping.

    Deadline failure is 124. A normally exited leader with a live same-group
    descendant is a terminal-contract failure, 125. Capture uses temporary
    files, matching actual step streams without a pipe-dependent terminal.
    Procfs can be mounted in an ancestor PID namespace; its group coordinates
    are authenticated against the owned child before treating a scan as empty.
    The leader remains unreaped through group cleanup, so no group signal uses
    a post-reap PGID. Two seconds bound cleanup; Z/X descendants are stopped,
    not claimed reaped. Detached descendants, external reapers and kernel tasks
    that cannot settle remain outside a general containment/recovery claim.
    """
    if (not sys.platform.startswith('linux') or not hasattr(os, 'WNOWAIT')
            or not hasattr(os, 'pidfd_open')
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise ValueError('exclusive Linux child ownership required')
    if type(budget) not in (int, float) or not math.isfinite(budget) or budget <= 0:
        raise ValueError('positive finite command deadline required')
    if capture_output and (stdout is not None or stderr is not None):
        raise ValueError('capture_output cannot be combined with stream targets')
    if not capture_output and (stdout == subprocess.PIPE or stderr == subprocess.PIPE):
        raise ValueError('use file-backed capture_output for this observer')
    with ExitStack() as files:
        captured = None
        if capture_output:
            captured = [files.enter_context(tempfile.TemporaryFile()) for _ in range(2)]
            stdout, stderr = captured
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                   text=text, start_new_session=True)
        deadline = time.monotonic() + budget
        cleanup_deadline = None
        anchor_available = True
        try:
            while True:
                exited = _owned_leader_exit(process.pid)
                now = time.monotonic()
                timed_out = now >= deadline
                if timed_out or exited is not None:
                    break
                time.sleep(min(0.005, deadline - now))
            cleanup_deadline = time.monotonic() + 2
            residual = not timed_out and bool(_owned_group_live(process.pid, cleanup_deadline))
            # Signal while the unreaped leader still prevents PGID reuse. This
            # includes a leader that already exited, regardless of stream type.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while True:
                exited = _owned_leader_exit(process.pid)
                live = _owned_group_live(process.pid, cleanup_deadline)
                residual = residual or bool(live)
                if exited is not None and not live:
                    break
                remaining = cleanup_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, 2)
                time.sleep(min(0.005, remaining))
            process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
        except ChildProcessError:
            anchor_available = False
            raise
        finally:
            # Failure to observe cleanup never becomes a successful terminal.
            # Reconfirm ownership before best-effort cleanup; never signal
            # after Popen has reaped the leader, even on an exceptional exit.
            if process.returncode is None and anchor_available:
                try:
                    _owned_leader_exit(process.pid)
                except ChildProcessError:
                    pass
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    end = cleanup_deadline if cleanup_deadline is not None else time.monotonic() + 2
                    process.wait(timeout=max(0, end - time.monotonic()))
        out = err = None
        if captured is not None:
            values = []
            for stream in captured:
                stream.seek(0)
                value = stream.read()
                if text:
                    value = value.decode(process.encoding, process.errors or 'strict')
                    value = value.replace('\r\n', '\n').replace('\r', '\n')
                values.append(value)
            out, err = values
        status = 124 if timed_out else 125 if residual else process.returncode
        return subprocess.CompletedProcess(argv, status, out, err)


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
            result = run_with_deadline(argv, budget, cwd=ROOT, env=env, stdout=out, stderr=err)
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
