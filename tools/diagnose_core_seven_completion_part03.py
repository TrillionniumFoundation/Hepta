"""Bounded completion-barrier Part03 observation; execution and replay always exit nonzero.

Exactly four hardened parents and one marked PTY target. No retry, sixth slot,
workflow activation or target admission. Activation requires separate review.
"""
import ctypes
import os
from pathlib import Path
import sys
import time
import uuid
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import core_seven_completion_part03_plan as p
from tools import core_seven_completion_part03_replay as replay
from tools import core_seven_completion_part03_capture as target_capture
from tools import core_seven_acceptance_capture as parent_capture
from tools.check_guarded_slice_lean import require


class Failure(ValueError):
    def __init__(self, code, status=None):
        super().__init__(code)
        self.code, self.status = code, status


def sync_file(root, name):
    parent, leaf = root._parent(name)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def finalize(root, snapshot, result):
    """Exclusive pending write then atomic no-replace publication, never retry."""
    p.validate_result(result)
    raw = p.encode(result)
    require(len(raw) <= p.cap('RESULT.pending.json'), 'result bound')
    actual = {name: snapshot.read(name, mutable=name in p.TERMINALS)
              for name in root.scan(p.FIXED_FILES)}
    # Reserve the complete candidate before any positive write. Existing
    # pending/result/footer bytes remain charged, never replaced in accounting.
    p.budgets({**actual, 'RESULT.pending.json': actual.get('RESULT.pending.json', raw),
               'RESULT.json': actual.get('RESULT.json', raw)})
    root.write('RESULT.pending.json', raw)
    sync_file(root, 'RESULT.pending.json')
    require(snapshot.read('RESULT.pending.json', mutable=True) == raw, 'pending readback')
    snapshot.check_directories()
    actual = {name: snapshot.read(name, mutable=name in p.TERMINALS)
              for name in root.scan(p.FIXED_FILES)}
    # Charge both real copies when present. A preexisting destination is still
    # left untouched by RENAME_NOREPLACE, never silently removed or replaced.
    p.budgets({**actual, 'RESULT.json': actual.get('RESULT.json', raw)})
    # os.replace can overwrite an attacker-created result. Linux RENAME_NOREPLACE
    # gives the required single atomic installation without that race.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(root.fd, b'RESULT.pending.json', root.fd, b'RESULT.json', 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    os.fsync(root.fd)
    require(snapshot.read('RESULT.json', mutable=True) == raw, 'result readback')


def failure_footer(root, snapshot, run_id, files):
    hashes, state = {}, 'absent'
    for name in ('RESULT.json', 'RESULT.pending.json'):
        try:
            if os.path.lexists(root.path / name):
                hashes[name] = p.digest(snapshot.read(name, mutable=True))
                if state != 'uncertain':
                    state = 'present'
        except Exception:
            state = 'uncertain'
    value = dict(**p.common(run_id), status='container_invalid', error_code='finalization_failed',
        phase='finalization', result_sha256=hashes.get('RESULT.json'), pending_sha256=hashes.get('RESULT.pending.json'),
        run_sha256=p.digest(files['RUN.json']) if 'RUN.json' in files else None,
        artifact_state=state, **p.flags())
    p.validate_failure_footer(value)
    actual = {n: snapshot.read(n, mutable=n in p.TERMINALS) for n in root.scan(p.FIXED_FILES)}
    p.budgets({**actual, 'FAILURE.json': p.encode(value)})
    root.write('FAILURE.json', p.encode(value))
    sync_file(root, 'FAILURE.json')


def diagnose(lean, output_directory):
    origin = time.monotonic_ns()
    launch_deadline, outer_deadline = origin + p.BUDGETS['launch_ns'], origin + 600_000_000_000
    run_id = uuid.uuid4().hex + uuid.uuid4().hex
    root = snapshot = external = identity = plan = run = None
    files, receipts, accepted = {}, [], {}
    phase, current, captured, terminal = 'preparation', None, None, None
    invocations = slots = 0
    launch_state = 'not_attempted'
    validated_sources = None

    def wall():
        value = time.monotonic_ns() - origin
        p.integer(value, 0, 600_000_000_000)
        return value

    def write(name, raw):
        require(name in p.FROZEN_FILES and name not in files, 'exclusive fixed artifact')
        p.budgets({**files, name: raw})
        root.write(name, raw)
        sync_file(root, name)
        require(snapshot.read(name) == raw, 'artifact readback')
        files[name] = raw

    def write_json(name, value):
        write(name, p.encode(value))

    def state(extra=()):
        try:
            external.check()
        except Exception as exc:
            raise Failure('identity_changed') from exc
        try:
            actual = root.scan(p.FIXED_FILES)
            require(set(files) <= set(actual) <= set(files) | set(extra), 'unexpected file set')
            require(all(snapshot.read(name) == raw for name, raw in files.items()), 'frozen byte change')
            p.budgets({name: snapshot.read(name) for name in actual})
            require(time.monotonic_ns() < outer_deadline, 'outer deadline')
        except Exception as exc:
            raise Failure('filesystem_invalid') from exc

    def authenticated_prefix():
        nonlocal validated_sources
        # The semantic inverse is cached only after the actual persisted bytes
        # passed it. Every use first repeats full safe byte/membership/external
        # identity checks; unchanged bytes carry the same semantic validation.
        # Parent authority is never cached: all receipts/logs/modules replay here.
        state()
        if validated_sources is None:
            require(p.same(identity, external.identity(run_id)), 'actual external identity')
            restored, candidate, diagnostic, expected_plan = p.reconstruct_plan(
                snapshot, identity, external.executable, root.path)
            require(p.same(plan, expected_plan) and p.same(run, p.make_run(expected_plan)), 'regenerated plan/run')
            validated_sources = (restored, candidate, diagnostic)
        restored, candidate, diagnostic = validated_sources
        require(files['PLAN.json'] == p.encode(plan) and files['RUN.json'] == p.encode(run)
                and files['IDENTITY.json'] == p.encode(external.identity(run_id)), 'validated input commitments')
        p.base._support_imports(restored, identity['support'])
        checked = {}
        for index in range(len(receipts)):
            _, receipt = replay.validate_stage(snapshot, plan, run, plan['stages'][index], candidate.stages[index], checked)
            require(receipt == receipts[index], 'committed parent changed')
        require(p.same(checked, accepted), 'parent ancestry changed')
        return restored, candidate, diagnostic

    def gather():
        actual = root.scan(p.FIXED_FILES)
        result = {name: snapshot.read(name, mutable=name in p.TERMINALS) for name in actual if name not in p.TERMINALS}
        p.budgets(result)
        return result

    try:
        executable = Path(p.absolute(str(Path(lean).absolute())))
        destination = Path(p.absolute(str(Path(output_directory).absolute())))
        require(not os.path.lexists(destination), 'fresh output root required')
        external = p.External(executable)
        identity = external.identity(run_id)
        prepared, proposal, marked, plan = p.prepare_plan(identity, executable, destination)
        external.check()
        require(p.same(identity, external.identity(run_id)), 'preparation external identity changed')
        run = p.make_run(plan)
        p.base._support_imports(prepared, identity['support'])
        root = p.base.SafeRoot(destination)
        snapshot = p.Snapshot(root)
        # This order is part of the closed preparation-prefix contract.
        write_json('IDENTITY.json', identity)
        write('diagnostic-manifest.json', marked.manifest_json.encode())
        write_json('PLAN.json', plan)
        write_json('RUN.json', run)
        write('relocation-manifest.json', proposal.manifest_json.encode())
        source_bytes = {'original/' + s.name + '.lean': s.source.encode() for s in prepared['stages']}
        for stage, source in zip(plan['stages'], proposal.stages):
            source_bytes[stage['retained_source_path']] = source.source.encode()
        source_bytes[plan['target']['source_path']] = marked.stages[4].source.encode()
        require(set(source_bytes) == set(p.SOURCE_FILES), 'exact retained sources')
        for name in sorted(source_bytes):
            write(name, source_bytes[name])
        authenticated_prefix()
        for index in range(4):
            phase, current, captured = 'prelaunch', index, None
            launch_state = 'not_attempted'
            stage, source = plan['stages'][index], proposal.stages[index]
            state()
            authenticated_prefix()
            remaining = launch_deadline - time.monotonic_ns()
            if remaining <= 0:
                raise Failure('launch_deadline', 'no_launch')
            start = p.started(plan, run, stage, accepted, remaining)
            try:
                write_json(stage['name'] + '.started.json', start)
            except Exception as exc:
                raise Failure('receipt_failed') from exc
            state()
            if time.monotonic_ns() >= launch_deadline:
                raise Failure('launch_deadline', 'no_launch')
            module_path = stage['source_path'][:-5] + '.olean'
            env = dict(os.environ)
            env.pop('LEAN_SRC_PATH', None)
            env['LEAN_PATH'], env['LEAN_SYSROOT'] = str(destination), str(executable.parent.parent)
            argv = [str(executable), '--root=' + str(destination), '-o', str(destination / module_path), str(destination / stage['source_path'])]
            phase, launch_state = 'capturing', 'spawn_outcome_uncertain'
            slots += 1
            captured = parent_capture.capture(argv, cwd=str(destination), env=env,
                stdout_path=destination / (stage['name'] + '.stdout'), stderr_path=destination / (stage['name'] + '.stderr'),
                raw_remaining=p.RAW_GLOBAL - sum(len(files.get(n, b'')) for n in p.LOG_FILES), launch_deadline_ns=launch_deadline)
            # Preserve confirmed creation before any fallible shape/clock check.
            # Only the exact boolean True establishes a confirmed process.
            observed_spawn = captured.get('process', {}).get('spawned')
            launch_state = ('spawned' if observed_spawn is True else
                'not_spawned' if observed_spawn is False and captured.get('error_code') in
                ('launch_deadline', 'filesystem_invalid') else 'spawn_outcome_uncertain')
            invocations += int(observed_spawn is True)
            p.validate_process(captured['process'])
            # The unchanged collector cannot distinguish an uncertain Popen
            # exception from definitely unspawned. It consumes a slot and stops.
            for stream in ('stdout', 'stderr'):
                name = stage['name'] + '.' + stream
                if os.path.lexists(destination / name):
                    files[name] = snapshot.read(name)
            if not captured['process']['spawned']:
                if launch_state == 'spawn_outcome_uncertain':
                    raise Failure('capture_incomplete', 'capture_incomplete')
                phase = 'prelaunch'
                raise Failure('launch_deadline' if captured['error_code'] == 'launch_deadline' else 'receipt_failed', 'no_launch')
            if captured['error_code'] is not None:
                raise Failure(captured['error_code'], 'parent_failed')
            phase = 'verifying'
            state((module_path,))
            p.validate_process(captured['process'], success=True)
            try:
                inventory = p.inventory(files[stage['name'] + '.stdout'], files[stage['name'] + '.stderr'], source)
            except Exception as exc:
                raise Failure('inventory_invalid', 'parent_failed') from exc
            try:
                module_raw = snapshot.read(module_path)
                require(module_raw, 'empty parent module')
                p.budgets({**files, module_path: module_raw})
            except Exception as exc:
                raise Failure('module_invalid', 'parent_failed') from exc
            logs = {stream: p.file_record(files[stage['name'] + '.' + stream]) for stream in ('stdout', 'stderr')}
            require(p.same(logs, captured['logs']), 'capture log binding')
            finish = dict(**p.common(run_id), index=index, name=stage['name'], started_sha256=p.commitment(start),
                status='stage_passed', process=captured['process'], logs=logs,
                inventory=dict(subject_count=len(inventory), inventory_sha256=p.commitment(inventory)),
                olean=dict(p.file_record(module_raw), source_sha256=source.source_sha256))
            phase = 'receipt_commit'
            try:
                write_json(stage['name'] + '.finished.json', finish)
            except Exception as exc:
                raise Failure('receipt_failed', 'parent_failed') from exc
            state((module_path,))
            _, receipt_hash = replay.validate_stage(snapshot, plan, run, stage, source, accepted)
            files[module_path] = module_raw
            receipts.append(receipt_hash)
        phase, current, captured, launch_state = 'target_prelaunch', 4, None, 'not_attempted'
        state()
        authenticated_prefix()
        remaining = launch_deadline - time.monotonic_ns()
        if remaining <= 0:
            raise Failure('launch_deadline', 'no_launch')
        start = p.started(plan, run, plan['target'], accepted, remaining)
        try:
            write_json(replay.TARGET + '.started.json', start)
        except Exception as exc:
            raise Failure('receipt_failed') from exc
        state()
        phase, launch_state = 'capturing', 'spawn_outcome_uncertain'
        slots += 1
        captured = target_capture.capture(root, plan, run, start,
            launch_deadline_ns=launch_deadline, outer_deadline_ns=outer_deadline)
        observed_spawn = captured.get('process', {}).get('spawned')
        launch_state = ('spawned' if observed_spawn is True else 'not_spawned'
            if observed_spawn is False and captured.get('launch_state') == 'not_spawned'
            else 'spawn_outcome_uncertain')
        invocations += int(observed_spawn is True)
        p.validate_process(captured['process'])
        require(launch_state == captured['launch_state'], 'collector launch state contradiction')
        terminal = captured['terminal']
        files = gather()
        if captured['status'] != 'diagnostic_completed':
            phase = 'target_prelaunch' if not captured['process']['spawned'] and launch_state != 'spawn_outcome_uncertain' else (
                'target_verifying' if captured['status'] == 'target_invalid' else 'capturing')
            if captured['status'] == 'finalization_failed':
                phase, current = 'finalization', None
            raise Failure(captured['error_code'], captured['status'])
        phase = 'target_verifying'
        checked_terminal, markers, _ = replay.validate_target(snapshot, plan, run, marked, proposal, accepted,
            p.RAW_GLOBAL - sum(len(files.get(n + '.' + s, b'')) for n in p.SCHEDULE[:4] for s in ('stdout', 'stderr')))
        require(p.same(checked_terminal, terminal), 'terminal replay differs')
        state()
        authenticated_prefix()
        phase, current = 'finalization', None
        result = replay.make_result(run_id, files, status='diagnostic_completed', phase=phase, error_code=None,
            failed_stage=None, invocations=invocations, launch_slots_used=slots, launch_state=launch_state,
            wall_ns=wall(), receipts=receipts, terminal=terminal, marker_count=len(markers))
        p.budgets({**files, 'RESULT.pending.json': p.encode(result), 'RESULT.json': p.encode(result)})
        finalize(root, snapshot, result)
        phase = 'replay'
        verified = replay.verify_evidence(destination)
        require(time.monotonic_ns() < outer_deadline, 'outer deadline during replay')
        return dict(result=verified.result, display=verified.display, exit_code=1, deadline_ns=outer_deadline)
    except Exception as exc:
        code = exc.code if isinstance(exc, Failure) else (
            'preparation_invalid' if phase == 'preparation' else 'finalization_failed' if phase == 'finalization'
            else 'replay_invalid' if phase == 'replay' else 'filesystem_invalid')
        status = exc.status if isinstance(exc, Failure) and exc.status else (
            'no_launch' if phase in ('preparation', 'prelaunch', 'target_prelaunch') else
            'finalization_failed' if phase == 'finalization' else 'replay_failed' if phase == 'replay' else 'capture_incomplete')
        if root is not None and current is not None and current < 4 and captured is not None:
            try:
                if captured['process']['spawned'] and stage['name'] + '.finished.json' not in root.scan(p.FIXED_FILES):
                    failed = dict(**p.common(run_id), index=current, name=stage['name'],
                        started_sha256=p.digest(files[stage['name'] + '.started.json']), status='stage_failed',
                        error_code=code, process=captured['process'], logs=captured['logs'], inventory=None, olean=None)
                    write_json(stage['name'] + '.finished.json', failed)
            except Exception:
                pass  # Existing/uncertain receipts are never overwritten.
        try:
            if root is not None:
                files = gather()
            marker_count = 0
            if terminal is not None and replay.safe_prefix(terminal):
                _, markers, _ = replay.validate_target(snapshot, plan, run, marked, proposal, accepted,
                    p.RAW_GLOBAL - sum(len(files.get(n + '.' + s, b'')) for n in p.SCHEDULE[:4] for s in ('stdout', 'stderr')))
                marker_count = len(markers)
            result = replay.make_result(run_id, files, status=status, phase=phase, error_code=code,
                failed_stage=current, invocations=invocations, launch_slots_used=slots, launch_state=launch_state,
                wall_ns=wall(), receipts=receipts, terminal=terminal, marker_count=marker_count)
            summary = replay.display(result, plan=plan)
            if root is not None and phase not in ('finalization', 'replay'):
                try:
                    p.budgets({**files, 'RESULT.pending.json': p.encode(result), 'RESULT.json': p.encode(result)})
                    finalize(root, snapshot, result)
                except Exception:
                    # Even a post-install fsync/readback failure is uncertain
                    # publication. A present RESULT must not hide that failure.
                    try:
                        failure_footer(root, snapshot, run_id, files)
                    except Exception:
                        pass
                else:
                    try:
                        summary = replay.verify_evidence(root.path).display
                    except Exception:
                        pass  # Read-only replay never repairs a valid publication.
            elif root is not None and phase == 'finalization':
                try:
                    failure_footer(root, snapshot, run_id, files)
                except Exception:
                    pass
            return dict(result=result, display=summary, exit_code=1, deadline_ns=outer_deadline)
        except Exception:
            # Unrepresentable clocks, unsafe reads or malformed fragments cannot
            # be laundered into a truthful complete RESULT. No disk retry occurs.
            return dict(display=rejection_summary(run_id, invocations=invocations, launch_state=launch_state,
                execution=True, failed_stage=current), exit_code=1, deadline_ns=outer_deadline)
    finally:
        if root is not None:
            root.close()



# Public execution name for callers; no alternate limits or injected callbacks.
execute = diagnose

def rejection_summary(run_id=None, *, invocations=0, launch_state='not_attempted', execution=False, failed_stage=None):
    """No invented frontier or reset of known execution launch observations."""
    run_id = run_id or uuid.uuid4().hex + uuid.uuid4().hex
    value = dict(**p.common(run_id), status='container_unverifiable',
        outcome='capture_incomplete' if execution else 'replay_failed',
        phase='capturing' if execution else 'replay',
        error_code='capture_incomplete' if execution else 'replay_invalid',
        failed_stage=failed_stage if execution else None, invocations=invocations,
        launch_state=launch_state, parents=[], target=dict(name=replay.TARGET, marker_count=0, markers=[], sentinel=None,
            completion=dict(observed=False, received_ns=None, meaning='checked_chain_resolved_not_proof_success')),
        source_sha256=None, diagnostic_manifest_sha256=None, events_sha256=None, result_sha256=None,
        evidence_sha256=None, identity_sha256=None, plan_sha256=None, acceptance_eligible=False,
        kernel_core_syntax_connection_checked=False, wider_obligations='12 unproved', authority='DENY_ALL')
    p.validate_summary(value)
    return p.encode(value)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', type=Path)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--replay', '--print-diagnostics', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.replay:
            origin = time.monotonic_ns()
            output = dict(display=replay.verify_evidence(args.output_directory).display, deadline_ns=origin + 600_000_000_000)
        else:
            require(args.lean is not None, '--lean required')
            output = diagnose(args.lean, args.output_directory)
        if time.monotonic_ns() >= output['deadline_ns']:
            return 1  # No late delivery claim or replacement that erases launches.
    except Exception:
        output = dict(display=rejection_summary())
    try:
        written = sys.stdout.buffer.write(output['display'])
        require(written == len(output['display']), 'short summary write')
        sys.stdout.buffer.flush()
    except Exception:
        return 1
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
