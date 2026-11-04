"""Complete fresh seven-certificate kernel acceptance. Never upgrades diagnostics.

Invoke only after independent implementation review. Full replay, not RESULT
flags, is the consumer boundary. All wider proof/production gates remain closed.
"""
import os
from pathlib import Path
import sys
import time
import uuid
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import core_seven_acceptance_plan as p
from tools import core_seven_acceptance_replay as replay
from tools import core_seven_acceptance_capture as collector
from tools.check_guarded_slice_lean import require


class Failure(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def sync_file(root, name):
    parent, leaf = root._parent(name)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try: os.fsync(fd)
        finally: os.close(fd)
        os.fsync(parent)
    finally: os.close(parent)


def finalize(root, snapshot, result):
    """One exclusive candidate, durable reread, atomic rename and directory sync."""
    raw = p.encode(result)
    require(len(raw) <= p.cap('RESULT.pending.json'), 'terminal cap')
    root.write('RESULT.pending.json', raw)
    sync_file(root, 'RESULT.pending.json')
    require(snapshot.read('RESULT.pending.json', mutable=True) == raw, 'pending reread')
    snapshot.check_directories()
    os.replace('RESULT.pending.json', 'RESULT.json', src_dir_fd=root.fd, dst_dir_fd=root.fd)
    os.fsync(root.fd)
    require(snapshot.read('RESULT.json', mutable=True) == raw, 'final reread')


def qualify(lean, output_directory):
    started_at = time.monotonic_ns()  # preparation and all identity reads included
    deadline = started_at + p.BUDGETS['launch_ns']
    run_id = uuid.uuid4().hex + uuid.uuid4().hex
    root = snapshot = external = identity = plan = run = None
    files, accepted, inventories, receipts = {}, {}, {}, []
    phase, current, invocations = 'preparation', None, 0
    captured = None

    def wall():
        return min(600000000000, max(0, time.monotonic_ns() - started_at))

    def write(name, raw):
        require(name not in files and name in p.FROZEN_FILES, 'exclusive fixed artifact')
        p.budgets({**files, name: raw})
        root.write(name, raw)
        sync_file(root, name)
        require(snapshot.read(name) == raw, 'persisted bytes differ')
        files[name] = raw

    def write_json(name, value):
        write(name, p.encode(value))

    def state(extra=()):
        try: external.check()
        except Exception as exc: raise Failure('identity_changed') from exc
        try:
            snapshot.check_directories()
            actual = root.scan(p.FIXED_FILES)
            require(set(files) <= set(actual) <= set(files) | set(extra), 'unexpected/stale/missing evidence file')
            for name, raw in files.items():
                require(snapshot.read(name) == raw, 'frozen bytes changed')
            transient = {n: snapshot.read(n) for n in actual if n not in files}
            p.budgets({**files, **transient})
        except Exception as exc: raise Failure('filesystem_invalid') from exc

    try:
        executable = Path(p.absolute(str(Path(lean).absolute())))
        destination = Path(p.absolute(str(Path(output_directory).absolute())))
        require(not os.path.lexists(destination), 'fresh output root required')
        external = p.External(executable)
        prepared, proposal = p.prepare()
        external.check()
        identity = external.identity(run_id)
        plan = p.make_plan(run_id, identity, executable, destination, prepared, proposal)
        run = p.make_run(plan)
        p.base._support_imports(prepared, identity['support'])
        root = p.base.SafeRoot(destination)
        snapshot = p.Snapshot(root)
        write_json('IDENTITY.json', identity)
        write_json('PLAN.json', plan)
        write_json('RUN.json', run)
        write('seven-manifest.json', proposal.manifest_json.encode())
        for s in prepared['stages']: write('original/' + s.name + '.lean', s.source.encode())
        for s in proposal.stages: write(s.module_name.replace('.', '/') + '.lean', s.source.encode())
        for stage, source in zip(plan['stages'], proposal.stages):
            phase, current, captured = 'prelaunch', stage['index'], None
            state()
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0: raise Failure('launch_deadline')
            start = p.started(plan, run, stage, accepted, remaining)
            try: write_json(stage['name'] + '.started.json', start)
            except Exception as exc: raise Failure('receipt_failed') from exc
            # Expensive checks precede the adjacent-to-spawn deadline in collector.
            state()
            if time.monotonic_ns() >= deadline: raise Failure('launch_deadline')
            module_path = stage['source_path'][:-5] + '.olean'
            env = dict(os.environ)
            env.pop('LEAN_SRC_PATH', None)
            env['LEAN_PATH'], env['LEAN_SYSROOT'] = str(destination), str(executable.parent.parent)
            argv = [str(executable), '--root=' + str(destination), '-o', str(destination / module_path), str(destination / stage['source_path'])]
            phase = 'capturing'
            captured = collector.capture(argv, cwd=str(destination), env=env,
                stdout_path=destination / (stage['name'] + '.stdout'), stderr_path=destination / (stage['name'] + '.stderr'),
                raw_remaining=p.RAW_GLOBAL - sum(len(files.get(n, b'')) for n in p.LOG_FILES), launch_deadline_ns=deadline)
            p.validate_process(captured['process'])
            invocations += int(captured['process']['spawned'])
            if not captured['process']['spawned']:
                phase = 'prelaunch'
                raise Failure('launch_deadline' if captured['error_code'] == 'launch_deadline' else 'receipt_failed')
            for stream in ('stdout', 'stderr'):
                n = stage['name'] + '.' + stream
                if os.path.lexists(destination / n): files[n] = snapshot.read(n)
            if captured['error_code'] is not None: raise Failure(captured['error_code'])
            phase = 'verifying'
            state((module_path,))
            p.validate_process(captured['process'], success=True)
            try:
                iv = p.inventory(files[stage['name'] + '.stdout'], files[stage['name'] + '.stderr'], source)
            except Exception as exc: raise Failure('inventory_invalid') from exc
            try:
                module_raw = snapshot.read(module_path)
                require(module_raw, 'empty module')
                p.budgets({**files, module_path: module_raw})
            except Exception as exc: raise Failure('module_invalid') from exc
            logs = {stream: p.file_record(files[stage['name'] + '.' + stream]) for stream in ('stdout', 'stderr')}
            require(p.same(logs, captured['logs']), 'capture retained hash mismatch')
            finish = dict(**p.common(run_id), index=current, name=stage['name'], started_sha256=p.commitment(start),
                status='stage_passed', process=captured['process'], logs=logs,
                inventory=dict(subject_count=len(iv), inventory_sha256=p.commitment(iv)),
                olean=dict(p.file_record(module_raw), source_sha256=source.source_sha256))
            phase = 'receipt_commit'
            try: write_json(stage['name'] + '.finished.json', finish)
            except Exception as exc: raise Failure('receipt_failed') from exc
            state((module_path,))
            # Admission follows committed/reread receipt AND independent stage replay.
            checked, receipt_hash = replay.validate_stage(snapshot, plan, run, stage, source, accepted)
            files[module_path] = module_raw
            inventories[stage['name']] = checked
            receipts.append(receipt_hash)
        phase, current = 'finalization', None
        state()
        # Full actual declaration inverse and byte reconstruction again before commit.
        restored, candidate = p.reconstruct(snapshot)
        require(p.same(plan, p.make_plan(run_id, identity, executable, destination, restored, candidate)), 'final plan regeneration')
        state()
        require(time.monotonic_ns() - started_at <= 600000000000, 'outer command deadline exceeded')
        candidate_result = replay.success_result(plan, run, identity, files, inventories, receipts, wall())
        display = replay.display(candidate_result, identity, plan)
        p.budgets({**files, 'RESULT.json': p.encode(candidate_result)}, display)
        finalize(root, snapshot, candidate_result)
        # There is intentionally no caller callback capable of authorizing success.
        verified = replay.verify_evidence(destination)
        result = verified.result
        require(p.same(result, candidate_result) and verified.display == display, 'final replay/display differs')
        external.check()
        require(all(snapshot.read(n) == raw for n, raw in files.items()), 'post-replay frozen bytes changed')
        require(set(root.scan(p.FIXED_FILES)) == p.FROZEN_FILES | {'RESULT.json'}, 'post-replay file set changed')
        require(snapshot.read('RESULT.json', mutable=True) == p.encode(result), 'post-replay terminal changed')
        require(time.monotonic_ns() - started_at <= 600000000000, 'outer deadline during final replay')
        return dict(result=result, display=display, exit_code=0, deadline_ns=started_at + 600000000000)
    except Exception as exc:
        code = exc.code if isinstance(exc, Failure) else ('preparation_invalid' if phase == 'preparation' else
                'finalization_failed' if phase == 'finalization' else 'filesystem_invalid')
        if phase not in p.PHASE_CODES.get(code, ()):
            code = 'filesystem_invalid'
        result = dict(**p.common(run_id), status='failed',
            run_sha256=p.digest(files['RUN.json']) if 'RUN.json' in files else None,
            plan_sha256=p.digest(files['PLAN.json']) if 'PLAN.json' in files else None,
            identity_sha256=p.digest(files['IDENTITY.json']) if 'IDENTITY.json' in files else None,
            failed_stage=current, phase=phase, error_code=code, invocations=invocations,
            wall_ns=wall(), committed_receipt_sha256=list(receipts), **p.flags())
        p.validate_failure(result)
        if root is not None:
            # Captured outputs are diagnostic only; never admit any failed module.
            if current is not None and captured is not None and captured['process']['spawned']:
                name = p.seven.NAMES[current]
                failed = dict(**p.common(run_id), index=current, name=name,
                    started_sha256=p.digest(files[name + '.started.json']), status='stage_failed', error_code=code,
                    process=captured['process'], logs=captured['logs'], inventory=None, olean=None)
                p.validate_failed_stage(failed)
                if not os.path.lexists(root.path / (name + '.finished.json')):
                    try: write_json(name + '.finished.json', failed)
                    except Exception: pass
            try:
                p.budgets({**files, 'RESULT.json': p.encode(result)})
                finalize(root, snapshot, result)
            except Exception:
                # No overwrite/unlink of an uncertain pending candidate. The one
                # fixed failure artifact makes independent success replay reject.
                try:
                    root.write('FAILURE.json', p.encode(result))
                    sync_file(root, 'FAILURE.json')
                except Exception: pass
        display = replay.display(result, identity, plan)
        return dict(result=result, display=display, exit_code=1)
    finally:
        if root is not None: root.close()


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', type=Path)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--replay', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.replay:
            replay_started = time.monotonic_ns()
            verified = replay.verify_evidence(args.output_directory)
            output = dict(display=verified.display, exit_code=0,
                          deadline_ns=replay_started + 600000000000)
        else:
            require(args.lean is not None, '--lean required')
            output = qualify(args.lean, args.output_directory)
    except Exception:
        # No unbounded traceback/path/error string is a protocol display.
        result = dict(**p.common(uuid.uuid4().hex + uuid.uuid4().hex), status='failed', run_sha256=None,
            plan_sha256=None, identity_sha256=None, failed_stage=None, phase='preparation',
            error_code='preparation_invalid', invocations=0, wall_ns=0, committed_receipt_sha256=[], **p.flags())
        output = dict(display=replay.display(result), exit_code=1)
    if output['exit_code'] == 0 and time.monotonic_ns() >= output['deadline_ns']:
        return 1
    try:
        sys.stdout.buffer.write(output['display'])
        sys.stdout.buffer.flush()
    except Exception:
        return 1
    return output['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
