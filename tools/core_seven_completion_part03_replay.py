"""Independent, read-only replay of the closed five-slot Part03 diagnostic.

A verified failure prefix is reporting evidence, never parent admission. Nothing
in this module invokes Lean or imports the untrusted target output module.
"""
from dataclasses import dataclass
import os
from pathlib import Path
from tools import core_seven_completion_part03_plan as p
from tools.check_guarded_slice_lean import require

TARGET = 'CompletionPart03'


@dataclass(frozen=True)
class VerifiedEvidence:
    result_json: bytes
    display: bytes

    @property
    def result(self):
        return p.parse(self.result_json)


def open_snapshot(directory):
    path = Path(p.absolute(str(Path(directory).absolute())))
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'replay symlink ancestor')
    root = object.__new__(p.base.SafeRoot)
    root.path = path
    root.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root.identity = os.fstat(root.fd)
    return root, p.Snapshot(root)


def validate_stage(snapshot, plan, run, stage, source, accepted):
    """Rebuild a parent receipt in the new namespace using the unchanged gate."""
    name = stage['name']
    start_raw, finish_raw = (snapshot.read(name + suffix) for suffix in ('.started.json', '.finished.json'))
    start, finish = p.parse(start_raw), p.parse(finish_raw)
    remaining = p.integer(start.get('remaining_launch_ns'), 1, p.BUDGETS['launch_ns'])
    require(p.same(start, p.started(plan, run, stage, accepted, remaining)), 'parent start/ancestry')
    process = p.validate_process(finish.get('process'), success=True)
    out, err = snapshot.read(name + '.stdout'), snapshot.read(name + '.stderr')
    require(len(out) + len(err) <= p.BUDGETS['raw_stage'], 'parent raw cap')
    inventory = p.inventory(out, err, source)
    module_raw = snapshot.read(source.module_name.replace('.', '/') + '.olean')
    require(0 < len(module_raw) <= p.BUDGETS['module'], 'actual nonempty parent module')
    module = dict(p.file_record(module_raw), source_sha256=source.source_sha256)
    expected = dict(**p.common(plan['run_id']), index=stage['index'], name=name,
        started_sha256=p.digest(start_raw), status='stage_passed', process=process,
        logs=dict(stdout=p.file_record(out), stderr=p.file_record(err)),
        inventory=dict(subject_count=len(inventory), inventory_sha256=p.commitment(inventory)), olean=module)
    require(p.same(finish, expected), 'parent full independent receipt binding')
    accepted[source.module_name] = dict(finished_receipt_sha256=p.digest(finish_raw),
        olean_sha256=module['sha256'], olean_bytes=module['bytes'], source_sha256=source.source_sha256)
    return inventory, p.digest(finish_raw)



def validate_parent_failure(result, process, files, stage, source):
    """Reproduce failure predicates separately; none authorize a descendant."""
    code, phase = result['error_code'], result['phase']
    require(result['launch_state'] == 'spawned', 'failed parent launch state')
    require(result['status'] in ('parent_failed', 'capture_incomplete', 'cleanup_uncertain', 'raw_overflow'),
            'failed parent outcome')
    if code == 'process_timeout':
        require(phase == 'capturing' and process['timed_out'], 'parent timeout predicate')
    elif code == 'process_failed':
        require(phase == 'capturing' and process['leader_reaped'] and process['returncode'] != 0,
                'parent nonzero predicate')
    elif code == 'output_limit':
        require(phase == 'capturing' and process['output_truncated'], 'parent overflow predicate')
    elif code == 'cleanup_failed':
        require(phase == 'capturing' and (process['incomplete'] or not process['original_group_empty']
                or not process['leader_reaped']), 'parent cleanup predicate')
    elif code == 'capture_incomplete':
        require(phase == 'capturing' and process['incomplete'], 'parent incomplete predicate')
    elif code == 'inventory_invalid':
        require(phase == 'verifying', 'parent inventory phase')
        p.validate_process(process, success=True)
        try:
            p.inventory(files[stage['name'] + '.stdout'], files[stage['name'] + '.stderr'], source)
        except (ValueError, UnicodeError):
            pass
        else:
            raise ValueError('claimed inventory failure not reproduced')
    elif code == 'module_invalid':
        require(phase == 'verifying', 'parent module phase')
        p.validate_process(process, success=True)
        p.inventory(files[stage['name'] + '.stdout'], files[stage['name'] + '.stderr'], source)
        require(not files.get(stage['source_path'][:-5] + '.olean'), 'claimed module failure not reproduced')
    else:
        raise ValueError('failure requires unavailable external/partial-write observation')


def verify_target_capture(root, plan, run, started, marker_events, process, logs, observed_bytes):
    """Fixed collector finalization path, before its terminal is serialized."""
    from tools import core_seven_completion_part03_capture as capture
    snapshot = p.Snapshot(root)
    identity = p.parse(snapshot.read('IDENTITY.json'))
    external = p.External(p.absolute(plan['process_spec']['executable']))
    require(p.same(identity, external.identity(plan['run_id'])), 'target actual external identity')
    prepared, proposal, marked, expected_plan = p.reconstruct_plan(
        snapshot, identity, plan['process_spec']['executable'], root.path)
    require(p.same(plan, expected_plan), 'target regenerated plan')
    require(p.same(run, p.make_run(plan)), 'target same run')
    p.base._support_imports(prepared, identity['support'])
    require(snapshot.read(TARGET + '.started.json') == p.encode(started), 'target start persistence')
    p.validate_process(process, success=True)
    out, err = snapshot.read(TARGET + '.stdout'), snapshot.read(TARGET + '.stderr')
    actual_logs = dict(stdout=p.file_record(out), stderr=p.file_record(err))
    require(p.same(logs, actual_logs) and p.same(observed_bytes, dict(stdout=len(out), stderr=len(err))),
            'target observed/written/hash mismatch')
    parsed = capture.parse_raw(out, err, proposal.stages[4], marked.manifest['markers'],
                               events=marker_events, complete=True)
    inventory = p.inventory(parsed['stdout'], err, proposal.stages[4])
    try:
        module = snapshot.read(plan['target']['module_path'])
        require(0 < len(module) <= p.BUDGETS['module'], 'target actual module bound')
        module_total = sum(len(snapshot.read(name)) for name in p.MODULE_FILES)
        require(module_total <= p.BUDGETS['modules'], 'aggregate target module bound')
    except Exception as exc:
        raise capture.CaptureFailure('target_module_invalid') from exc
    # The target is deliberately never added to any admitted parent map.
    actual = root.scan(p.FIXED_FILES)
    # The collector is paused here: include its actual preterminal EVENTS bytes
    # in both aggregate charging and the immutable readback before return.
    files = {name: snapshot.read(name) for name in actual}
    p.budgets(files)
    require(snapshot.read(TARGET + '.stdout') == out and snapshot.read(TARGET + '.stderr') == err
            and snapshot.read(plan['target']['module_path']) == module, 'target post-validation reread')
    external.check()
    require(root.scan(p.FIXED_FILES) == actual, 'target post-validation membership')
    require(all(snapshot.read(name) == raw for name, raw in files.items()), 'target post-validation all bytes')
    return dict(inventory=dict(subject_count=len(inventory), inventory_sha256=p.commitment(inventory)),
                olean=dict(p.file_record(module), source_sha256=plan['target']['source_sha256']))


def safe_prefix(terminal):
    process = p.validate_process(terminal['process'])
    return (process['spawned'] and process['leader_reaped'] and process['leader_reap_observed']
        and process['stdout_eof'] and process['stderr_eof'] and process['original_group_empty']
        and process['post_reap_group_probe'] == 'esrch'
        and process['pre_reap_group_signal'] in ('sigkill_sent', 'sigkill_no_signalable_group')
        and process['leader_start_ticks'] is not None
        and not process['incomplete'] and not process['output_truncated']
        and terminal['status'] in ('diagnostic_completed', 'target_timeout', 'target_nonzero')
        and all(terminal['observed_bytes'][s] == terminal['logs'][s]['bytes'] for s in ('stdout', 'stderr')))


def validate_target(snapshot, plan, run, marked, proposal, accepted, raw_remaining):
    from tools import core_seven_completion_part03_capture as capture
    start_raw = snapshot.read(TARGET + '.started.json')
    start = p.parse(start_raw)
    remaining = p.integer(start.get('remaining_launch_ns'), 1, p.BUDGETS['launch_ns'])
    require(p.same(start, p.started(plan, run, plan['target'], accepted, remaining)), 'target parent/start binding')
    raw_events = snapshot.read(TARGET + '.events.jsonl')
    events = capture.validate_events(raw_events, plan, run, start, raw_remaining)
    terminal, marker_events = events[-1], events[1:-1]
    out, err = snapshot.read(TARGET + '.stdout'), snapshot.read(TARGET + '.stderr')
    require(p.same(terminal['logs'], dict(stdout=p.file_record(out), stderr=p.file_record(err))), 'target raw hashes')
    require(len(out) + len(err) <= min(p.BUDGETS['raw_stage'], raw_remaining), 'target raw allowance')
    require(terminal['accounting_before_terminal']['raw_written_bytes'] == len(out) + len(err), 'raw accounting')
    if terminal['status'] == 'raw_overflow':
        allowance = min(p.BUDGETS['raw_stage'], raw_remaining)
        require(len(out) + len(err) == allowance and
                sum(terminal['observed_bytes'].values()) == allowance + 1,
                'overflow retains the entire allowance plus one unretained sentinel')
    if terminal['status'] == 'event_overflow' or (terminal['status'] == 'capture_incomplete' and
            terminal['error_code'] in ('filesystem_invalid', 'clock_invalid', 'evidence_limit')):
        # An incomplete flag does not reproduce an external I/O, clock or
        # partial-write failure. Keep the recorded counts as an unverifiable
        # fragment, never promote the self-assertion to a bounded replay.
        raise ValueError('unavailable target failure observation is not replayable')
    markers = []
    if safe_prefix(terminal):
        parsed = capture.parse_raw(out, err, proposal.stages[4], marked.manifest['markers'],
                                   events=marker_events, complete=terminal['status'] == 'diagnostic_completed')
        markers = [{k: v for k, v in event.items() if k != 'kind'} for event in marker_events if event['kind'] == 'marker']
        if terminal['status'] == 'diagnostic_completed':
            p.validate_process(terminal['process'], success=True)
            inventory = p.inventory(parsed['stdout'], err, proposal.stages[4])
            module = snapshot.read(plan['target']['module_path'])
            require(module, 'empty target module')
            require(p.same(terminal['inventory'], dict(subject_count=len(inventory), inventory_sha256=p.commitment(inventory)))
                    and p.same(terminal['olean'], dict(p.file_record(module), source_sha256=plan['target']['source_sha256'])),
                    'target full inventory/module')
    else:
        require(terminal['status'] != 'diagnostic_completed', 'unsafe completed target')
        if terminal['status'] == 'target_invalid':
            code = terminal['error_code']
            if code in ('target_inventory_invalid', 'marker_invalid'):
                try:
                    capture.parse_raw(out, err, proposal.stages[4], marked.manifest['markers'],
                        events=marker_events, complete=code == 'target_inventory_invalid')
                except (ValueError, UnicodeError):
                    pass
                else:
                    raise ValueError('claimed target raw failure not reproduced')
            elif code == 'target_module_invalid':
                p.validate_process(terminal['process'], success=True)
                capture.parse_raw(out, err, proposal.stages[4], marked.manifest['markers'], events=marker_events, complete=True)
                actual = snapshot.root.scan(p.FIXED_FILES)
                module_path = plan['target']['module_path']
                require(module_path not in actual or not snapshot.read(module_path), 'claimed module failure not reproduced')
            else:
                raise ValueError('target clock failure cannot establish a bounded receipt')
    return terminal, markers, events


def frozen_commitment(files):
    return p.commitment({name: p.file_record(raw) for name, raw in sorted(files.items())
                         if name not in ('RESULT.json', 'RESULT.pending.json', 'FAILURE.json')})


def make_result(run_id, files, *, status, phase, error_code, failed_stage, invocations,
                launch_slots_used, launch_state, wall_ns, receipts, terminal=None, marker_count=0):
    def digest_file(name):
        return p.digest(files[name]) if name in files else None
    result = dict(**p.common(run_id), status=status, phase=phase, error_code=error_code,
        failed_stage=failed_stage, invocations=invocations, launch_slots_used=launch_slots_used,
        launch_state=launch_state, wall_ns=wall_ns, run_sha256=digest_file('RUN.json'),
        plan_sha256=digest_file('PLAN.json'), identity_sha256=digest_file('IDENTITY.json'),
        diagnostic_manifest_sha256=digest_file('diagnostic-manifest.json'),
        committed_parent_receipt_sha256=list(receipts), target_started_sha256=digest_file(TARGET + '.started.json'),
        target_events_sha256=digest_file(TARGET + '.events.jsonl'),
        target_terminal_sha256=p.commitment(terminal) if terminal is not None else None,
        target_marker_count=marker_count,
        frozen_files_count=len(set(files) - {'RESULT.json', 'RESULT.pending.json', 'FAILURE.json'}),
        frozen_files_sha256=frozen_commitment(files), **p.flags())
    p.validate_result(result)
    return result


def display(result, *, status='container_unverifiable', parents=(), markers=(), sentinel=None, plan=None, result_raw=None):
    """Closed projection. The default never claims a verified frontier."""
    if status == 'container_unverifiable':
        parents, markers, sentinel = (), (), None
    value = dict(**p.common(result['run_id']), status=status, outcome=result['status'],
        invocations=result['invocations'], phase=result['phase'], error_code=result['error_code'],
        failed_stage=result['failed_stage'], launch_state=result['launch_state'], parents=list(parents),
        target=dict(name=TARGET, marker_count=len(markers), markers=list(markers), sentinel=sentinel,
            completion=dict(observed=sentinel is not None,
                received_ns=sentinel['received_ns'] if sentinel is not None else None,
                meaning='checked_chain_resolved_not_proof_success')),
        source_sha256=plan['target']['source_sha256'] if plan else None,
        diagnostic_manifest_sha256=result['diagnostic_manifest_sha256'], events_sha256=result['target_events_sha256'],
        result_sha256=p.digest(result_raw) if result_raw is not None else None,
        evidence_sha256=result['frozen_files_sha256'], identity_sha256=result['identity_sha256'],
        plan_sha256=result['plan_sha256'], acceptance_eligible=False,
        kernel_core_syntax_connection_checked=False, wider_obligations='12 unproved', authority='DENY_ALL')
    p.validate_summary(value)
    raw = p.encode(value)
    require(len(raw) <= p.BUDGETS['display'], 'summary cap')
    return raw


def verify_evidence(directory):
    """Replay complete success OR a bounded failure; never modify the directory."""
    root, snapshot = open_snapshot(directory)
    try:
        actual = root.scan(p.FIXED_FILES)
        require('RESULT.json' in actual and not {'RESULT.pending.json', 'FAILURE.json'} & set(actual), 'terminal publication incomplete')
        files = {name: snapshot.read(name) for name in sorted(actual)}
        p.budgets(files)
        result = p.validate_result(p.parse(files['RESULT.json']))
        require(result['phase'] != 'preparation', 'preparation fragment has no source replay')
        identity, plan, run = (p.parse(files[name]) for name in ('IDENTITY.json', 'PLAN.json', 'RUN.json'))
        p.validate_identity(identity)
        require(plan['process_spec']['root'] == str(root.path), 'actual root differs')
        external = p.External(p.absolute(plan['process_spec']['executable']))
        require(p.same(identity, external.identity(result['run_id'])), 'actual external identity')
        prepared, proposal, marked, expected_plan = p.reconstruct_plan(snapshot, identity, external.executable, root.path)
        p.base._support_imports(prepared, identity['support'])
        require(p.same(plan, expected_plan) and p.same(run, p.make_run(expected_plan)), 'regenerated plan/run')
        base_files = set(p.SOURCE_FILES) | set(p.GLOBALS)
        require(base_files <= set(files), 'complete preparation required')
        accepted, receipts, parents = {}, [], []
        permitted = set(base_files)
        remaining_before, duration_before, duration_total = p.BUDGETS['launch_ns'], 0, 0
        invocations = 0
        terminal, markers, target_events = None, [], None
        failed_parent = False
        count = len(result['committed_parent_receipt_sha256'])
        current = 4 if result['status'] == 'diagnostic_completed' else result['failed_stage']
        p.validate_file_prefix(files, count, current)
        for index, stage in enumerate(plan['stages'][:4]):
            name = stage['name']
            stage_files = {name + suffix for suffix in ('.started.json', '.finished.json', '.stdout', '.stderr')}
            stage_files.add(stage['source_path'][:-5] + '.olean')
            if index > count: break
            present = stage_files & set(files)
            if index == count and not present: break
            require(not failed_parent, 'later parent after failure')
            permitted.update(stage_files)
            start_name = name + '.started.json'
            require(start_name in files, 'parent artifact without start')
            start = p.parse(files[start_name])
            remaining = p.integer(start.get('remaining_launch_ns'), 1, p.BUDGETS['launch_ns'])
            require(remaining <= remaining_before - duration_before, 'parent launch clock')
            require(p.same(start, p.started(plan, run, stage, accepted, remaining)), 'parent start chain')
            remaining_before = remaining
            finish_name = name + '.finished.json'
            if index < count:
                require(stage_files <= set(files), 'committed parent complete set')
                _, receipt = validate_stage(snapshot, plan, run, stage, proposal.stages[index], accepted)
                receipts.append(receipt)
                finish = p.parse(files[finish_name])
            elif finish_name in files:
                finish = p.parse(files[finish_name])
                process = p.validate_process(finish.get('process'))
                require(process['spawned'], 'failed finish must establish spawned process')
                logs = {s: p.file_record(files[name + '.' + s]) for s in ('stdout', 'stderr')}
                expected = dict(**p.common(result['run_id']), index=index, name=name, started_sha256=p.digest(files[start_name]),
                    status='stage_failed', error_code=result['error_code'], process=process, logs=logs, inventory=None, olean=None)
                require(p.same(finish, expected), 'failed parent complete bindings')
                p.validate_parent_finish(finish)
                validate_parent_failure(result, process, files, stage, proposal.stages[index])
                require(result['failed_stage'] == index and result['status'] != 'diagnostic_completed', 'first failed parent')
                failed_parent = True
            else:
                require(present <= {start_name, name + '.stdout', name + '.stderr'}
                        and all(not files[n] for n in present - {start_name})
                        and result['failed_stage'] == index and result['phase'] == 'prelaunch'
                        and result['invocations'] == index, 'unverified parent capture fragment')
                break
            process = finish['process']
            duration_before = process['elapsed_ns'] + process['cleanup_ns']
            duration_total += duration_before
            invocations += int(process['spawned'])
            parents.append(dict(name=name, subjects=stage['subject_count'], status=finish['status'],
                                elapsed_ns=process['elapsed_ns'], cleanup_ns=process['cleanup_ns']))
        target_files = {TARGET + suffix for suffix in ('.started.json', '.events.jsonl', '.stdout', '.stderr')}
        target_files.add(plan['target']['module_path'])
        target_present = target_files & set(files)
        if target_present:
            require(count == 4 and len(receipts) == 4 and not failed_parent, 'target requires all four admitted parents')
            permitted.update(target_files)
            target_start = TARGET + '.started.json'
            require(target_start in files, 'target artifact without start')
            start = p.parse(files[target_start])
            remaining = p.integer(start.get('remaining_launch_ns'), 1, p.BUDGETS['launch_ns'])
            require(remaining <= remaining_before - duration_before, 'target launch clock')
            require(p.same(start, p.started(plan, run, plan['target'], accepted, remaining)), 'target chain')
            remaining_before = remaining
            if TARGET + '.events.jsonl' in files:
                raw_remaining = p.RAW_GLOBAL - sum(len(files.get(n + '.' + s, b'')) for n in p.SCHEDULE[:4] for s in ('stdout', 'stderr'))
                terminal, markers, target_events = validate_target(snapshot, plan, run, marked, proposal, accepted, raw_remaining)
                require(result['status'] == terminal['status'] and result['error_code'] == terminal['error_code'],
                        'result/target outcome and code')
                expected_phase = ('finalization' if terminal['status'] == 'diagnostic_completed' else
                    'target_prelaunch' if not terminal['process']['spawned'] else
                    'target_verifying' if terminal['status'] == 'target_invalid' else 'capturing')
                require(result['phase'] == expected_phase and result['failed_stage'] == (
                    None if terminal['status'] == 'diagnostic_completed' else 4), 'target failure phase/index')
                require(result['launch_state'] == ('spawned' if terminal['process']['spawned'] else 'not_spawned'),
                        'target actual launch state')
                invocations += int(terminal['process']['spawned'])
                duration_before = terminal['receipt_elapsed_ns']
                duration_total += duration_before
            else:
                require(target_present == {target_start} and result['phase'] == 'target_prelaunch'
                        and result['invocations'] == 4, 'unverified target capture fragment')
        require(set(files) == (set(files) & permitted) | {'RESULT.json'}, 'later/unscheduled artifacts')
        if result['status'] != 'diagnostic_completed':
            require(result['phase'] not in ('finalization', 'replay'), 'terminal/replay failure is unverified')
            if result['phase'] in ('prelaunch', 'target_prelaunch'):
                require(result['status'] == 'no_launch' and result['failed_stage'] == len(receipts)
                        and invocations == len(receipts), 'known no-launch prefix')
            else:
                require(failed_parent or terminal is not None, 'failure needs actual current-stage evidence')
        require(receipts == result['committed_parent_receipt_sha256'] and invocations == result['invocations'], 'actual receipt/launch prefix')
        require(result['launch_state'] != 'spawn_outcome_uncertain', 'uncertain launch cannot be independently established')
        if result['launch_state'] == 'not_spawned':
            require(result['failed_stage'] is not None and
                    p.SCHEDULE[result['failed_stage']] + '.started.json' in files, 'collector entry requires durable start')
        require(result['launch_slots_used'] == invocations + int(result['launch_state'] == 'not_spawned'),
                'launch slot accounting')
        require(result['wall_ns'] >= duration_total and result['wall_ns'] >= p.BUDGETS['launch_ns'] - remaining_before + duration_before,
                'wall clock contradicts actual receipts')
        if result['status'] == 'diagnostic_completed':
            require(set(files) == set(p.FROZEN_FILES) | {'RESULT.json'} and len(markers) == 12 and count == 4,
                    'complete diagnostic set')
        expected = make_result(result['run_id'], files, status=result['status'], phase=result['phase'],
            error_code=result['error_code'], failed_stage=result['failed_stage'], invocations=invocations,
            launch_slots_used=result['launch_slots_used'], launch_state=result['launch_state'], wall_ns=result['wall_ns'],
            receipts=receipts, terminal=terminal, marker_count=len(markers))
        require(p.same(expected, result), 'actual frozen/result commitments')
        summary = display(result, status='complete_diagnostic_replayed' if result['status'] == 'diagnostic_completed' else 'bounded_failure_replayed',
                          parents=parents, markers=markers,
                          sentinel=next(({k:v for k,v in e.items() if k != 'kind'} for e in (target_events or [])[1:-1]
                                         if e.get('kind') == 'sentinel'), None) if terminal is not None and safe_prefix(terminal) else None,
                          plan=plan, result_raw=files['RESULT.json'])
        p.budgets(files, summary)
        external.check()
        require(root.scan(p.FIXED_FILES) == actual, 'final file set changed')
        require(all(snapshot.read(name) == raw for name, raw in files.items()), 'final actual byte reread changed')
        return VerifiedEvidence(files['RESULT.json'], summary)
    finally:
        root.close()
