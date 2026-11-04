"""Independent full-byte replay for the complete eleven-process acceptance run.

No compiler invocation, injected readers, acceptance callbacks or test mode.
A success flag alone is never a proof receipt. Actual pinned inputs are required.
"""
from dataclasses import dataclass
import os
from pathlib import Path
from tools import core_seven_relocation_acceptance_plan as p
from tools.check_guarded_slice_lean import require


@dataclass(frozen=True)
class VerifiedEvidence:
    """Immutable result and display bytes from one fully validated snapshot."""
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
    name = stage['name']
    start_raw = snapshot.read(name + '.started.json')
    finish_raw = snapshot.read(name + '.finished.json')
    start, finish = p.parse(start_raw), p.parse(finish_raw)
    remaining = start.get('remaining_launch_ns')
    p.integer(remaining, 1, p.BUDGETS['launch_ns'])
    require(p.same(start, p.started(plan, run, stage, accepted, remaining)), 'same-run started/parent chain')
    process = p.validate_process(finish.get('process'), success=True)
    out, err = snapshot.read(name + '.stdout'), snapshot.read(name + '.stderr')
    require(len(out) + len(err) <= p.BUDGETS['raw_stage'], 'stage raw limit')
    inventory = p.inventory(out, err, source)
    module_raw = snapshot.read(source.module_name.replace('.', '/') + '.olean')
    require(0 < len(module_raw) <= p.BUDGETS['module'], 'actual module required')
    module = dict(p.file_record(module_raw), source_sha256=source.source_sha256)
    expected = dict(**p.common(plan['run_id']), index=stage['index'], name=name,
        started_sha256=p.digest(start_raw), status='stage_passed', process=process,
        logs=dict(stdout=p.file_record(out), stderr=p.file_record(err)),
        inventory=dict(subject_count=len(inventory), inventory_sha256=p.commitment(inventory)), olean=module)
    require(p.same(finish, expected), 'strict successful receipt/source/log/inventory/module binding')
    accepted[source.module_name] = dict(finished_receipt_sha256=p.digest(finish_raw),
        olean_sha256=module['sha256'], olean_bytes=module['bytes'], source_sha256=source.source_sha256)
    return inventory, p.digest(finish_raw)


def success_result(plan, run, identity, files, inventories, receipts, wall_ns):
    p.integer(wall_ns, 0, 600000000000)
    require(set(files) == p.FROZEN_FILES and len(files) == 81 and len(receipts) == 11, 'complete frozen success set')
    positive = {n: inventories['ConnectionsTransportRejections'][n] for n in plan['positive_targets']}
    negative = {}
    for n, desc in plan['negatives'].items():
        stage = desc['current_location']['module'].rsplit('.', 1)[1]
        negative[n] = dict(certificate=desc['certificate'], axioms=inventories[stage][desc['certificate']])
    require(len(positive) == 66 and len(negative) == 10, 'full original positive/exact negation set')
    return dict(**p.common(plan['run_id']), status='passed', run_sha256=p.commitment(run),
        plan_sha256=p.commitment(plan), identity_sha256=p.commitment(identity),
        frozen_files_count=81, frozen_files_sha256=p.commitment({n: p.file_record(v) for n, v in sorted(files.items())}),
        stage_receipt_sha256=receipts, positive_inventory_count=66, positive_inventory_sha256=p.commitment(positive),
        negative_certificate_count=10, negative_certificate_sha256=p.commitment(negative), invocations=11,
        wall_ns=wall_ns, **p.flags(True))


def verify_evidence(directory):
    root, snapshot = open_snapshot(directory)
    try:
        actual = root.scan(p.FIXED_FILES)
        require(set(actual) == p.FROZEN_FILES | {'RESULT.json'}, 'complete final snapshot required; no pending or failure artifact')
        files = {n: snapshot.read(n) for n in sorted(actual)}
        p.budgets(files)
        result = p.parse(files['RESULT.json'])
        require(result.get('status') == 'passed', 'failed/incomplete run cannot qualify')
        identity, plan, run = (p.parse(files[n]) for n in ('IDENTITY.json', 'PLAN.json', 'RUN.json'))
        run_id = p.hash_value(result.get('run_id'))
        spec = plan.get('process_spec')
        require(type(spec) is dict and set(spec) == {'executable', 'root', 'sysroot', 'argv_template', 'environment_keys', 'unset_environment_keys'},
                'process spec keys')
        require(p.absolute(spec['root']) == str(root.path), 'run root differs')
        external = p.External(p.absolute(spec['executable']))
        require(p.same(identity, external.identity(run_id)), 'full actual identity differs')
        p.base._support_imports({'stages': ()}, identity['support'])
        prepared, proposal = p.reconstruct(snapshot)
        p.base._support_imports(prepared, identity['support'])
        p.validate_plan_records(identity, plan, run, external.identity(run_id), external.executable, root.path, prepared, proposal)
        p.parse(files['relocation-manifest.json'], newline=False)
        accepted, inventories, receipts = {}, {}, []
        previous_remaining = p.BUDGETS['launch_ns']
        previous_process_ns = 0
        for stage, source in zip(plan['stages'], proposal.stages):
            remaining = p.parse(files[stage['name'] + '.started.json'])['remaining_launch_ns']
            require(remaining <= previous_remaining - previous_process_ns, 'launch clock contradicts previous process')
            previous_remaining = remaining
            inventory, receipt = validate_stage(snapshot, plan, run, stage, source, accepted)
            inventories[stage['name']] = inventory
            receipts.append(receipt)
            process = p.parse(files[stage['name'] + '.finished.json'])['process']
            previous_process_ns = process['elapsed_ns'] + process['cleanup_ns']
        expected = success_result(plan, run, identity, {n: files[n] for n in p.FROZEN_FILES}, inventories, receipts, result.get('wall_ns'))
        require(p.same(result, expected), 'strict result and full frozen map differ')
        elapsed = sum(sum(p.parse(files[n + '.finished.json'])['process'][key] for key in ('elapsed_ns', 'cleanup_ns')) for n in p.seven.NAMES)
        require(result['wall_ns'] >= elapsed and result['wall_ns'] >= p.BUDGETS['launch_ns'] - previous_remaining + previous_process_ns, 'impossible total wall clock')
        verified_display = display(result, identity, plan)
        p.budgets(files, verified_display)
        # Rehash every actual byte after the inverse and receipt passes; detect
        # inode-preserving writes and directory swaps, not merely stored hashes.
        external.check()
        require(root.scan(p.FIXED_FILES) == actual, 'final file set changed')
        require(all(snapshot.read(n) == raw for n, raw in files.items()), 'final bytes changed')
        return VerifiedEvidence(files['RESULT.json'], verified_display)
    finally:
        root.close()


def display(result, identity=None, plan=None):
    success = result['status'] == 'passed'
    if not success: p.validate_failure(result)
    count = 11 if success else len(result['committed_receipt_sha256'])
    stages = [] if plan is None else [dict(name=s['name'], subjects=s['subject_count'], status='stage_passed') for s in plan['stages'][:count]]
    value = dict(**p.common(result['run_id']), status='full_replay_verified' if success else 'full_replay_failed',
        commit_sha=identity['commit_sha'] if identity else None, tree_sha=identity['tree_sha'] if identity else None,
        invocations=result['invocations'], positive_targets=66 if count >= 10 else 0,
        exact_negation_proofs=10 if count == 11 else 9 if count == 10 else 0,
        stages=stages, result_sha256=p.commitment(result), error_code=None if success else result['error_code'],
        phase=None if success else result['phase'], failed_stage=None if success else result['failed_stage'], scope=p.SCOPE)
    raw = p.encode(value)
    require(len(raw) <= p.BUDGETS['display'], 'display cap')
    return raw
