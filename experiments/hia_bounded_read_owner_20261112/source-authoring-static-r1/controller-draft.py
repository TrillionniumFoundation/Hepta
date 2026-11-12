"""Static source-only Actions controller for the bounded-read candidate.

This controller has not been parsed or executed. It never builds a native image
or invokes the original read_bounded callers. The original external guardian
owns the source driver; final acceptance is separate from process completion.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import (
    _checked_parent, _create_bytes, _create_directory, create, identity,
    measurements, pin, read, require, wire,
)

CANDIDATE = '436398aca7297059eeaca45e5fd8af1e028bf0e6'
TREE = '8df3f6a460d757f522224a337630b8a8480cad59'
MANIFEST_SHA = '2e130e0a77516bbf1a5b0ffa772ed849b4e29d45102195c271c5713dac42484c'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
GUARDIAN_SHA = 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
FIXED_NAMES = (
    'source_common.py', 'source_worker.py', 'driver.py', 'controller.py',
    'diagnostics.py', 'source-manifest.json', 'guardian.py',
    'process_owner_impl.py', 'workflow_process.py',
)
ORIGINAL_NAMES = (
    'context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
    'guard/child.stdout.log', 'guard/child.stderr.log',
    'supervisor.stdout.log', 'supervisor.stderr.log', 'driver-report.json',
    'logs/source.stdout.log', 'logs/source.stderr.log', 'logs/source.process.json',
    'generated/report.json', 'generated/source-before.json',
    'generated/source-after.json', 'generated/bounded-read.hia.json',
    'generated/bounded-read.hiaasm',
)
CHILD_NAMES = set(ORIGINAL_NAMES) - {'context.json', 'setup.json', 'guard/request.json'}
NATURAL_EVENTS = {
    'qualification_started', 'owned_child_observed',
    'qualification_exit_observed', 'owned_child_reaped',
}
LIMITS = {
    'source_bytes': 1048576, 'source_lines': 16384, 'functions': 128,
    'blocks': 1536, 'max_blocks_per_function': 256, 'operations': 8192,
    'max_unique_ssa_names_per_function': 2048,
    'max_function_parameters': 16, 'max_block_parameters': 16,
    'max_edge_arguments': 16, 'max_operation_arguments': 16,
    'max_return_arguments': 16,
}
MAX_ONE_ORIGINAL = 16 << 20
MAX_ALL_ORIGINALS = 64 << 20


def hex40(value):
    return type(value) is str and len(value) == 40 and all(c in '0123456789abcdef' for c in value)


def document(path, maximum=4 << 20):
    raw, record = read(path, maximum)
    return json.loads(raw), raw, record


def private_directory(path):
    with _checked_parent(path / '.spine-observation'):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                'private ordinary directory required: ' + str(path))


def fixed_file(path, wanted, *, system_binary=False):
    raw, record = read(path, max(1, wanted['bytes']), system_binary=system_binary)
    require(record['bytes'] == wanted['bytes'] and record['sha256'] == wanted['sha256']
            and ('git_blob_sha1' not in wanted or pin(raw)['git_blob_sha1'] == wanted['git_blob_sha1']),
            'fixed input differs: ' + str(path))
    return raw, record


def base_context(args):
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'controller requires a fresh -I -S -B interpreter')
    refused = [name for name in os.environ
               if name.startswith(('LD_', 'HEPTA_HIA_'))
               or name in ('PYTHONPATH', 'PYTHONHOME', 'HIA_CUSTODY_GITHUB_TOKEN')]
    require(not refused, 'unexpected selector, loader or custody token environment')
    origin = Path(__file__).absolute().parent
    policy_raw, policy_record = read(origin / 'policy.json', 256 << 10)
    require(sha256(policy_raw).hexdigest() == args.policy_sha256, 'exact policy SHA differs')
    policy = json.loads(policy_raw)
    require(policy['schema'] == 'hia.bounded-read-source-actions-policy.v1'
            and policy['repository'] == 'TrillionniumFoundation/Hepta'
            and policy['source']['commit'] == CANDIDATE
            and policy['source']['tree'] == TREE
            and policy['source']['members'] == 4025
            and policy['source_manifest']['sha256'] == MANIFEST_SHA
            and policy['controller_seconds'] == 180 and policy['cleanup_seconds'] == 3
            and policy['source_step_seconds'] == 60
            and policy['compiler_limits'] == LIMITS
            and policy['original_names'] == list(ORIGINAL_NAMES)
            and set(policy['control_files']) == set(FIXED_NAMES)
            and hex40(args.control_commit),
            'fixed source-only policy differs')
    for name in ('native_execution_requested', 'product_tests_requested',
                 'cold_qualification_requested', 'default_hook_changed'):
        require(policy[name] is False, 'policy scope promotion: ' + name)
    workspace = Path(os.environ['GITHUB_WORKSPACE'])
    runner_temp = Path(os.environ['RUNNER_TEMP'])
    require(workspace.is_absolute() and runner_temp.is_absolute()
            and '..' not in workspace.parts and '..' not in runner_temp.parts,
            'canonical runner paths required')
    source = workspace / 'source'
    control_checkout = workspace / 'control'
    require(origin == control_checkout / policy['control_prefix']
            and args.root == runner_temp / policy['work_root_name'],
            'actual control or work-root path differs')
    public = runner_temp / policy['public_root_name']
    require(os.environ.get('GITHUB_REPOSITORY') == policy['repository']
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_REF_TYPE') == 'branch'
            and os.environ.get('GITHUB_REF_NAME') == policy['trigger_branch']
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1',
            'unexpected workflow identity')
    workflow_sha = os.environ.get('HIA_BOUNDED_SOURCE_WORKFLOW_SHA')
    require(hex40(workflow_sha) and os.environ.get('GITHUB_SHA') == workflow_sha,
            'actual workflow commit identity missing')
    source_head, source_head_record = read(source / '.git' / 'HEAD', 128)
    control_head, control_head_record = read(control_checkout / '.git' / 'HEAD', 128)
    require(source_head == (CANDIDATE + '\n').encode()
            and control_head == (args.control_commit + '\n').encode(),
            'actual detached checkout HEAD differs')
    original_controls = {}
    for name in FIXED_NAMES:
        _, original_controls[name] = fixed_file(origin / name, policy['control_files'][name])
    require(policy['control_files']['guardian.py']['sha256'] == GUARDIAN_SHA
            and policy['control_files']['process_owner_impl.py']['sha256'] == OWNER_SHA,
            'original lifecycle source changed')
    require(sys.version_info[:3] == (3, 14, 4), 'fixed authoring interpreter version differs')
    python = Path(sys.executable).resolve()
    binary, python_record = read(python, 64 << 20, system_binary=True)
    return {
        'policy': policy, 'policy_raw': policy_raw, 'policy_record': policy_record,
        'origin': origin, 'source': source, 'root': args.root, 'public': public,
        'source_head_record': source_head_record, 'control_head_record': control_head_record,
        'original_controls': original_controls, 'python_record': python_record,
        'python': {'resolved': str(python), 'bytes': len(binary),
                   'sha256': sha256(binary).hexdigest(), 'version': sys.version},
        'workflow_sha': workflow_sha, 'control_commit': args.control_commit,
        'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': 1,
    }


def expected_fixed_inputs(base):
    expected = {}
    for name in FIXED_NAMES:
        wanted = base['policy']['control_files'][name]
        for path in (base['origin'] / name, base['root'] / 'control' / name):
            expected[str(path)] = {'bytes': wanted['bytes'], 'sha256': wanted['sha256']}
    for path in (base['origin'] / 'policy.json', base['root'] / 'control' / 'policy.json'):
        expected[str(path)] = {'bytes': len(base['policy_raw']),
                              'sha256': sha256(base['policy_raw']).hexdigest()}
    for item in (base['source_head_record'], base['control_head_record']):
        expected[item['path']] = {'bytes': item['bytes'], 'sha256': item['sha256']}
    item = base['python_record']
    expected[item['path']] = {'bytes': item['bytes'], 'sha256': item['sha256'],
                              'system_binary': True}
    return expected


def observe_fixed_inputs(expected):
    records = {}
    for path, wanted in expected.items():
        _, records[path] = fixed_file(Path(path), wanted,
                                     system_binary=wanted.get('system_binary', False))
    return records


def source_command(base):
    return [base['python']['resolved'], '-I', '-S', '-B',
            str(base['root'] / 'control' / 'source_worker.py'),
            '--source-root', str(base['source']),
            '--source-manifest', str(base['root'] / 'control' / 'source-manifest.json'),
            '--output-dir', str(base['root'] / 'generated')]


def driver_command(base, context_sha):
    return [base['python']['resolved'], '-I', '-S', '-B',
            str(base['root'] / 'control' / 'driver.py'),
            '--context', str(base['root'] / 'context.json'),
            '--context-sha256', context_sha]


def guardian_request(base, context_record, fixed_inputs):
    identities = {path: item['sha256'] for path, item in fixed_inputs.items()}
    identities[context_record['path']] = context_record['sha256']
    return {
        'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
        'command': driver_command(base, context_record['sha256']),
        'cwd': str(base['root']), 'source_identities': identities,
    }


def guardian_argv(base, request_record):
    return [base['python']['resolved'], '-I', '-S', '-B',
            str(base['root'] / 'control' / 'guardian.py'),
            '--config', str(base['root'] / 'guard' / 'request.json'),
            '--config-sha256', request_record['sha256'],
            '--implementation', str(base['root'] / 'control' / 'process_owner_impl.py')]


def prepare(args):
    base = base_context(args)
    root = base['root']
    require(not os.path.lexists(root) and not os.path.lexists(base['public']),
            'new source-authoring root already exists; do not replay')
    os.umask(0o077)
    _create_directory(root)
    for name in ('control', 'guard', 'logs'):
        _create_directory(root / name)
    capacity = os.statvfs(root)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30
            and capacity.f_favail >= 100000, 'source-authoring storage gate not met')
    for name in FIXED_NAMES:
        raw, _ = fixed_file(base['origin'] / name, base['policy']['control_files'][name])
        create(root / 'control' / name, raw)
    create(root / 'control' / 'policy.json', base['policy_raw'])
    fixed = expected_fixed_inputs(base)
    before = observe_fixed_inputs(fixed)
    context = {
        'schema': 'hia.bounded-read-source-actions-context.v1',
        'root': str(root), 'source': str(base['source']), 'public': str(base['public']),
        'candidate_commit': CANDIDATE, 'candidate_tree': TREE, 'candidate_members': 4025,
        'control_commit': args.control_commit, 'workflow_commit': base['workflow_sha'],
        'run_id': base['run_id'], 'run_attempt': 1,
        'policy_sha256': args.policy_sha256, 'python': base['python'],
        'execution_PATH': str(Path(base['python']['resolved']).parent) + ':/usr/bin:/bin',
        'fixed_inputs': fixed, 'source_command': source_command(base),
        'controller_seconds': 180, 'cleanup_seconds': 3, 'source_step_seconds': 60,
        'source_manifest_sha256': MANIFEST_SHA,
        'native_execution_requested': False, 'product_tests_requested': False,
        'cold_qualification_requested': False,
        'full_source_namespace_scope': 'The worker reads every one of 4025 members before and after source authoring. This is not formal Git-object consumer/clone qualification.',
    }
    context_record = create(root / 'context.json', wire(context))
    request = guardian_request(base, context_record, fixed)
    request_record = create(root / 'guard' / 'request.json', wire(request))
    after = observe_fixed_inputs(fixed)
    require(before == after, 'fixed inputs changed during preparation')
    setup = {
        'schema': 'hia.bounded-read-source-actions-setup.v1',
        'status': 'SOURCE_AUTHORING_PREPARED_NOT_EXECUTED',
        'context_original': context_record, 'request_original': request_record,
        'context': context, 'source_identities': request['source_identities'],
        'guardian_argv': guardian_argv(base, request_record),
        'inputs_before': before, 'inputs_after': after, 'inputs_stable': True,
        'storage': {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                    'free_inodes': capacity.f_favail, 'device': root.lstat().st_dev},
        'source_generated': False, 'native_compilation_executed': False,
        'product_tests_executed': False, 'cold_qualified': False,
    }
    create(root / 'setup.json', wire(setup))
    print(json.dumps({'status': setup['status'], 'context_sha256': context_record['sha256'],
                      'request_sha256': request_record['sha256'],
                      'qualification_claimed': False}), flush=True)
    return 0


def bound_setup(base):
    root = base['root']
    for path in (root, root / 'control', root / 'guard', root / 'logs'):
        private_directory(path)
    context, context_raw, context_record = document(root / 'context.json', 256 << 10)
    expected = expected_fixed_inputs(base)
    require(context['schema'] == 'hia.bounded-read-source-actions-context.v1'
            and context['root'] == str(root) and context['source'] == str(base['source'])
            and context['public'] == str(base['public'])
            and context['candidate_commit'] == CANDIDATE and context['candidate_tree'] == TREE
            and context['candidate_members'] == 4025
            and context['control_commit'] == base['control_commit']
            and context['workflow_commit'] == base['workflow_sha']
            and context['run_id'] == base['run_id'] and context['run_attempt'] == 1
            and context['policy_sha256'] == base['policy_record']['sha256']
            and context['python'] == base['python']
            and context['execution_PATH'] == str(Path(base['python']['resolved']).parent) + ':/usr/bin:/bin'
            and context['fixed_inputs'] == expected
            and context['source_command'] == source_command(base)
            and context['controller_seconds'] == 180 and context['cleanup_seconds'] == 3
            and context['source_step_seconds'] == 60
            and context['source_manifest_sha256'] == MANIFEST_SHA,
            'actual prepared context does not bind this operation')
    for name in ('native_execution_requested', 'product_tests_requested',
                 'cold_qualification_requested'):
        require(context[name] is False, 'prepared scope differs')
    request, request_raw, request_record = document(root / 'guard' / 'request.json', 256 << 10)
    wanted_request = guardian_request(base, context_record, expected)
    require(request == wanted_request and request_raw == wire(wanted_request),
            'actual guardian request differs')
    setup, setup_raw, setup_record = document(root / 'setup.json', 256 << 10)
    current = observe_fixed_inputs(expected)
    require(setup['schema'] == 'hia.bounded-read-source-actions-setup.v1'
            and setup['status'] == 'SOURCE_AUTHORING_PREPARED_NOT_EXECUTED'
            and setup['context'] == context
            and setup['context_original'] == context_record
            and setup['request_original'] == request_record
            and setup['source_identities'] == wanted_request['source_identities']
            and setup['guardian_argv'] == guardian_argv(base, request_record)
            and setup['inputs_before'] == setup['inputs_after'] == current
            and setup['inputs_stable'] is True,
            'actual setup or frozen input identities differ')
    return context, setup, {'context.json': context_record,
                            'guard/request.json': request_record,
                            'setup.json': setup_record}


def redirect_original(path, descriptor_number):
    _create_bytes(path, b'', 0o600)
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and info.st_size == 0
                    and identity(info) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'new supervisor log identity differs')
            stable()
            os.dup2(descriptor, descriptor_number)
        finally:
            os.close(descriptor)


def run(args):
    base = base_context(args)
    context, setup, _ = bound_setup(base)
    for path in (base['root'] / 'generated', base['root'] / 'driver-report.json',
                 base['root'] / 'guard' / 'guardian.json'):
        require(not os.path.lexists(path), 'source authoring was already admitted; do not replay')
    environment = {'PATH': context['execution_PATH'], 'LANG': 'C.UTF-8',
                   'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
    os.chdir(base['root'])
    redirect_original(base['root'] / 'supervisor.stdout.log', 1)
    redirect_original(base['root'] / 'supervisor.stderr.log', 2)
    os.execve(base['python']['resolved'], setup['guardian_argv'], environment)
    raise AssertionError('exec returned')


def closed_guardian(guardian, setup, base):
    require(guardian['schema'] == 'hepta.hia.external-qualification-guardian.v1'
            and guardian['command'] == driver_command(base, setup['context_original']['sha256'])
            and guardian['cwd'] == str(base['root'])
            and guardian['external_controller_seconds'] == 180
            and guardian['lifecycle_implementation_sha256'] == OWNER_SHA
            and guardian['source_identities_before'] == setup['source_identities']
            and guardian['cold_180_second_gate_modified'] is False,
            'guardian belongs to another operation')
    life = guardian['lifecycle']
    cleanup = life['cleanup']
    require(life['schema'] == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
            and life['subreaper_enabled'] is True
            and cleanup['attempted'] is True and cleanup['complete'] is True
            and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
            and cleanup['deadline_exceeded'] is False
            and cleanup['errors'] == [] and cleanup['remaining_direct_children'] == [],
            'owned child activity is not proven closed')
    return True


def natural_guardian(guardian, setup, base, records):
    closed_guardian(guardian, setup, base)
    life = guardian['lifecycle']
    events = life['events']
    require(guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian['qualification'] is None and guardian['input_identity_preserved'] is True
            and guardian['source_identities_after'] == setup['source_identities']
            and guardian['whole_native_delivery_qualified'] is False
            and life['status'] == 'OWNED_PROCESS_COMPLETED'
            and type(life['returncode']) is int and life['returncode'] == 0
            and life['qualification_started'] is True
            and life['exit_observed_before_deadline'] is True
            and life['timed_out'] is False and life['event_overflow'] is False
            and life['interrupted_signals'] == [] and life.get('owner_error') is None
            and type(events) is list and events
            and all(event['kind'] in NATURAL_EVENTS for event in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {event['kind'] for event in events},
            'source driver did not finish naturally without owned child kills')
    for name in ('guard/child.stdout.log', 'guard/child.stderr.log'):
        require(guardian['logs'][str(base['root'] / name)] == records[name]['original']['sha256'],
                'guardian raw log binding differs')


def verify_source_result(views, records, context, setup, base):
    driver = json.loads(views['driver-report.json'])
    worker = json.loads(views['generated/report.json'])
    process = json.loads(views['logs/source.process.json'])
    require(driver['schema'] == 'hia.bounded-read-source-actions-driver.v1'
            and driver['status'] == 'SOURCE_DRIVER_PASS_PENDING_OUTER_GUARDIAN'
            and driver['context_original'] == records['context.json']['original']
            and driver['candidate_commit'] == CANDIDATE and driver['candidate_tree'] == TREE
            and driver['command'] == context['source_command']
            and driver['source_step_seconds'] == 60 and driver['outer_owner_seconds'] == 180
            and driver['cleanup_seconds'] == 3 and driver['inputs_stable'] is True
            and driver['inputs_before'] == driver['inputs_after'] == setup['inputs_before']
            and driver['worker_report'] == records['generated/report.json']['original']
            and driver['workflow_step'] == records['logs/source.process.json']['original'],
            'actual source driver result differs')
    for name in ('native_compilation_executed', 'native_execution_executed',
                 'product_tests_executed', 'cold_qualified',
                 'whole_native_delivery_qualified', 'original_product_deadlines_changed'):
        require(driver[name] is False, 'driver scope promotion')
    require(process['schema'] == 'hepta.hia.external-workflow-process.v1'
            and process['status'] == 'WORKFLOW_STEP_COMPLETED'
            and process['command'] == context['source_command']
            and process['cwd'] == str(base['root']) and process['workflow_seconds'] == 60
            and process['returncode'] == 0 and process['timed_out'] is False
            and process['cleanup']['complete'] is True
            and process['cleanup']['signalled'] == [] and process['cleanup']['errors'] == []
            and process['selfhost_qualification_gate_modified'] is False,
            'actual 60-second source step failed')
    for name in ('logs/source.stdout.log', 'logs/source.stderr.log'):
        require(process['logs'][str(base['root'] / name)] == records[name]['original']['sha256'],
                'source-step raw log binding differs')
    require(worker['schema'] == 'hepta.hia.bounded-read-source-authoring.v2'
            and worker['status'] == 'SOURCE_AUTHORING_PASS_NOT_NATIVE_QUALIFIED'
            and worker['canonical_candidate_commit'] == CANDIDATE
            and worker['canonical_candidate_tree'] == TREE
            and worker['complete_source_members'] == 4025 and worker['baseline_members'] == 4023
            and worker['source_stable'] is True and worker['manifest_stable'] is True
            and worker['core_roundtrip'] is True and worker['deterministic_source'] is True
            and worker['syntax_checked'] == [
                'hepta/hia_bounded_read_native.py', 'tools/generate_hia_bounded_read.py']
            and worker['original_limits'] == LIMITS,
            'actual generated source result differs')
    for name in ('native_compilation_executed', 'native_execution_executed',
                 'old_or_new_lifecycle_controls_executed', 'original_eight_test_methods_executed',
                 'formal_git_consumer_or_clone_qualification', 'cold_qualified',
                 'default_activation', 'whole_native_delivery_qualified'):
        require(worker[name] is False, 'source worker scope promotion')
    for key, filename in (('source_before', 'source-before.json'), ('source_after', 'source-after.json'),
                          ('core_document', 'bounded-read.hia.json'), ('assembly', 'bounded-read.hiaasm')):
        observed = records['generated/' + filename]['original']
        require(worker[key] == observed and driver['outputs'][filename] == observed,
                'generated original identity differs: ' + filename)
    manifest_raw, manifest_record = fixed_file(base['root'] / 'control' / 'source-manifest.json',
                                             base['policy']['source_manifest'])
    require(worker['source_manifest'] == {**pin(manifest_raw), 'identity': manifest_record},
            'actual source manifest binding differs')
    require(views['generated/source-before.json'] == views['generated/source-after.json'],
            'raw complete source before/after differs')
    before = json.loads(views['generated/source-before.json'])
    manifest = json.loads(manifest_raw)
    require(len(before) == 4025
            and [row['path'] for row in before] == [row['path'] for row in manifest['files']],
            'complete source snapshot population or order differs')
    for actual, wanted in zip(before, manifest['files'], strict=True):
        require(actual['mode'] == wanted['mode'] and actual['bytes'] == wanted['size']
                and actual['git_blob_sha1'] == wanted['git_blob_sha1']
                and ('sha256' not in wanted or actual['sha256'] == wanted['sha256']),
                'source snapshot does not bind canonical manifest')
    core = json.loads(views['generated/bounded-read.hia.json'])
    summary, functions = measurements(core, views['generated/bounded-read.hiaasm'])
    require(summary == worker['measurements'] and functions == worker['functions']
            and summary['functions'] == 12
            and all(summary[name] <= bound for name, bound in LIMITS.items()),
            'actual generated compiler-cap measurements differ')
    require(core['functions'][0]['name'] == 'f0'
            and [item['type'] for item in core['functions'][0]['params']] == ['readbuf', 'mutbuf', 'mutbuf']
            and core['functions'][0]['returns'] == ['u32'], 'actual source byte ABI differs')
    return {'complete_source_members': 4025, 'measurements': summary,
            'source_before_after_raw_equal': True,
            'scope': 'SOURCE_AUTHORING_ONLY_NO_NATIVE_OR_PUBLIC_REPLACEMENT'}


def finalize(args):
    base = base_context(args)
    public = base['public']
    require(not os.path.lexists(public), 'final source originals already exist; do not replay')
    os.umask(0o077)
    _create_directory(public)
    result = {
        'schema': 'hia.bounded-read-source-actions-final.v1', 'status': 'HOLD',
        'candidate_commit': CANDIDATE, 'candidate_tree': TREE, 'candidate_members': 4025,
        'control_commit': args.control_commit, 'workflow_commit': base['workflow_sha'],
        'run_id': base['run_id'], 'run_attempt': 1, 'policy_sha256': args.policy_sha256,
        'root': str(base['root']), 'public': str(public),
        'native_execution_executed': False, 'product_tests_executed': False,
        'cold_qualified': False, 'whole_native_delivery_qualified': False,
        'original_product_deadlines_changed': False,
        'closed_ECHILD_before_child_read': False, 'errors': [], 'files': [],
    }
    context = setup = guardian = None
    records, views = {}, {}
    try:
        context, setup, parent_records = bound_setup(base)
        guardian, _, guardian_record = document(base['root'] / 'guard' / 'guardian.json', 4 << 20)
        closed_guardian(guardian, setup, base)
        result['closed_ECHILD_before_child_read'] = True
    except BaseException as error:
        result['errors'].append({'stage': 'CLOSED_OPERATION', 'type': type(error).__name__,
                                 'traceback': traceback.format_exc()})
    total = 0
    for index, name in enumerate(ORIGINAL_NAMES):
        item = {'logical_path': name}
        try:
            if name in CHILD_NAMES and not result['closed_ECHILD_before_child_read']:
                item['not_read_without_closed_operation'] = True
                raise RuntimeError('owned operation not proven closed')
            path = base['root'] / name
            raw, observed = read(path, MAX_ONE_ORIGINAL)
            require(total + len(raw) <= MAX_ALL_ORIGINALS, 'fixed original custody budget exhausted')
            copied = create(public / ('%02d.original' % index), raw)
            total += len(raw)
            item.update(original=observed, retained=copied, independent_raw_copy=True)
            records[name] = item
            views[name] = raw
        except BaseException as error:
            item['error'] = {'type': type(error).__name__, 'traceback': traceback.format_exc()}
            result['errors'].append({'stage': 'CAPTURE', 'logical_path': name,
                                     'type': type(error).__name__})
        result['files'].append(item)
    result['retained_raw_bytes'] = total
    try:
        require(result['closed_ECHILD_before_child_read'] and not result['errors']
                and set(records) == set(ORIGINAL_NAMES), 'full source originals are incomplete')
        require(json.loads(views['context.json']) == context
                and json.loads(views['setup.json']) == setup
                and json.loads(views['guard/guardian.json']) == guardian,
                'bound control originals changed before capture')
        natural_guardian(guardian, setup, base, records)
        result['source_acceptance'] = verify_source_result(views, records, context, setup, base)
        after_context, after_setup, _ = bound_setup(base)
        require(after_context == context and after_setup == setup, 'final frozen inputs changed')
        for name, item in records.items():
            raw, current = read(Path(item['retained']['path']), MAX_ONE_ORIGINAL)
            require(current == item['retained'] and raw == views[name],
                    'retained source original changed after verification')
        result['status'] = 'BOUNDED_READ_SOURCE_AUTHORING_PASS_NOT_NATIVE_QUALIFIED'
        result['natural_guardian_accepted'] = True
        result['frozen_control_inputs_stable'] = True
    except BaseException as error:
        result['status'] = 'HOLD'
        result['errors'].append({'stage': 'SOURCE_ACCEPTANCE', 'type': type(error).__name__,
                                 'traceback': traceback.format_exc()})
    final_record = create(public / 'FINAL.json', wire(result))
    print(json.dumps({'status': result['status'], 'final': final_record,
                      'retained_files': len(records), 'retained_raw_bytes': total,
                      'source_only': True, 'native_qualified': False}), flush=True)
    return 0 if result['status'] == 'BOUNDED_READ_SOURCE_AUTHORING_PASS_NOT_NATIVE_QUALIFIED' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    return {'prepare': prepare, 'run': run, 'finalize': finalize}[args.operation](args)


if __name__ == '__main__':
    raise SystemExit(main())
