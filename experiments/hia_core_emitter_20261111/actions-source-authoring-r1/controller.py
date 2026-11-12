"""Own one fixed Actions source-only authoring run and retain its original output."""
from __future__ import annotations
import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import traceback

REPOSITORY = 'TrillionniumFoundation/Hepta'
PREFIX = 'experiments/hia_core_emitter_20261111/actions-source-authoring-r1'
CANDIDATE = '80ec04ae7489209b122c874531d194c67b30dfed'
TREE = '963e980c2486e1f7c74fa42bc8132ef6b1b8b690'
TRIGGER = 'codex/hia-core-emitter-authoring-r2-run-20261112-e26e'
WORK_ROOT = 'hia-core-emitter-source-authoring-r2'
NATURAL = {'qualification_started', 'owned_child_observed',
           'qualification_exit_observed', 'owned_child_reaped'}
MAX_RECEIPT = 32 << 20

def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def read(path, maximum=MAX_RECEIPT, *, system_binary=False):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'regular input required: ' + str(path))
    if system_binary:
        require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                and not stat.S_IMODE(before.st_mode) & 0o022,
                'runner tool is writable or has unexpected ownership')
    else:
        require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                'owned single-link input required')
    require(before.st_size <= maximum, 'bounded original input required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before),
                'input changed before reading')
        raw = stream.read(before.st_size + 1)
        require(len(raw) == before.st_size and identity(os.fstat(stream.fileno())) == identity(before)
                and identity(path.lstat()) == identity(before), 'input changed during reading')
    return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                 'identity': list(identity(before))}

def create(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    copied, record = read(path, max(len(raw), 1))
    require(copied == raw, 'create-only original readback differs')
    return record

def save(path, value):
    return create(path, wire(value))

def clean_environment():
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_', 'PYTHON'))
                   and name not in ('GITHUB_TOKEN', 'GH_TOKEN')}
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return environment

def git(source, executable, *arguments):
    environment = clean_environment()
    environment['GIT_OPTIONAL_LOCKS'] = '0'
    return subprocess.run([str(executable), '--no-replace-objects', *arguments],
                          cwd=source, env=environment, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout

def source_head(source, executable):
    head = git(source, executable, 'rev-parse', 'HEAD').decode().strip()
    tree = git(source, executable, 'rev-parse', 'HEAD^{tree}').decode().strip()
    git(source, executable, 'diff', '--cached', '--quiet', TREE, '--')
    require(head == CANDIDATE and tree == TREE, 'actual source HEAD/tree differs')
    require(read(source / '.git/HEAD', 256)[0].decode().strip() == CANDIDATE,
            'source checkout is not detached at the exact input commit')
    return {'head': head, 'tree': tree, 'actual_HEAD_is_candidate': True}

def context(args):
    require(not any(value for name, value in os.environ.items()
                    if name.startswith(('GIT_', 'LD_'))),
            'ambient Git/loader redirection is outside this source-only profile')
    require(not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN'),
            'publication or API token must not enter source authoring')
    require(sys.version_info[:3] == (3, 14, 4) and platform.python_implementation() == 'CPython',
            'actual setup-python interpreter version differs')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    control_checkout = workspace / 'control'
    control = Path(__file__).resolve().parent
    require(control == control_checkout / PREFIX
            and re.fullmatch(r'[0-9a-f]{40}', args.control_commit) is not None
            and read(control_checkout / '.git/HEAD', 256)[0].decode().strip() == args.control_commit,
            'actual detached reviewed control checkout differs')
    policy_raw, policy_record = read(control / 'policy.json', 1 << 20)
    require(policy_record['sha256'] == args.policy_sha256, 'frozen policy bytes differ')
    policy = json.loads(policy_raw)
    require(policy['schema'] == 'hia.core-emitter-actions-policy.v1'
            and policy['candidate'] == {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4023}
            and policy['controller_seconds'] == 180 and policy['cleanup_seconds'] == 3
            and policy['trigger_branch'] == TRIGGER,
            'frozen source-only policy differs')
    event_raw, event_record = read(Path(os.environ['GITHUB_EVENT_PATH']), 1 << 20)
    event = json.loads(event_raw)
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and event.get('ref_type') == 'branch' and event.get('ref') == TRIGGER
            and event.get('repository', {}).get('full_name') == REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER,
            'unique original create event differs')
    workflow_sha = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}', workflow_sha) is not None
            and os.environ.get('HIA_CORE_EMITTER_WORKFLOW_SHA') == workflow_sha
            and os.environ.get('GITHUB_WORKFLOW_SHA') == workflow_sha,
            'actual workflow commit identity differs')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    root = temp / WORK_ROOT
    source = workspace / 'source'
    require(args.root == root and args.source == source and source.resolve(strict=True) == source
            and not any(p.is_symlink() for p in (root.parent, *root.parent.parents,
                                                source, *source.parents)),
            'fixed private output/source path differs')
    python = Path(sys.executable).resolve(strict=True)
    python_raw, python_record = read(python, 64 << 20, system_binary=True)
    git_executable = Path(shutil.which('git')).resolve(strict=True)
    _, git_record = read(git_executable, 64 << 20, system_binary=True)
    git_version = subprocess.run([str(git_executable), '--version'], env=clean_environment(),
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
    records = {}
    for name, pin in policy['controls'].items():
        require(re.fullmatch(r'[a-z_]+[.]py', name) is not None, 'control basename differs')
        raw, observed = read(control / name, 1 << 20)
        require(observed['bytes'] == pin['bytes'] and observed['sha256'] == pin['sha256'],
                'frozen control source differs: ' + name)
        records[str(control / name)] = pin['sha256']
    records[str(control / 'policy.json')] = policy_record['sha256']
    value = {'schema': 'hia.core-emitter-actions-context.v1',
             'repository': REPOSITORY, 'event': 'create', 'trigger_branch': TRIGGER,
             'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': 1,
             'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
             'event_sha256': event_record['sha256'], 'workflow_commit': workflow_sha,
             'workflow_ref': os.environ['GITHUB_WORKFLOW_REF'],
             'actual_control_commit': args.control_commit,
             'policy_sha256': policy_record['sha256'], 'control_sources': records,
             'candidate_commit': CANDIDATE, 'candidate_tree': TREE, 'candidate_leaves': 4023,
             'source': str(source), 'root': str(root), 'evidence': str(root / 'evidence'),
             'controller_seconds': 180, 'cleanup_seconds': 3,
             'python': {'source': 'actions/setup-python fixed action with python-version 3.14.4',
                        'executable': sys.executable, 'resolved': str(python), 'version': sys.version,
                        'implementation': platform.python_implementation(),
                        'version_info': list(sys.version_info), 'prefix': sys.prefix,
                        'base_prefix': sys.base_prefix, 'platform': sys.platform,
                        'machine': platform.machine(), 'binary': python_record,
                        'desktop_binary_identity_claimed': False},
             'git': {'resolved': str(git_executable), 'version': git_version, 'binary': git_record},
             'native_execution_requested': False, 'product_tests_requested': False,
             'cold_qualification_requested': False}
    return control, policy, policy_raw, root, source, value

def expected_inputs(control, policy, root, value):
    result = dict(value['control_sources'])
    for name, pin in policy['controls'].items():
        result[str(root / 'control' / name)] = pin['sha256']
    result[str(root / 'control/policy.json')] = value['policy_sha256']
    result[str(root / 'context.json')] = sha256(wire(value)).hexdigest()
    result[value['python']['resolved']] = value['python']['binary']['sha256']
    result[value['git']['resolved']] = value['git']['binary']['sha256']
    return result

def command(root, source, value):
    return [value['python']['resolved'], '-I', '-S', '-B', str(root / 'control/authoring.py'),
            '--source', str(source), '--output', str(root / 'evidence'),
            '--context', str(root / 'context.json'), '--policy-sha256', value['policy_sha256']]

def prepare(args):
    control, policy, raw, root, source, value = context(args)
    require(not os.path.lexists(root), 'new source authoring root already exists')
    capacity = os.statvfs(root.parent)
    available = capacity.f_bavail * capacity.f_frsize
    require(available >= 2 << 30, 'source-only development output reserve unavailable')
    actual_source = source_head(source, value['git']['resolved'])
    os.umask(0o077)
    root.mkdir(mode=0o700)
    (root / 'control').mkdir(mode=0o700)
    (root / 'guard').mkdir(mode=0o700)
    for name, pin in policy['controls'].items():
        original, observed = read(control / name, 1 << 20)
        require(observed['sha256'] == pin['sha256'], 'control changed before copying')
        create(root / 'control' / name, original)
    create(root / 'control/policy.json', raw)
    create(root / 'context.json', wire(value))
    inputs = expected_inputs(control, policy, root, value)
    invocation = command(root, source, value)
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
              'command': invocation, 'cwd': str(root), 'source_identities': inputs}
    config_record = save(root / 'guard/request.json', config)
    setup = {'schema': 'hia.core-emitter-actions-setup.v1', 'status': 'PREPARED_NOT_EXECUTED',
             'context': value, 'source_actual_HEAD': actual_source,
             'source_identities': inputs, 'command': invocation,
             'guardian_config_sha256': config_record['sha256'],
             'controller_seconds': 180, 'cleanup_seconds': 3,
             'resource_observation': {'available_bytes': available,
                 'minimum_source_only_available_bytes': 2 << 30,
                 'formal_full_resource_or_inode_qualification': False}}
    record = save(root / 'setup.json', setup)
    print(json.dumps({'status': setup['status'], 'setup_sha256': record['sha256'],
                      'root': str(root), 'actual_source_head': actual_source['head']}), flush=True)
    return 0

def setup_record(control, policy, root, source, value):
    setup_raw, record = read(root / 'setup.json', 1 << 20)
    setup = json.loads(setup_raw)
    require(setup['schema'] == 'hia.core-emitter-actions-setup.v1'
            and setup['status'] == 'PREPARED_NOT_EXECUTED'
            and setup['context'] == value and setup['command'] == command(root, source, value)
            and setup['source_identities'] == expected_inputs(control, policy, root, value)
            and setup['controller_seconds'] == 180 and setup['cleanup_seconds'] == 3,
            'original setup differs from this exact operation')
    require(read(root / 'context.json', 1 << 20)[0] == wire(value), 'actual original context differs')
    return setup, record

def run(args):
    control, policy, _, root, source, value = context(args)
    setup, _ = setup_record(control, policy, root, source, value)
    source_head(source, value['git']['resolved'])
    config_raw, config_record = read(root / 'guard/request.json', 1 << 20)
    require(config_record['sha256'] == setup['guardian_config_sha256'], 'guardian request changed')
    config = json.loads(config_raw)
    require(config == {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
                       'command': setup['command'], 'cwd': str(root),
                       'source_identities': setup['source_identities']}, 'unexpected guardian request')
    for path, expected in setup['source_identities'].items():
        _, record = read(Path(path), 64 << 20,
                         system_binary=path in (value['python']['resolved'], value['git']['resolved']))
        require(record['sha256'] == expected, 'frozen input changed before owned authoring')
    os.chdir(root)
    python = value['python']['resolved']
    os.execve(python, [python, '-I', '-S', '-B', str(root / 'control/guardian.py'),
                      '--config', str(root / 'guard/request.json'),
                      '--config-sha256', setup['guardian_config_sha256'],
                      '--implementation', str(root / 'control/process_owner_impl.py')], clean_environment())

def closed_owner(guardian, setup, root):
    life = guardian.get('lifecycle', {})
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('command') == setup['command'] and guardian.get('cwd') == str(root)
            and guardian.get('external_controller_seconds') == 180
            and guardian.get('source_identities_before') == setup['source_identities']
            and guardian.get('lifecycle_implementation_sha256') ==
                setup['source_identities'][str(root / 'control/process_owner_impl.py')]
            and life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True,
            'guardian is not the exact original authoring operation')
    cleanup = life.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [],
            'original authoring process tree has no closed ECHILD boundary')
    return life

def retained(path, expected, *, maximum=32 << 20):
    raw, record = read(path, maximum)
    require(expected['path'] == str(path) and expected['size'] == len(raw)
            and expected['sha256'] == record['sha256']
            and expected['git_blob_sha1'] ==
                sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'actual retained original differs from worker pin')
    return raw, record

def verify_outputs(root, setup):
    evidence = root / 'evidence'
    report_raw, report_pin = read(evidence / 'report.json', 32 << 20)
    report = json.loads(report_raw)
    require(report['schema'] == 'hia.core-emitter-actions-authoring.v1'
            and report['status'] == 'DEVELOPMENT_ACTIONS_EMITTER_AUTHORING_PASS'
            and report.get('error') is None and report.get('preservation_error') is None
            and report['candidate_commit'] == CANDIDATE and report['candidate_tree'] == TREE
            and report['actual_checkout_HEAD_is_candidate'] is True
            and report['context_sha256'] == sha256(wire(setup['context'])).hexdigest()
            and report['policy_sha256'] == setup['context']['policy_sha256']
            and report['python'] == setup['context']['python']
            and report['source_preserved'] is True
            and report['candidate_physical_namespace_verified'] is True
            and report['outer_controller_seconds'] == 180 and report['cleanup_seconds'] == 3,
            'actual complete source-only authoring report differs')
    for flag in ('native_compiler_executed', 'Core_VM_executed', 'product_tests_executed',
                 'cold_qualified', 'old_v1_results_inherited', 'original_limits_changed',
                 'derived_global_contracts_regenerated', 'formal_full_resource_prerequisites_checked',
                 'desktop_interpreter_identity_claimed'):
        require(report[flag] is False, 'source-only report widened its scope')
    require(report['generated_outputs_are_new_v2_observations'] is True
            and report['original_AST']['original_bodies'] == 33
            and report['original_AST']['all_exact'] is True
            and len(report['original_AST']['classes']['_Function']) == 22
            and len(report['original_AST']['classes']['_Emitter']) == 6
            and len(report['original_AST']['helpers']) == 5
            and report['finite_IR']['functions'] == 36
            and report['finite_IR']['instructions'] == 2428
            and report['finite_IR']['literal_count'] == 312
            and report['finite_IR']['maximum_slots'] == 510
            and len(report['finite_IR']['modes']) == 36,
            'complete original AST or frozen finite-IR denominator differs')
    before, _ = retained(evidence / 'candidate-before.json', report['candidate_before'])
    after, _ = retained(evidence / 'candidate-after.json', report['candidate_after'])
    physical_before, _ = retained(evidence / 'candidate-physical-before.json',
                                  report['candidate_physical_before'])
    physical_after, _ = retained(evidence / 'candidate-physical-after.json',
                                 report['candidate_physical_after'])
    require(before == after and physical_before == physical_after,
            'complete before/after source originals differ')
    rows = json.loads(before)
    namespace = json.loads(physical_before)
    require(type(rows) is list and len(rows) == 4023
            and len({x['path'] for x in rows}) == 4023
            and namespace['file_count'] == 4023
            and namespace['files'] == sorted(x['path'] for x in rows)
            and namespace['excluded_only'] == ['.git']
            and namespace['ignored_and_untracked_extras_rejected'] is True,
            'complete physical source denominator differs')
    metadata = report['candidate_metadata_before']
    require(metadata == report['candidate_metadata_after']
            and metadata['actual_head'] == CANDIDATE and metadata['actual_head_tree'] == TREE
            and metadata['actual_index_tree'] == TREE and metadata['actual_head_is_candidate'] is True
            and metadata['tracked_status'] == '', 'real source Git identity was not stable')
    abi_raw, abi_pin = retained(evidence / 'hia_core_lowering_abi.json', report['abi'])
    abi = json.loads(abi_raw)
    expected_names = ['core_lowering_pool', *abi['units']]
    units = report['units']
    require(report['expected_unit_count'] == 39 and len(expected_names) == 39
            and len(set(expected_names)) == 39 and len(units) == 39
            and [x['name'] for x in units] == expected_names,
            'complete new 39-unit inventory differs')
    limits = {'source_bytes': 1048576, 'functions': 128, 'blocks_total': 1536,
              'blocks_per_function': 256, 'instructions': 8192,
              'ssa_names_per_function': 2048, 'parameters_or_arguments': 16,
              'source_lines': 16384}
    require(report['unchanged_limits'] == limits, 'original authoring limits changed')
    originals = []
    for item in units:
        name = item['name']
        require(re.fullmatch(r'[a-z0-9_]+', name) is not None
                and item['status'] == 'PASS' and item['public_core_roundtrip'] is True
                and re.fullmatch(r'[0-9a-f]{64}', item['checked_core_sha256']) is not None,
                'unit lacks its actual public Core authoring result')
        _, authored_pin = retained(evidence / 'authoring' / (name + '.py.txt'), item['authoring'])
        assembly, assembly_pin = retained(evidence / 'assembled' / (name + '.hiaasm'), item)
        require(all(type(item['structure'][key]) is int and 0 <= item['structure'][key] <= maximum
                    for key, maximum in limits.items())
                and item['structure']['source_bytes'] == len(assembly)
                and item['structure']['source_lines'] == len(assembly.splitlines()),
                'actual unit violates an unchanged source/compiler limit')
        originals.append({'name': name, 'authoring': authored_pin, 'assembly': assembly_pin,
                          'structure': item['structure'], 'checked_core_sha256': item['checked_core_sha256']})
    return {'report': report_pin, 'abi': abi_pin, 'unit_originals': originals,
            'complete_AST_bodies': 33, 'modes': 36, 'units': 39,
            'original_source_metadata': metadata}

def finalize(args):
    control, policy, _, root, source, value = context(args)
    require(root.is_dir(), 'source-only preparation never created its output root')
    final = {'schema': 'hia.core-emitter-actions-final.v1', 'status': 'HOLD',
             'context': value, 'qualification_executed': False,
             'native_compiler_executed': False, 'Core_VM_executed': False,
             'product_tests_executed': False, 'cold_qualified': False,
             'old_v1_results_inherited': False, 'original_limits_changed': False,
             'scope': 'SOURCE_ONLY_NEW_CORE_EMITTER_V2_AUTHORING',
             'desktop_interpreter_identity_claimed': False}
    try:
        setup, setup_pin = setup_record(control, policy, root, source, value)
        final['setup_original'] = setup_pin
        guardian_raw, guardian_pin = read(root / 'guard/guardian.json', 8 << 20)
        guardian = json.loads(guardian_raw)
        life = closed_owner(guardian, setup, root)
        final['guardian_original'] = guardian_pin
        final['closed_ECHILD_before_output_read'] = True
        require(guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
                and guardian['input_identity_preserved'] is True
                and guardian['source_identities_after'] == setup['source_identities']
                and guardian['cold_180_second_gate_modified'] is False
                and guardian['qualification'] is None
                and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
                and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
                and life['event_overflow'] is False and life['interrupted_signals'] == []
                and life.get('owner_error') is None,
                'source-only authoring did not end naturally within its original owner')
        events = life['events']
        require(type(events) is list and events
                and all(x['kind'] in NATURAL for x in events)
                and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                    <= {x['kind'] for x in events}, 'non-natural process lifecycle event')
        log_pins = {}
        for name in ('child.stdout.log', 'child.stderr.log'):
            _, pin = read(root / 'guard' / name, 32 << 20)
            log_pins[str(root / 'guard' / name)] = pin['sha256']
        require(guardian['logs'] == log_pins, 'original child log identity differs')
        for path, wanted in setup['source_identities'].items():
            _, pin = read(Path(path), 64 << 20,
                          system_binary=path in (value['python']['resolved'], value['git']['resolved']))
            require(pin['sha256'] == wanted, 'fixed input changed at final observation')
        final['outputs'] = verify_outputs(root, setup)
        final['source_actual_HEAD_after'] = source_head(source, value['git']['resolved'])
        final['status'] = 'SOURCE_ONLY_CORE_EMITTER_V2_AUTHORING_PASS'
    except BaseException as error:
        final['status'] = 'HOLD'
        final['error'] = {'type': type(error).__name__, 'message': str(error),
                          'traceback': traceback.format_exc()}
    record = save(root / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'final': record,
                      'qualification_executed': False}), flush=True)
    return 0 if final['status'] == 'SOURCE_ONLY_CORE_EMITTER_V2_AUTHORING_PASS' else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    return {'prepare': prepare, 'run': run, 'finalize': finalize}[args.operation](args)

if __name__ == '__main__':
    raise SystemExit(main())
