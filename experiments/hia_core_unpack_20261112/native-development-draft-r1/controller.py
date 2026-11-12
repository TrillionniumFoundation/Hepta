"""Own Core39 plus UNPACK preparation, 18 component methods, and complete116.

Preparation and the complete test command have separate, unchanged 180/3
ownership boundaries. Their combination is never a cold or matching-source
qualification claim. No split development groups are admitted here.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (PREFIX, REPO, GENERATED, create, declared_inputs, document,
                    git, git_leaves, inspect_file, metadata, natural_owner,
                    closed_owner, observe_inputs, read, require, save, snapshot, wire)
import verify

WORK_ROOT = 'hia-core-unpack-native-development-r1'
TRIGGER = 'codex/hia-core-unpack-native-development-run-r1-20261112-e26e'
PHASES = ('preparation', 'components', 'tests')
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}

def environment(value=None):
    from common import clean_environment
    result = clean_environment()
    if value is not None:
        result['CLANG'] = value['tools']['clang-20']['resolved']
        result['HEPTA_CLANG'] = value['tools']['clang-20']['resolved']
    return result

def runtime_tool(name, arguments):
    found = shutil.which(name)
    require(found is not None, 'required original native development tool missing: ' + name)
    path = Path(found).resolve(strict=True)
    _, pin = inspect_file(path, 128 << 20, system_binary=True)
    result = subprocess.run([str(path), *arguments], env=environment(),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10, check=True)
    require(len(result.stdout) + len(result.stderr) <= 1 << 20, 'unbounded tool version output')
    return {'resolved': str(path), 'binary': pin, 'version_stdout': result.stdout.decode('utf-8'),
            'version_stderr_sha256': sha256(result.stderr).hexdigest()}

def configuration(args):
    require(not any(value for name, value in os.environ.items() if name.startswith(('GIT_', 'LD_'))),
            'ambient Git or loader redirection refused before any new root')
    require(not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN'),
            'repository API/publication token must not enter native development')
    require(sys.version_info[:3] == (3, 14, 4) and platform.python_implementation() == 'CPython'
            and sys.platform == 'linux' and platform.machine().lower() in ('x86_64', 'amd64'),
            'actual pinned Actions interpreter/platform differs')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    control_checkout = workspace / 'control'
    control = Path(__file__).resolve().parent
    require(control == control_checkout / PREFIX
            and re.fullmatch('[0-9a-f]{40}', args.control_commit) is not None
            and read(control_checkout / '.git/HEAD', 256)[0].decode().strip() == args.control_commit,
            'actual exact detached control checkout differs')
    policy_raw, policy_pin = read(control / 'policy.json', 1 << 20)
    require(policy_pin['sha256'] == args.policy_sha256, 'fixed development policy bytes differ')
    policy = json.loads(policy_raw)
    candidate = policy['candidate']
    require(policy['schema'] == 'hia.core-unpack-native-actions-policy.v1'
            and policy['repository'] == REPO and policy['control_prefix'] == PREFIX
            and policy['trigger_branch'] == TRIGGER
            and re.fullmatch('[0-9a-f]{40}', candidate['commit']) is not None
            and candidate['commit'] != '0' * 40
            and re.fullmatch('[0-9a-f]{40}', candidate['tree']) is not None
            and candidate['tree'] != '0' * 40 and candidate['leaves'] == 4063
            and policy['phase_controller_seconds'] == 180 and policy['cleanup_seconds'] == 3
            and policy['compile_child_wall_seconds'] == 20
            and policy['compile_child_CPU_seconds'] == 10
            and policy['original_compile_capacity_bytes'] == 1048576
            and policy['expected_test_methods'] == 116 and policy['expected_component_methods'] == 18
            and policy['phase_names'] == list(PHASES),
            'unresolved or widened frozen development policy')
    event_raw, event_pin = read(Path(os.environ['GITHUB_EVENT_PATH']), 1 << 20)
    event = json.loads(event_raw)
    require(os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and event.get('ref_type') == 'branch' and event.get('ref') == TRIGGER
            and event.get('repository', {}).get('full_name') == REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER,
            'unique create event/first attempt binding differs')
    workflow_sha = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', workflow_sha) is not None
            and os.environ.get('HIA_CORE_UNPACK_NATIVE_WORKFLOW_SHA') == workflow_sha
            and os.environ.get('GITHUB_WORKFLOW_SHA') == workflow_sha,
            'actual workflow source identity differs')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    root = temp / WORK_ROOT
    source = workspace / 'source'
    require(args.root == root and args.source == source and source.resolve(strict=True) == source
            and not any(path.is_symlink() for path in (root.parent, *root.parent.parents,
                                                      source, *source.parents)),
            'fixed private source/output path differs')
    python = Path(sys.executable).resolve(strict=True)
    _, python_pin = inspect_file(python, 64 << 20, system_binary=True)
    git_tool = runtime_tool('git', ['--version'])
    tools = {name: runtime_tool(name, ['--version'])
             for name in ('ld', 'as', 'gcc', 'clang-20', 'objdump', 'readelf', 'nm', 'strace')}
    require('clang version 20.' in tools['clang-20']['version_stdout'],
            'actual original compiler major version differs')
    distributions = {}
    for name, version in PACKAGES.items():
        dist = importlib.metadata.distribution(name)
        require(dist.version == version, 'actual pinned original Python dependency differs: ' + name)
        files = list(dist.files or ())
        metadata_files = [item for item in files if item.name in ('METADATA', 'RECORD')
                          and item.parent.name.endswith('.dist-info')]
        require({item.name for item in metadata_files} == {'METADATA', 'RECORD'},
                'installed dependency identity files missing: ' + name)
        distributions[name] = {'version': dist.version, 'identity_files': [
            inspect_file(Path(dist.locate_file(item)).resolve(strict=True), 8 << 20,
                         system_binary=True)[1] for item in sorted(metadata_files)]}
    controls = {}
    for name, pin in policy['controls'].items():
        require(re.fullmatch('[a-z_]+[.]py', name) is not None, 'unsafe control basename')
        original, observed = read(control / name, 1 << 20)
        require(observed['bytes'] == pin['bytes'] and observed['sha256'] == pin['sha256']
                and observed['git_blob_sha1'] == pin['git_blob_sha1'], 'frozen control source differs')
        controls[str(control / name)] = pin['sha256']
    controls[str(control / 'policy.json')] = policy_pin['sha256']
    value = {'schema': 'hia.core-unpack-native-actions-context.v1', 'repository': REPO,
             'event': 'create', 'trigger_branch': TRIGGER, 'run_id': int(os.environ['GITHUB_RUN_ID']),
             'run_attempt': 1, 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
             'event_sha256': event_pin['sha256'], 'workflow_commit': workflow_sha,
             'actual_control_commit': args.control_commit, 'policy_sha256': policy_pin['sha256'],
             'control_sources': controls, 'candidate': candidate, 'source': str(source), 'root': str(root),
             'phase_controller_seconds': 180, 'cleanup_seconds': 3,
             'python': {'executable': sys.executable, 'resolved': str(python), 'version': sys.version,
                        'implementation': platform.python_implementation(), 'binary': python_pin,
                        'actual_setup_python_version': '3.14.4',
                        'desktop_binary_identity_claimed': False},
             'git': git_tool, 'tools': tools, 'python_distributions': distributions,
             'development_native_compilation_requested': True,
             'complete_116_tests_requested': True, 'cold_qualification_requested': False,
             'split_group_equivalence_claimed': False, 'old_compiler_image_reused': False}
    return control, policy, policy_raw, root, source, value

def stored_context(root, expected):
    value, pin = document(root / 'context.json', 2 << 20)
    require(set(value) == set(expected) | {'initial_source_sha256'}
            and all(value[name] == expected[name] for name in expected)
            and re.fullmatch('[0-9a-f]{64}', value['initial_source_sha256']) is not None,
            'actual fixed context differs')
    return value, pin

def system_paths(context):
    paths = {context['python']['resolved'], context['git']['resolved']}
    paths.update(item['resolved'] for item in context['tools'].values())
    paths.update(item['path'] for dist in context['python_distributions'].values()
                 for item in dist['identity_files'])
    return paths

def fixed_inputs(control, policy, root, value):
    inputs = dict(value['control_sources'])
    for name, pin in policy['controls'].items():
        inputs[str(root / 'control' / name)] = pin['sha256']
    inputs[str(root / 'control/policy.json')] = value['policy_sha256']
    inputs[str(root / 'context.json')] = sha256(wire(value)).hexdigest()
    inputs[str(root / 'initial-source.json')] = value['initial_source_sha256']
    inputs[value['python']['resolved']] = value['python']['binary']['sha256']
    inputs[value['git']['resolved']] = value['git']['binary']['sha256']
    for item in value['tools'].values():
        inputs[item['resolved']] = item['binary']['sha256']
    for dist in value['python_distributions'].values():
        for item in dist['identity_files']:
            inputs[item['path']] = item['sha256']
    return inputs

def phase_command(phase, root, source, value):
    python = value['python']['resolved']
    if phase == 'preparation':
        return [python, '-I', '-S', '-B', str(root / 'control/preparation.py'),
                '--root', str(root), '--source', str(source),
                '--policy-sha256', value['policy_sha256']]
    if phase == 'components':
        return [python, '-I', '-B', str(root / 'control/components.py'),
                '--root', str(root), '--source', str(source),
                '--policy-sha256', value['policy_sha256']]
    require(phase == 'tests', 'unknown development phase')
    # The wrapper delegates one default full15+51+50 invocation, never split groups.
    return [python, '-I', '-B', str(source / 'tools/qualify_hia_core_unpack_callers.py'),
            '--core-development-manifest', str(root / 'preparation/bundle/manifest.json'),
            '--unpack-development-manifest', str(root / 'preparation/unpack/manifest.json'),
            '--evidence', str(root / 'callers')]

def create_phase(phase, control, policy, root, source, value, rows, extra=None):
    guard = root / (phase + '-guard')
    require(not os.path.lexists(guard), 'create-only phase owner already exists')
    inputs = fixed_inputs(control, policy, root, value)
    declared = declared_inputs(source, rows)
    excluded = {str(source / name) for name in GENERATED} if phase == 'preparation' else set()
    inputs.update({path: digest for path, digest in declared.items() if path not in excluded})
    inputs.update(extra or {})
    guard.mkdir(mode=0o700)
    command = phase_command(phase, root, source, value)
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
              'command': command, 'cwd': str(root), 'source_identities': inputs}
    config_raw = wire(config)
    require(len(config_raw) <= 262144, 'original unchanged guardian request capacity exceeded')
    request_pin = create(guard / 'request.json', config_raw)
    setup = {'schema': 'hia.core-unpack-native-phase-setup.v1', 'phase': phase,
             'context': value, 'command': command, 'cwd': str(root),
             'source_identities': inputs, 'declared_source_count': len(declared),
             'intentionally_mutable_source_paths': sorted(excluded),
             'additional_original_bindings': extra or {},
             'controller_seconds': 180, 'cleanup_seconds': 3,
             'guardian_config_sha256': request_pin['sha256'],
             'cold_qualification_requested': False}
    save(root / (phase + '-setup.json'), setup)
    return setup

def setup_record(phase, control, policy, root, source, value):
    setup, pin = document(root / (phase + '-setup.json'), 2 << 20)
    require(setup['schema'] == 'hia.core-unpack-native-phase-setup.v1'
            and setup['phase'] == phase and setup['context'] == value
            and setup['command'] == phase_command(phase, root, source, value)
            and setup['cwd'] == str(root) and setup['controller_seconds'] == 180
            and setup['cleanup_seconds'] == 3 and setup['cold_qualification_requested'] is False,
            'this exact original phase setup differs')
    if phase == 'preparation':
        initial, _ = document(root / 'initial-source.json', 8 << 20)
        rows = initial['rows']
        excluded = {str(source / name) for name in GENERATED}
        require(setup['additional_original_bindings'] == {}, 'unexpected preparation extra binding')
    else:
        acceptance, _ = document(root / 'PREPARATION-ACCEPTANCE.json', 16 << 20)
        require(acceptance['status'] == 'DEVELOPMENT_PREPARATION_ACCEPTED',
                'complete test request has no admitted actual preparation')
        derived, _ = document(root / 'preparation/derived-source.json', 8 << 20)
        rows, excluded = derived['rows'], set()
        expected_extra = actual_preparation_inputs(root, acceptance)
        if phase == 'tests':
            component_acceptance, _ = document(root / 'COMPONENT-ACCEPTANCE.json', 16 << 20)
            require(component_acceptance['status'] == 'DEVELOPMENT_COMPONENTS_ACCEPTED',
                    'complete116 lacks admitted components')
            expected_extra.update(actual_component_inputs(root, component_acceptance))
        require(setup['additional_original_bindings'] == expected_extra,
                'test request does not bind exact actual preparation originals')
    declared = declared_inputs(source, rows)
    expected = fixed_inputs(control, policy, root, value)
    expected.update({path: digest for path, digest in declared.items() if path not in excluded})
    expected.update(setup['additional_original_bindings'])
    require(setup['source_identities'] == expected and setup['declared_source_count'] == len(declared)
            and setup['intentionally_mutable_source_paths'] == sorted(excluded),
            'exact phase source identities differ')
    config_raw, config_pin = read(root / (phase + '-guard/request.json'), 262144)
    config = json.loads(config_raw)
    require(config_pin['sha256'] == setup['guardian_config_sha256']
            and config == {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
                           'command': setup['command'], 'cwd': str(root),
                           'source_identities': expected}, 'actual owner request differs')
    return setup, pin

def prepare(args):
    control, policy, raw, root, source, value = configuration(args)
    require(not os.path.lexists(root), 'new development root already exists')
    capacity = os.statvfs(root.parent)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
            'original native development storage reserve unavailable')
    rows = git_leaves(source, value['git']['resolved'], policy['candidate'])
    initial = snapshot(source, value['git']['resolved'], policy['candidate'], rows)
    require(initial['actual_worktree_tree'] == policy['candidate']['tree'],
            'canonical source bytes do not reproduce its whole input tree')
    os.umask(0o077)
    root.mkdir(mode=0o700)
    (root / 'control').mkdir(mode=0o700)
    for name, pin in policy['controls'].items():
        data, observed = read(control / name, 1 << 20)
        require(observed['sha256'] == pin['sha256'], 'fixed control changed before copying')
        create(root / 'control' / name, data)
    create(root / 'control/policy.json', raw)
    snapshot_pin = save(root / 'initial-source.json', initial)
    value['initial_source_sha256'] = snapshot_pin['sha256']
    save(root / 'context.json', value)
    setup = create_phase('preparation', control, policy, root, source, value, initial['rows'])
    save(root / 'PREPARED.json', {'schema': 'hia.core-unpack-native-prepared.v1',
        'status': 'PREPARED_NOT_EXECUTED', 'context': value,
        'initial_source': snapshot_pin, 'source_file_count': len(initial['rows']),
        'resource_observation': {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                                'free_inodes': capacity.f_favail},
        'native_or_product_execution_claimed': False})
    print(json.dumps({'status': 'PREPARED_NOT_EXECUTED', 'source': policy['candidate'],
                      'request_sha256': setup['guardian_config_sha256']}), flush=True)
    return 0

def run_phase(args, phase):
    control, policy, _, root, source, observed = configuration(args)
    value, _ = stored_context(root, observed)
    setup, _ = setup_record(phase, control, policy, root, source, value)
    metadata(source, value['git']['resolved'], policy['candidate'])
    observe_inputs(setup['source_identities'], system_paths(value))
    guard = root / (phase + '-guard')
    require(not any(os.path.lexists(guard / name) for name in
                    ('guardian.json', 'child.stdout.log', 'child.stderr.log')),
            'original phase has already entered ownership; do not replay')
    python = value['python']['resolved']
    os.chdir(root)
    os.execve(python, [python, '-I', '-S', '-B', str(root / 'control/guardian.py'),
                      '--config', str(guard / 'request.json'),
                      '--config-sha256', setup['guardian_config_sha256'],
                      '--implementation', str(root / 'control/process_owner_impl.py')], environment(value))

def actual_preparation_inputs(root, acceptance):
    report = acceptance['actual_preparation']['report']
    inputs = {}
    for name in ('PREPARATION-ACCEPTANCE.json', 'preparation-setup.json',
                 'preparation-guard/request.json', 'preparation-guard/guardian.json',
                 'preparation-guard/child.stdout.log', 'preparation-guard/child.stderr.log',
                 'preparation/report.json', 'preparation/source-before.json',
                 'preparation/derived-source.json', 'preparation/source-after.json',
                 'preparation/hia_core_lowering_abi.json'):
        inputs[str(root / name)] = inspect_file(root / name, 32 << 20)[1]['sha256']
    for pin in [*report['build_files'], *report['companion_build_files']]:
        inputs[pin['path']] = pin['sha256']
    for item in [*acceptance['actual_preparation']['compile_originals'],
                 acceptance['actual_preparation']['companion']['compile_original']]:
        for pin in item['files']:
            inputs[pin['path']] = pin['sha256']
    for pin in acceptance['actual_preparation']['B0_originals'].values():
        inputs[pin['path']] = pin['sha256']
    for name in ('B0.so', 'B0.receipt.json', 'B1.image.bin', 'B1.receipt.json',
                 'B2.image.bin', 'B2.receipt.json'):
        path = root / 'preparation/bootstrap' / name
        inputs[str(path)] = inspect_file(path, 64 << 20)[1]['sha256']
    for pin in report['derived_originals'].values():
        inputs[pin['path']] = pin['sha256']
    for pin in report['final_inventory_originals'].values():
        inputs[pin['path']] = pin['sha256']
    return inputs

def admit_preparation(args):
    control, policy, _, root, source, observed = configuration(args)
    value, _ = stored_context(root, observed)
    final = {'schema': 'hia.core-unpack-native-preparation-acceptance.v1', 'status': 'HOLD',
             'context': value, 'cold_qualified': False, 'complete_116_tests_executed': False}
    try:
        setup, setup_pin = setup_record('preparation', control, policy, root, source, value)
        guardian, guardian_pin = document(root / 'preparation-guard/guardian.json', 8 << 20)
        natural_owner(guardian, setup, root, root / 'preparation-guard')
        final['closed_ECHILD_before_product_output_read'] = True
        observe_inputs(setup['source_identities'], system_paths(value))
        final['setup_original'] = setup_pin
        final['guardian_original'] = guardian_pin
        final['actual_preparation'] = verify.preparation(root, source, value, policy)
        final['status'] = 'DEVELOPMENT_PREPARATION_ACCEPTED'
    except BaseException as error:
        final['status'] = 'HOLD'
        final['error'] = {'type': type(error).__name__, 'message': str(error),
                          'traceback': traceback.format_exc()}
    save(root / 'PREPARATION-ACCEPTANCE.json', final)
    if final['status'] != 'DEVELOPMENT_PREPARATION_ACCEPTED':
        print(json.dumps({'status': final['status'], 'error': final.get('error')}, sort_keys=True), flush=True)
        return 1
    rows = final['actual_preparation']['derived_source']['rows']
    extras = actual_preparation_inputs(root, final)
    setup = create_phase('components', control, policy, root, source, value, rows, extras)
    print(json.dumps({'status': 'DEVELOPMENT_COMPONENT_REQUEST_READY',
                      'preparation_status': final['status'], 'actual_Core_units': 39,
                      'actual_UNPACK_units': 1, 'next_component_tests': 18,
                      'next_owner_seconds': 180, 'request_sha256': setup['guardian_config_sha256']},
                     sort_keys=True), flush=True)
    return 0


def actual_component_inputs(root, acceptance):
    inputs = {}
    for name in ('COMPONENT-ACCEPTANCE.json', 'components-setup.json',
                 'components-guard/request.json', 'components-guard/guardian.json',
                 'components-guard/child.stdout.log', 'components-guard/child.stderr.log'):
        inputs[str(root / name)] = inspect_file(root / name, 32 << 20)[1]['sha256']
    for pin in acceptance['actual_components']['actual_originals']:
        inputs[pin['path']] = pin['sha256']
    return inputs


def admit_components(args):
    control, policy, _, root, source, observed = configuration(args)
    value, _ = stored_context(root, observed)
    final = {'schema': 'hia.core-unpack-components-acceptance.v1', 'status': 'HOLD',
             'context': value, 'cold_qualified': False, 'complete116_executed': False}
    try:
        admission, _ = document(root / 'PREPARATION-ACCEPTANCE.json', 16 << 20)
        require(admission['status'] == 'DEVELOPMENT_PREPARATION_ACCEPTED'
                and admission.get('error') is None and admission['context'] == value,
                'components do not have admitted exact preparation')
        setup, setup_pin = setup_record('components', control, policy, root, source, value)
        guardian, guardian_pin = document(root / 'components-guard/guardian.json', 8 << 20)
        natural_owner(guardian, setup, root, root / 'components-guard')
        observe_inputs(setup['source_identities'], system_paths(value))
        final['closed_ECHILD_before_product_output_read'] = True
        final['setup_original'], final['guardian_original'] = setup_pin, guardian_pin
        prepared = verify.preparation(root, source, value, policy)
        require(prepared == admission['actual_preparation'], 'actual preparation changed during components')
        final['actual_components'] = verify.components(root, source, value, policy, prepared)
        final['status'] = 'DEVELOPMENT_COMPONENTS_ACCEPTED'
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    save(root / 'COMPONENT-ACCEPTANCE.json', final)
    if final['status'] != 'DEVELOPMENT_COMPONENTS_ACCEPTED':
        print(json.dumps({'status': final['status'], 'error': final.get('error')}, sort_keys=True), flush=True)
        return 1
    extras = actual_preparation_inputs(root, admission)
    extras.update(actual_component_inputs(root, final))
    setup = create_phase('tests', control, policy, root, source, value, prepared['derived_source']['rows'], extras)
    print(json.dumps({'status': 'DEVELOPMENT_COMPLETE116_REQUEST_READY',
                      'component_status': final['status'], 'next_complete_tests': 116,
                      'next_owner_seconds': 180, 'request_sha256': setup['guardian_config_sha256']},
                     sort_keys=True), flush=True)
    return 0


def finalize(args):
    control, policy, _, root, source, observed = configuration(args)
    require(root.is_dir(), 'native development preparation never created its root')
    value, _ = stored_context(root, observed)
    final = {'schema': 'hia.core-unpack-native-actions-final.v1', 'status': 'HOLD',
             'context': value, 'scope': 'NEW_DEVELOPMENT_CORE39_PLUS_UNPACK_COMPONENT18_AND_ONE_DEFAULT116',
             'cold_qualified': False, 'matching_source_cold_qualification_claimed': False,
             'old_compiler_or_product_results_inherited': False,
             'preparation_plus_tests_claimed_as_one_cold_180': False,
             'split_development_groups_accepted': False, 'original_limits_changed': False,
             'whole_native_claimed': False, 'production_activated': False,
             'actual_native_and_product_results_required': True}
    try:
        admission, admission_pin = document(root / 'PREPARATION-ACCEPTANCE.json', 16 << 20)
        require(admission['status'] == 'DEVELOPMENT_PREPARATION_ACCEPTED'
                and admission.get('error') is None and admission['context'] == value,
                'actual preparation was not admitted')
        final['preparation_acceptance_original'] = admission_pin
        final['phase_owners'] = {}
        for phase in PHASES:
            setup, setup_pin = setup_record(phase, control, policy, root, source, value)
            guardian, guardian_pin = document(root / (phase + '-guard/guardian.json'), 8 << 20)
            life = natural_owner(guardian, setup, root, root / (phase + '-guard'))
            observe_inputs(setup['source_identities'], system_paths(value))
            final['phase_owners'][phase] = {'setup': setup_pin, 'guardian': guardian_pin,
                'natural_exit': True, 'closed_ECHILD': True, 'controller_seconds': 180, 'cleanup_seconds': 3,
                'actual_lifecycle_event_timestamps': [
                    {'kind': row['kind'], 'monotonic_ns': row['monotonic_ns']}
                    for row in life['events']
                    if row['kind'] in ('qualification_started', 'qualification_exit_observed')]}
        final['all_owned_processes_closed_before_read'] = True
        prepared = verify.preparation(root, source, value, policy)
        require(prepared == admission['actual_preparation'], 'actual preparation originals changed')
        component_admission, component_pin = document(root / 'COMPONENT-ACCEPTANCE.json', 16 << 20)
        require(component_admission['status'] == 'DEVELOPMENT_COMPONENTS_ACCEPTED'
                and component_admission.get('error') is None and component_admission['context'] == value,
                'all18 component methods were not admitted')
        components = verify.components(root, source, value, policy, prepared)
        require(components == component_admission['actual_components'], 'component originals changed')
        final['component_acceptance_original'] = component_pin
        final['actual_components'] = components
        final['complete_native_callers'] = verify.selected_callers(root, source, value, policy, prepared)
        actual_after = snapshot(source, value['git']['resolved'], policy['candidate'],
                                prepared['derived_source']['rows'])
        final['complete_source_after'] = save(root / 'complete-source-after.json', actual_after)
        require(actual_after == prepared['derived_source'], 'complete derived source changed during 116 methods')
        final['source_preserved_after_only_two_declared_derivations'] = True
        final['status'] = 'DEVELOPMENT_CORE_UNPACK_COMPONENT18_AND_COMPLETE116_PASS'
    except BaseException as error:
        final['status'] = 'HOLD'
        final['error'] = {'type': type(error).__name__, 'message': str(error),
                          'traceback': traceback.format_exc()}
    pin = save(root / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'final': pin,
                      'cold_qualified': False, 'whole_native_claimed': False}, sort_keys=True), flush=True)
    return 0 if final['status'] == 'DEVELOPMENT_CORE_UNPACK_COMPONENT18_AND_COMPLETE116_PASS' else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run-preparation', 'admit-preparation',
                                             'run-components', 'admit-components', 'run-tests', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    operations = {'prepare': prepare, 'run-preparation': lambda a: run_phase(a, 'preparation'),
                  'admit-preparation': admit_preparation,
                  'run-components': lambda a: run_phase(a, 'components'),
                  'admit-components': admit_components, 'run-tests': lambda a: run_phase(a, 'tests'),
                  'finalize': finalize}
    return operations[args.operation](args)

if __name__ == '__main__':
    raise SystemExit(main())
