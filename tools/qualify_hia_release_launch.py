"""Qualify the original 26 selected-release launch controls from matching cold inputs.

This hosted qualification/custody driver grants no runtime selection or release
promotion. It has no development-compiler option. Historical development test
records remain separately named and cannot enter this production fixture.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

COLD_FIXTURE_ENV = 'HEPTA_HIA_RELEASE_LAUNCH_COLD_FIXTURE'
COLD_EVIDENCE_ENV = 'HEPTA_HIA_RELEASE_LAUNCH_COLD_EVIDENCE'
DEVELOPMENT_ENV = (
    'HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_BUILD',
    'HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_AGENT',
    'HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_EVIDENCE',
)
FIXTURE_SCHEMA = 'hepta.hia.release-launch-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_SOURCE_COLD_FIXTURE_BUILT'
AGENT_SCHEMA = 'hepta.hia.release-launch-cold-agent-payload.v1'
AGENT_STATUS = 'MATCHING_SOURCE_COLD_HIA_AGENT_PAYLOAD'
GROUP_SECONDS = 1800
CLEANUP_SECONDS = 5
COMPILE_SECONDS = 20
CAPACITY = 1048576
MODULE = 'tests.test_hia_release_launch'
TEST_SOURCE = 'tests/test_hia_release_launch.py'
TEST_SOURCE_SHA256 = 'bba1ae297f5345d067922adfabbe28cb54111098807e578ee4edc66a1e7f5f0c'
EXPECTED_IDS = ('tests.test_hia_release_launch.ReleaseLaunchFrameTests.test_argument_result_and_refusals_match_complete_vm_and_native_frames',
 'tests.test_hia_release_launch.ReleaseLaunchFrameTests.test_exact_entry_and_elf_refusal_match_complete_vm_and_native_frames',
 'tests.test_hia_release_launch.ReleaseLaunchFrameTests.test_seal_digest_terminal_and_replay_match_complete_vm_and_native_frames',
 'tests.test_hia_release_launch.ReleaseLaunchInstalledAgentTests.test_actual_hia_stdio_capabilities_verify_compile_and_assembly_through_selected_release',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_actual_trace_seals_readback_single_exec_and_descriptor_cleanup',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_business_stdin_stdout_and_same_process_native_pid',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_changed_installed_permissions_bytes_and_symlink_refuse',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_exact_native_exit_and_original_verify_remains_nonexecuting',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_explicit_native_text_and_dynamic_elf_profile_refuse_only_execution',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_hardlinked_entry_and_replaced_selection_during_actual_read_refuse',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_inherited_sigpipe_is_preserved_across_in_place_exec',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_missing_package_descriptor_and_wrong_arity_never_execute',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_native_signal_termination_is_not_relabelled_a_launcher_success',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_nonexecuting_mode_and_noncanonical_elf_are_not_old_verify_refusals',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_signal_cancellation_keeps_process_group_and_releases_selection_lock',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_stale_sequence_release_and_separate_execution_digest_refuse',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_target_observes_all_seals_no_private_descriptors_and_empty_environment',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_builder_rejects_unqualified_cold_before_output',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_generated_hia_and_verifier_transport_preimages_are_exact',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_independent_vm_actual_seal_metadata_digest_and_one_terminal',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_independent_vm_arguments_complete_buffers_and_bounds',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_independent_vm_entry_and_exact_canonical_elf',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_actual_eintr_preserves_capture_memfd_write_and_seal_operations',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_exec_refusal_returns_once_without_retry_or_path_execution',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_false_short_write_and_incomplete_seal_readback_cannot_execute',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_memfd_seal_and_descriptor_cleanup_feature_refusals_have_no_fallback')
GROUPS = ('local-observations', 'required-ptrace')
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
EXTRA_REQUIRED_SOURCES = (
    'tools/qualify_hia_release_launch.py',
    'tests/test_hia_release_launch.py',
    'tests/test_hia_release_launch_qualifier.py',
    'tests/test_hia_release_install.py',
    'tests/test_hia_agent_stdio.py',
    'tools/build_hia_agent_stdio.py',
    'tools/build_hia_json_preflight.py',
    'tools/generate_hia_agent_stdio.py',
    'tools/generate_hia_core_json_cli.py',
    'tools/qualify_hia_selfhost.py',
    'tools/qualify_hia_selfhost_cli.py',
    'tools/hia_selfhost_child.py',
    'tools/hia_selfhost_contract.py',
    'examples/hia_bootstrap/agent_stdio_dispatch.hepta',
    'examples/hia_bootstrap/agent_stdio_packer.hepta',
    'examples/hia_bootstrap/core_json_frontend.hepta',
    'examples/hia_bootstrap/bytesum.hepta',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON constant: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def _publish(path, value):
    with Path(path).open('xb') as stream:
        stream.write(_wire(value))


def _pin(path):
    path = Path(path).absolute()
    observed = path.lstat()
    require(stat.S_ISREG(observed.st_mode), 'regular input required: ' + str(path))
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'mode': stat.S_IMODE(observed.st_mode)}


def _check_bindings(bindings):
    require(type(bindings) is list and bindings, 'nonempty exact input bindings required')
    paths = []
    for item in bindings:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256', 'mode'},
                'unknown input binding')
        require(type(item['path']) is str and Path(item['path']).is_absolute(), 'absolute input required')
        require(type(item['bytes']) is int and type(item['mode']) is int, 'exact integer input identity required')
        require(_pin(item['path']) == item, 'qualification input changed: ' + item['path'])
        paths.append(item['path'])
    require(len(paths) == len(set(paths)), 'duplicate qualification input binding')


def required_source_names():
    from tools import build_hia_release_install as install
    from tools import build_hia_release_selection as selection
    from tools import build_hia_release_launch as launch
    return tuple(sorted(set(EXTRA_REQUIRED_SOURCES) | set(install.SOURCES)
                        | set(selection.SOURCES) | set(launch.SOURCES)))


def _admit_required_sources(sources, root=ROOT, names=None):
    require(type(sources) is dict, 'complete cold source map required')
    for name in required_source_names() if names is None else names:
        require(name in sources, 'launcher qualification input missing from cold source contract: ' + name)
        require(sources[name] == sha256((Path(root) / name).read_bytes()).hexdigest(),
                'launcher qualification source identity differs: ' + name)


def _outer_shape(outer):
    require(type(outer) is dict and outer.get('schema') == 'hepta.hia.selfhost-cold-replay.v1'
            and outer.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
            and type(outer.get('returncode')) is int and outer['returncode'] == 0,
            'a completed matching cold replay is required')
    require(type(outer.get('qualification_wall_limit_seconds')) is int
            and outer['qualification_wall_limit_seconds'] == 180
            and type(outer.get('cleanup_wall_limit_seconds')) is int
            and outer['cleanup_wall_limit_seconds'] == 3,
            'original cold limits must remain 180+3 seconds')
    owner = outer.get('process_owner')
    require(type(owner) is dict and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
            and type(owner.get('returncode')) is int and owner['returncode'] == 0
            and owner.get('timed_out') is False
            and owner.get('exit_observed_before_deadline') is True
            and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True,
            'cold process completion and cleanup are not established')
    require(type(outer.get('nested_report')) is str and outer['nested_report']
            and type(outer.get('nested_report_sha256')) is str,
            'actual nested cold report is required')


def admit_cold(cold_report):
    """Read original authority and all three actual generations, before writes."""
    from tools.build_hia_json_preflight import admit_cold_build
    cold_path = Path(cold_report).resolve(strict=True)
    cold_raw = cold_path.read_bytes()
    outer = _json(cold_raw)
    _outer_shape(outer)
    nested_path = Path(outer['nested_report']).resolve(strict=True)
    nested_raw = nested_path.read_bytes()
    require(sha256(nested_raw).hexdigest() == outer['nested_report_sha256'], 'nested cold report changed')
    nested = _json(nested_raw)
    require(type(nested) is dict and nested.get('schema') == 'hepta.hia.selfhost-qualification.v6'
            and nested.get('status') == 'SELF_HOSTED_FIXED_CORE_PASS'
            and type(nested.get('checks')) is dict and nested['checks']
            and all(value is True for value in nested['checks'].values()), 'nested cold qualification failed')
    generations = nested.get('generations')
    require(type(generations) is list and len(generations) == 3
            and all(type(row) is dict for row in generations), 'three actual cold generations required')
    paths = [Path(row['produced_image']).resolve(strict=True) for row in generations]
    raws = [path.read_bytes() for path in paths]
    hashes = [sha256(raw).hexdigest() for raw in raws]
    require([row.get('produced_sha256') for row in generations] == hashes
            == outer.get('generation_sha256') and len(set(hashes)) == 1
            and all(type(row.get('produced_bytes')) is int and row['produced_bytes'] == len(raw)
                    for row, raw in zip(generations, raws)), 'actual cold generation bytes differ')
    sources = admit_cold_build(raws[-1], cold_raw)
    require(nested.get('source_manifest') == sources and nested.get('profile') == outer.get('profile'),
            'nested source/profile identity differs')
    _admit_required_sources(sources)
    require(sha256((ROOT / TEST_SOURCE).read_bytes()).hexdigest() == TEST_SOURCE_SHA256,
            'original launcher caller source changed')
    bound = list(dict.fromkeys((cold_path, nested_path, *paths)))
    result = {'cold_report': str(cold_path), 'nested_report': str(nested_path),
              'compiler': str(paths[-1]), 'compiler_sha256': hashes[-1],
              'cold_report_sha256': sha256(cold_raw).hexdigest(),
              'source_manifest': sources, 'input_bindings': [_pin(path) for path in bound]}
    guard_authority(result)
    return result


def guard_authority(authority):
    from tools.build_hia_json_preflight import current_sources
    _check_bindings(authority['input_bindings'])
    require(current_sources() == authority['source_manifest'], 'full matching-cold source map changed')
    _admit_required_sources(authority['source_manifest'])


def _observation(directory, label, image, payload):
    """Bind the actual request, receipt and full output to captured call inputs."""
    from tools.qualify_hia_selfhost import CHILD, _compile_observation_size
    directory, image = Path(directory), Path(image)
    receipt = _json((directory / (label + '.receipt.json')).read_bytes())
    request = _json((directory / (label + '.request.json')).read_bytes())
    source = directory / (label + '.input.bin')
    output_path = directory / (label + '.output.bin')
    output = output_path.read_bytes()
    image_sha, source_sha = sha256(image.read_bytes()).hexdigest(), sha256(payload).hexdigest()
    require(type(request) is dict and set(request) == {'capacity', 'format', 'image', 'image_sha256',
            'output', 'source', 'source_sha256', 'workspace_fill', 'workspace_size'}
            and source.read_bytes() == payload and request.get('image') == str(image.resolve())
            and request.get('source') == str(source.resolve())
            and request.get('output') == str(output_path.resolve())
            and request.get('format') == 'flat-x86-64'
            and request.get('image_sha256') == image_sha
            and request.get('source_sha256') == source_sha
            and type(request.get('capacity')) is int and request['capacity'] == CAPACITY
            and type(request.get('workspace_size')) is int and request['workspace_size'] == CAPACITY
            and type(request.get('workspace_fill')) is int and request['workspace_fill'] == 0,
            'actual native request differs from captured inputs: ' + label)
    size = _compile_observation_size(receipt, output, image_format='flat-x86-64',
                                   compiler_sha256=image_sha, source_sha256=source_sha, input_bytes=len(payload))
    require(size is not None and receipt.get('case') == label
            and receipt.get('runner_sha256') == sha256(CHILD.read_bytes()).hexdigest(),
            'actual native receipt differs from captured inputs: ' + label)
    limits = receipt.get('limits')
    require(limits == {'address_bytes': 268435456, 'core_dumpable': False,
            'cpu_seconds': 10, 'output_capacity': CAPACITY, 'stack_bytes': 8388608,
            'workspace_bytes': CAPACITY} and limits['core_dumpable'] is False
            and all(type(limits[name]) is int for name in limits if name != 'core_dumpable'),
            'original native child limits differ: ' + label)
    return receipt, output[:size]


def _compile_observation(directory, label, compiler, source):
    receipt, produced = _observation(directory, label, compiler, source)
    path = Path(directory) / (label + '.image.bin')
    require(receipt.get('produced_image') == str(path) and receipt.get('produced_sha256') == sha256(produced).hexdigest()
            and type(receipt.get('produced_bytes')) is int and receipt['produced_bytes'] == len(produced)
            and path.read_bytes() == produced, 'compiled image differs from actual output: ' + label)
    return path, receipt


def _tool_build(folder, role, authority):
    from tools import build_hia_release_install as install
    from tools import build_hia_release_selection as selection
    from tools import build_hia_release_launch as launch
    from tools.qualify_hia_selfhost_cli import inspect_executable
    configs = {
        'install': (install, ('policy', 'packer', 'sha256'), ('policy', 'sha256'),
                    'hia-release', 'hepta.hia.release-install-build.v1', 'NATIVE_RELEASE_INSTALLER_BUILT', 'release-pack'),
        'selection': (selection, ('policy', 'sha256', 'selection', 'packer'), ('policy', 'sha256', 'selection'),
                      'hia-select', 'hepta.hia.release-selection-build.v1', 'NATIVE_RELEASE_SELECTION_BUILT', 'selection-pack'),
        'launch': (launch, ('installer', 'sha256', 'selection', 'launch', 'packer'),
                   ('installer', 'sha256', 'selection', 'launch'), 'hia-run-selected',
                   'hepta.hia.release-launch-build.v1', 'NATIVE_SELECTED_RELEASE_LAUNCHER_BUILT', 'launch-pack'),
    }
    builder, labels, payload_labels, executable_name, schema, status, pack_label = configs[role]
    report = _json((folder / 'build.json').read_bytes())
    sources = {name: (ROOT / name).read_bytes() for name in builder.SOURCES}
    require(report.get('schema') == schema and report.get('status') == status
            and report.get('source_manifest') == authority['source_manifest']
            and report.get('source_sha256') == {name: sha256(raw).hexdigest() for name, raw in sources.items()}
            and report.get('compiler_sha256') == authority['compiler_sha256']
            and report.get('cold_report_sha256') == authority['cold_report_sha256'],
            'production builder source or cold binding differs: ' + role)
    images, receipts = {}, {}
    for label, source_name in zip(labels, builder.SOURCES):
        images[label], receipts[label] = _compile_observation(folder, label, authority['compiler'], sources[source_name])
    payloads = [images[label].read_bytes() for label in payload_labels]
    frame = struct.pack('<' + str(len(payloads) + 1) + 'Q', builder.MAGIC, *map(len, payloads)) + b''.join(payloads)
    pack, executable = _observation(folder, pack_label, images['packer'], frame)
    path = folder / executable_name
    require(path.read_bytes() == executable and stat.S_IMODE(path.stat().st_mode) == 0o700
            and report.get('executable_path') == executable_name
            and report.get('executable_sha256') == sha256(executable).hexdigest()
            and report.get('executable') == inspect_executable(executable)
            and report.get('compile_receipts') == receipts and report.get('pack_receipt') == pack
            and report.get('image_sha256') == {label: sha256(image.read_bytes()).hexdigest() for label, image in images.items()},
            'production executable or actual receipts differ: ' + role)
    return path, images


def _agent_build(folder, sample_folder, authority):
    from tools.generate_hia_agent_stdio import MAGIC, LIMIT
    from tools.qualify_hia_selfhost_cli import inspect_executable
    compiler = authority['compiler']
    report = _json((folder / 'build.json').read_bytes())
    names = ('agent_stdio_dispatch', 'agent_stdio_packer', 'core_json_frontend', 'bytesum')
    sources = {name: (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes() for name in names}
    dispatch, dr = _compile_observation(folder, 'agent-dispatch', compiler, sources['agent_stdio_dispatch'])
    packer, pr = _compile_observation(folder, 'agent-packer', compiler, sources['agent_stdio_packer'])
    frontend, fr = _compile_observation(folder / 'frontend', 'core-json-frontend', compiler, sources['core_json_frontend'])
    manifest = _json((folder / 'frontend/manifest.json').read_bytes())
    front_build = _json((folder / 'frontend/build.json').read_bytes())
    require(manifest == {'schema': 'hepta.hia.core-json-frontend-native.v1',
                        'source_sha256': sha256(sources['core_json_frontend']).hexdigest(),
                        'image_path': frontend.name, 'image_sha256': sha256(frontend.read_bytes()).hexdigest(),
                        'compiler_sha256': authority['compiler_sha256']}
            and front_build.get('schema') == 'hepta.hia.core-json-frontend-build.v1'
            and front_build.get('status') == 'NATIVE_CANDIDATE_BUILT'
            and front_build.get('source_manifest') == authority['source_manifest']
            and front_build.get('cold_report_sha256') == authority['cold_report_sha256']
            and front_build.get('manifest') == manifest and front_build.get('native_compile_receipt') == fr,
            'actual Agent frontend admission chain differs')
    payloads = [dispatch.read_bytes(), frontend.read_bytes(), Path(compiler).read_bytes()]
    frame = struct.pack('<5Q', MAGIC, *map(len, payloads), 0) + b''.join(payloads)
    require(len(frame) <= LIMIT, 'unchanged Agent packer frame limit exceeded')
    pack, executable = _observation(folder, 'agent-pack', packer, frame)
    path = folder / 'hia-native'
    require(path.read_bytes() == executable and stat.S_IMODE(path.stat().st_mode) == 0o700
            and report.get('schema') == 'hepta.hia.agent-stdio-build.v1'
            and report.get('status') == 'NATIVE_AGENT_STDIO_BUILT' and report.get('output_profile') == 'flat'
            and report.get('compiler_sha256') == authority['compiler_sha256']
            and report.get('cold_report_sha256') == authority['cold_report_sha256']
            and report.get('source_sha256') == {'examples/hia_bootstrap/' + name + '.hepta': sha256(sources[name]).hexdigest()
                                               for name in names[:3]}
            and report.get('dispatch_sha256') == sha256(payloads[0]).hexdigest()
            and report.get('frontend_sha256') == sha256(payloads[1]).hexdigest()
            and report.get('packer_sha256') == sha256(packer.read_bytes()).hexdigest()
            and report.get('frame_sha256') == sha256(frame).hexdigest()
            and report.get('dispatch_compile_receipt') == dr and report.get('packer_compile_receipt') == pr
            and report.get('pack_receipt') == pack and report.get('executable') == inspect_executable(executable),
            'actual Agent build/pack custody differs')
    sample, sr = _compile_observation(sample_folder, 'bytesum', compiler, sources['bytesum'])
    return {'schema': AGENT_SCHEMA, 'status': AGENT_STATUS, 'matching_cold': True,
            'whole_native': False, 'compiler_sha256': authority['compiler_sha256'],
            'cold_report_sha256': authority['cold_report_sha256'],
            'source_sha256': {name: sha256(raw).hexdigest() for name, raw in sources.items()},
            'path': str(path), 'bytes': len(executable), 'sha256': sha256(executable).hexdigest(),
            'sample_image': str(sample), 'sample_image_sha256': sha256(sample.read_bytes()).hexdigest(),
            'sample_compile_receipt': sr}


def _fixture_description(output, authority):
    applications, images = {}, {}
    for role in ('install', 'selection', 'launch'):
        executable, images[role] = _tool_build(output / role, role, authority)
        applications[executable.name] = {**_pin(executable)}
    agent = _agent_build(output / 'agent', output / 'sample', authority)
    names = ('release_install_policy', 'release_install_packer', 'sha256_stream',
             'release_selection_policy', 'release_selection_packer', 'release_launch_policy', 'release_launch_packer')
    bindings = []
    for role in ('install', 'selection', 'launch', 'agent', 'sample'):
        for path in sorted((output / role).rglob('*')):
            if path.is_dir():
                require(not path.is_symlink(), 'fixture directory link refused')
            else:
                bindings.append(_pin(path))
    policy = images['launch']['launch']
    description = {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS, 'matching_cold': True,
                   'whole_native': False, 'qualification_complete': False,
                   'authority': authority, 'executables': applications,
                   'source_sha256': {name: sha256((ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes()).hexdigest()
                                     for name in names},
                   'policy_image': str(policy), 'policy_sha256': sha256(policy.read_bytes()).hexdigest(),
                   'build_input_bindings': bindings, 'agent_record': _pin(output / 'AGENT.json')}
    return description, agent


def prepare_fixture(output, cold_report):
    """Use only the original strict production builders and actual cold compiler."""
    from tools import build_hia_release_install, build_hia_release_selection, build_hia_release_launch, build_hia_agent_stdio
    from tools.qualify_hia_selfhost import compile_stage
    authority = admit_cold(cold_report)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive new cold fixture directory required')
    output.mkdir(mode=0o700)
    compiler, cold = Path(authority['compiler']), Path(authority['cold_report'])
    for role, builder in (('install', build_hia_release_install), ('selection', build_hia_release_selection),
                          ('launch', build_hia_release_launch), ('agent', build_hia_agent_stdio)):
        guard_authority(authority)
        builder.build(output / role, compiler, cold)
        guard_authority(authority)
    sample = output / 'sample'
    sample.mkdir(mode=0o700)
    compile_stage(sample, 'bytesum', compiler, (ROOT / 'examples/hia_bootstrap/bytesum.hepta').read_bytes())
    agent = _agent_build(output / 'agent', sample, authority)
    _publish(output / 'AGENT.json', agent)
    description, actual_agent = _fixture_description(output, authority)
    require(actual_agent == agent, 'Agent fixture changed before publication')
    guard_authority(authority)
    path = output / 'FIXTURE.json'
    _publish(path, description)
    admit_fixture(path)
    return path


def admit_fixture(path):
    """A selected fixture is re-admitted; its matching_cold flag is not authority."""
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    selected = _json(raw)
    require(type(selected) is dict and selected.get('schema') == FIXTURE_SCHEMA
            and selected.get('status') == FIXTURE_STATUS and selected.get('matching_cold') is True
            and selected.get('whole_native') is False and selected.get('qualification_complete') is False,
            'explicit production cold fixture required; development records are not cold authority')
    authority = admit_cold(selected['authority']['cold_report'])
    require(selected.get('authority') == authority, 'fixture cold authority changed')
    _check_bindings(selected['build_input_bindings'])
    actual, agent = _fixture_description(path.parent, authority)
    require(actual == selected and _json((path.parent / 'AGENT.json').read_bytes()) == agent,
            'fixture differs from actual production builders or Agent payload')
    guard_authority(authority)
    require(path.read_bytes() == raw, 'cold fixture record changed during admission')
    return selected


def selected_cold_fixture(environment=None):
    env = os.environ if environment is None else environment
    if COLD_FIXTURE_ENV not in env:
        return None
    value = env[COLD_FIXTURE_ENV]
    require(type(value) is str and value, 'empty cold fixture selection is not absence')
    require(not any(name in env for name in DEVELOPMENT_ENV), 'cold and development fixture selections cannot mix')
    return Path(value)


def load_cold_fixture():
    path = selected_cold_fixture()
    require(path is not None, 'explicit cold fixture required')
    data = admit_fixture(path)
    return path, data


def load_cold_agent():
    path, fixture = load_cold_fixture()
    selected = path.parent / 'AGENT.json'
    require(_pin(selected) == fixture['agent_record'], 'cold Agent fixture identity changed')
    raw = selected.read_bytes()
    return selected, raw, _json(raw)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def group_ids(group):
    require(group in GROUPS, 'unknown launcher group')
    ptrace = [value for value in EXPECTED_IDS if '.ReleaseLaunchSyscallFaultTests.' in value
              or value.endswith('.test_actual_trace_seals_readback_single_exec_and_descriptor_cleanup')]
    return ptrace if group == 'required-ptrace' else [value for value in EXPECTED_IDS if value not in ptrace]


def load_suite(group):
    require(sha256((ROOT / TEST_SOURCE).read_bytes()).hexdigest() == TEST_SOURCE_SHA256,
            'frozen original launcher caller module differs')
    loader = unittest.TestLoader()
    whole = loader.loadTestsFromName(MODULE)
    all_ids = [case.id() for case in flatten(whole)]
    require(not loader.errors and all_ids == list(EXPECTED_IDS) and len(set(all_ids)) == 26,
            'original complete 26-method launcher discovery differs')
    require(Path(sys.modules[MODULE].__file__).resolve() == ROOT / TEST_SOURCE, 'caller module came from another source')
    ids = group_ids(group)
    suite = loader.loadTestsFromNames(ids)
    require(not loader.errors and [case.id() for case in flatten(suite)] == ids, 'group discovery differs')
    return suite, ids


def admit_child_observations(report, request_sha, group):
    ids = group_ids(group)
    require(type(report) is dict and report.get('schema') == 'hepta.hia.release-launch-observations.v1'
            and report.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
            and report.get('status') == 'PASS' and report.get('request_sha256') == request_sha
            and report.get('group') == group and report.get('loaded_ids') == ids
            and report.get('executed_ids') == ids and type(report.get('tests_run')) is int
            and report['tests_run'] == len(ids) and report.get('source_and_inputs_unchanged') is True,
            'complete original launcher observations differ')
    anomalies = report.get('anomalies')
    require(type(anomalies) is dict and set(anomalies) == set(ANOMALIES)
            and all(type(anomalies[name]) is list and not anomalies[name] for name in ANOMALIES),
            'original launcher failure, error, skip or expected failure cannot qualify')


def _child(request_path):
    raw = Path(request_path).read_bytes()
    request = _json(raw)
    output = Path(request['output'])
    report = {'schema': 'hepta.hia.release-launch-observations.v1', 'status': 'FAIL',
              'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'request_sha256': sha256(raw).hexdigest(),
              'python': sys.version, 'group': request['group'], 'loaded_ids': [], 'executed_ids': [],
              'tests_run': 0, 'anomalies': {name: [] for name in ANOMALIES}}
    started = time.monotonic_ns()
    authority = None
    try:
        require(request.get('schema') == 'hepta.hia.release-launch-group-request.v1', 'unknown group request')
        path, fixture = load_cold_fixture()
        require(str(path) == request['fixture'] and _pin(path) == request['fixture_binding'], 'group fixture changed')
        authority = fixture['authority']
        require(authority['source_manifest'] == request['source_manifest'], 'group source changed')
        suite, ids = load_suite(request['group'])
        report['loaded_ids'] = ids
        executed = report['executed_ids']
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report['tests_run'] = result.testsRun
        report['anomalies'] = {
            'failures': [(test.id(), trace) for test, trace in result.failures],
            'errors': [(test.id(), trace) for test, trace in result.errors],
            'skipped': [(test.id(), why) for test, why in result.skipped],
            'expected_failures': [(test.id(), trace) for test, trace in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses]}
        if executed == ids and type(result.testsRun) is int and result.testsRun == len(ids) and not any(report['anomalies'].values()):
            report['status'] = 'PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        try:
            require(authority is not None, 'child never admitted current cold authority')
            guard_authority(authority)
            require(_pin(request['fixture']) == request['fixture_binding'], 'child fixture record changed')
            admit_fixture(request['fixture'])
            require(Path(request_path).read_bytes() == raw, 'child request changed')
            report['source_and_inputs_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns() - started
        _publish(output, report)
    return 0 if report['status'] == 'PASS' else 1


def _prepare_child(output, cold_report):
    report = {'schema': 'hepta.hia.release-launch-fixture-preparation.v1', 'status': 'FAIL',
              'matching_cold': False, 'qualification_complete': False, 'whole_native': False}
    try:
        path = prepare_fixture(output / 'fixture', cold_report)
        report.update(status='PASS', matching_cold=True, fixture=str(path), fixture_binding=_pin(path))
    except BaseException:
        report['traceback'] = traceback.format_exc()
    _publish(output / 'PREPARE.json', report)
    return 0 if report['status'] == 'PASS' else 1


def run_stage(argv, output, environment):
    """Preserve original 1800-second stage and five-second direct-child cleanup."""
    output.mkdir(mode=0o700)
    report = {'argv': argv, 'group_seconds': GROUP_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
              'timed_out': False, 'returncode': None, 'direct_child_reaped': False,
              'cleanup_attempted': False,
              'cleanup_scope': 'original process group and direct child; no independent descendant-completeness claim'}
    _publish(output / 'COMMAND.json', report)
    started = time.monotonic_ns()
    child = None
    try:
        with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
            child = subprocess.Popen(argv, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            report['pid'] = child.pid
            try:
                report['returncode'] = child.wait(timeout=GROUP_SECONDS)
            except subprocess.TimeoutExpired:
                report['timed_out'] = True
                report['cleanup_attempted'] = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                report['returncode'] = child.wait(timeout=CLEANUP_SECONDS)
            report['direct_child_reaped'] = True
    except BaseException:
        report['traceback'] = traceback.format_exc()
        if child is not None and child.poll() is None and not report['cleanup_attempted']:
            report['cleanup_attempted'] = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
                report['returncode'] = child.wait(timeout=CLEANUP_SECONDS)
                report['direct_child_reaped'] = True
            except BaseException:
                report['cleanup_error'] = traceback.format_exc()
    finally:
        report['wall_ns'] = time.monotonic_ns() - started
        report['status'] = ('PASS' if type(report['returncode']) is int and report['returncode'] == 0
                            and report['timed_out'] is False and report['direct_child_reaped'] is True
                            and 'traceback' not in report else 'FAIL')
        _publish(output / 'TERMINAL.json', report)
    return report


def qualify(output, cold_report):
    authority = admit_cold(cold_report)
    require(sys.platform == 'linux' and platform.machine().lower() in ('x86_64', 'amd64'), 'Linux x86-64 required')
    environment = dict(os.environ)
    removed = sorted(name for name in environment if name.startswith('HEPTA_'))
    for name in removed:
        del environment[name]
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    prerequisites = {name: shutil.which(name, path=environment.get('PATH')) for name in ('as', 'objcopy', 'strace')}
    require(all(prerequisites.values()), 'real assembler, objcopy and ptrace tracer are required; no skip fallback')
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'exclusive qualification evidence directory required')
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.release-launch-qualification.v1', 'status': 'FAIL',
              'scope': 'MATCHING_SOURCE_COLD_RELEASE_LAUNCH', 'matching_cold': True,
              'whole_native_delivery_qualified': False, 'default_activated': False,
              'old_verify_grants_execution': False, 'qualification_complete': False,
              'expected_ids': list(EXPECTED_IDS), 'expected_count': 26,
              'groups': [], 'source_before': authority['source_manifest'],
              'authority': authority, 'prerequisites': prerequisites,
              'cleared_inherited_selector_names': removed,
              'group_seconds': GROUP_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
              'compiler_child_seconds': COMPILE_SECONDS, 'compiler_output_and_workspace_bytes': CAPACITY,
              'original_native_call_seconds': 30, 'original_native_call_cleanup_seconds': 5,
              'original_assertions_and_budgets_changed': False}
    started = time.monotonic_ns()
    fixture = None
    try:
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--_prepare-output', str(output),
                   '--cold-report', authority['cold_report']]
        report['preparation_terminal'] = run_stage(command, output / 'prepare-command', environment)
        preparation = _json((output / 'PREPARE.json').read_bytes())
        report['preparation'] = preparation
        require(report['preparation_terminal']['status'] == 'PASS' and preparation.get('status') == 'PASS',
                'strict production fixture preparation failed')
        fixture = Path(preparation['fixture'])
        require(_pin(fixture) == preparation['fixture_binding'], 'prepared fixture identity differs')
        admit_fixture(fixture)
        passed = True
        for group in GROUPS:
            guard_authority(authority)
            group_folder = output / group
            group_folder.mkdir(mode=0o700)
            request = {'schema': 'hepta.hia.release-launch-group-request.v1', 'group': group,
                       'fixture': str(fixture), 'fixture_binding': _pin(fixture),
                       'source_manifest': authority['source_manifest'], 'output': str(group_folder / 'REPORT.json')}
            request_path = group_folder / 'REQUEST.json'
            _publish(request_path, request)
            child_env = {**environment, COLD_FIXTURE_ENV: str(fixture),
                         COLD_EVIDENCE_ENV: str(group_folder / 'kernel-controls')}
            command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--_child-request', str(request_path)]
            terminal = run_stage(command, group_folder / 'command', child_env)
            item = {'group': group, 'terminal': terminal, 'status': 'FAIL'}
            try:
                observations = _json((group_folder / 'REPORT.json').read_bytes())
                item['observations'] = observations
                admit_child_observations(observations, sha256(request_path.read_bytes()).hexdigest(), group)
                require(terminal['status'] == 'PASS', 'original launcher child did not finish successfully')
                item['status'] = 'PASS'
            except BaseException:
                item['traceback'] = traceback.format_exc()
                passed = False
            report['groups'].append(item)
        require(passed and len(report['groups']) == 2, 'complete original 21+5 launcher conjunction failed')
        report.update(status='MATCHING_SOURCE_COLD_RELEASE_LAUNCH_PASS', qualification_complete=True)
    except BaseException:
        report.update(status='FAIL', qualification_complete=False, traceback=traceback.format_exc())
    finally:
        try:
            guard_authority(authority)
            if fixture is not None:
                admit_fixture(fixture)
            from tools.build_hia_json_preflight import current_sources
            report.update(source_after=current_sources(), source_and_inputs_unchanged=True)
        except BaseException:
            report.update(status='FAIL', qualification_complete=False, source_and_inputs_unchanged=False,
                          final_guard_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns() - started
        _publish(output / 'REPORT.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--_prepare-output', type=Path)
    parser.add_argument('--_child-request', type=Path)
    args = parser.parse_args(argv)
    if args._child_request is not None:
        require(args.cold_report is None and args.evidence is None and args._prepare_output is None,
                'child invocation cannot mix qualifier arguments')
        return _child(args._child_request)
    if args._prepare_output is not None:
        require(args.cold_report is not None and args.evidence is None, 'explicit production cold preparation required')
        return _prepare_child(args._prepare_output, args.cold_report)
    require(args.cold_report is not None and args.evidence is not None, '--cold-report and --evidence are required')
    report = qualify(args.evidence, args.cold_report)
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'qualification_complete', 'whole_native_delivery_qualified')}))
    return 0 if report['status'] == 'MATCHING_SOURCE_COLD_RELEASE_LAUNCH_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
