"""Qualify all six protocol-04 native controls under a separate 180/3 owner.

The unchanged test fixture compiles both JSON wire and binary64 formatting
from this exact completed cold B3. This command does not replace the original
wire89, cache7, Core116, UNPACK18, or any of the thirty-two mandatory gates.
The complete fixture, twelve compile originals, actual step-return matrix,
test report and original process-owner evidence are retained for readback.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools import hia_store_page_gates as originals

SCHEMA = 'hepta.hia.json-wire-key-summary-native6.v1'
SCOPE = 'MATCHING_SOURCE_COLD_WIRE_KEY_SUMMARY_NATIVE6'
MODULE = 'tests.test_hia_json_wire_key_summary'
CLASS = MODULE + '.WireKeySummaryNativeTests'
IDS = tuple(CLASS + '.' + name for name in (
    'test_budget_unicode_collision_and_failure_order_are_unchanged',
    'test_cache_capacity_collision_and_long_keys_fall_back',
    'test_foreign_renderer_and_replaced_observer_keep_legacy_protocol',
    'test_ordinary_entry_has_fresh_cache_and_no_host_encoder',
    'test_protocol04_rejects_cross_version_ack_and_preserves_canaries',
    'test_repeated_keys_keep_every_value_child_and_sort_observation'))
ANOMALIES = ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes')
COMPILE_SUFFIXES = ('.receipt.json', '.stdout.log', '.stderr.log',
                    '.request.json', '.input.bin', '.output.bin')
SOURCE_FILES = (
    'tools/qualify_hia_json_wire_key_summary.py', 'tests/test_hia_json_wire_key_summary.py',
    'tests/test_hia_json_wire_native.py', 'hepta/hia_json_wire_native.py',
    'hepta/hia_agent_binary64_format_native.py', 'hepta/hia_json_preflight_native.py',
    'examples/hia_bootstrap/json_wire.hiaasm', 'examples/hia_bootstrap/agent_binary64_format.hiaasm',
    'tools/build_hia_json_wire.py', 'tools/build_hia_agent_binary64_format.py',
    'tools/build_hia_json_preflight.py', 'tools/qualify_hia_selfhost.py',
    'tools/hia_selfhost_child.py', 'tools/hia_selfhost_process_owner.py',
    'tools/hia_store_page_gates.py', 'tools/qualify_hia_compiler_owner_ci.py')
require = originals.require


def read(path, maximum=16 * 1024 * 1024):
    """Read a fixed original completely or refuse; never truncate its bytes."""
    path = Path(path).absolute()
    current = Path(path.anchor)
    parents = []
    for part in path.parts[1:-1]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                'wire6 original has a non-directory or symbolic-link ancestor')
        parents.append((current, (info.st_dev, info.st_ino, info.st_mode)))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            'wire6 original must be a regular file')
    require(0 <= info.st_size <= maximum, 'wire6 original exceeds its complete-read bound')
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(info), 'wire6 original changed before open')
        body = stream.read(maximum + 1)
        require(identity(os.fstat(stream.fileno())) == identity(info), 'wire6 held original changed during read')
    after = path.lstat()
    require(len(body) == info.st_size and identity(info) == identity(after),
            'wire6 original changed during its complete read')
    for parent, expected in parents:
        actual = parent.lstat()
        require((actual.st_dev, actual.st_ino, actual.st_mode) == expected,
                'wire6 original ancestor changed during read')
    return body


def pin(path, maximum=16 * 1024 * 1024):
    path = Path(path).absolute()
    body = read(path, maximum)
    return {'path': str(path), 'bytes': len(body), 'sha256': sha256(body).hexdigest()}


def json_read(path):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate wire6 original JSON field')
            result[key] = value
        return result
    return json.loads(read(path), object_pairs_hook=unique)


def create(path, value):
    body = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def runtime_identity():
    require(platform.python_implementation() == 'CPython'
            and sys.version_info[:3] == (3, 14, 4),
            'current-cold wire6 requires the explicitly supported CPython 3.14.4')
    return {'implementation': 'CPython', 'version': list(sys.version_info[:3]),
            'executable': pin(Path(sys.executable).resolve(strict=True), 128 * 1024 * 1024)}


def cold_context(cold):
    from tools.build_hia_json_preflight import current_sources
    context = originals.cold_inputs(cold)
    value = json_read(cold)
    require(type(value.get('qualification_wall_limit_seconds')) is int
            and value['qualification_wall_limit_seconds'] == 180
            and type(value.get('cleanup_wall_limit_seconds')) is int
            and value['cleanup_wall_limit_seconds'] == 3,
            'wire6 input cold qualification did not preserve its original 180/3 limits')
    require(current_sources() == context['source_manifest'], 'wire6 current complete source closure differs')
    for name in SOURCE_FILES:
        require(context['source_manifest'].get(name) == pin(ROOT / name)['sha256'],
                'wire6 dependency is outside this exact cold source closure: ' + name)
    return context


def owned_environment(environment, cold, fixture):
    from tools.qualify_hia_compiler_owner_ci import owned_environment as base_environment
    result = base_environment(environment, 'core', cold)
    # An unrelated ambient selector cannot replace either current-cold image.
    for name in tuple(result):
        if name.startswith('HEPTA_'):
            result.pop(name)
    result.update(HEPTA_HIA_JSON_WIRE_COLD_REPORT=str(Path(cold).resolve(strict=True)),
                  HEPTA_HIA_JSON_WIRE_KEY_SUMMARY_FIXTURE_EVIDENCE=str(Path(fixture).absolute()),
                  PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    return result


def compile_binding(folder, label, source_name, schema, context):
    folder = Path(folder).resolve(strict=True)
    paths = [folder / ('manifest.json'), folder / (label + '.image.bin'), folder / 'build.json']
    paths += [folder / (label + suffix) for suffix in COMPILE_SUFFIXES]
    before = [pin(path) for path in paths]
    manifest, build = json_read(paths[0]), json_read(paths[2])
    expected = {'schema': schema, 'source_sha256': context['source_manifest'][source_name],
                'image_path': paths[1].name, 'image_sha256': before[1]['sha256'],
                'compiler_sha256': context['compiler_sha256']}
    require(manifest == expected and 0 < before[1]['bytes'] <= 1048576,
            'wire6 actual image/manifest/source/B3 differs')
    receipt = json_read(paths[3])
    require(build.get('source_manifest') == context['source_manifest']
            and build.get('cold_report_sha256') == context['cold_sha256']
            and build.get('native_compile_receipt') == receipt,
            'wire6 fixture build is not from this current cold')
    if label == 'json-wire':
        from hepta.hia_json_wire_native import ORDINARY_PROFILE
        require(build.get('schema') == 'hepta.hia.json-wire-build.v1'
                and build.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
                and build.get('manifest') == manifest and build.get('production_activated') is False
                and build.get('ordinary_entry_profile') == ORDINARY_PROFILE
                and build.get('foreign_object_transport_is_python') is True
                and build.get('whole_stack_native') is False,
                'wire6 wire fixture scope or profile differs')
    else:
        require(build.get('status') == 'NATIVE_AGENT_BINARY64_FORMAT_BUILT'
                and build.get('native_shortest_roundtrip_binary64_printing') is True
                and build.get('native_float_printing') is True
                and build.get('foreign_float_boxing_is_hosted') is True
                and build.get('native_Agent_persistence') is False
                and build.get('default_changed') is False
                and build.get('whole_native_delivery_qualified') is False,
                'wire6 original binary64 fixture scope differs')
    originals.compile_receipt(receipt, manifest, paths[1], context)
    added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
             'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
    require(json_read(paths[4]) == {key: value for key, value in receipt.items() if key not in added},
            'wire6 compiler stdout differs from its complete receipt')
    require(receipt.get('case') == label and receipt.get('format') == 'flat-x86-64'
            and type(receipt.get('abi_status')) is int and receipt['abi_status'] == 0
            and type(receipt.get('core_u32')) is int
            and receipt['core_u32'] == receipt.get('produced_bytes') == before[1]['bytes']
            and receipt.get('produced_image') == str(paths[1])
            and receipt.get('runner_sha256') == context['source_manifest']['tools/hia_selfhost_child.py']
            and type(receipt.get('wall_elapsed_ns')) is int and receipt['wall_elapsed_ns'] >= 0,
            'wire6 actual compiler stage/child identity differs')
    request = json_read(paths[6])
    require(request == {'format': 'flat-x86-64', 'image': context['identities'][2]['path'],
                'image_sha256': context['compiler_sha256'], 'source': str(paths[7]),
                'source_sha256': manifest['source_sha256'], 'capacity': 1048576,
                'workspace_size': 1048576, 'workspace_fill': 0, 'output': str(paths[8])}
            and all(type(request[key]) is int for key in ('capacity', 'workspace_size', 'workspace_fill')),
            'wire6 full original compile request differs')
    source, output, image = read(paths[7]), read(paths[8]), read(paths[1])
    require(source == read(ROOT / source_name) and len(source) == receipt.get('input_bytes')
            and len(output) == 1048576 and sha256(output).hexdigest() == receipt.get('output_sha256')
            and output[:len(image)] == image, 'wire6 full compile input/output or image prefix differs')
    require(before == [pin(path) for path in paths], 'wire6 build originals changed during readback')
    return {'label': label, 'manifest': manifest, 'files': before[:3], 'compile_originals': before[3:]}


def fixture_binding(fixture, context):
    fixture = Path(fixture)
    return {
        'wire': compile_binding(fixture / 'build', 'json-wire', 'examples/hia_bootstrap/json_wire.hiaasm',
                               'hepta.hia.json-wire-native.v1', context),
        'format': compile_binding(fixture / 'format', 'agent-binary64-format',
                                 'examples/hia_bootstrap/agent_binary64_format.hiaasm',
                                 'hepta.hia.agent-binary64-format-native.v1', context)}


def flatten(suite):
    if isinstance(suite, unittest.TestSuite):
        for item in suite:
            yield from flatten(item)
    else:
        yield suite


def validate_child(value, context, runtime, binding):
    require(type(value) is dict and value.get('schema') == SCHEMA and value.get('status') == 'PASS'
            and value.get('scope') == SCOPE and value.get('error') is None
            and value.get('preservation_error') is None and value.get('recording_errors') == []
            and value.get('recording_failed') is False,
            'wire6 child did not pass with complete original diagnostics')
    for key in ('expected_ids', 'loaded_ids', 'executed_ids'):
        require(value.get(key) == list(IDS), 'wire6 complete six-method order differs: ' + key)
    require(type(value.get('tests_run')) is int and value['tests_run'] == 6
            and value.get('unittest_successful') is True and value.get('loader_errors') == []
            and all(value.get(key) == [] for key in ANOMALIES), 'wire6 original result has anomalies')
    require(value.get('cold_before') == context == value.get('cold_after')
            and value.get('runtime_before') == runtime == value.get('runtime_after')
            and value.get('fixture_before') == binding == value.get('fixture_after')
            and type(value.get('fixture_setup_calls')) is int and value['fixture_setup_calls'] == 1
            and value.get('fixture_scope') == 'MATCHING_SOURCE_COLD_BUILD'
            and value.get('foreign_object_transport_still_hosted') is True
            and value.get('original_wire89_pass_claimed') is False
            and value.get('whole_native_delivery_qualified') is False,
            'wire6 fixture/runtime/source identity or scope differs')
    rows = value.get('actual_wire_step_returns')
    require(type(rows) is list and rows, 'wire6 has no actual normal step returns')
    seen, tests, protocols, statuses = set(), set(), set(), set()
    accepted_magic = tuple(int.from_bytes(word, 'little') for word in (b'HIAWIR02', b'HIAWIR03', b'HIAWIR04', b'HIAWIR05'))
    for row in rows:
        require(type(row) is dict and set(row) == {'test', 'image_sha256', 'session_protocol_magic', 'status', 'count'}
                and row['test'] in IDS and row['image_sha256'] == binding['wire']['manifest']['image_sha256']
                and type(row['session_protocol_magic']) is int and row['session_protocol_magic'] in accepted_magic
                and type(row['status']) is int and 0 <= row['status'] < (1 << 32)
                and type(row['count']) is int and row['count'] > 0,
                'wire6 normal step row lacks its exact method/image/protocol binding')
        key = (row['test'], row['image_sha256'], row['session_protocol_magic'], row['status'])
        require(key not in seen, 'duplicate wire6 normal step row')
        seen.add(key); tests.add(row['test']); protocols.add(row['session_protocol_magic']); statuses.add(row['status'])
    require(tests == set(IDS) and protocols == set(accepted_magic) and {1, 2, 199} <= statuses,
            'wire6 complete method/legacy/current/rejection native observations differ')
    return value


def child(cold, directory):
    from tests import test_hia_json_wire_key_summary as cases
    from hepta import hia_json_wire_native as bridge
    context, runtime = cold_context(cold), runtime_identity()
    directory = Path(directory).absolute()
    require(not directory.exists(), 'wire6 child output already exists')
    directory.mkdir(mode=0o700)
    fixture = directory / 'fixture'
    environment = owned_environment(os.environ, cold, fixture)
    report = {'schema': SCHEMA, 'scope': SCOPE, 'status': 'HOLD', 'expected_ids': list(IDS),
        'loaded_ids': [], 'executed_ids': [], 'loader_errors': [], 'fixture_setup_calls': 0,
        'fixture_scope': None, 'fixture_before': None, 'fixture_after': None,
        'cold_before': context, 'cold_after': None, 'runtime_before': runtime, 'runtime_after': None,
        'recording_errors': [], 'recording_failed': False, 'foreign_object_transport_still_hosted': True,
        'original_wire89_pass_claimed': False, 'whole_native_delivery_qualified': False,
        'step_meaning': 'WireSession.step returned normally from the admitted wire image; not whole-method PASS.',
        'protocol_meaning': 'Session initial protocol; deliberate malformed ACK bytes are tested separately.'}
    current, returned, recording_failed = ['outside-test'], Counter(), [False]
    started = time.monotonic()
    actual_setup = cases.WireKeySummaryNativeTests.setUpClass
    actual_step = bridge.WireSession.step

    def setup(cls):
        report['fixture_setup_calls'] += 1
        actual_setup()
        require(type(cls.image) is bridge.NativeJsonWire and cls.temp is None,
                'wire6 fixture is not the retained current-cold native image')
        report['fixture_scope'] = cls.scope
        report['fixture_before'] = fixture_binding(fixture, context)
        require(cls.image.image_sha256 == report['fixture_before']['wire']['manifest']['image_sha256']
                and cls.format_image.image_sha256 == report['fixture_before']['format']['manifest']['image_sha256'],
                'wire6 live fixture images differ from the compiled originals')

    def step(session, packet=None):
        status = actual_step(session, packet)
        try:
            require(session.image is cases.WireKeySummaryNativeTests.image and current[0] in IDS,
                    'wire6 step escaped its actual native fixture or active method')
            returned[(current[0], session.image.image_sha256, session._protocol_magic, status)] += 1
        except BaseException:
            # Recording cannot replace the original normal return. Qualification
            # independently refuses even one preserved recording failure.
            recording_failed[0] = True
            try:
                report['recording_errors'].append(traceback.format_exc())
            except BaseException:
                pass
        return status

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            current[0] = test.id()
            report['executed_ids'].append(test.id())
            super().startTest(test)
        def stopTest(self, test):
            try:
                return super().stopTest(test)
            finally:
                current[0] = 'outside-test'

    try:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(CLASS)
        report['loaded_ids'] = [test.id() for test in flatten(suite)]
        report['loader_errors'] = list(loader.errors)
        require(report['loaded_ids'] == list(IDS) and not loader.errors, 'wire6 exact test discovery differs')
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            stack.enter_context(patch.object(cases.WireKeySummaryNativeTests, 'setUpClass', classmethod(setup)))
            stack.enter_context(patch.object(bridge.WireSession, 'step', step))
            stream = stack.enter_context((directory / 'unittest.log').open('x'))
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, unittest_successful=result.wasSuccessful())
        for key, attr in zip(ANOMALIES, ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')):
            report[key] = [dict(test=item[0].id(), detail=item[1]) if isinstance(item, tuple)
                           else dict(test=item.id()) for item in getattr(result, attr)]
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        report['recording_failed'] = recording_failed[0]
        report['actual_wire_step_returns'] = [dict(test=key[0], image_sha256=key[1],
            session_protocol_magic=key[2], status=key[3], count=count) for key, count in sorted(returned.items())]
        try:
            report['cold_after'] = cold_context(cold)
            report['runtime_after'] = runtime_identity()
            report['fixture_after'] = fixture_binding(fixture, context)
            validate_child(report, context, runtime, report['fixture_after'])
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        create(directory / 'report.json', report)
    return 0 if report['status'] == 'PASS' else 1


def closed_owner(returned, owner_dir, command, environment):
    """Bind raw owner evidence before opening any qualification child output."""
    from tools import hia_selfhost_process_owner as owner
    receipt_path = owner_dir / 'process-owner.json'
    request_path = owner_dir / 'process-owner.json.request.json'
    raw, request_raw = read(receipt_path, 4 * 1024 * 1024), read(request_path, 262144)
    receipt, request = json_read(receipt_path), json_read(request_path)
    implementation = pin(ROOT / 'tools/hia_selfhost_process_owner.py')['sha256']
    require(type(returned) is dict and type(returned.get('supervisor_returncode')) is int
            and {key: value for key, value in returned.items() if key not in ('receipt_sha256', 'supervisor_returncode')} == receipt
            and returned.get('receipt_sha256') == sha256(raw).hexdigest(),
            'wire6 wrapper does not bind the complete original owner receipt')
    require(request.get('schema') == owner.SCHEMA and receipt.get('schema') == owner.SCHEMA
            and request.get('command') == command and request.get('env') == environment
            and request.get('cwd') == str(ROOT)
            and request.get('stdout_path') == str(owner_dir / 'child.stdout.log')
            and request.get('stderr_path') == str(owner_dir / 'child.stderr.log')
            and request.get('receipt_path') == str(receipt_path)
            and request.get('implementation_sha256') == implementation == receipt.get('implementation_sha256')
            and receipt.get('request_sha256') == sha256(request_raw).hexdigest()
            and request.get('parent_pid') == receipt.get('parent_pid')
            and type(request.get('started_ns')) is int and type(request.get('deadline_ns')) is int
            and request['deadline_ns'] - request['started_ns'] == 180 * 1000000000,
            'wire6 owner request/command/current implementation binding differs')
    for value in (request, receipt):
        require(type(value.get('qualification_seconds')) is int and value['qualification_seconds'] == 180
                and type(value.get('cleanup_seconds')) is int and value['cleanup_seconds'] == 3,
                'wire6 original owner 180/3 budget differs')
    cleanup = receipt.get('cleanup', {})
    require(receipt.get('subreaper_enabled') is True and receipt.get('event_overflow') is False
            and receipt.get('qualification_started') is True
            and cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'wire6 owner closure is unconfirmed')
    observed = {(row['pid'], row['start_ticks']) for row in receipt['direct_and_adopted_children']}
    events = receipt.get('events', [])
    reaped = [(row.get('pid'), row.get('start_ticks')) for row in events if row.get('kind') == 'owned_child_reaped']
    require(len(observed) == len(receipt['direct_and_adopted_children']) and set(reaped) == observed
            and len(reaped) == len(set(reaped)) and any(pid == receipt['qualification_pid'] for pid, _ in observed),
            'wire6 owner observed/reaped identities do not close one-to-one')
    natural = (returned['supervisor_returncode'] == 0 and type(receipt.get('returncode')) is int
        and receipt['returncode'] == 0 and receipt.get('status') == 'OWNED_PROCESS_COMPLETED'
        and receipt.get('exit_observed_before_deadline') is True and receipt.get('timed_out') is False
        and receipt.get('interrupted_signals') == [] and receipt.get('owner_error') is None
        and all(row.get('kind') != 'owned_child_sigkill' for row in events)
        and all(type(row.get('returncode')) is int and row['returncode'] == 0
                for row in events if row.get('kind') == 'owned_child_reaped'))
    return {'closed': True, 'natural': natural, 'request': pin(request_path),
            'receipt': pin(receipt_path), 'supervisor_returncode': returned['supervisor_returncode']}


def inventory(directory):
    """Only the parent calls this after bound ECHILD, including closed failures."""
    result = []
    for path in sorted(Path(directory).rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode), 'wire6 retained output is not an ordinary file')
        result.append(pin(path))
    return result


def owned(cold, directory):
    from tools import hia_selfhost_process_owner as owner
    context, runtime = cold_context(cold), runtime_identity()
    directory = Path(directory).absolute()
    require(not directory.exists(), 'preserve previous wire6 originals; use a new evidence directory')
    directory.mkdir(mode=0o700, parents=True)
    owner_dir = directory / 'owner'; owner_dir.mkdir(mode=0o700)
    child_dir = directory / 'child'
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '--child',
               '--cold-report', str(Path(cold).resolve(strict=True)), '--evidence-dir', str(child_dir)]
    environment = owned_environment(os.environ, cold, child_dir / 'fixture')
    final = {'schema': SCHEMA, 'scope': SCOPE, 'status': 'HOLD', 'closed': False,
             'command': command, 'environment': environment, 'cwd': str(ROOT),
             'expected_ids': list(IDS), 'qualification_seconds': 180, 'cleanup_seconds': 3,
             'cold_before': context, 'runtime_before': runtime,
             'original_wire89_unchanged': True, 'original_cache7_unchanged': True,
             'original_Core116_UNPACK18_and_32_gates_unchanged': True,
             'whole_native_delivery_qualified': False}
    create(directory / 'INTENT.json', final)
    returned = None
    try:
        returned = owner.run_owned(command, cwd=ROOT, env=environment,
            stdout_path=owner_dir / 'child.stdout.log', stderr_path=owner_dir / 'child.stderr.log',
            receipt_path=owner_dir / 'process-owner.json', qualification_seconds=180, cleanup_seconds=3)
        create(directory / 'RETURNED-OWNER.json', returned)
        final['owner'] = closed_owner(returned, owner_dir, command, environment)
        final['closed'] = True
        require(final['owner']['natural'], 'wire6 owner did not finish naturally inside its original budget')
        binding = fixture_binding(child_dir / 'fixture', context)
        report = json_read(child_dir / 'report.json')
        validate_child(report, context, runtime, binding)
        final.update(child_report=pin(child_dir / 'report.json'), fixture=binding,
                     actual_wire_step_returns=report['actual_wire_step_returns'])
        final['status'] = 'MATCHING_COLD_WIRE_KEY_SUMMARY_NATIVE6_PASS'
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    finally:
        if final['closed']:
            try:
                final['retained_originals'] = inventory(directory)
                final['cold_after'] = cold_context(cold)
                final['runtime_after'] = runtime_identity()
                require(final['cold_after'] == context and final['runtime_after'] == runtime,
                        'wire6 current cold/source/runtime changed after closure')
            except BaseException:
                final['status'] = 'HOLD'
                final['preservation_error'] = traceback.format_exc()
        else:
            final['child_originals_read'] = False
            final['unconfirmed_owner_originals_left_in_place'] = True
        create(directory / 'FINAL.json', final)
    print(json.dumps({key: final.get(key) for key in ('schema', 'scope', 'status', 'closed', 'error')}, sort_keys=True))
    return 0 if final['status'] == 'MATCHING_COLD_WIRE_KEY_SUMMARY_NATIVE6_PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--child', action='store_true')
    args = parser.parse_args()
    return child(args.cold_report, args.evidence_dir) if args.child else owned(args.cold_report, args.evidence_dir)


if __name__ == '__main__':
    raise SystemExit(main())
