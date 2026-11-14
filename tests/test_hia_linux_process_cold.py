"""Permanent current-cold, retained-observation and installed process controls.

The source tests never construct positive cold authority. The five native
classes require the actual current-source fixture produced by the qualifier.
All historical development observations remain separate inputs and evidence.
"""
from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_linux_process import PROFILE, PROFILE_SOURCE_FILES, profile_resource_path
from tools import hia_linux_process_cold as custody
from tools import build_hia_linux_process_cold as builder
from tools import qualify_hia_linux_process as qualifier
from tests import hia_linux_process_cold_cases as cases

ROOT = Path(__file__).resolve().parents[1]


def _function(raw, name):
    found = [node for node in ast.parse(raw).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(found) != 1:
        raise AssertionError('one complete original function required: ' + name)
    return found[0]


def _fields(value):
    if isinstance(value, ast.AST):
        return (type(value).__name__, tuple((key, _fields(item))
                for key, item in ast.iter_fields(value)))
    if isinstance(value, list):
        return tuple(_fields(item) for item in value)
    return (type(value).__name__, value)


class LinuxProcessColdSourceTests(unittest.TestCase):
    def test_complete_process_inputs_extend_the_original_fresh_cold_domain(self):
        from tools.hia_selfhost_contract import SOURCE_FILES
        from tools.hia_release import BOOTSTRAP_FILES
        from tools.hia_linux_stdio_cold import REQUIRED_SOURCES as OLD
        self.assertEqual(custody.REQUIRED_SOURCES[:len(OLD)], OLD)
        self.assertEqual(len(custody.REQUIRED_SOURCES), len(set(custody.REQUIRED_SOURCES)))
        self.assertLessEqual(set(custody.REQUIRED_SOURCES), set(SOURCE_FILES))
        self.assertLessEqual(set(custody.REQUIRED_SOURCES), set(BOOTSTRAP_FILES))
        source = {name: custody.digest((ROOT / name).read_bytes()) for name in custody.REQUIRED_SOURCES}
        custody.admit_required_sources(source)
        for name in custody.PROCESS_SOURCES:
            missing = dict(source); del missing[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                custody.admit_required_sources(missing)
            changed = dict(source); changed[name] = '0' * 64
            with self.subTest(changed=name), self.assertRaises(ValueError):
                custody.admit_required_sources(changed)

    def test_retained_program_bytes_and_original_71_order_are_exact(self):
        retained = custody.retained_inputs()
        self.assertFalse(retained['native_or_cold_qualification'])
        self.assertEqual(retained['original_raw_recipe'], 'a66c166016fb9a7012bd45d257080c92ec9f5f27')
        self.assertEqual(len(cases.program_names()), 18)
        for name in cases.program_names():
            raw = cases.case_source(name)
            checked = assemble_program(raw, profile=PROFILE)
            with self.subTest(name=name):
                self.assertEqual(render_assembly(checked, profile=PROFILE).encode(), raw)
                self.assertEqual(custody.digest(raw), retained['programs'][name]['sha256'])
        suite, ids = qualifier.load_suite('source')
        self.assertEqual(ids, retained['original_71_ids'])
        self.assertEqual(suite.countTestCases(), 71)
        self.assertEqual(len(set(ids)), 71)
        self.assertEqual([len(retained['groups'][name]) for name in
                          ('direct', 'packer', 'startup', 'entry', 'legacy')], [33, 13, 4, 4, 4])

    def test_all_fixed_native_method_ids_are_complete_and_ordered(self):
        for group, count in (('direct', 33), ('packer', 13), ('startup', 4),
                             ('entry', 4), ('legacy', 4), ('portable', 1)):
            suite, ids = qualifier.load_suite(group)
            with self.subTest(group=group):
                self.assertEqual(ids, list(qualifier.EXPECTED_IDS[group]))
                self.assertEqual(len(ids), suite.countTestCases())
                self.assertEqual(len(set(ids)), count)
        self.assertEqual(sum(qualifier.GROUP_COUNTS.values()), 130)

    def test_original_definitions_and_fixed_observer_bodies_are_preserved(self):
        original = custody.retained_inputs()['scripts']
        old = original['run_process_controls.py']['text']
        new = (ROOT / 'tests/hia_linux_process_cold_cases.py').read_text()
        for name in ('encoded', 'definitions'):
            self.assertEqual(_fields(_function(old, name)), _fields(_function(new, name)))
        self.assertEqual((ROOT / 'tests/hia_linux_process_buffer_child.py').read_text(),
                         original['retained_buffer_child.py']['text'])
        self.assertEqual((ROOT / 'tests/hia_linux_process_startup_fault_observer.py').read_text(),
                         original['process_startup_fault_observer.py']['text'])
        self.assertEqual((ROOT / 'tests/hia_linux_process_buffer_observer.py').read_text(),
            original['retained_buffer_observer.py']['text'].replace(
                "'retained_buffer_child.py'", "'hia_linux_process_buffer_child.py'"))

    def test_two_historical_failures_are_not_relabelled_as_cold_success(self):
        retained = custody.retained_inputs()
        self.assertEqual(set(retained['historical_failures']), {'process_controls_r1', 'legacy_domain_r1'})
        self.assertIn('remains FAIL', retained['historical_failures']['process_controls_r1'])
        self.assertIn('remains FAIL', retained['historical_failures']['legacy_domain_r1'])
        definitions = cases.packer_definitions(b'\xc3')
        self.assertEqual(definitions[0][0], 'same-A5-full-observation')
        self.assertEqual(definitions[0][3], 8192)
        self.assertEqual(definitions[-2][1][32:], bytes(custody.CAPACITY - 1024))
        self.assertEqual(definitions[-2][3], custody.CAPACITY)
        self.assertEqual(retained['groups']['legacy'][-1], 'explicit-empty-exports')

    def test_missing_failed_or_development_cold_refuses_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path = folder / 'cold.json'
            for status in ('DEVELOPMENT_BUILD', 'PASS', 'FAIL', 'QUALIFICATION_TIMEOUT'):
                path.write_text(json.dumps({'schema': 'hepta.hia.selfhost-cold-replay.v1',
                                            'status': status, 'returncode': 0}))
                with self.subTest(status=status), mock.patch.object(builder, 'compile_bound',
                        side_effect=AssertionError('rejected input must not compile')):
                    with self.assertRaises(ValueError):
                        builder.build_toolchain(folder / 'not-created', path)
                self.assertFalse((folder / 'not-created').exists())
            with self.assertRaises(FileNotFoundError):
                builder.build_toolchain(folder / 'not-created', folder / 'missing.json')
            self.assertFalse((folder / 'not-created').exists())

    def test_original_owner_deadline_exit_and_cleanup_are_strictly_typed(self):
        # Structural controls only; no source, compiler or cold authority.
        owner = {'schema': 'hepta.hia.selfhost-process-owner.v1',
            'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0,
            'qualification_seconds': 180, 'cleanup_seconds': 3,
            'timed_out': False, 'exit_observed_before_deadline': True,
            'cleanup': {'complete': True}}
        self.assertTrue(qualifier._owner_pass(owner))
        for key, value in [('returncode', False), ('qualification_seconds', 180.0),
                ('qualification_seconds', 181), ('cleanup_seconds', 3.0),
                ('cleanup_seconds', 4), ('timed_out', 0),
                ('exit_observed_before_deadline', 1), ('cleanup', {'complete': 1})]:
            changed = copy.deepcopy(owner); changed[key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(qualifier._owner_pass(changed))
        outer = {'schema': 'hepta.hia.selfhost-cold-replay.v1',
            'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
            'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
            'nested_report': '/structural-only/not-authority', 'nested_report_sha256': '0' * 64,
            'process_owner': owner}
        custody.outer_shape(outer)
        for key, value in [('returncode', False), ('qualification_wall_limit_seconds', 180.0),
                           ('qualification_wall_limit_seconds', 181), ('cleanup_wall_limit_seconds', 4)]:
            changed = copy.deepcopy(outer); changed[key] = value
            with self.subTest(outer_key=key), self.assertRaises(ValueError):
                custody.outer_shape(changed)

    def test_input_bindings_are_fresh_and_reject_symlink_mode_or_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'captured'; path.write_bytes(b'old')
            record = custody.pin(path); custody.check_bindings([record])
            path.write_bytes(b'new')
            with self.assertRaises(ValueError): custody.check_bindings([record])
            path.write_bytes(b'old'); path.chmod(record['mode'] ^ 0o100)
            with self.assertRaises(ValueError): custody.check_bindings([record])
            path.chmod(record['mode'])
            link = root / 'link'; link.symlink_to(path)
            with self.assertRaises(ValueError): custody.pin(link)
            with self.assertRaises(ValueError): custody.check_bindings([record, record])

    def test_duplicate_or_nonfinite_serialization_cannot_supply_custody(self):
        for raw in (b'{"status":"FAIL","status":"PASS"}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): custody.decode(raw)

    def test_development_fixtures_and_other_profiles_cannot_reenter_cold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'development.json'
            for function, schema in ((builder.admit_toolchain, builder.TOOLCHAIN_SCHEMA),
                    (builder.admit_program, builder.PROGRAM_SCHEMA),
                    (qualifier.admit_fixture, qualifier.FIXTURE_SCHEMA)):
                path.write_text(json.dumps({'schema': schema, 'status': 'DEVELOPMENT_BUILD',
                                           'matching_cold': False, 'profile': PROFILE}))
                with self.subTest(function=function.__name__), self.assertRaises(ValueError): function(path)
        for profile in (None, False, 'hepta.hia.linux-stdio.v1', PROFILE + ' '):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                custody.guard_authority({'schema': custody.AUTHORITY_SCHEMA, 'physical_profile': profile})
        for environment in ({}, {qualifier.COLD_FIXTURE_ENV: '', qualifier.EVIDENCE_ENV: 'x'}):
            with self.assertRaises(ValueError): qualifier.load_fixture(environment)

    def test_serialized_authority_is_rechecked_against_original_cold_each_time(self):
        value = {'schema': custody.AUTHORITY_SCHEMA, 'physical_profile': PROFILE,
                 'cold_report': '/no-cold', 'compiler': '/no-compiler'}
        refusal = ValueError('original cold admission refused')
        with mock.patch.object(custody, 'admit_cold', side_effect=refusal) as admitted:
            with self.assertRaises(ValueError) as caught: custody.re_admit_authority(value)
            self.assertIs(caught.exception, refusal)
            admitted.assert_called_once_with('/no-cold', compiler='/no-compiler')

    def test_ambient_override_refuses_before_admission_or_evidence_creation(self):
        for key in (qualifier.COLD_FIXTURE_ENV, qualifier.EVIDENCE_ENV, qualifier.SOURCE_EVIDENCE_ENV):
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: ''}), \
                    mock.patch.object(qualifier, 'admit_cold', side_effect=AssertionError('must not read')):
                with self.assertRaises(ValueError): qualifier.qualify('/unread', '/uncreated')

    def test_complete_group_reports_refuse_missing_ids_and_every_anomaly(self):
        for group, count in qualifier.GROUP_COUNTS.items():
            row = {'schema': 'hepta.hia.linux-process-cold-observations.v1',
                'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'status': 'PASS', 'group': group,
                'request_sha256': 'shape-only', 'loaded_ids': list(qualifier.EXPECTED_IDS[group]),
                'started_ids': list(qualifier.EXPECTED_IDS[group]),
                'stopped_ids': list(qualifier.EXPECTED_IDS[group]), 'tests_run': count,
                'source_and_inputs_unchanged': True, 'anomalies': {key: [] for key in qualifier.ANOMALIES}}
            qualifier.admit_child_report(row, 'shape-only', group)
            for name in qualifier.ANOMALIES:
                changed = copy.deepcopy(row); changed['anomalies'][name].append('actual anomaly')
                with self.subTest(group=group, anomaly=name), self.assertRaises(ValueError):
                    qualifier.admit_child_report(changed, 'shape-only', group)
            for field in ('loaded_ids', 'started_ids', 'stopped_ids'):
                changed = copy.deepcopy(row); changed[field].pop()
                with self.subTest(group=group, field=field), self.assertRaises(ValueError):
                    qualifier.admit_child_report(changed, 'shape-only', group)
            for key, value in [('tests_run', float(count)), ('source_and_inputs_unchanged', 1),
                               ('scope', 'MATCHING_CURRENT_SOURCE_COLD'), ('group', 'unknown')]:
                changed = copy.deepcopy(row); changed[key] = value
                with self.subTest(group=group, key=key), self.assertRaises(ValueError):
                    qualifier.admit_child_report(changed, 'shape-only', group)

    def test_compile_and_probe_requests_refuse_extensions_and_boolean_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); provider = folder / 'provider'; provider.write_bytes(b'\xc3')
            payload = b'never-executed-shape-input'; label = 'shape'
            request = {'format': 'flat-x86-64', 'capacity': custody.CAPACITY,
                'image': str(provider), 'image_sha256': custody.digest(provider.read_bytes()),
                'source': str(folder / (label + '.input.bin')), 'source_sha256': custody.digest(payload),
                'output': str(folder / (label + '.output.bin')), 'workspace_fill': 0,
                'workspace_size': custody.CAPACITY}
            (folder / (label + '.input.bin')).write_bytes(payload)
            (folder / (label + '.output.bin')).write_bytes(b'')
            (folder / (label + '.receipt.json')).write_text('{}')
            (folder / (label + '.stdout.log')).write_text('{}')
            (folder / (label + '.stderr.log')).write_bytes(b'')
            for key, value in [('workspace_fill', False), ('workspace_fill', 1),
                    ('capacity', float(custody.CAPACITY)), ('workspace_size', True),
                    ('observe_trap_writes', True), ('output_initial_hex', '')]:
                changed = dict(request); changed[key] = value
                (folder / (label + '.request.json')).write_text(json.dumps(changed))
                for function in (custody.observation, custody.probe_observation):
                    with self.subTest(function=function.__name__, key=key), self.assertRaisesRegex(ValueError, 'request differs'):
                        function(folder, label, provider, payload)
            (folder / (label + '.request.json')).write_text(json.dumps(request))
            for function in (custody.observation, custody.probe_observation):
                with self.subTest(function=function.__name__), self.assertRaisesRegex(ValueError, 'actual child stdout differs'):
                    function(folder, label, provider, payload)

    def test_compile_owner_and_vm_limits_have_no_override_parameter(self):
        self.assertEqual((qualifier.GROUP_SECONDS, qualifier.CLEANUP_SECONDS,
                          qualifier.COMPILE_SECONDS, custody.CAPACITY), (180, 3, 20, 1048576))
        for name in ('build_toolchain', 'build_program'):
            node = _function((ROOT / 'tools/build_hia_linux_process_cold.py').read_bytes(), name)
            self.assertFalse({a.arg for a in (*node.args.args, *node.args.kwonlyargs)} &
                             {'timeout', 'capacity', 'workspace_size', 'development'})
        self.assertEqual(builder.LABELS, ('process-P1', 'process-P2', 'process-P3',
                                        'ordinary-B3-regression', 'entry-packer'))
        self.assertEqual(builder.TOOLCHAIN_STATUS, 'MATCHING_SOURCE_COLD_LINUX_PROCESS_COMPILER_BUILT')
        self.assertEqual(builder.PROGRAM_STATUS, 'MATCHING_SOURCE_COLD_LINUX_PROCESS_PROGRAM_BUILT')

    def test_packer_readback_binds_exact_request_provider_shared_bytes_and_limits(self):
        # A mechanical readback shape only. No child or image is executed and
        # this observation never enters fixture/cold/qualification admission.
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); image = folder/'not-an-authority'; image.write_bytes(b'\xc3')
            initial = (b'input',b'\xa5'*8,bytes(8)); guard = b'\xd3'*64
            buffers = []
            for label, raw in zip(('source','output','workspace'),initial):
                path = folder/(label+'.shared'); value = guard+raw+guard; path.write_bytes(value)
                buffers.append({'path':str(path),'bytes':len(value),'sha256':custody.digest(value),'extent':len(raw)})
            request = {'schema':'hia.linux-stdio.native-request.v1','image':str(image),
                'image_sha256':custody.digest(image.read_bytes()),'buffers':buffers,'mode':'ordinary',
                'report':str(folder/'CHILD-REPORT.json')}
            request_raw = custody.wire(request); (folder/'request.json').write_bytes(request_raw)
            for name in ('stdin.bin','stdout.bin','stderr.bin'): (folder/name).write_bytes(b'')
            child = {'schema':'hia.linux-stdio.native-observation.v1','status':'returned',
                'result_u64':0,'native_elapsed_ns':0,'image_sha256':request['image_sha256'],
                'request_sha256':custody.digest(request_raw),
                'limits':{'wall_seconds':20,'cpu_seconds':10,'source_output_workspace_bytes':1048576,
                    'address_bytes':268435456,'stack_bytes':8388608,'core_dumpable':False},
                'forbidden_modules_loaded':[],'matched_cold':False,'whole':False}
            observed = {'child':child,'returncode':0,'timed_out':False,'timeout_seconds':20,'cleanup_seconds':3,
                'stdin_consumed':0,'stdout_hex':'','stderr_hex':'','source_hex':initial[0].hex(),
                'output_hex':initial[1].hex(),'workspace_hex':initial[2].hex(),'canaries':[True]*3}
            def record(child_value=child, observed_value=observed):
                (folder/'CHILD-REPORT.json').write_bytes(custody.wire(child_value))
                (folder/'OBSERVATION.json').write_bytes(custody.wire(observed_value))
            record()
            self.assertEqual(qualifier._actual_packer(folder,image,*initial),observed)
            for key, value in [('unknown',1),('image_sha256','0'*64),('mode','changed')]:
                changed = copy.deepcopy(request); changed[key]=value
                (folder/'request.json').write_bytes(custody.wire(changed))
                with self.subTest(request=key), self.assertRaises(ValueError):
                    qualifier._actual_packer(folder,image,*initial)
            (folder/'request.json').write_bytes(request_raw)
            for key, value in [('result_u64',False),('image_sha256','0'*64),('matched_cold',True),
                               ('limits',{**child['limits'],'wall_seconds':20.0})]:
                changed = copy.deepcopy(child); changed[key]=value
                record(changed,{**observed,'child':changed})
                with self.subTest(child=key), self.assertRaises(ValueError):
                    qualifier._actual_packer(folder,image,*initial)
            record()
            for raw in (guard+b'\x00'+initial[1][1:]+guard, b'x'+(guard+initial[1]+guard)[1:]):
                (folder/'output.shared').write_bytes(raw)
                with self.subTest(buffer=raw[0]), self.assertRaises(ValueError):
                    qualifier._actual_packer(folder,image,*initial)
            (folder/'output.shared').write_bytes(guard+initial[1]+guard)
            self.assertEqual(qualifier._actual_packer(folder,image,*initial),observed)

    def test_public_resource_lookup_keeps_both_exact_entries_and_refuses_fallback(self):
        self.assertEqual(PROFILE_SOURCE_FILES, (custody.COMPILER_SOURCE, custody.PACKER_SOURCE))
        for name in PROFILE_SOURCE_FILES:
            self.assertEqual(profile_resource_path(name), ROOT / name)
            self.assertTrue(profile_resource_path(name).read_bytes())
        for name in (None, True, '', '../selfhost.hepta', '/tmp/other', custody.ORDINARY_SOURCE):
            with self.subTest(name=name), self.assertRaises(ValueError): profile_resource_path(name)


class LinuxProcessPortableSourceTests(unittest.TestCase):
    def test_actual_sdist_wheel_installed_process_profile_and_missing_resources(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES,
            PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES,
            BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES,
            CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES,
        )
        roles = (
            ('DISCOVERY_FILES', tuple('docs/' + name for name in DISCOVERY_FILES)),
            ('NATIVE_SOURCE_FILES', NATIVE_SOURCE_FILES), ('SOURCE_BUILD_FILES', SOURCE_BUILD_FILES),
            ('COMPILER_BUILD_FILES', COMPILER_BUILD_FILES), ('PUBLICATION_BUILD_FILES', PUBLICATION_BUILD_FILES),
            ('BACKEND_BUILD_FILES', BACKEND_BUILD_FILES), ('EMITTER_BUILD_FILES', EMITTER_BUILD_FILES),
            ('BYTE_WRAPPER_BUILD_FILES', BYTE_WRAPPER_BUILD_FILES), ('MACHINE_OBJECT_BUILD_FILES', MACHINE_OBJECT_BUILD_FILES),
            ('EXECUTION_OBSERVATION_BUILD_FILES', EXECUTION_OBSERVATION_BUILD_FILES),
            ('CONTINUATION_BUILD_FILES', CONTINUATION_BUILD_FILES), ('ENTRY_BUILD_FILES', ENTRY_BUILD_FILES),
        )
        resources = tuple(name for _, names in roles for name in names)
        self.assertEqual(resources, RESOURCES)
        self.assertEqual(len(resources), len(set(resources)))
        self.assertLessEqual(set(PROFILE_SOURCE_FILES), set(ENTRY_BUILD_FILES))
        self.assertTrue(set(PROFILE_SOURCE_FILES).isdisjoint(NATIVE_SOURCE_FILES))
        originals = {name: (ROOT / name).read_bytes() for name in resources}
        selected = os.environ.get(qualifier.SOURCE_EVIDENCE_ENV)
        temporary = None
        if selected:
            folder = Path(selected).absolute(); folder.mkdir(mode=0o700, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-linux-process-portable-')
            folder = Path(temporary.name)
        commands = []
        try:
            source = folder / 'source'; source.mkdir()
            shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            for name in (*resources, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
                target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                'PYTHONDONTWRITEBYTECODE': '1', 'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
            def run(label, arguments, *, cwd=source, success=True):
                command = [sys.executable, '-B', *map(str, arguments)]
                result = subprocess.run(command, cwd=cwd, env=environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                stdout = folder / (label + '.stdout'); stdout.write_bytes(result.stdout)
                stderr = folder / (label + '.stderr'); stderr.write_bytes(result.stderr)
                record = {'label': label, 'command': command, 'cwd': str(cwd), 'environment': environment,
                    'timeout_seconds': 60, 'returncode': result.returncode,
                    'stdout': custody.pin(stdout), 'stderr': custody.pin(stderr)}
                commands.append(record); custody.publish(folder / (label + '.COMMAND.json'), record)
                if success:
                    self.assertEqual(result.returncode, 0, (label, result.stderr[-4000:].decode(errors='replace')))
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b'FileNotFoundError', result.stderr)
                return result.stdout
            run('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
            archive, = (folder / 'sdist').glob('*.tar.gz')
            with tarfile.open(archive) as tar:
                prefix = tar.getmembers()[0].name.split('/')[0] + '/'
                for name in resources:
                    self.assertEqual(tar.extractfile(prefix + name).read(), originals[name], name)
            run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', folder / 'wheel', archive])
            wheel, = (folder / 'wheel').glob('*.whl')
            with zipfile.ZipFile(wheel) as zipped:
                self.assertEqual({name for name in zipped.namelist()
                    if name.startswith('hepta/_data/') and not name.endswith('/')},
                    {'hepta/_data/' + name for name in resources})
                for name in resources:
                    self.assertEqual(zipped.read('hepta/_data/' + name), originals[name], name)
            installed = folder / 'installed'
            run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel])
            for name in resources:
                self.assertEqual((installed / 'hepta/_data' / name).read_bytes(), originals[name], name)
            input_program = folder / 'explicit-process.hepta'; input_program.write_bytes(cases.case_source('inspect'))
            child = r'''import hashlib,json,pathlib,struct,sys
sys.path.insert(0,sys.argv[1])
from hepta.hia_linux_process import PROFILE,PROFILE_SOURCE_FILES,profile_resource_path,LinuxStartupSnapshot
from hepta.hia_linux_stdio import PROFILE as OLD
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program import verify_program,HIAProgramRejected
from hepta.hia_program_runtime import execute_program
root=pathlib.Path(sys.argv[1]);resources={}
for name in PROFILE_SOURCE_FILES:
 p=profile_resource_path(name)
 assert p==root/'hepta'/'_data'/name
 resources[name]=hashlib.sha256(p.read_bytes()).hexdigest()
raw=pathlib.Path(sys.argv[2]).read_bytes()
checked=assemble_program(raw,profile=PROFILE)
assert render_assembly(checked,profile=PROFILE).encode()==raw
argv=(b'process',b'',b'\xff\xfe\n',b'x=x');env=(b'A=1',b'A=2',b'',b'NO_EQUALS',b'\xff=\x80')
expected=struct.pack('<QQQ',3546416430321002824,len(argv),len(env))+b''.join(struct.pack('<Q',len(x))+x for x in argv+env)
seen=[];written={1:bytearray(),2:bytearray()}
def provider(request):
 assert request.fd in (1,2)
 assert len(request.write_bytes)==request.count
 seen.append((request.fd,request.count));written[request.fd].extend(request.write_bytes)
 return request.count,b''
observed=execute_program(checked,'f0',(b'',bytes(1048576),bytes(1048576)),profile=PROFILE,
 linux_process_startup=LinuxStartupSnapshot(argv,env),linux_process_provider=provider,max_steps=10000000)
assert observed['values']==[0] and observed['actual_kernel_execution'] is False
assert bytes(written[1])==expected and bytes(written[2])==b'\xff\0\n'
refused=0
for operation in (lambda:assemble_program(raw),lambda:assemble_program(raw,profile=OLD),
                  lambda:verify_program(checked),lambda:execute_program(checked,'f0',(b'',b'',b''))):
 try:operation()
 except HIAProgramRejected:refused+=1
 else:raise AssertionError('default or stdio entry admitted process profile')
print(json.dumps({'resources':resources,'profile':PROFILE,'actual_kernel_execution':False,
 'default_and_stdio_refusals':refused,'stdout_hex':written[1].hex(),'stderr_hex':written[2].hex(),
 'ordered_argv_hex':[x.hex() for x in argv],'ordered_environment_hex':[x.hex() for x in env],
 'provider_calls':seen,'program_sha256':checked.sha256},sort_keys=True))
'''
            child_path = folder / 'installed-observer.py'; child_path.write_text(child)
            observed = json.loads(run('installed', ['-I', child_path, installed, input_program], cwd=folder))
            self.assertEqual(observed['resources'], {name: custody.digest((ROOT / name).read_bytes())
                                                      for name in PROFILE_SOURCE_FILES})
            self.assertIs(observed['actual_kernel_execution'], False)
            self.assertEqual(observed['default_and_stdio_refusals'], 4)
            for index, name in enumerate(PROFILE_SOURCE_FILES):
                path = installed / 'hepta/_data' / name
                original = path.read_bytes(); path.unlink()
                try:
                    run('missing-' + str(index), ['-I', child_path, installed, input_program], cwd=ROOT, success=False)
                finally:
                    path.write_bytes(original)
            self.assertEqual(json.loads(run('restored', ['-I', child_path, installed, input_program], cwd=folder)), observed)
            resources_report = {'roles': {role: list(names) for role, names in roles},
                'resources': {name: {'bytes': len(raw), 'sha256': custody.digest(raw)} for name, raw in originals.items()},
                'sdist_wheel_installed_complete_bytes_equal': True}
            custody.publish(folder / 'RESOURCE-READBACK.json', resources_report)
            custody.publish(folder / 'COMMANDS.json', commands)
            bindings = [custody.pin(path) for path in (archive, wheel, child_path, input_program,
                        folder / 'RESOURCE-READBACK.json', folder / 'COMMANDS.json')]
            bindings += [custody.pin(installed / 'hepta/_data' / name) for name in resources]
            for command in commands:
                bindings.extend((command['stdout'], command['stderr'], custody.pin(folder / (command['label'] + '.COMMAND.json'))))
            custody.publish(folder / 'PORTABLE-RESULT.json', {
                'schema': 'hepta.hia.linux-process-portable.v1', 'status': 'PASS', 'profile': PROFILE,
                'all_resource_bytes_equal': True, 'installed_profile_reference_only': True,
                'actual_kernel_execution': False, 'whole_native': False, 'matching_cold': False,
                'resource_count': len(resources), 'resource_roles': resources_report['roles'],
                'observed': observed, 'archive': custody.pin(archive), 'wheel': custody.pin(wheel),
                'installed': str(installed), 'bindings': bindings})
        finally:
            if temporary is not None: temporary.cleanup()


class _MatchingColdCase(unittest.TestCase):
    group = None

    @classmethod
    def setUpClass(cls):
        cls.fixture_path, cls.fixture, cls.output = qualifier.load_fixture()
        cls.fixture_binding = custody.pin(cls.fixture_path)
        cls.output.mkdir(mode=0o700, parents=False, exist_ok=True)

    def _case(self, index):
        custody.guard_authority(self.fixture['authority'])
        self.assertEqual(custody.pin(self.fixture_path), self.fixture_binding)
        check = {'direct': cases.direct_case, 'packer': cases.packer_case,
                 'startup': cases.startup_case, 'entry': cases.entry_case,
                 'legacy': cases.domain_case}[self.group]
        try:
            row = check(self.fixture, self.output, index)
            self.assertEqual(row['name'], custody.retained_inputs()['groups'][self.group][index])
            self.assertEqual(row['status'], 'PASS', row)
            self.assertTrue(row['checks'])
            self.assertTrue(all(type(value) is bool and value for value in row['checks'].values()), row)
        finally:
            custody.guard_authority(self.fixture['authority'])
            custody.check_bindings([self.fixture['compiler_image'], self.fixture['packer_image'],
                                    self.fixture['cold_compiler']])
            self.assertEqual(custody.pin(self.fixture_path), self.fixture_binding)


# Exact explicit methods below are generated once from the frozen case names;
# Their complete file bytes and independent ordered IDs are admitted.


class LinuxProcessMatchingColdNativeTests(_MatchingColdCase):
    group = 'direct'

    def test_01_kernel_empty_vector_count(self): self._case(0)
    def test_02_empty_vectors_kernel_entry(self): self._case(1)
    def test_03_explicit_empty_arg(self): self._case(2)
    def test_04_ordered_raw_duplicates(self): self._case(3)
    def test_05_raw_no_utf8_and_newlines(self): self._case(4)
    def test_06_large_aggregate_over_1mib(self): self._case(5)
    def test_07_fd2_three_raw_bytes(self): self._case(6)
    def test_08_fd2_closed_full_negative_ebadf(self): self._case(7)
    def test_09_fd2_inherited_default_sigpipe(self): self._case(8)
    def test_10_fd2_inherited_ignore_full_epipe(self): self._case(9)
    def test_11_fd2_zero_open(self): self._case(10)
    def test_12_fd2_zero_closed_still_ebadf(self): self._case(11)
    def test_13_fd2_exact_1mib(self): self._case(12)
    def test_14_fd2_nonblocking_short_write(self): self._case(13)
    def test_15_invalid_argv_index(self): self._case(14)
    def test_16_invalid_env_index(self): self._case(15)
    def test_17_copy_invalid_source(self): self._case(16)
    def test_18_copy_invalid_destination(self): self._case(17)
    def test_19_copy_source_overflow(self): self._case(18)
    def test_20_copy_destination_overflow(self): self._case(19)
    def test_21_copy_zero_at_both_ends(self): self._case(20)
    def test_22_retained_empty_input(self): self._case(21)
    def test_23_retained_short_binary_input(self): self._case(22)
    def test_24_retained_zero_count_open(self): self._case(23)
    def test_25_retained_zero_count_closed_read(self): self._case(24)
    def test_26_retained_zero_count_closed_write(self): self._case(25)
    def test_27_retained_full_signed_read_ebadf(self): self._case(26)
    def test_28_retained_full_signed_write_ebadf(self): self._case(27)
    def test_29_retained_sigpipe_default(self): self._case(28)
    def test_30_retained_sigpipe_inherited_ignore_epipe(self): self._case(29)
    def test_31_retained_exact_1mib(self): self._case(30)
    def test_32_retained_over_1mib_rejected_before_write(self): self._case(31)
    def test_33_retained_bounds_before_read(self): self._case(32)


class LinuxProcessPackerMatchingColdNativeTests(_MatchingColdCase):
    group = 'packer'

    def test_01_same_a5_full_observation(self): self._case(0)
    def test_02_empty_frame(self): self._case(1)
    def test_03_wrong_magic(self): self._case(2)
    def test_04_wrong_version(self): self._case(3)
    def test_05_reserved_field(self): self._case(4)
    def test_06_zero_image(self): self._case(5)
    def test_07_truncated_frame(self): self._case(6)
    def test_08_trailing_byte(self): self._case(7)
    def test_09_zero_output(self): self._case(8)
    def test_10_short_output(self): self._case(9)
    def test_11_image_one_over_entry_limit(self): self._case(10)
    def test_12_exact_1mib_elf_structural_only(self): self._case(11)
    def test_13_minimum_image_structural_only(self): self._case(12)


class LinuxProcessStartupMatchingColdNativeTests(_MatchingColdCase):
    group = 'startup'

    def test_01_prctl(self): self._case(0)
    def test_02_mprotect_stack(self): self._case(1)
    def test_03_mprotect_guard(self): self._case(2)
    def test_04_mprotect_cap(self): self._case(3)


class LinuxProcessEntryMatchingColdNativeTests(_MatchingColdCase):
    group = 'entry'

    def test_01_empty_source_distinct_zero_1mib_buffers_both_ends(self): self._case(0)
    def test_02_kernel_131071_byte_string_plus_nul(self): self._case(1)
    def test_03_kernel_string_one_byte_over(self): self._case(2)
    def test_04_kernel_aggregate_over_8mib_stack_limit(self): self._case(3)


class LinuxProcessDomainMatchingColdNativeTests(_MatchingColdCase):
    group = 'legacy'

    def test_01_selfhost_elf(self): self._case(0)
    def test_02_selfhost_exec(self): self._case(1)
    def test_03_explicit_scalar_exports(self): self._case(2)
    def test_04_explicit_empty_exports(self): self._case(3)
