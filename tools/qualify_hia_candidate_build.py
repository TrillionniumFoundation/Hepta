"""Run the original candidate-build controls from actual matching cold inputs.

This hosted evidence driver does not grant runtime selection, release promotion,
or whole-native authority. It has no development compiler option. The original
development fixture remains a separate, explicitly selected test route.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

COLD_FIXTURE_ENV = 'HEPTA_HIA_CANDIDATE_BUILD_COLD_FIXTURE'
DEVELOPMENT_ENV = 'HEPTA_HIA_CANDIDATE_BUILD_DEVELOPMENT_EVIDENCE'
EVIDENCE_ENV = 'HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE'
FIXTURE_SCHEMA = 'hepta.hia.candidate-build-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_SOURCE_COLD_FIXTURE_BUILT'
GROUP_SECONDS = 180
CLEANUP_SECONDS = 3
COMPILE_SECONDS = 20
CAPACITY = 1048576
TEST_SOURCE = 'tests/test_hia_candidate_build.py'
MODULE = 'tests.test_hia_candidate_build'
SELECTORS = (MODULE + '.CandidateBuildSourceTests', MODULE + '.CandidateBuildNativeTests')
ORIGINAL_TEST_SOURCE_SHA256 = 'fc7e7cf046a67d71f5568f10e1ae4e7c78e320aca25cabb68b1d00766b14c879'
EXPECTED_IDS = ('tests.test_hia_candidate_build.CandidateBuildSourceTests.test_complete_generated_hia_and_original_limits', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_exact_original_catalog_all_55_and_three_dedicated_exclusions', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_vm_actual_hia_catalog_selection_and_permanent_rejection', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_vm_packer_all_output_bytes_and_short_output_no_write', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_vm_sha_mismatch_refuses_before_compiler_request', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_all_55_real_canonical_images_and_exact_original_manifests', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_complete_preflight_rejections_publish_no_bytes', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_existing_installed_preflight_loader_accepts_actual_native_manifest', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_runtime_has_no_file_open_exec_child_or_writable_executable_mapping')
ORIGINAL_METHOD_SHA256 = {'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_exact_original_catalog_all_55_and_three_dedicated_exclusions': '5cb64084d100e320357662e74c32e74383658a9555c6a89105876a0f6d90477f', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_complete_generated_hia_and_original_limits': '00d582bbde3a462296bf484ea1b6f4870fb14634af359c65bcb5a5001b7ebd57', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_vm_actual_hia_catalog_selection_and_permanent_rejection': '361ae682a90fe203bdc81db7a7997042aeb81c1fe40584a050f433b8d018008f', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_vm_sha_mismatch_refuses_before_compiler_request': 'db9ccac25663393b9be0ec290319ba27a38eb68a22cdae40cbf5942b3d5f76dd', 'tests.test_hia_candidate_build.CandidateBuildSourceTests.test_vm_packer_all_output_bytes_and_short_output_no_write': '99551ae463c9bc894a321222746803ec013b0437989acc8bc15b4251640efc30', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_all_55_real_canonical_images_and_exact_original_manifests': '1e9c0fb5f8c02a6a21deff0ef1f2f1e6c1f74a6c987e9ac344a9723b9d86bf97', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_complete_preflight_rejections_publish_no_bytes': '20a5b270a8eeb81532810b54cbf40ef2ed0230a9e940c892e4d370a0c766a9dc', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_runtime_has_no_file_open_exec_child_or_writable_executable_mapping': 'edfee8e369676872584b5098df539b62404f394233ab85938ef7e7326e1313e4', 'tests.test_hia_candidate_build.CandidateBuildNativeTests.test_existing_installed_preflight_loader_accepts_actual_native_manifest': '57d47512affc50667a260bac0096be02e935bb3b482674d141b05c2777a8d00e'}
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
COMPILE_SOURCES = (
    ('candidate-build-policy', 'examples/hia_bootstrap/candidate_build_policy.hepta'),
    ('source-build-policy', 'examples/hia_bootstrap/source_build_policy.hepta'),
    ('sha256', 'examples/hia_bootstrap/sha256.hepta'),
    ('candidate-build-packer', 'examples/hia_bootstrap/candidate_build_packer.hepta'),
)
EXTRA_REQUIRED_SOURCES = (
    'tools/qualify_hia_candidate_build.py',
    'tests/test_hia_candidate_build.py',
    'tests/test_hia_candidate_build_qualifier.py',
    'tests/test_hia_source_build.py',
    'tools/generate_hia_artifact_publication.py',
    'tools/generate_hia_source_build.py',
    'tools/hia_selfhost_process_owner.py',
    'tools/hia_selfhost_contract.py',
    'tools/qualify_hia_selfhost_cli.py',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_program_runtime.py',
)
REJECTION_LABELS = (
    'unknown', 'dedicated-core', 'dedicated-ledger', 'dedicated-emission',
    'wrong-name', 'source-drift', 'wrong-mode', 'trailing', 'truncated', 'empty',
    'bad-magic', 'zero-members', '129-members', 'nonzero-reserved', 'duplicate',
    'two-distinct', 'source-over-limit',
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


def _publish(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw)


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
        require(type(item['path']) is str and Path(item['path']).is_absolute()
                and type(item['bytes']) is int and type(item['mode']) is int,
                'absolute path and exact integer identities required')
        require(_pin(item['path']) == item, 'qualification input changed: ' + item['path'])
        paths.append(item['path'])
    require(len(paths) == len(set(paths)), 'duplicate qualification input binding')


def required_source_names():
    from tools.build_hia_candidate_build import SOURCE_NAMES
    from tools.generate_hia_candidate_build import catalog
    return tuple(sorted(set(SOURCE_NAMES) | set(EXTRA_REQUIRED_SOURCES)
                        | {'examples/hia_bootstrap/' + row['source_name'] for row in catalog()}))


def _admit_required_sources(sources, root=ROOT, names=None):
    require(type(sources) is dict, 'complete cold source map required')
    for name in required_source_names() if names is None else names:
        require(name in sources, 'candidate qualification input missing from cold source contract: ' + name)
        require(sources[name] == sha256((Path(root) / name).read_bytes()).hexdigest(),
                'candidate qualification source differs: ' + name)


def _outer_shape(outer):
    require(type(outer) is dict and outer.get('schema') == 'hepta.hia.selfhost-cold-replay.v1'
            and outer.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
            and type(outer.get('returncode')) is int and outer['returncode'] == 0,
            'a completed matching cold replay is required')
    require(type(outer.get('qualification_wall_limit_seconds')) is int
            and outer['qualification_wall_limit_seconds'] == 180
            and type(outer.get('cleanup_wall_limit_seconds')) is int
            and outer['cleanup_wall_limit_seconds'] == 3, 'original cold limits must remain 180+3')
    owner = outer.get('process_owner')
    require(type(owner) is dict and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
            and type(owner.get('returncode')) is int and owner['returncode'] == 0
            and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
            and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True,
            'cold process completion and cleanup are not established')
    require(type(outer.get('nested_report')) is str and outer['nested_report']
            and type(outer.get('nested_report_sha256')) is str, 'actual nested cold report required')


def _original_methods():
    raw = (ROOT / TEST_SOURCE).read_text()
    lines = raw.splitlines(keepends=True)
    observed = {}
    for group in ast.parse(raw).body:
        if isinstance(group, ast.ClassDef) and group.name in ('CandidateBuildSourceTests', 'CandidateBuildNativeTests'):
            for method in group.body:
                if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'):
                    name = MODULE + '.' + group.name + '.' + method.name
                    text = ''.join(lines[method.lineno - 1:method.end_lineno])
                    observed[name] = sha256(text.encode()).hexdigest()
    require(observed == ORIGINAL_METHOD_SHA256, 'original nine business method texts differ')
    return observed


def admit_cold(cold_report):
    from tools.build_hia_json_preflight import admit_cold_build
    path = Path(cold_report).resolve(strict=True)
    raw = path.read_bytes()
    outer = _json(raw)
    _outer_shape(outer)
    nested_path = Path(outer['nested_report']).resolve(strict=True)
    nested_raw = nested_path.read_bytes()
    require(sha256(nested_raw).hexdigest() == outer['nested_report_sha256'], 'nested cold report changed')
    nested = _json(nested_raw)
    require(type(nested) is dict and nested.get('schema') == 'hepta.hia.selfhost-qualification.v6'
            and nested.get('status') == 'SELF_HOSTED_FIXED_CORE_PASS'
            and type(nested.get('checks')) is dict and nested['checks']
            and all(value is True for value in nested['checks'].values()), 'nested qualification failed')
    generations = nested.get('generations')
    require(type(generations) is list and len(generations) == 3
            and all(type(row) is dict for row in generations), 'three actual cold generations required')
    paths = [Path(row['produced_image']).resolve(strict=True) for row in generations]
    images = [item.read_bytes() for item in paths]
    hashes = [sha256(image).hexdigest() for image in images]
    require([row.get('produced_sha256') for row in generations] == hashes
            == outer.get('generation_sha256') and len(set(hashes)) == 1
            and all(type(row.get('produced_bytes')) is int and row['produced_bytes'] == len(image)
                    and 0 < len(image) <= CAPACITY for row, image in zip(generations, images)),
            'actual cold generation bytes differ')
    sources = admit_cold_build(images[-1], raw)
    require(nested.get('source_manifest') == sources and nested.get('profile') == outer.get('profile'),
            'nested source/profile identity differs')
    _admit_required_sources(sources)
    _original_methods()
    authority = {'cold_report': str(path), 'cold_report_sha256': sha256(raw).hexdigest(),
                 'nested_report': str(nested_path), 'compiler': str(paths[-1]),
                 'compiler_sha256': hashes[-1], 'source_manifest': sources,
                 'input_bindings': [_pin(p) for p in dict.fromkeys((path, nested_path, *paths))]}
    guard_authority(authority)
    return authority


def guard_authority(authority):
    from tools.build_hia_json_preflight import current_sources
    _check_bindings(authority['input_bindings'])
    require(current_sources() == authority['source_manifest'], 'full current cold source map changed')
    _admit_required_sources(authority['source_manifest'])
    _original_methods()


def _observation(directory, label, image, payload):
    """Bind the actual request and complete output to the captured native inputs."""
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
            and request.get('source') == str(source.resolve()) and request.get('output') == str(output_path.resolve())
            and request.get('format') == 'flat-x86-64' and request.get('image_sha256') == image_sha
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
    require(limits == {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                      'output_capacity': CAPACITY, 'stack_bytes': 8388608, 'workspace_bytes': CAPACITY}
            and limits['core_dumpable'] is False
            and all(type(limits[key]) is int for key in limits if key != 'core_dumpable'),
            'original child limits differ: ' + label)
    return receipt, output[:size]


def _compile_observation(directory, label, compiler, source):
    receipt, produced = _observation(directory, label, compiler, source)
    path = Path(directory) / (label + '.image.bin')
    require(receipt.get('produced_image') == str(path) and receipt.get('produced_sha256') == sha256(produced).hexdigest()
            and type(receipt.get('produced_bytes')) is int and receipt['produced_bytes'] == len(produced)
            and path.read_bytes() == produced, 'compiled image differs from actual output: ' + label)
    return path, receipt


def _production_build(folder, authority):
    from tools import build_hia_candidate_build as builder
    from tools.generate_hia_candidate_build import PACK_MAGIC, LAYOUT
    from tools.qualify_hia_selfhost_cli import inspect_executable
    folder = Path(folder)
    report = _json((folder / 'BUILD.json').read_bytes())
    require(type(report) is dict and report.get('schema') == 'hepta.hia.candidate-build-bootstrap.v1'
            and report.get('status') == 'COLD_BOUND_NATIVE_BUILDER_CREATED'
            and report.get('development') is False and report.get('cold_authority') is True,
            'actual production cold bootstrap required; development cannot qualify')
    compiler = folder / 'captured-compiler.image.bin'
    compiler_bytes = compiler.read_bytes()
    require(compiler_bytes == Path(authority['compiler']).read_bytes()
            and sha256(compiler_bytes).hexdigest() == authority['compiler_sha256']
            and stat.S_IMODE(compiler.stat().st_mode) == 0o400, 'captured cold compiler differs')
    sources = {name: (ROOT / name).read_bytes() for name in builder.SOURCE_NAMES}
    require(report.get('source_identity') == {name: sha256(raw).hexdigest() for name, raw in sources.items()}
            and report.get('cold_source_manifest') == authority['source_manifest']
            and report.get('compiler_sha256') == authority['compiler_sha256']
            and report.get('cold_report_sha256') == authority['cold_report_sha256'],
            'production bootstrap source or cold binding differs')
    images, receipts = {}, {}
    for label, name in COMPILE_SOURCES:
        images[label], receipts[label] = _compile_observation(folder, label, compiler, sources[name])
    payloads = [images['candidate-build-policy'].read_bytes(), images['source-build-policy'].read_bytes(),
                compiler_bytes, images['sha256'].read_bytes()]
    frame = struct.pack('<5Q', PACK_MAGIC, *map(len, payloads)) + b''.join(payloads)
    pack, executable = _observation(folder, 'pack-candidate-build', images['candidate-build-packer'], frame)
    path = folder / 'hia-candidate-build'
    require(path.read_bytes() == executable and stat.S_IMODE(path.stat().st_mode) == 0o500
            and report.get('executable_path') == path.name
            and type(report.get('executable_bytes')) is int and report['executable_bytes'] == len(executable)
            and report.get('executable_sha256') == sha256(executable).hexdigest()
            and report.get('inspection') == inspect_executable(executable)
            and report.get('memory_layout') == LAYOUT
            and report.get('compile_receipts') == receipts and report.get('pack_receipt') == pack
            and report.get('resident_images') == {label: sha256(p.read_bytes()).hexdigest() for label, p in images.items()}
            and report.get('runtime_python_required') is False and report.get('runtime_child_process_required') is False
            and report.get('catalog_manifest_and_compile_dispatch_owned_by_HIA') is True
            and report.get('cold_admission_provider_is_python') is True
            and report.get('bootstrap_and_publication_provider_is_python') is True
            and report.get('production_activated') is False and report.get('whole_native_qualified') is False,
            'production executable or complete actual receipts differ')
    return path


def _fixture_description(directory, authority):
    directory = Path(directory)
    build_dir = directory / 'bootstrap'
    executable = _production_build(build_dir, authority)
    bindings = []
    for path in sorted(build_dir.rglob('*')):
        if path.is_dir():
            require(not path.is_symlink(), 'fixture directory link refused')
        else:
            bindings.append(_pin(path))
    return {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS, 'matching_cold': True,
            'qualification_complete': False, 'whole_native': False, 'authority': authority,
            'build_directory': str(build_dir), 'executable': _pin(executable),
            'build_input_bindings': bindings, 'original_test_source_sha256': ORIGINAL_TEST_SOURCE_SHA256,
            'original_method_sha256': _original_methods()}


def prepare_fixture(directory, cold_report):
    from tools.build_hia_candidate_build import build
    authority = admit_cold(cold_report)
    directory = Path(directory).absolute()
    require(not directory.exists() and not directory.is_symlink(), 'exclusive new fixture directory required')
    directory.mkdir(mode=0o700)
    build(directory / 'bootstrap', Path(authority['compiler']), cold_report=Path(authority['cold_report']))
    guard_authority(authority)
    description = _fixture_description(directory, authority)
    guard_authority(authority)
    path = directory / 'FIXTURE.json'
    _publish(path, description)
    admit_fixture(path)
    return path


def admit_fixture(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    selected = _json(raw)
    require(type(selected) is dict and selected.get('schema') == FIXTURE_SCHEMA
            and selected.get('status') == FIXTURE_STATUS and selected.get('matching_cold') is True
            and selected.get('qualification_complete') is False and selected.get('whole_native') is False,
            'explicit production cold fixture required')
    authority = admit_cold(selected['authority']['cold_report'])
    require(selected.get('authority') == authority, 'fixture cold authority changed')
    _check_bindings(selected['build_input_bindings'])
    require(_fixture_description(path.parent, authority) == selected, 'actual fixture or production receipt chain changed')
    guard_authority(authority)
    require(path.read_bytes() == raw, 'fixture record changed during admission')
    return selected


def selected_cold_fixture(environment=None):
    environment = os.environ if environment is None else environment
    if COLD_FIXTURE_ENV not in environment:
        return None
    value = environment[COLD_FIXTURE_ENV]
    require(type(value) is str and value, 'empty cold selection is not absence')
    require(DEVELOPMENT_ENV not in environment, 'cold and development selections cannot mix')
    return Path(value)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def load_suite():
    _original_methods()
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(SELECTORS)
    ids = [case.id() for case in flatten(suite)]
    require(not loader.errors and ids == list(EXPECTED_IDS) and len(ids) == len(set(ids)) == 9,
            'original complete nine-method discovery differs')
    require(Path(sys.modules[MODULE].__file__).resolve() == ROOT / TEST_SOURCE, 'caller module came from another source')
    return suite, ids


def admit_child_report(report, request_sha):
    require(type(report) is dict and report.get('schema') == 'hepta.hia.candidate-build-observations.v1'
            and report.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
            and report.get('status') == 'PASS' and report.get('request_sha256') == request_sha
            and report.get('loaded_ids') == list(EXPECTED_IDS)
            and report.get('started_ids') == list(EXPECTED_IDS) and report.get('stopped_ids') == list(EXPECTED_IDS)
            and type(report.get('tests_run')) is int and report['tests_run'] == 9
            and report.get('source_and_inputs_unchanged') is True, 'complete original nine observations differ')
    anomalies = report.get('anomalies')
    require(type(anomalies) is dict and set(anomalies) == set(ANOMALIES)
            and all(type(anomalies[key]) is list and not anomalies[key] for key in ANOMALIES),
            'failure, error, skip or expected failure cannot qualify')
    require(type(report.get('native_observations')) is list and len(report['native_observations']) == 75
            and type(report.get('vm_observations')) is list and len(report['vm_observations']) == 69,
            'original 75 native and 69 VM observations required')


def _source_snapshot():
    result = {}
    for path in sorted(ROOT.rglob('*')):
        if path.is_file():
            require(not path.is_symlink(), 'source link refused')
            raw = path.read_bytes()
            result[path.relative_to(ROOT).as_posix()] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                                                       'mode': stat.S_IMODE(path.stat().st_mode)}
    return result


def _child(request_path):
    request_path = Path(request_path)
    raw = request_path.read_bytes()
    request = _json(raw)
    output = Path(request['output'])
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.candidate-build-observations.v1', 'status': 'FAIL',
              'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'request_sha256': sha256(raw).hexdigest(),
              'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
              'loaded_ids': [], 'started_ids': [], 'stopped_ids': [], 'tests_run': 0,
              'anomalies': {name: [] for name in ANOMALIES}, 'native_observations': [], 'vm_observations': []}
    authority = before = None
    started = time.monotonic_ns()
    try:
        require(request.get('schema') == 'hepta.hia.candidate-build-group-request.v1', 'unknown group request')
        selected = selected_cold_fixture()
        require(selected is not None and str(selected) == request['fixture']
                and _pin(selected) == request['fixture_binding'], 'group fixture selection differs')
        fixture = admit_fixture(selected)
        authority = fixture['authority']
        require(authority['source_manifest'] == request['source_manifest'], 'group source changed')
        require(os.environ.get(EVIDENCE_ENV) == str(output / 'observations'), 'explicit observation directory differs')
        before = _source_snapshot()
        _publish(output / 'SOURCE-BEFORE.json', before)
        suite, ids = load_suite()
        report['loaded_ids'] = ids
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                report['started_ids'].append(test.id())
                super().startTest(test)
            def stopTest(self, test):
                report['stopped_ids'].append(test.id())
                super().stopTest(test)
        with (output / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        module = sys.modules[MODULE]
        report.update(tests_run=result.testsRun, native_observations=module.RAW_OBSERVATIONS,
                      vm_observations=module.VM_OBSERVATIONS,
                      anomalies={'failures': [(t.id(), text) for t, text in result.failures],
                                 'errors': [(t.id(), text) for t, text in result.errors],
                                 'skipped': [(t.id(), reason) for t, reason in result.skipped],
                                 'expected_failures': [(t.id(), text) for t, text in result.expectedFailures],
                                 'unexpected_successes': [t.id() for t in result.unexpectedSuccesses]})
        report['status'] = 'PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        try:
            require(authority is not None and before is not None, 'child never admitted current cold authority')
            after = _source_snapshot()
            _publish(output / 'SOURCE-AFTER.json', after)
            require(before == after, 'full source bytes or modes changed')
            guard_authority(authority)
            require(_pin(request['fixture']) == request['fixture_binding'], 'fixture record changed')
            admit_fixture(request['fixture'])
            require(request_path.read_bytes() == raw, 'group request changed')
            report['source_and_inputs_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        try:
            admit_child_report(report, sha256(raw).hexdigest())
        except BaseException:
            report.update(status='FAIL', outcome_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns() - started
        _publish(output / 'RESULT.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _verify_actual_observations(directory, report, fixture):
    """Read actual component artifacts; a count or PASS flag is insufficient."""
    from tools.generate_hia_candidate_build import catalog
    from tests.test_hia_source_build import unpack
    directory = Path(directory)
    compiler = Path(fixture['build_directory']) / 'captured-compiler.image.bin'
    rows = catalog()
    expected = [f'catalog-{i:02d}-' + row['candidate'] for i, row in enumerate(rows)]
    expected += ['reject-' + label for label in REJECTION_LABELS]
    expected += ['existing-loader', 'runtime-normal', 'runtime-restricted']
    actual = report['native_observations']
    require([row.get('case') for row in actual] == expected and len(set(expected)) == 75,
            'actual native observation identities or ordering differ')
    outputs = {}
    for row in actual:
        folder = directory / row['case']
        require(_json((folder / 'OBSERVATION.json').read_bytes()) == row, 'native observation record changed')
        wire, output, error = [(folder / name).read_bytes() for name in ('input.raw', 'stdout.raw', 'stderr.raw')]
        rejected = row['case'].startswith('reject-')
        require(type(row.get('returncode')) is int and row['returncode'] == (16 if rejected else 0)
                and type(row.get('expected_returncode')) is int and row['expected_returncode'] == row['returncode']
                and type(row.get('wall_limit_seconds')) is int and row['wall_limit_seconds'] == COMPILE_SECONDS
                and type(row.get('input_bytes')) is int and row['input_bytes'] == len(wire)
                and type(row.get('output_bytes')) is int and row['output_bytes'] == len(output)
                and row.get('input_sha256') == sha256(wire).hexdigest()
                and row.get('output_sha256') == sha256(output).hexdigest()
                and row.get('stderr_sha256') == sha256(error).hexdigest() and error == b''
                and row.get('executable_sha256') == fixture['executable']['sha256']
                and row.get('restricted_runtime') is (row['case'] == 'runtime-restricted')
                and (not rejected or not output), 'actual native bytes/return/limit differs')
        outputs[row['case']] = output
    for index, row in enumerate(rows):
        label = f'catalog-{index:02d}-' + row['candidate']
        folder = directory / label
        source = (ROOT / 'examples/hia_bootstrap' / row['source_name']).read_bytes()
        reference, receipt = _compile_observation(folder, 'reference-compile', compiler, source)
        members = unpack(outputs[label])
        require(list(members) == [row['source_name'].encode(), (row['protocol'] + '.image.bin').encode(), b'manifest.json']
                and members[row['source_name'].encode()] == source
                and members[(row['protocol'] + '.image.bin').encode()] == reference.read_bytes(),
                'actual canonical source or image differs from the cold compiler observation')
        expected_manifest = {'schema': 'hepta.hia.' + row['protocol'] + '-native.v' + str(row['schema_version']),
                             'source_sha256': sha256(source).hexdigest(), 'image_path': row['protocol'] + '.image.bin',
                             'image_sha256': sha256(reference.read_bytes()).hexdigest(),
                             'compiler_sha256': fixture['authority']['compiler_sha256']}
        serialized = (json.dumps(expected_manifest, indent=2, sort_keys=True) + '\n').encode()
        require(members[b'manifest.json'] == serialized == (folder / 'expected-manifest.json').read_bytes()
                == (folder / 'actual-manifest.json').read_bytes(), 'actual full manifest bytes differ')
    require(outputs['runtime-normal'] == outputs['runtime-restricted'] == outputs['existing-loader'],
            'restricted runtime or installed-loader payload differs')
    vm = sorted((directory / 'vm').glob('*.json'))
    require(len(vm) == 69, 'all independent VM artifacts required')
    for index, path in enumerate(vm):
        observed = _json(path.read_bytes())
        require(path.name == f'{index:04d}.json' and observed.get('sequence') == index
                and {key: observed[key] for key in ('sequence', 'result', 'steps')} == report['vm_observations'][index],
                'VM report no longer matches the actual artifact')
        import base64
        import zlib
        require(set(observed['buffers']) == {'source', 'output_before', 'workspace_before', 'output_after', 'workspace_after'},
                'complete VM buffer set required')
        for bound in observed['buffers'].values():
            require(bound.get('encoding') == 'base64-zlib' and type(bound.get('bytes')) is int,
                    'actual full VM buffer encoding required')
            raw = zlib.decompress(base64.b64decode(bound['data'], validate=True))
            require(len(raw) == bound['bytes'] and sha256(raw).hexdigest() == bound['sha256'], 'VM buffer bytes changed')
    return {'canonical_image_and_manifest_pairs': 55, 'native_process_observations': 75,
            'independent_vm_full_frames': 69,
            'bindings': [_pin(path) for path in sorted(directory.rglob('*')) if path.is_file()]}


def qualify(cold_report, evidence):
    from tools.hia_selfhost_process_owner import run_owned
    require(DEVELOPMENT_ENV not in os.environ and COLD_FIXTURE_ENV not in os.environ,
            'standalone qualifier accepts its explicit cold report, not ambient test selections')
    evidence = Path(evidence).absolute()
    require(not evidence.exists() and not evidence.is_symlink(), 'exclusive new qualification evidence directory required')
    evidence.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.candidate-build-cold-qualification.v1', 'status': 'FAIL',
              'matching_cold': False, 'qualification_complete': False, 'whole_native': False,
              'production_activated': False, 'group_seconds': GROUP_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
              'compile_seconds': COMPILE_SECONDS, 'python': sys.version, 'platform': platform.platform()}
    fixture = None
    try:
        selected = prepare_fixture(evidence / 'fixture', cold_report)
        fixture = admit_fixture(selected)
        request = {'schema': 'hepta.hia.candidate-build-group-request.v1', 'fixture': str(selected),
                   'fixture_binding': _pin(selected), 'source_manifest': fixture['authority']['source_manifest'],
                   'output': str(evidence / 'components')}
        request_path = evidence / 'REQUEST.json'
        _publish(request_path, request)
        request_raw = request_path.read_bytes()
        environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                       'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0',
                       COLD_FIXTURE_ENV: str(selected), EVIDENCE_ENV: str(evidence / 'components/observations')}
        argv = [sys.executable, '-B', '-m', 'tools.qualify_hia_candidate_build', '--child-request', str(request_path)]
        owner = run_owned(argv, cwd=ROOT, env=environment, stdout_path=evidence / 'stdout.log',
                          stderr_path=evidence / 'stderr.log', receipt_path=evidence / 'OWNER.json',
                          qualification_seconds=GROUP_SECONDS, cleanup_seconds=CLEANUP_SECONDS)
        report['owner'] = owner
        require(owner.get('status') == 'OWNED_PROCESS_COMPLETED' and type(owner.get('returncode')) is int
                and owner['returncode'] == 0 and owner.get('timed_out') is False
                and owner.get('exit_observed_before_deadline') is True
                and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True,
                'original owned-process completion, deadline or cleanup failed')
        child = _json((evidence / 'components/RESULT.json').read_bytes())
        admit_child_report(child, sha256(request_raw).hexdigest())
        actual = _verify_actual_observations(evidence / 'components/observations', child, fixture)
        require(request_path.read_bytes() == request_raw and _pin(selected) == request['fixture_binding'],
                'request or fixture record changed')
        guard_authority(fixture['authority'])
        require(admit_fixture(selected) == fixture, 'fixture changed after components')
        report.update(status='MATCHING_COLD_CANDIDATE_BUILD_COMPONENTS_PASS', matching_cold=True,
                      qualification_complete=True, fixture=str(selected), fixture_binding=_pin(selected),
                      authority=fixture['authority'], actual=actual, loaded_ids=child['loaded_ids'],
                      started_ids=child['started_ids'], stopped_ids=child['stopped_ids'], tests_run=child['tests_run'])
    except BaseException:
        report['traceback'] = traceback.format_exc()
    finally:
        if fixture is not None:
            try:
                guard_authority(fixture['authority'])
                require(admit_fixture(evidence / 'fixture/FIXTURE.json') == fixture, 'final fixture readback differs')
            except BaseException:
                report.update(status='FAIL', qualification_complete=False, matching_cold=False,
                              final_guard_error=traceback.format_exc())
        _publish(evidence / 'QUALIFICATION.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--child-request', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child_request is not None:
        if args.cold_report is not None or args.evidence is not None:
            parser.error('internal child request cannot combine outer arguments')
        return _child(args.child_request)
    if args.cold_report is None or args.evidence is None:
        parser.error('--cold-report and --evidence are required')
    report = qualify(args.cold_report, args.evidence)
    print(json.dumps({key: report[key] for key in ('status', 'matching_cold', 'qualification_complete', 'whole_native')}))
    return 0 if report['status'] == 'MATCHING_COLD_CANDIDATE_BUILD_COMPONENTS_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
