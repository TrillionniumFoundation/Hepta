"""v86 explicit development: original method bodies, different disclosed fixtures.

Never executes either original native class's fresh B0/B1/B2 setUpClass.
Never claims original 39 publication tests, fresh cold, or recovered CI state.
"""
from collections import Counter
from hashlib import sha256
import argparse
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
import traceback
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (controls, external_inputs, imported_modules, join_child, read,
                    require, small_pin, source_snapshot, write)


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def run_suite(suite, folder, expected, current):
    loaded = [test.id() for test in flatten(suite)]
    require(loaded == expected and len(set(loaded)) == len(loaded), 'complete fixed development fixture IDs differ')
    executed = []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            current[0] = test.id(); executed.append(test.id())
            super().startTest(test)
    started = time.monotonic_ns()
    with (folder / 'unittest.log').open('x') as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
    value = {'loaded_ids': loaded, 'executed_ids': executed, 'tests_run': result.testsRun,
             'elapsed_ns': time.monotonic_ns() - started}
    for name in ('errors', 'failures', 'skipped', 'expectedFailures'):
        value[name] = [[test.id(), detail] for test, detail in getattr(result, name)]
    value['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
    value['pass'] = (result.testsRun == len(loaded) and loaded == executed
                     and not any(value[name] for name in
                        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')))
    write(folder / 'suite.json', value)
    return value


def build(folder, source, config):
    from tools import qualify_hia_selfhost as qualify
    from tools.generate_hia_artifact_publication import MAGIC
    require(qualify.CAPACITY == 1 << 20 and qualify.NATIVE_OBSERVER is None
            and qualify.NATIVE_LINKED_OBSERVER is None, 'original direct child compile path required')
    folder.mkdir(mode=0o700)
    compiler = folder / 'existing-v82-B3.image.bin'
    compiler.write_bytes(read(config['inputs']['compiler']['path'])[0]); compiler.chmod(0o400)
    result = {'scope': 'EXISTING_V82_B3_DEVELOPMENT', 'fresh_B0_B1_B2_executed': False,
              'compiler': small_pin(compiler), 'compiled': {}, 'retained_bundle': {}}
    for label, schema in [('sha256', 'hepta.hia.sha256-native.v1'),
                          ('sha256_stream', 'hepta.hia.sha256-stream-native.v1')]:
        raw = (source / 'examples/hia_bootstrap' / (label + '.hiaasm')).read_bytes()
        image, receipt = qualify.compile_stage(folder, label, compiler, raw)
        joined = join_child(folder, label, compiler, raw, config, image)
        manifest = folder / (label + '.manifest.json')
        write(manifest, {'schema': schema, 'source_sha256': sha256(raw).hexdigest(),
                        'image_path': image.name, 'image_sha256': small_pin(image)['sha256'],
                        'compiler_sha256': small_pin(compiler)['sha256']})
        result['compiled'][label] = {'image': str(image), 'manifest': str(manifest),
                                    'receipt': receipt, 'actual_child_join': joined}
        for path in (image, manifest, folder / (label + '.receipt.json')):
            result['retained_bundle'][str(path)] = small_pin(path)
    # The earlier comparison actually compiled these exact, unchanged sources.
    # Copy the sealed images; do not repeat their compiles or pretend they are new.
    for label in ('policy', 'packer'):
        name = 'artifact_publication_' + label
        current = small_pin(source / 'examples/hia_bootstrap' / (name + '.hiaasm'))
        require(current == {k: config['inputs'][label + '_source'][k] for k in ('bytes', 'sha256')},
                'retained publication image source is no longer identical')
        path = folder / (label + '.retained.image.bin')
        path.write_bytes(read(config['inputs'][label + '_image']['path'])[0]); path.chmod(0o400)
        result['retained_bundle'][str(path)] = small_pin(path)
    policy = (folder / 'policy.retained.image.bin').read_bytes()
    stream = Path(result['compiled']['sha256_stream']['image']).read_bytes()
    packet = struct.pack('<3Q', MAGIC, len(policy), len(stream)) + policy + stream
    receipt, full = qualify.invoke(folder, 'publication-pack', folder / 'packer.retained.image.bin', packet)
    result['pack'] = join_child(folder, 'publication-pack', folder / 'packer.retained.image.bin', packet, config)
    raw = full[:result['pack']['returned_bytes']]
    require(raw[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH', raw, 16) == (2, 62),
            'actual pack output is not Linux x86-64 ET_EXEC')
    app = folder / 'hia-artifact'; app.write_bytes(raw); app.chmod(0o700)
    result['app'] = str(app); result['retained_bundle'][str(app)] = small_pin(app)
    result['retained_bundle'][str(compiler)] = small_pin(compiler)
    result['new_compile_transactions'] = 2; result['new_pack_transactions'] = 1
    write(folder / 'BUILD.json', result)
    return result


def sha_phase(output, source, config, report):
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from hepta.hia_sha256_stream_native import NativeSha256Stream
    from tests.test_hia_sha256_native import Sha256HiaNativeTests
    from tests.test_hia_sha256_stream_native import Sha256StreamNativeTests
    built = build(output / 'build', source, config); report['build'] = built
    current = ['outside-method']; returns = Counter(); lock = threading.Lock()
    original_init = NativeHiaJsonImage.__init__
    expected_images = {small_pin(v['image'])['sha256'] for v in built['compiled'].values()}
    def observed_init(self, image, expected_sha):
        original_init(self, image, expected_sha)
        if expected_sha in expected_images:
            actual_entry = self._entry
            def entry(*arguments):
                value = actual_entry(*arguments)
                with lock:
                    returns[(current[0], self.image_sha256, len(arguments), value)] += 1
                return value
            self._entry = entry
    fixture_events = []
    class DevelopmentOneShotCases(Sha256HiaNativeTests):
        @classmethod
        def setUpClass(cls):
            value = built['compiled']['sha256']
            raw = Path(value['image']).read_bytes()
            cls.code = NativeHiaJsonImage(raw, sha256(raw).hexdigest())
            cls.receipt = value['receipt']; cls.manifest = Path(value['manifest'])
            fixture_events.append({'class': cls.__name__, 'operation': 'explicit_existing_compiler_fixture'})
        @classmethod
        def tearDownClass(cls):
            fixture_events.append({'class': cls.__name__, 'operation': 'retain_complete_fixture'})
    class DevelopmentStreamCases(Sha256StreamNativeTests):
        @classmethod
        def setUpClass(cls):
            value = built['compiled']['sha256_stream']
            raw = Path(value['image']).read_bytes()
            cls.image = NativeSha256Stream(raw, sha256(raw).hexdigest())
            cls.receipt = value['receipt']; cls.manifest = Path(value['manifest'])
            fixture_events.append({'class': cls.__name__, 'operation': 'explicit_existing_compiler_fixture'})
        @classmethod
        def tearDownClass(cls):
            fixture_events.append({'class': cls.__name__, 'operation': 'retain_complete_fixture'})
    loader = unittest.TestLoader(); suite = unittest.TestSuite(); mapping = {}
    for cls, original, key in [(DevelopmentOneShotCases, Sha256HiaNativeTests, 'one_shot'),
                               (DevelopmentStreamCases, Sha256StreamNativeTests, 'stream')]:
        names = loader.getTestCaseNames(original)
        expected = config['sha_original_ids'][key]
        require([original.__module__ + '.' + original.__name__ + '.' + n for n in names] == expected,
                'original method population differs')
        for name, origin in zip(names, expected):
            require(getattr(cls, name) is getattr(original, name), 'original method body was replaced')
            instance = cls(name); mapping[instance.id()] = origin; suite.addTest(instance)
    require(not loader.errors and len(mapping) == 12, 'original 7+5 loader differs')
    report.update({'fixture_scope': 'ORIGINAL_METHOD_BODIES_WITH_EXPLICIT_DEVELOPMENT_SUBCLASSES',
                   'original_native_classes_executed': False, 'original_fresh_setUpClass_executed': False,
                   'original_VM_setUpClass_prechecks_executed': False, 'original_to_development_IDs': mapping})
    try:
        with patch.object(NativeHiaJsonImage, '__init__', observed_init):
            report['suite'] = run_suite(suite, output, list(mapping), current)
    finally:
        report['fixture_events'] = fixture_events
        report['actual_native_returns'] = [dict(test=k[0], original_method=mapping.get(k[0]),
            image_sha256=k[1], flat_C_ABI_argument_count=k[2], status=k[3], count=n)
            for k, n in sorted(returns.items())]
        write(output / 'native-returns.json', report['actual_native_returns'])
    require(report['suite']['pass'] and report['suite']['tests_run'] == 12, 'complete original 12 bodies did not pass')
    require(fixture_events == [
        {'class': 'DevelopmentOneShotCases', 'operation': 'explicit_existing_compiler_fixture'},
        {'class': 'DevelopmentOneShotCases', 'operation': 'retain_complete_fixture'},
        {'class': 'DevelopmentStreamCases', 'operation': 'explicit_existing_compiler_fixture'},
        {'class': 'DevelopmentStreamCases', 'operation': 'retain_complete_fixture'},
    ], 'explicit development setup and retained teardown must both complete')
    require({r['test'] for r in report['actual_native_returns']} == set(mapping)
            and all(type(r['flat_C_ABI_argument_count']) is int and r['flat_C_ABI_argument_count'] == 6
                    and type(r['status']) is int and r['status'] in (0, 32, 0xfffffffd)
                    and type(r['count']) is int and r['count'] > 0
                    and r['image_sha256'] in expected_images for r in report['actual_native_returns']),
            'actual new-image returns do not cover all original methods')
    for path, expected in built['retained_bundle'].items():
        require(small_pin(path) == expected, 'actual built image/manifest/receipt changed')
    report['status'] = 'DEVELOPMENT_SHA_12_METHOD_BODIES_PASS'


def publication_phase(output, source, config, report, prior):
    from tests.test_hia_agent_artifact_store_native import AgentArtifactStoreKernelTests
    from tests.test_hia_artifact_publication_native import ArtifactPublicationKernelTests
    previous_raw, previous_pin = read(prior / 'REPORT.json', 8 << 20)
    previous = json.loads(previous_raw)
    require(previous['status'] == 'DEVELOPMENT_SHA_12_METHOD_BODIES_PASS', 'SHA phase did not fully pass')
    built = previous['build']; app = Path(built['app'])
    require(app == prior / 'build/hia-artifact', 'private actual app path differs')
    for path, expected in built['retained_bundle'].items():
        require(small_pin(path) == expected, 'previous exact build bytes differ')
    report['prior_sha_report'] = previous_pin; report['app'] = small_pin(app)
    fixtures = output / 'fixtures'; fixtures.mkdir(mode=0o700)
    calls = []; current = ['outside-method']; real_run = subprocess.run
    def observed_run(command, **kwargs):
        index = len(calls); folder = output / ('call-%02d' % index); folder.mkdir(mode=0o700)
        require(type(command) is list and command[0] == str(app), 'unexpected application command')
        operation = command[1]; seconds = 30 if operation == 'publish' else 60
        require(set(kwargs) == {'input','capture_output','env','timeout'}
                and type(kwargs['input']) is bytes and kwargs['capture_output'] is True
                and kwargs['env'] == {'PATH': ''} and kwargs['timeout'] == seconds,
                'original subprocess arguments/deadline differ')
        wire = kwargs['input']; (folder / 'stdin.original.bin').write_bytes(wire)
        row = {'ordinal': index, 'test': current[0], 'command': command, 'timeout_seconds': seconds,
               'environment': kwargs['env'], 'offered_input': small_pin(folder / 'stdin.original.bin'),
               'app_before': small_pin(app), 'status': 'HOLD',
               'offered_input_not_claimed_fully_consumed': True}
        calls.append(row); write(folder / 'REQUEST.json', row)
        started = time.monotonic_ns()
        try:
            value = real_run(command, **kwargs)
        except subprocess.TimeoutExpired as error:
            row['run_elapsed_ns'] = time.monotonic_ns() - started
            (folder / 'stdout.original.bin').write_bytes(error.stdout or b'')
            (folder / 'stderr.original.bin').write_bytes(error.stderr or b'')
            row['status'] = 'ORIGINAL_TIMEOUT_EXPIRED'; row['exception'] = traceback.format_exc()
            raise
        except BaseException:
            row['run_elapsed_ns'] = time.monotonic_ns() - started
            row['exception'] = traceback.format_exc(); raise
        else:
            row['run_elapsed_ns'] = time.monotonic_ns() - started
            (folder / 'stdout.original.bin').write_bytes(value.stdout)
            (folder / 'stderr.original.bin').write_bytes(value.stderr)
            row.update(status='RETURNED', returncode=value.returncode)
            return value
        finally:
            row['app_after'] = small_pin(app)
            for stream in ('stdout', 'stderr'):
                path = folder / (stream + '.original.bin')
                if path.exists(): row[stream] = small_pin(path)
            write(folder / 'RESULT.json', row)
    class DevelopmentQuotaCase(AgentArtifactStoreKernelTests):
        @classmethod
        def setUpClass(cls):
            cls.app = app; cls.folder = fixtures; cls.serial = 0
        @classmethod
        def tearDownClass(cls):
            pass  # Preserve actual fixture bytes, including failed invocations.
    class DevelopmentGenericCase(ArtifactPublicationKernelTests):
        @classmethod
        def setUpClass(cls):
            cls.app = app; cls.folder = fixtures; cls.serial = 0
        @classmethod
        def tearDownClass(cls):
            pass
        def test_generic_publish_accepts_same_first_overquota_payload(self):
            payload = b'x' * ((64 << 20) + 1)
            self.stage.write_bytes(payload)
            expected = {'sha256': sha256(payload).hexdigest(), 'bytes': len(payload)}
            value = self.run_app(wire=payload)
            self.assertEqual(json.loads(value.stdout), expected); self.assertEqual(value.stderr, b'')
            self.assertEqual(self.stage.read_bytes(), payload); self.assertEqual(self.dest.read_bytes(), payload)
            a, b = self.stage.stat(), self.dest.stat()
            self.assertEqual((a.st_dev, a.st_ino), (b.st_dev, b.st_ino))
            self.assertEqual(a.st_nlink, 2)
    method = 'test_quota_is_original_64MiB_and_never_applied_to_generic_publisher'
    require(getattr(DevelopmentQuotaCase, method) is getattr(AgentArtifactStoreKernelTests, method),
            'the original quota method body differs')
    require(DevelopmentQuotaCase.run_store is AgentArtifactStoreKernelTests.run_store
            and DevelopmentGenericCase.run_app is ArtifactPublicationKernelTests.run_app,
            'original 60/30 helper body differs')
    cases = [DevelopmentQuotaCase(method),
             DevelopmentGenericCase('test_generic_publish_accepts_same_first_overquota_payload')]
    report.update({'scope': 'ONE_ORIGINAL_QUOTA_METHOD_BODY_PLUS_ONE_EXPLICIT_GENERIC_MEASUREMENT',
                   'original_39_run': False, 'original_fresh_setUpClass_executed': False,
                   'original_quota_method': AgentArtifactStoreKernelTests.__module__ + '.' + AgentArtifactStoreKernelTests.__name__ + '.' + method,
                   'generic_input': 'same x repeated (64 MiB + 1) bytes as the original first rejected quota payload',
                   'calls': calls})
    try:
        with patch.object(subprocess, 'run', observed_run):
            report['suite'] = run_suite(unittest.TestSuite(cases), output, [c.id() for c in cases], current)
    finally:
        write(output / 'application-calls.json', calls)
    require(report['suite']['pass'] and report['suite']['tests_run'] == 2, 'quota/generic measurement failed')
    require([r['command'][1] for r in calls] == ['store-put','store-get','store-hash','store-put','publish']
            and [r['timeout_seconds'] for r in calls] == [60,60,60,60,30]
            and [r.get('returncode') for r in calls] == [0,0,17,17,0]
            and [r['offered_input']['bytes'] for r in calls] == [64<<20,0,(64<<20)+1,(64<<20)+1,(64<<20)+1]
            and all(r['status']=='RETURNED' and r['app_before']==r['app_after']==report['app'] for r in calls),
            'all five actual fixed runtime invocations are required')
    report['status'] = 'DEVELOPMENT_QUOTA_AND_GENERIC_MEASUREMENT_PASS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('sha','publication'), required=True)
    for key in ('config','source','output','prior'):
        parser.add_argument('--'+key, type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args(); config = json.loads(args.config.read_bytes())
    source = args.source.resolve(); output = args.output.resolve(); output.mkdir(mode=0o700)
    report = {'schema':'hepta.hia.v86-native-development-phase.v1','status':'HOLD','phase':args.phase,
              'source_candidate':config['candidate'],'python':sys.version,'fresh_cold':False,
              'original_39_run':False,'source_snapshot_scope':'all 1813 explicitly materialized canonical members'}
    try:
        before = source_snapshot(source, config); report['source_before'] = write(output/'source-before.json', before)
        report['control_before'] = controls(args.config, config, args.config_sha256)
        report['external_before'] = external_inputs(config)
        sys.path.insert(0, str(source))
        if args.phase == 'sha': sha_phase(output, source, config, report)
        else: publication_phase(output, source, config, report, args.prior.resolve())
    except BaseException:
        report['status'] = 'HOLD'; report['failure'] = traceback.format_exc()
    finally:
        try:
            report['imported_repository_modules'] = imported_modules(source, config)
            after = source_snapshot(source, config); report['source_after'] = write(output/'source-after.json', after)
            require(after == before, 'source bytes or identities changed')
            report['control_after'] = controls(args.config, config, args.config_sha256)
            report['external_after'] = external_inputs(config)
            require(report['control_after'] == report['control_before']
                    and report['external_after'] == report['external_before'], 'fixed inputs changed')
            report['source_stable'] = True
        except BaseException:
            report['status'] = 'HOLD'; report['final_read_error'] = traceback.format_exc()
        write(output/'REPORT.json', report)
    return 0 if report['status'].endswith('_PASS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
