"""Independent worker UNKNOWN terminal controls; original gates stay complete."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_EVIDENCE = 'HEPTA_HIA_WORKER_UNKNOWN_SOURCE_EVIDENCE'
EVIDENCE = 'HEPTA_HIA_WORKER_UNKNOWN_EVIDENCE'
COLD = 'HEPTA_HIA_WORKER_UNKNOWN_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_WORKER_UNKNOWN_DEVELOPMENT_COMPILER'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class WorkerUnknownSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence = os.environ.get(SOURCE_EVIDENCE)
        if evidence == '':
            raise ValueError('worker source evidence cannot be empty')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-worker-unknown-source-')
            cls.root = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)

    def control(self, mode, count):
        from tests.hia_service_verification_controls import run_process, clean_environment, write
        from tests.hia_service_verification_oracle import canonical
        from tools.read_hia_worker_unknown import read_source
        out, err, execution = run_process(self.root, mode, [
            ROOT/'tests/hia_worker_unknown_controls.py', '--mode', mode,
            '--output', self.root/mode], env=clean_environment(), timeout=180)
        # Bind the returned real supervisor result, not a later refreshed file.
        expected = pin(canonical(execution) + b'\n')
        result = read_source(self.root, mode, expected)
        self.assertEqual(result['count'], count)
        self.assertEqual(result['status'], 'PASS')
        write(self.root/(mode+'-independent-readback.json'), result)

    def test_01_complete_original_worker_ordinary_contract(self):
        self.control('ordinary', 40)

    def test_02_complete_true_loss_and_named_unrelated_error_controls(self):
        self.control('unknown', 15)

    def test_03_request_scope_resource_thread_fork_and_HIA_region_custody(self):
        source = ROOT/'tools/generate_hia_worker_report.py'
        tree = ast.parse(source.read_bytes())
        fields, = [node.value for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'FIELDS'
                           for target in node.targets)]
        values = {key.value: value.value for key, value in zip(fields.keys, fields.values)
                  if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)}
        self.assertEqual(values['CALL_REGION'], 120)
        self.assertEqual(values['CLOSE_REGION'], 128)
        self.control('scope', 13)


class WorkerUnknownNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests import test_hia_service_verification_native as original
        from tools.build_hia_worker_report import build, build_development
        from tools.build_hia_json_preflight import build as build_request
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_worker_request_native import SOURCE as REQUEST_SOURCE, SCHEMA as REQUEST_SCHEMA
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('one explicit matching cold report or DEV compiler is required')
        saved = dict(os.environ)
        try:
            for name in (original.COLD, original.DEVELOPMENT, original.EVIDENCE):
                os.environ.pop(name, None)
            os.environ[original.COLD if cold is not None else original.DEVELOPMENT] = cold if cold is not None else development
            if evidence is not None:
                os.environ[original.EVIDENCE] = evidence
            # Invoke the unchanged original build fixture, not a partial old
            # test. Its complete original class remains a separate required gate.
            original.ServiceVerificationNativeTests.setUpClass.__func__(cls)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        if cold is not None:
            cls.report_manifest = build(cls.root/'worker-report', cls.compiler, Path(cold))
            cls.request_manifest = build_request(cls.root/'worker-request', cls.compiler, Path(cold),
                                                 candidate='worker-request')
        else:
            cls.report_manifest = build_development(cls.root/'worker-report', cls.compiler)
            directory = cls.root/'worker-request'
            directory.mkdir(mode=0o700)
            image, receipt = compile_stage(directory, 'worker-request', cls.compiler, REQUEST_SOURCE.read_bytes())
            cls.request_manifest = directory/'manifest.json'
            value = {'schema': REQUEST_SCHEMA, 'source_sha256': sha256(REQUEST_SOURCE.read_bytes()).hexdigest(),
                     'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                     'compiler_sha256': sha256(cls.compiler_raw).hexdigest()}
            cls.request_manifest.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')
        cls.request_manifest.chmod(0o600)
        for path in (cls.report_manifest, cls.request_manifest):
            cls.manifest_pins[str(path)] = sha256(path.read_bytes()).hexdigest()
        from tests.hia_service_verification_controls import write
        write(cls.root/'worker-build-custody.json', {
            'schema':'hepta.hia.worker-unknown-build-custody.v1',
            'scope':'EXPLICIT_DEVELOPMENT_ONLY' if cold is None else 'MATCHING_SOURCE_COLD_BUILD',
            'cold_report':cold, 'compiler':str(cls.compiler),
            'compiler_sha256':sha256(cls.compiler_raw).hexdigest(),
            'source_before':cls.sources, 'manifests':cls.manifest_pins,
            'worker_report_manifest':str(cls.report_manifest),
            'worker_request_manifest':str(cls.request_manifest),
            'whole_native_stack_qualified':False})

    @classmethod
    def tearDownClass(cls):
        from tests.test_hia_service_verification_native import ServiceVerificationNativeTests
        ServiceVerificationNativeTests.tearDownClass.__func__(cls)

    def setUp(self):
        self.output = self.root/self._testMethodName
        self.output.mkdir(mode=0o700)

    def finish(self, profile, report, output):
        from tests.hia_service_verification_oracle import canonical
        from tests.hia_service_verification_controls import write
        from tools.read_hia_worker_unknown import read_installed
        # The original/new producer returns this exact object immediately
        # after serializing it. Require those bytes, not a later inferred pin.
        raw = canonical(report) + b'\n'
        self.assertEqual((output/'installed.json').read_bytes(), raw)
        value = {'schema':'hepta.hia.worker-unknown-installed-completion.v1',
                 'profile':profile, 'installed_report':pin(raw)}
        written = write(output/'completion-receipt.json', value)
        expected_raw = canonical(value) + b'\n'
        self.assertEqual(written, sha256(expected_raw).hexdigest())
        result = read_installed(output, pin(expected_raw), profile)
        self.assertEqual(result['status'], 'PASS')
        write(self.output/'independent-readback.json', result)

    def test_01_complete_original_v1_installed_verification_worker(self):
        from tests.hia_service_verification_installed import run
        output = self.output/'installed'
        report = run(self.manifest, self.store_manifest, output)
        self.finish('v1', report, output)

    def test_02_complete_v2_native_worker_actual_loss_cleanup_and_replacement(self):
        from tests.hia_worker_unknown_installed import run
        output = self.output/'installed'
        report = run(self.manifest, self.store_manifest, self.report_manifest,
                     self.request_manifest, output)
        self.finish('v2', report, output)


if __name__ == '__main__':
    unittest.main()
