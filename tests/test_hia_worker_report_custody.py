"""Current worker custody refuses incomplete report companions before mapping."""
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_native_helpers as authority
from hepta.hia_worker_bundle import NativeWorkerBundleBinding, SCHEMA


def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    path.chmod(0o600)
    return sha256(path.read_bytes()).hexdigest()


class WorkerReportCustodySourceTests(unittest.TestCase):
    def test_environment_report_selector_cannot_bypass_current_worker_scope(self):
        from hepta import hia_agent_worker as worker
        clean = {key: value for key, value in os.environ.items()
                 if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        clean['HEPTA_HIA_WORKER_REPORT_MANIFEST'] = '/unused-unpinned-report'
        errors = io.StringIO()
        with (patch.dict(os.environ, clean, clear=True), patch.object(worker.sys, 'stderr', errors),
              patch.object(worker, '_run', side_effect=AssertionError('worker entered before custody'))):
            self.assertEqual(worker.main(['--state-root', '/unused', '--request-json-stdin']), 2)
        self.assertIn('explicit pinned bundle', errors.getvalue())

    def test_v2_requires_native_request_before_adapter_or_mapping(self):
        with tempfile.TemporaryDirectory(prefix='hia-worker-v2-source-') as temporary:
            root = Path(temporary)
            base = root / 'helpers.json'
            base_pin = put(base, {'schema': authority.SCHEMA, 'target': authority.TARGET,
                                  'abi': authority.ABI, 'helpers': []})
            report = root / 'report.json'
            report_pin = put(report, {})
            top = root / 'worker.json'
            pin = put(top, {'schema': SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
                            'helpers_bundle': base.name, 'helpers_bundle_sha256': base_pin,
                            'report_bundle': report.name, 'report_bundle_sha256': report_pin})
            captured = authority._read(top, authority.MAX_BUNDLE_BYTES)
            with patch.object(authority, 'NativeHelpersBinding', side_effect=AssertionError('mapped legacy')):
                with self.assertRaisesRegex(ValueError, 'requires its pinned native request'):
                    NativeWorkerBundleBinding(captured, pin)

    def test_both_companion_sources_are_verified_before_any_mapping(self):
        from hepta import hia_worker_report_native as worker
        from hepta import hia_json_wire_native as wire
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        with tempfile.TemporaryDirectory(prefix='hia-worker-v2-source-') as temporary:
            root = Path(temporary)
            base = root / 'helpers.json'
            base_pin = put(base, {'schema': authority.SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
                'helpers': [{'selector': 'HEPTA_HIA_WORKER_REQUEST_MANIFEST',
                             'manifest_path': 'unreached-request.json', 'manifest_sha256': '0' * 64}]})
            image = root / 'unmapped.bin'
            image.write_bytes(b'not executable; no factory may be entered')
            image.chmod(0o600)
            pins = {}
            for name, source, schema in (('policy', worker.SOURCE, worker.POLICY_SCHEMA),
                                         ('wire', wire.SOURCE, wire.SCHEMA)):
                pins[name] = put(root / (name + '.json'), {'schema': schema,
                    'source_sha256': sha256(source.read_bytes()).hexdigest() if name == 'policy' else '0' * 64,
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': '1' * 64})
            report = root / 'report.json'
            report_pin = put(report, {'schema': worker.SCHEMA,
                'policy_manifest': 'policy.json', 'policy_manifest_sha256': pins['policy'],
                'wire_manifest': 'wire.json', 'wire_manifest_sha256': pins['wire']})
            top = root / 'worker.json'
            pin = put(top, {'schema': SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
                            'helpers_bundle': base.name, 'helpers_bundle_sha256': base_pin,
                            'report_bundle': report.name, 'report_bundle_sha256': report_pin})
            captured = authority._read(top, authority.MAX_BUNDLE_BYTES)
            with (patch.object(authority, 'NativeHelpersBinding', side_effect=AssertionError('mapped legacy')),
                  patch.object(NativeHiaJsonImage, '__init__', side_effect=AssertionError('mapped companion'))):
                with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    NativeWorkerBundleBinding(captured, pin)
