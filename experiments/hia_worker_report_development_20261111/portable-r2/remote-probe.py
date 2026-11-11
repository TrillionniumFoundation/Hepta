"""Actual CPython 3.14 portability subset, never a whole-source qualification."""
import base64
import ctypes
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import zipfile

payload = json.load(sys.stdin)
raw = base64.b64decode(payload['archive'], validate=True)
assert sha256(raw).hexdigest() == payload['sha256']
base = Path('/var/tmp/he26v65/s')
before = subprocess.check_output(['git', '-C', str(base), 'rev-parse', 'HEAD'], text=True).strip()
assert before.startswith('4161e8d'), before
root = Path('/var/tmp/he26worker')
root.mkdir(mode=0o700)
private = root / 'public-dict-r2'
private.mkdir(mode=0o700)
(private / 'transfer.zip').write_bytes(raw)
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    pins = json.loads(archive.read('PINS.json'))
    for name, expected in pins.items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts
        content = archive.read(name)
        assert sha256(content).hexdigest() == expected
        target = private / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(content)
(private / 'PINS.json').write_text(json.dumps(pins, sort_keys=True, indent=2) + '\n')
sys.dont_write_bytecode = True
sys.path.insert(0, str(base))
import hepta
hepta.__path__.insert(0, str(private / 'hepta'))
spec = importlib.util.spec_from_file_location('worker_portability_fixture', private / 'tests/test_hia_worker_report_native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
from hepta.hia_worker_report_native import SOURCE, installed_worker_report, _dict_primitives
assert SOURCE == private / 'examples/hia_bootstrap/worker_report.hiaasm', SOURCE
cls = module.WorkerReportNativeTests
cls.manifest = private / 'bundle/manifest.json'
cls.owner = installed_worker_report(cls.manifest)
cls.folder = private / 'observations'
cls.folder.mkdir()
cls.scope = 'ACTUAL_CPYTHON314_SUBSET_PORTABILITY_ONLY'
cls.setUpClass = classmethod(lambda cls: None)
cls.tearDownClass = classmethod(lambda cls: None)
names = [
    'test_ordinary_success_and_service_close_exception_order',
    'test_modes_pins_and_malformed_request_correlation',
    'test_entire_manifest_equality_and_latest_identity_adoption',
    'test_manifest_numeric_unicode_and_container_random_differential',
    'test_error_callbacks_order_mutation_and_unicode_slice',
    'test_error_callback_failure_and_output_encoding_remain_outside_catch',
    'test_foreign_leaf_effects_and_list_mutation_order',
    'test_stored_hash_foreign_key_capability_and_public_builtin_profile',
    'test_uncorrelated_empty_message_and_foreign_text_subclass_behavior',
]
suite = unittest.TestSuite(cls(name) for name in names)
loaded = [test.id() for test in suite]
started = time.monotonic()
result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
after = subprocess.check_output(['git', '-C', str(base), 'rev-parse', 'HEAD'], text=True).strip()
unchanged = before == after and all(sha256((private / name).read_bytes()).hexdigest() == expected for name, expected in pins.items())
passed = bool(loaded) and result.testsRun == len(loaded) and result.wasSuccessful() and not any((result.skipped, result.expectedFailures, result.unexpectedSuccesses)) and unchanged
record = {
    'schema': 'hia.worker-cpython314-portability-observation.v1',
    'scope': 'ACTUAL_CPYTHON314_WORKER_SUBSET_WITH_READONLY_416_FOREIGN_DEPENDENCIES_NOT_FULL_SOURCE_QUALIFICATION',
    'status': 'PASS' if passed else 'FAIL', 'source_commit_of_uploaded_subset': payload['source_commit'],
    'baseline_before': before, 'baseline_after': after, 'uploaded_source_and_image_pins': pins,
    'all_pins_unchanged': unchanged, 'tests_run': result.testsRun, 'loaded_test_ids': loaded,
    'failures': len(result.failures), 'errors': len(result.errors), 'skips': len(result.skipped),
    'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses),
    'setUpClass_bypassed_only_to_use_transferred_development_images': True,
    'cold_qualification': False, 'ordinary_entry_witness': True,
    'python': sys.version, 'executable': sys.executable,
    'executable_sha256': sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
    'private_hash_iterator_exported': _dict_primitives()[2],
    'public_iterator_exported': hasattr(ctypes.pythonapi, 'PyDict_Next'),
    'known_hash_lookup_exported': hasattr(ctypes.pythonapi, '_PyDict_GetItem_KnownHash'),
    'wall_seconds': time.monotonic() - started,
    'whole_worker_native': False, 'foreign_dictionary_keys_without_stored_hash_are_explicit_profile_refusals': True,
}
(private / 'audit.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
print(json.dumps(record, sort_keys=True))
raise SystemExit(0 if passed else 1)
