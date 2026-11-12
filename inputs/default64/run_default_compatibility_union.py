"""Actual Python3.11 original default callers and zero-entry native refusal."""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--inputs', type=Path, required=True)
parser.add_argument('--original-source-manifest', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
source, inputs, out = args.source.resolve(strict=True), args.inputs.resolve(strict=True), args.output.absolute()
out.mkdir(exist_ok=False)
if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 11):
    raise RuntimeError('this default-compatibility control requires actual CPython3.11')
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_'):
        del os.environ[key]
sys.path.insert(0, str(source))
from hepta import hia_program as program, hia_agent_assembly as assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_exception_delivery import ExceptionDeliveryUnavailable

def snapshot():
    return {p.relative_to(source).as_posix(): {
        'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': p.stat().st_mode & 0o777}
        for p in source.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
before = snapshot()
base = json.loads(args.original_source_manifest.read_bytes())
modules = [('tests.test_hia_program', 21), ('tests.test_hia_program_composite', 25),
           ('tests.test_hia_agent_assembly', 18)]
def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test.id()
loader = unittest.TestLoader()
suite = unittest.TestSuite()
loaded = []
original = {}
for name, count in modules:
    path = name.replace('.', '/') + '.py'
    raw = (source / path).read_bytes()
    assert sha256(raw).hexdigest() == base[path]['sha256']
    group = loader.loadTestsFromName(name)
    ids = list(flatten(group))
    assert len(ids) == count and not loader.errors
    loaded.extend(ids)
    suite.addTests(group)
    original[path] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'ordered_ids': ids}
executed = []
class Result(unittest.TextTestResult):
    def startTest(self, test):
        executed.append(test.id())
        super().startTest(test)
with (out / 'tests.log').open('w') as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
ports_before_native = sorted(name for name in sys.modules if name in (
    'hepta.hia_core_verification_ports', 'hepta.hia_assembly_front_ports'))

saved = json.loads((inputs / 'original-two-images.json').read_bytes())
observations = []
original_initialize = NativeHiaJsonImage.__init__
native_entries = []
def observed_initialize(self, *values, **keywords):
    original_initialize(self, *values, **keywords)
    entry = self._entry
    def observed_entry(*args):
        native_entries.append(True)
        return entry(*args)
    self._entry = observed_entry

from tests.test_hia_program import arithmetic
from tests.test_hia_agent_assembly import SOURCE as ASM
for stem, row in saved['images'].items():
    packed = base64.b64decode(row['zlib_base64'], validate=True)
    assert len(packed) == row['zlib_bytes'] and sha256(packed).hexdigest() == row['zlib_sha256']
    decoder = zlib.decompressobj()
    image = decoder.decompress(packed, row['bytes'] + 1)
    assert not decoder.unconsumed_tail
    image += decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert len(image) == row['bytes'] and sha256(image).hexdigest() == row['sha256']
    directory = out / stem
    directory.mkdir()
    binary = directory / 'original-development.image.bin'
    binary.write_bytes(image)
    manifest = {**row['original_manifest'], 'image_path': binary.name}
    hia = source / ('examples/hia_bootstrap/' + stem + '.hiaasm')
    assert sha256(hia.read_bytes()).hexdigest() == manifest['source_sha256']
    path = directory / 'development-manifest.json'
    path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    selector = 'HEPTA_HIA_CORE_VERIFICATION_MANIFEST' if stem == 'core_verification' else 'HEPTA_HIA_ASSEMBLY_FRONT_MANIFEST'
    call = (lambda: program.verify_program(arithmetic())) if stem == 'core_verification' else (lambda: assembly.assemble_program(ASM))
    caught = None
    try:
        with patch.dict(os.environ, {selector: str(path)}), patch.object(NativeHiaJsonImage, '__init__', observed_initialize):
            call()
    except BaseException as error:
        caught = {'type': type(error).__name__, 'message': str(error),
                  'expected_type': isinstance(error, ExceptionDeliveryUnavailable)}
    observations.append({'owner': stem, 'error': caught, 'actual_native_entries': len(native_entries),
        'actual_image_sha256': sha256(binary.read_bytes()).hexdigest()})
after = snapshot()
passed = (result.testsRun == 64 and loaded == executed and not any((result.failures, result.errors,
    result.skipped, result.expectedFailures, result.unexpectedSuccesses)) and before == after
    and not ports_before_native and not native_entries and len(observations) == 2
    and all(row['error'] is not None and row['error']['expected_type']
            and 'reviewed CPython' in row['error']['message'] for row in observations))
report = {'schema': 'hia.front.default-compatibility.actual-python311.v81.r3',
    'status': 'PASS' if passed else 'FAIL', 'python': sys.version, 'tests_run': result.testsRun,
    'loaded': loaded, 'executed': executed, 'original_sources': original,
    'failures': [(str(t), error) for t, error in result.failures],
    'errors': [(str(t), error) for t, error in result.errors], 'skipped': result.skipped,
    'expected_failures': [(str(t), error) for t, error in result.expectedFailures],
    'unexpected_successes': list(map(str, result.unexpectedSuccesses)),
    'ports_loaded_before_native_selection': ports_before_native,
    'unsupported_native_observations': observations, 'source_before': before,
    'source_after': after, 'source_unchanged': before == after,
    'native_qualification': False, 'current_cold': False, 'whole_normalization': False}
(out / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'tests_run': result.testsRun,
    'unsupported_native_cases': len(observations), 'actual_native_entries': len(native_entries)}))
raise SystemExit(0 if passed else 1)
