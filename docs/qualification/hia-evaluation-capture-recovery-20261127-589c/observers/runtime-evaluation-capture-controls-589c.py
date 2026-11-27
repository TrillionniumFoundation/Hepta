from __future__ import annotations
import contextlib
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
OUT = Path('/tmp/runtime-evaluation-capture-controls-v1-589c')
BUILD = Path('/tmp/runtime-evaluation-capture-native-build-589c')
OUT.mkdir(mode=0o700)
sys.path.insert(0, str(ROOT))
os.environ['HEPTA_HIA_EVALUATION_CAPTURE_DEVELOPMENT_MANIFEST'] = str(BUILD / 'evaluation/manifest.json')
os.environ['HEPTA_HIA_EVALUATION_CAPTURE_ADMISSION_DEVELOPMENT_MANIFEST'] = str(BUILD / 'admission/manifest.json')
from hepta import hia_evaluation_native as native
from hepta.hia_agent_assembly import assemble_program
from tests import test_hia_evaluation_native as originals

construction = json.loads((BUILD / 'construction-custody.json').read_bytes())
captured = {name: (ROOT / name).read_bytes() for name in construction['source_before']}
assert all({'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} == construction['source_before'][name]
           for name, raw in captured.items())
image = native.installed_evaluation(str(BUILD / 'evaluation/manifest.json'))
program = assemble_program(native.SOURCE.read_bytes())
(OUT / 'original-methods').mkdir()

class OriginalMethodsWithExplicitDevelopmentConstruction(unittest.TestCase):
    def run_original(self, name):
        # Execute the complete existing method without changing its assertions.
        # The original class's hosted-cold-only construction gate is not claimed
        # here: the official builders just performed explicit native development
        # construction, with every current component input captured and reread.
        original = originals.EvaluationNativeTests(name)
        original.root, original.image, original.program = OUT / 'original-methods', image, program
        original.setUp()
        getattr(original, name)()
        original.tearDown()

    def test_complete_111_original_foreign_effect_traces_and_first_errors(self):
        self.run_original('test_complete_111_original_foreign_effect_traces_and_first_errors')

    def test_actual_native_full_buffers_and_state_match_independent_VM(self):
        self.run_original('test_actual_native_full_buffers_and_state_match_independent_VM')

suite = unittest.TestSuite([
    unittest.defaultTestLoader.loadTestsFromName('tests.test_hia_evaluation_capture'),
    unittest.defaultTestLoader.loadTestsFromTestCase(originals.EvaluationSourceTests),
    unittest.defaultTestLoader.loadTestsFromTestCase(OriginalMethodsWithExplicitDevelopmentConstruction),
])
started = time.monotonic()
with (OUT / 'stdout').open('w') as stdout, (OUT / 'stderr').open('w') as stderr, \
        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
    result = unittest.TextTestRunner(stream=stderr, verbosity=2).run(suite)
after = {name: (ROOT / name).read_bytes() for name in captured}
receipt = {
    'schema': 'hepta.hia.evaluation-capture-controls.v1',
    'scope': 'EXPLICIT_DEVELOPMENT_COMPONENT; no current cold or installed qualification',
    'base_commit': '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375',
    'construction_receipt_sha256': sha256((BUILD / 'construction-custody.json').read_bytes()).hexdigest(),
    'tests': result.testsRun, 'errors': [(str(test), details) for test, details in result.errors],
    'failures': [(str(test), details) for test, details in result.failures], 'skips': result.skipped,
    'elapsed_seconds': time.monotonic() - started, 'python': sys.version,
    'sources_before': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for name, raw in captured.items()},
    'sources_after': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for name, raw in after.items()},
    'source_unchanged': before == after if (before := captured) else False,
    'original_frozen_fixtures_changed': False,
    'original_evaluation_protocol_changed': False,
    'original_class_hosted_cold_gate_executed': False,
    'whole_stack_rewritten_in_hia': False, 'installed_full_release_qualified': False,
}
(OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({key: receipt[key] for key in ('tests', 'errors', 'failures', 'skips', 'elapsed_seconds', 'source_unchanged')}, sort_keys=True))
sys.exit(0 if result.wasSuccessful() and before == after else 1)
