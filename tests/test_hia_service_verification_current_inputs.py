"""Real Core inputs through all nine current verification business methods."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest

from hepta import hia_service_verification_native as native
from tests import hia_service_verification_current_inputs as current


class CurrentServiceVerificationBusinessTests(unittest.TestCase):
    def test_all_nine_current_methods_use_actual_admitted_core_inputs(self):
        manifest = Path(os.environ['HIA_FINITE_BEHAVIOR_MANIFEST']).resolve(strict=True)
        before = manifest.read_bytes()
        image = native.installed_service_verification(str(manifest))
        original_entry, entries = image._entry, []
        def entered(*args):
            result = original_entry(*args)
            entries.append(result)
            return result
        rows = []
        image._entry = entered
        try:
            for case in current.cases():
                with self.subTest(case=case['id']):
                    reference, reference_errors = current.observe(case, current.host_factory)
                    count = len(entries)
                    observed, observed_errors = current.observe(case, current.native_factory(image))
                    self.assertGreater(len(entries), count, case['id'])
                    self.assertEqual(reference['outcome']['status'], 'returned', reference_errors)
                    self.assertEqual(observed, reference)
                    self.assertEqual(observed_errors, reference_errors)
                    if case['mode'] == 'behavior':
                        self.assertEqual(observed['outcome']['value'][0], 'proved')
                        self.assertEqual(observed['outcome']['value'][2]['checked'], 1)
                    rows.append({'case': case, 'host': reference, 'native': observed,
                                 'native_entries': len(entries) - count})
        finally:
            image._entry = original_entry
        self.assertEqual(manifest.read_bytes(), before)
        self.assertEqual(len(rows), 9)
        evidence = os.environ.get('HIA_FINITE_BEHAVIOR_CURRENT_EVIDENCE')
        if evidence:
            output = Path(evidence)
            output.mkdir(mode=0o700, parents=True, exist_ok=True)
            report = {'scope': 'CURRENT_REAL_CORE_NINE_BUSINESS_METHODS',
                'historical_185_qualified_here': False,
                'manifest_sha256': sha256(before).hexdigest(),
                'inputs': current.current_input_identities(), 'rows': rows,
                'actual_native_entries': len(entries)}
            (output / 'current-nine-methods.json').write_text(
                json.dumps(report, sort_keys=True, indent=2) + '\n')
