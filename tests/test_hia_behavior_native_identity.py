"""Current immutable inputs through the real HIA service controller.

The complete foreign-provider predecessor is a separate historical domain.
This suite requires a current image and performs real scalar VM observations.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from hepta import hia_agent_service as service
from hepta import hia_service_verification_native as native
from tests import test_hia_behavior_source_identity as current


class NativeBehaviorSourceIdentityTests(current.BehaviorSourceIdentityTests):
    @classmethod
    def setUpClass(cls):
        declared = os.environ.get('HIA_FINITE_BEHAVIOR_MANIFEST')
        if not declared:
            raise ValueError('explicit current behavior native manifest is required')
        cls.manifest = Path(declared).resolve(strict=True)
        cls.manifest_raw = cls.manifest.read_bytes()
        cls.image = native.installed_service_verification(str(cls.manifest))
        cls.entry_calls = 0
        cls.reference_entry = cls.image._entry

        def counted(*args):
            cls.entry_calls += 1
            return cls.reference_entry(*args)
        cls.image._entry = counted

    @classmethod
    def tearDownClass(cls):
        cls.image._entry = cls.reference_entry
        if cls.manifest.read_bytes() != cls.manifest_raw:
            raise AssertionError('current native manifest changed')
        if cls.entry_calls <= 0:
            raise AssertionError('no actual HIA controller entry executed')

    def routes(self):
        def selected(original, revised, timeout_ms):
            def forbidden(*args, **kwargs):
                raise AssertionError('current HIA route invoked retained proof body')
            with patch.object(service, '_SERVICE_VERIFICATION_REFERENCE_1', forbidden):
                frame = native.ServiceVerificationFrame(
                    self.image, native.BEHAVIOR,
                    {'self': self.owner, 'original': original, 'revised': revised,
                     'timeout_ms': timeout_ms})
                result = frame.finish()
                self.assertTrue(frame.finished)
                self.assertFalse(frame.native_failed)
                return result
        return (('current-native-HIA', selected),)

    def test_current_public_selected_route_binds_real_inputs(self):
        left, right, _ = self.inputs()
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
            result = self.owner._behavior_equivalence(left, right, 10000)
        self.assertEqual(result[0], 'proved', result)
        self.assertTrue(result[2]['complete'])
        self.assertEqual(result[2]['checked'], 256)
        self.assertEqual(result[2]['base_sha256'], left.sha256)
        self.assertEqual(result[2]['candidate_sha256'], right.sha256)
