"""Independent public-default replay controls, additional to the frozen 43.

These tests execute the actual public fallback and retained original policy.
They do not select a native image or replace the actual SQLite/proof providers
in the separate full-request control.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from tests import hia_service_verification_fixtures as fixtures


@contextmanager
def default_selection():
    selectors = {name: '' for name in os.environ
                 if name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST')}
    with patch.dict(os.environ, selectors):
        yield


@contextmanager
def count_original_calls(code):
    count = [0]
    previous = sys.getprofile()
    def observe(frame, event, argument):
        if event == 'call' and frame.f_code is code:
            count[0] += 1
    try:
        sys.setprofile(observe)
        yield count
    finally:
        sys.setprofile(previous)


class ServiceVerificationDefaultReplaySourceTests(unittest.TestCase):
    def test_actual_default_forwards_all_original_controlled_replay_outcomes(self):
        # These are the retained corpus names. In particular, replay-success's
        # controlled fixture can itself reject proof scope; compare the whole
        # actual reference outcome rather than claiming success from its name.
        for case in ('replay-success', 'replay-subject', 'replay-claims', 'replay-schema'):
            with self.subTest(case=case), default_selection():
                expected = fixtures.fixture_call(case, False)
                original = fixtures.REFERENCE['_replay_verification']
                with patch.object(fixtures.Reference, '_replay_verification',
                                  api.HIAAgentService._replay_verification), \
                     patch.object(fixtures.Reference, '_replay_verification_reference', original, create=True), \
                     count_original_calls(original.__code__) as entered:
                    actual = fixtures.fixture_call(case, False)
                self.assertEqual(actual, expected)
                self.assertEqual(entered, [1])

    def test_actual_default_cached_proof_replays_the_same_sqlite_response(self):
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program
        with default_selection(), tempfile.TemporaryDirectory(prefix='hia-default-replay-') as directory:
            service = api.HIAAgentService(Path(directory) / 'state')
            try:
                self.assertIsNone(service._native_verification)
                session = Session(ToolClient(service.call), prefix='default-replay-regression')
                session.freeze({'schema': 'hepta.hia.agent.workload.v1',
                                'cases': [{'function': 'transform', 'arguments': [0]}],
                                'warmup_iterations': 0, 'repetitions': 1})
                candidate = session.import_program(add_program())
                session.verify(candidate)
                record = next(row for row in session.client.records if row['tool'] == 'hia_verify')
                request, response = record['arguments'], record['response']
                original = api.HIAAgentService._replay_verification_reference
                self.assertIsNone(original(service, response, request))
                with count_original_calls(original.__code__) as entered:
                    actual = session.client.call('hia_verify', request)
                self.assertEqual(actual, response)
                self.assertEqual(entered, [1])
                self.assertEqual(session.client.records[-1]['response'], response)
                self.assertIsNone(service._native_verification)
            finally:
                service.close()


if __name__ == '__main__':
    unittest.main()
