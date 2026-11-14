"""Explicit empty selections refuse before the ordinary reference or effects."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import artifact_publication, hia_agent_buffers, hia_agent_store
from hepta import hia_agent_worker, hia_capability_flow, hia_json_decode
from hepta import hia_json_preflight, hia_program_tools, hia_sha256_native
from hepta.hia_agent_journal_native import JournalSession
from hepta.hia_agent_service import HIAAgentService


class EmptyNativeSelectorTests(unittest.TestCase):
    def setUp(self):
        environment = {key: value for key, value in os.environ.items()
            if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        scope = patch.dict(os.environ, environment, clear=True)
        scope.start()
        self.addCleanup(scope.stop)

    def test_preflight_refuses_before_reference(self):
        os.environ['HEPTA_HIA_JSON_PREFLIGHT_MANIFEST'] = ''
        with patch.object(hia_json_preflight, '_preflight_hia_json_reference',
                          side_effect=AssertionError('reference scanner entered')):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_json_preflight.preflight_hia_json('{}', max_nodes=10, max_depth=4)

    def test_both_decoder_entries_refuse_before_foreign_json(self):
        os.environ['HEPTA_HIA_JSON_DECODE_MANIFEST'] = ''
        with patch.object(hia_json_decode.json, 'loads',
                          side_effect=AssertionError('foreign JSON entered')):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_json_decode.decode_hia_json('null', max_nodes=10, max_depth=4)
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_json_decode.decode_internal_canonical(b'null', max_nodes=10, max_depth=4)

    def test_both_hash_selectors_refuse_before_foreign_digest(self):
        for selector in ('HEPTA_HIA_SHA256_MANIFEST', 'HEPTA_HIA_SHA256_STREAM_MANIFEST'):
            with (self.subTest(selector=selector), patch.dict(os.environ, {selector: ''}),
                  patch.object(hia_sha256_native, '_foreign_sha256',
                               side_effect=AssertionError('foreign digest entered'))):
                with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                    hia_sha256_native.payload_sha256(b'abc')

    def test_both_snapshot_entries_refuse_before_reference(self):
        os.environ['HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST'] = ''
        with (patch.object(hia_agent_buffers, '_buffer_size_reference',
                           side_effect=AssertionError('reference size entered')),
              patch.object(hia_agent_buffers, '_buffer_bytes_reference',
                           side_effect=AssertionError('reference bytes entered'))):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_agent_buffers.buffer_size({'bytes_hex': 'ab'})
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_agent_buffers.buffer_bytes({'bytes_hex': 'ab'})

    def test_capability_renaming_refuses_before_reference(self):
        os.environ['HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST'] = ''
        with patch.object(hia_capability_flow, '_reference_rename_capabilities',
                          side_effect=AssertionError('reference rename entered')):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_capability_flow.rename_capabilities({}, {})

    def test_json_wire_refuses_before_reference(self):
        os.environ['HEPTA_HIA_JSON_WIRE_MANIFEST'] = ''
        with patch.object(hia_program_tools, '_reference_bounded_json_wire',
                          side_effect=AssertionError('reference wire entered')):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_program_tools.bounded_json_wire({}, 1024)

    def test_both_identity_entries_refuse_before_reference(self):
        os.environ['HEPTA_HIA_AGENT_IDENTITY_MANIFEST'] = ''
        with (patch.object(hia_agent_store, '_reference_digest',
                           side_effect=AssertionError('reference identity entered')),
              patch.object(hia_agent_store, '_reference_uint64',
                           side_effect=AssertionError('reference u64 entered'))):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_agent_store.canonical_digest('0' * 64)
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                hia_agent_store.uint64('1', 'value')

    def test_public_worker_refuses_before_reference_or_report_output(self):
        os.environ['HEPTA_HIA_WORKER_REPORT_MANIFEST'] = ''
        output, error = io.StringIO(), io.StringIO()
        with (patch.object(hia_agent_worker, '_reference_run',
                           side_effect=AssertionError('reference worker entered')),
              redirect_stdout(output), redirect_stderr(error)):
            result = hia_agent_worker.main(['--installation-manifest'])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('selector must not be empty', error.getvalue())

    def test_all_publication_entries_refuse_before_file_observation_or_effect(self):
        os.environ['HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST'] = ''
        with (patch.object(artifact_publication, '_read_exact',
                           side_effect=AssertionError('file read entered')),
              patch.object(Path, 'lstat', side_effect=AssertionError('file identity entered')),
              patch.object(artifact_publication.os, 'link', side_effect=AssertionError('link entered'))):
            with self.assertRaisesRegex(artifact_publication.PublicationRejected, 'selector must not be empty'):
                artifact_publication.publish_verified('/unused/stage', '/unused/final', b'abc')
            with self.assertRaisesRegex(artifact_publication.PublicationRejected, 'selector must not be empty'):
                artifact_publication.verify_published('/unused/stage', '/unused/final', b'abc')
            with self.assertRaisesRegex(artifact_publication.PublicationRejected, 'selector must not be empty'):
                artifact_publication.withdraw_own_link('/unused/stage', '/unused/final')

    def test_service_journal_refuses_before_reference_request_reservation(self):
        os.environ['HEPTA_HIA_AGENT_JOURNAL_MANIFEST'] = ''
        service = object.__new__(HIAAgentService)
        with patch.object(HIAAgentService, '_reference_call',
                          side_effect=AssertionError('reference journal entered')):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                service.call('hia_resource_read', {})

    def test_cached_journal_preflight_refuses_before_native_transition(self):
        os.environ['HEPTA_HIA_JSON_PREFLIGHT_MANIFEST'] = ''
        session = object.__new__(JournalSession)
        with patch.object(JournalSession, '_run', side_effect=AssertionError('journal transition entered')):
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                session.cached(b'null')

    def test_absent_selections_preserve_original_public_results(self):
        self.assertIsNone(hia_json_preflight.preflight_hia_json('{}', max_nodes=10, max_depth=4))
        self.assertIsNone(hia_json_decode.decode_hia_json('null', max_nodes=10, max_depth=4))
        self.assertIsNone(hia_json_decode.decode_internal_canonical(b'null', max_nodes=10, max_depth=4))
        self.assertEqual(hia_sha256_native.payload_sha256(b'abc'), sha256(b'abc').digest())
        self.assertEqual(hia_agent_buffers.buffer_size({'bytes_hex': 'ab'}), 1)
        self.assertEqual(hia_agent_buffers.buffer_bytes({'bytes_hex': 'ab'}), b'\xab')
        self.assertEqual(hia_capability_flow.rename_capabilities({}, {}), {})
        self.assertEqual(hia_program_tools.bounded_json_wire({}, 1024), b'{}')
        self.assertTrue(hia_agent_store.canonical_digest('0' * 64))
        self.assertEqual(hia_agent_store.uint64('1', 'value'), 1)
        with tempfile.TemporaryDirectory() as name:
            stage, target = Path(name) / 'stage', Path(name) / 'target'
            stage.write_bytes(b'abc')
            expected = {'sha256': sha256(b'abc').hexdigest(), 'bytes': 3}
            self.assertEqual(artifact_publication.publish_verified(stage, target, b'abc'), expected)
            self.assertEqual(artifact_publication.verify_published(stage, target, b'abc'), expected)
            self.assertTrue(artifact_publication.withdraw_own_link(stage, target))
        service = object.__new__(HIAAgentService)
        with patch.object(HIAAgentService, '_reference_call', return_value='reference') as reference:
            self.assertEqual(service.call('hia_resource_read', {}), 'reference')
            reference.assert_called_once_with('hia_resource_read', {})
        with patch.object(hia_agent_worker, '_reference_run', return_value=7) as reference:
            self.assertEqual(hia_agent_worker._run(None, None), 7)
            reference.assert_called_once_with(None, None)

    def test_nonempty_selection_keeps_original_outside_profile_routes(self):
        from hepta import hia_json_decode_native, hia_json_preflight_native
        with (patch.dict(os.environ, {'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST': '/missing'}),
              patch.object(hia_json_preflight_native, 'installed_preflight',
                           side_effect=AssertionError('outside-profile native load'))):
            self.assertIsNone(hia_json_preflight.preflight_hia_json('{}', max_nodes=1048577, max_depth=4))
            with self.assertRaisesRegex(ValueError, 'isolated Unicode surrogate'):
                hia_json_preflight.preflight_hia_json('"\ud800"', max_nodes=10, max_depth=4)
        with (patch.dict(os.environ, {'HEPTA_HIA_JSON_DECODE_MANIFEST': '/missing'}),
              patch.object(hia_json_decode_native, 'installed_decoder',
                           side_effect=AssertionError('outside-profile native load'))):
            self.assertIsNone(hia_json_decode.decode_hia_json('null', max_nodes=1048577, max_depth=4))
            self.assertIsNone(hia_json_decode.decode_internal_canonical(b'null', max_nodes=1048577, max_depth=4))
        data = bytearray(b'abc')
        with (patch.dict(os.environ, {'HEPTA_HIA_SHA256_MANIFEST': '/missing',
                                     'HEPTA_HIA_SHA256_STREAM_MANIFEST': '/missing'}),
              patch.object(hia_sha256_native, 'installed_hasher',
                           side_effect=AssertionError('outside-profile native load'))):
            self.assertEqual(hia_sha256_native.payload_sha256(data), sha256(data).digest())


if __name__ == '__main__':
    unittest.main()
