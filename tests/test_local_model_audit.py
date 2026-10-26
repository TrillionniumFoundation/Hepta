"""Synthetic ledger consistency controls. No fixture is a model observation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.provider_adapter.local_model_common import canonical, digest, model_identity
from tools.provider_adapter.local_model_service import Service
from tools.provider_adapter.local_model_audit import audit, check_tokenizer_response
from tests.test_local_model_adapter import fake_assets


def seal(value):
    value = {k: v for k, v in value.items() if k != 'record_sha256'}
    return {**value, 'record_sha256': digest(canonical(value))}


class SyntheticEngine:
    def __init__(self, lock): self.lock = lock

    def generate(self, request):
        ids, text = {'input': [1, 2, 3], 'output': [8, 9]}, 'unit-test-only output'
        return {'status': 'completed', 'inference_started': True, 'text': text, 'token_ids': ids,
                'usage': {'input_tokens': 3, 'output_tokens': 2, 'total_tokens': 5,
                          'input_ids_sha256': digest(canonical(ids['input'])),
                          'output_ids_sha256': digest(canonical(ids['output'])),
                          'text_sha256': digest(text.encode()), 'model_lock_sha256': self.lock['lock_sha256'],
                          'elapsed_ns': 17, 'finish_reason': 'eos'}}


class LocalAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = fake_assets(self.root / 'fake-model')
        self.directory = self.root / 'ledger'
        self.service = Service([self.lock], [SyntheticEngine(self.lock)], {'unit_test_only': True}, self.directory)
        public = {'task_id': 'unit-test-task', 'language': 'rust', 'budget': {'total_tokens': 20},
                  'files': {'main.rs': 'unit-test-only source'},
                  'tools': ['read_file', 'check', 'public_test', 'replace_files']}
        self.request = {'schema': 'hepta.local_generate_request.v1', 'model': model_identity(self.lock),
                        'service_sha256': self.service.sha256,
                        'messages': [{'role': 'system', 'content': 'unit test'},
                                     {'role': 'user', 'content': canonical(public).decode()}],
                        'remaining_tokens': {'input_tokens': 20, 'output_tokens': 20, 'total_tokens': 20},
                        'wall_seconds': 5.0}
        result = self.service.generate(self.request, 'synthetic-1')
        receipt = {'request_id': 'synthetic-1', 'model': model_identity(self.lock),
                   'input_tokens': 3, 'output_tokens': 2, 'raw_usage': result['usage']}
        self.report = seal({'schema': 'hepta.crossfile_run.v1', 'run_kind': 'provider_adapter_run',
                            'model': model_identity(self.lock), 'task_id': public['task_id'],
                            'language': public['language'], 'budget': public['budget'], 'arm': 'rust_plain',
                            'base_sha256': digest(canonical({k: digest(v.encode()) for k, v in public['files'].items()})),
                            'usage': {'input_tokens': 3, 'output_tokens': 2, 'total_tokens': 5,
                                      'provider_calls': [receipt]}})

    def mutate(self, suffix, change):
        path = self.directory / ('synthetic-1.' + suffix + '.json')
        value = json.loads(path.read_text()); change(value)
        path.write_bytes(canonical(value))

    def test_exact_ids_text_and_cumulative_receipt_reconcile(self):
        result = audit(self.directory, [self.report])
        self.assertEqual(result['known_service_total_tokens'], 5)
        self.assertEqual(result['known_report_total_tokens'], 5)
        self.assertTrue(result['all_service_cost_received_by_reports'])
        self.assertFalse(result['claims']['independent_inference_attestation'])

    def test_unreceived_known_usage_remains_visible(self):
        result = audit(self.directory, [])
        self.assertEqual(result['known_service_total_tokens'], 5)
        self.assertEqual(result['known_report_total_tokens'], 0)
        self.assertEqual(result['measured_but_unreceived_request_ids'], ['synthetic-1'])
        self.assertFalse(result['all_service_cost_received_by_reports'])

    def test_missing_response_is_pending_not_zero_cost(self):
        (self.directory / 'synthetic-1.response.json').unlink()
        result = audit(self.directory, [])
        self.assertEqual(result['pending_request_ids'], ['synthetic-1'])
        self.assertFalse(result['all_service_cost_received_by_reports'])

    def test_runtime_failure_has_unknown_usage(self):
        class Broken:
            def generate(self, request): raise RuntimeError('unit-test-only failure')
        self.service.engines = [Broken()]
        self.service.generate(self.request, 'synthetic-2')
        result = audit(self.directory, [self.report])
        self.assertEqual(result['unknown_usage_request_ids'], ['synthetic-2'])
        self.assertEqual(result['known_service_total_tokens'], 5)
        self.assertFalse(result['all_service_cost_received_by_reports'])

    def test_token_id_mutation_rejects_even_if_counts_unchanged(self):
        self.mutate('response', lambda v: v['token_ids']['output'].__setitem__(0, 99))
        with self.assertRaises(ValueError): audit(self.directory, [self.report])

    def test_receipt_cannot_move_to_another_task_or_arm(self):
        for key, value in [('task_id', 'another-task'), ('arm', 'rust_semantic'), ('base_sha256', 'a' * 64)]:
            changed = copy.deepcopy(self.report); changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                audit(self.directory, [seal(changed)])

    def test_duplicate_receipt_in_two_reports_is_rejected(self):
        with self.assertRaises(ValueError): audit(self.directory, [self.report, self.report])

    def test_unfinished_request_still_requires_exact_original_identity(self):
        (self.directory / 'synthetic-1.response.json').unlink()
        self.mutate('request', lambda v: v.update(request_sha256='0' * 64))
        with self.assertRaises(ValueError): audit(self.directory, [])

    def test_completed_outcome_requires_eos_reason(self):
        self.mutate('response', lambda v: v['usage'].update(finish_reason='length'))
        with self.assertRaises(ValueError): audit(self.directory, [self.report])

    def test_rehashed_text_still_must_decode_from_original_output_ids(self):
        class UnitTokenizer:
            def apply_chat_template(self, messages, **kwargs): return 'unit-test rendered input'
            def encode(self, text, **kwargs): return [1, 2, 3]
            def decode(self, ids, **kwargs): return 'unit-test-only output'
        request = json.loads((self.directory / 'synthetic-1.request.json').read_text())
        response = json.loads((self.directory / 'synthetic-1.response.json').read_text())
        check_tokenizer_response(UnitTokenizer(), self.lock, request, response)
        response['text'] = 'different visible output'
        response['usage']['text_sha256'] = digest(response['text'].encode())
        with self.assertRaises(ValueError): check_tokenizer_response(UnitTokenizer(), self.lock, request, response)

    def test_input_prompt_tokenization_must_match_original_ids(self):
        class UnitTokenizer:
            def apply_chat_template(self, messages, **kwargs): return 'unit-test rendered input'
            def encode(self, text, **kwargs): return [1, 2, 99]
            def decode(self, ids, **kwargs): return 'unit-test-only output'
        request = json.loads((self.directory / 'synthetic-1.request.json').read_text())
        response = json.loads((self.directory / 'synthetic-1.response.json').read_text())
        with self.assertRaises(ValueError): check_tokenizer_response(UnitTokenizer(), self.lock, request, response)


if __name__ == '__main__':
    unittest.main()
