"""Synthetic protocol controls only. No test completion is AI evidence."""
from __future__ import annotations

import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.provider_adapter import local_model_adapter as adapter
from tools.provider_adapter import local_model_common as common
from tools.provider_adapter import local_model_service as local_service
from tools.provider_adapter.local_model_export import export_bundle
from tools.provider_adapter.local_model_service import Service, service_identity, validate_request, render_prompt
from experiments.agent_eval.harness import Budget, validate_usage
from experiments.crossfile_eval.adapter_binding import actual_config

INITIAL, UPDATED = 'a' * 64, 'b' * 64
MODEL = {'provider': 'local-transformers', 'name': 'unit-test/model', 'revision': 'c' * 64}
CONFIG = {'schema': 'hepta.local_model_adapter.v1', 'host': '127.0.0.1',
          'port': 19073, 'service_sha256': 'd' * 64, 'models': [MODEL]}


def request(arm='rust_plain'):
    language, semantic = adapter.protocol.ARMS[arm]
    suffix = '.rs' if language == 'rust' else '.hepta'
    return {'schema': 'hepta.crossfile_request.v1', 'protocol': 'hepta.crossfile_study.v2',
            'kind': 'start', 'request_id': 'unit-test-request', 'task_sha256': 'e' * 64,
            'base_sha256': INITIAL, 'model': copy.deepcopy(MODEL), 'adapter_kind': 'provider',
            'arm': arm, 'language': language, 'version': INITIAL,
            'capabilities': {'abort_frame': True}, 'task_id': 'unit-test-only',
            'files': {'main' + suffix: '// frozen', 'service' + suffix: '// editable'},
            'editable': ['service' + suffix], 'entry': 'main' + suffix,
            'instructions': 'Unit-test-only task.', 'language_reference': 'Unit-test-only syntax.',
            'public_tests': [], 'budget': {'input_tokens': 32000, 'output_tokens': 4000,
                'total_tokens': 36000, 'wall_seconds': 30.0, 'tool_calls': 12, 'protocol_bytes': 2 * 1024**2},
            'tools': list(adapter.protocol.COMMON_TOOLS) +
                     (['query_nodes', 'replace_nodes'] if semantic else ['replace_files'])}


class Clock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class Wire:
    def __init__(self, frozen):
        self.request, self.version = frozen, frozen['version']
        self.frames, self.output_bytes, self.maximum = [], 0, 2 * 1024**2

    def fits(self, value, reserve=0):
        return self.output_bytes + len(common.canonical(value)) + 1 + reserve <= self.maximum

    def send(self, value, deadline, *, reserve=0):
        if not self.fits(value, reserve): adapter.protocol.fail('E_ADAPTER_PROTOCOL_BYTES')
        self.output_bytes += len(common.canonical(value)) + 1
        self.frames.append(json.loads(common.canonical(value)))

    def read(self, deadline):
        call = self.frames[-1]
        if call['tool'] in {'replace_nodes', 'replace_files'}: self.version = UPDATED
        return {'schema': 'hepta.crossfile_tool_result.v1', 'kind': 'tool_result',
                'request_id': self.request['request_id'], 'call_id': call['call_id'],
                'version': self.version, 'result': {'ok': False if call['tool'] == 'check' else True,
                    'diagnostics': ['unit-test public compiler rejection'], 'version': self.version},
                'remaining': {'wall_seconds': 20.0,
                    'tool_calls': self.request['budget']['tool_calls'] - call['usage']['tool_calls'],
                    'total_tokens': self.request['budget']['total_tokens'] - call['usage']['total_tokens']}}


class Transport:
    def __init__(self, actions, *, mutate=None):
        self.actions, self.requests, self.mutate = list(actions), [], mutate

    def request(self, payload, deadline, pending):
        self.requests.append(copy.deepcopy(payload))
        text = self.actions.pop(0)
        if not isinstance(text, str): text = json.dumps(text)
        rid = 'unit-test-local-receipt-' + str(len(self.requests))
        pending['request_id'] = rid
        usage = {'input_tokens': 100, 'output_tokens': 20, 'total_tokens': 120,
                 'input_ids_sha256': '1' * 64, 'output_ids_sha256': '2' * 64,
                 'text_sha256': common.digest(text.encode()), 'model_lock_sha256': MODEL['revision'],
                 'service_sha256': CONFIG['service_sha256'], 'elapsed_ns': 1000,
                 'finish_reason': 'eos', 'request_sha256': common.digest(common.canonical(payload))}
        value = {'schema': 'hepta.local_generation.v1', 'service_sha256': CONFIG['service_sha256'],
                 'model': copy.deepcopy(MODEL), 'request_id': rid,
                 'request_sha256': usage['request_sha256'], 'status': 'completed',
                 'inference_started': True, 'usage': usage, 'text': text}
        if self.mutate: self.mutate(value, pending)
        return value


class LocalAdapterTests(unittest.TestCase):
    def run_case(self, actions, *, frozen=None, mutate=None):
        frozen = frozen or request()
        wire, transport = Wire(frozen), Transport(actions, mutate=mutate)
        result = adapter.run_adapter(frozen, CONFIG, wire, transport=transport, clock=Clock())
        return result, wire, transport

    def test_same_public_protocol_all_four_arms(self):
        for arm in adapter.protocol.ARMS:
            with self.subTest(arm=arm):
                frozen = request(arm)
                result, wire, transport = self.run_case([
                    {'tool': 'check', 'arguments': {}}, {'version': INITIAL}], frozen=frozen)
                self.assertEqual(result, 0)
                self.assertEqual([f['kind'] for f in wire.frames], ['tool_call', 'final'])
                self.assertIn('unit-test public compiler rejection', transport.requests[1]['messages'][-1]['content'])
                self.assertEqual(transport.requests[1]['messages'][-1]['role'], 'user')
                counts = wire.frames[-1]['usage']
                self.assertEqual((counts['input_tokens'], counts['output_tokens'], counts['tool_calls']), (200, 40, 1))
                validate_usage(counts, MODEL, Budget(**frozen['budget']), 1, 'provider')

    def test_edits_require_model_supplied_exact_current_version(self):
        frozen = request()
        result, wire, _ = self.run_case([
            {'tool': 'replace_files', 'arguments': {'expected_version': INITIAL, 'files': {'service.rs': '// new'}}},
            {'version': UPDATED}], frozen=frozen)
        self.assertEqual(result, 0)
        self.assertEqual(wire.frames[-1]['version'], UPDATED)
        result, wire, _ = self.run_case([
            {'tool': 'replace_files', 'arguments': {'expected_version': INITIAL, 'files': {'service.rs': '// new'}}},
            {'version': INITIAL}], frozen=frozen)
        self.assertEqual(result, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_LOCAL_ACTION')

    def test_malformed_model_text_preserves_known_cost(self):
        result, wire, _ = self.run_case(['```json\n{}\n```'])
        self.assertEqual(result, 2)
        self.assertTrue(wire.frames[-1]['usage_complete'])
        self.assertEqual(wire.frames[-1]['usage']['total_tokens'], 120)

    def test_unknown_or_unavailable_tool_never_executes(self):
        for tool in ('shell', 'read_hidden_oracle', 'replace_nodes'):
            with self.subTest(tool=tool):
                result, wire, _ = self.run_case([{'tool': tool, 'arguments': {}}])
                self.assertEqual(result, 2)
                self.assertEqual(len(wire.frames), 1)
                self.assertEqual(wire.frames[0]['kind'], 'abort')

    def test_no_abort_capability_rejected_before_inference(self):
        frozen = request(); frozen['capabilities']['abort_frame'] = False
        result, wire, transport = self.run_case([], frozen=frozen)
        self.assertEqual(result, 2)
        self.assertFalse(transport.requests)
        self.assertFalse(wire.frames)

    def test_incomplete_generation_retains_token_receipt(self):
        def mutate(v, _): v.update(status='incomplete'); v['usage']['finish_reason'] = 'length'
        result, wire, _ = self.run_case(['{}'], mutate=mutate)
        self.assertEqual(result, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_LOCAL_GENERATION')
        self.assertTrue(wire.frames[-1]['usage_complete'])

    def test_over_budget_receipt_is_retained_before_rejection(self):
        frozen = request(); frozen['budget']['input_tokens'] = 99
        result, wire, _ = self.run_case([{'version': INITIAL}], frozen=frozen)
        self.assertEqual(result, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_TOKEN_BUDGET')
        self.assertEqual(wire.frames[-1]['usage']['input_tokens'], 100)
        self.assertTrue(wire.frames[-1]['usage_complete'])

    def test_forged_receipts_are_unverified_not_zero_cost(self):
        mutations = [
            lambda v, p: v.update(service_sha256='0' * 64),
            lambda v, p: v['model'].update(revision='0' * 64),
            lambda v, p: v.update(request_sha256='0' * 64),
            lambda v, p: v['usage'].update(text_sha256='0' * 64),
            lambda v, p: v['usage'].update(total_tokens=121),
            lambda v, p: v['usage'].update(input_tokens=True),
            lambda v, p: v['usage'].update(model_lock_sha256='0' * 64),
            lambda v, p: v['usage'].update(service_sha256='0' * 64),
            lambda v, p: v['usage'].update(request_sha256='0' * 64),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                result, wire, _ = self.run_case([{'version': INITIAL}], mutate=mutate)
                self.assertEqual(result, 2)
                self.assertIsNone(wire.frames[-1]['usage'])
                self.assertFalse(wire.frames[-1]['usage_complete'])
                self.assertIn('pending_provider_request', wire.frames[-1])

    def test_duplicate_receipt_cannot_be_reused(self):
        def mutate(v, pending):
            v['request_id'] = pending['request_id'] = 'unit-test-local-receipt-1'
        result, wire, _ = self.run_case([{'tool': 'check', 'arguments': {}}, {'version': INITIAL}], mutate=mutate)
        self.assertEqual(result, 2)
        self.assertEqual(len(wire.frames[-1]['usage']['provider_calls']), 1)
        self.assertFalse(wire.frames[-1]['usage_complete'])

    def test_pre_inference_refusal_does_not_forge_receipt(self):
        def mutate(v, _): v.update(status='rejected_pre_inference', inference_started=False, usage=None)
        result, wire, _ = self.run_case([{}], mutate=mutate)
        self.assertEqual(result, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_LOCAL_ADMISSION')
        self.assertIsNone(wire.frames[-1]['usage'])
        self.assertNotIn('pending_provider_request', wire.frames[-1])

    def test_network_endpoint_cannot_leave_ipv4_loopback(self):
        for host in ('localhost', '0.0.0.0', '::1', 'example.com', '127.0.0.1.evil'):
            config = copy.deepcopy(CONFIG); config['host'] = host
            with self.subTest(host=host), self.assertRaises(ValueError):
                common.validate_config(config)


def fake_assets(path, marker=b'unit-test-only-not-real-weights'):
    path.mkdir()
    for name in ('config.json', 'tokenizer_config.json', 'tokenizer.json'):
        (path / name).write_text('{}')
    (path / 'model.safetensors').write_bytes(marker)
    return common.freeze_model(path, 'unit-test/model', '1' * 40)


class LocalLockTests(unittest.TestCase):
    def test_base_prompt_format_is_explicit_and_preserves_every_message(self):
        messages = [{'role': 'system', 'content': 'rules'}, {'role': 'user', 'content': 'complete source\n'}]
        self.assertEqual(render_prompt(None, messages, 'chatml_v1'),
                         '<|im_start|>system\nrules<|im_end|>\n<|im_start|>user\ncomplete source\n'
                         '<|im_end|>\n<|im_start|>assistant\n')
        with self.assertRaises(ValueError): render_prompt(None, messages, 'silent-fallback')

    def test_prompt_format_is_frozen_in_the_model_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'model'; original = fake_assets(root)
            changed = common.freeze_model(root, 'unit-test/model', '1' * 40, prompt_format='chatml_v1')
            self.assertNotEqual(original['lock_sha256'], changed['lock_sha256'])
            changed['generation']['prompt_format'] = 'unknown'
            with self.assertRaises(ValueError): common.validate_lock(changed)

    def test_exact_files_and_generation_form_model_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'model'; lock = fake_assets(root)
            self.assertTrue(common.verify_assets(lock, root))
            self.assertEqual(common.model_identity(lock)['revision'], lock['lock_sha256'])
            (root / 'tokenizer.json').write_text('{"changed":true}')
            with self.assertRaises(ValueError): common.verify_assets(lock, root)

    def test_unlisted_model_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'model'; lock = fake_assets(root)
            (root / 'generation_config.json').write_text('{}')
            with self.assertRaises(ValueError): common.verify_assets(lock, root)

    def test_model_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'model'; lock = fake_assets(root)
            target = root / 'tokenizer.json'; original = target.read_bytes(); target.unlink()
            outside = Path(td) / 'outside'; outside.write_bytes(original); target.symlink_to(outside)
            with self.assertRaises(ValueError): common.verify_assets(lock, root)

    def test_executable_or_pickle_model_inputs_rejected(self):
        for filename in ('modeling_custom.py', 'pytorch_model.bin'):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td) / 'model'; fake_assets(root)
                (root / filename).write_bytes(b'not admitted')
                with self.assertRaises(ValueError): common.freeze_model(root, 'unit-test/model', '1' * 40)

    def test_moving_upstream_revision_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'model'; fake_assets(root)
            for revision in ('main', 'latest', 'stable'):
                with self.assertRaises(ValueError): common.freeze_model(root, 'unit-test/model', revision)

    def test_rehashed_escaping_asset_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            lock = fake_assets(Path(td) / 'model')
            lock['files'][0]['path'] = '../config.json'
            lock['lock_sha256'] = common.digest(common.canonical({k: v for k, v in lock.items() if k != 'lock_sha256'}))
            with self.assertRaises(ValueError): common.validate_lock(lock)

    def test_changed_generation_without_reseal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            lock = fake_assets(Path(td) / 'model'); lock['generation']['threads'] = 3
            with self.assertRaises(ValueError): common.validate_lock(lock)

    def test_export_matches_existing_evaluator_identity_and_contains_no_oracles(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); lock = fake_assets(root / 'model')
            service = {'schema': 'hepta.local_service.v1', 'locks': [lock],
                       'models': [common.model_identity(lock)], 'runtime': {'unit_test_only': True}}
            service['service_sha256'] = service_identity([lock], service['runtime'])
            result = export_bundle(service, root / 'bundle', root / 'configs.json', port=19073)
            configs = json.loads((root / 'configs.json').read_text())
            actual, _ = actual_config(root / 'bundle', result['command'], (), True)
            self.assertEqual(actual, {k: v for k, v in configs[0].items() if k != 'model'})
            self.assertEqual(result['actual_ai_model_runs'], 0)
            self.assertFalse(result['complete_study_model_requirement_met'])
            self.assertEqual(set(p.name for p in (root / 'bundle').iterdir()),
                             {'local_model_adapter.py', 'local_model_common.py', 'openai_chat.py',
                              'local-config.json', 'command.json', 'manifest.json'})
            self.assertFalse(any('oracle' in p.name or p.suffix == '.safetensors' for p in (root / 'bundle').iterdir()))

    def test_changed_settings_do_not_count_as_second_model(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); one = fake_assets(root / 'model')
            two = copy.deepcopy(one); two['generation']['max_new_tokens'] = 512
            two['lock_sha256'] = common.digest(common.canonical({k: v for k, v in two.items() if k != 'lock_sha256'}))
            locks = [one, two]
            service = {'schema': 'hepta.local_service.v1', 'locks': locks,
                       'models': [common.model_identity(v) for v in locks], 'runtime': {'unit_test_only': True}}
            service['service_sha256'] = service_identity(locks, service['runtime'])
            with self.assertRaises(ValueError):
                export_bundle(service, root / 'bundle', root / 'configs.json', port=19073)


class LocalServiceTests(unittest.TestCase):
    def test_service_failure_preserves_unknown_inference_cost(self):
        class Broken:
            def generate(self, request): raise RuntimeError('unit-test-only failure')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); lock = fake_assets(root / 'model')
            service = Service([lock], [Broken()], {'unit_test_only': True}, root / 'evidence')
            value = {'schema': 'hepta.local_generate_request.v1', 'model': service.models[0],
                     'service_sha256': service.sha256, 'messages': [{'role': 'user', 'content': 'unit-test-only'}],
                     'remaining_tokens': {'input_tokens': 100, 'output_tokens': 20, 'total_tokens': 120},
                     'wall_seconds': 10}
            response = service.generate(value, 'unit-test-inference')
            self.assertEqual(response['status'], 'inference_failed')
            self.assertIsNone(response['usage'])
            self.assertTrue((root / 'evidence/unit-test-inference.request.json').exists())
            self.assertTrue((root / 'evidence/unit-test-inference.response.json').exists())

    def test_service_request_boundary_rejects_unbounded_or_wrong_identity(self):
        value = {'schema': 'hepta.local_generate_request.v1', 'model': MODEL,
                 'service_sha256': CONFIG['service_sha256'], 'messages': [{'role': 'user', 'content': 'unit-test'}],
                 'remaining_tokens': {'input_tokens': 100, 'output_tokens': 20, 'total_tokens': 120}, 'wall_seconds': 10}
        validate_request(value, CONFIG['service_sha256'], [MODEL])
        for field, replacement in [('wall_seconds', float('inf')), ('model', {}), ('messages', []),
                                   ('remaining_tokens', {'input_tokens': True, 'output_tokens': 2, 'total_tokens': 3})]:
            mutated = copy.deepcopy(value); mutated[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_request(mutated, CONFIG['service_sha256'], [MODEL])


class UnitGenerationConfig:
    """API-shaped control, with no runtime/model weights or claimed generation."""
    def __init__(self, **changes):
        self.__dict__.update(num_beams=1, num_beam_groups=1, num_return_sequences=1,
                             return_dict_in_generate=False, token_healing=False,
                             stop_strings=None, max_time=None, do_sample=False, mode_override=None)
        self.__dict__.update(changes)

    def get_generation_mode(self):
        return SimpleNamespace(value=self.mode_override or ('sample' if self.do_sample else 'greedy_search'))


class LocalPolicyTests(unittest.TestCase):
    def test_uniform_thread_policy_allows_equal_counts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            locks = [fake_assets(root / 'first'), fake_assets(root / 'second', b'other-unit-test-only')]
            self.assertEqual(common.validate_service_locks(locks), locks)

    def test_mixed_threads_reject_before_runtime_or_engine_startup_in_both_orders(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                locks = [fake_assets(root / 'first'), fake_assets(root / 'second')]
                locks[1]['generation']['threads'] = 3
                locks[1]['lock_sha256'] = common.digest(common.canonical(
                    {k: v for k, v in locks[1].items() if k != 'lock_sha256'}))
                if reverse: locks.reverse()
                arguments = ['serve', '--port', '19073', '--evidence-dir', str(root / 'evidence')]
                for index, lock in enumerate(locks):
                    path = root / ('lock-' + str(index) + '.json'); path.write_bytes(common.canonical(lock))
                    arguments += ['--lock', str(path), '--model-dir', str(root / ('first' if index == 0 else 'second'))]
                with patch.object(local_service, 'TransformersEngine') as engine, patch.object(local_service, 'runtime_identity') as runtime:
                    with self.assertRaisesRegex(ValueError, 'E_LOCAL_THREADS'):
                        local_service.main(arguments)
                    engine.assert_not_called(); runtime.assert_not_called()
                self.assertFalse((root / 'evidence').exists())

    def sharded_service(self, root, contents):
        locks = []
        for index, shards in enumerate(contents):
            directory = root / ('model-' + str(index)); fake_assets(directory)
            (directory / 'model.safetensors').unlink()
            for number, data in enumerate(shards):
                (directory / ('part-' + str(number) + '.safetensors')).write_bytes(data)
            locks.append(common.freeze_model(directory, 'unit-test/model-' + str(index), str(index + 1) * 40))
        service = {'schema': 'hepta.local_service.v1', 'locks': locks,
                   'models': [common.model_identity(v) for v in locks], 'runtime': {'unit_test_only': True}}
        service['service_sha256'] = service_identity(locks, service['runtime'])
        return service

    def test_renamed_same_weight_shards_are_not_a_second_model(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); service = self.sharded_service(root, [(b'unit-a', b'unit-b'), (b'unit-b', b'unit-a')])
            with self.assertRaisesRegex(ValueError, 'identical weights'):
                export_bundle(service, root / 'bundle', root / 'configs.json', port=19073)
            self.assertFalse((root / 'bundle').exists())

    def test_distinct_weight_shards_still_export(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); service = self.sharded_service(root, [(b'unit-a', b'unit-b'), (b'unit-a', b'unit-c')])
            result = export_bundle(service, root / 'bundle', root / 'configs.json', port=19073)
            self.assertTrue(result['complete_study_model_requirement_met'])
            self.assertEqual(result['actual_ai_model_runs'], 0)

    def test_sampling_override_is_effectively_greedy_without_mutating_saved_config(self):
        saved = UnitGenerationConfig(do_sample=True)
        effective = local_service.validate_greedy_generation(saved)
        self.assertFalse(effective.do_sample)
        self.assertTrue(saved.do_sample)

    def test_generate_receives_validated_config_and_disables_model_default_rebuild(self):
        class Tensor:
            ndim = 2
            def __init__(self, rows): self.rows, self.shape = rows, (len(rows), len(rows[0]))
            def __getitem__(self, index): return SimpleNamespace(tolist=lambda: self.rows[index])
            def tolist(self): return self.rows

        class Model:
            def __init__(self): self.generation_config = UnitGenerationConfig(eos_token_id=0)
            def generate(self, **kwargs):
                self.kwargs = kwargs
                # Regression control for Transformers' legacy config.json
                # reconstruction/default merge when no explicit config is used.
                if 'generation_config' not in kwargs or kwargs.get('use_model_defaults') is not False:
                    return Tensor([[1, 2, 3, 7, 99], [1, 2, 3, 8, 99]])
                if kwargs['generation_config'].num_beams != 1:
                    raise AssertionError('unit control: unvalidated strategy reached generation')
                return Tensor([[1, 2, 3, 7, 0]])

        class Tokenizer:
            pad_token_id = eos_token_id = 0
            def __call__(self, rendered, **kwargs): return {'input_ids': Tensor([[1, 2, 3]])}
            def decode(self, ids, **kwargs): return 'unit-test-only completion'

        engine = local_service.TransformersEngine.__new__(local_service.TransformersEngine)
        engine.model = Model(); engine.tokenizer = Tokenizer(); engine.context_limit = 32
        engine.effective_generation = local_service.validate_greedy_generation(engine.model.generation_config)
        engine.model.generation_config.num_beams = 2
        engine.model.generation_config.eos_token_id = 99
        engine.lock = {'lock_sha256': 'a' * 64,
                       'generation': {'prompt_format': 'chatml_v1', 'max_input_tokens': 20, 'max_new_tokens': 10}}
        fake_torch = SimpleNamespace(is_tensor=lambda value: isinstance(value, Tensor), inference_mode=nullcontext)
        fake_transformers = SimpleNamespace(StoppingCriteria=type('StoppingCriteria', (), {}), StoppingCriteriaList=list)
        payload = {'messages': [{'role': 'user', 'content': 'unit-test-only input'}],
                   'remaining_tokens': {'input_tokens': 20, 'output_tokens': 10, 'total_tokens': 30}, 'wall_seconds': 10.0}
        with patch.dict('sys.modules', {'torch': fake_torch, 'transformers': fake_transformers}):
            result = engine.generate(payload)
        self.assertIs(engine.model.kwargs['generation_config'], engine.effective_generation)
        self.assertFalse(engine.model.kwargs['use_model_defaults'])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['usage']['output_tokens'], 2)
        self.assertEqual(result['usage']['finish_reason'], 'eos')

    def test_beams_multiple_sequences_dictionary_and_custom_stopping_reject(self):
        changes = [{'num_beams': 2}, {'num_beam_groups': 2}, {'num_return_sequences': 2},
                   {'num_beams': True}, {'return_dict_in_generate': True}, {'token_healing': True},
                   {'stop_strings': ['END']}, {'max_time': 1.0}]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'E_LOCAL_GENERATION_CONFIG'):
                local_service.validate_greedy_generation(UnitGenerationConfig(**change))

    def test_contrastive_constrained_and_other_effective_strategies_reject(self):
        for mode in ('contrastive_search', 'constrained_beam_search', 'beam_search', 'sample', 'assisted_generation'):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'not greedy'):
                local_service.validate_greedy_generation(UnitGenerationConfig(mode_override=mode))

    def test_encoder_decoder_configuration_rejects_before_suffix_accounting(self):
        local_service.require_decoder_only(SimpleNamespace(is_encoder_decoder=False))
        for value in (True, 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'decoder-only'):
                local_service.require_decoder_only(SimpleNamespace(is_encoder_decoder=value))

    def test_suffix_counts_exact_generated_tokens_including_eos(self):
        self.assertEqual(local_service.generated_suffix([1, 2, 3], [[1, 2, 3, 9, 0]]), [9, 0])

    def test_changed_prefix_missing_prefix_multi_sequence_and_invalid_ids_reject(self):
        invalid = [[[1, 2, 99, 4]], [[1, 2]], [[1, 2, 3, 4], [1, 2, 3, 5]],
                   {'sequences': [[1, 2, 3, 4]]}, [[1, 2, 3, True]], [[1, 2, 3, -1]], [[1, 2, 3, 1.5]]]
        for sequences in invalid:
            with self.subTest(sequences=sequences), self.assertRaisesRegex(ValueError, 'E_LOCAL_OUTPUT_SHAPE'):
                local_service.generated_suffix([1, 2, 3], sequences)


if __name__ == '__main__':
    unittest.main()
