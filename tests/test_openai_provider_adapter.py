"""Offline HTTP protocol tests only; synthetic receipts are never AI evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.provider_adapter import openai_chat as adapter
from tools.provider_adapter.export import bundle_digest, export_bundle


MODELS = [{'provider': 'openai', 'name': 'unit-test-only-' + name,
           'revision': 'unit-test-only-' + name + '-2000-01-01'} for name in ('alpha', 'beta')]
KEY = 'sk-offline-unit-test-only-sentinel'
INITIAL, UPDATED = 'a' * 64, 'b' * 64


def request(arm='rust_semantic'):
    language, semantic = adapter.ARMS[arm]
    suffix = '.rs' if language == 'rust' else '.hepta'
    return {'schema': 'hepta.crossfile_request.v1', 'protocol': 'hepta.crossfile_study.v2',
            'kind': 'start', 'request_id': 'unit-test-request', 'task_sha256': 'c' * 64,
            'base_sha256': INITIAL, 'model': copy.deepcopy(MODELS[0]), 'adapter_kind': 'provider',
            'arm': arm, 'language': language, 'version': INITIAL,
            'capabilities': {'abort_frame': True}, 'task_id': 'unit-test-task',
            'files': {'main' + suffix: '// frozen', 'service' + suffix: '// editable'},
            'editable': ['service' + suffix], 'entry': 'main' + suffix,
            'instructions': 'Unit-test-only task.', 'language_reference': 'Unit-test-only syntax.',
            'public_tests': [{'test': 'unit-test-only-public'}],
            'budget': {'input_tokens': 32000, 'output_tokens': 4000, 'total_tokens': 36000,
                       'wall_seconds': 30.0, 'tool_calls': 12, 'protocol_bytes': 2 * 1024**2},
            'tools': list(adapter.COMMON_TOOLS) + (['query_nodes', 'replace_nodes'] if semantic else ['replace_files'])}


def tool(name, number, arguments=None):
    return {'id': 'unit-test-call-' + str(number), 'type': 'function',
            'function': {'name': name, 'arguments': json.dumps(arguments or {})}}


def completion(*, calls=None, version=INITIAL, prompt=120, output=40, model=None, finish=None):
    message = {'role': 'assistant', 'content': None if calls else json.dumps({'version': version}), 'refusal': None}
    if calls is not None: message['tool_calls'] = calls
    return {'id': 'unit-test-only-completion', 'object': 'chat.completion',
            'model': model or MODELS[0]['revision'],
            'choices': [{'index': 0, 'finish_reason': finish or ('tool_calls' if calls else 'stop'), 'message': message}],
            'usage': {'prompt_tokens': prompt, 'completion_tokens': output, 'total_tokens': prompt + output,
                      'prompt_tokens_details': {'cached_tokens': 20},
                      'completion_tokens_details': {'reasoning_tokens': 10}}}


def http_response(body=None, request_id='unit-test-only-provider-1', status=200, **extra):
    return {'body': completion() if body is None else body, 'request_id': request_id, 'status': status, **extra}


class Clock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class FakeWire:
    def __init__(self, frozen, *, feedback=None):
        self.request = frozen
        self.frames, self.output_bytes, self.maximum = [], 0, 2 * 1024**2
        self.version, self.feedback = frozen['version'], feedback

    def fits(self, value, reserve=0):
        return self.output_bytes + len(adapter.canonical(value)) + 1 + reserve <= self.maximum

    def send(self, value, deadline, *, reserve=0):
        if not self.fits(value, reserve): adapter.fail('E_ADAPTER_PROTOCOL_BYTES')
        self.output_bytes += len(adapter.canonical(value)) + 1
        self.frames.append(json.loads(adapter.canonical(value)))

    def read(self, deadline):
        frame = self.frames[-1]
        if frame['tool'] in {'replace_nodes', 'replace_files'}: self.version = UPDATED
        value = {'schema': 'hepta.crossfile_tool_result.v1', 'kind': 'tool_result',
                 'request_id': self.request['request_id'], 'call_id': frame['call_id'],
                 'version': self.version,
                 'result': {'ok': frame['tool'] != 'check', 'version': self.version,
                            'feedback': 'unit-test feedback for ' + frame['tool'],
                            'diagnostics': ['unit-test public compiler detail']},
                 'remaining': {'wall_seconds': 20.0,
                               'tool_calls': self.request['budget']['tool_calls'] - frame['usage']['tool_calls'],
                               'total_tokens': self.request['budget']['total_tokens'] - frame['usage']['total_tokens']}}
        return self.feedback(value) if self.feedback else value


class FakeSocket:
    def __init__(self): self.timeouts = []
    def settimeout(self, value): self.timeouts.append(value)


class FakeResponse:
    def __init__(self, spec):
        self.status, self.request_id = spec['status'], spec['request_id']
        self.data = spec['body'] if isinstance(spec['body'], bytes) else adapter.canonical(spec['body'])
        self.length = len(self.data)
        self.read_error, self.reads = spec.get('read_error'), 0
        self.closed = False

    def getheader(self, name):
        return self.request_id if name.lower() == 'x-request-id' else None

    def read(self, amount):
        self.reads += 1
        if self.read_error is not None: raise self.read_error
        data, self.data = self.data[:amount], self.data[amount:]
        self.length -= len(data)
        if not self.length: self.closed = True
        return data

    def close(self): self.closed = True
    def isclosed(self): return self.closed


class FakeHTTPS:
    def __init__(self, script):
        self.script, self.requests, self.connections = list(script), [], []

    def __call__(self, host, port, timeout, context):
        owner = self
        class Connection:
            def __init__(self):
                self.sock, self.closed = FakeSocket(), False
                self.host, self.port, self.timeout, self.context = host, port, timeout, context
                owner.connections.append(self)
            def connect(self): pass
            def request(self, method, path, body, headers):
                owner.requests.append({'method': method, 'path': path, 'body': json.loads(body), 'headers': headers})
            def getresponse(self):
                if not owner.script: raise AssertionError('Unexpected extra HTTP request or retry')
                spec = owner.script.pop(0)
                if isinstance(spec, Exception): raise spec
                self.response = FakeResponse(spec)
                if spec.get('connection_close'): self.sock = None
                return self.response
            def close(self): self.closed = True
        return Connection()


class ProviderAdapterTests(unittest.TestCase):
    def setUp(self):
        # Even a test bug must not turn this suite into a real network request.
        self.no_network = patch('socket.create_connection', side_effect=AssertionError('Offline tests forbid sockets'))
        self.no_network.start()
        self.addCleanup(self.no_network.stop)

    def run_offline(self, script, *, frozen=None, feedback=None, environment=None):
        frozen = frozen or request()
        wire, network, clock = FakeWire(frozen, feedback=feedback), FakeHTTPS(script), Clock()
        with patch.object(adapter.http.client, 'HTTPSConnection', network):
            status = adapter.run_adapter(frozen, MODELS, wire, environment={'OPENAI_API_KEY': KEY} if environment is None else environment,
                                         clock=clock)
        self.assertTrue(all(c.closed for c in network.connections))
        self.assertNotIn(KEY, json.dumps(wire.frames))
        return status, wire, network

    def test_fixed_https_origin_exact_revision_and_real_usage_shape(self):
        status, wire, network = self.run_offline([http_response()])
        self.assertEqual(status, 0)
        sent, connection = network.requests[0], network.connections[0]
        self.assertEqual((connection.host, connection.port, sent['method'], sent['path']),
                         ('api.openai.com', 443, 'POST', '/v1/chat/completions'))
        self.assertTrue(connection.context.check_hostname)
        self.assertEqual(connection.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(sent['headers']['Authorization'], 'Bearer ' + KEY)
        self.assertEqual(sent['body']['model'], MODELS[0]['revision'])
        self.assertEqual((sent['body']['stream'], sent['body']['store'], sent['body']['n']), (False, False, 1))
        self.assertEqual(sent['body']['max_completion_tokens'], request()['budget']['output_tokens'])
        receipt = wire.frames[-1]['usage']['provider_calls'][0]
        self.assertEqual(receipt['request_id'], 'unit-test-only-provider-1')
        self.assertNotEqual(receipt['request_id'], sent['headers']['X-Client-Request-Id'])
        self.assertEqual(receipt['raw_usage'], completion()['usage'])
        self.assertEqual(wire.frames[-1]['usage']['total_tokens'], 160)

    def test_all_four_arms_and_every_tool_feedback_reaches_next_completion(self):
        for arm in adapter.ARMS:
            with self.subTest(arm=arm):
                frozen = request(arm)
                calls = [tool(name, index, {'path': frozen['entry']} if name == 'read_file' else {})
                         for index, name in enumerate(frozen['tools'])]
                status, wire, network = self.run_offline([
                    http_response(completion(calls=calls)),
                    http_response(completion(version=UPDATED), request_id='unit-test-only-provider-2')], frozen=frozen)
                self.assertEqual(status, 0)
                self.assertEqual([f['tool'] for f in wire.frames[:-1]], frozen['tools'])
                schemas = network.requests[0]['body']['tools']
                self.assertEqual([s['function']['name'] for s in schemas], frozen['tools'])
                self.assertTrue(all(s['function']['strict'] is False for s in schemas))
                feedback = [m for m in network.requests[1]['body']['messages'] if m['role'] == 'tool']
                self.assertEqual(len(feedback), len(calls))
                for call, row in zip(calls, feedback):
                    self.assertEqual(row['tool_call_id'], call['id'])
                    self.assertIn('unit-test feedback for ' + call['function']['name'], row['content'])
                    self.assertIn('unit-test public compiler detail', row['content'])
                self.assertEqual(wire.frames[-1]['version'], UPDATED)
                self.assertEqual(wire.frames[-1]['usage']['tool_calls'], len(calls))
                self.assertEqual(len(wire.frames[-1]['usage']['provider_calls']), 2)

    def test_frames_validate_against_actual_harness_usage_contract(self):
        from experiments.agent_eval.harness import Budget, validate_usage
        calls = [tool('read_file', 1, {'path': 'main.rs'}), tool('check', 2)]
        status, wire, _ = self.run_offline([http_response(completion(calls=calls)),
                                          http_response(request_id='unit-test-only-provider-2')])
        self.assertEqual(status, 0)
        previous, observed = None, 0
        for frame in wire.frames:
            observed += frame['kind'] == 'tool_call'
            previous = validate_usage(frame['usage'], MODELS[0], Budget(**request()['budget']), observed, 'provider', previous)
            for name in adapter.IDENTITIES: self.assertEqual(frame[name], request()[name])

    def test_multi_call_receipt_once_tool_calls_individually(self):
        calls = [tool('check', i) for i in range(3)]
        _, wire, _ = self.run_offline([http_response(completion(calls=calls)),
                                      http_response(request_id='unit-test-only-provider-2')])
        self.assertEqual([f['usage']['tool_calls'] for f in wire.frames], [1, 2, 3, 3])
        self.assertEqual([len(f['usage']['provider_calls']) for f in wire.frames], [1, 1, 1, 2])
        self.assertEqual([f['usage']['total_tokens'] for f in wire.frames], [160, 160, 160, 320])

    def test_duplicate_tool_ids_within_completion_reject_before_forwarding(self):
        status, wire, _ = self.run_offline([http_response(completion(calls=[tool('check', 1), tool('check', 1)]))])
        self.assertEqual(status, 2)
        self.assertEqual([f['kind'] for f in wire.frames], ['abort'])
        self.assertEqual(wire.frames[0]['error']['code'], 'E_ADAPTER_TOOL_CALL')
        self.assertEqual(wire.frames[0]['usage']['tool_calls'], 0)
        self.assertEqual(wire.frames[0]['usage']['total_tokens'], 160)

    def test_duplicate_tool_ids_across_completions_keep_second_paid_receipt(self):
        first = completion(calls=[tool('check', 1)])
        status, wire, _ = self.run_offline([http_response(first), http_response(first, request_id='unit-test-only-provider-2')])
        self.assertEqual(status, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_TOOL_CALL')
        self.assertEqual(wire.frames[-1]['usage']['tool_calls'], 1)
        self.assertEqual(wire.frames[-1]['usage']['total_tokens'], 320)

    def test_duplicate_provider_request_id_cannot_manufacture_extra_receipt(self):
        status, wire, _ = self.run_offline([http_response(completion(calls=[tool('check', 1)])), http_response()])
        self.assertEqual(status, 2)
        failure = wire.frames[-1]
        self.assertEqual(failure['error']['code'], 'E_OPENAI_REQUEST_ID')
        self.assertEqual(len(failure['usage']['provider_calls']), 1)
        self.assertFalse(failure['pending_provider_request']['receipt_verified'])

    def test_first_http_failure_is_unknown_cost_not_fabricated_zero_receipt(self):
        status, wire, network = self.run_offline([http_response({'error': KEY}, status=429)])
        self.assertEqual((status, len(network.requests)), (2, 1))
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_OPENAI_HTTP')
        self.assertIsNone(wire.frames[-1]['usage'])
        self.assertFalse(wire.frames[-1]['usage_complete'])
        self.assertEqual(wire.frames[-1]['pending_provider_request']['request_id'], 'unit-test-only-provider-1')
        self.assertEqual(network.connections[0].response.reads, 0)

    def test_later_timeout_preserves_completed_receipt_prefix_without_retry(self):
        status, wire, network = self.run_offline([http_response(completion(calls=[tool('check', 1)])),
                                                 TimeoutError('secret header ' + KEY)])
        self.assertEqual((status, len(network.requests)), (2, 2))
        failure = wire.frames[-1]
        self.assertEqual(failure['error']['code'], 'E_OPENAI_TRANSPORT')
        self.assertEqual(failure['usage'], wire.frames[0]['usage'])
        self.assertIsNone(failure['pending_provider_request']['request_id'])
        self.assertFalse(failure['usage_complete'])
        self.assertNotEqual(network.requests[0]['headers']['X-Client-Request-Id'],
                            network.requests[1]['headers']['X-Client-Request-Id'])

    def test_redirect_is_never_followed_and_body_is_not_exposed(self):
        for code in (301, 302, 307, 308):
            with self.subTest(code=code):
                status, wire, network = self.run_offline([http_response({'Location': 'https://evil.invalid/' + KEY}, status=code)])
                self.assertEqual((status, len(network.requests)), (2, 1))
                self.assertEqual(wire.frames[-1]['error']['code'], 'E_OPENAI_HTTP')

    def test_connection_close_response_retains_socket_for_bounded_read(self):
        status, _, network = self.run_offline([http_response(connection_close=True)])
        self.assertEqual(status, 0)
        self.assertTrue(network.connections[0].response.closed)

    def test_partial_body_failure_is_unknown_cost_and_closes_response(self):
        status, wire, network = self.run_offline([http_response(read_error=OSError(KEY))])
        self.assertEqual(status, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_OPENAI_TRANSPORT')
        self.assertIsNone(wire.frames[-1]['usage'])
        self.assertFalse(wire.frames[-1]['pending_provider_request']['receipt_verified'])
        self.assertTrue(network.connections[0].response.closed)

    def test_environment_cannot_override_endpoint_or_add_proxy(self):
        with patch.dict(os.environ, {'OPENAI_BASE_URL': 'http://evil.invalid',
                                    'HTTPS_PROXY': 'http://evil.invalid:1', 'HTTP_PROXY': 'http://evil.invalid:1'}):
            status, _, network = self.run_offline([http_response()])
        self.assertEqual(status, 0)
        self.assertEqual((network.connections[0].host, network.connections[0].port), ('api.openai.com', 443))

    def test_response_model_drift_is_not_relabelled(self):
        status, wire, _ = self.run_offline([http_response(completion(model=MODELS[1]['revision']))])
        self.assertEqual(status, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_OPENAI_MODEL_DRIFT')
        self.assertIsNone(wire.frames[-1]['usage'])
        self.assertFalse(wire.frames[-1]['pending_provider_request']['receipt_verified'])

    def test_missing_request_id_or_usage_rejected_without_fake_receipt(self):
        missing_usage = completion(); missing_usage.pop('usage')
        for spec, code in ((http_response(request_id=None), 'E_OPENAI_REQUEST_ID'),
                           (http_response(missing_usage), 'E_OPENAI_USAGE')):
            with self.subTest(code=code):
                status, wire, _ = self.run_offline([spec])
                self.assertEqual(status, 2)
                self.assertEqual(wire.frames[-1]['error']['code'], code)
                self.assertIsNone(wire.frames[-1]['usage'])

    def test_invalid_or_sensitive_usage_never_enters_ledger(self):
        for usage in ({'prompt_tokens': True, 'completion_tokens': 2, 'total_tokens': 3},
                      {'prompt_tokens': 2, 'completion_tokens': 2, 'total_tokens': 5},
                      {'prompt_tokens': 2, 'completion_tokens': 2, 'total_tokens': 4, 'authorization': 1},
                      {'prompt_tokens': 2, 'completion_tokens': 2, 'total_tokens': 4, 'opaque': 'sensitive-string'}):
            with self.subTest(usage=usage):
                value = completion(); value['usage'] = usage
                status, wire, _ = self.run_offline([http_response(value)])
                self.assertEqual(status, 2)
                self.assertEqual(wire.frames[-1]['error']['code'], 'E_OPENAI_USAGE')
                self.assertIsNone(wire.frames[-1]['usage'])

    def test_valid_receipt_over_token_cap_is_kept_in_full(self):
        from experiments.agent_eval.harness import Budget, EvalError, validate_usage
        value = completion(output=5000)
        status, wire, _ = self.run_offline([http_response(value)])
        failure = wire.frames[-1]
        self.assertEqual(status, 2)
        self.assertEqual(failure['error']['code'], 'E_ADAPTER_TOKEN_BUDGET')
        self.assertEqual(failure['usage']['output_tokens'], 5000)
        self.assertEqual(failure['usage']['total_tokens'], 5120)
        self.assertTrue(failure['usage_complete'])
        self.assertNotIn('pending_provider_request', failure)
        with self.assertRaises(EvalError):
            validate_usage(failure['usage'], MODELS[0], Budget(**request()['budget']), 0, 'provider')
        relaxed = Budget(**{**request()['budget'], 'output_tokens': 5000})
        self.assertEqual(validate_usage(failure['usage'], MODELS[0], relaxed, 0, 'provider'), failure['usage'])

    def test_remaining_output_cap_reduced_and_time_only_shortens(self):
        status, _, network = self.run_offline([http_response(completion(calls=[tool('check', 1)], output=300)),
                                              http_response(request_id='unit-test-only-provider-2')])
        self.assertEqual(status, 0)
        self.assertEqual([r['body']['max_completion_tokens'] for r in network.requests], [4000, 3700])
        self.assertGreater(network.connections[0].timeout, network.connections[1].timeout)

    def test_initial_remaining_wall_and_interface_policy_are_honored(self):
        frozen = request()
        frozen['interface_policy'] = 'preserve'
        frozen['remaining'] = {'wall_seconds': 3.0, 'tool_calls': frozen['budget']['tool_calls'],
                               'total_tokens': frozen['budget']['total_tokens']}
        status, _, network = self.run_offline([http_response()], frozen=frozen)
        self.assertEqual(status, 0)
        self.assertEqual(network.connections[0].timeout, 3.0)
        public = json.loads(network.requests[0]['body']['messages'][1]['content'])
        self.assertEqual(public['interface_policy'], 'preserve')
        self.assertEqual(public['remaining'], frozen['remaining'])
        self.assertEqual(public['budget'], frozen['budget'])

    def test_initial_remaining_wall_cannot_increase_frozen_wall_cap(self):
        frozen = request()
        frozen['remaining'] = {'wall_seconds': 3000.0, 'tool_calls': frozen['budget']['tool_calls'],
                               'total_tokens': frozen['budget']['total_tokens']}
        status, _, network = self.run_offline([http_response()], frozen=frozen)
        self.assertEqual(status, 0)
        self.assertEqual(network.connections[0].timeout, frozen['budget']['wall_seconds'])

    def test_zero_output_and_conservative_input_admission_make_no_request(self):
        for budget, code in (({'output_tokens': 0}, 'E_ADAPTER_OUTPUT_BUDGET'),
                             ({'input_tokens': 1}, 'E_ADAPTER_INPUT_ADMISSION'),
                             ({'total_tokens': 1}, 'E_ADAPTER_INPUT_ADMISSION')):
            with self.subTest(code=code):
                frozen = request(); frozen['budget'].update(budget)
                status, wire, network = self.run_offline([], frozen=frozen)
                self.assertEqual((status, len(network.requests)), (2, 0))
                self.assertEqual(wire.frames[-1]['error']['code'], code)
                self.assertIsNone(wire.frames[-1]['usage'])

    def test_output_byte_reserve_stops_before_spending(self):
        frozen = request(); frozen['budget']['protocol_bytes'] = 4096
        status, wire, network = self.run_offline([], frozen=frozen)
        self.assertEqual((status, len(network.requests)), (2, 0))
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_PROTOCOL_BYTES')

    def test_wall_exhausted_by_tool_blocks_next_http_call(self):
        def exhausted(value):
            value['remaining']['wall_seconds'] = 0
            return value
        status, wire, network = self.run_offline([http_response(completion(calls=[tool('check', 1)]))], feedback=exhausted)
        self.assertEqual((status, len(network.requests)), (2, 1))
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_WALL_BUDGET')
        self.assertEqual(wire.frames[-1]['usage']['total_tokens'], 160)

    def test_tool_cap_no_forwarded_overrun_and_keeps_paid_usage(self):
        frozen = request(); frozen['budget']['tool_calls'] = 1
        status, wire, network = self.run_offline([http_response(completion(calls=[tool('check', 1), tool('check', 2)]))], frozen=frozen)
        self.assertEqual(status, 2)
        self.assertEqual([f['kind'] for f in wire.frames], ['abort'])
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_TOOL_BUDGET')
        self.assertEqual(wire.frames[-1]['usage']['tool_calls'], 0)

    def test_no_tools_remaining_disables_provider_tools_for_final_turn(self):
        frozen = request(); frozen['budget']['tool_calls'] = 1
        status, _, network = self.run_offline([http_response(completion(calls=[tool('check', 1)])),
                                              http_response(request_id='unit-test-only-provider-2')], frozen=frozen)
        self.assertEqual(status, 0)
        self.assertEqual(network.requests[1]['body']['tool_choice'], 'none')

    def test_model_truncation_refusal_and_wrong_final_are_failures_with_receipts(self):
        refusal = completion(); refusal['choices'][0]['message']['refusal'] = 'unit-test refusal'
        for value, code in ((completion(finish='length'), 'E_OPENAI_INCOMPLETE'),
                            (refusal, 'E_OPENAI_INCOMPLETE'),
                            (completion(version=UPDATED), 'E_ADAPTER_FINAL')):
            with self.subTest(code=code):
                status, wire, _ = self.run_offline([http_response(value)])
                self.assertEqual(status, 2)
                self.assertEqual(wire.frames[-1]['error']['code'], code)
                self.assertEqual(wire.frames[-1]['usage']['total_tokens'], 160)
                self.assertTrue(wire.frames[-1]['usage_complete'])

    def test_bad_tool_result_cannot_switch_request_or_current_version(self):
        def wrong(value): value['request_id'] = 'another-sample'; return value
        status, wire, network = self.run_offline([http_response(completion(calls=[tool('check', 1)]))], feedback=wrong)
        self.assertEqual((status, len(network.requests)), (2, 1))
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_TOOL_RESULT')

    def test_malformed_json_usage_duplicate_keys_and_response_size(self):
        for body in (b'{"model":"x","model":"y"}', b'not-json', b' ' * (adapter.MAX_JSON_BYTES + 1)):
            with self.subTest(size=len(body)):
                status, wire, _ = self.run_offline([http_response(body)])
                self.assertEqual(status, 2)
                self.assertEqual(wire.frames[-1]['error']['code'], 'E_OPENAI_RESPONSE')
                self.assertIsNone(wire.frames[-1]['usage'])

    def test_credentials_in_success_body_are_withheld(self):
        body = completion(); body['choices'][0]['message']['content'] = KEY
        status, wire, _ = self.run_offline([http_response(body)])
        self.assertEqual(status, 2)
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_SECRET')
        self.assertNotIn(KEY, json.dumps(wire.frames))

    def test_key_required_only_from_explicit_environment(self):
        status, wire, network = self.run_offline([], environment={})
        self.assertEqual((status, len(network.requests)), (2, 0))
        self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_KEY')
        self.assertIsNone(wire.frames[-1]['usage'])

    def test_abort_capability_required_and_no_null_version_fake_final(self):
        frozen = request(); frozen.pop('capabilities')
        status, wire, network = self.run_offline([], frozen=frozen)
        self.assertEqual((status, wire.frames, network.requests), (2, [], []))

    def test_model_configuration_requires_two_distinct_exact_dated_ids(self):
        self.assertEqual(adapter.validate_models(MODELS), MODELS)
        for values in ([MODELS[0]], [MODELS[0], MODELS[0]],
                       [MODELS[0], {**MODELS[1], 'revision': 'latest'}],
                       [MODELS[0], {**MODELS[1], 'revision': 'name-2000-13-01'}],
                       [MODELS[0], {**MODELS[1], 'provider': 'another-provider'}]):
            with self.subTest(values=values):
                with self.assertRaises(adapter.AdapterError): adapter.validate_models(values)

    def test_unconfigured_model_and_cross_arm_tool_escalation_rejected(self):
        for change in ('model', 'tools'):
            frozen = request('rust_plain')
            if change == 'model': frozen['model'] = {**MODELS[0], 'revision': 'unconfigured-2000-01-01'}
            else: frozen['tools'].append('query_nodes')
            status, wire, network = self.run_offline([], frozen=frozen)
            self.assertEqual((status, len(network.requests)), (2, 0))
            self.assertEqual(wire.frames[-1]['error']['code'], 'E_ADAPTER_REQUEST')


class RealHTTPResponseTests(unittest.TestCase):
    """Real stdlib framing over local AF_UNIX sockets; never an API connection.

    These tests deliberately keep HTTPConnection.request/getresponse and
    HTTPResponse.read/close intact. Only connect() selects the local socketpair.
    Environments denying AF_UNIX must run this qualification in an approved
    execution context; failure is not silently converted into mocked coverage.
    """
    def run_response(self, framing, body, *, version='HTTP/1.1', close=False, eof=False):
        frozen, wire = request(), FakeWire(request())
        headers = [version + ' 200 OK', 'x-request-id: unit-test-real-http-response']
        if close: headers.append('Connection: close')
        headers.extend(framing)
        payload = ('\r\n'.join(headers) + '\r\n\r\n').encode() + body
        client, server = socket.socketpair()
        with client, server:
            server.settimeout(2)
            server.sendall(payload)
            if eof: server.shutdown(socket.SHUT_WR)
            class OfflineConnection(adapter.http.client.HTTPConnection):
                def __init__(self, host, port, timeout, context):
                    super().__init__(host, port, timeout=timeout)
                def connect(self):
                    self.sock = client
            with patch('socket.create_connection', side_effect=AssertionError('External TCP is forbidden')), \
                 patch.object(adapter.http.client, 'HTTPSConnection', OfflineConnection):
                status = adapter.run_adapter(frozen, MODELS, wire, environment={'OPENAI_API_KEY': KEY})
        self.assertNotIn(KEY, json.dumps(wire.frames))
        return status, wire.frames[-1]

    def assert_success(self, result):
        status, frame = result
        self.assertEqual(status, 0, frame)
        self.assertEqual(frame['kind'], 'final')
        self.assertEqual(frame['version'], INITIAL)
        self.assertEqual(frame['usage']['total_tokens'], 160)
        self.assertEqual(frame['usage']['provider_calls'][0]['request_id'], 'unit-test-real-http-response')

    def assert_truncated(self, result):
        status, frame = result
        self.assertEqual(status, 2)
        self.assertEqual((frame['kind'], frame['error']['code']), ('abort', 'E_OPENAI_TRANSPORT'))
        self.assertIsNone(frame['usage'])
        self.assertFalse(frame['usage_complete'])
        self.assertEqual(frame['pending_provider_request']['request_id'], 'unit-test-real-http-response')
        self.assertFalse(frame['pending_provider_request']['receipt_verified'])

    def test_content_length_connection_close_preserves_complete_usage(self):
        body = adapter.canonical(completion())
        self.assert_success(self.run_response(['Content-Length: ' + str(len(body))], body, close=True))

    def test_content_length_keep_alive_control(self):
        body = adapter.canonical(completion())
        self.assert_success(self.run_response(['Content-Length: ' + str(len(body))], body))

    def test_chunked_connection_close_preserves_complete_usage(self):
        body = adapter.canonical(completion())
        chunks = [body[:17], body[17:]]
        wire_body = b''.join(('%x\r\n' % len(chunk)).encode() + chunk + b'\r\n' for chunk in chunks) + b'0\r\n\r\n'
        self.assert_success(self.run_response(['Transfer-Encoding: chunked'], wire_body, close=True))

    def test_http10_eof_delimited_complete_body(self):
        body = adapter.canonical(completion())
        self.assert_success(self.run_response([], body, version='HTTP/1.0', eof=True))

    def test_complete_json_with_truncated_content_length_remains_unknown_cost(self):
        body = adapter.canonical(completion())
        self.assert_truncated(self.run_response(['Content-Length: ' + str(len(body) + 7)], body, close=True, eof=True))

    def test_chunked_body_missing_terminal_zero_remains_unknown_cost(self):
        body = adapter.canonical(completion())
        wire_body = ('%x\r\n' % len(body)).encode() + body + b'\r\n'
        self.assert_truncated(self.run_response(['Transfer-Encoding: chunked'], wire_body, close=True, eof=True))


class ProviderExportTests(unittest.TestCase):
    def test_export_cli_produces_frozen_metadata_without_key_or_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'models.json').write_bytes(adapter.canonical(MODELS))
            script = Path(__file__).resolve().parents[1] / 'tools/provider_adapter/export.py'
            ran = subprocess.run(['/usr/bin/python3', str(script), '--models', str(root / 'models.json'),
                                  '--output', str(root / 'bundle'), '--metadata-out', str(root / 'configs.json')],
                                 capture_output=True, timeout=5, cwd=root,
                                 env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(ran.returncode, 0, ran.stderr)
            report = json.loads(ran.stdout)
            self.assertEqual(report['bundle_sha256'], bundle_digest(root / 'bundle'))
            self.assertEqual(report['actual_ai_model_runs'], 0)
            self.assertEqual(len(json.loads((root / 'configs.json').read_text())), 2)

    def test_standalone_export_digest_metadata_and_no_evaluator_or_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(os.environ, {'OPENAI_API_KEY': KEY}):
                result = export_bundle(MODELS, root / 'bundle', root / 'adapter-configs.json')
            bundle = root / 'bundle'
            self.assertEqual({p.name for p in bundle.iterdir()},
                             {'openai_chat.py', 'README.md', 'models.json', 'command.json', 'manifest.json'})
            self.assertEqual(result['actual_ai_model_runs'], 0)
            metadata = json.loads((root / 'adapter-configs.json').read_text())
            self.assertEqual(len(metadata), 2)
            self.assertEqual({m['bundle_sha256'] for m in metadata}, {bundle_digest(bundle)})
            self.assertEqual([m['model'] for m in metadata], MODELS)
            for item in metadata:
                self.assertEqual(set(item), {'model', 'bundle_sha256', 'command', 'executable_sha256',
                                             'passed_environment_names', 'network_requested'})
                self.assertEqual(item['passed_environment_names'], ['OPENAI_API_KEY'])
                self.assertTrue(item['network_requested'])
                self.assertEqual(item['executable_sha256'], hashlib.sha256(Path('/usr/bin/python3').resolve().read_bytes()).hexdigest())
            for path in root.rglob('*'):
                if path.is_file(): self.assertNotIn(KEY.encode(), path.read_bytes())
            original = bundle_digest(bundle)
            (bundle / 'README.md').write_text('changed')
            self.assertNotEqual(bundle_digest(bundle), original)

    def test_exported_subprocess_runs_without_repo_and_aborts_before_api_without_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export_bundle(MODELS, root / 'bundle', root / 'adapter-configs.json')
            command = json.loads((root / 'bundle/command.json').read_text())
            command = [arg.replace('{adapter}', str(root / 'bundle')) for arg in command]
            ran = subprocess.run(command, input=adapter.canonical(request()) + b'\n', capture_output=True,
                                 cwd=root, timeout=5, env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(ran.returncode, 2, ran.stderr)
            frame = json.loads(ran.stdout)
            self.assertEqual((frame['kind'], frame['error']['code']), ('abort', 'E_ADAPTER_KEY'))
            self.assertIsNone(frame['usage'])
            self.assertFalse(frame['usage_complete'])
            self.assertEqual(ran.stderr, b'')

    def test_export_rejects_reuse_repo_destination_and_self_referential_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError): export_bundle(MODELS, root / 'bundle', root / 'bundle/configs.json')
            export_bundle(MODELS, root / 'bundle', root / 'configs.json')
            with self.assertRaises(ValueError): export_bundle(MODELS, root / 'bundle', root / 'new-configs.json')
        with self.assertRaises(ValueError):
            export_bundle(MODELS, Path(__file__).resolve().parents[1] / 'never-write-this-bundle', '/tmp/never-write-this-config.json')


if __name__ == '__main__':
    unittest.main()
