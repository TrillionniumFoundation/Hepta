"""Independent journal transitions, ordinary SQL effects and installed custody.

Native cases require an explicit current-source cold report or a distinctly
named development manifest. A development image never supplies cold evidence.
"""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_agent_journal_native import (
    SOURCE, SCHEMA, SELECTOR, NativeAgentJournal, installed_agent_journal,
    NONE, CONTINUE, LOOKUP, RESERVE, CACHE, REPLAY, VERIFY_REPLAY, ALIAS,
    ATOMIC, JOURNAL, FINAL, REFUSE, TOOLS, HEADER_OFFSET, PRIVATE_BYTES, buffer_sizes,
)
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT'


def independent_wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode()


def rows(service):
    return {
        'requests': [tuple(r) for r in service.store.db.execute('SELECT * FROM requests ORDER BY key')],
        'costs': [tuple(r) for r in service.store.db.execute('SELECT * FROM costs ORDER BY rowid')],
    }


class JournalSourceTests(unittest.TestCase):
    def test_caller_gate_rejects_incomplete_and_expected_failure_results(self):
        from tools.qualify_hia_agent_journal_callers import strict_pass
        class Expected(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail('actual expected failure must not qualify native callers')
        expected = Expected()
        result = unittest.TestResult()
        expected.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertFalse(strict_pass(result, [expected.id()], [expected.id()], True))
        result = unittest.TestResult()
        self.assertFalse(strict_pass(result, [], [], True))
        result.testsRun = 1
        self.assertTrue(strict_pass(result, ['case'], ['case'], True))
        self.assertFalse(strict_pass(result, ['case', 'missing'], ['case'], True))
        self.assertFalse(strict_pass(result, ['case'], ['different'], True))
        self.assertFalse(strict_pass(result, ['case'], ['case'], False))
        result.unexpectedSuccesses.append(expected)
        self.assertFalse(strict_pass(result, ['case'], ['case'], True))

    def test_source_reproduces_and_original_owner_is_unchanged(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_journal import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        # The retained owner remains independently callable for differential
        # comparison; selection cannot be implemented by renaming that owner.
        import inspect
        self.assertNotIn('native', inspect.getsource(HIAAgentService._reference_call))
        self.assertIn('call_with_native_journal', inspect.getsource(HIAAgentService.call))

    def test_independent_core_VM_request_identity(self):
        # Bound the child, rather than risking the test controller when a VM
        # regression allocates excessive memory. No native image is loaded.
        script = r'''
import hashlib,json,resource,struct,sys
resource.setrlimit(resource.RLIMIT_AS,(384 << 20,384 << 20))
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_agent_journal_native import SOURCE,buffer_sizes,HEADER_OFFSET
raw=b'{"tool":"hia_describe","arguments":{}}'
program=assemble_program(SOURCE.read_bytes())
out,work=buffer_sizes(len(raw))
owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(out)),_Owner(-3,bytearray(work))]
struct.pack_into('<2Q',owners[2].data,0,0,sys.get_int_max_str_digits())
machine=_Machine(program,20000000,64 << 20,None,128)
code=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
header=bytes(owners[1].data[HEADER_OFFSET:HEADER_OFFSET+512])
expected=hashlib.sha256(b'{"arguments":{},"tool":"hia_describe"}').hexdigest()
assert code==1,(code,header.hex())
assert header[64:128].decode()==expected
assert header[192:258].decode()=='r-'+expected
assert bytes(owners[0].data)==raw
print(json.dumps({'code':code,'request_sha256':expected,'native_image_loaded':False}))
'''
        result = subprocess.run([sys.executable, '-B', '-c', script], cwd=ROOT,
                                capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(json.loads(result.stdout)['native_image_loaded'])


class JournalNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development image cannot override a requested cold report')
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-journal-native-')
        cls.folder = Path(cls.temp.name)
        if cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'build', compiler, Path(cold), candidate='agent-journal')
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            cls.temp.cleanup()
            raise unittest.SkipTest('requires explicit journal cold report or development manifest')
        cls.image = installed_agent_journal(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix='case-', dir=self.folder))

    def selected(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest)}))
        stack.enter_context(patch.object(HIAAgentService, '_reference_call',
                                       side_effect=AssertionError('retained journal owner entered')))
        return stack

    def test_request_identity_keys_unicode_binary64_and_unknown_tool_order(self):
        keys = ['', 'a', '雪' * 192, '🧪' * 193, 7, None]
        numbers = [0, -0.0, 1.25, 1e15, 1e-300, 5e-324, 1.7976931348623157e308, 10 ** 300]
        for tool in TOOLS + ('unknown', [], {}):
            for key in keys:
                arguments = {'request_key': key, 'number': numbers[len(str(key)) % len(numbers)],
                             'nested': {'request_key': 'not-the-outer-key'}}
                value = {'tool': tool, 'arguments': arguments}
                # Deliberately unsorted input; independent stdlib is the oracle.
                raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
                session = self.image.session()
                decision = session.prepare(raw)
                expected = sha256(independent_wire(value)).hexdigest()
                self.assertEqual(session.request_digest, expected)
                self.assertEqual(session.request_id, 'r-' + expected)
                if type(tool) is not str or tool == 'unknown':
                    self.assertEqual(decision.action, REFUSE)
                elif tool == 'hia_resource_read':
                    self.assertEqual(decision.action, ALIAS)
                    self.assertIsNone(session.key)
                elif type(key) is str and 1 <= len(key) <= 192:
                    self.assertEqual(decision.action, LOOKUP)
                    self.assertEqual(session.key, sha256(independent_wire({'tool': tool, 'key': key})).hexdigest())
                else:
                    self.assertEqual(decision.action, CONTINUE)
                    self.assertIsNone(session.key)
        import math
        import random
        rng = random.Random(881)
        values = [*numbers, -5e-324, 2.2250738585072014e-308]
        while len(values) < 210:
            value = struct.unpack('<d', rng.getrandbits(64).to_bytes(8, 'little'))[0]
            if math.isfinite(value):
                values.append(value)
        request = {'tool': 'hia_describe', 'arguments': {'values': values}}
        session = self.image.session()
        session.prepare(json.dumps(request, separators=(',', ':')).encode())
        self.assertEqual(session.request_digest, sha256(independent_wire(request)).hexdigest())
        result = {'status': 'completed', 'result': values}
        self.assertEqual(session.finish(result).response, independent_wire(result))

    def test_ack_order_conflict_unknown_and_special_verification_replay(self):
        for tool in ('hia_artifact', 'hia_verify', 'hia_adopt'):
            raw = independent_wire({'tool': tool, 'arguments': {'request_key': 'phase'}})
            session = self.image.session()
            with self.assertRaises(RuntimeError):
                session.reserved()
            self.assertEqual(session.prepare(raw).action, LOOKUP)
            with self.assertRaises(RuntimeError):
                session.committed_inline()
            self.assertEqual(session.lookup(None).action, RESERVE)
            self.assertEqual(session.reserved().action, CONTINUE)
            with self.assertRaises(RuntimeError):
                session.reserved()
            self.assertEqual(session.effect().action, ATOMIC if tool == 'hia_adopt' else CONTINUE)
            response = {'status': 'completed', 'result': {'z': -0.0, 'a': 1.25}}
            if tool == 'hia_adopt':
                instruction = session.inline(response)
                self.assertEqual((instruction.action, instruction.flags), (JOURNAL, 2))
                self.assertEqual(instruction.response, independent_wire(response))
                session.committed_inline()
                with self.assertRaises(RuntimeError):
                    session.committed_inline()
            final = session.finish(response)
            self.assertEqual(final.flags, 1 if tool == 'hia_adopt' else 3)
            self.assertEqual(final.cost_details, b'{"error":null,"replayed":false}')
            with self.assertRaises(RuntimeError):
                session.finish(response)
            for state, changed in [('running', False), ('completed', True), ('alien', False)]:
                other = self.image.session(); other.prepare(raw)
                decision = other.lookup({'digest': '0' * 64 if changed else other.request_digest, 'state': state})
                self.assertEqual(decision.action, REFUSE)
                with self.assertRaises(ValueError) as rejected:
                    other.raise_refusal()
                self.assertEqual(rejected.exception.code, 'E_HIA_REQUEST_CONFLICT' if changed else 'E_HIA_REQUEST_UNKNOWN')
            for status in ('completed', 'rejected'):
                other = self.image.session(); other.prepare(raw)
                self.assertEqual(other.lookup({'digest': other.request_digest, 'state': 'completed'}).action, CACHE)
                cached = '{"z":2,"status":"' + status + '","a":-0.0}'
                decision, value = other.cached(cached)
                self.assertEqual(list(value), ['z', 'status', 'a'])
                self.assertEqual(decision.action, VERIFY_REPLAY if tool == 'hia_verify' and status == 'completed' else REPLAY)
                self.assertEqual(other.finish(None).flags, 0)

    def test_exact_reference_errors_rows_and_arbitrary_precision_clock_TEXT(self):
        services = [HIAAgentService(self.case / name) for name in ('reference', 'native')]
        self.addCleanup(lambda: [service.close() for service in services])
        catalog = services[0].catalog_sha256
        cases = [
            ('unknown', {'request_key': 'key'}),
            ([], {'request_key': 'key'}),
            ((), {'request_key': 'tuple-empty'}),
            (('x',), {'request_key': 'tuple-scalar'}),
            ((('x', 1, None),), {'request_key': 'tuple-nested'}),
            ((['x'], {}), {'request_key': 'tuple-list-first'}),
            (({}, ['x']), {'request_key': 'tuple-dict-first'}),
            (((('x',), []),), {'request_key': 'tuple-nested-list'}),
            ('hia_artifact', {'request_key': 'unicode-雪', 'catalog_sha256': catalog}),
            ('hia_artifact', {'request_key': 'claim-first', 'unknown': True}),
            ('hia_artifact', {'request_key': 'claim-first', 'unknown': False}),
            ('hia_artifact', {'request_key': '雪' * 192}),
            ('hia_artifact', {'request_key': '雪' * 193}),
            ('hia_artifact', {'request_key': ''}),
            ('hia_artifact', {'request_key': 4}),
            ('hia_artifact', []),
            ('hia_resource_read', {'uri': 'missing', 'request_key': 'no-alias-key'}),
            ('hia_describe', {'section': float('inf')}),
        ]
        for tool, args in cases:
            outcomes = []
            for index, service in enumerate(services):
                with ExitStack() as stack:
                    stack.enter_context(patch('hepta.hia_agent_service.uuid.uuid4',
                                              return_value=SimpleNamespace(hex='1' * 32)))
                    stack.enter_context(patch('hepta.hia_agent_service.time.time_ns', return_value=10 ** 90 + 7))
                    stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns',
                                              side_effect=[10 ** 100, 10 ** 100 + 10 ** 80 + 9]))
                    if index:
                        stack.enter_context(self.selected())
                        outcome = service.call(tool, args)
                    else:
                        outcome = service._reference_call(tool, args)
                    outcomes.append(outcome)
            self.assertEqual(independent_wire(outcomes[0]), independent_wire(outcomes[1]), (tool, args))
            self.assertEqual(rows(services[0]), rows(services[1]), (tool, args))
        self.assertTrue(all(row[5] == str(10 ** 90 + 7) for row in rows(services[1])['requests']))
        self.assertTrue(all(row[4] == str(10 ** 80 + 9) for row in rows(services[1])['costs']))

    def test_real_artifact_restart_replay_alias_and_no_effect_cost_or_update(self):
        from tools.hia_agent_native_qualification import Session, ToolClient
        with self.selected():
            service = HIAAgentService(self.case / 'state')
            self.addCleanup(service.close)
            session = Session(ToolClient(service.call), prefix='journal')
            args = session.arguments(context=False, artifact_profile=session.profiles['artifact'],
                                     source={'kind': 'utf8', 'text': 'actual durable effect 雪'})
            first = service.call('hia_artifact', args)
            self.assertEqual(first['status'], 'completed', first)
            snapshot = rows(service)
            with patch.object(service, '_hia_artifact', side_effect=AssertionError('replayed effect')), \
                    patch('hepta.hia_agent_service.digest', side_effect=AssertionError('hosted journal hash')):
                self.assertEqual(service.call('hia_artifact', args), first)
            self.assertEqual(rows(service), snapshot)
            restarted = HIAAgentService(self.case / 'state')
            self.addCleanup(restarted.close)
            snapshot = rows(restarted)
            with patch.object(restarted, '_hia_artifact', side_effect=AssertionError('restart effect')):
                self.assertEqual(restarted.call('hia_artifact', args), first)
            self.assertEqual(rows(restarted), snapshot)
            changed = {**args, 'source': {'kind': 'utf8', 'text': 'changed'}}
            conflict = restarted.call('hia_artifact', changed)
            self.assertEqual(conflict['error']['code'], 'E_HIA_REQUEST_CONFLICT')
            alias = {'uri': first['result']['artifact']['uri']}
            response = restarted.call('hia_resource_read', alias)
            self.assertEqual(response['status'], 'completed', response)
            expected = sha256(independent_wire({'tool': 'hia_resource_read', 'arguments': alias})).hexdigest()
            self.assertEqual(response['request_id'], 'r-' + expected)
            self.assertEqual(rows(restarted)['costs'][-1][2], 'hia_read')
            self.assertEqual(len(rows(restarted)['requests']), len(snapshot['requests']))

    def test_malformed_cached_response_never_reexecutes_or_rewrites_request(self):
        with self.selected():
            service = HIAAgentService(self.case / 'state')
            self.addCleanup(service.close)
            args = {'request_key': 'bad-cache'}
            session = self.image.session()
            session.prepare(independent_wire({'tool': 'hia_artifact', 'arguments': args}))
            service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                (session.key, session.request_digest, 'hia_artifact', 'completed', '{"bad":', '1'))
            before = rows(service)['requests']
            with patch.object(service, '_hia_artifact', side_effect=AssertionError('fallback effect')):
                response = service.call('hia_artifact', args)
            self.assertEqual(response['status'], 'rejected')
            self.assertEqual(rows(service)['requests'], before)
            self.assertEqual(len(rows(service)['costs']), 1)

    def test_real_SQL_commit_fault_preserves_ack_before_commit_semantics(self):
        class FaultDB:
            def __init__(self, actual, commit_first):
                self.actual, self.commit_first, self.count = actual, commit_first, 0
            def __getattr__(self, name):
                return getattr(self.actual, name)
            def execute(self, sql, *args):
                if sql == 'COMMIT':
                    self.count += 1
                    if self.count == 2:
                        self.actual.execute('COMMIT' if self.commit_first else 'ROLLBACK')
                        raise sqlite3.OperationalError('injected commit acknowledgement failure')
                return self.actual.execute(sql, *args)
        for committed in (False, True):
            observations = []
            for native in (False, True):
                service = HIAAgentService(self.case / ('commit-%s-%s' % (committed, native)))
                self.addCleanup(service.close)
                service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
                actual = service.store.db
                service.store.db = FaultDB(actual, committed)
                def effect(_args):
                    service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
                    return {'effect': 'committed'}
                args = {'catalog_sha256': service.catalog_sha256, 'request_key': 'cas'}
                with ExitStack() as stack:
                    stack.enter_context(patch('hepta.hia_agent_service.validate', return_value=None))
                    stack.enter_context(patch.object(service, '_hia_adopt', side_effect=effect))
                    stack.enter_context(patch('hepta.hia_agent_service.time.time_ns', return_value=10 ** 80))
                    stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1, 8, 10, 18]))
                    if native:
                        stack.enter_context(self.selected())
                        first = service.call('hia_adopt', args)
                        second = service.call('hia_adopt', args)
                    else:
                        first = service._reference_call('hia_adopt', args)
                        second = service._reference_call('hia_adopt', args)
                observations.append((first, second, rows(service),
                                     [tuple(r) for r in actual.execute('SELECT * FROM effect_probe')]))
            self.assertEqual(observations[0], observations[1])
            first, second, state, effects = observations[1]
            self.assertEqual(first['status'], 'rejected')
            self.assertEqual(effects, [('effect',)] if committed else [])
            if committed:
                self.assertEqual(second['status'], 'completed')
                self.assertEqual(len(state['costs']), 1)
            else:
                self.assertEqual(second['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                self.assertEqual(state['requests'][0][3], 'running')

    def test_native_protocol_failure_cannot_journal_a_rolled_back_success(self):
        from hepta.hia_agent_journal_native import JournalSession
        import itertools
        for operation, after, exception in itertools.product(
                ('reserved', 'inline', 'committed_inline'), (False, True),
                (RuntimeError, KeyboardInterrupt, SystemExit, MemoryError)):
                with self.subTest(operation=operation, after=after, exception=exception.__name__), self.selected():
                    service = HIAAgentService(self.case / ('ack-%s-%s-%s' % (operation, after, exception.__name__)))
                    self.addCleanup(service.close)
                    service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
                    def effect(_args):
                        service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
                        return {'effect': 'would-have-committed'}
                    original = getattr(JournalSession, operation)
                    def fail(session, *args):
                        if after:
                            original(session, *args)
                        raise exception('injected native protocol acknowledgement failure')
                    args = {'catalog_sha256': service.catalog_sha256, 'request_key': 'native-ack'}
                    with patch('hepta.hia_agent_service.validate', return_value=None), \
                            patch.object(service, '_hia_adopt', side_effect=effect), \
                            patch.object(JournalSession, operation, fail):
                        with self.assertRaisesRegex(exception, 'acknowledgement failure'):
                            service.call('hia_adopt', args)
                    state = rows(service)
                    self.assertEqual(list(service.store.db.execute('SELECT * FROM effect_probe')), [])
                    self.assertEqual(state['costs'], [])
                    if operation == 'reserved':
                        self.assertEqual(state['requests'], [])
                    else:
                        self.assertEqual(len(state['requests']), 1)
                        self.assertEqual(state['requests'][0][3:5], ('running', None))
                        with patch.object(service, '_hia_adopt', side_effect=AssertionError('unknown effect retried')):
                            retry = service.call('hia_adopt', args)
                        self.assertEqual(retry['error']['code'], 'E_HIA_REQUEST_UNKNOWN')

    def test_cached_foreign_values_and_lazy_numeric_selector_match_reference(self):
        payloads = [b'{"status":"rejected","result":7}',
                    '{"status":"rejected","result":1e400}', '1e400',
                    '{"status":"rejected","integer":' + '1' * 4301 + '}',
                    'null', 'true', 'false', '7', '1.25', '"text"', '[]', 3, None,
                    '{"z":1,"status":"rejected","a":2}',
                    '{"status":"rejected","number":1.25}']
        for number, payload in enumerate(payloads):
            for missing_converter in (False, True):
                outcomes = []
                tool = 'hia_verify' if number in range(4, 11) else 'hia_artifact'
                for native in (False, True):
                    service = HIAAgentService(self.case / ('cache-%s-%s-%s' % (number, missing_converter, native)))
                    self.addCleanup(service.close)
                    args = {'request_key': 'cached-domain'}
                    identity = self.image.session()
                    identity.prepare(independent_wire({'tool': tool, 'arguments': args}))
                    service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                        (identity.key, identity.request_digest, tool, 'completed', payload, '1'))
                    with ExitStack() as stack:
                        if missing_converter:
                            stack.enter_context(patch.dict(os.environ, {
                                'HEPTA_HIA_AGENT_BINARY64_MANIFEST': str(self.case / 'missing-float.json')}))
                        stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1, 9]))
                        if native:
                            stack.enter_context(self.selected())
                        try:
                            response = service.call(tool, args) if native else service._reference_call(tool, args)
                            outcome = ('returned', response)
                        except AttributeError as exc:
                            outcome = ('raised', type(exc).__name__, str(exc))
                    outcomes.append((outcome, rows(service)))
                self.assertEqual(outcomes[0], outcomes[1], (number, missing_converter, payload))

    def test_cached_syntax_UTF8_and_budget_errors_match_reference_exactly(self):
        syntax = ['', ' ', '[', '{', '[1', '[1,', '[1,]', '[1 2]',
                  '{1:2}', '{"a"}', '{"a":}', '{"a":1,}', '{"a":1 "b":2}',
                  'true false', 'NaN', 'Infinity', '-', '+1', '.1', '01',
                  '1.', '1e', '1e+', '-1.0e-', '[1.2e,0]', '{"x":1e+}',
                  '"', '"abc', '"abc\\', '"\\x"', '"\\u"', '"\\u12"',
                  '"\\uQQQQ"', '"\\ud800"', '"\\ud800\\u0041"', '"\\udc00"',
                  '"a\x01b"', '"\\u𐐷', '"\\u𐐷ab"',
                  '"\\u"123456e7', '"\\uG"12345e7', '"\\u𐐷"12345e7', '"\\u00"12345e7',
                  '--1.0', '[1.0,--2e0]', '["雪",--1.0]', '[1-1.0]', '{"a":1-1.0}',
                  '10-1.0', '-1-1e0', '[--1.0,0]', '{"x":--1e0}', '\n[1,\n --2e1]',
                  '{"a":1,"\\u0061":2}', '[' * 129 + '0' + ']' * 129,
                  '{"x":1e400,"x":0}', '{"x":' + '9' * 4301 + ',"x":0}']
        payloads = syntax + [item.encode() for item in syntax[:30]] + [
            b'"\xff"', b'"\xe2("', b'"\xe2\x82', b'"\xed\xa0\x80"',
            b'bad JSON then \xff', b'\xff' + b' ' * (8 << 20),
            b' ' * ((8 << 20) + 1)]
        for index, payload in enumerate(payloads):
            observations = []
            for native in (False, True):
                service = HIAAgentService(self.case / ('syntax-%s-%s' % (index, native)))
                args = {'request_key': 'syntax-refusal'}
                digest = sha256(independent_wire({'tool': 'hia_artifact', 'arguments': args})).hexdigest()
                key = sha256(independent_wire({'tool': 'hia_artifact', 'key': args['request_key']})).hexdigest()
                service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                    (key, digest, 'hia_artifact', 'completed', payload, '1'))
                with ExitStack() as stack:
                    stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1, 9]))
                    stack.enter_context(patch.object(service, '_hia_artifact',
                        side_effect=AssertionError('malformed cached JSON reexecuted an effect')))
                    if native:
                        stack.enter_context(self.selected())
                    response = service.call('hia_artifact', args) if native else service._reference_call('hia_artifact', args)
                observed = rows(service)
                self.assertEqual(observed['requests'][0][4], payload)
                observations.append((wire(response), observed))
                service.close()
            self.assertEqual(observations[0], observations[1], (index, repr(payload[:100])))

    def test_HIA_UTF8_codec_reports_python_byte_spans_without_host_decoding(self):
        session = self.image.session()
        session.prepare(independent_wire({'tool': 'hia_artifact', 'arguments': {'request_key': 'codec'}}))
        session.lookup({'digest': session.request_digest, 'state': 'completed'})
        payloads = [b'', b'ASCII\x00\x1f', '雪🧪'.encode(), b'\xc2\x80', b'\xf4\x8f\xbf\xbf']
        payloads += [bytes([first]) for first in range(128, 256)]
        payloads += [b'prefix' + bytes(seq) for seq in (
            (0xe0, 0x9f, 0x80), (0xed, 0xa0, 0x80), (0xf0, 0x8f, 0x80, 0x80),
            (0xf4, 0x90, 0x80, 0x80), (0xf0, 0x90), (0xf0, 0x90, 0x80),
            (0xf0, 0x90, 0x20), (0xf0, 0x90, 0x80, 0x20), (0xe2, 0x82, 0x20))]
        for payload in payloads:
            try:
                payload.decode('utf-8')
            except UnicodeDecodeError as expected:
                with self.assertRaises(UnicodeDecodeError) as actual:
                    session._run(10, payload)
                self.assertEqual(actual.exception.args, expected.args)
                self.assertEqual(str(actual.exception), str(expected))
            else:
                self.assertEqual(session._run(10, payload).action, 13)

    def test_cached_explicit_selectors_are_readmitted_after_argument_snapshot(self):
        from hepta import hia_agent_data_json_native as data_module
        from hepta import hia_json_preflight_native as preflight_module
        from tools.build_hia_json_preflight import build as build_preflight
        from tools.build_hia_agent_data_json import build as build_data
        from tools.qualify_hia_selfhost import compile_stage
        cold = os.environ.get(COLD)
        if cold:
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            # Development composition uses the explicit build's retained raw
            # request. It never obtains a new-source cold claim from its B3.
            request = json.loads((self.manifest.parent / 'agent-journal.request.json').read_bytes())
            compiler = Path(request['image'])
            self.assertEqual(sha256(compiler.read_bytes()).hexdigest(),
                             json.loads(self.manifest.read_bytes())['compiler_sha256'])
        class ObservedDB:
            def __init__(self, actual, change):
                self.actual, self.change, self.changed = actual, change, False
            def __getattr__(self, name):
                return getattr(self.actual, name)
            def execute(self, sql, *args):
                result = self.actual.execute(sql, *args)
                if sql.startswith('SELECT * FROM requests') and not self.changed:
                    self.changed = True
                    self.change()
                return result
        for name, module, selector, builder in (
                ('data', data_module, 'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST', build_data),
                ('preflight', preflight_module, 'HEPTA_HIA_JSON_PREFLIGHT_MANIFEST', build_preflight)):
            folder = self.case / ('build-' + name)
            if cold:
                original_manifest = builder(folder, compiler, Path(cold))
            else:
                folder.mkdir()
                label = 'agent-data-json' if name == 'data' else 'json-preflight'
                image, _receipt = compile_stage(folder, label, compiler, module.SOURCE.read_bytes())
                original_manifest = folder / 'manifest.json'
                original_manifest.write_text(json.dumps({
                    'schema': module.SCHEMA if name == 'data' else 'hepta.hia.json-preflight-native.v1',
                    'source_sha256': sha256(module.SOURCE.read_bytes()).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}))
            for fault in ('new-selector', 'selector-switch', 'manifest', 'source', 'warm-image', 'new-image'):
                observations = []
                for native in (False, True):
                    case = self.case / ('selector-%s-%s-%s' % (name, fault, native));case.mkdir()
                    manifest = case / 'manifest.json'
                    record = json.loads(original_manifest.read_bytes())
                    image = case / record['image_path']
                    image.write_bytes((original_manifest.parent / record['image_path']).read_bytes())
                    manifest.write_bytes(original_manifest.read_bytes())
                    source = case / 'source.hiaasm';source.write_bytes(module.SOURCE.read_bytes())
                    service = HIAAgentService(case / 'state')
                    args = {'request_key': 'selector-drift'}
                    digest = sha256(independent_wire({'tool': 'hia_artifact', 'arguments': args})).hexdigest()
                    key = sha256(independent_wire({'tool': 'hia_artifact', 'key': args['request_key']})).hexdigest()
                    payload = '{"status":"rejected","result":7}'
                    service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                        (key, digest, 'hia_artifact', 'completed', payload, '1'))
                    def change():
                        if fault in ('new-selector', 'selector-switch'):
                            os.environ[selector] = str(self.case / ('missing-' + name))
                        elif fault == 'manifest':
                            manifest.write_text('{}')
                        elif fault == 'source':
                            source.write_bytes(source.read_bytes() + b'\n')
                        elif fault == 'warm-image':
                            image.write_bytes(image.read_bytes() + b'\x00')
                        else:
                            damaged = case / 'new-damaged-image.bin'
                            damaged.write_bytes(image.read_bytes() + b'\x00')
                            changed = dict(record, image_path=damaged.name)
                            manifest.write_text(json.dumps(changed))
                    service.store.db = ObservedDB(service.store.db, change)
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(module, 'SOURCE', source))
                        stack.enter_context(patch.dict(os.environ,
                            {selector: '' if fault == 'new-selector' else str(manifest)}))
                        stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1, 9]))
                        stack.enter_context(patch.object(service, '_hia_artifact',
                            side_effect=AssertionError('selected cached refusal reexecuted effect')))
                        if native:
                            stack.enter_context(self.selected())
                        result = service.call('hia_artifact', args) if native else service._reference_call('hia_artifact', args)
                    self.assertTrue(service.store.db.changed)
                    state = rows(service)
                    self.assertEqual(state['requests'][0][4], payload)
                    if fault == 'warm-image':
                        # Both loaders retain the previously admitted immutable
                        # mapping when the manifest key is unchanged.
                        self.assertEqual(result, {'status': 'rejected', 'result': 7})
                        self.assertEqual(state['costs'], [])
                    else:
                        self.assertEqual(result['status'], 'rejected')
                        self.assertIn('error', result)
                        self.assertEqual(len(state['costs']), 1)
                    observations.append((wire(result), state))
                    service.close()
                self.assertEqual(observations[0], observations[1], (name, fault))

    def test_real_SQLite_non_TEXT_observations_preserve_conflict_before_state(self):
        args = {'request_key': 'opaque-sqlite-columns'}
        expected_digest = sha256(independent_wire({'tool': 'hia_artifact', 'arguments': args})).hexdigest()
        key = sha256(independent_wire({'tool': 'hia_artifact', 'key': args['request_key']})).hexdigest()
        cases = [(expected_digest.encode(), 'completed', 'E_HIA_REQUEST_CONFLICT'),
                 (expected_digest.encode(), b'completed', 'E_HIA_REQUEST_CONFLICT'),
                 (float('inf'), 'completed', 'E_HIA_REQUEST_CONFLICT'),
                 (expected_digest, b'completed', 'E_HIA_REQUEST_UNKNOWN')]
        for index, (digest, state, code) in enumerate(cases):
            observations = []
            for native in (False, True):
                service = HIAAgentService(self.case / ('sqlite-types-%s-%s' % (index, native)))
                self.addCleanup(service.close)
                service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                    (key, digest, 'hia_artifact', state, '{"status":"rejected"}', '1'))
                with ExitStack() as stack:
                    stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns', side_effect=[1, 9]))
                    if native:
                        stack.enter_context(self.selected())
                    result = service.call('hia_artifact', args) if native else service._reference_call('hia_artifact', args)
                self.assertEqual(result['error']['code'], code)
                observations.append((result, rows(service)))
            self.assertEqual(observations[0], observations[1])

    def test_real_process_kill_after_effect_preserves_running_intent(self):
        from tools.hia_agent_native_qualification import Session, ToolClient
        with self.selected():
            service = HIAAgentService(self.case / 'state')
            self.addCleanup(service.close)
            session = Session(ToolClient(service.call), prefix='kill')
            args = session.arguments(context=False, artifact_profile=session.profiles['artifact'],
                                     source={'kind': 'utf8', 'text': 'native journal crash checkpoint'})
            marker = self.case / 'effect.json'
            script = r'''
import json,pathlib,signal,sys
from hepta.hia_agent_service import HIAAgentService
def forbidden(*args,**kwargs):raise AssertionError('retained journal owner in child')
HIAAgentService._reference_call=forbidden
s=HIAAgentService(sys.argv[1]);original=s._hia_artifact
def stopped(args):
    value=original(args)
    pathlib.Path(sys.argv[2]).write_text(json.dumps(value))
    print('effect-visible',flush=True)
    signal.pause()
s._hia_artifact=stopped
s.call('hia_artifact',json.loads(sys.argv[3]))
'''
            child = subprocess.Popen([sys.executable, '-B', '-c', script, str(self.case / 'state'),
                                      str(marker), json.dumps(args)], cwd=ROOT,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                import select
                ready, _, _ = select.select([child.stdout], [], [], 15)
                self.assertTrue(ready, 'child did not reach effect checkpoint')
                self.assertEqual(child.stdout.readline().strip(), b'effect-visible')
                child.kill()
                child.communicate(timeout=5)
            finally:
                if child.poll() is None:
                    child.kill(); child.communicate(timeout=5)
            retained = json.loads(marker.read_bytes())['artifact']
            self.assertEqual(service.store.get(retained)[0], args['source']['text'].encode())
            with patch.object(service, '_hia_artifact', side_effect=AssertionError('unknown intent retried')):
                unknown = service.call('hia_artifact', args)
            self.assertEqual(unknown['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(unknown['error']['retry_action'], 'observe_original')

    def test_selected_source_and_catalog_drift_fail_closed_before_SQL(self):
        with self.selected():
            service = HIAAgentService(self.case / 'state')
            self.addCleanup(service.close)
            before = rows(service)
            with patch('hepta.hia_agent_journal_native.SOURCE', self.case / 'missing.hiaasm'):
                rejected = service.call('hia_describe', {})
            self.assertEqual(rejected['error']['code'], 'E_HIA_JOURNAL_NATIVE')
            self.assertEqual(rows(service), before)

            catalog = self.case / 'catalog.json'
            catalog.write_text('{"tools":[]}')
            with patch('hepta.hia_agent_journal_native._agent_resource_path', return_value=catalog):
                rejected = service.call('hia_describe', {})
            self.assertEqual(rejected['error']['code'], 'E_HIA_JOURNAL_NATIVE')
            self.assertEqual(rows(service), before)

    def test_terminal_channels_do_not_add_a_combined_eight_MiB_gate(self):
        from hepta.hia_agent_journal_native import MAX_BYTES
        session = self.image.session()
        session.prepare(b'{"tool":"hia_describe","arguments":{}}')
        response = {'status': 'rejected', 'error': {'message': 'x' * (MAX_BYTES - 4096)}}
        result = session.finish(response)
        self.assertEqual(result.response, independent_wire(response))
        self.assertEqual(result.cost_details, independent_wire({'error': response['error'], 'replayed': False}))
        self.assertGreater(len(result.response) + len(result.cost_details), MAX_BYTES)
        self.assertLessEqual(len(result.response), MAX_BYTES)
        self.assertLessEqual(len(result.cost_details), MAX_BYTES)

    def test_raw_numeric_expansion_refuses_before_channel_overwrite(self):
        script = r'''
import pathlib,resource,sys
resource.setrlimit(resource.RLIMIT_AS,(384 << 20,384 << 20))
from hepta.hia_agent_journal_native import installed_agent_journal,MAX_BYTES
image=installed_agent_journal(sys.argv[1])
raw=b'{"status":"rejected","error":{"a":"'+b'x'*(MAX_BYTES-8000)+b'","z":['+b','.join([b'1e15']*1000)+b']}}'
assert len(raw)<MAX_BYTES
try:image.session()._run(8,raw)
except ValueError as exc:assert str(exc)=='E_HIA_EDIT: JSON encoding exceeds byte budget',exc
else:raise AssertionError('expanded canonical response exceeded its independent channel')
print('REFUSED_WITH_INPUT_AND_OUTPUT_CANARIES_INTACT')
'''
        result = subprocess.run([sys.executable, '-B', '-c', script, str(self.manifest)],
                                cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'CANARIES_INTACT', result.stdout)

    def test_native_ABI_canaries_and_instruction_header_refuse_corruption(self):
        original = self.image._entry
        for location in ('source', 'output-canary', 'scratch-canary', 'flags'):
            def corrupt(source, source_size, output, output_size, scratch, scratch_size):
                result = original(source, source_size, output, output_size, scratch, scratch_size)
                if location == 'source':
                    source[0] = b'!'
                elif location == 'output-canary':
                    output[output_size] = b'\xff'
                elif location == 'scratch-canary':
                    scratch[scratch_size] = b'\xff'
                else:
                    struct.pack_into('<Q', output, HEADER_OFFSET + 288, 3)
                return result
            with self.subTest(location=location), patch.object(self.image, '_entry', corrupt):
                with self.assertRaises(RuntimeError):
                    self.image.session().prepare(b'{"tool":"hia_describe","arguments":{}}')

    def test_installed_wheel_ordinary_call_no_tools_and_source_catalog_binding(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        source = self.case / 'wheel-source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels = self.case / 'wheels'
        build = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], cwd=source,
            capture_output=True, timeout=120, env={**os.environ, 'PIP_DISABLE_PIP_VERSION_CHECK': '1'})
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        wheel, = wheels.glob('*.whl')
        installed = self.case / 'installed'
        install = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.case, capture_output=True,
            timeout=120, env={**os.environ, 'PIP_DISABLE_PIP_VERSION_CHECK': '1'})
        self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
        script = r'''
import importlib.abc,json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed journal imported tools')
sys.meta_path.insert(0,NoTools())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_journal_native import SOURCE,SELECTOR
from hepta.hia_agent_store import _agent_resource_path
def forbidden(*args,**kwargs):raise AssertionError('retained installed owner')
HIAAgentService._reference_call=forbidden
os.environ[SELECTOR]=sys.argv[2]
service=HIAAgentService(pathlib.Path(sys.argv[3])/'state')
first=service.call('hia_describe',{'section':'manifest'})
assert first['status']=='completed',first
assert '_data/examples/hia_bootstrap/agent_journal.hiaasm' in SOURCE.as_posix()
before=service.store.db.execute('SELECT count(*) FROM costs').fetchone()[0]
old=SOURCE.read_bytes()
SOURCE.write_bytes(old+b'\n')
bad=service.call('hia_describe',{})
assert bad['error']['code']=='E_HIA_JOURNAL_NATIVE',bad
assert service.store.db.execute('SELECT count(*) FROM costs').fetchone()[0]==before
SOURCE.write_bytes(old)
catalog=_agent_resource_path('docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json')
old_catalog=catalog.read_bytes()
catalog.write_bytes(old_catalog+b'\n')
bad=service.call('hia_describe',{})
assert bad['error']['code']=='E_HIA_JOURNAL_NATIVE',bad
assert service.store.db.execute('SELECT count(*) FROM costs').fetchone()[0]==before
catalog.write_bytes(old_catalog)
service.close()
print(json.dumps({'ordinary_native':True,'tools_imported':False,'source_and_catalog_drift_refused':True}))
'''
        run = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed),
                              str(self.manifest), str(self.case)], cwd=self.case,
                             capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertTrue(json.loads(run.stdout)['ordinary_native'])
