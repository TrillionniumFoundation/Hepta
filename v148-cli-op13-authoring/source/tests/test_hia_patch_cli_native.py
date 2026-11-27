"""Twelve separately owned real-image op13 witness groups.

The positive path uses the actual six-image report CLI, the independently
admitted Inspect owner, and the actual PatchResult mapping. Dynamic providers
below are negative/foreign-boundary observations, not replacement native
owners or manufactured positive policy results. Importing runs no tests.
"""
from __future__ import annotations

import builtins
from contextlib import contextmanager, ExitStack
import copy
import gc
from pathlib import Path
from types import ModuleType
import unittest
from unittest.mock import patch
import weakref

from tests import hia_patch_cli_support as support
from tests.hia_patch_cli_support import (
    ActualPatchCli, LostPatchReturn, comparable, plain, publish,
)
from tests.hia_patch_result_support import observed_admission


class ForeignFailure(Exception):
    pass


@contextmanager
def import_route(components, route, events):
    """Only the original CLI effect's two real import calls are labeled."""
    old = builtins.__import__
    namespace = components.base.original_effect.__globals__
    def observing(name, globals=None, locals=None, fromlist=(), level=0):
        if globals is namespace and level == 1 and name in ('hia_program', 'hia_program_tools'):
            events.append(('import', name, tuple(fromlist), level))
            return route(old, name, globals, locals, fromlist, level)
        return old(name, globals, locals, fromlist, level)
    builtins.__import__ = observing
    try:
        yield
    finally:
        builtins.__import__ = old


class PatchCliNativeTests(unittest.TestCase):
    def setUp(self):
        self.c = ActualPatchCli(Path(support.context()['controls_output']))
        self.addCleanup(self.c.close)

    def assert_native_patch(self, row):
        self.assertGreater(row['call_delta']['patch'], 0, 'no real Patch HIA entry')
        self.assertNotIn('apply_program_patch', row['old_policy_calls'])
        self.assertNotIn('_check_patch_interface', row['old_policy_calls'])

    def assert_foreign_patch(self, row):
        self.assertEqual(row['call_delta']['patch'], 0, 'foreign route entered Patch HIA')

    def test_full_cli_patch_v1_v2_real_hia_and_publication(self):
        c = self.c
        self.assertEqual(len(c.base.native_origins), 7)
        self.assertEqual(len(c.issuance), 1)
        for v2 in (False, True):
            with self.subTest(v2=v2):
                argv, output = c.patch_files(v2=v2)
                self.assertFalse(output.exists())
                old, _, old_error = c.observe('full-cli-reference-' + str(v2),
                    lambda: c.base.selected.run(argv, c.cli))
                self.assertIsNone(old_error)
                old_bytes, old_mode = c.retain_output_and_remove(output, 'reference-' + str(v2))
                new, _, new_error = c.observe('full-cli-selected-' + str(v2),
                    lambda: c.selected.run(argv, c.cli))
                self.assertIsNone(new_error)
                new_bytes, new_mode = c.retain_output_and_remove(output, 'selected-' + str(v2))
                self.assertEqual(comparable(new), comparable(old))
                self.assertEqual((new_bytes, new_mode), (old_bytes, old_mode))
                self.assertIn('apply_program_patch', old['old_policy_calls'])
                self.assert_native_patch(new)
                self.assertGreater(new['call_delta']['control'], 0)
                self.assertGreater(new['call_delta']['routing'], 0)
                document, request = c.fixture()
                if v2:
                    request.update(schema='hepta.hia.patch.v2', interface_policy='preserve')
                row, value, error = c.observe('direct-real-receipt-' + str(v2),
                    lambda: c.call13(c.session(), document, request))
                self.assertIsNone(error)
                self.assertEqual(value[0].canonical_bytes, new_bytes)
                self.assertIs(value[1]['claims']['native_executed'], False)
                self.assertIs(value[1]['claims']['behavior_equivalence_proved'], False)
                self.assertEqual(value[1]['status'], 'verified_unpublished')
                self.assertNotIn('publication', value[1])
                self.assert_native_patch(row)

    def test_provider_document_request_order_and_consumed_request(self):
        c = self.c
        for consume in (False, True):
            observations = []
            for selected in (False, True):
                session, events = c.session(selected=selected), []
                document, request = {'document': 1}, {'request': 2}
                a, b = session.register(document), session.register(request)
                value, argument, register = session.value, session.argument, session.register
                class Foreign:
                    def __getattribute__(self, name):
                        raise AssertionError('unrequested callable attribute: ' + name)
                    def __call__(self, left, right):
                        events.append(('call', left is document, right is request))
                        return left, right
                provider = Foreign()
                class Common(dict):
                    def __getitem__(self, key):
                        events.append(('provider', key))
                        return dict.__getitem__(self, key)
                session.common = Common(session.common)
                session.common['apply_program_patch'] = provider
                def read(handle):
                    events.append(('value', 'document' if handle == a else 'request'))
                    return value(handle)
                def arg(handle, position):
                    events.append(('argument', handle == b, position))
                    return argument(handle, position)
                def store(item):
                    events.append(('register', 'document' if item is document else 'request'))
                    return register(item)
                session.value, session.argument, session.register = read, arg, store
                session.consume_mask = 2 if consume else 0
                row, handles, error = c.observe('order-%s-%s' % (consume, selected),
                    lambda: session._effect(13, a, b, 0, 0))
                session.value, session.argument, session.register = value, argument, register
                self.assertIsNone(error)
                self.assertEqual(handles[2], 0)
                self.assertIs(value(handles[0]), document)
                self.assertIs(value(handles[1]), request)
                self.assertEqual(events[:3], [('provider', 'apply_program_patch'),
                    ('value', 'document'), ('argument', True, 1)])
                self.assertEqual(events[-3:], [('call', True, True),
                    ('register', 'document'), ('register', 'request')])
                self.assert_foreign_patch(row)
                if consume:
                    with self.assertRaises(RuntimeError):
                        value(b)
                else:
                    self.assertIs(value(b), request)
                observations.append(events)
            self.assertEqual(*observations)

    def test_absent_forged_and_stale_tokens_use_captured_foreign_once(self):
        c = self.c
        fake = object.__new__(c.records.PatchDefinitionRecord)
        candidates = (None, {}, object(), fake, c.records.record_receipt(c.record))
        serial = c.records._NEXT_SERIAL
        for index, token in enumerate(candidates):
            with self.subTest(case=index):
                selected = c.adapter.select_patch_inspect_cli(c.base.selected, token)
                self.assertIs(selected, c.base.selected)
                session, calls = c.session(owner=selected), []
                left, right = {'left': index}, {'right': index}
                class Foreign:
                    def __getattribute__(self, name):
                        raise AssertionError('foreign callable probe: ' + name)
                    def __call__(self, a, b):
                        calls.append((a is left, b is right))
                        return a, b
                session.common['apply_program_patch'] = Foreign()
                row, value, error = c.observe('unissued-' + str(index),
                    lambda: c.call13(session, left, right))
                self.assertIsNone(error)
                self.assertIs(value[0], left)
                self.assertIs(value[1], right)
                self.assertEqual(calls, [(True, True)])
                self.assert_foreign_patch(row)
        entry = c.patch_owner._entry
        try:
            c.patch_owner._entry = object()
            self.assertIsNone(c.records.selected_record(c.record))
            self.assertIs(c.adapter.select_patch_inspect_cli(c.base.selected, c.record), c.base.selected)
        finally:
            c.patch_owner._entry = entry
        self.assertIs(c.records.selected_record(c.record), c.record)
        self.assertIsNone(c.records.selected_record(fake))
        self.assertEqual(c.records._NEXT_SERIAL, serial)

    def test_original_import_operands_failures_and_update_commit(self):
        c = self.c
        expected = [('import', 'hia_program', ('verify_program',), 1),
            ('import', 'hia_program_tools', ('read_bounded', 'decode_json', 'inspect_program',
             'apply_program_patch', 'publish_program'), 1)]
        for mode in ('canonical', 'same-shaped-foreign'):
            observations = []
            for selected in (False, True):
                session, events = c.session(selected=selected, imports=False), []
                clone = ModuleType(c.module.__name__)
                clone.__dict__.update(c.module.__dict__)
                def route(old, name, globals, locals, fromlist, level):
                    if mode == 'same-shaped-foreign' and name == 'hia_program_tools':
                        return clone
                    return old(name, globals, locals, fromlist, level)
                with import_route(c, route, events):
                    session._effect(35, 0, 0, 0, 0)
                self.assertEqual(events, expected)
                document, request = c.fixture()
                row, _, error = c.observe(mode + '-' + str(selected),
                    lambda: c.call13(session, document, request))
                self.assertIsNone(error)
                if selected and mode == 'canonical':
                    self.assert_native_patch(row)
                else:
                    self.assert_foreign_patch(row)
                observations.append(comparable(row))
            self.assertEqual(*observations)
        for failing in ('hia_program', 'hia_program_tools', 'update'):
            outcomes = []
            for selected in (False, True):
                session, events = c.session(selected=selected, imports=False), []
                failure = ImportError('real op35 failure ' + failing)
                class Common(dict):
                    def update(self, **values):
                        events.append(('update', tuple(values)))
                        if failing == 'update':
                            raise failure
                        return dict.update(self, **values)
                session.common = Common()
                def route(old, name, globals, locals, fromlist, level):
                    if name == failing:
                        raise failure
                    return old(name, globals, locals, fromlist, level)
                with import_route(c, route, events):
                    row, _, error = c.observe('import-fail-%s-%s' % (failing, selected),
                        lambda: session._effect(35, 0, 0, 0, 0))
                self.assertIs(error, failure)
                self.assert_foreign_patch(row)
                self.assertEqual(session.common, {})
                outcomes.append((events, comparable(row)))
            self.assertEqual(*outcomes)

    def test_captured_alias_survives_late_public_replacement(self):
        c = self.c
        results = []
        for selected in (False, True):
            session, events = c.session(selected=selected), []
            document, request = c.fixture()
            a, b = session.register(document), session.register(request)
            real_value = session.value
            captured = session.common['apply_program_patch']
            original_alias = c.tools.apply_program_patch
            def forbidden(*args):
                raise AssertionError('captured provider was looked up again')
            def read(handle):
                if handle == a:
                    events.append('document')
                    session.common['apply_program_patch'] = forbidden
                    c.tools.apply_program_patch = forbidden
                else:
                    events.append('request')
                return real_value(handle)
            session.value = read
            try:
                row, handles, error = c.observe('late-public-alias-' + str(selected),
                    lambda: session._effect(13, a, b, 0, 0))
            finally:
                session.value = real_value
                c.tools.apply_program_patch = original_alias
            self.assertIsNone(error)
            self.assertIs(captured, original_alias)
            self.assertEqual(events, ['document', 'request'])
            result = real_value(handles[0]), real_value(handles[1])
            if selected:
                self.assert_native_patch(row)
            else:
                self.assert_foreign_patch(row)
            results.append(plain(result))
        self.assertEqual(*results)

    def test_permissions_report_and_inspect_keep_original_delegates(self):
        c = self.c
        for selected in (False, True):
            session, calls = c.session(selected=selected), []
            class Permission:
                def consume_legacy_port(self, actual_session, operation, a, b, c, d):
                    calls.append((actual_session is session, operation, a, b, c, d))
                    return 7, 8, 9
            class Common(dict):
                def __getitem__(self, key):
                    raise AssertionError('provider was observed before permission')
            session.common = Common()
            session.discovery_permission = Permission()
            row, result, error = c.observe('permission-' + str(selected),
                lambda: session._effect(13, 11, 12, 13, 14))
            self.assertIsNone(error)
            self.assertEqual(result, (7, 8, 9))
            self.assertEqual(calls, [(True, 13, 11, 12, 13, 14)])
            self.assert_foreign_patch(row)
        document, _ = c.fixture()
        verified = c.program.verify_program(document)
        for operation, item, image in ((9, verified, 'verified_report'), (10, document, 'inspect')):
            rows = []
            for selected in (False, True):
                session = c.session(selected=selected)
                handle = session.register(item)
                def call():
                    result, second, third = session._effect(operation, handle, 0, 0, 0)
                    self.assertEqual((second, third), (0, 0))
                    return session.value(result)
                row, _, error = c.observe('unchanged-op%d-%s' % (operation, selected), call)
                self.assertIsNone(error)
                self.assertGreater(row['call_delta'][image], 0)
                self.assert_foreign_patch(row)
                rows.append(comparable(row))
            self.assertEqual(*rows)
        # A real public report-method replacement stays a once-called foreign
        # provider through the unchanged report closure.
        reports = []
        def foreign_report(actual):
            reports.append(actual is verified)
            return {'foreign_report': True}
        session = c.session()
        handle = session.register(verified)
        with patch.object(type(verified), 'report', foreign_report):
            def call_report():
                result, second, third = session._effect(9, handle, 0, 0, 0)
                self.assertEqual((second, third), (0, 0))
                return session.value(result)
            row, result, error = c.observe('foreign-public-report', call_report)
        self.assertIsNone(error)
        self.assertEqual(result, {'foreign_report': True})
        self.assertEqual(reports, [True])
        self.assertEqual(row['call_delta']['verified_report'], 0)
        self.assert_foreign_patch(row)
        # A replaced public prepare creates its real session and effect. It
        # is not accepted as the known report/inspect closure by op13.
        from hepta.hia_cli_verified_report_native import NativeReportCli
        original_prepare, prepare_calls, effects = NativeReportCli.prepare, [], []
        def replaced_prepare(owner, argv, cli):
            session = original_prepare(owner, argv, cli)
            previous = session._effect
            prepare_calls.append('actual-original-prepare')
            def delegated(operation, a, b, c, d):
                if operation == 13:
                    effects.append('foreign-report-effect')
                return previous(operation, a, b, c, d)
            session._effect = delegated
            return session
        with patch.object(NativeReportCli, 'prepare', replaced_prepare):
            session = c.session()
            document, request = c.fixture()
            row, _, error = c.observe('changed-public-report-prepare',
                lambda: c.call13(session, document, request))
        self.assertIsNone(error)
        self.assertEqual(prepare_calls, ['actual-original-prepare'])
        self.assertEqual(effects, ['foreign-report-effect'])
        self.assert_foreign_patch(row)
        self.assertEqual(row['old_policy_calls'].count('apply_program_patch'), 1)

    def test_argument_unpack_and_register_exceptions_are_not_retried(self):
        c = self.c
        for fail_at in ('document', 'request', 'provider', 'register-first'):
            observations = []
            for selected in (False, True):
                session, events = c.session(selected=selected), []
                document, request = {'document': 1}, {'request': 2}
                a, b = session.register(document), session.register(request)
                read, argument, register = session.value, session.argument, session.register
                failure = ForeignFailure('actual foreign failure at ' + fail_at)
                def provider(left, right):
                    events.append('call')
                    if fail_at == 'provider':
                        raise failure
                    return left, right
                def value(handle):
                    name = 'document' if handle == a else 'request'
                    events.append(name)
                    if fail_at == name:
                        raise failure
                    return read(handle)
                def store(item):
                    events.append('register')
                    if fail_at == 'register-first':
                        raise failure
                    return register(item)
                session.common['apply_program_patch'] = provider
                session.value, session.register = value, store
                try:
                    row, _, error = c.observe('operand-failure-%s-%s' % (fail_at, selected),
                        lambda: session._effect(13, a, b, 0, 0))
                finally:
                    session.value, session.argument, session.register = read, argument, register
                self.assertIs(error, failure)
                self.assertLessEqual(events.count('call'), 1)
                self.assertLessEqual(events.count('register'), 1)
                self.assert_foreign_patch(row)
                observations.append((events, comparable(row)))
            self.assertEqual(*observations)
        for count in (0, 1, 2, 3):
            observations = []
            for selected in (False, True):
                session, events = c.session(selected=selected), []
                a, b = session.register({'document': 1}), session.register({'request': 2})
                original_register = session.register
                class Values:
                    def __iter__(self):
                        events.append('iter')
                        for index in range(count):
                            events.append(('yield', index))
                            yield {'index': index}
                        events.append('exhausted')
                def provider(left, right):
                    events.append('call')
                    return Values()
                def register(item):
                    events.append(('register', item['index']))
                    return original_register(item)
                session.common['apply_program_patch'], session.register = provider, register
                try:
                    row, _, error = c.observe('unpack-%d-%s' % (count, selected),
                        lambda: session._effect(13, a, b, 0, 0))
                finally:
                    session.register = original_register
                self.assertEqual(error is None, count == 2)
                if count != 2:
                    self.assertIsInstance(error, ValueError)
                    self.assertFalse(any(type(item) is tuple and item[0] == 'register' for item in events))
                else:
                    self.assertEqual(events[-3:], ['exhausted', ('register', 0), ('register', 1)])
                self.assertEqual(events.count('call'), 1)
                self.assert_foreign_patch(row)
                observations.append((events, comparable(row)))
            self.assertEqual(*observations)

    def test_real_policy_keeps_captured_verifier_and_late_prepare(self):
        c = self.c
        outcomes = []
        for selected in (False, True):
            session = c.session(selected=selected)
            document, request = c.fixture()
            events = []
            verify, prepare = c.program.verify_program, c.tools._prepare_program_patch
            def forbidden(*args):
                raise AssertionError('original imported verifier was looked up twice')
            def late_prepare(original, packet):
                events.append('late-prepare')
                return prepare(original, packet)
            def first_prepare(*args):
                raise AssertionError('prepare was captured before original verification')
            def observed_verify(value):
                events.append('verify-original' if value is document else 'verify-candidate')
                if value is document:
                    c.program.verify_program = forbidden
                    c.tools._prepare_program_patch = late_prepare
                return verify(value)
            with patch.object(c.program, 'verify_program', observed_verify), \
                    patch.object(c.tools, '_prepare_program_patch', first_prepare):
                row, result, error = c.observe('captured-verifier-' + str(selected),
                    lambda: c.call13(session, document, request))
            self.assertIsNone(error)
            self.assertEqual(events, ['verify-original', 'late-prepare', 'verify-candidate'])
            if selected:
                self.assert_native_patch(row)
            outcomes.append((events, plain(result)))
        self.assertEqual(*outcomes)
        for selected in (False, True):
            session, events = c.session(selected=selected), []
            document, request = c.fixture()
            failure = ForeignFailure('actual policy provider error')
            def refusing(value):
                events.append(value is document)
                raise failure
            with patch.object(c.program, 'verify_program', refusing):
                row, _, error = c.observe('real-policy-error-' + str(selected),
                    lambda: c.call13(session, document, request))
            self.assertIs(error, failure)
            self.assertEqual(events, [True])
            if selected:
                self.assert_native_patch(row)

    def test_definition_invalidation_after_arguments_calls_captured_provider_once(self):
        c = self.c
        for changed in ('code', 'defaults', 'entry'):
            results = []
            for selected in (False, True):
                session = c.session(selected=selected)
                document, request = c.fixture()
                a, b = session.register(document), session.register(request)
                provider = session.common['apply_program_patch']
                code, defaults, entry = provider.__code__, provider.__defaults__, c.patch_owner._entry
                original_argument = session.argument
                def replacement(document, request):
                    return document, request
                def invalidating(handle, position):
                    value = original_argument(handle, position)
                    if changed == 'code':
                        provider.__code__ = replacement.__code__
                    elif changed == 'defaults':
                        provider.__defaults__ = (None,)
                    else:
                        c.patch_owner._entry = object()
                    return value
                session.argument = invalidating
                try:
                    row, handles, error = c.observe('invalidate-%s-%s' % (changed, selected),
                        lambda: session._effect(13, a, b, 0, 0))
                finally:
                    session.argument = original_argument
                    provider.__code__, provider.__defaults__ = code, defaults
                    c.patch_owner._entry = entry
                self.assertIsNone(error)
                self.assert_foreign_patch(row)
                result = session.value(handles[0]), session.value(handles[1])
                if changed != 'code':
                    self.assertEqual(row['old_policy_calls'].count('apply_program_patch'), 1)
                results.append(plain(result))
            self.assertEqual(*results)
        self.assertIs(c.records.selected_record(c.record), c.record)

    def test_explicit_signature_admission_and_late_foreign_signature(self):
        c = self.c
        self.assertTrue(support.context()['signature_native'], 'this group needs actual Inspect admission')
        self.assertIs(c.patch_owner._signature.admission.owner, c.base.owner)
        document, request = c.fixture()
        session = c.session()
        row, expected, error = c.observe('real-Patch-plus-Inspect',
            lambda: c.call13(session, document, request))
        self.assertIsNone(error)
        self.assert_native_patch(row)
        self.assertGreater(row['call_delta']['inspect'], 0)
        self.assertNotIn('function_signature', row['old_policy_calls'])
        original_signature, calls = c.tools.function_signature, []
        class ForeignSignature:
            def __getattribute__(self, name):
                raise AssertionError('foreign signature attribute probe: ' + name)
            def __call__(self, function, *, include_return_loans):
                calls.append((function['name'], include_return_loans))
                return original_signature(function, include_return_loans=include_return_loans)
        with patch.object(c.tools, 'function_signature', ForeignSignature()):
            row, actual, error = c.observe('actual-late-foreign-signature',
                lambda: c.call13(session, document, request))
        self.assertIsNone(error)
        self.assertEqual(plain(actual), plain(expected))
        self.assertTrue(calls)
        self.assertTrue(all(value is True for _, value in calls))
        self.assert_native_patch(row)
        self.assertEqual(row['call_delta']['inspect'], 0)
        keywords = dict(original_signature.__kwdefaults__)
        try:
            original_signature.__kwdefaults__['include_return_loans'] = True
            row, actual, error = c.observe('signature-definition-invalidated',
                lambda: c.call13(session, document, request))
        finally:
            original_signature.__kwdefaults__.clear()
            original_signature.__kwdefaults__.update(keywords)
        self.assertIsNone(error)
        self.assertEqual(plain(actual), plain(expected))
        self.assert_native_patch(row)
        self.assertEqual(row['call_delta']['inspect'], 0)

    def test_real_error_pending_reentry_and_lost_claim_never_retry(self):
        c = self.c
        document, request = c.fixture()
        session = c.session()
        failure, calls = ForeignFailure('inside actual Patch HIA'), []
        def refusing(value):
            calls.append(value is document)
            raise failure
        with patch.object(c.program, 'verify_program', refusing):
            row, _, error = c.observe('op13-real-provider-error',
                lambda: c.call13(session, document, request))
        self.assertIs(error, failure)
        self.assertEqual(calls, [True])
        self.assert_native_patch(row)
        # A direct actual Patch frame isolates the continuation boundary.
        # It neither edits nor requalifies the retained R5 witness10 contract.
        frame = c.patch_owner.prepare('apply_program_patch', (document, request))
        verify, reentries = c.program.verify_program, []
        def reenter(value):
            before = (c.patch_owner.entries, bytes(frame.state), bytes(frame.output),
                      frame.pending, frame.closed, frame._uncertain)
            with self.assertRaises(RuntimeError):
                frame.drive()
            self.assertEqual((c.patch_owner.entries, bytes(frame.state), bytes(frame.output),
                              frame.pending, frame.closed, frame._uncertain), before)
            self.assertTrue(frame.executed and not frame.completed)
            reentries.append('original' if value is document else 'candidate')
            return verify(value)
        with patch.object(c.program, 'verify_program', reenter):
            row, _, error = c.observe('actual-Patch-pending-boundary', lambda: c.patch_owner.finish(frame))
        self.assertIsNone(error)
        self.assertEqual(reentries, ['original', 'candidate'])
        self.assert_native_patch(row)
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        before_keys = set(_UNCONFIRMED_RETIREMENTS)
        c.gate.armed = True
        row, _, error = c.observe('lost-claim', lambda: c.call13(c.session(), document, request))
        self.assertIsInstance(error, LostPatchReturn)
        self.assertEqual(len(c.gate.losses), 1)
        self.assert_native_patch(row)
        unknown = [_UNCONFIRMED_RETIREMENTS[key]
                   for key in set(_UNCONFIRMED_RETIREMENTS) - before_keys]
        self.assertTrue(unknown)
        before = c.counts()['patch']
        for held in unknown:
            self.assertIs(held.image, c.patch_owner)
            self.assertTrue(held._uncertain and held.closed)
            for call in (held.step, held.drive, held.take, lambda: held.service(held.pending)):
                with self.assertRaises(RuntimeError):
                    call()
                self.assertEqual(c.counts()['patch'], before)
        publish(c.directory / 'UNKNOWN-BOUNDARY.json', {
            'losses': c.gate.losses, 'nonces': [held.nonce for held in unknown],
            'no_foreign_retry': 'apply_program_patch' not in row['old_policy_calls'],
            'no_calls_after_unknown': True, 'frames_retired': False,
            'quarantine_retained_until_owned_child_exit': True,
            'retained_R5_witness10_still_failed': True})

    def test_preissued_record_lifetimes_and_failed_issuance_cleanup(self):
        c = self.c
        from hepta import hia_patch_result_native as component
        cfg = support.context()
        token = observed_admission(component.NativePatchResult, c.directory / 'lifetime-admission',
            c.records.issue_preselected_patch_record, cfg['patch_manifest'])
        key, weak_token = id(token), weakref.ref(token)
        selected = c.adapter.select_patch_inspect_cli(c.base.selected, token)
        self.assertIs(type(selected), c.adapter.NativePatchInspectReportCli)
        argv, _ = c.patch_files()
        session = selected.prepare(argv, c.cli)
        weak_session = weakref.ref(session)
        del token, selected
        self.assertIsNotNone(weak_token())
        del session
        gc.collect()
        self.assertIsNone(weak_session())
        self.assertIsNone(weak_token())
        self.assertNotIn(key, c.records._RECORDS)
        actual_admit = component.admit_patch_result
        captured, serial, keys = [], c.records._NEXT_SERIAL, set(c.records._RECORDS)
        original = c.tools.apply_program_patch
        defaults = original.__defaults__
        def changed_after_actual_admission(*args, **kwargs):
            admission = actual_admit(*args, **kwargs)
            captured.append(admission)
            original.__defaults__ = (None,)
            return admission
        try:
            with patch.object(component, 'admit_patch_result', changed_after_actual_admission):
                with self.assertRaises(ValueError):
                    observed_admission(component.NativePatchResult, c.directory / 'failed-issuance-admission',
                        c.records.issue_preselected_patch_record, cfg['patch_manifest'])
        finally:
            original.__defaults__ = defaults
        self.assertEqual(len(captured), 1, 'negative path still needs one actual admitted mapping')
        failed = captured[0].owner
        self.assertIsNone(failed._entry)
        self.assertTrue(failed._mapping.closed)
        self.assertEqual(set(c.records._RECORDS), keys)
        self.assertEqual(c.records._NEXT_SERIAL, serial)
        self.assertIs(c.records.selected_record(c.record), c.record)
        publish(c.directory / 'RECORD-LIFETIMES.json', {
            'independent_record_released_after_session': True,
            'session_not_retained_by_weak_closure': True,
            'actual_failed_owner_entry_revoked': failed._entry is None,
            'actual_failed_mapping_closed': failed._mapping.closed,
            'issuer_registry_unchanged_after_failure': True,
            'original_two_bodies_unchanged': True,
            'no_history_or_current_cold_claim': True})


if __name__ == '__main__':
    unittest.main()
