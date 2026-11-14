"""Twelve executable, real-image groups. No test is executed by importing.

One named method per fresh owned child. Direct-port controls are labeled as
such; only the full CLI run controls establish the positive op10 route.
"""
from __future__ import annotations

import builtins
from contextlib import contextmanager, ExitStack
import gc
import json
from pathlib import Path
import sys
from types import ModuleType
import unittest
import weakref

import inspect_cli_control_support as support
from inspect_cli_control_support import (
    ActualComponents, LostActualReturn, changed_attr, comparable, plain,
)
from inspect_exec_support import publish


class ImportFailure(Exception):
    pass


class ForeignFailure(Exception):
    pass


@contextmanager
def import_route(components, route, events):
    """Observe exactly the old effect globals' actual import calls.

    Imports performed by the real policy or the observer are not relabeled as
    op35 imports. The actual f_builtins mapping remains the mapping used by
    both original code and the instruction-slice port.
    """
    old = builtins.__import__
    effect_globals = components.original_effect.__globals__
    def observed(name, globals=None, locals=None, fromlist=(), level=0):
        if globals is effect_globals and level == 1 and name in ('hia_program', 'hia_program_tools'):
            events.append(('import', name, tuple(fromlist), level))
            return route(old, name, globals, locals, fromlist, level)
        return old(name, globals, locals, fromlist, level)
    builtins.__import__ = observed
    try:
        yield
    finally:
        builtins.__import__ = old


class InspectCliWitnessControls(unittest.TestCase):
    def setUp(self):
        self.c = ActualComponents(Path(support.CONTEXT['controls_output']))
        self.addCleanup(self.c.close)

    def assert_native_inspect(self, row):
        self.assertGreater(row['call_delta']['inspect'], 0, 'no real inspect HIA entry')
        self.assertEqual(row['old_policy_calls'], [], 'original policy body was a positive fallback')

    def assert_foreign(self, row):
        self.assertEqual(row['call_delta']['inspect'], 0, 'foreign route entered inspect HIA')

    def test_actual_record_and_hia_op10(self):
        c = self.c
        argv = ['inspect', str(c.source_file())]
        old, _, old_error = c.observe('full-cli-reference', lambda: c.report.run(argv, c.cli))
        new, _, new_error = c.observe('full-cli-selected', lambda: c.selected.run(argv, c.cli))
        self.assertIsNone(old_error)
        self.assertIsNone(new_error)
        self.assertEqual(comparable(new), comparable(old))
        self.assertGreater(old['old_policy_calls'].count('inspect_program'), 0)
        self.assert_native_inspect(new)
        self.assertGreater(new['call_delta']['control'], 0)
        self.assertGreater(new['call_delta']['routing'], 0)
        self.assertIs(c.records.selected_record(c.record), c.record)
        self.assertIs(c.records._state(c.record).entry, c.gate)
        # The source modules, original native address, two actual admissions
        # and every real before/after frame are separately persisted by setup.
        self.assertEqual(len(c.native_origins), 7)

    def test_missing_unknown_and_forged_records(self):
        c = self.c
        fake = object.__new__(c.records.DefinitionRecord)
        candidates = [None, {}, c.records.record_receipt(c.record), object(), fake]
        serial = c.records._NEXT_SERIAL
        for index, token in enumerate(candidates):
            with self.subTest(case=index):
                selected = c.adapter.select_inspect_report_cli(c.report, token)
                self.assertIs(selected, c.report)
                session = c.session(owner=selected)
                calls, document, answer = [], object(), {'foreign': index}
                def provider(value):
                    calls.append(value)
                    return answer
                session.common['inspect_program'] = provider
                row, result, error = c.observe('unissued-%d-direct-port' % index,
                    lambda: c.call10(session, document))
                self.assertIsNone(error)
                self.assertIs(result, answer)
                self.assertEqual(len(calls), 1)
                self.assertIs(calls[0], document)
                self.assert_foreign(row)
        self.assertEqual(c.records._NEXT_SERIAL, serial)
        self.assertIsNone(c.records.selected_record(fake))

    def test_same_shape_module_replacement(self):
        c = self.c
        clone = ModuleType(c.module.__name__)
        clone.__dict__.update(c.module.__dict__)
        self.assertIs(clone.inspect_program, c.module.inspect_program)
        self.assertFalse(c.records.imported_operand_matches(c.record, clone))
        def route(old, name, globals, locals, fromlist, level):
            if name == 'hia_program_tools':
                return clone
            return old(name, globals, locals, fromlist, level)
        outcomes = []
        for selected in (False, True):
            events = []
            with import_route(c, route, events):
                owner = c.selected if selected else c.report
                row, _, error = c.observe('same-shaped-module-' + str(selected),
                    lambda: owner.run(['inspect', str(c.source_file())], c.cli))
            self.assertIsNone(error)
            self.assert_foreign(row)
            self.assertEqual(row['old_policy_calls'].count('inspect_program'), 1)
            self.assertEqual([item[1] for item in events], ['hia_program', 'hia_program_tools'])
            outcomes.append(comparable(row))
        self.assertEqual(outcomes[0], outcomes[1])

    def test_import_provider_and_operand_order(self):
        c = self.c
        expected = [('import', 'hia_program', ('verify_program',), 1),
            ('import', 'hia_program_tools', ('read_bounded', 'decode_json', 'inspect_program',
             'apply_program_patch', 'publish_program'), 1)]
        observations = []
        for selected in (False, True):
            session, events = c.session(selected=selected), []
            first = {'seen': False}
            clone = ModuleType(c.module.__name__)
            clone.__dict__.update(c.module.__dict__)
            def route(old, name, globals, locals, fromlist, level):
                if name == 'hia_program':
                    first['seen'] = True
                    return old(name, globals, locals, fromlist, level)
                self.assertTrue(first['seen'], 'second import preceded the first side effect')
                events.append(('first-import-effect-visible',))
                return clone
            with import_route(c, route, events):
                result = session._effect(35, 0, 0, 0, 0)
            self.assertEqual(result, (0, 0, 0))
            self.assertEqual([item for item in events if item[0] == 'import'], expected)
            self.assertEqual(tuple(session.common), tuple(expected[0][2] + expected[1][2]))
            self.assertIs(session.common['inspect_program'], c.module.inspect_program)
            observations.append(events)
        self.assertEqual(observations[0], observations[1])
        publish(c.directory / 'IMPORT-ORDER.json', {'observations': observations,
            'actual_original_f_builtins_import_provider': True,
            'module_operand_is_selection_evidence_not_provenance': True})

    def test_every_import_failure(self):
        c = self.c
        fields = ('verify_program', 'read_bounded', 'decode_json', 'inspect_program',
                  'apply_program_patch', 'publish_program')
        cases = [('import', 'hia_program'), ('import', 'hia_program_tools')]
        cases += [('field', field) for field in fields]
        evidence = []
        for kind, target in cases:
            pair = []
            for selected in (False, True):
                session, events = c.session(selected=selected), []
                failure = ImportFailure(kind + ':' + target)
                class Namespace:
                    def __init__(self, module):
                        self.module = module
                    def __getattribute__(self, name):
                        if name in fields:
                            events.append(('field', name))
                            if kind == 'field' and name == target:
                                raise failure
                            return getattr(object.__getattribute__(self, 'module'), name)
                        return object.__getattribute__(self, name)
                class Common(dict):
                    def update(self, **kwargs):
                        events.append(('update', tuple(kwargs)))
                        return dict.update(self, **kwargs)
                session.common = Common(unchanged='sentinel')
                def route(old, name, globals, locals, fromlist, level):
                    if kind == 'import' and name == target:
                        raise failure
                    return Namespace(c.program if name == 'hia_program' else c.module)
                with import_route(c, route, events):
                    row, _, caught = c.observe('failure-%s-%s-%s' % (kind, target, selected),
                                              lambda: session._effect(35, 0, 0, 0, 0))
                self.assertIs(caught, failure)
                self.assertEqual(session.common, {'unchanged': 'sentinel'})
                self.assertNotIn('update', [item[0] for item in events])
                self.assert_foreign(row)
                pair.append(events)
                evidence.append({'kind': kind, 'target': target, 'selected': selected,
                                 'events': events, 'same_exception_object': caught is failure,
                                 'actual_traceback': row['traceback']})
            self.assertEqual(pair[0], pair[1])
        publish(c.directory / 'IMPORT-FAILURES.json', {'cases': evidence,
            'new_private_traceback_frames_are_explicit': True})

    def test_definition_and_owner_drift(self):
        c = self.c
        original = c.module.inspect_program
        signature = c.module.function_signature
        def replacement(document):
            return {'replacement': True}
        c.old_codes[replacement.__code__] = 'mutated-inspect-body'
        changes = [
            (original, '__code__', replacement.__code__),
            (original, '__defaults__', (None,)),
            (original, '__kwdefaults__', {}),
            (signature, '__kwdefaults__', {'include_return_loans': True}),
            (c.owner, 'builtins', dict(c.owner.builtins)),
            (c.owner, 'image_sha256', '0' * 64),
            (c.owner, '_admitted_source_sha256', '0' * 64),
            (c.owner, '_mapping', object()),
            (c.owner, '_entry', object()),
        ]
        for index, (target, name, replacement_value) in enumerate(changes):
            with self.subTest(case=index, attribute=name):
                session = c.ports(c.session())
                before = c.counts()['inspect']
                with changed_attr(target, name, replacement_value):
                    self.assertIsNone(c.records.selected_record(c.record))
                    row, _, error = c.observe('drift-%d-direct-port' % index,
                        lambda: c.call10(session, c.fixture()))
                self.assertIsNone(error)
                self.assert_foreign(row)
                self.assertEqual(c.counts()['inspect'], before)
                if name != '__code__':
                    self.assertEqual(row['old_policy_calls'].count('inspect_program'), 1)
                else:
                    self.assertEqual(row['old_policy_calls'].count('mutated-inspect-body'), 1)
                self.assertIs(c.records.selected_record(c.record), c.record)
        # In-place keyword mutation is distinct from replacing its dict.
        session = c.ports(c.session())
        original_default = signature.__kwdefaults__['include_return_loans']
        try:
            signature.__kwdefaults__['include_return_loans'] = True
            self.assertIsNone(c.records.selected_record(c.record))
            row, _, error = c.observe('in-place-default-direct-port', lambda: c.call10(session, c.fixture()))
            self.assertIsNone(error)
            self.assert_foreign(row)
        finally:
            signature.__kwdefaults__['include_return_loans'] = original_default

    def test_provider_then_argument(self):
        c = self.c
        pair = []
        for selected in (False, True):
            session = c.ports(c.session(selected=selected))
            events, document = [], c.fixture()
            def first(value):
                events.append(('first', value is document))
                return {'provider': 'first'}
            def second(value):
                events.append(('second', value is document))
                return {'provider': 'second'}
            class Common(dict):
                def __getitem__(self, key):
                    events.append(('select', key))
                    return dict.__getitem__(self, key)
            session.common = Common(session.common)
            session.common['inspect_program'] = first
            original_value = session.value
            def value(handle):
                events.append(('argument',))
                session.common['inspect_program'] = second
                return original_value(handle)
            handle = session.register(document)
            session.value = value
            try:
                row, result, error = c.observe('provider-before-argument-' + str(selected),
                    lambda: session._effect(10, handle, 0, 0, 0))
            finally:
                session.value = original_value
            self.assertIsNone(error)
            self.assertEqual(original_value(result[0]), {'provider': 'first'})
            self.assertEqual(events, [('select', 'inspect_program'), ('argument',), ('first', True)])
            self.assert_foreign(row)
            pair.append(events)
        self.assertEqual(pair[0], pair[1])

        # A mutation during argument evaluation is checked at the real call.
        session = c.ports(c.session())
        provider, value = c.module.inspect_program, session.value
        old_code = provider.__code__
        def changed(document):
            return {'changed-during-argument': True}
        c.old_codes[changed.__code__] = 'argument-time-inspect-body'
        handle = session.register(c.fixture())
        def mutate(handle):
            provider.__code__ = changed.__code__
            return value(handle)
        session.value = mutate
        try:
            row, result, error = c.observe('definition-after-argument',
                lambda: session._effect(10, handle, 0, 0, 0))
        finally:
            provider.__code__ = old_code
            session.value = value
        self.assertIsNone(error)
        self.assertEqual(value(result[0]), {'changed-during-argument': True})
        self.assert_foreign(row)
        self.assertEqual(row['old_policy_calls'].count('argument-time-inspect-body'), 1)

        # A nested op35 cannot replace the witness already put on this call's
        # operand stack. It does replace the witness for the next call.
        session = c.ports(c.session())
        value = session.value
        handle = session.register(c.fixture())
        clone = ModuleType(c.module.__name__)
        clone.__dict__.update(c.module.__dict__)
        events = []
        def route(old, name, globals, locals, fromlist, level):
            return clone if name == 'hia_program_tools' else old(name, globals, locals, fromlist, level)
        def nested(handle):
            with import_route(c, route, events):
                session._effect(35, 0, 0, 0, 0)
            return value(handle)
        session.value = nested
        try:
            row, _, error = c.observe('held-witness-during-argument-reentry',
                lambda: session._effect(10, handle, 0, 0, 0))
        finally:
            session.value = value
        self.assertIsNone(error)
        self.assert_native_inspect(row)
        row, _, error = c.observe('next-call-uses-new-foreign-witness',
                                  lambda: c.call10(session, c.fixture()))
        self.assertIsNone(error)
        self.assert_foreign(row)
        self.assertEqual(row['old_policy_calls'].count('inspect_program'), 1)

    def test_foreign_attribute_poison(self):
        c = self.c
        for raises in (False, True):
            with self.subTest(raises=raises):
                session = c.ports(c.session())
                document, events, probes = object(), [], []
                failure = ForeignFailure('actual captured provider failure')
                class Foreign:
                    def __getattribute__(self, name):
                        probes.append(name)
                        raise AssertionError('foreign metadata attribute observed: ' + name)
                    def __call__(self, value):
                        events.append(value is document)
                        if raises:
                            raise failure
                        return {'foreign': True}
                session.common['inspect_program'] = Foreign()
                row, result, error = c.observe('foreign-poison-' + str(raises),
                    lambda: c.call10(session, document))
                self.assertEqual(events, [True])
                self.assertEqual(probes, [])
                self.assert_foreign(row)
                if raises:
                    self.assertIs(error, failure)
                else:
                    self.assertIsNone(error)
                    self.assertEqual(result, {'foreign': True})

    def test_common_update_reentry_and_failure(self):
        c = self.c
        required = ('verify_program', 'read_bounded', 'decode_json', 'inspect_program',
                    'apply_program_patch', 'publish_program')
        records = []
        for old_witness in (False, True):
            for fail_update in (False, True):
                with self.subTest(old_witness=old_witness, fail_update=fail_update):
                    session = c.session()
                    if old_witness:
                        c.ports(session)
                    else:
                        session.common['inspect_program'] = c.module.inspect_program
                    nested, events = [], []
                    failure = ForeignFailure('common.update actual failure')
                    class Common(dict):
                        def update(self, **kwargs):
                            events.append(('update', tuple(kwargs)))
                            row, _, caught = c.observe('update-reentry',
                                lambda: c.call10(session, c.fixture()))
                            nested.append(row)
                            if caught is not None:
                                raise caught
                            if fail_update:
                                raise failure
                            dict.update(self, **kwargs)
                    session.common = Common(session.common)
                    before = dict(session.common)
                    # New operand is deliberately foreign. It cannot clear
                    # an old witness before update has actually succeeded.
                    clone = ModuleType(c.module.__name__)
                    clone.__dict__.update(c.module.__dict__)
                    def route(old, name, globals, locals, fromlist, level):
                        return clone if name == 'hia_program_tools' else old(name, globals, locals, fromlist, level)
                    caught = None
                    try:
                        with import_route(c, route, events):
                            session._effect(35, 0, 0, 0, 0)
                    except BaseException as error:
                        caught = error
                    self.assertEqual(len(nested), 1)
                    if old_witness:
                        self.assert_native_inspect(nested[0])
                    else:
                        self.assert_foreign(nested[0])
                    self.assertEqual([item for item in events if item[0] == 'update'], [('update', required)])
                    if fail_update:
                        self.assertIs(caught, failure)
                        self.assertEqual(dict(session.common), before)
                    else:
                        self.assertIsNone(caught)
                    row, _, error = c.observe('after-common-update',
                        lambda: c.call10(session, c.fixture()))
                    self.assertIsNone(error)
                    if fail_update and old_witness:
                        self.assert_native_inspect(row)
                    else:
                        self.assert_foreign(row)
                    records.append({'old_witness': old_witness, 'failed': fail_update,
                                    'events': events, 'nested': nested, 'after': row})
        publish(c.directory / 'UPDATE-BOUNDARIES.json', {'cases': records})

    def test_entry_error_busy_unknown_no_retry(self):
        c = self.c
        session = c.ports(c.session())
        failure, calls = ForeignFailure('inside real HIA provider'), []
        def refusing(document):
            calls.append(document)
            raise failure
        with changed_attr(c.program, 'verify_program', refusing):
            row, _, error = c.observe('real-HIA-provider-error',
                lambda: c.call10(session, c.fixture()))
        self.assertIs(error, failure)
        self.assertEqual(len(calls), 1)
        self.assert_native_inspect(row)

        # Original executed-but-uncompleted boundary, on an actual component
        # frame. It is not counted as a full CLI positive control.
        frame = c.owner.prepare('inspect_program', (c.fixture(),))
        real_verify, reentries = c.program.verify_program, []
        def reenter(document):
            before = c.owner.entries
            with self.assertRaises(RuntimeError):
                frame.drive()
            self.assertEqual(c.owner.entries, before)
            self.assertTrue(frame.executed and not frame.completed)
            reentries.append('refused-without-machine-entry')
            return real_verify(document)
        with changed_attr(c.program, 'verify_program', reenter):
            row, _, error = c.observe('real-executed-pending-reentry', lambda: c.owner.finish(frame))
        self.assertIsNone(error)
        self.assertEqual(reentries, ['refused-without-machine-entry'])
        self.assert_native_inspect(row)

        # Last in this fresh child: the wrapper was captured BEFORE issuance.
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        session = c.ports(c.session())
        keys = set(_UNCONFIRMED_RETIREMENTS)
        c.gate.armed = 'first-real-claim'
        row, _, error = c.observe('lost-real-claim-via-op10', lambda: c.call10(session, c.fixture()))
        self.assertIsInstance(error, LostActualReturn)
        self.assertEqual(len(c.gate.losses), 1)
        self.assert_native_inspect(row)
        unknown = [_UNCONFIRMED_RETIREMENTS[k] for k in set(_UNCONFIRMED_RETIREMENTS) - keys]
        self.assertGreaterEqual(len(unknown), 1)
        before = c.counts()['inspect']
        for held in unknown:
            self.assertTrue(held._uncertain and held.closed)
            for call in (held.step, held.drive, lambda: held.service(held.pending), held.take):
                with self.assertRaises(RuntimeError):
                    call()
                self.assertEqual(c.counts()['inspect'], before)
        publish(c.directory / 'UNKNOWN-BOUNDARY.json', {
            'losses': c.gate.losses, 'quarantined_nonces': [held.nonce for held in unknown],
            'no_foreign_retry': row['old_policy_calls'] == [],
            'no_product_calls_after_unknown_refusals': True,
            'quarantine_is_retained_until_owned_child_exit': True})

    def test_operand_and_record_lifetimes(self):
        c = self.c
        observations = []
        for selected in (False, True):
            events, session = [], c.session(selected=selected)
            class Ephemeral(ModuleType):
                def __del__(self):
                    events.append('operand-released')
            class Common(dict):
                def update(self, **kwargs):
                    events.append('update')
                    return dict.update(self, **kwargs)
            session.common = Common()
            def route(old, name, globals, locals, fromlist, level):
                if name != 'hia_program_tools':
                    return old(name, globals, locals, fromlist, level)
                value = Ephemeral(c.module.__name__)
                value.__dict__.update(c.module.__dict__)
                return value
            imports = []
            with import_route(c, route, imports):
                session._effect(35, 0, 0, 0, 0)
            self.assertEqual(events, ['operand-released', 'update'])
            observations.append({'selected': selected, 'events': events, 'imports': imports})
        token = c.records.issue_preselected_inspect_record(support.CONTEXT['inspect_manifest'])
        key, weak_token = id(token), weakref.ref(token)
        selected = c.adapter.select_inspect_report_cli(c.report, token)
        del token
        self.assertIsNotNone(weak_token())
        del selected
        gc.collect()
        self.assertIsNone(weak_token())
        self.assertNotIn(key, c.records._RECORDS)
        session = c.session()
        held_session = weakref.ref(session)
        c.sessions.remove(session)
        del session
        gc.collect()
        self.assertIsNone(held_session(), 'new effect closure strongly retains its session')
        publish(c.directory / 'LIFETIMES.json', {
            'operand_events': observations, 'registry_entry_removed': key not in c.records._RECORDS,
            'unstepped_session_released': True, 'mapping_cache_owner_retention_is_separate': True,
            'claim_of_exact_frame_refcount_or_GC_timing_equivalence': False})

    def test_retained_report_discovery_parser_cli(self):
        c = self.c
        inputs = str(c.source_file())
        cases = [(['verify', inputs], 'verified_report'),
                 (['capabilities'], 'discovery'),
                 (['catalog', '--schema', 'hepta.hia.program.v8'], 'discovery'),
                 (['inspect', inputs], 'inspect'),
                 (['--help'], 'format'),
                 (['verify'], 'parser_context')]
        for argv, component in cases:
            with self.subTest(argv=argv):
                old, _, _ = c.observe('six-image-reference-' + component,
                                      lambda: c.report.run(argv, c.cli))
                new, _, _ = c.observe('seven-image-selected-' + component,
                                      lambda: c.selected.run(argv, c.cli))
                self.assertEqual(comparable(new), comparable(old))
                self.assertGreater(new['call_delta'][component], 0)
                if component == 'inspect':
                    self.assert_native_inspect(new)

        # A public report replacement remains the existing report closure's
        # actual captured method; the new adapter does not intercept op9.
        calls = []
        def report(instance):
            calls.append(type(instance).__name__)
            return {'ok': True, 'replaced-report': True}
        outcomes = []
        with changed_attr(c.program.VerifiedProgram, 'report', report):
            for selected in (False, True):
                owner = c.selected if selected else c.report
                row, _, error = c.observe('foreign-report-' + str(selected),
                    lambda: owner.run(['verify', inputs], c.cli))
                self.assertIsNone(error)
                self.assertEqual(row['call_delta']['verified_report'], 0)
                outcomes.append(comparable(row))
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(len(calls), 2)

        # An actual public inspect replacement selected by op35 is foreign
        # once; after capture, changing the public name cannot retarget it.
        calls = []
        def provider(document):
            calls.append(document)
            return {'foreign-inspect': True}
        session = c.session()
        with changed_attr(c.tools, 'inspect_program', provider):
            c.ports(session)
        row, result, error = c.observe('public-inspect-after-capture',
            lambda: c.call10(session, c.fixture()))
        self.assertIsNone(error)
        self.assertEqual(result, {'foreign-inspect': True})
        self.assertEqual(len(calls), 1)
        self.assert_foreign(row)

        # Future retained3 and CLI43 stages execute the exact original files
        # and IDs under the real bundle. This method does not impersonate them.
        publish(c.directory / 'DELEGATION.json', {
            'six_companions_exercised': list(support.COMPONENTS),
            'original_retained_groups_run_by_separate_owned_stages': True,
            'private_code_arbitrary_mutation_is_not_a_promised_sandbox': True})
