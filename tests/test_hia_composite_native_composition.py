"""Joint native types/signatures/origins and complete task-helper witnesses.

The two images must be built from the same completed current-source cold run.
Retained implementations are independent oracles before selection, and are
forbidden during the combined ordinary verification and VM execution paths.
This finite composition witness does not claim whole-stack native ownership.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_types_native import (
    SELECTOR as TYPES_SELECTOR, NativeCompositeTypeSession, _NativeTypeIdentity,
)
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from hepta.hia_task_helpers_native import SELECTOR as HELPERS_SELECTOR, NativeTaskHelpers
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans


COLD_REPORTS = ('HEPTA_HIA_COMPOSITE_TYPES_COLD_REPORT',
                'HEPTA_HIA_TASK_HELPERS_COLD_REPORT')
DEVELOPMENT_MANIFESTS = ('HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
                         'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST')


def joint_cold_report():
    """Require joint custody; build() separately admits the complete contract."""
    if any(os.environ.get(name) for name in DEVELOPMENT_MANIFESTS):
        raise AssertionError('development manifests are not joint cold qualification')
    selected = [os.environ.get(name) for name in COLD_REPORTS]
    if not all(selected):
        raise AssertionError('both native owners require explicit cold reports')
    paths = [Path(value) for value in selected]
    raw = [path.read_bytes() for path in paths]
    if raw[0] != raw[1]:
        raise AssertionError('native owners require the same exact cold report')
    return paths[0], raw[0]


class SourceTests(unittest.TestCase):
    def test_missing_either_report_refuses_before_reading_artifacts(self):
        for selected in ({}, {COLD_REPORTS[0]: '/unread-types'},
                         {COLD_REPORTS[1]: '/unread-helpers'}):
            with self.subTest(selected=selected), patch.dict(os.environ, selected, clear=True), \
                    patch.object(Path, 'read_bytes', side_effect=AssertionError('artifact read')):
                with self.assertRaisesRegex(AssertionError, 'both native owners'):
                    joint_cold_report()

    def test_development_cannot_be_used_with_or_instead_of_joint_cold(self):
        for development in DEVELOPMENT_MANIFESTS:
            for cold in ({}, dict.fromkeys(COLD_REPORTS, '/unread-cold')):
                with self.subTest(development=development, cold=cold), patch.dict(
                        os.environ, {**cold, development: '/unread-development'}, clear=True), \
                        patch.object(Path, 'read_bytes', side_effect=AssertionError('artifact read')):
                    with self.assertRaisesRegex(AssertionError, 'development manifests'):
                        joint_cold_report()

    def test_different_reports_cannot_compose_separate_qualifications(self):
        with patch.dict(os.environ, dict(zip(COLD_REPORTS, ('/types', '/helpers'))), clear=True), \
                patch.object(Path, 'read_bytes', side_effect=[b'first qualification', b'second qualification']):
            with self.assertRaisesRegex(AssertionError, 'same exact cold report'):
                joint_cold_report()


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, raw = joint_cold_report()
        from tools.build_hia_json_preflight import admit_cold_build, build
        report = json.loads(raw)
        nested = json.loads(Path(report['nested_report']).read_bytes())
        compiler = Path(nested['generations'][-1]['produced_image'])
        compiler_bytes = compiler.read_bytes()
        # Refuse stale source, profile or incomplete cold evidence before any
        # candidate directory is created. Each build repeats that admission.
        admit_cold_build(compiler_bytes, raw)
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-native-composition-')
        cls.addClassCleanup(cls.temporary.cleanup)
        folder = Path(cls.temporary.name)
        cls.types_manifest = build(folder / 'types', compiler, cold, candidate='composite-types')
        cls.helpers_manifest = build(folder / 'helpers', compiler, cold, candidate='task-helpers')
        if cold.read_bytes() != raw or compiler.read_bytes() != compiler_bytes:
            raise AssertionError('joint native build inputs changed')
        cls.cold_report_sha256 = sha256(raw).hexdigest()
        cls.fixture_scope = 'MATCHING_SOURCE_JOINT_COLD_BUILD'

    @contextmanager
    def selected(self):
        seen = {'operations': set(), 'return_loans': set()}
        generate = NativeTaskHelpers.generate
        origins = NativeCompositeTypeSession.loan_origins

        def checked_generate(image, typ, step, operation, *args):
            self.assertIsInstance(typ.key, _NativeTypeIdentity)
            self.assertIsInstance(step.key, _NativeTypeIdentity)
            self.assertIs(typ.key.session, step.key.session)
            seen['operations'].add(operation)
            return generate(image, typ, step, operation, *args)

        def checked_origins(session, function, params, returns):
            if 'return_loans' in function:
                seen['return_loans'].add(function['name'])
            return origins(session, function, params, returns)

        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {
                TYPES_SELECTOR: str(self.types_manifest), HELPERS_SELECTOR: str(self.helpers_manifest)}))
            stack.enter_context(patch.object(composite, '_Types',
                                            side_effect=AssertionError('retained type owner called')))
            for name in ('_reference_parameters', '_reference_check_task', 'loan_origins', '_reference_helper'):
                stack.enter_context(patch.object(composite._Elaborator, name,
                    side_effect=AssertionError('retained owner called: ' + name)))
            stack.enter_context(patch.object(NativeTaskHelpers, 'generate', checked_generate))
            stack.enter_context(patch.object(NativeCompositeTypeSession, 'loan_origins', checked_origins))
            yield seen

    def test_joint_ordinary_bytes_and_task_lifecycle_across_three_schemas(self):
        cases = ((fixtures.task_program, 'task_case', False),
                 (partials.task_partial_program, 'partial_task', True),
                 (loans.task_program, 'task_probe', True))
        for factory, function, sized in cases:
            document = factory()
            original = deepcopy(document)
            arguments = [[13, mode] if sized else [mode] for mode in (0, 1, 2, 255)]
            with patch.dict(os.environ, {TYPES_SELECTOR: '', HELPERS_SELECTOR: ''}):
                expected = verify_core(document)
                reference = {(index, failure): execute_program(expected, function, args,
                    allocation_fail_at=failure) for index, args in enumerate(arguments)
                    for failure in (None, 1)}
            with self.subTest(schema=document['schema']), self.selected() as seen:
                actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                self.assertIsNotNone(actual.structured_bytes)
                for index, args in enumerate(arguments):
                    for failure in (None, 1):
                        result = execute_program(actual, function, args, allocation_fail_at=failure)
                        self.assertEqual(result, reference[index, failure])
                        resources = result['resources']
                        self.assertEqual(resources['live_owners'], 0)
                        self.assertEqual(resources['live_local_loans'], 0)
                        self.assertEqual(resources['allocations'], resources['frees'])
                        self.assertEqual(resources['owners_created'], resources['owners_dropped'])
                self.assertEqual(seen['operations'], {'start', 'poll', 'cancel', 'join', 'close'})
                if factory is loans.task_program:
                    self.assertIn('task_view', seen['return_loans'])
            self.assertEqual(document, original)

    def test_joint_selection_preserves_parameter_protocol_and_origin_refusals(self):
        parameter = fixtures.task_program()
        parameter['functions'][0]['params'] *= 2
        protocol = partials.task_partial_program()
        next(item for item in protocol['types'] if item['kind'] == 'task')['poll'] = 'absent'
        origin = loans.task_program()
        next(fn for fn in origin['functions'] if fn['name'] == 'task_view')['return_loans'] = [
            loans.origin('absent')]
        for reason, document in (('parameter', parameter), ('protocol', protocol), ('origin', origin)):
            original = deepcopy(document)
            with self.subTest(reason=reason):
                with patch.dict(os.environ, {TYPES_SELECTOR: '', HELPERS_SELECTOR: ''}):
                    with self.assertRaises(HIAProgramRejected) as expected:
                        verify_core(document)
                with self.selected(), self.assertRaises(HIAProgramRejected) as actual:
                    verify_core(document)
                self.assertEqual((actual.exception.code, str(actual.exception)),
                                 (expected.exception.code, str(expected.exception)))
                self.assertEqual(document, original)


if __name__ == '__main__':
    unittest.main()
