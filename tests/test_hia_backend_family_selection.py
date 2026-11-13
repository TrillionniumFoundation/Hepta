"""Fixed family routing controls; these do not qualify a native image."""
from contextlib import ExitStack
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_backend_family_selection as policies


class BackendFamilySelectionTests(unittest.TestCase):
    def setUp(self):
        self.cleanup = ExitStack()
        self.addCleanup(self.cleanup.close)
        self.families = (policies.lowering_family, policies.emitter_family,
                         policies.plan_family, policies.elf_family)
        environment = {}
        for family in self.families:
            left, right = family._modules()
            old_route = family._route.set(family._unscoped)
            old_left = left._OWNER.set(left._UNSELECTED)
            old_right = right._OWNER.set(right._UNSELECTED)
            self.cleanup.callback(family._route.reset, old_route)
            self.cleanup.callback(left._OWNER.reset, old_left)
            self.cleanup.callback(right._OWNER.reset, old_right)
            environment[family.bundle_selector] = ''
            environment[family.control_selector] = ''
        self.cleanup.enter_context(patch.dict(os.environ, environment))

    def patch_admission(self, stack, family, primary, control):
        left, right = family._modules()
        first = family.primary_admit or family.installed
        stack.enter_context(patch.object(left, first, side_effect=primary))
        stack.enter_context(patch.object(right, family.control_admit, side_effect=control))

    def test_no_selection_does_not_read_either_manifest(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                def forbidden(*args):
                    raise AssertionError('unselected native admission')
                self.patch_admission(stack, family, forbidden, forbidden)
                self.assertIsNone(family.selected({}))
                with family.scope({}):
                    self.assertEqual(family.active(), (None, None))

    def test_dual_selection_refuses_before_either_admission(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                calls = []
                def forbidden(*args):
                    calls.append(args)
                    raise AssertionError('ambiguous admission reached')
                self.patch_admission(stack, family, forbidden, forbidden)
                stack.enter_context(patch.dict(os.environ, {
                    family.bundle_selector: '/primary',
                    family.control_selector: '/control'}))
                with self.assertRaisesRegex(ValueError, 'one explicit native family'):
                    family.selected({})
                self.assertEqual(calls, [])

    def test_control_selection_cannot_probe_the_primary_loader(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                owner, calls = object(), []
                admission = SimpleNamespace(owner=owner, checker_owner=object())
                def primary(*args):
                    raise AssertionError('primary loader reached')
                def control(path, namespace):
                    calls.append((path, namespace))
                    return admission
                self.patch_admission(stack, family, primary, control)
                stack.enter_context(patch.dict(os.environ, {
                    family.control_selector: '/control'}))
                namespace = {}
                with family.scope(namespace):
                    self.assertEqual(family.active(), ('control', owner))
                    self.assertIs(family.selected(namespace), owner)
                self.assertEqual(calls, [('/control', namespace)])

    def test_primary_selection_preserves_actual_original_owner(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                owner, calls = object(), []
                def primary(path, namespace):
                    calls.append((path, namespace))
                    if family.primary_admit:
                        return SimpleNamespace(owner=owner, checker_owner=object())
                    return owner
                def control(*args):
                    raise AssertionError('control loader reached')
                self.patch_admission(stack, family, primary, control)
                stack.enter_context(patch.dict(os.environ, {
                    family.bundle_selector: '/primary'}))
                namespace = {}
                with family.scope(namespace):
                    self.assertEqual(family.active(), (family.primary_family, owner))
                    self.assertIs(family.selected(namespace), owner)
                self.assertEqual(calls, [('/primary', namespace)])

    def test_held_selection_survives_both_selector_changes_and_exception(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                owner, calls = object(), []
                def primary(*args):
                    raise AssertionError('new primary route')
                def control(path, namespace):
                    calls.append(path)
                    return SimpleNamespace(owner=owner, checker_owner=object())
                self.patch_admission(stack, family, primary, control)
                stack.enter_context(patch.dict(os.environ, {
                    family.control_selector: '/original'}))
                error = LookupError('foreign callback')
                with self.assertRaises(LookupError) as caught:
                    with family.scope({}):
                        os.environ[family.bundle_selector] = '/changed-primary'
                        os.environ[family.control_selector] = '/changed-control'
                        self.assertIs(family.selected({}), owner)
                        with family.scope({}):
                            self.assertIs(family.selected({}), owner)
                        raise error
                self.assertIs(caught.exception, error)
                self.assertEqual(calls, ['/original'])
                self.assertIs(family._route.get(), family._unscoped)
                left, right = family._modules()
                self.assertIs(left._OWNER.get(), left._UNSELECTED)
                self.assertIs(right._OWNER.get(), right._UNSELECTED)
                with self.assertRaisesRegex(ValueError, 'one explicit native family'):
                    family.selected({})

    def test_explicit_absence_masks_later_enabling_of_either_family(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                def forbidden(*args):
                    raise AssertionError('captured absence was lost')
                self.patch_admission(stack, family, forbidden, forbidden)
                with family.scope({}):
                    with patch.dict(os.environ, {
                            family.bundle_selector: '/later-primary',
                            family.control_selector: '/later-control'}):
                        self.assertIsNone(family.selected({}))
                        with family.scope({}):
                            self.assertEqual(family.active(), (None, None))
                self.assertIs(family._route.get(), family._unscoped)

    def test_admission_exception_keeps_identity_and_cannot_fall_back(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                failure, calls = ValueError('exact loader refusal'), []
                def primary(*args):
                    raise AssertionError('fallback route')
                def control(*args):
                    calls.append(args)
                    raise failure
                self.patch_admission(stack, family, primary, control)
                stack.enter_context(patch.dict(os.environ, {
                    family.control_selector: '/bad'}))
                with self.assertRaises(ValueError) as caught:
                    with family.scope({}):
                        self.fail('admission exception ignored')
                self.assertIs(caught.exception, failure)
                self.assertEqual(len(calls), 1)
                self.assertIs(family._route.get(), family._unscoped)

    def test_observation_distinguishes_unscoped_and_absence_without_admission(self):
        for family in self.families:
            with self.subTest(family=family.name), ExitStack() as stack:
                left, right = family._modules()
                def forbidden(*args):
                    raise AssertionError('read-only observation attempted admission')
                self.patch_admission(stack, family, forbidden, forbidden)
                stack.enter_context(patch.dict(os.environ, {
                    family.bundle_selector: '/ambient-primary',
                    family.control_selector: '/ambient-control'}))
                self.assertEqual(family.observe(), (False, None, None))
                token = left._OWNER.set(None)
                try:
                    self.assertEqual(family.observe(), (True, None, None))
                finally:
                    left._OWNER.reset(token)
                token = right._OWNER.set(None)
                try:
                    self.assertEqual(family.observe(), (True, None, None))
                finally:
                    right._OWNER.reset(token)
                primary_owner, control_owner = object(), object()
                primary = (SimpleNamespace(owner=primary_owner, checker_owner=object())
                           if family.primary_admit else primary_owner)
                token = left._OWNER.set(primary)
                try:
                    self.assertEqual(family.observe(), (True, family.primary_family, primary_owner))
                finally:
                    left._OWNER.reset(token)
                control = SimpleNamespace(owner=control_owner, checker_owner=object())
                token = right._OWNER.set(control)
                try:
                    self.assertEqual(family.observe(), (True, 'control', control_owner))
                finally:
                    right._OWNER.reset(token)
                with family._bind(policies._Route(None, None)):
                    self.assertEqual(family.observe(), (True, None, None))
                self.assertEqual(family.observe(), (False, None, None))

    def test_native_build_canonical_callers_preserve_every_other_original_byte(self):
        from pathlib import Path
        from tools import qualify_hia_native_build as callers
        root = Path(__file__).resolve().parents[1]
        raw = (root / callers.CANONICAL_CALLER_PATH).read_bytes()
        result = callers.admit_canonical_caller_source(raw)
        self.assertEqual(result['exact_literal_replacements'], 2)
        self.assertTrue(result['all_other_bytes_preserved'])
        self.assertFalse(result['prior_qualification_inherited'])
        self.assertEqual(len(callers.EXPECTED_IDS), 114)
        self.assertEqual(len(callers.MODULES), 11)
        with self.assertRaisesRegex(ValueError, 'canonical caller source bytes differ'):
            callers.admit_canonical_caller_source(raw + b'\n')
        for path, pin in callers.MODULE_SOURCE_PINS.items():
            if path != callers.CANONICAL_CALLER_PATH:
                self.assertEqual(pin, callers.ORIGINAL_MODULE_SOURCE_PINS[path])

    def test_set_return_loss_restores_all_preexisting_scope_values(self):
        for family in self.families:
            for failed_position in ('primary', 'control', 'route'):
                with self.subTest(family=family.name, failed_position=failed_position), ExitStack() as stack:
                    left, right = family._modules()
                    target, attribute = ((left, '_OWNER') if failed_position == 'primary'
                        else (right, '_OWNER') if failed_position == 'control'
                        else (family, '_route'))
                    actual = getattr(target, attribute)
                    initial = actual.get()
                    failure = KeyboardInterrupt('lost ContextVar set acknowledgement')
                    class SetThenRaise:
                        def __init__(self):
                            self.first = True
                        def get(self):
                            return actual.get()
                        def set(self, value):
                            result = actual.set(value)
                            if self.first:
                                self.first = False
                                raise failure
                            return result
                    stack.enter_context(patch.object(target, attribute, SetThenRaise()))
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        with family.scope({}):
                            self.fail('lost set return reached body')
                    self.assertIs(caught.exception, failure)
                    self.assertIs(actual.get(), initial)
                    self.assertIs(family._route.get(), family._unscoped)
                    self.assertIs(left._OWNER.get(), left._UNSELECTED)
                    self.assertIs(right._OWNER.get(), right._UNSELECTED)


class BackendFamilyFacadeTests(unittest.TestCase):
    def test_main_core_helpers_keep_the_original_invoke_shape(self):
        from hepta import hia_program_native as backend
        calls = []
        class Owner:
            def invoke(self, name, arguments):
                calls.append((name, arguments))
                return 'observed'
        owner = Owner()
        left, right, third = object(), object(), object()
        with patch.object(policies.lowering_family, 'active', return_value=('bundle', owner)):
            self.assertEqual(backend._words(left), 'observed')
            self.assertEqual(backend._normalize(left, right, third), 'observed')
        self.assertEqual(calls, [('_words', (left,)), ('_normalize', (left, right, third))])

    def test_control_helpers_transfer_formals_before_finish(self):
        import weakref
        from hepta import hia_program_native as backend
        events = []
        class Argument:
            def __del__(self):
                events.append('retired')
        class Owner:
            def prepare(self, name, arguments):
                return name, tuple(weakref.ref(value) for value in arguments)
            def finish(self, frame):
                name, references = frame
                if any(reference() is not None for reference in references):
                    raise AssertionError('public helper retained a transferred argument')
                return name
        with patch.object(policies.lowering_family, 'active', return_value=('control', Owner())):
            self.assertEqual(backend._words(Argument()), '_words')
            self.assertEqual(backend._normalize(Argument(), Argument(), Argument()), '_normalize')
        self.assertEqual(events, ['retired'] * 4)

    def test_plan_v1_and_control_keep_each_owned_public_entry(self):
        from contextlib import nullcontext
        from hepta import hia_machine_plan as plans
        calls = []
        checked, plan, assignments = object(), object(), object()
        class V1:
            def validate(self, actual_checked, actual_plan, witness):
                calls.append(('v1-validate', actual_checked, actual_plan, witness))
                return 'v1-validate'
            def witness(self, actual_checked, actual_assignments, *, allow_leaf_registers):
                calls.append(('v1-witness', actual_checked, actual_assignments, allow_leaf_registers))
                return 'v1-witness'
        class Control:
            def validate(self, actual_checked, actual_plan):
                calls.append(('control-validate', actual_checked, actual_plan))
                return 'control-validate'
            def witness(self, actual_checked, actual_assignments, *, allow_leaf_registers):
                calls.append(('control-witness', actual_checked, actual_assignments, allow_leaf_registers))
                return 'control-witness'
            def code_options(self, actual_plan):
                calls.append(('control-options', actual_plan))
                return 'control-options'
            def preservation_checks(self, actual_plan, actual_checked):
                calls.append(('control-preservation', actual_plan, actual_checked))
                return 'control-preservation'
        prior = plans._NATIVE_OWNER.get()
        with patch.object(policies.plan_family, 'scope', side_effect=lambda namespace: nullcontext()), \
             patch.object(policies.plan_family, 'active', return_value=('plan-v1', V1())), \
             patch.object(plans, '_reference_code_options', return_value='reference-options') as options, \
             patch.object(plans, '_reference_preservation_checks', return_value='reference-preservation') as preservation:
            self.assertEqual(plans.validate_plan(checked, plan), 'v1-validate')
            self.assertEqual(plans.register_assignment_witness(checked, assignments, allow_leaf_registers=True), 'v1-witness')
            self.assertEqual(plans.code_options(plan), 'reference-options')
            self.assertEqual(plans.preservation_checks(plan, checked), 'reference-preservation')
            options.assert_called_once_with(plan)
            preservation.assert_called_once_with(plan, checked)
        with patch.object(policies.plan_family, 'scope', side_effect=lambda namespace: nullcontext()), \
             patch.object(policies.plan_family, 'active', return_value=('control', Control())), \
             patch.object(plans, '_reference_code_options', side_effect=AssertionError('control options fell back')), \
             patch.object(plans, '_reference_preservation_checks', side_effect=AssertionError('control preservation fell back')):
            self.assertEqual(plans.validate_plan(checked, plan), 'control-validate')
            self.assertEqual(plans.register_assignment_witness(checked, assignments, allow_leaf_registers=True), 'control-witness')
            self.assertEqual(plans.code_options(plan), 'control-options')
            self.assertEqual(plans.preservation_checks(plan, checked), 'control-preservation')
        self.assertIs(plans._NATIVE_OWNER.get(), prior)
        self.assertEqual(calls, [
            ('v1-validate', checked, plan, plans.register_assignment_witness),
            ('v1-witness', checked, assignments, True),
            ('control-validate', checked, plan),
            ('control-witness', checked, assignments, True),
            ('control-options', plan), ('control-preservation', plan, checked)])

    def test_elf_main_and_control_keep_their_distinct_entry_protocols(self):
        from hepta import hia_machine_elf as elf
        from hepta import hia_machine_elf_selection as selection
        from contextlib import nullcontext
        calls = []
        class Bundle:
            def invoke(self, name, arguments):
                calls.append(('bundle', name, arguments))
                return b'bundle'
        class Control:
            def write(self, code, symbols, relocations, *, text_alignment):
                calls.append(('control', code, symbols, relocations, text_alignment))
                return b'control'
        code, symbols, relocations = b'code', [], []
        with patch.object(selection, 'native_elf_policy_scope', return_value=nullcontext()), \
             patch.object(selection, 'selected_elf_policy', return_value=('bundle', Bundle())):
            self.assertEqual(elf.write_elf_object(code, symbols, relocations, text_alignment=32), b'bundle')
        with patch.object(selection, 'native_elf_policy_scope', return_value=nullcontext()), \
             patch.object(selection, 'selected_elf_policy', return_value=('control', Control())):
            self.assertEqual(elf.write_elf_object(code, symbols, relocations, text_alignment=32), b'control')
        self.assertEqual(calls, [('bundle', 'write_elf_object', (code, symbols, relocations, 32)),
                                ('control', code, symbols, relocations, 32)])
